//! Measurement evidence shared by the versioned Hard/Hard plan selector.
//! Socket ownership remains in the existing provisional-socket guards.

use super::*;
use p2pnet_nat::{
    infer_port_domain, infer_scoped_allocation, plan_fixed_anchor, validate_allocation_attempts,
    AllocationAttempt, AllocationAttemptOutcome, AllocationEvidenceRejection, AllocationIdentity,
    AllocationSample, FixedAnchorPlan, PortDomainEvidence, ScopedAllocationEvidence,
};

pub(crate) struct HardHardPreparedMeasurement {
    /// Owns every exact socket/guard, including the predictable first socket.
    pub(crate) birthday: HardHardBirthdayResult,
    pub(crate) identity: AllocationIdentity,
    /// Complete bounded syscall ledger. A timeout remains SentUnobserved;
    /// successful observation counts alone cannot establish consumption.
    pub(crate) measurement_trace: Vec<AllocationAttempt>,
    pub(crate) allocation: Option<ScopedAllocationEvidence>,
    pub(crate) allocation_rejection: Option<AllocationEvidenceRejection>,
    /// Evidence-only view of the first owned socket; it owns no second guard.
    pub(crate) predictable: Option<FreshMappingResult>,
    /// Original monotonic schedule and its upper forecast bound. Rechecking
    /// publication never advances either value or the actual sample times.
    pub(super) scheduled_send: Option<(u64, u64)>,
}

impl HardHardPreparedMeasurement {
    pub(crate) fn measurement_cost(&self) -> HardHardMeasurementStats {
        self.birthday.measurement
    }

    /// Call immediately before publishing the immutable offer. Unknown final
    /// STUN allocations may still use birthday guessing, but never advertise
    /// prediction/anchor evidence. This is not a physical-send identity fence.
    pub(crate) fn validate_publication(
        &self,
        network_generation: u64,
        prediction_count: usize,
        anchor_port: u16,
    ) -> std::result::Result<(), AllocationEvidenceRejection> {
        use AllocationEvidenceRejection as Reject;
        let primary = self
            .birthday
            .sockets
            .first()
            .ok_or(Reject::IdentityChanged)?;
        if network_generation != self.identity.network_generation
            || primary.punch_generation != self.identity.measurement_generation
        {
            return Err(Reject::IdentityChanged);
        }
        let sampled_at_ms = self
            .birthday
            .measurement
            .measurement_started_at_ms
            .ok_or(Reject::SampleCount)?;
        let (send_at_ms, horizon_ms) = self.scheduled_send.ok_or(Reject::ForecastExpired)?;
        p2pnet_nat::mapping::allocation::validate_allocation_publication_timing(
            sampled_at_ms,
            monotonic_millis(),
            send_at_ms,
            FRESH_MAPPING_MODEL_MAX_AGE,
            Duration::from_millis(horizon_ms),
        )?;
        if prediction_count > 0 {
            let candidates = self.prediction_candidates(network_generation, prediction_count)?;
            if prediction_count > 32 || candidates.len() != prediction_count {
                return Err(Reject::NoConsistentStep);
            }
        }
        if anchor_port != 0 {
            let count = self.birthday.sockets.len();
            let anchor =
                self.fixed_anchor_plan(network_generation, count, count.saturating_sub(1))?;
            if anchor.local_anchor.port() != anchor_port {
                return Err(Reject::IdentityChanged);
            }
        }
        Ok(())
    }

    fn validate_plan_identity(
        &self,
        network_generation: u64,
    ) -> std::result::Result<(), AllocationEvidenceRejection> {
        use AllocationEvidenceRejection as Reject;
        let Some(primary) = self.birthday.sockets.first() else {
            return Err(Reject::IdentityChanged);
        };
        if network_generation != self.identity.network_generation
            || primary.punch_generation != self.identity.measurement_generation
        {
            return Err(Reject::IdentityChanged);
        }
        if self.measurement_trace.is_empty()
            || self
                .measurement_trace
                .iter()
                .any(|attempt| attempt.outcome != AllocationAttemptOutcome::Observed)
        {
            return Err(Reject::UnobservedAllocation);
        }
        Ok(())
    }

    /// Revalidate the evidence when publishing/agreeing a plan. Physical sends
    /// still require the existing exact session/socket/profile fences.
    pub(crate) fn prediction_candidates(
        &self,
        network_generation: u64,
        cap: usize,
    ) -> std::result::Result<Vec<SocketAddr>, AllocationEvidenceRejection> {
        self.validate_plan_identity(network_generation)?;
        let prediction = self
            .predictable
            .as_ref()
            .ok_or(AllocationEvidenceRejection::NoConsistentStep)?;
        if !p2pnet_nat::model_is_fresh(
            &prediction.model,
            FRESH_MAPPING_MODEL_MAX_AGE,
            monotonic_millis(),
        ) {
            return Err(AllocationEvidenceRejection::Stale);
        }
        let ports = p2pnet_nat::mapping::rendezvous::bounded_prediction_window(
            &prediction.predicted_ports,
            cap.min(32),
        );
        if ports.is_empty() {
            return Err(AllocationEvidenceRejection::NoConsistentStep);
        }
        Ok(ports
            .into_iter()
            .map(|port| SocketAddr::new(self.birthday.public_ip, port))
            .collect())
    }

    /// A bounded conditional attempt. Prefix consumption is before the first
    /// socket sends, not an allowance for arbitrary interleaved allocations.
    pub(crate) fn fixed_anchor_plan(
        &self,
        network_generation: u64,
        socket_count: usize,
        max_prefix_allocations: usize,
    ) -> std::result::Result<FixedAnchorPlan, AllocationEvidenceRejection> {
        self.validate_plan_identity(network_generation)?;
        if socket_count > self.birthday.sockets.len() {
            return Err(AllocationEvidenceRejection::InvalidSocketCount);
        }
        let evidence = self.allocation.as_ref().ok_or_else(|| {
            self.allocation_rejection
                .unwrap_or(AllocationEvidenceRejection::ScopeUnproven)
        })?;
        plan_fixed_anchor(
            evidence,
            self.identity,
            monotonic_millis(),
            FRESH_MAPPING_MODEL_MAX_AGE,
            socket_count,
            max_prefix_allocations,
        )
    }
}

pub(super) struct HardHardGridMeasurement {
    pub(super) observations_by_socket: Vec<Vec<MappingObservation>>,
    pub(super) samples: Vec<AllocationSample>,
    pub(super) attempts: Vec<AllocationAttempt>,
    pub(super) stats: HardHardMeasurementStats,
}

impl UdpTransport {
    pub(super) async fn measure_hard_hard_grid(
        &self,
        sockets: &[(usize, Arc<UdpSocket>)],
        observers: &[SocketAddr],
        stun_timeout: Duration,
        keep_measuring: impl Fn() -> bool,
    ) -> HardHardGridMeasurement {
        let mut seen = HashSet::new();
        let mut observers = observers
            .iter()
            .copied()
            .filter(|addr| seen.insert(*addr))
            .collect::<Vec<_>>();
        if let Some(first) = observers.first().copied() {
            if let Some(other) = observers.iter().position(|addr| addr.ip() != first.ip()) {
                observers.swap(1, other);
            }
        }
        observers.truncate(4);
        let mut pairs = Vec::new();
        if sockets.len() >= 2 && observers.len() >= 4 {
            // The last grid send is A1. A2/A3 then extend that same socket's
            // ordered tail without another socket consuming an allocation.
            pairs.extend([(0, 0), (1, 0), (1, 1), (0, 1), (0, 2), (0, 3)]);
        } else if !sockets.is_empty() {
            pairs.extend((0..observers.len()).map(|observer| (0, observer)));
        }
        let requests = pairs
            .iter()
            .map(|(socket, observer)| (sockets[*socket].1.clone(), observers[*observer]))
            .collect::<Vec<_>>();
        let measurement = self
            .measure_ordered_mapping_requests(&requests, stun_timeout, keep_measuring)
            .await;
        let mut observations_by_socket = vec![Vec::new(); sockets.len()];
        let mut samples = Vec::new();
        for observation in measurement.observations {
            let Some(&(position, _)) = pairs.get(usize::from(observation.sequence)) else {
                continue;
            };
            observations_by_socket[position].push(observation.clone());
            samples.push(AllocationSample {
                socket_id: sockets[position].0,
                observation,
            });
        }
        HardHardGridMeasurement {
            observations_by_socket,
            samples,
            attempts: measurement.attempts,
            stats: measurement.stats,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepared_prediction(
    samples: &[AllocationSample],
    attempts: &[AllocationAttempt],
    primary: &[MappingObservation],
    identity: AllocationIdentity,
    socket_index: usize,
    socket_local_endpoint: SocketAddr,
    measurement: HardHardMeasurementStats,
    scheduled_send: (u64, u64),
) -> (
    Option<ScopedAllocationEvidence>,
    Option<AllocationEvidenceRejection>,
    Option<FreshMappingResult>,
) {
    let now_ms = monotonic_millis();
    if let Err(rejection) = validate_allocation_attempts(samples, attempts) {
        // There is no defensible last allocation when the final accepted
        // syscall has no observation. Do not guess that it consumed exactly
        // one mapping: retain the exact trace and use the birthday fallback.
        return (None, Some(rejection), None);
    }
    let allocation_result =
        infer_scoped_allocation(samples, identity, now_ms, FRESH_MAPPING_MODEL_MAX_AGE);
    let allocation_rejection = allocation_result.as_ref().err().copied();
    let allocation = allocation_result.ok();
    let delay_ms = scheduled_send.0.saturating_sub(now_ms);
    if delay_ms > scheduled_send.1 {
        return (allocation, allocation_rejection, None);
    }
    // Only the final consecutive primary run models that socket. The early A0
    // sample is separated by B0/B1 and must not teach a false enlarged stride.
    let mut tail = Vec::new();
    for observation in primary.iter().rev() {
        if tail.first().is_some_and(|next: &&MappingObservation| {
            observation.sequence.saturating_add(1) != next.sequence
        }) {
            break;
        }
        tail.insert(0, observation);
    }
    let Some(first) = tail.first() else {
        return (allocation, allocation_rejection, None);
    };
    let Some(last) = tail.last() else {
        return (allocation, allocation_rejection, None);
    };
    if tail.len() < 3
        || now_ms.saturating_sub(first.sent_at_ms) > FRESH_MAPPING_MODEL_MAX_AGE.as_millis() as u64
    {
        return (allocation, allocation_rejection, None);
    }
    let sequence = tail
        .iter()
        .map(|sample| sample.observed.port())
        .collect::<Vec<_>>();
    let mut model = p2pnet_nat::build_model(&sequence, Some(first.observed.ip()), first.sent_at_ms);
    let domain = match allocation.as_ref() {
        Some(evidence) => {
            // The complete grid can identify a wrap that the short tail alone
            // cannot distinguish. Its last sample is also this primary tail.
            model.kind = PortModelKind::FixedStep {
                step: evidence.step,
            };
            model.deltas = vec![evidence.step; sequence.len() - 1];
            model.confidence = 90;
            evidence.domain
        }
        None => infer_port_domain(&sequence)
            .map(|(_, domain)| domain)
            .unwrap_or(PortDomainEvidence::Unobserved),
    };
    let bounded_step = match &model.kind {
        PortModelKind::FixedStep { step }
        | PortModelKind::Linear { step }
        | PortModelKind::NoisyLinear { step } => {
            step.unsigned_abs() <= FRESH_MAPPING_MAX_ABS_STEP as u16
        }
        _ => true,
    };
    if !bounded_step {
        return (allocation, allocation_rejection, None);
    }
    let predicted_ports = if let PortModelKind::FixedStep { step } = model.kind {
        (1..=p2pnet_nat::MAX_PREDICTED_PORTS)
            .map_while(|distance| {
                domain.advance(last.observed.port(), i64::from(step) * distance as i64)
            })
            .collect()
    } else if model.kind.clone().is_predictable() {
        let timing = p2pnet_nat::mapping::rendezvous::RendezvousPredictionTiming {
            measurement_span_ms: last.sent_at_ms.saturating_sub(first.sent_at_ms),
            last_measurement_send_at_ms: last.sent_at_ms,
            now_ms,
            send_delay_ms: delay_ms,
            max_send_delay_ms: scheduled_send.1,
            max_model_age: FRESH_MAPPING_MODEL_MAX_AGE,
        };
        p2pnet_nat::mapping::rendezvous::predict_for_rendezvous(
            &model,
            last.observed.port(),
            timing,
            None,
            false,
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|candidate| {
            // With no domain evidence, never manufacture a wrap from the
            // legacy 16-bit arithmetic used by hh1's hypothesis generator.
            let delta = i32::from(candidate.port) - i32::from(last.observed.port());
            model
                .deltas
                .iter()
                .all(|step| *step == 0 || delta.signum() == i32::from(*step).signum())
        })
        .map(|candidate| candidate.port)
        .collect()
    } else {
        Vec::new()
    };
    let prediction = (!predicted_ports.is_empty()).then_some(FreshMappingResult {
        punch_generation: identity.measurement_generation,
        network_generation: identity.network_generation,
        socket_local_endpoint,
        socket_index,
        model,
        predicted_ports,
        public_ip: Some(first.observed.ip()),
        first_punch_sent_at_ms: 0,
        last_punch_sent_at_ms: 0,
        measurement,
    });
    (allocation, allocation_rejection, prediction)
}
