//! Bounded, explicitly scoped evidence for allocating new UDP mappings.
//!
//! A fixed step on one socket does not establish an allocator shared by other
//! sockets or destinations. These observations are evidence, not a lock on the
//! NAT: unrelated traffic may still consume allocations after measurement.

use super::MappingObservation;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const MAX_ALLOCATION_SAMPLES: usize = 16;
const MAX_STEP: i32 = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationIdentity {
    pub network_generation: u64,
    pub measurement_generation: u64,
    /// Local UDP publication identity. `network_generation` separately fences
    /// its route/interface; this address is not proof of the public egress.
    pub egress: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationSample {
    pub socket_id: usize,
    pub observation: MappingObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationAttemptOutcome {
    /// The UDP syscall failed; do not claim it consumed a NAT allocation.
    SendFailed,
    /// The kernel accepted the datagram, but its NAT mapping is unknown.
    SentUnobserved,
    Observed,
}

/// Every attempted request, including failures and the last timed-out send.
/// A successful syscall is consumption risk, not proof of a NAT allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationAttempt {
    pub sequence: u16,
    pub local_endpoint: SocketAddr,
    pub destination: SocketAddr,
    pub sent_at_ms: u64,
    pub datagram_bytes: u32,
    pub outcome: AllocationAttemptOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationScope {
    SameSocketMultipleDestinations,
    MultipleSocketsFixedDestination,
    /// A complete two-socket/two-destination grid, including distinct IPs,
    /// followed one ordered allocation sequence. It does not prove that all
    /// unobserved NAT destinations share that allocator forever.
    ObservedSharedSequence,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PortDomainEvidence {
    /// No boundary crossing was observed: ordinary arithmetic only.
    #[default]
    Unobserved,
    /// Under the observed fixed-step hypothesis, a boundary transition
    /// uniquely constrained this range. An allocator reset can invalidate it.
    ObservedRange { first: u16, last: u16 },
}

impl PortDomainEvidence {
    pub fn advance(self, port: u16, delta: i64) -> Option<u16> {
        if port == 0 {
            return None;
        }
        match self {
            Self::Unobserved => {
                let next = i64::from(port).checked_add(delta)?;
                (1..=65_535).contains(&next).then_some(next as u16)
            }
            Self::ObservedRange { first, last } => {
                if first == 0 || first >= last || !(first..=last).contains(&port) {
                    return None;
                }
                let width = i64::from(last) - i64::from(first) + 1;
                Some(
                    (i64::from(first)
                        + (i64::from(port - first) + delta.rem_euclid(width)).rem_euclid(width))
                        as u16,
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationEvidenceRejection {
    SampleCount,
    Stale,
    ForecastExpired,
    ForecastHorizonExceeded,
    IdentityChanged,
    InconsistentOrder,
    ReusedMappingPair,
    PublicIpChanged,
    NoConsistentStep,
    AmbiguousPortDomain,
    ScopeUnproven,
    InvalidSocketCount,
    DriftExceedsCoverage,
    UnobservedAllocation,
}

impl AllocationEvidenceRejection {
    pub fn label(self) -> &'static str {
        match self {
            Self::SampleCount => "allocation_sample_count",
            Self::Stale => "allocation_stale",
            Self::ForecastExpired => "allocation_forecast_expired",
            Self::ForecastHorizonExceeded => "allocation_forecast_horizon_exceeded",
            Self::IdentityChanged => "allocation_identity_changed",
            Self::InconsistentOrder => "allocation_inconsistent_order",
            Self::ReusedMappingPair => "allocation_reused_pair",
            Self::PublicIpChanged => "allocation_public_ip_changed",
            Self::NoConsistentStep => "allocation_no_consistent_step",
            Self::AmbiguousPortDomain => "allocation_port_domain_unproven",
            Self::ScopeUnproven => "allocation_scope_unproven",
            Self::InvalidSocketCount => "allocation_socket_count",
            Self::DriftExceedsCoverage => "allocation_drift_exceeds_coverage",
            Self::UnobservedAllocation => "allocation_unobserved_send",
        }
    }
}

/// Publication freshness and forecasting are different clocks: the sample
/// must still be fresh NOW, while the original scheduled send may be further
/// in the future. The caller retains these original timestamps; validating
/// again must never replace the sample time or extend the forecast deadline.
pub fn validate_allocation_publication_timing(
    sampled_at_ms: u64,
    now_ms: u64,
    planned_send_at_ms: u64,
    max_sample_age: Duration,
    max_forecast_horizon: Duration,
) -> Result<(), AllocationEvidenceRejection> {
    use AllocationEvidenceRejection as Reject;
    if sampled_at_ms > now_ms
        || now_ms.saturating_sub(sampled_at_ms) > max_sample_age.as_millis() as u64
    {
        return Err(Reject::Stale);
    }
    if now_ms >= planned_send_at_ms {
        return Err(Reject::ForecastExpired);
    }
    if planned_send_at_ms.saturating_sub(sampled_at_ms) > max_forecast_horizon.as_millis() as u64 {
        return Err(Reject::ForecastHorizonExceeded);
    }
    Ok(())
}

/// Reconcile the model input with every attempted send. In particular, a
/// trailing timeout cannot disappear just because the successful prefix has
/// no sequence gaps. Callers may fall back to bounded guessing on rejection.
pub fn validate_allocation_attempts(
    samples: &[AllocationSample],
    attempts: &[AllocationAttempt],
) -> Result<(), AllocationEvidenceRejection> {
    use AllocationEvidenceRejection as Reject;
    if attempts.is_empty() || attempts.len() > MAX_ALLOCATION_SAMPLES {
        return Err(Reject::SampleCount);
    }
    if attempts
        .iter()
        .any(|attempt| attempt.outcome != AllocationAttemptOutcome::Observed)
    {
        return Err(Reject::UnobservedAllocation);
    }
    if samples.len() != attempts.len() {
        return Err(Reject::InconsistentOrder);
    }
    for (index, (sample, attempt)) in samples.iter().zip(attempts).enumerate() {
        let observation = &sample.observation;
        if usize::from(attempt.sequence) != index
            || observation.sequence != attempt.sequence
            || observation.local_endpoint != attempt.local_endpoint
            || observation.observer != attempt.destination
            || observation.sent_at_ms != attempt.sent_at_ms
            || observation.responded_at_ms == 0
            || observation.responded_at_ms < observation.sent_at_ms
            || attempt.datagram_bytes == 0
            || index > 0 && observation.sent_at_ms < samples[index - 1].observation.responded_at_ms
        {
            return Err(Reject::InconsistentOrder);
        }
    }
    Ok(())
}

/// Recover a same-socket prediction base after an earlier unknown allocation.
/// Every attempt must still reconcile with the sparse observation ledger. Only
/// the complete final run of observed, previously unused destination pairs is
/// returned; an unobserved final send can never be hidden by an older prefix.
/// This does not establish the shared allocator needed by a fixed anchor.
pub fn validate_allocation_prediction_tail<'a>(
    samples: &'a [AllocationSample],
    attempts: &[AllocationAttempt],
    socket_id: usize,
    local_endpoint: SocketAddr,
) -> Result<&'a [AllocationSample], AllocationEvidenceRejection> {
    use AllocationEvidenceRejection as Reject;
    if attempts.is_empty() || attempts.len() > MAX_ALLOCATION_SAMPLES {
        return Err(Reject::SampleCount);
    }
    let mut sample_index = 0;
    let mut previous_completed_at = 0;
    let mut sockets = HashMap::new();
    let mut pairs = HashSet::new();
    for (index, attempt) in attempts.iter().enumerate() {
        if usize::from(attempt.sequence) != index
            || attempt.local_endpoint.port() == 0
            || attempt.destination.port() == 0
            || attempt.datagram_bytes == 0
            || attempt.sent_at_ms < previous_completed_at
        {
            return Err(Reject::InconsistentOrder);
        }
        // Even an unobserved earlier request could have opened this mapping.
        // Reusing that pair cannot supply a fresh allocator-step observation.
        if !pairs.insert((attempt.local_endpoint, attempt.destination)) {
            return Err(Reject::ReusedMappingPair);
        }
        previous_completed_at = attempt.sent_at_ms;
        if attempt.outcome != AllocationAttemptOutcome::Observed {
            continue;
        }
        let sample = samples.get(sample_index).ok_or(Reject::InconsistentOrder)?;
        let observation = &sample.observation;
        if observation.sequence != attempt.sequence
            || observation.local_endpoint != attempt.local_endpoint
            || observation.observer != attempt.destination
            || observation.sent_at_ms != attempt.sent_at_ms
            || observation.responded_at_ms == 0
            || observation.responded_at_ms < observation.sent_at_ms
            || observation.observed.port() == 0
        {
            return Err(Reject::InconsistentOrder);
        }
        if sockets
            .insert(sample.socket_id, observation.local_endpoint)
            .is_some_and(|endpoint| endpoint != observation.local_endpoint)
        {
            return Err(Reject::IdentityChanged);
        }
        previous_completed_at = observation.responded_at_ms;
        sample_index += 1;
    }
    if sample_index != samples.len()
        || sockets.values().copied().collect::<HashSet<_>>().len() != sockets.len()
    {
        return Err(Reject::InconsistentOrder);
    }
    if attempts
        .last()
        .is_some_and(|attempt| attempt.outcome != AllocationAttemptOutcome::Observed)
    {
        return Err(Reject::UnobservedAllocation);
    }
    let tail_len = attempts
        .iter()
        .rev()
        .take_while(|attempt| {
            attempt.outcome == AllocationAttemptOutcome::Observed
                && attempt.local_endpoint == local_endpoint
        })
        .count();
    if tail_len < 3 || tail_len > samples.len() {
        return Err(Reject::SampleCount);
    }
    let tail = &samples[samples.len() - tail_len..];
    if tail.iter().any(|sample| sample.socket_id != socket_id) {
        return Err(Reject::IdentityChanged);
    }
    if samples
        .iter()
        .any(|sample| sample.observation.observed.ip() != tail[0].observation.observed.ip())
    {
        return Err(Reject::PublicIpChanged);
    }
    Ok(tail)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedAllocationEvidence {
    pub identity: AllocationIdentity,
    pub scope: AllocationScope,
    pub domain: PortDomainEvidence,
    pub step: i16,
    pub public_ip: IpAddr,
    pub last_port: u16,
    pub sampled_at_ms: u64,
    pub last_send_at_ms: u64,
    pub completed_at_ms: u64,
    pub sample_count: u8,
    pub socket_count: u8,
    pub destination_count: u8,
}

/// Infer a range only from an actual wrap and a unique compatible boundary.
/// Ordinary positive/negative sequences do not justify a 65536 or 64512 ring.
pub fn infer_port_domain(
    sequence: &[u16],
) -> Result<(i16, PortDomainEvidence), AllocationEvidenceRejection> {
    use AllocationEvidenceRejection as Reject;
    if sequence.len() < 3 || sequence.len() > MAX_ALLOCATION_SAMPLES || sequence.contains(&0) {
        return Err(Reject::SampleCount);
    }
    let deltas = sequence
        .windows(2)
        .map(|p| i32::from(p[1]) - i32::from(p[0]))
        .collect::<Vec<_>>();
    let ordinary = deltas
        .iter()
        .copied()
        .filter(|d| *d != 0 && d.abs() <= MAX_STEP)
        .collect::<Vec<_>>();
    let Some(&step) = ordinary.first() else {
        return Err(Reject::NoConsistentStep);
    };
    if ordinary.len() < 2 || ordinary.iter().any(|d| *d != step) {
        return Err(Reject::NoConsistentStep);
    }
    if deltas.iter().all(|d| *d == step) {
        return Ok((step as i16, PortDomainEvidence::Unobserved));
    }
    let wraps = deltas
        .iter()
        .copied()
        .filter(|d| *d != step)
        .collect::<Vec<_>>();
    if wraps.iter().any(|d| d.signum() == step.signum() || *d == 0) {
        return Err(Reject::NoConsistentStep);
    }
    let width = (wraps[0] - step).abs();
    if width <= MAX_STEP || width > 65_535 || wraps.iter().any(|d| (*d - step).abs() != width) {
        return Err(Reject::AmbiguousPortDomain);
    }
    let min = i32::from(*sequence.iter().min().ok_or(Reject::SampleCount)?);
    let max = i32::from(*sequence.iter().max().ok_or(Reject::SampleCount)?);
    let lower_min = 1.max(max - width + 1);
    let lower_max = min.min(65_536 - width);
    if lower_min != lower_max {
        return Err(Reject::AmbiguousPortDomain);
    }
    let domain = PortDomainEvidence::ObservedRange {
        first: lower_min as u16,
        last: (lower_min + width - 1) as u16,
    };
    if !sequence
        .windows(2)
        .all(|p| domain.advance(p[0], i64::from(step)) == Some(p[1]))
    {
        return Err(Reject::AmbiguousPortDomain);
    }
    Ok((step as i16, domain))
}

/// Accept complete, serially observed new pairs only. A timeout/gap or a
/// repeated pair cannot silently become an extra allocation in this model.
pub fn infer_scoped_allocation(
    samples: &[AllocationSample],
    identity: AllocationIdentity,
    now_ms: u64,
    max_age: Duration,
) -> Result<ScopedAllocationEvidence, AllocationEvidenceRejection> {
    use AllocationEvidenceRejection as Reject;
    if !(4..=MAX_ALLOCATION_SAMPLES).contains(&samples.len()) {
        return Err(Reject::SampleCount);
    }
    let first = &samples[0].observation;
    if first.sent_at_ms > now_ms || now_ms - first.sent_at_ms > max_age.as_millis() as u64 {
        return Err(Reject::Stale);
    }
    let mut sockets = HashMap::new();
    let mut pairs = HashSet::new();
    let mut destinations = HashSet::new();
    let mut previous = None::<&MappingObservation>;
    for sample in samples {
        let obs = &sample.observation;
        if obs.responded_at_ms == 0
            || obs.responded_at_ms < obs.sent_at_ms
            || obs.responded_at_ms > now_ms
            || obs.observer.port() == 0
            || obs.local_endpoint.port() == 0
            || previous.is_some_and(|prev| {
                obs.sequence != prev.sequence.saturating_add(1)
                    || obs.sent_at_ms < prev.responded_at_ms
            })
        {
            return Err(Reject::InconsistentOrder);
        }
        if obs.observed.ip() != first.observed.ip() {
            return Err(Reject::PublicIpChanged);
        }
        if sockets
            .insert(sample.socket_id, obs.local_endpoint)
            .is_some_and(|endpoint| endpoint != obs.local_endpoint)
            || !pairs.insert((sample.socket_id, obs.observer))
        {
            return Err(Reject::ReusedMappingPair);
        }
        destinations.insert(obs.observer);
        previous = Some(obs);
    }
    if sockets.values().copied().collect::<HashSet<_>>().len() != sockets.len() {
        return Err(Reject::ReusedMappingPair);
    }
    let scope = if sockets.len() == 1 {
        AllocationScope::SameSocketMultipleDestinations
    } else if destinations.len() == 1 {
        AllocationScope::MultipleSocketsFixedDestination
    } else {
        let ips = destinations
            .iter()
            .map(SocketAddr::ip)
            .collect::<HashSet<_>>();
        let socket_ids = sockets.keys().copied().collect::<Vec<_>>();
        let grid = socket_ids.iter().enumerate().any(|(i, a)| {
            socket_ids.iter().skip(i + 1).any(|b| {
                destinations
                    .iter()
                    .filter(|dst| pairs.contains(&(*a, **dst)) && pairs.contains(&(*b, **dst)))
                    .map(SocketAddr::ip)
                    .collect::<HashSet<_>>()
                    .len()
                    >= 2
            })
        });
        if ips.len() < 2 || !grid {
            return Err(Reject::ScopeUnproven);
        }
        AllocationScope::ObservedSharedSequence
    };
    let ports = samples
        .iter()
        .map(|s| s.observation.observed.port())
        .collect::<Vec<_>>();
    let (step, domain) = infer_port_domain(&ports)?;
    let last = &samples[samples.len() - 1].observation;
    Ok(ScopedAllocationEvidence {
        identity,
        scope,
        domain,
        step,
        public_ip: first.observed.ip(),
        last_port: last.observed.port(),
        sampled_at_ms: first.sent_at_ms,
        last_send_at_ms: last.sent_at_ms,
        completed_at_ms: last.responded_at_ms,
        sample_count: samples.len() as u8,
        socket_count: sockets.len() as u8,
        destination_count: destinations.len() as u8,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedAnchorPlan {
    pub local_anchor: SocketAddr,
    pub socket_count: u8,
    /// Covered allocation count BEFORE the first socket sends. This does not
    /// cover allocations interleaved among the K socket sends.
    pub max_prefix_allocations: u8,
}

/// All sockets send the same remote anchor, then repeat those exact pairs.
/// For K consecutive socket allocations after a prefix d in [0,D], choosing
/// allocation D+1 lies in every [d+1,d+K] iff D<K. A foreign allocation DURING
/// those K sends can consume the anchor itself even when total foreign
/// consumption <=D. Neither bounded background drift nor an uninterrupted
/// allocation burst is established by STUN evidence; this is a conditional
/// attempt, not a guarantee of tolerance to arbitrary shared-NAT traffic.
pub fn plan_fixed_anchor(
    evidence: &ScopedAllocationEvidence,
    identity: AllocationIdentity,
    now_ms: u64,
    max_age: Duration,
    socket_count: usize,
    max_prefix_allocations: usize,
) -> Result<FixedAnchorPlan, AllocationEvidenceRejection> {
    use AllocationEvidenceRejection as Reject;
    if evidence.identity != identity {
        return Err(Reject::IdentityChanged);
    }
    if now_ms < evidence.sampled_at_ms
        || now_ms.saturating_sub(evidence.sampled_at_ms) > max_age.as_millis() as u64
    {
        return Err(Reject::Stale);
    }
    if evidence.scope != AllocationScope::ObservedSharedSequence {
        return Err(Reject::ScopeUnproven);
    }
    if !matches!(socket_count, 2 | 4 | 8) {
        return Err(Reject::InvalidSocketCount);
    }
    if max_prefix_allocations >= socket_count {
        return Err(Reject::DriftExceedsCoverage);
    }
    let port = evidence
        .domain
        .advance(
            evidence.last_port,
            i64::from(evidence.step) * (max_prefix_allocations + 1) as i64,
        )
        .ok_or(Reject::AmbiguousPortDomain)?;
    Ok(FixedAnchorPlan {
        local_anchor: SocketAddr::new(evidence.public_ip, port),
        socket_count: socket_count as u8,
        max_prefix_allocations: max_prefix_allocations as u8,
    })
}
