/// Measured alternatives advertised by one endpoint. Prediction candidates
/// occupy a bounded prefix; the optional anchor must occur in the full set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HardHardOfferParameters {
    pub(crate) socket_count: u8,
    pub(crate) prediction_count: u8,
    pub(crate) anchor_port: u16,
}

impl HardHardOfferParameters {
    pub(crate) fn is_valid(self, candidates: &[SocketAddr]) -> bool {
        matches!(self.socket_count, 2 | 4 | 8)
            && self.prediction_count <= 32
            && usize::from(self.prediction_count) <= candidates.len()
            && !candidates.is_empty()
            && candidates.len() <= crate::MAX_SIGNAL_CANDIDATES
            && candidates.iter().copied().collect::<HashSet<_>>().len() == candidates.len()
            && candidates
                .iter()
                .all(|endpoint| endpoint.port() != 0 && endpoint.ip() == candidates[0].ip())
            && (self.anchor_port == 0 || candidates.iter().any(|p| p.port() == self.anchor_port))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HardHardProbeStrategy {
    Predictable = 1,
    FixedAnchor = 2,
    Birthday = 3,
}

impl HardHardProbeStrategy {
    #[cfg(test)]
    pub(crate) fn select(a: HardHardOfferParameters, b: HardHardOfferParameters) -> Self {
        Self::select_with_order(a, b, 0)
    }

    pub(crate) fn select_with_order(
        a: HardHardOfferParameters,
        b: HardHardOfferParameters,
        order: u8,
    ) -> Self {
        let choices = match order {
            1 => [Self::Predictable, Self::FixedAnchor, Self::Birthday],
            2 => [Self::Birthday, Self::Predictable, Self::FixedAnchor],
            _ => [Self::FixedAnchor, Self::Predictable, Self::Birthday],
        };
        choices
            .into_iter()
            .find(|strategy| match strategy {
                Self::FixedAnchor => a.anchor_port != 0 && b.anchor_port != 0,
                Self::Predictable => a.prediction_count != 0 && b.prediction_count != 0,
                Self::Birthday => true,
            })
            .unwrap_or(Self::Birthday)
    }

    pub(crate) fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Predictable),
            2 => Some(Self::FixedAnchor),
            3 => Some(Self::Birthday),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HardHardAgreedPlan {
    pub(crate) strategy: HardHardProbeStrategy,
    pub(crate) digest: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HardHardAgreedStart {
    pub(crate) server_time_ms: u64,
    pub(crate) agreement: HardHardAgreedPlan,
}

/// A final activation binds the already agreed transcript to an earlier
/// start. It cannot alter candidates, strategy, phase or the outer deadline.
pub(crate) fn hard_hard_start_agreement(
    base: HardHardAgreedPlan,
    server_time_ms: u64,
) -> HardHardAgreedPlan {
    use sha2::Digest as _;
    let mut hash = sha2::Sha256::new();
    hash.update(b"p2wlan/hh2/start/v1\0");
    hash.update(base.digest);
    hash.update([base.strategy as u8]);
    hash.update(server_time_ms.to_be_bytes());
    let hash = hash.finalize();
    let mut digest = [0; 16];
    digest.copy_from_slice(&hash[..16]);
    HardHardAgreedPlan {
        strategy: base.strategy,
        digest,
    }
}

/// One authoritative agreement, stored inside the existing HH session. Every
/// copy is a fenced snapshot; readiness never creates another session owner.
#[derive(Debug, Clone)]
pub(crate) struct HardHardCoordinatedPlan {
    pub(crate) measurement_lease: Option<crate::udp::HardHardMeasurementLease>,
    pub(crate) recovery_identity: Option<RecoveryEpochIdentity>,
    pub(crate) strategy_order: u8,
    pub(crate) local_offer: HardHardOfferParameters,
    pub(crate) remote_offer: Option<HardHardOfferParameters>,
    pub(crate) local_registration_seq: u64,
    pub(crate) remote_registration_seq: u64,
    pub(crate) phase: bool,
    pub(crate) canonical_server_deadline: u64,
    pub(crate) scheduled_start: Instant,
    /// Immutable upper bound for the first physical send of a predicted pair.
    /// SYNC may advance `scheduled_start`, but never renew this forecast.
    pub(crate) forecast_first_send_deadline: Instant,
    pub(crate) agreement: Option<HardHardAgreedPlan>,
    pub(crate) ready_received: bool,
    pub(crate) ready_ack_received: bool,
    pub(crate) ready_sent_at: Option<Instant>,
    /// An ACK after retransmission cannot identify which READY it answered.
    pub(crate) ready_retransmitted: bool,
    pub(crate) ready_rtt: Option<Duration>,
    pub(crate) sync_uncertainty: Duration,
    pub(crate) start: Option<HardHardAgreedStart>,
    pub(crate) start_ack_received: bool,
    pub(crate) start_ack_queued: bool,
    pub(crate) start_ack_delivery: Option<Arc<crate::control::HardHardStartAckDelivery>>,
}

impl HardHardCoordinatedPlan {
    pub(crate) fn ready(&self, initiator: bool) -> bool {
        self.agreement.is_some()
            && self.start.is_some()
            && if initiator {
                self.ready_ack_received && self.start_ack_received
            } else {
                self.ready_received && self.start_ack_queued
            }
    }

    pub(crate) fn remote_targets(&self, candidates: &[SocketAddr]) -> Option<Vec<SocketAddr>> {
        let remote = self.remote_offer?;
        if !remote.is_valid(candidates) {
            return None;
        }
        if self.agreement?.strategy
            != HardHardProbeStrategy::select_with_order(
                self.local_offer,
                remote,
                self.strategy_order,
            )
        {
            return None;
        }
        Some(match self.agreement?.strategy {
            HardHardProbeStrategy::FixedAnchor => vec![*candidates
                .iter()
                .find(|endpoint| endpoint.port() == remote.anchor_port)?],
            HardHardProbeStrategy::Predictable => {
                candidates[..usize::from(remote.prediction_count)].to_vec()
            }
            HardHardProbeStrategy::Birthday => candidates.to_vec(),
        })
    }
}

/// Convert the immutable wall-clock session expiry into a conservative
/// latest start. Both selection and activation use the full existing runtime
/// window. Selection adds its clock-conversion margin before publishing the
/// wire start; acceptance enforces this full window again. This is a derived
/// snapshot, never a renewed lifetime or another owner.
pub(crate) fn hard_hard_latest_start_for_session(
    expires_at_ms: u64,
    now_ms: u64,
    now: Instant,
) -> Option<Instant> {
    now.checked_add(Duration::from_millis(expires_at_ms.checked_sub(now_ms)?))?
        .checked_sub(crate::HARD_HARD_SWEEP_DEADLINE + crate::HARD_HARD_DIRECT_CONFIRMATION_GRACE)
}

impl PeerManager {
    /// The initial HH2 publication may retry once, but must leave the existing
    /// three READY and three SYNC/ACK credits available in this same epoch.
    pub(crate) async fn reserve_hard_hard_initial_signal_retry(
        &self,
        peer: &str,
        expected: RecoveryEpochIdentity,
    ) -> bool {
        let mut epochs = self.recovery_epochs.write().await;
        let Some(state) = epochs.get_mut(peer) else {
            return false;
        };
        if state.epoch != expected.epoch
            || state.network_generation != expected.network_generation
            || state.allocation_id != expected.allocation_id
            || state.epoch_http_quota_remaining
                <= u32::from(crate::HARD_HARD_BARRIER_MAX_ATTEMPTS)
                    + u32::from(crate::control::HARD_HARD_START_ACK_MAX_ATTEMPTS)
        {
            return false;
        }
        state.epoch_http_quota_remaining -= 1;
        true
    }

    pub(crate) async fn hard_hard_activate_start(
        &self,
        peer: &str,
        token: &str,
        start: HardHardAgreedStart,
    ) -> bool {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.state == HardHardSessionState::AwaitingPeer
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return false;
        };
        let now = Instant::now();
        let latest_start =
            hard_hard_latest_start_for_session(record.expires_at_ms, hard_hard_now_ms(), now);
        let Some(plan) = record.coordinated_plan.as_mut() else {
            return false;
        };
        let Some(base) = plan.agreement else {
            return false;
        };
        if !(if record.initiator {
            plan.ready_ack_received
        } else {
            plan.ready_received
        }) || start.server_time_ms == 0
            || start.server_time_ms > plan.canonical_server_deadline
            || start.agreement != hard_hard_start_agreement(base, start.server_time_ms)
        {
            return false;
        }
        let scheduled_start = if let Some(prior) = plan.start {
            if prior != start {
                return false;
            }
            plan.scheduled_start
        } else {
            let advance =
                Duration::from_millis(plan.canonical_server_deadline - start.server_time_ms);
            let Some(scheduled_start) = plan.scheduled_start.checked_sub(advance) else {
                return false;
            };
            scheduled_start
        };
        if now >= scheduled_start {
            return false;
        }
        if latest_start.is_none_or(|latest| scheduled_start > latest) {
            // No await or new lock dependency while retaining the HH ledger.
            // Release it before best-effort diagnostic publication.
            drop(sessions);
            self.record_direct_event_non_queuing(
                peer,
                "hard_hard_start_rejected",
                None,
                None,
                None,
                "reason_code=confirmation_window_exceeds_session_ttl",
            );
            return false;
        }
        if plan.start.is_some() {
            return true;
        }
        plan.scheduled_start = scheduled_start;
        plan.start = Some(start);
        // Keep the observation on the same monotonic timeline as the agreed
        // activation; do not report deviation against the superseded upper bound.
        record.measurement.planned_send_at_ms =
            record.measurement.planned_send_at_ms.map(|value| {
                value.saturating_sub(plan.canonical_server_deadline - start.server_time_ms)
            });
        true
    }

    pub(crate) async fn hard_hard_confirm_start(
        &self,
        peer: &str,
        token: &str,
        start: HardHardAgreedStart,
        received: bool,
        delivery: Option<Arc<crate::control::HardHardStartAckDelivery>>,
    ) -> bool {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.initiator == received
                && record.state == HardHardSessionState::AwaitingPeer
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return false;
        };
        let Some(plan) = record.coordinated_plan.as_mut() else {
            return false;
        };
        if plan.start != Some(start) || Instant::now() >= plan.scheduled_start {
            return false;
        }
        if received {
            plan.start_ack_received = true;
        } else {
            let Some(delivery) = delivery else {
                return false;
            };
            plan.start_ack_delivery = Some(delivery);
            plan.start_ack_queued = true;
        }
        true
    }

    pub(crate) async fn hard_hard_agree_plan(
        &self,
        peer: &str,
        token: &str,
        remote_offer: HardHardOfferParameters,
        agreement: HardHardAgreedPlan,
        remote_prediction: &[SocketAddr],
        remote_network_generation: u64,
        remote_confidence: u8,
        sync_uncertainty: Duration,
    ) -> Option<HardHardSessionRecord> {
        if !remote_offer.is_valid(remote_prediction) {
            return None;
        }
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.state == HardHardSessionState::AwaitingPeer
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return None;
        };
        let Some(plan) = record.coordinated_plan.as_mut() else {
            return None;
        };
        if remote_network_generation == 0
            || remote_confidence == 0
            || (record.remote_network_generation != 0
                && record.remote_network_generation != remote_network_generation)
        {
            return None;
        }
        if plan.agreement.is_some_and(|prior| prior != agreement)
            || plan.remote_offer.is_some_and(|prior| prior != remote_offer)
            || (plan.agreement.is_some()
                && (record.remote_prediction != remote_prediction
                    || record.remote_prediction_confidence != remote_confidence))
            || agreement.strategy
                != HardHardProbeStrategy::select_with_order(
                    plan.local_offer,
                    remote_offer,
                    plan.strategy_order,
                )
        {
            return None;
        }
        plan.remote_offer = Some(remote_offer);
        plan.agreement = Some(agreement);
        plan.sync_uncertainty = sync_uncertainty;
        record.remote_prediction = remote_prediction.to_vec();
        record.remote_network_generation = remote_network_generation;
        record.remote_prediction_confidence = remote_confidence;
        // The next owner must fence against this committed snapshot, not the
        // pre-ANSWER values which this transaction deliberately replaced.
        Some(record.clone())
    }

    pub(crate) async fn hard_hard_mark_ready_sent(&self, peer: &str, token: &str) -> bool {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.initiator
                && record.state == HardHardSessionState::AwaitingPeer
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return false;
        };
        let Some(plan) = record.coordinated_plan.as_mut() else {
            return false;
        };
        if plan.agreement.is_none() {
            return false;
        }
        if plan.ready_sent_at.is_some() {
            plan.ready_retransmitted = true;
        } else {
            plan.ready_sent_at = Some(Instant::now());
        }
        true
    }

    /// READY is a control-plane acknowledgement, never a candidate update.
    /// The caller checks sender and wire identity before entering this reducer.
    pub(crate) async fn hard_hard_accept_ready(
        &self,
        peer: &str,
        token: &str,
        agreement: HardHardAgreedPlan,
        acknowledgement: bool,
    ) -> bool {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.initiator == acknowledgement
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return false;
        };
        let Some(plan) = record.coordinated_plan.as_mut() else {
            return false;
        };
        if plan.agreement != Some(agreement) || Instant::now() >= plan.scheduled_start {
            return false;
        }
        if acknowledgement {
            let Some(sent_at) = plan.ready_sent_at else {
                return false;
            };
            plan.ready_rtt.get_or_insert_with(|| sent_at.elapsed());
            plan.ready_ack_received = true;
        } else {
            plan.ready_received = true;
        }
        true
    }
}
