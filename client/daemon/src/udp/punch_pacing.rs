//! One bounded clock for every worker in a Hard↔Hard sweep. Reservations
//! contain no packets and never hold a lock while waiting or sending.

use super::*;

const HARD_HARD_PROBE_SPACING: Duration = Duration::from_millis(5);

/// Scheduling allowance for the bounded first wave, before the immutable
/// forecast expires. Admission contention may still reject sends; this is
/// not a credit reservation and never extends the physical-send deadline.
pub(crate) fn hard_hard_first_wave_pacing_margin(new_pairs: usize) -> Duration {
    HARD_HARD_PROBE_SPACING
        .max(OUTBOUND_CONNECTIVITY_PROBE_PRODUCTION_SPACING)
        .saturating_mul(new_pairs.min(32) as u32)
        + Duration::from_millis(50)
}

pub(super) struct HardHardProbePacer {
    state: StdMutex<HardHardProbePacerState>,
    deadline: tokio::time::Instant,
}

struct HardHardProbePacerState {
    next: tokio::time::Instant,
    stop: Option<probe_budget::OutboundProbeSweepStop>,
}

impl HardHardProbePacer {
    pub(super) fn new() -> Self {
        Self::with_window(crate::HARD_HARD_SWEEP_DEADLINE)
    }

    fn with_window(window: Duration) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            state: StdMutex::new(HardHardProbePacerState {
                next: now,
                stop: None,
            }),
            deadline: now + window,
        }
    }

    /// At most the bounded socket worker count can reserve future slots.
    /// Dropping a cancelled wait merely leaves an unused slot; no permit or
    /// budget is consumed. Executor stalls can release at most the bounded
    /// worker count together; the shared admission budget still applies.
    pub(super) async fn wait_turn(&self) -> bool {
        let slot = {
            let now = tokio::time::Instant::now();
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.stop.is_some() {
                return false;
            }
            let slot = state.next.max(now);
            if slot >= self.deadline {
                return false;
            }
            state.next = slot + HARD_HARD_PROBE_SPACING;
            slot
        };
        tokio::time::sleep_until(slot).await;
        self.stop_reason().is_none() && tokio::time::Instant::now() < self.deadline
    }

    pub(super) fn stop(&self, reason: probe_budget::OutboundProbeSweepStop) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.stop = state.stop.max(Some(reason));
    }

    pub(super) fn stop_reason(&self) -> Option<probe_budget::OutboundProbeSweepStop> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).stop
    }
}

impl OutboundProbeAdmission {
    /// Only the one-second sliding windows can recover within this sweep.
    /// Persistent limits and quarantine are terminal for a target; exact
    /// recovery verdicts stop the sweep. Lock contention can defer admission
    /// without consuming credit, but still uses the original pacing deadline.
    pub(super) fn retryable_in_sweep(self) -> bool {
        matches!(
            self,
            Self::NetworkRateLimited
                | Self::PeerRateLimited
                | Self::RemoteIpRateLimited
                | Self::GlobalNetworkRateLimited
                | Self::GlobalPeerRateLimited
                | Self::GlobalRemoteIpRateLimited
                | Self::GlobalDestinationRateLimited
                | Self::HardHardConfirmationRateReserved
                | Self::AdmissionDeferred
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn hard_hard_pacing_bounds_512_slots_and_aggregate_rate() {
        let pacer = Arc::new(HardHardProbePacer::new());
        let start = tokio::time::Instant::now();
        let mut workers = JoinSet::new();
        for _ in 0..8 {
            let pacer = pacer.clone();
            workers.spawn(async move {
                let mut sent = Vec::new();
                for _ in 0..64 {
                    assert!(pacer.wait_turn().await);
                    sent.push(tokio::time::Instant::now());
                }
                sent
            });
        }
        let mut sent = Vec::new();
        while let Some(result) = workers.join_next().await {
            sent.extend(result.unwrap());
        }
        sent.sort_unstable();
        assert_eq!(sent.len(), 512);
        for time in &sent {
            let count = sent
                .iter()
                .filter(|other| **other >= *time && **other < *time + Duration::from_secs(1))
                .count();
            assert!(count <= OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP);
        }
        assert!(sent[511] - start < crate::HARD_HARD_SWEEP_DEADLINE);
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_pacing_cancellation_and_deadline_release_all_waits() {
        let pacer = HardHardProbePacer::with_window(Duration::from_millis(10));
        assert!(pacer.wait_turn().await);
        let mut cancelled = Box::pin(pacer.wait_turn());
        assert!(futures_util::poll!(&mut cancelled).is_pending());
        drop(cancelled);
        assert!(!pacer.wait_turn().await);
        tokio::time::advance(Duration::from_millis(20)).await;
        assert!(!pacer.wait_turn().await);
    }

    #[test]
    fn hard_hard_pacing_never_retries_persistent_or_epoch_limits() {
        for admission in [
            OutboundProbeAdmission::GlobalNetworkPersistentRateLimited,
            OutboundProbeAdmission::GlobalPeerPersistentRateLimited,
            OutboundProbeAdmission::GlobalRemoteIpPersistentRateLimited,
            OutboundProbeAdmission::GlobalDestinationPersistentRateLimited,
            OutboundProbeAdmission::GlobalPeerSocketPersistentRateLimited,
            OutboundProbeAdmission::EpochCreditExhausted,
            OutboundProbeAdmission::HardHardConfirmationCreditReserved,
            OutboundProbeAdmission::HardHardRecoveryConfirmationReserved,
            OutboundProbeAdmission::RecoveryIdentityStale,
            OutboundProbeAdmission::HeartbeatBudgetLimited,
            OutboundProbeAdmission::Accepted,
        ] {
            assert!(!admission.retryable_in_sweep());
        }
        assert!(OutboundProbeAdmission::GlobalRemoteIpRateLimited.retryable_in_sweep());
        assert!(OutboundProbeAdmission::HardHardConfirmationRateReserved.retryable_in_sweep());
        assert!(OutboundProbeAdmission::AdmissionDeferred.retryable_in_sweep());
        assert_eq!(
            OutboundProbeAdmission::HardHardRecoveryConfirmationReserved.sweep_stop(),
            Some(probe_budget::OutboundProbeSweepStop::ConfirmationCreditReserved),
        );
        for admission in [
            OutboundProbeAdmission::GlobalRemoteIpRateLimited,
            OutboundProbeAdmission::HardHardConfirmationRateReserved,
            OutboundProbeAdmission::HardHardConfirmationCreditReserved,
            OutboundProbeAdmission::GlobalDestinationPersistentRateLimited,
            OutboundProbeAdmission::AdmissionDeferred,
        ] {
            assert_eq!(admission.sweep_stop(), None);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_recovery_verdict_stops_reserved_and_future_worker_slots() {
        let pacer = HardHardProbePacer::new();
        assert!(pacer.wait_turn().await);
        let mut waiting = Box::pin(pacer.wait_turn());
        assert!(futures_util::poll!(&mut waiting).is_pending());
        let stop = probe_budget::OutboundProbeSweepStop::ConfirmationCreditReserved;
        pacer.stop(stop);
        tokio::time::advance(HARD_HARD_PROBE_SPACING).await;
        assert!(!waiting.await);
        assert!(!pacer.wait_turn().await);
        assert_eq!(pacer.stop_reason(), Some(stop));
    }
}
