impl Daemon {
    /// Apply a barrier while the caller continues polling the existing work
    /// lanes. A short local lock wait must not turn into a full server lease
    /// retry, but neither wire time nor contention may extend this round.
    async fn apply_hard_hard_barrier_signal(
        &self,
        peer_id: &str,
        coordination: &HardHardCoordination,
        candidates: &[String],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
    ) -> control::SignalApplyOutcome {
        let now = Instant::now();
        let Some(remaining) = punch_at_ms
            .and_then(|deadline| deadline.checked_sub(hard_hard_now_ms()))
            .filter(|remaining| *remaining > 0)
        else {
            return control::SignalApplyOutcome::TerminalRejected;
        };
        let wire_upper = now + Duration::from_millis(remaining).min(HARD_HARD_PUNCH_LEAD);
        let application = async {
            let Some(record) = self
                .peers
                .hard_hard_session_by_token(peer_id, &coordination.token)
                .await
            else {
                return false;
            };
            let Some(plan) = record.coordinated_plan.as_ref() else {
                return false;
            };
            let deadline = wire_upper.min(plan.scheduled_start);
            if deadline <= Instant::now() || record.cancellation.is_cancelled() {
                return false;
            }
            tokio::select! {
                biased;
                _ = record.cancellation.cancelled() => false,
                _ = tokio::time::sleep_until(deadline.into()) => false,
                // This re-reads the live token and checks both registration,
                // network/profile generations and the canonical transcript.
                accepted = self.accept_hard_hard_ready_signal(
                    peer_id, coordination, candidates, punch_at_server_ms) => accepted,
            }
        };
        let mut shutdown = self.shutdown_rx.clone();
        let mut task_shutdown = self.task_manager.shutdown_rx();
        tokio::pin!(application);
        loop {
            if *shutdown.borrow() || *task_shutdown.borrow() {
                return control::SignalApplyOutcome::TerminalRejected;
            }
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() { return control::SignalApplyOutcome::TerminalRejected; }
                }
                changed = task_shutdown.changed() => {
                    if changed.is_err() { return control::SignalApplyOutcome::TerminalRejected; }
                }
                _ = tokio::time::sleep_until(wire_upper.into()) => {
                    return control::SignalApplyOutcome::TerminalRejected;
                }
                accepted = &mut application => {
                    return if accepted { control::SignalApplyOutcome::Applied }
                        else { control::SignalApplyOutcome::TerminalRejected };
                }
            }
        }
    }
}
