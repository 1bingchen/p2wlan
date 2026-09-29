/// Observation ownership follows the existing HH record and its worker snapshots.
/// It never authorizes a packet, a retry or a path transition. No global history
/// map or task is created; the last record/worker snapshot releases the data.
#[derive(Debug, Clone, Default)]
pub(crate) struct HardHardAttemptEvidence(Arc<std::sync::Mutex<HardHardAttemptEvidenceState>>);

// Equality is observation-owner identity, including before binding; cloned
// measurement snapshots compare equal, unrelated empty measurements do not.
impl PartialEq for HardHardAttemptEvidence {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for HardHardAttemptEvidence {}

/// Own a sealed terminal observation across the bounded commit await. Dropping
/// that future cannot lose a cancelled attempt or publish into a new peer.
struct HardHardTerminalObservation {
    report: Option<HardHardAttemptReport>,
    peer_id: String,
    timeline: Option<Arc<ConnectionTimeline>>,
}

impl HardHardTerminalObservation {
    fn archive(&mut self, reason: &'static str) {
        if let Some(report) = self.report.take() {
            if let Some(timeline) = self.timeline.as_ref() {
                timeline.record_hard_hard_terminal(&self.peer_id, &report, false, Some(reason));
            }
            if let Ok(json) = serde_json::to_string(&report) {
                tracing::info!(event = "hard_hard_attempt_report_archived",
                    reason_code = reason, session_tag = %report.session_tag,
                    network_generation = report.network_generation,
                    current_connection_committed = false, report_json = %json,
                    "historical Hard-Hard terminal evidence; not a current connection report");
            }
        }
    }
}

impl Drop for HardHardTerminalObservation {
    fn drop(&mut self) {
        self.archive("commit_future_cancelled");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HardHardObservationIdentity {
    session_id: String,
    socket: HardHardFreshSocketIdentity,
    peer_session: PeerSessionGeneration,
    socket_indices: Vec<usize>,
}

#[derive(Debug, Default)]
struct HardHardAttemptEvidenceState {
    identity: Option<HardHardObservationIdentity>,
    attempt: u8,
    strategy: Option<HardHardProbeStrategy>,
    frozen: bool,
    sealed: bool,
    received: crate::udp::UdpProbeRxSnapshot,
    pairs: Vec<(HardHardPairKey, crate::udp::UdpProbeRxSnapshot)>,
    confirmation: Option<HardHardConfirmationCosts>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum HardHardReceiveObservation {
    AuthenticatedPunch,
    AuthenticatedAck,
    MatchedAck,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum HardHardConfirmationPurpose {
    TriggeredCheck,
    Nomination,
    ProbeAck,
    ValidationRequest,
    ValidationAck,
}

fn update_hard_hard_received(
    snapshot: &mut crate::udp::UdpProbeRxSnapshot,
    observation: HardHardReceiveObservation,
    at_ms: u64,
) {
    match observation {
        HardHardReceiveObservation::AuthenticatedPunch
        | HardHardReceiveObservation::AuthenticatedAck => {
            // Only attributable, token-authenticated datagrams enter the HH
            // packet total. Peer-IP-only traffic remains in ordinary metrics.
            snapshot.known_peer_ip_datagrams_received =
                snapshot.known_peer_ip_datagrams_received.saturating_add(1);
            snapshot.authenticated_probe_packets_received = snapshot
                .authenticated_probe_packets_received
                .saturating_add(1);
            snapshot.last_authenticated_at_ms = Some(at_ms);
            if matches!(observation, HardHardReceiveObservation::AuthenticatedAck) {
                snapshot.authenticated_probe_acks_observed =
                    snapshot.authenticated_probe_acks_observed.saturating_add(1);
            }
        }
        HardHardReceiveObservation::MatchedAck => {
            snapshot.probe_acks_received = snapshot.probe_acks_received.saturating_add(1);
            snapshot.last_matched_ack_at_ms = Some(at_ms);
        }
    }
    snapshot.authenticated_probe_acks_unmatched = snapshot
        .authenticated_probe_acks_observed
        .saturating_sub(snapshot.probe_acks_received);
}

impl HardHardAttemptEvidence {
    fn bind(
        &mut self,
        identity: HardHardObservationIdentity,
        attempt: u8,
        strategy: Option<HardHardProbeStrategy>,
        hh2: bool,
    ) {
        // Cloning a record to create a replacement must not transfer its old
        // token's counters or terminal-report right to the replacement.
        let replace = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .identity
            .as_ref()
            .is_some_and(|old| old != &identity);
        if replace {
            *self = Self::default();
        }
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.identity = Some(identity);
        state.attempt = attempt;
        state.strategy = strategy;
        if hh2 && !state.frozen {
            state.confirmation.get_or_insert_with(Default::default);
        }
    }

    /// Mirror only an identity already committed by this record's owner (the
    /// admitted response epoch or authenticated winner), without reopening it.
    fn owner_committed_socket(&self, socket: &HardHardFreshSocketIdentity) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.frozen {
            return;
        }
        let Some(identity) = state.identity.as_mut() else {
            return;
        };
        if identity.socket.peer_id == socket.peer_id
            && identity.socket.session_token == socket.session_token
            && identity.socket.network_generation == socket.network_generation
            && identity.socket.local_profile_generation == socket.local_profile_generation
            && identity.socket.remote_profile_generation == socket.remote_profile_generation
            && identity.socket_indices.contains(&socket.socket_index)
        {
            identity.socket = socket.clone();
        }
    }

    pub(crate) fn socket_snapshot(&self) -> Option<HardHardFreshSocketIdentity> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .identity
            .as_ref()
            .map(|identity| identity.socket.clone())
    }

    pub(crate) fn peer_session_generation(&self) -> Option<PeerSessionGeneration> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .identity
            .as_ref()
            .map(|identity| identity.peer_session)
    }

    pub(crate) fn receive_snapshot(&self) -> crate::udp::UdpProbeRxSnapshot {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).received
    }

    /// The terminal learning decision and report share this same cutoff.
    /// Freezing never consumes the separate one-shot report publication right.
    pub(crate) fn freeze_receive_snapshot(
        &self,
        expected_socket: &HardHardFreshSocketIdentity,
        peer_session: PeerSessionGeneration,
        attempt: u8,
    ) -> Option<crate::udp::UdpProbeRxSnapshot> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.sealed
            || state.attempt != attempt
            || !state.identity.as_ref().is_some_and(|identity| {
                identity.peer_session == peer_session && identity.socket == *expected_socket
            })
        {
            return None;
        }
        state.frozen = true;
        Some(state.received)
    }

    pub(crate) fn confirmation_snapshot(&self) -> Option<HardHardConfirmationCosts> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .confirmation
            .clone()
    }

    fn begin_sweep(&self, attempt: u8, strategy: Option<HardHardProbeStrategy>) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.attempt = attempt;
        state.strategy = strategy;
    }

    fn record_receive(
        &self,
        pair: HardHardPairKey,
        observation: HardHardReceiveObservation,
        at_ms: u64,
    ) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.frozen
            || !state
                .identity
                .as_ref()
                .is_some_and(|identity| identity.socket_indices.contains(&pair.socket_index))
        {
            return;
        }
        update_hard_hard_received(&mut state.received, observation, at_ms);
        if let Some((_, received)) = state.pairs.iter_mut().find(|(key, _)| key == &pair) {
            update_hard_hard_received(received, observation, at_ms);
        } else if state.pairs.len() < HARD_HARD_PAIR_MAX_CANDIDATES {
            let mut received = crate::udp::UdpProbeRxSnapshot::default();
            update_hard_hard_received(&mut received, observation, at_ms);
            state.pairs.push((pair, received));
        }
    }

    /// Called synchronously beside a successful nonblocking kernel handoff.
    pub(crate) fn record_confirmation_handoff(
        &self,
        purpose: HardHardConfirmationPurpose,
        bytes: usize,
    ) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.frozen {
            return;
        }
        let Some(confirmation) = state.confirmation.as_mut() else {
            return;
        };
        let cost = match purpose {
            HardHardConfirmationPurpose::TriggeredCheck => &mut confirmation.triggered_check,
            HardHardConfirmationPurpose::Nomination => &mut confirmation.nomination,
            HardHardConfirmationPurpose::ProbeAck => &mut confirmation.probe_ack,
            HardHardConfirmationPurpose::ValidationRequest => &mut confirmation.validation_request,
            HardHardConfirmationPurpose::ValidationAck => &mut confirmation.validation_ack,
        };
        cost.datagrams = cost.datagrams.saturating_add(1);
        cost.bytes = cost.bytes.saturating_add(bytes as u64);
    }

    pub(crate) fn record_send_outcome(&self, outcome: HardHardPairSendOutcome) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.frozen {
            return;
        }
        let Some(confirmation) = state.confirmation.as_mut() else {
            return;
        };
        match outcome {
            HardHardPairSendOutcome::Sent => (),
            HardHardPairSendOutcome::RetryableNotSent => {
                confirmation.retryable_not_sent = confirmation.retryable_not_sent.saturating_add(1)
            }
            HardHardPairSendOutcome::BudgetDeferred => {
                confirmation.budget_deferred = confirmation.budget_deferred.saturating_add(1)
            }
            HardHardPairSendOutcome::DeliveryUnknown => {
                confirmation.delivery_unknown = confirmation.delivery_unknown.saturating_add(1)
            }
            HardHardPairSendOutcome::Stopped => {
                confirmation.stopped = confirmation.stopped.saturating_add(1)
            }
        }
    }

    /// Seal only an exact owner report, once, even if cleanup has removed the
    /// ledger. This permits historical cancellation evidence without granting
    /// an old worker authority over a replacement connection.
    pub(crate) fn seal_report(
        &self,
        peer: &str,
        token: &str,
        report: &mut HardHardAttemptReport,
    ) -> bool {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(identity) = state.identity.as_ref() else {
            return false;
        };
        let socket = &identity.socket;
        if state.sealed
            || socket.peer_id != peer
            || socket.session_token != token
            || socket.network_generation != report.network_generation
            || identity.peer_session.value() != report.peer_session_generation
            || socket.remote_candidate_epoch != report.remote_candidate_epoch
            || socket.local_profile_generation != report.local_profile_generation
            || socket.remote_profile_generation != report.remote_profile_generation
            || socket.punch_generation != report.punch_generation
            || !report
                .socket_index
                .is_some_and(|index| identity.socket_indices.contains(&index))
            || state.attempt != report.attempt
        {
            return false;
        }
        if let Some(strategy) = state.strategy {
            report.mode = match strategy {
                HardHardProbeStrategy::FixedAnchor => "fixed_anchor",
                HardHardProbeStrategy::Predictable => "predictable",
                HardHardProbeStrategy::Birthday => "birthday",
            }
            .to_string();
        }
        report.confirmation = state.confirmation.clone();
        state.frozen = true;
        state.sealed = true;
        true
    }
}

impl PeerManager {
    fn bind_hard_hard_observations(&self, record: &mut HardHardSessionRecord) {
        let Some(peer_session) = self.peer_session_generation_sync(&record.peer_id) else {
            return;
        };
        let identity = HardHardObservationIdentity {
            session_id: record.session_id.clone(),
            socket: record.fresh_socket.clone(),
            peer_session,
            socket_indices: record
                .requested_socket_indices
                .iter()
                .copied()
                .take(HARD_HARD_PAIR_MAX_CANDIDATES)
                .collect(),
        };
        record.measurement.evidence.bind(
            identity,
            record.attempt_count,
            record
                .coordinated_plan
                .as_ref()
                .and_then(|p| p.agreement.map(|a| a.strategy)),
            record.coordinated_plan.is_some(),
        );
    }

    /// Caller supplies the exact receiving socket after MAC verification. The
    /// active record fences token/lifecycle and socket index; the caller already
    /// verified the actual local/remote socket tuple. Normal peer counters never enter.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_hard_hard_receive(
        &self,
        peer: &str,
        token: &str,
        peer_session: PeerSessionGeneration,
        pair: HardHardPairKey,
        observation: HardHardReceiveObservation,
        at_ms: u64,
    ) {
        let sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
                && record.local_network_generation == self.current_network_generation_sync()
                && self.peer_session_is_current_sync(peer, peer_session)
                && record.requested_socket_indices.contains(&pair.socket_index)
        }) else {
            return;
        };
        record
            .measurement
            .evidence
            .record_receive(pair, observation, at_ms);
    }
}

#[cfg(test)]
#[path = "hard_hard_observation_tests.rs"]
mod hard_hard_observation_tests;
