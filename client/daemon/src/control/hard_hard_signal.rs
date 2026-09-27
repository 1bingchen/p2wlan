//! Lifetime of the final HH2 acknowledgement in the existing Control queue.
//! The peer must receive the ACK; this endpoint need not wait for the POST
//! response, which may arrive after its peer has already received the signal.
use super::*;

#[derive(Debug)]
struct DeliveryState {
    response: Option<oneshot::Receiver<PeerOfferSendOutcome>>,
    accepted: bool,
}

/// One bounded receipt lease per HH plan. Dropping its last owner closes the
/// response channel and cancels queued/in-flight work in the existing worker.
#[derive(Debug)]
pub(crate) struct HardHardStartAckDelivery(std::sync::Mutex<DeliveryState>);

impl HardHardStartAckDelivery {
    /// Advisory evidence for terminal classification, never a Direct grant.
    pub(crate) fn server_accepted(&self) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return false;
        };
        if let Some(response) = state.response.as_mut() {
            match response.try_recv() {
                Ok(outcome) => {
                    state.accepted = outcome == PeerOfferSendOutcome::Sent;
                    state.response = None;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    state.response = None;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
        }
        state.accepted
    }
}

impl ControlClient {
    /// READY/READY_ACK/SYNC use the same immutable, registration-bound queue
    /// ownership as initial HH2 signals. Their existing phase owner controls
    /// retries; this command spends exactly its one already-paid HTTP attempt.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_hard_hard_barrier(
        &self,
        peer: &str,
        candidates: &[String],
        sources: &HashMap<String, String>,
        local_time_ms: u64,
        server_time_ms: u64,
        session_id: String,
        ownership: Arc<crate::PunchSessionCancellation>,
        deadline: Instant,
        registration_seq: u64,
    ) -> std::result::Result<(), PeerOfferSendFailure> {
        self.send_hard_hard_prepaid_signal(
            peer,
            candidates,
            sources,
            local_time_ms,
            server_time_ms,
            session_id,
            ownership,
            deadline,
            1,
            registration_seq,
            Some(Duration::from_millis(400)),
        )
        .await
    }

    /// OFFER/ANSWER retries retain one prepared wire payload in the existing
    /// per-peer worker. Queue contention is bounded by the original plan;
    /// every possible HTTP attempt was prepaid by the recovery owner.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_hard_hard_initial_offer(
        &self,
        peer: &str,
        candidates: &[String],
        sources: &HashMap<String, String>,
        local_time_ms: u64,
        server_time_ms: u64,
        session_id: String,
        ownership: Arc<crate::PunchSessionCancellation>,
        deadline: Instant,
        prepaid_attempts: u8,
        registration_seq: u64,
    ) -> std::result::Result<(), PeerOfferSendFailure> {
        self.send_hard_hard_prepaid_signal(
            peer,
            candidates,
            sources,
            local_time_ms,
            server_time_ms,
            session_id,
            ownership,
            deadline,
            prepaid_attempts,
            registration_seq,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_hard_hard_prepaid_signal(
        &self,
        peer: &str,
        candidates: &[String],
        sources: &HashMap<String, String>,
        local_time_ms: u64,
        server_time_ms: u64,
        session_id: String,
        ownership: Arc<crate::PunchSessionCancellation>,
        deadline: Instant,
        prepaid_attempts: u8,
        registration_seq: u64,
        attempt_timeout: Option<Duration>,
    ) -> std::result::Result<(), PeerOfferSendFailure> {
        if !(1..=2).contains(&prepaid_attempts) || registration_seq == 0 {
            return Err(PeerOfferSendFailure::SendFailed);
        }
        if ownership.is_cancelled()
            || Instant::now() >= deadline
            || self.local_hh2_registration_seq() != Some(registration_seq)
        {
            return Err(PeerOfferSendFailure::Cancelled);
        }
        #[cfg(test)]
        for attempt in 0..prepaid_attempts {
            if ownership.is_cancelled() || Instant::now() >= deadline {
                return Err(PeerOfferSendFailure::Cancelled);
            }
            let Some(result) = self.maybe_forward_test_signal(
                peer,
                candidates,
                sources,
                &[],
                Some(local_time_ms),
                Some(&session_id),
                Some(&ownership),
            ) else {
                break;
            };
            if result.is_ok() || attempt + 1 == prepaid_attempts {
                return result;
            }
        }
        let permit = tokio::select! {
            biased;
            _ = ownership.cancelled() => return Err(PeerOfferSendFailure::Cancelled),
            _ = tokio::time::sleep_until(deadline.into()) => return Err(PeerOfferSendFailure::Cancelled),
            permit = self.candidate_offer_tx.reserve() => permit.map_err(|_| PeerOfferSendFailure::ChannelClosed)?,
        };
        if ownership.is_cancelled()
            || Instant::now() >= deadline
            || self.local_hh2_registration_seq() != Some(registration_seq)
        {
            return Err(PeerOfferSendFailure::Cancelled);
        }
        let (response_tx, response_rx) = oneshot::channel();
        permit.send(CandidateOfferCommand {
            expected_registration_seq: Some(registration_seq),
            not_after: Some(deadline),
            attempt_timeout,
            prepaid_attempts,
            to_node_id: peer.to_owned(),
            candidates: candidates.to_vec(),
            session_id: Some(session_id),
            probe_ephemeral_public_key: None,
            candidate_sources: sources.clone(),
            handshake_init: Vec::new(),
            punch_at_ms: Some(local_time_ms),
            punch_at_server_ms: Some(server_time_ms),
            fresh_ownership: Some(ownership.clone()),
            response_tx,
        });
        tokio::select! {
            biased;
            _ = ownership.cancelled() => Err(PeerOfferSendFailure::Cancelled),
            _ = tokio::time::sleep_until(deadline.into()) => Err(PeerOfferSendFailure::Cancelled),
            result = response_rx => match result {
                Ok(PeerOfferSendOutcome::Sent) => Ok(()),
                Ok(PeerOfferSendOutcome::Cancelled) => Err(PeerOfferSendFailure::Cancelled),
                Ok(PeerOfferSendOutcome::Failed) => Err(PeerOfferSendFailure::SendFailed),
                Err(_) => Err(PeerOfferSendFailure::ChannelClosed),
            },
        }
    }

    /// The caller owns the already authenticated, agreed SYNC transcript.
    /// Only its final ACK may use queue admission instead of HTTP completion:
    /// the initiator still waits for actual peer delivery before sweeping.
    /// Every permitted HTTP attempt must already be charged to the same
    /// recovery epoch; the worker cannot request credits or extend deadline.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn queue_hard_hard_start_ack(
        &self,
        peer: &str,
        candidates: &[String],
        sources: &HashMap<String, String>,
        local_time_ms: u64,
        server_time_ms: u64,
        session_id: String,
        ownership: Arc<crate::PunchSessionCancellation>,
        deadline: Instant,
        prepaid_attempts: u8,
        registration_seq: u64,
    ) -> std::result::Result<Arc<HardHardStartAckDelivery>, PeerOfferSendFailure> {
        if !(1..=HARD_HARD_START_ACK_MAX_ATTEMPTS).contains(&prepaid_attempts) {
            return Err(PeerOfferSendFailure::SendFailed);
        }
        if ownership.is_cancelled()
            || Instant::now() >= deadline
            || registration_seq == 0
            || self.local_hh2_registration_seq() != Some(registration_seq)
        {
            return Err(PeerOfferSendFailure::Cancelled);
        }
        let (response_tx, response_rx) = oneshot::channel();
        #[cfg(test)]
        if let Some(result) = self.maybe_forward_test_signal(
            peer,
            candidates,
            sources,
            &[],
            Some(local_time_ms),
            Some(&session_id),
            Some(&ownership),
        ) {
            result?;
            let _ = response_tx.send(PeerOfferSendOutcome::Sent);
            return Ok(Arc::new(HardHardStartAckDelivery(std::sync::Mutex::new(
                DeliveryState {
                    response: Some(response_rx),
                    accepted: false,
                },
            ))));
        }
        // Keep this one prepaid ACK in its caller's existing bounded owner.
        // Queue pressure cannot spend a second reservation or rebuild its
        // transcript; dropping this future drops the queue reservation too.
        let permit = tokio::select! {
            biased;
            _ = ownership.cancelled() => return Err(PeerOfferSendFailure::Cancelled),
            _ = tokio::time::sleep_until(deadline.into()) => return Err(PeerOfferSendFailure::Cancelled),
            permit = self.candidate_offer_tx.reserve() => permit.map_err(|_| PeerOfferSendFailure::ChannelClosed)?,
        };
        if ownership.is_cancelled()
            || Instant::now() >= deadline
            || self.local_hh2_registration_seq() != Some(registration_seq)
        {
            return Err(PeerOfferSendFailure::Cancelled);
        }
        permit.send(CandidateOfferCommand {
            expected_registration_seq: Some(registration_seq),
            not_after: Some(deadline),
            attempt_timeout: None,
            prepaid_attempts,
            to_node_id: peer.to_owned(),
            candidates: candidates.to_vec(),
            session_id: Some(session_id),
            probe_ephemeral_public_key: None,
            candidate_sources: sources.clone(),
            handshake_init: Vec::new(),
            punch_at_ms: Some(local_time_ms),
            punch_at_server_ms: Some(server_time_ms),
            fresh_ownership: Some(ownership),
            response_tx,
        });
        Ok(Arc::new(HardHardStartAckDelivery(std::sync::Mutex::new(
            DeliveryState {
                response: Some(response_rx),
                accepted: false,
            },
        ))))
    }
}
