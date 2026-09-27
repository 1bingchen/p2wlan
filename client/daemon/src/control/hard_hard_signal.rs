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
    /// The caller owns the already authenticated, agreed SYNC transcript.
    /// Only its final ACK may use queue admission instead of HTTP completion:
    /// the initiator still waits for actual peer delivery before sweeping.
    /// Every permitted HTTP attempt must already be charged to the same
    /// recovery epoch; the worker cannot request credits or extend deadline.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn queue_hard_hard_start_ack(
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
    ) -> std::result::Result<Arc<HardHardStartAckDelivery>, PeerOfferSendFailure> {
        if !(1..=HARD_HARD_START_ACK_MAX_ATTEMPTS).contains(&prepaid_attempts) {
            return Err(PeerOfferSendFailure::SendFailed);
        }
        if ownership.is_cancelled() || Instant::now() >= deadline {
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
        self.candidate_offer_tx
            .try_send(CandidateOfferCommand {
                not_after: Some(deadline),
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
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => PeerOfferSendFailure::SendFailed,
                mpsc::error::TrySendError::Closed(_) => PeerOfferSendFailure::ChannelClosed,
            })?;
        Ok(Arc::new(HardHardStartAckDelivery(std::sync::Mutex::new(
            DeliveryState {
                response: Some(response_rx),
                accepted: false,
            },
        ))))
    }
}
