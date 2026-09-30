impl Daemon {
    /// Keep ordinary revisions in the existing bounded candidate owner while
    /// an immutable HH measurement/negotiation is live. Applying them first
    /// would advance its candidate epoch and consume its only attempt before
    /// the reciprocal answer arrives. The one queued successor can always
    /// preempt this wait, so an HH answer is never stuck behind ordinary work.
    /// Incarnation reset runs BEFORE this wait; a restarted peer is not held
    /// behind its retired session. No lock survives the polling sleep.
    async fn wait_for_hard_hard_candidate_owner(
        &self,
        offer: &PendingPeerOffer,
        reservation: &mut CandidateOfferWorkReservation,
    ) -> bool {
        if offer
            .session_id
            .as_deref()
            .is_some_and(HardHardCoordination::looks_like)
        {
            return true;
        }
        let peer_id = &offer.from_node_id;
        let deadline = tokio::time::Instant::now() + HARD_HARD_SESSION_TTL + HARD_HARD_PUNCH_LEAD;
        let mut deferred = false;
        loop {
            let current = || {
                !*reservation.cancellation.borrow()
                    && self
                        .pending_handshakes
                        .lock()
                        .candidate_offer_work_is_current(peer_id, reservation.owner)
                    && self.peers.current_network_generation_sync() == offer.network_generation
                    && self.peers.peer_session_generation_sync(peer_id)
                        == offer.peer_session_generation
                    && self.peers.signal_sender_identity_matches_peer_sync(
                        peer_id,
                        offer.sender_public_key.as_deref(),
                    )
            };
            if !current() {
                return false;
            }
            if self
                .pending_handshakes
                .lock()
                .candidate_offer_work_has_priority_successor(peer_id, reservation.owner, offer)
            {
                return true;
            }
            let active = self.peers.hard_hard_session_is_active(peer_id).await
                || self.punch_attempts.has_local_fresh_owner(
                    peer_id,
                    offer.network_generation,
                    offer.peer_session_generation,
                );
            if !current() {
                return false;
            }
            if !active {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                self.timeline.emit(
                    "peer_offer_candidate_wait_expired",
                    None,
                    Some("hard_hard_owner_wait_expired"),
                    None,
                );
                return false;
            }
            if !deferred {
                self.timeline.emit(
                    "peer_offer_candidate_deferred",
                    None,
                    Some("hard_hard_owner_active"),
                    Some(format!(
                        "candidate_generation={} owner={}",
                        offer.candidate_generation, reservation.owner
                    )),
                );
                deferred = true;
            }
            tokio::select! {
                changed = reservation.cancellation.changed() => {
                    if changed.is_err() || *reservation.cancellation.borrow() { return false; }
                }
                _ = sleep(UNKNOWN_PEER_OFFER_POLL) => {}
            }
        }
    }
}
