impl Daemon {
    fn candidate_offer_owner_is_current(
        &self,
        offer: &PendingPeerOffer,
        reservation: &CandidateOfferWorkReservation,
    ) -> bool {
        !*reservation.cancellation.borrow()
            && self
                .pending_handshakes
                .lock()
                .candidate_offer_work_is_current(&offer.from_node_id, reservation.owner)
            && self.peers.current_network_generation_sync() == offer.network_generation
            && self.peers.peer_session_generation_sync(&offer.from_node_id)
                == offer.peer_session_generation
            && self.peers.signal_sender_identity_matches_peer_sync(
                &offer.from_node_id,
                offer.sender_public_key.as_deref(),
            )
    }

    /// A newly advertised HH offer must give an existing encrypted validation
    /// a bounded chance to finish before replacing its candidate epoch. The
    /// remote initiator may already have committed ordinary Direct and retired
    /// its HH socket, so cancelling this validation would strand this side
    /// behind a rendezvous that the other side will never execute.
    async fn wait_for_candidate_validation(
        &self,
        offer: &PendingPeerOffer,
        reservation: &mut CandidateOfferWorkReservation,
    ) -> bool {
        let wait = async {
            let Some(udp) = self.udp_transport.read().await.clone() else {
                return;
            };
            let Some(target) = udp.direct_validation_target(&offer.from_node_id).await else {
                return;
            };
            if target.cancelled
                || target.generation != offer.network_generation
                || Some(target.peer_session_generation) != offer.peer_session_generation
            {
                return;
            }
            self.timeline.emit(
                "peer_offer_candidate_deferred",
                None,
                Some("direct_validation_active"),
                Some(format!(
                    "candidate_owner={} validation_owner={}",
                    reservation.owner, target.owner_token
                )),
            );
            loop {
                if !self.candidate_offer_owner_is_current(offer, reservation) {
                    return;
                }
                let current = udp.direct_validation_target(&offer.from_node_id).await;
                if !current.is_some_and(|current| {
                    !current.cancelled
                        && current.owner_token == target.owner_token
                        && current.generation == target.generation
                        && current.peer_session_generation == target.peer_session_generation
                        && current.remote_candidate_epoch == target.remote_candidate_epoch
                }) {
                    return;
                }
                tokio::select! {
                    _ = reservation.cancellation.changed() => return,
                    _ = sleep(UNKNOWN_PEER_OFFER_POLL) => {}
                }
            }
        };
        // Includes lock acquisition time and never renews for replacement
        // validation owners. Neither the handshake lane nor a reciprocal HH
        // answer waits here; only the existing candidate worker is retained.
        if tokio::time::timeout(Duration::from_millis(250), wait)
            .await
            .is_err()
        {
            self.timeline.emit(
                "peer_offer_candidate_wait_expired",
                None,
                Some("direct_validation_wait_expired"),
                None,
            );
        }
        self.candidate_offer_owner_is_current(offer, reservation)
    }

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
            if hard_hard_candidate_priority(offer, hard_hard_now_ms())
                .is_some_and(|coordination| coordination.role == HardHardRole::Initiator)
            {
                return self.wait_for_candidate_validation(offer, reservation).await;
            }
            return true;
        }
        let peer_id = &offer.from_node_id;
        let deadline = tokio::time::Instant::now() + HARD_HARD_SESSION_TTL + HARD_HARD_PUNCH_LEAD;
        let mut deferred = false;
        loop {
            let current = || self.candidate_offer_owner_is_current(offer, reservation);
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
