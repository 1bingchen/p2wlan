pub(crate) const HARD_HARD_PAIR_MAX_CANDIDATES: usize = 32;
pub(crate) const HARD_HARD_PAIR_CHECK_ATTEMPTS: u8 = 3;
pub(crate) const HARD_HARD_PAIR_CONFIRM_ATTEMPTS: u8 = 8;
pub(crate) const HARD_HARD_PAIR_RETRY_INTERVAL: Duration = Duration::from_millis(150);
/// Preserve the old worst case of sixteen admitted workers, each with the
/// existing request sequence. Coalesced/backpressured observations are free;
/// replacement owners share this one successful-handoff total.
const HARD_HARD_PAIR_VALIDATION_REQUEST_LIMIT: usize =
    16 * crate::DIRECT_VALIDATION_REQUEST_DELAYS.len();

/// One local view of the negotiated transport pair. The peer's socket index
/// is deliberately absent: a matching authenticated nonce joins the two views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HardHardPairKey {
    pub(crate) socket_index: usize,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) remote_endpoint: SocketAddr,
}

#[derive(Debug, Clone)]
struct HardHardPairCandidate {
    pair: HardHardPairKey,
    valid: bool,
    attempts: u8,
    local_deferrals: u8,
    next_check: Instant,
}

#[derive(Debug, Clone)]
struct HardHardPairSelection {
    pair: HardHardPairKey,
    confirmed: bool,
    validated: bool,
    attempts: u8,
    local_deferrals: u8,
    next_check: Instant,
    /// Successful encrypted Request handoffs, shared by every validation owner
    /// for this selected pair. Queueing and merging observations spend none.
    validation_requests: usize,
}

/// Bounded state owned exclusively by HardHardSessionRecord. A session may
/// choose exactly one pair, even if the nomination response is lost.
#[derive(Debug, Clone, Default)]
pub(crate) struct HardHardPairNomination {
    candidates: Vec<HardHardPairCandidate>,
    /// Successful kernel handoffs only, bounded by the prediction window cap.
    /// Receiving a check/ACK or reserving admission never populates this list.
    exploration_handoffs: Vec<HardHardPairKey>,
    selected: Option<HardHardPairSelection>,
    worker_claimed: bool,
    discovery_deadline: Option<tokio::time::Instant>,
    confirmation_deadline: Option<tokio::time::Instant>,
}

impl HardHardPairNomination {
    fn record_exploration_handoff(&mut self, pair: &HardHardPairKey) -> bool {
        if self.exploration_handoffs.contains(pair) {
            return true;
        }
        if self.exploration_handoffs.len() >= HARD_HARD_PAIR_MAX_CANDIDATES {
            return false;
        }
        self.exploration_handoffs.push(pair.clone());
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardPairEvidence {
    Observed,
    ConnectivityAck,
    NominationRequest,
    NominationAck,
}

#[derive(Debug, Clone)]
pub(crate) enum HardHardPairAction {
    Send(HardHardPairKey, HardHardPairSendPhase),
    Validate(HardHardPairKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardPairSendPhase {
    CandidateCheck,
    SelectedCheck,
    Nomination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardPairSendOutcome {
    Sent,
    /// Definitely no kernel handoff; only the pair attempt may be refunded.
    RetryableNotSent,
    /// A sliding-window budget can refill within the original phase. Do not
    /// consume the physical retry allowance while waiting for that window.
    BudgetDeferred,
    /// Cancellation after entering the sender may follow a successful syscall.
    /// Keep the attempt and every already-consumed budget credit.
    DeliveryUnknown,
    Stopped,
}

/// Scheduling is separate from wire attempts. A budget wait is bounded by
/// the original phase deadline; definite local failures get at most one
/// additional scheduling allowance per original attempt. Unknown delivery
/// remains charged, and no branch changes UDP/recovery credits.
fn complete_hard_hard_pair_send_attempt(
    attempts: &mut u8,
    deferrals: &mut u8,
    ceiling: u8,
    outcome: HardHardPairSendOutcome,
) {
    match outcome {
        HardHardPairSendOutcome::BudgetDeferred => *attempts = attempts.saturating_sub(1),
        HardHardPairSendOutcome::RetryableNotSent if *deferrals < ceiling => {
            *deferrals += 1;
            *attempts = attempts.saturating_sub(1);
        }
        HardHardPairSendOutcome::Stopped => *attempts = ceiling,
        _ => {}
    }
}

#[cfg(test)]
#[path = "hard_hard_pair_retry_tests.rs"]
mod hard_hard_pair_retry_tests;

/// The Direct reducer invokes these synchronously while it owns the current
/// connection. The UDP implementation holds the exact socket/session guards
/// until `finish`, so no cleanup can remove the pair before the connection's
/// Direct and business-path mirrors are published.
pub(crate) trait DirectCommitHooks: Send {
    fn is_current(&self) -> bool;
    fn committed(&mut self);
    fn finish(&mut self);
}

/// Immutable send permission for one action of the exact pair. This is a
/// snapshot of the existing HH owner, never a second owner or a TTL renewal.
pub(crate) struct HardHardDatagramSendPermit {
    cancellation: Arc<crate::PunchSessionCancellation>,
    deadline: tokio::time::Instant,
    expires_at_ms: u64,
    peer_id: String,
    peer_session_generation: PeerSessionGeneration,
    network_generation: u64,
    local_profile_generation: u64,
}

impl HardHardDatagramSendPermit {
    pub(crate) fn is_current(&self, peers: &PeerManager) -> bool {
        !self.cancellation.is_cancelled()
            && tokio::time::Instant::now() < self.deadline
            && hard_hard_now_ms() < self.expires_at_ms
            && peers.peer_session_is_current_sync(&self.peer_id, self.peer_session_generation)
            && peers.current_network_generation_sync() == self.network_generation
            && peers.current_local_profile_generation_sync() == self.local_profile_generation
    }
}

/// Borrow the existing session through the nonblocking exploration handoff.
/// The caller already owns epoch and exact-socket guards; lock order is the
/// same socket-state -> session order used by the Direct commit guard.
pub(crate) struct HardHardExplorationHandoffGuard<'a> {
    sessions: tokio::sync::MutexGuard<'a, HashMap<(String, String), HardHardSessionRecord>>,
    record_key: (String, String),
    pair: HardHardPairKey,
    track_handoff: bool,
    permit: HardHardDatagramSendPermit,
}

/// The existing HH ledger stays locked only over the nonblocking Request
/// handoff. ACK replies do not consume this bounded Request allowance.
pub(crate) struct HardHardValidationRequestGuard<'a> {
    sessions: tokio::sync::MutexGuard<'a, HashMap<(String, String), HardHardSessionRecord>>,
    record_key: (String, String),
    permit: HardHardDatagramSendPermit,
}

impl HardHardValidationRequestGuard<'_> {
    pub(crate) fn is_current(&self, peers: &PeerManager) -> bool {
        self.permit.is_current(peers)
    }

    pub(crate) fn handoff_succeeded(&mut self) {
        let selected = self
            .sessions
            .get_mut(&self.record_key)
            .and_then(|record| record.pair_nomination.as_mut())
            .and_then(|nomination| nomination.selected.as_mut())
            .expect("selected pair remains locked through Request handoff");
        selected.validation_requests += 1;
    }
}

impl HardHardExplorationHandoffGuard<'_> {
    pub(crate) fn is_current(&self, peers: &PeerManager) -> bool {
        self.permit.is_current(peers)
    }

    pub(crate) fn handoff_succeeded(&mut self) {
        if !self.track_handoff {
            return;
        }
        let nomination = self
            .sessions
            .get_mut(&self.record_key)
            .and_then(|record| record.pair_nomination.as_mut())
            .expect("existing session remains locked through handoff");
        let recorded = nomination.record_exploration_handoff(&self.pair);
        debug_assert!(
            recorded,
            "capacity was checked under this same session guard"
        );
    }
}

#[cfg(test)]
#[path = "hard_hard_forecast_tests.rs"]
mod hard_hard_forecast_tests;

fn hard_hard_exploration_forecast_deadline(
    plan: Option<&HardHardCoordinatedPlan>,
    nomination: &HardHardPairNomination,
    pair: &HardHardPairKey,
    discovery_deadline: tokio::time::Instant,
) -> Option<(tokio::time::Instant, bool)> {
    let Some(plan) = plan else {
        return Some((discovery_deadline, false));
    };
    let track = matches!(
        plan.agreement?.strategy,
        HardHardProbeStrategy::Predictable | HardHardProbeStrategy::FixedAnchor
    );
    if !track || nomination.exploration_handoffs.contains(pair) {
        return Some((discovery_deadline, track));
    }
    if nomination.exploration_handoffs.len() >= HARD_HARD_PAIR_MAX_CANDIDATES {
        return None;
    }
    Some((
        discovery_deadline.min(plan.forecast_first_send_deadline.into()),
        true,
    ))
}

pub(crate) struct HardHardPairCommitGuard<'a> {
    manager: &'a PeerManager,
    sessions: tokio::sync::MutexGuard<'a, HashMap<(String, String), HardHardSessionRecord>>,
    winners: tokio::sync::MutexGuard<'a, HashMap<(String, String), usize>>,
    record_key: (String, String),
    token_key: (String, String),
    pair: HardHardPairKey,
    punch_generation: u64,
    pub(crate) deadline: tokio::time::Instant,
}

impl HardHardPairCommitGuard<'_> {
    pub(crate) fn is_current(&self) -> bool {
        let record = &self.sessions[&self.record_key];
        record.state != HardHardSessionState::Retiring
            && !record.cancellation.is_cancelled()
            && tokio::time::Instant::now() < self.deadline
            && record.expires_at_ms >= hard_hard_now_ms()
            && record.local_network_generation == self.manager.current_network_generation_sync()
            && record.local_profile_generation
                == self.manager.current_local_profile_generation_sync()
    }

    pub(crate) fn commit(&mut self) {
        let record = self
            .sessions
            .get_mut(&self.record_key)
            .expect("owned HH record");
        record.fresh_socket.socket_index = self.pair.socket_index;
        record.fresh_socket.socket_local_endpoint = self.pair.local_endpoint;
        record.fresh_socket.punch_generation = self.punch_generation.max(1);
        // Publish validation only at the synchronous Direct commit. A
        // cancelled/contended ACK transaction must leave the nominated pair
        // eligible for another bounded encrypted validation request.
        if let Some(selected) = record
            .pair_nomination
            .as_mut()
            .and_then(|n| n.selected.as_mut())
        {
            selected.validated = true;
        }
        self.winners
            .insert(self.token_key.clone(), self.pair.socket_index);
    }
}

/// Preserve the existing Probe-session authentication and additionally bind
/// the entire frame (including USE-CANDIDATE) to this negotiated HH attempt.
pub(crate) fn hard_hard_scoped_probe_key(key: &ProbeMacKey, token: &str) -> ProbeMacKey {
    let mut context = b"p2wlan/hh2/pair-probe/v1\0".to_vec();
    context.extend_from_slice(token.as_bytes());
    hmac(key, &context)
}

impl PeerManager {
    pub(crate) async fn hard_hard_validation_request_guard(
        &self,
        peer: &str,
        scope: &crate::udp::HardHardValidationScope,
        permit: HardHardDatagramSendPermit,
    ) -> Option<HardHardValidationRequestGuard<'_>> {
        if !self.peer_session_is_current_sync(peer, scope.peer_session)
            || self.current_network_generation_sync() != scope.generation
        {
            return None;
        }
        let sessions = self.hard_hard_sessions.lock().await;
        let (record_key, record) = sessions.iter().find(|(_, record)| {
            record.peer_id == peer
                && record.session_token == scope.token
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
        })?;
        let selected = record.pair_nomination.as_ref()?.selected.as_ref()?;
        if selected.pair != scope.pair
            || !selected.confirmed
            || selected.validated
            || selected.validation_requests >= HARD_HARD_PAIR_VALIDATION_REQUEST_LIMIT
            || !permit.is_current(self)
        {
            return None;
        }
        let record_key = record_key.clone();
        Some(HardHardValidationRequestGuard {
            sessions,
            record_key,
            permit,
        })
    }

    pub(crate) async fn hard_hard_validation_deadline(
        &self,
        peer: &str,
        scope: &crate::udp::HardHardValidationScope,
    ) -> Option<tokio::time::Instant> {
        if !self.peer_session_is_current_sync(peer, scope.peer_session)
            || self.current_network_generation_sync() != scope.generation
        {
            return None;
        }
        let record = self.hard_hard_pair_scope(peer, &scope.token).await?;
        let selected = record.pair_nomination.as_ref()?.selected.as_ref()?;
        if selected.pair != scope.pair
            || selected.validation_requests >= HARD_HARD_PAIR_VALIDATION_REQUEST_LIMIT
        {
            return None;
        }
        Some(
            self.hard_hard_validation_send_permit(peer, &scope.token, &scope.pair)
                .await?
                .deadline,
        )
    }

    /// Completion merely permits another observation; it cannot authorize a
    /// connection or reset any Request credits. The immutable HH scope fences
    /// cleanup from a different token, registration lifecycle or selected pair.
    pub(crate) async fn hard_hard_validation_completed(
        &self,
        peer: &str,
        scope: &crate::udp::HardHardValidationScope,
        completion: crate::udp::DirectValidationCompletion,
    ) {
        if completion == crate::udp::DirectValidationCompletion::DeadlineExpired
            || self
                .hard_hard_validation_deadline(peer, scope)
                .await
                .is_none()
        {
            return;
        }
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(selected) = sessions
            .values_mut()
            .find(|record| {
                record.peer_id == peer
                    && record.session_token == scope.token
                    && !record.cancellation.is_cancelled()
                    && record.state != HardHardSessionState::Retiring
            })
            .and_then(|record| record.pair_nomination.as_mut())
            .and_then(|nomination| nomination.selected.as_mut())
            .filter(|selected| selected.pair == scope.pair && !selected.validated)
        else {
            return;
        };
        selected.next_check = selected
            .next_check
            .min(Instant::now() + HARD_HARD_PAIR_RETRY_INTERVAL);
    }

    pub(crate) async fn hard_hard_exploration_handoff_guard(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
    ) -> Option<HardHardExplorationHandoffGuard<'_>> {
        let sessions = self.hard_hard_sessions.lock().await;
        let (record_key, record) = sessions.iter().find(|(_, record)| {
            record.peer_id == peer
                && record.session_token == token
                && record.state != HardHardSessionState::Retiring
                && record.requested_socket_indices.contains(&pair.socket_index)
        })?;
        if record.coordinated_plan.as_ref().is_some_and(|plan| {
            !plan.ready(record.initiator) || Instant::now() < plan.scheduled_start
        }) {
            return None;
        }
        let nomination = record.pair_nomination.as_ref()?;
        if nomination.selected.is_some() {
            return None;
        }
        let (deadline, track_handoff) = hard_hard_exploration_forecast_deadline(
            record.coordinated_plan.as_ref(),
            nomination,
            pair,
            nomination.discovery_deadline?,
        )?;
        let permit = HardHardDatagramSendPermit {
            cancellation: record.cancellation.clone(),
            deadline,
            expires_at_ms: record.expires_at_ms,
            peer_id: peer.into(),
            peer_session_generation: self.peer_session_generation_sync(peer)?,
            network_generation: record.local_network_generation,
            local_profile_generation: record.local_profile_generation,
        };
        if !permit.is_current(self) {
            return None;
        }
        let record_key = record_key.clone();
        Some(HardHardExplorationHandoffGuard {
            sessions,
            record_key,
            pair: pair.clone(),
            track_handoff,
            permit,
        })
    }

    pub(crate) async fn hard_hard_validation_send_permit(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
    ) -> Option<HardHardDatagramSendPermit> {
        let record = self.hard_hard_pair_scope(peer, token).await?;
        let nomination = record.pair_nomination.as_ref()?;
        if !nomination
            .selected
            .as_ref()
            .is_some_and(|selected| selected.confirmed && selected.pair == *pair)
        {
            return None;
        }
        let permit = HardHardDatagramSendPermit {
            cancellation: record.cancellation.clone(),
            deadline: nomination.confirmation_deadline?,
            expires_at_ms: record.expires_at_ms,
            peer_id: peer.into(),
            peer_session_generation: self.peer_session_generation_sync(peer)?,
            network_generation: record.local_network_generation,
            local_profile_generation: record.local_profile_generation,
        };
        permit.is_current(self).then_some(permit)
    }

    /// Reply only to an observed exact pair in the still-live action phase.
    /// Once a pair is frozen, duplicates may re-ACK that pair without spending
    /// mappings on other candidates or reviving exploration.
    pub(crate) async fn hard_hard_probe_ack_send_permit(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
        nomination_request: bool,
    ) -> Option<HardHardDatagramSendPermit> {
        let record = self.hard_hard_pair_scope(peer, token).await?;
        if !record.requested_socket_indices.contains(&pair.socket_index)
            || record.coordinated_plan.as_ref().is_some_and(|plan| {
                !plan.ready(record.initiator) || Instant::now() < plan.scheduled_start
            })
        {
            return None;
        }
        let nomination = record.pair_nomination.as_ref()?;
        let deadline = match nomination.selected.as_ref() {
            Some(selected)
                if selected.pair == *pair && (!nomination_request || !record.initiator) =>
            {
                nomination.confirmation_deadline?
            }
            None if !nomination_request
                && nomination
                    .candidates
                    .iter()
                    .any(|candidate| candidate.pair == *pair) =>
            {
                nomination.discovery_deadline?
            }
            _ => return None,
        };
        let permit = HardHardDatagramSendPermit {
            cancellation: record.cancellation.clone(),
            deadline,
            expires_at_ms: record.expires_at_ms,
            peer_id: peer.into(),
            peer_session_generation: self.peer_session_generation_sync(peer)?,
            network_generation: record.local_network_generation,
            local_profile_generation: record.local_profile_generation,
        };
        permit.is_current(self).then_some(permit)
    }
    pub(crate) async fn hard_hard_pair_commit_guard(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
        punch_generation: u64,
    ) -> Option<HardHardPairCommitGuard<'_>> {
        let sessions = self.hard_hard_sessions.lock().await;
        let (record_key, record) = sessions.iter().find(|(_, record)| {
            record.peer_id == peer
                && record.session_token == token
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
        })?;
        let nomination = record.pair_nomination.as_ref()?;
        if !nomination
            .selected
            .as_ref()
            .is_some_and(|selected| selected.confirmed && selected.pair == *pair)
        {
            return None;
        }
        let deadline = nomination.confirmation_deadline?;
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        let record_key = record_key.clone();
        let token_key = (peer.to_owned(), token.to_owned());
        let winners = self.hard_hard_winners.lock().await;
        if winners
            .get(&token_key)
            .is_some_and(|index| *index != pair.socket_index)
        {
            return None;
        }
        Some(HardHardPairCommitGuard {
            manager: self,
            sessions,
            winners,
            record_key,
            token_key,
            pair: pair.clone(),
            punch_generation,
            deadline,
        })
    }
    pub(crate) async fn hard_hard_pair_is_enabled(&self, peer: &str, token: &str) -> bool {
        self.hard_hard_session_by_token(peer, token)
            .await
            .is_some_and(|record| record.pair_nomination.is_some())
    }

    pub(crate) async fn hard_hard_pair_is_prepared(&self, peer: &str, token: &str) -> bool {
        self.hard_hard_session_by_token(peer, token)
            .await
            .and_then(|record| record.pair_nomination)
            .is_some_and(|nomination| nomination.selected.is_some())
    }

    pub(crate) async fn hard_hard_pair_scope(
        &self,
        peer: &str,
        token: &str,
    ) -> Option<HardHardSessionRecord> {
        let record = self.hard_hard_session_by_token(peer, token).await?;
        if record.pair_nomination.is_none()
            || !self.peer_supports_hh2(peer).await
            || !self
                .hard_hard_session_identity_is_current(&record.fresh_socket)
                .await
        {
            return None;
        }
        Some(record)
    }

    /// None means legacy/unmanaged; Some(None) means hh2 has not agreed a
    /// pair and MUST block ordinary validation ingress for this peer.
    pub(crate) async fn hard_hard_pair_validation_target(
        &self,
        peer: &str,
    ) -> Option<Option<(String, HardHardPairKey)>> {
        let now = hard_hard_now_ms();
        let sessions = self.hard_hard_sessions.lock().await;
        let record = sessions.values().find(|record| {
            record.peer_id == peer
                && record.pair_nomination.is_some()
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= now
        })?;
        let nomination = record.pair_nomination.as_ref()?;
        Some(
            nomination
                .selected
                .as_ref()
                .filter(|selection| {
                    selection.confirmed
                        && nomination
                            .confirmation_deadline
                            .is_some_and(|deadline| tokio::time::Instant::now() < deadline)
                })
                .map(|selection| (record.session_token.clone(), selection.pair.clone())),
        )
    }

    pub(crate) async fn hard_hard_pair_observe(
        &self,
        peer: &str,
        token: &str,
        pair: HardHardPairKey,
        evidence: HardHardPairEvidence,
    ) -> bool {
        let Some(scope) = self.hard_hard_pair_scope(peer, token).await else {
            return false;
        };
        if !scope.requested_socket_indices.contains(&pair.socket_index) {
            return false;
        }
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return false;
        };
        let controlling = record.initiator;
        let Some(nomination) = record.pair_nomination.as_mut() else {
            return false;
        };
        let deadline = if nomination.selected.is_some() {
            nomination.confirmation_deadline
        } else {
            nomination.discovery_deadline
        };
        if !deadline.is_some_and(|deadline| tokio::time::Instant::now() < deadline) {
            return false;
        }
        if matches!(evidence, HardHardPairEvidence::NominationRequest) && controlling
            || matches!(evidence, HardHardPairEvidence::NominationAck) && !controlling
        {
            return false;
        }
        if nomination
            .selected
            .as_ref()
            .is_some_and(|selected| selected.pair != pair)
        {
            // In particular, never ACK acceptance of a conflicting nomination.
            return !matches!(evidence, HardHardPairEvidence::NominationRequest);
        }
        let candidate_index = match nomination.candidates.iter().position(|c| c.pair == pair) {
            Some(index) => index,
            None if nomination.candidates.len() < HARD_HARD_PAIR_MAX_CANDIDATES => {
                nomination.candidates.push(HardHardPairCandidate {
                    pair: pair.clone(),
                    valid: false,
                    attempts: 0,
                    local_deferrals: 0,
                    next_check: Instant::now(),
                });
                nomination.candidates.len() - 1
            }
            None => return false,
        };
        if evidence == HardHardPairEvidence::ConnectivityAck {
            nomination.candidates[candidate_index].valid = true;
        }
        if nomination.selected.is_none()
            && ((controlling && evidence == HardHardPairEvidence::ConnectivityAck)
                || (!controlling && evidence == HardHardPairEvidence::NominationRequest))
        {
            nomination.selected = Some(HardHardPairSelection {
                pair: pair.clone(),
                confirmed: !controlling && nomination.candidates[candidate_index].valid,
                validated: false,
                attempts: 0,
                local_deferrals: 0,
                next_check: Instant::now(),
                validation_requests: 0,
            });
        }
        if let Some(selected) = nomination.selected.as_mut() {
            if (controlling && evidence == HardHardPairEvidence::NominationAck)
                || (!controlling && evidence == HardHardPairEvidence::ConnectivityAck)
            {
                selected.confirmed = true;
            }
        }
        true
    }

    pub(crate) async fn hard_hard_pair_claim_worker(
        &self,
        peer: &str,
        token: &str,
        discovery_deadline: tokio::time::Instant,
    ) -> bool {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|r| {
            r.peer_id == peer
                && r.session_token == token
                && r.state != HardHardSessionState::Retiring
                && !r.cancellation.is_cancelled()
                && r.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return false;
        };
        let Some(nomination) = record.pair_nomination.as_mut() else {
            return false;
        };
        if nomination.worker_claimed {
            return false;
        }
        nomination.worker_claimed = true;
        let discovery_deadline =
            record
                .coordinated_plan
                .as_ref()
                .map_or(discovery_deadline, |plan| {
                    discovery_deadline.min(
                        tokio::time::Instant::from_std(plan.scheduled_start)
                            + Duration::from_secs(3),
                    )
                });
        let ttl = tokio::time::Instant::now()
            + Duration::from_millis(record.expires_at_ms.saturating_sub(hard_hard_now_ms()));
        nomination.discovery_deadline = Some(
            nomination
                .discovery_deadline
                .unwrap_or(discovery_deadline)
                .min(discovery_deadline)
                .min(ttl),
        );
        nomination.confirmation_deadline = Some(
            nomination
                .confirmation_deadline
                .unwrap_or(discovery_deadline + Duration::from_secs(2))
                .min(discovery_deadline + Duration::from_secs(2))
                .min(ttl),
        );
        true
    }

    /// One owner requests at most one action each tick. Both the candidate
    /// set and per-pair sends are capped, independently of the shared budget.
    pub(crate) async fn hard_hard_pair_next_action(
        &self,
        peer: &str,
        token: &str,
        discovery_open: bool,
    ) -> Option<HardHardPairAction> {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let record = sessions.values_mut().find(|r| {
            r.peer_id == peer
                && r.session_token == token
                && r.state != HardHardSessionState::Retiring
                && !r.cancellation.is_cancelled()
                && r.expires_at_ms >= hard_hard_now_ms()
        })?;
        let controlling = record.initiator;
        let nomination = record.pair_nomination.as_mut()?;
        let now = Instant::now();
        let deadline = if nomination.selected.is_some() {
            nomination.confirmation_deadline
        } else {
            nomination.discovery_deadline
        }?;
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        if let Some(selected) = nomination.selected.as_mut() {
            if selected.validated {
                return None;
            }
            if selected.confirmed {
                if selected.validation_requests >= HARD_HARD_PAIR_VALIDATION_REQUEST_LIMIT
                    || selected.next_check > now
                {
                    return None;
                }
                selected.next_check = now + HARD_HARD_PAIR_RETRY_INTERVAL;
                return Some(HardHardPairAction::Validate(selected.pair.clone()));
            }
            if selected.attempts >= HARD_HARD_PAIR_CONFIRM_ATTEMPTS || selected.next_check > now {
                return None;
            }
            selected.attempts += 1;
            selected.next_check = now + HARD_HARD_PAIR_RETRY_INTERVAL;
            return Some(HardHardPairAction::Send(
                selected.pair.clone(),
                if controlling {
                    HardHardPairSendPhase::Nomination
                } else {
                    HardHardPairSendPhase::SelectedCheck
                },
            ));
        }
        if !discovery_open {
            return None;
        }
        let candidate = nomination.candidates.iter_mut().find(|c| {
            !c.valid && c.attempts < HARD_HARD_PAIR_CHECK_ATTEMPTS && c.next_check <= now
        })?;
        candidate.attempts += 1;
        candidate.next_check = now + HARD_HARD_PAIR_RETRY_INTERVAL;
        Some(HardHardPairAction::Send(
            candidate.pair.clone(),
            HardHardPairSendPhase::CandidateCheck,
        ))
    }

    /// Complete the single worker's scheduled action. A definite local
    /// non-send may refund its pair attempt at most the existing retry cap;
    /// admission credits are never refunded. The original 150ms cadence and
    /// phase deadline still apply. Phase identity prevents a late candidate
    /// result from decrementing a newly selected pair's nomination attempts.
    pub(crate) async fn hard_hard_pair_record_send_outcome(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
        phase: HardHardPairSendPhase,
        outcome: HardHardPairSendOutcome,
    ) {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|record| {
            record.peer_id == peer
                && record.session_token == token
                && record.state != HardHardSessionState::Retiring
                && !record.cancellation.is_cancelled()
                && record.expires_at_ms > hard_hard_now_ms()
        }) else {
            return;
        };
        let Some(nomination) = record.pair_nomination.as_mut() else {
            return;
        };
        let (attempts, deferrals, ceiling) = match phase {
            HardHardPairSendPhase::CandidateCheck => {
                let Some(candidate) = nomination.candidates.iter_mut().find(|c| c.pair == *pair)
                else {
                    return;
                };
                (
                    &mut candidate.attempts,
                    &mut candidate.local_deferrals,
                    HARD_HARD_PAIR_CHECK_ATTEMPTS,
                )
            }
            HardHardPairSendPhase::SelectedCheck | HardHardPairSendPhase::Nomination => {
                let Some(selected) = nomination.selected.as_mut().filter(|s| s.pair == *pair)
                else {
                    return;
                };
                if (phase == HardHardPairSendPhase::Nomination) != record.initiator {
                    return;
                }
                (
                    &mut selected.attempts,
                    &mut selected.local_deferrals,
                    HARD_HARD_PAIR_CONFIRM_ATTEMPTS,
                )
            }
        };
        complete_hard_hard_pair_send_attempt(attempts, deferrals, ceiling, outcome);
    }

    /// Derive budget purpose from the authoritative phase, not from a caller's
    /// nomination bit. Only the selected responder pair can spend the final
    /// confirmation credits; ordinary candidate checks retain their reserve.
    pub(crate) async fn hard_hard_pair_send_admission(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
        phase: HardHardPairSendPhase,
    ) -> Option<(tokio::time::Instant, RecoveryProbePurpose)> {
        let scope = self.hard_hard_pair_scope(peer, token).await?;
        let nomination = scope.pair_nomination.as_ref()?;
        let purpose = match (phase, nomination.selected.as_ref()) {
            (HardHardPairSendPhase::CandidateCheck, None)
                if nomination
                    .candidates
                    .iter()
                    .any(|c| c.pair == *pair && !c.valid) =>
            {
                RecoveryProbePurpose::HardHardTriggered
            }
            (HardHardPairSendPhase::SelectedCheck, Some(selected))
                if !scope.initiator && selected.pair == *pair && !selected.confirmed =>
            {
                RecoveryProbePurpose::HardHardSelectedCheck
            }
            (HardHardPairSendPhase::Nomination, Some(selected))
                if scope.initiator && selected.pair == *pair && !selected.confirmed =>
            {
                RecoveryProbePurpose::HardHardNomination
            }
            _ => return None,
        };
        let deadline = self
            .hard_hard_pair_send_deadline(
                peer,
                token,
                pair,
                phase == HardHardPairSendPhase::Nomination,
            )
            .await?;
        Some((deadline, purpose))
    }

    /// Validate the immutable send intent at the final handoff. A queued
    /// Check can never become a nomination after another pair was selected.
    pub(crate) async fn hard_hard_pair_send_deadline(
        &self,
        peer: &str,
        token: &str,
        pair: &HardHardPairKey,
        nominate: bool,
    ) -> Option<tokio::time::Instant> {
        let scope = self.hard_hard_pair_scope(peer, token).await?;
        if !scope.requested_socket_indices.contains(&pair.socket_index) {
            return None;
        }
        if scope.coordinated_plan.as_ref().is_some_and(|plan| {
            !plan.ready(scope.initiator) || Instant::now() < plan.scheduled_start
        }) {
            return None;
        }
        let nomination = scope.pair_nomination.as_ref()?;
        let deadline = match nomination.selected.as_ref() {
            Some(selected)
                if selected.pair == *pair
                    && !selected.validated
                    && (!nominate || scope.initiator) =>
            {
                nomination.confirmation_deadline?
            }
            None if !nominate => nomination.discovery_deadline?,
            _ => return None,
        };
        (tokio::time::Instant::now() < deadline).then_some(deadline)
    }

    pub(crate) async fn hard_hard_pair_arm(&self, peer: &str, token: &str) -> bool {
        let mut sessions = self.hard_hard_sessions.lock().await;
        let Some(record) = sessions.values_mut().find(|r| {
            r.peer_id == peer
                && r.session_token == token
                && r.state != HardHardSessionState::Retiring
                && !r.cancellation.is_cancelled()
        }) else {
            return false;
        };
        let Some(nomination) = record.pair_nomination.as_mut() else {
            return false;
        };
        let now_ms = hard_hard_now_ms();
        let now = tokio::time::Instant::now();
        let ttl = now + Duration::from_millis(record.expires_at_ms.saturating_sub(now_ms));
        let discovery = record.coordinated_plan.as_ref().map_or_else(
            || {
                now + Duration::from_millis(
                    record
                        .punch_at_ms
                        .saturating_add(3_000)
                        .saturating_sub(now_ms),
                )
            },
            |plan| tokio::time::Instant::from_std(plan.scheduled_start) + Duration::from_secs(3),
        );
        let discovery = discovery.min(ttl);
        let confirmation = (discovery + Duration::from_secs(2)).min(ttl);
        nomination.discovery_deadline = Some(
            nomination
                .discovery_deadline
                .map_or(discovery, |prior| prior.min(discovery)),
        );
        nomination.confirmation_deadline = Some(
            nomination
                .confirmation_deadline
                .map_or(confirmation, |prior| prior.min(confirmation)),
        );
        now < ttl
    }

    pub(crate) fn hard_hard_committed_pair_is_current_sync(
        &self,
        peer: &str,
        pair: &HardHardPairKey,
        generation: u64,
    ) -> bool {
        if self.current_network_generation_sync() != generation {
            return false;
        }
        self.direct_commit_pair_snapshot_sync(peer)
            .is_some_and(|snapshot| {
                snapshot.path_revision.is_some()
                    && snapshot.generation == generation
                    && snapshot.local_endpoint == Some(pair.local_endpoint)
                    && snapshot.remote_endpoint == pair.remote_endpoint
                    && self.peer_session_is_current_sync(peer, snapshot.peer_session_generation)
            })
    }
}
