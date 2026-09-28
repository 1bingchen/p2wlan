/// Observation only: this guard never owns or mutates a candidate/session.
/// It lives in the existing bounded worker and emits once even when its
/// future is dropped. No lock guard is retained across the logging call.
struct HardHardCandidateTrace {
    session_tag: String,
    plan_tag: String,
    role: &'static str,
    peer_tag: String,
    peer_id: String,
    peers: Arc<PeerManager>,
    owner: u64,
    network_generation: u64,
    peer_session_generation: Option<u64>,
    candidate_generation: u64,
    local_profile_generation: Option<u64>,
    remote_profile_generation: Option<u64>,
    protocol: &'static str,
    outcome: &'static str,
}

impl HardHardCandidateTrace {
    fn begin(offer: &PendingPeerOffer, owner: u64, peers: &Arc<PeerManager>) -> Option<Self> {
        let raw = offer.session_id.as_deref()?;
        if !HardHardCoordination::looks_like(raw) {
            return None;
        }
        let coordination = HardHardCoordination::parse(raw);
        let (session_tag, plan_tag, _) =
            hard_hard_a0_stage_tags(coordination.as_ref().map(|value| value.token.as_str()));
        let role = coordination
            .as_ref()
            .map_or("unclassified", |value| match value.role {
                HardHardRole::Initiator => "responder",
                HardHardRole::Responder => "initiator",
            });
        let trace = Self {
            session_tag,
            plan_tag,
            role,
            peer_tag: hard_hard_anonymized_tag(&offer.from_node_id, "peer"),
            peer_id: offer.from_node_id.clone(),
            peers: peers.clone(),
            owner,
            network_generation: offer.network_generation,
            peer_session_generation: offer.peer_session_generation.map(|value| value.value()),
            candidate_generation: offer.candidate_generation,
            local_profile_generation: coordination
                .as_ref()
                .map(|value| value.remote_profile_generation),
            remote_profile_generation: coordination
                .as_ref()
                .map(|value| value.local_profile_generation),
            protocol: coordination.as_ref().map_or("malformed", |value| {
                if value.v2.is_some() {
                    "hh2"
                } else {
                    "hh1"
                }
            }),
            outcome: "worker_cancelled_or_dropped",
        };
        trace.emit("started");
        Some(trace)
    }

    fn outcome(trace: &mut Option<Self>, outcome: &'static str) {
        if let Some(trace) = trace {
            trace.outcome = outcome;
        }
    }

    fn emit(&self, outcome: &'static str) {
        let observed_network_generation = self.peers.current_network_generation_sync();
        let observed_peer_session_generation = self
            .peers
            .peer_session_generation_sync(&self.peer_id)
            .map(|value| value.value());
        tracing::info!(
            event = "hard_hard_candidate_work",
            session_tag = %self.session_tag,
            plan_tag = %self.plan_tag,
            peer_tag = %self.peer_tag,
            role = self.role,
            protocol = self.protocol,
            candidate_owner = self.owner,
            expected_network_generation = self.network_generation,
            observed_network_generation,
            expected_peer_session_generation = ?self.peer_session_generation,
            observed_peer_session_generation = ?observed_peer_session_generation,
            candidate_generation = self.candidate_generation,
            expected_local_profile_generation = ?self.local_profile_generation,
            expected_remote_profile_generation = ?self.remote_profile_generation,
            outcome,
            "Hard-Hard candidate processing (separate from delivery Applied)"
        );
    }
}

impl Drop for HardHardCandidateTrace {
    fn drop(&mut self) {
        self.emit(self.outcome);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardHardCandidateDiscardReason {
    OrdinaryCoalesced,
    Superseded,
    SameSessionPreserved,
    Expired,
}

impl HardHardCandidateDiscardReason {
    fn label(self) -> &'static str {
        match self {
            Self::OrdinaryCoalesced => "ordinary_candidate_coalesced",
            Self::Superseded => "queued_hard_hard_superseded",
            Self::SameSessionPreserved => "queued_same_session_preserved",
            Self::Expired => "queued_hard_hard_expired",
        }
    }
}

/// Called after the pending-handshake guard is released. The displaced value
/// is temporary ownership of the existing queued payload, not another queue.
fn hard_hard_candidate_discarded(
    offer: Option<&PendingPeerOffer>,
    reason: HardHardCandidateDiscardReason,
) {
    let Some(offer) = offer else {
        return;
    };
    let Some(raw) = offer
        .session_id
        .as_deref()
        .filter(|value| HardHardCoordination::looks_like(value))
    else {
        return;
    };
    let parsed = HardHardCoordination::parse(raw);
    let (session_tag, plan_tag, identity_scope) =
        hard_hard_a0_stage_tags(parsed.as_ref().map(|value| value.token.as_str()));
    tracing::info!(event = "hard_hard_candidate_discarded", session_tag = %session_tag,
        plan_tag = %plan_tag, identity_scope, candidate_generation = offer.candidate_generation,
        network_generation = offer.network_generation, reason_code = reason.label(),
        "Hard-Hard candidate queue disposition");
}

/// Only canonical OFFER/ANSWER envelopes with an original useful deadline
/// outrank ordinary candidates. This is scheduling, never admission authority.
fn hard_hard_candidate_priority(
    offer: &PendingPeerOffer,
    now_ms: u64,
) -> Option<HardHardCoordination> {
    let coordination = HardHardCoordination::parse(offer.session_id.as_deref()?)?;
    if coordination
        .v2
        .as_ref()
        .is_some_and(|meta| !matches!(meta.stage, HardHardV2Stage::Offer | HardHardV2Stage::Answer))
    {
        return None;
    }
    let punch_at_ms = offer.punch_at_ms?;
    let useful = match coordination.role {
        HardHardRole::Initiator => hard_hard_punch_window_is_usable(now_ms, punch_at_ms),
        HardHardRole::Responder => {
            punch_at_ms.saturating_add(HARD_HARD_SWEEP_DEADLINE.as_millis() as u64) >= now_ms
                && punch_at_ms <= now_ms.saturating_add(HARD_HARD_SESSION_TTL.as_millis() as u64)
        }
    };
    (useful
        && offer
            .candidates_expires_at_ms
            .is_none_or(|expiry| expiry > now_ms))
    .then_some(coordination)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardHardClaimFailureReason {
    PunchWindowTooSoon,
    PunchWindowBeyondLifetime,
    SweepDeadlineExpired,
    AlreadyDirect,
    PeerSessionChanged,
    PlanUnavailable,
    PlanChanged,
    SessionMissing,
    SessionChanged,
    RecoverySuperseded,
    RecoveryBudgetExhausted,
    RecoveryEpochChanged,
    GenerationQuotaUnavailable,
    RetryReservationUnavailable,
    ClaimUnavailable,
    Deferred(PunchClaimDeferredReason),
}

impl HardHardClaimFailureReason {
    fn label(self) -> &'static str {
        match self {
            Self::PunchWindowTooSoon => "punch_window_too_soon",
            Self::PunchWindowBeyondLifetime => "punch_window_beyond_lifetime",
            Self::SweepDeadlineExpired => "sweep_deadline_expired",
            Self::AlreadyDirect => "already_direct",
            Self::PeerSessionChanged => "peer_session_changed",
            Self::PlanUnavailable => "plan_unavailable",
            Self::PlanChanged => "plan_generation_changed",
            Self::SessionMissing => "session_missing",
            Self::SessionChanged => "session_record_changed",
            Self::RecoverySuperseded => "recovery_superseded",
            Self::RecoveryBudgetExhausted => "recovery_budget_exhausted",
            Self::RecoveryEpochChanged => "recovery_epoch_changed",
            Self::GenerationQuotaUnavailable => "generation_quota_unavailable",
            Self::RetryReservationUnavailable => "retry_reservation_unavailable",
            Self::ClaimUnavailable => "claim_unavailable",
            Self::Deferred(reason) => reason.label(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HardHardClaimFailure {
    reason: HardHardClaimFailureReason,
    observed_plan: Option<crate::peer::HardHardPlanSnapshot>,
    observed_peer_session_generation: Option<u64>,
    observed_recovery_epoch: Option<u64>,
}

impl HardHardClaimFailure {
    fn new(reason: HardHardClaimFailureReason) -> Self {
        Self {
            reason,
            observed_plan: None,
            observed_peer_session_generation: None,
            observed_recovery_epoch: None,
        }
    }

    fn log(
        self,
        token: Option<&str>,
        role: &'static str,
        plan: crate::peer::HardHardPlanSnapshot,
        peer_session_generation: crate::peer::PeerSessionGeneration,
        epoch: u64,
    ) {
        let (session_tag, plan_tag, identity_scope) = hard_hard_a0_stage_tags(token);
        tracing::info!(event = "hard_hard_claim_rejected", session_tag = %session_tag,
            plan_tag = %plan_tag, identity_scope, role, reason_code = self.reason.label(),
            expected_network_generation = plan.local_network_generation,
            observed_network_generation = ?self.observed_plan.map(|value| value.local_network_generation),
            expected_remote_candidate_epoch = plan.remote_candidate_epoch,
            observed_remote_candidate_epoch = ?self.observed_plan.map(|value| value.remote_candidate_epoch),
            expected_local_profile_generation = plan.local_profile_generation,
            observed_local_profile_generation = ?self.observed_plan.map(|value| value.local_profile_generation),
            expected_remote_profile_generation = plan.remote_profile_generation,
            observed_remote_profile_generation = ?self.observed_plan.map(|value| value.remote_profile_generation),
            expected_peer_session_generation = peer_session_generation.value(),
            observed_peer_session_generation = ?self.observed_peer_session_generation,
            expected_recovery_epoch = epoch, observed_recovery_epoch = ?self.observed_recovery_epoch,
            "Hard-Hard claim rejected at the original authoritative fence");
    }
}

fn hard_hard_recovery_claim_fence(
    admission: RecoveryAdmission,
    epoch: u64,
) -> std::result::Result<(), HardHardClaimFailure> {
    let (reason, observed) = match admission {
        RecoveryAdmission::Accepted { epoch: current } if current == epoch => return Ok(()),
        RecoveryAdmission::Accepted { epoch: current } => (
            HardHardClaimFailureReason::RecoveryEpochChanged,
            Some(current),
        ),
        RecoveryAdmission::BudgetExhausted { epoch: current } => (
            HardHardClaimFailureReason::RecoveryBudgetExhausted,
            Some(current),
        ),
        RecoveryAdmission::Superseded => (HardHardClaimFailureReason::RecoverySuperseded, None),
    };
    let mut failure = HardHardClaimFailure::new(reason);
    failure.observed_recovery_epoch = observed;
    Err(failure)
}
