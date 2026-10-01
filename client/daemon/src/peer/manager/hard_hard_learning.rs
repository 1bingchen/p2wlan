// Performance advice only: these bounded, expiring scores never authorize a
// socket, a candidate, extra scan credit or a Direct transition. The negotiated
// plan must still validate the availability and budget of every chosen strategy.
const HARD_HARD_LEARNING_CAPACITY: usize = 64;
// A fully spent HH epoch permits its next attempt after 30 minutes. Advice
// must survive that default cadence, without becoming a permanent preference.
const HARD_HARD_LEARNING_TTL: Duration = Duration::from_secs(RECOVERY_EPOCH_MAX_AGE.as_secs() * 3);
const HARD_HARD_LEARNING_DECAY_INTERVAL: Duration =
    Duration::from_secs(RECOVERY_EPOCH_MAX_AGE.as_secs() * 2);

#[derive(Debug, Clone)]
pub(crate) enum HardHardStrategyOutcome {
    /// Only a completed exploration with successful physical sends and no
    /// authenticated responses belongs here. Budget exhaustion, cancellation,
    /// identity, signaling, measurement and nomination failures are inconclusive.
    ExploredNoResponse {
        identity: HardHardFreshSocketIdentity,
        probes_sent: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HardHardLearningScope {
    network_generation: u64,
    peer_session: PeerSessionGeneration,
    local_profile_generation: u64,
    remote_profile_generation: u64,
}

#[derive(Debug)]
struct HardHardLearningEntry {
    scope: HardHardLearningScope,
    // Anchor, prediction, birthday. Tiny saturating scores favor observed
    // success without letting ancient attempts dominate a changed network.
    scores: [i8; 3],
    /// Tie order starts after the last conclusive attempt. It rotates even
    /// when all scores reach the floor, and never changes a strategy's budget.
    tie_start: u8,
    last_token: String,
    recorded_at: Instant,
    decayed_at: Instant,
}

impl HardHardLearningEntry {
    fn new(scope: HardHardLearningScope, now: Instant) -> Self {
        Self {
            scope,
            scores: [0; 3],
            tie_start: 0,
            last_token: String::new(),
            recorded_at: now,
            decayed_at: now,
        }
    }

    fn decay(&mut self, now: Instant) {
        let Some(elapsed) = now.checked_duration_since(self.decayed_at) else {
            return;
        };
        let intervals = elapsed.as_secs() / HARD_HARD_LEARNING_DECAY_INTERVAL.as_secs();
        if intervals == 0 {
            return;
        }
        let decay = intervals.min(3) as i8;
        for score in &mut self.scores {
            *score -= score.signum() * score.abs().min(decay);
        }
        // Feedback refreshes the finite TTL but not this decay clock. Frequent
        // observations therefore cannot keep old scores from aging away.
        self.decayed_at +=
            Duration::from_secs(intervals * HARD_HARD_LEARNING_DECAY_INTERVAL.as_secs());
    }
}

#[derive(Debug, Default)]
struct HardHardStrategyLearning {
    entries: HashMap<String, HardHardLearningEntry>,
}

impl HardHardStrategyLearning {
    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            now.checked_duration_since(entry.recorded_at)
                .is_some_and(|age| age < HARD_HARD_LEARNING_TTL)
        });
    }

    fn order(&mut self, peer: &str, scope: HardHardLearningScope, now: Instant) -> u8 {
        self.prune(now);
        let Some(entry) = self
            .entries
            .get_mut(peer)
            .filter(|entry| entry.scope == scope)
        else {
            return 0;
        };
        entry.decay(now);
        // The empty-cache default remains anchor-first. Equal scores after
        // actual attempts cycle through the three bounded preference orders.
        let first = usize::from(entry.tie_start);
        (1..3)
            .map(|offset| (first + offset) % 3)
            .fold(first, |best, index| {
                if entry.scores[index] > entry.scores[best] {
                    index
                } else {
                    best
                }
            }) as u8
    }

    fn record(
        &mut self,
        peer: &str,
        scope: HardHardLearningScope,
        token: &str,
        strategy: HardHardProbeStrategy,
        success: bool,
        now: Instant,
    ) -> bool {
        self.prune(now);
        if !self.entries.contains_key(peer) && self.entries.len() >= HARD_HARD_LEARNING_CAPACITY {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.recorded_at)
                .map(|(peer, _)| peer.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        let entry = self
            .entries
            .entry(peer.to_string())
            .or_insert_with(|| HardHardLearningEntry::new(scope, now));
        if entry.scope != scope {
            *entry = HardHardLearningEntry::new(scope, now);
        }
        if entry.last_token == token {
            return false;
        }
        entry.decay(now);
        let index = match strategy {
            HardHardProbeStrategy::FixedAnchor => 0,
            HardHardProbeStrategy::Predictable => 1,
            HardHardProbeStrategy::Birthday => 2,
        };
        if success {
            // Prefer the latest proven path when two strategies previously
            // succeeded, while retaining a small bounded history for failures.
            for score in &mut entry.scores {
                *score = score.saturating_sub(1).max(-3);
            }
            entry.scores[index] = 3;
        } else {
            entry.scores[index] = entry.scores[index].saturating_sub(1).max(-3);
        }
        entry.tie_start = (index as u8 + 1) % 3;
        entry.last_token = token.to_string();
        entry.recorded_at = now;
        true
    }
}

impl PeerManager {
    fn hard_hard_learning_scope(
        &self,
        peer: &str,
        conn: &PeerConnection,
    ) -> Option<HardHardLearningScope> {
        if !conn.online
            || !conn.capabilities.supports_hh2()
            || conn.registration_seq == 0
            || !conn.remote_nat_profile_is_fresh()
            || !conn.remote_nat_profile_matches_candidate_epoch()
        {
            return None;
        }
        Some(HardHardLearningScope {
            network_generation: self.current_network_generation_sync(),
            peer_session: self.peer_session_generation_sync(peer)?,
            local_profile_generation: self.current_local_profile_generation_sync(),
            remote_profile_generation: conn.remote_nat_profile.as_ref()?.generation?,
        })
    }

    /// 0: anchor/predict/birthday; 1: predict/anchor/birthday;
    /// 2: birthday/predict/anchor. Contention or absent evidence uses 0.
    pub(crate) async fn hard_hard_strategy_order(&self, peer: &str) -> u8 {
        let Ok(connections) = self.connections.try_read() else {
            return 0;
        };
        let Some(conn) = connections.get(peer) else {
            return 0;
        };
        let Some(scope) = self.hard_hard_learning_scope(peer, conn) else {
            return 0;
        };
        let Ok(mut learning) = self.hard_hard_strategy_learning.try_lock() else {
            return 0;
        };
        learning.order(peer, scope, Instant::now())
    }

    /// Best-effort advice with no awaits under locks. The live HH record and
    /// connection provide all correctness facts; this cache only stores scores.
    /// Call before retiring/removing the exact attempt record. Contention may
    /// drop advice, but cannot delay path confirmation or cleanup.
    pub(crate) async fn record_hard_hard_strategy_outcome(
        &self,
        peer: &str,
        strategy: HardHardProbeStrategy,
        outcome: HardHardStrategyOutcome,
    ) -> bool {
        // Inconclusive attempts are deliberately not recorded. Positive
        // feedback belongs exclusively to the authoritative Direct commit.
        let identity = match outcome {
            HardHardStrategyOutcome::ExploredNoResponse {
                identity,
                probes_sent,
            } if probes_sent > 0 => identity,
            _ => return false,
        };
        if identity.peer_id != peer {
            return false;
        }
        // try_lock follows the normal epoch -> connection order and never
        // waits behind a session holder that may itself need the connection.
        let Ok(_epoch) = self.network_epoch_gate.try_lock() else {
            return false;
        };
        let Ok(connections) = self.connections.try_read() else {
            return false;
        };
        let Some(conn) = connections.get(peer) else {
            return false;
        };
        let Some(scope) = self.hard_hard_learning_scope(peer, conn) else {
            return false;
        };
        if scope.network_generation != identity.network_generation
            || scope.local_profile_generation != identity.local_profile_generation
            || scope.remote_profile_generation != identity.remote_profile_generation
            || conn.remote_candidate_epoch() != identity.remote_candidate_epoch
        {
            return false;
        }
        let Ok(sessions) = self.hard_hard_sessions.try_lock() else {
            return false;
        };
        let Some(record) = sessions.values().find(|record| {
            record.peer_id == peer
                && record.session_token == identity.session_token
                && record.fresh_socket == identity
                && record.state == HardHardSessionState::Sweeping
                && record.expires_at_ms >= hard_hard_now_ms()
        }) else {
            return false;
        };
        let Some(plan) = record.coordinated_plan.as_ref() else {
            return false;
        };
        if !plan.ready(record.initiator)
            || plan.remote_registration_seq != conn.registration_seq
            || !plan
                .agreement
                .is_some_and(|agreement| agreement.strategy == strategy)
        {
            return false;
        }
        let Some(nomination) = record.pair_nomination.as_ref() else {
            return false;
        };
        if record.cancellation.is_cancelled()
            || conn.state == ConnectionState::Direct
            || !nomination.worker_claimed
            || !nomination
                .discovery_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
            || !nomination.candidates.is_empty()
            || nomination.selected.is_some()
        {
            // Any authenticated connectivity or nomination evidence makes
            // this an inconclusive confirmation failure, never scan evidence.
            return false;
        }
        let Ok(mut learning) = self.hard_hard_strategy_learning.try_lock() else {
            return false;
        };
        learning.record(
            peer,
            scope,
            &identity.session_token,
            strategy,
            false,
            Instant::now(),
        )
    }
}

impl HardHardPairCommitGuard<'_> {
    /// Called by the Direct reducer's finish hook after all Direct mirrors
    /// were published, before releasing this exact session/socket transaction.
    /// The connection and epoch guards are already held by that reducer; never
    /// reacquire them here. Advice contention cannot delay the actual commit.
    pub(crate) fn record_strategy_success_after_direct_commit(&self) -> bool {
        let Some(record) = self.sessions.get(&self.record_key) else {
            return false;
        };
        let Some(plan) = record.coordinated_plan.as_ref() else {
            return false;
        };
        let Some(agreement) = plan.agreement else {
            return false;
        };
        let Some(peer_session) = self.manager.peer_session_generation_sync(&record.peer_id) else {
            return false;
        };
        if !plan.ready(record.initiator)
            || self.pair.socket_index != record.fresh_socket.socket_index
            || self.pair.local_endpoint != record.fresh_socket.socket_local_endpoint
            || record.local_network_generation != self.manager.current_network_generation_sync()
            || record.local_profile_generation
                != self.manager.current_local_profile_generation_sync()
            || !self
                .manager
                .direct_commit_pair_matches_sync(&record.fresh_socket)
        {
            return false;
        }
        let scope = HardHardLearningScope {
            network_generation: record.local_network_generation,
            peer_session,
            local_profile_generation: record.local_profile_generation,
            remote_profile_generation: record.remote_profile_generation,
        };
        let Ok(mut learning) = self.manager.hard_hard_strategy_learning.try_lock() else {
            return false;
        };
        learning.record(
            &record.peer_id,
            scope,
            &record.session_token,
            agreement.strategy,
            true,
            Instant::now(),
        )
    }
}

#[cfg(test)]
mod hard_hard_learning_tests {
    use super::*;

    fn scope() -> HardHardLearningScope {
        HardHardLearningScope {
            network_generation: 1,
            peer_session: PeerSessionGeneration::for_test(2),
            local_profile_generation: 3,
            remote_profile_generation: 4,
        }
    }

    #[test]
    fn evidence_changes_only_bounded_order_and_duplicate_attempt_is_ignored() {
        let mut cache = HardHardStrategyLearning::default();
        let now = Instant::now();
        assert_eq!(cache.order("peer", scope(), now), 0);
        assert!(cache.record(
            "peer",
            scope(),
            "one",
            HardHardProbeStrategy::FixedAnchor,
            false,
            now
        ));
        assert_eq!(cache.order("peer", scope(), now), 1);
        assert!(!cache.record(
            "peer",
            scope(),
            "one",
            HardHardProbeStrategy::Predictable,
            false,
            now
        ));
        assert_eq!(cache.order("peer", scope(), now), 1);
        assert!(cache.record(
            "peer",
            scope(),
            "two",
            HardHardProbeStrategy::Predictable,
            false,
            now
        ));
        assert_eq!(cache.order("peer", scope(), now), 2);
        assert!(cache.record(
            "peer",
            scope(),
            "three",
            HardHardProbeStrategy::FixedAnchor,
            true,
            now
        ));
        assert_eq!(cache.order("peer", scope(), now), 0);
    }

    #[test]
    fn every_identity_domain_and_ttl_reset_advice() {
        let mut cache = HardHardStrategyLearning::default();
        let now = Instant::now();
        cache.record(
            "peer",
            scope(),
            "one",
            HardHardProbeStrategy::Birthday,
            true,
            now,
        );
        assert_eq!(cache.order("peer", scope(), now), 2);
        let original = scope();
        for changed in [
            HardHardLearningScope {
                network_generation: 2,
                ..original
            },
            HardHardLearningScope {
                peer_session: PeerSessionGeneration::for_test(3),
                ..original
            },
            HardHardLearningScope {
                local_profile_generation: 4,
                ..original
            },
            HardHardLearningScope {
                remote_profile_generation: 5,
                ..original
            },
        ] {
            assert_eq!(cache.order("peer", changed, now), 0);
        }
        assert_eq!(
            cache.order("peer", scope(), now + HARD_HARD_LEARNING_TTL),
            0
        );
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn capacity_is_hard_bounded_and_reads_do_not_extend_ttl() {
        let mut cache = HardHardStrategyLearning::default();
        let now = Instant::now();
        for n in 0..100 {
            cache.record(
                &format!("peer-{n}"),
                scope(),
                "one",
                HardHardProbeStrategy::Predictable,
                true,
                now + Duration::from_millis(n),
            );
            assert!(cache.entries.len() <= HARD_HARD_LEARNING_CAPACITY);
        }
        assert!(!cache.entries.contains_key("peer-0"));
        let saved = cache.entries["peer-99"].recorded_at;
        assert_eq!(
            cache.order("peer-99", scope(), saved + Duration::from_secs(1)),
            1
        );
        assert_eq!(cache.entries["peer-99"].recorded_at, saved);
    }

    #[test]
    fn negative_advice_survives_the_default_recovery_cadence() {
        let mut cache = HardHardStrategyLearning::default();
        let now = Instant::now();
        cache.record(
            "peer",
            scope(),
            "anchor",
            HardHardProbeStrategy::FixedAnchor,
            false,
            now,
        );
        let second = now + RECOVERY_EPOCH_MAX_AGE;
        assert_eq!(cache.order("peer", scope(), second), 1);
        cache.record(
            "peer",
            scope(),
            "prediction",
            HardHardProbeStrategy::Predictable,
            false,
            second,
        );
        // At 60min old scores decay, while the tie cursor still gives the
        // as-yet-untried birthday preference its bounded opportunity.
        let third = second + RECOVERY_EPOCH_MAX_AGE;
        assert_eq!(cache.order("peer", scope(), third), 2);
        cache.record(
            "peer",
            scope(),
            "birthday",
            HardHardProbeStrategy::Birthday,
            false,
            third,
        );
        assert_eq!(
            cache.order("peer", scope(), third + RECOVERY_EPOCH_MAX_AGE),
            0
        );
    }

    #[test]
    fn tied_and_saturated_negative_scores_rotate_without_new_credit() {
        let mut cache = HardHardStrategyLearning::default();
        let now = Instant::now();
        let strategies = [
            HardHardProbeStrategy::FixedAnchor,
            HardHardProbeStrategy::Predictable,
            HardHardProbeStrategy::Birthday,
        ];
        // The first nine conclusive failures reach [-3;3]. Every subsequent
        // failure must still rotate, instead of permanently selecting anchor.
        for attempt in 0..18 {
            let index = attempt % 3;
            assert_eq!(cache.order("peer", scope(), now), index as u8);
            assert!(cache.record(
                "peer",
                scope(),
                &format!("attempt-{attempt}"),
                strategies[index],
                false,
                now
            ));
        }
        assert_eq!(cache.entries["peer"].scores, [-3; 3]);
        assert_eq!(cache.order("peer", scope(), now), 0);
        let expiry = cache.entries["peer"].recorded_at;
        assert!(!cache.record(
            "peer",
            scope(),
            "attempt-17",
            HardHardProbeStrategy::Birthday,
            false,
            now + RECOVERY_EPOCH_MAX_AGE
        ));
        assert_eq!(cache.entries["peer"].recorded_at, expiry);
        assert_eq!(cache.order("peer", scope(), now), 0);
    }

    #[test]
    fn feedback_does_not_restart_decay_and_reads_do_not_restart_expiry() {
        let mut cache = HardHardStrategyLearning::default();
        let now = Instant::now();
        cache.record(
            "peer",
            scope(),
            "success",
            HardHardProbeStrategy::FixedAnchor,
            true,
            now,
        );
        let later = now + RECOVERY_EPOCH_MAX_AGE;
        cache.record(
            "peer",
            scope(),
            "other-failure",
            HardHardProbeStrategy::Predictable,
            false,
            later,
        );
        assert_eq!(cache.entries["peer"].decayed_at, now);
        let decay_at = now + HARD_HARD_LEARNING_DECAY_INTERVAL;
        assert_eq!(cache.order("peer", scope(), decay_at), 0);
        assert_eq!(cache.entries["peer"].scores, [2, -1, 0]);
        assert_eq!(cache.entries["peer"].decayed_at, decay_at);
        assert_eq!(cache.entries["peer"].recorded_at, later);
        // Re-reading in the same interval applies no additional decay.
        assert_eq!(cache.order("peer", scope(), decay_at), 0);
        assert_eq!(cache.entries["peer"].scores, [2, -1, 0]);
        assert_eq!(
            cache.order("peer", scope(), later + HARD_HARD_LEARNING_TTL),
            0
        );
        assert!(cache.entries.is_empty());
    }
}
