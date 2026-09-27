use super::*;

fn forecast_plan(strategy: HardHardProbeStrategy, upper: Instant) -> HardHardCoordinatedPlan {
    HardHardCoordinatedPlan {
        measurement_lease: None,
        recovery_identity: None,
        strategy_order: 0,
        local_offer: HardHardOfferParameters::default(),
        remote_offer: None,
        local_registration_seq: 1,
        remote_registration_seq: 2,
        phase: false,
        canonical_server_deadline: 3_500,
        scheduled_start: upper,
        forecast_first_send_deadline: upper,
        agreement: Some(HardHardAgreedPlan {
            strategy,
            digest: [1; 16],
        }),
        ready_received: true,
        ready_ack_received: true,
        ready_sent_at: None,
        ready_retransmitted: false,
        ready_rtt: None,
        sync_uncertainty: Duration::ZERO,
        start: None,
        start_ack_received: true,
        start_ack_queued: true,
        start_ack_delivery: None,
    }
}

fn pair(index: usize) -> HardHardPairKey {
    HardHardPairKey {
        socket_index: index,
        local_endpoint: SocketAddr::from(([127, 0, 0, 1], 40_000 + index as u16)),
        remote_endpoint: SocketAddr::from(([203, 0, 113, 1], 50_000)),
    }
}

#[test]
fn predicted_retransmission_requires_success_on_the_exact_socket_target_pair() {
    let upper = Instant::now() + Duration::from_secs(1);
    let discovery = tokio::time::Instant::from_std(upper + Duration::from_secs(3));
    let plan = forecast_plan(HardHardProbeStrategy::Predictable, upper);
    let mut nomination = HardHardPairNomination::default();
    let sent = pair(0);
    let forecast = Some((tokio::time::Instant::from_std(upper), true));
    assert_eq!(
        hard_hard_exploration_forecast_deadline(Some(&plan), &nomination, &sent, discovery),
        forecast
    );
    assert!(nomination.record_exploration_handoff(&sent));
    assert_eq!(
        hard_hard_exploration_forecast_deadline(Some(&plan), &nomination, &sent, discovery),
        Some((discovery, true))
    );
    let mut different_target = sent.clone();
    different_target.remote_endpoint.set_port(50_001);
    let mut replaced_socket = sent.clone();
    replaced_socket.local_endpoint.set_port(40_001);
    for unsent in [pair(1), different_target, replaced_socket] {
        assert_eq!(
            hard_hard_exploration_forecast_deadline(Some(&plan), &nomination, &unsent, discovery),
            forecast
        );
    }
    assert_eq!(nomination.exploration_handoffs.len(), 1);
}

#[test]
fn every_fixed_anchor_socket_keeps_original_upper_bound_after_sync_advances_start() {
    for sockets in [2, 4, 8] {
        let upper = Instant::now() + Duration::from_secs(1);
        let discovery = tokio::time::Instant::from_std(upper + Duration::from_secs(3));
        let mut plan = forecast_plan(HardHardProbeStrategy::FixedAnchor, upper);
        plan.scheduled_start = upper - Duration::from_millis(500);
        let mut nomination = HardHardPairNomination::default();
        for index in 0..sockets {
            let current = pair(index);
            assert_eq!(
                hard_hard_exploration_forecast_deadline(
                    Some(&plan),
                    &nomination,
                    &current,
                    discovery
                ),
                Some((upper.into(), true)),
                "a prior socket must not exempt socket {index}"
            );
            assert!(nomination.record_exploration_handoff(&current));
            assert_eq!(
                hard_hard_exploration_forecast_deadline(
                    Some(&plan),
                    &nomination,
                    &current,
                    discovery
                ),
                Some((discovery, true))
            );
        }
        for index in 0..sockets {
            assert!(nomination.record_exploration_handoff(&pair(index)));
        }
        assert_eq!(nomination.exploration_handoffs.len(), sockets);
        assert_eq!(plan.forecast_first_send_deadline, upper);
    }
}

#[test]
fn birthday_and_legacy_exploration_keep_phase_deadline_without_prediction_ledger() {
    let upper = Instant::now() - Duration::from_millis(1);
    let discovery = tokio::time::Instant::now() + Duration::from_secs(3);
    let plan = forecast_plan(HardHardProbeStrategy::Birthday, upper);
    let nomination = HardHardPairNomination::default();
    for plan in [None, Some(&plan)] {
        assert_eq!(
            hard_hard_exploration_forecast_deadline(plan, &nomination, &pair(0), discovery),
            Some((discovery, false))
        );
    }
    assert!(nomination.exploration_handoffs.is_empty());
}

#[test]
fn received_or_acknowledged_pair_does_not_fabricate_a_local_kernel_handoff() {
    let upper = Instant::now() - Duration::from_millis(1);
    let discovery = tokio::time::Instant::now() + Duration::from_secs(3);
    let plan = forecast_plan(HardHardProbeStrategy::FixedAnchor, upper);
    let mut nomination = HardHardPairNomination::default();
    nomination.candidates.push(HardHardPairCandidate {
        pair: pair(0),
        valid: true,
        attempts: 1,
        local_deferrals: 0,
        next_check: Instant::now(),
    });
    let (deadline, track) =
        hard_hard_exploration_forecast_deadline(Some(&plan), &nomination, &pair(0), discovery)
            .unwrap();
    assert!(track);
    assert!(deadline < tokio::time::Instant::now());
    assert!(nomination.exploration_handoffs.is_empty());
}

#[test]
fn handoff_history_is_bounded_and_never_extends_the_discovery_phase() {
    let upper = Instant::now() + Duration::from_secs(2);
    let discovery = tokio::time::Instant::from_std(upper - Duration::from_secs(1));
    let plan = forecast_plan(HardHardProbeStrategy::Predictable, upper);
    let mut nomination = HardHardPairNomination::default();
    assert_eq!(
        hard_hard_exploration_forecast_deadline(Some(&plan), &nomination, &pair(0), discovery),
        Some((discovery, true))
    );
    for index in 0..HARD_HARD_PAIR_MAX_CANDIDATES {
        assert!(nomination.record_exploration_handoff(&pair(index)));
    }
    assert!(!nomination.record_exploration_handoff(&pair(HARD_HARD_PAIR_MAX_CANDIDATES)));
    assert_eq!(
        hard_hard_exploration_forecast_deadline(
            Some(&plan),
            &nomination,
            &pair(HARD_HARD_PAIR_MAX_CANDIDATES),
            discovery
        ),
        None
    );
    assert_eq!(
        hard_hard_exploration_forecast_deadline(Some(&plan), &nomination, &pair(0), discovery),
        Some((discovery, true))
    );
    assert_eq!(
        nomination.exploration_handoffs.len(),
        HARD_HARD_PAIR_MAX_CANDIDATES
    );
}
