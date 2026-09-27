// Included in hard_hard_wire_v2_tests to exercise the real manager transaction
// and coordination fences using the same canonical transcript fixtures.
fn initial_record(offer: &HardHardCoordination, offered: &[SocketAddr]) -> HardHardSessionRecord {
    let local = offer.v2.as_ref().unwrap().local;
    let mut coordinated = plan(local, HardHardOfferParameters::default());
    coordinated.phase = offer.v2.as_ref().unwrap().phase;
    coordinated.remote_offer = None;
    coordinated.agreement = None;
    coordinated.scheduled_start = Instant::now() + Duration::from_secs(2);
    coordinated.forecast_first_send_deadline = coordinated.scheduled_start;
    HardHardSessionRecord {
        session_id: offer.encode(),
        probe_session_id: None,
        session_token: offer.token.clone(),
        peer_id: "peer-negotiation".into(),
        initiator: true,
        pair_nomination: Some(Default::default()),
        coordinated_plan: Some(coordinated),
        remote_network_generation: 0,
        local_network_generation: offer.local_network_generation,
        remote_candidate_epoch: offer.remote_candidate_epoch,
        local_profile_generation: offer.local_profile_generation,
        remote_profile_generation: offer.remote_profile_generation,
        local_prediction_confidence: offer.local_prediction_confidence,
        remote_prediction_confidence: 0,
        requested_birthday_level: 0,
        generated_candidate_count: offered.len(),
        signaled_candidate_count: offered.len(),
        birthday: false,
        requested_socket_count: 2,
        requested_socket_indices: vec![4096, 4097],
        prediction_window: offered.to_vec(),
        remote_prediction: Vec::new(),
        fresh_socket: crate::peer::HardHardFreshSocketIdentity {
            peer_id: "peer-negotiation".into(),
            session_token: offer.token.clone(),
            network_generation: offer.local_network_generation,
            remote_candidate_epoch: offer.remote_candidate_epoch,
            local_profile_generation: offer.local_profile_generation,
            remote_profile_generation: offer.remote_profile_generation,
            punch_generation: 1,
            socket_index: 4096,
            socket_local_endpoint: "127.0.0.1:40000".parse().unwrap(),
        },
        punch_at_ms: hard_hard_now_ms().saturating_add(2_000),
        expires_at_ms: hard_hard_now_ms().saturating_add(30_000),
        state: HardHardSessionState::AwaitingPeer,
        attempt_count: 0,
        measurement: Default::default(),
        created_at: Instant::now(),
        cancellation: Arc::new(crate::PunchSessionCancellation::default()),
    }
}

#[tokio::test]
async fn first_answer_returns_the_committed_claim_snapshot_without_relaxing_identity() {
    let (offer, mut answer, offered, answered) = transcript();
    answer.v2.as_mut().unwrap().agreement = Some(HardHardAgreedPlan {
        strategy: HardHardProbeStrategy::FixedAnchor,
        digest: digest(&offer, &answer, &offered, &answered).unwrap(),
    });
    let peers =
        PeerManager::new(Config::generate_default("https://ctrl.test", "answer-snapshot").unwrap());
    let control = ControlClient::disabled_for_test();
    control.set_local_registration_for_test(Some(101), crate::control::PeerCapabilities::current());
    peers
        .add_peer(&crate::control::PeerInfo {
            capabilities: crate::control::PeerCapabilities::current(),
            registration_seq: 202,
            node_id: "peer-negotiation".into(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".into(),
            endpoint: answered[0].to_string(),
            nat_type: String::new(),
            virtual_ip: "10.20.0.2".into(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let before = initial_record(&offer, &offered);
    assert!(peers.hard_hard_register_session(before.clone()).await);
    let (ready, committed) = hard_hard_accept_answer(&peers, &control, &before, &answer, &answered)
        .await
        .expect("the first valid answer must install its reciprocal facts");
    assert_eq!(ready.v2.unwrap().stage, HardHardV2Stage::Ready);
    assert_eq!(
        committed.remote_network_generation,
        answer.local_network_generation
    );
    assert_eq!(committed.remote_prediction, answered);
    assert!(
        !hard_hard_initiator_response_record_matches(&committed, &before),
        "the old snapshot remains invalid"
    );
    assert!(hard_hard_initiator_response_record_matches(
        &committed, &committed
    ));
    assert!(
        peers
            .hard_hard_mark_candidate_signal_accepted(
                &before.peer_id,
                &before.session_token,
                Some(123),
                offered.len()
            )
            .await
    );
    let current = peers
        .hard_hard_session_by_token(&before.peer_id, &before.session_token)
        .await
        .unwrap();
    assert!(
        hard_hard_initiator_response_record_matches(&current, &committed),
        "HTTP receipt timing is observation-only"
    );
    for field in 0..4 {
        let mut changed = current.clone();
        match field {
            0 => changed.remote_candidate_epoch += 1,
            1 => changed.fresh_socket.socket_index += 1,
            2 => changed.remote_prediction.swap(0, 1),
            _ => changed.measurement.stun_datagrams_sent += 1,
        }
        assert!(!hard_hard_initiator_response_record_matches(
            &changed, &committed
        ));
    }
    let original = answer.v2.as_ref().unwrap();
    assert!(
        peers
            .hard_hard_agree_plan(
                &before.peer_id,
                &before.session_token,
                original.local,
                original.agreement.unwrap(),
                &answered,
                answer.local_network_generation,
                answer.local_prediction_confidence.saturating_sub(1),
                Duration::from_millis(25)
            )
            .await
            .is_none(),
        "a repeated answer cannot rewrite agreed confidence"
    );
    let retained = peers
        .hard_hard_session_by_token(&before.peer_id, &before.session_token)
        .await
        .unwrap();
    assert!(hard_hard_initiator_response_record_matches(
        &retained, &committed
    ));
}

#[test]
fn repeated_initial_signals_bind_the_full_transcript_and_original_deadline() {
    let (offer, mut answer, offered, answered) = transcript();
    let agreed = HardHardAgreedPlan {
        strategy: HardHardProbeStrategy::FixedAnchor,
        digest: digest(&offer, &answer, &offered, &answered).unwrap(),
    };
    answer.v2.as_mut().unwrap().agreement = Some(agreed);
    let mut record = initial_record(&offer, &offered);
    record.remote_prediction = answered.clone();
    record.coordinated_plan.as_mut().unwrap().agreement = Some(agreed);
    let candidates = answered.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert!(hard_hard_repeated_transcript_matches(
        &record,
        &answer,
        &candidates,
        Some(10_000)
    ));
    for change in 0..5 {
        let mut changed = answer.clone();
        match change {
            0 => changed.local_network_generation += 1,
            1 => changed.remote_candidate_epoch += 1,
            2 => changed.v2.as_mut().unwrap().rtt_ms += 1,
            3 => changed.v2.as_mut().unwrap().phase = false,
            _ => changed.local_prediction_confidence -= 1,
        }
        assert!(!hard_hard_repeated_transcript_matches(
            &record,
            &changed,
            &candidates,
            Some(10_000)
        ));
    }
    assert!(!hard_hard_repeated_transcript_matches(
        &record,
        &answer,
        &candidates,
        Some(10_001)
    ));
    let mut reordered = candidates.clone();
    reordered.swap(0, 1);
    assert!(!hard_hard_repeated_transcript_matches(
        &record,
        &answer,
        &reordered,
        Some(10_000)
    ));
    record
        .coordinated_plan
        .as_mut()
        .unwrap()
        .remote_registration_seq += 1;
    assert!(!hard_hard_repeated_transcript_matches(
        &record,
        &answer,
        &candidates,
        Some(10_000)
    ));
    record.initiator = false;
    record.remote_prediction = offered.clone();
    let candidates = offered.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert!(hard_hard_repeated_transcript_matches(
        &record,
        &offer,
        &candidates,
        Some(10_000)
    ));
    let mut changed_offer = offer.clone();
    changed_offer.local_network_generation += 1;
    assert!(!hard_hard_repeated_transcript_matches(
        &record,
        &changed_offer,
        &candidates,
        Some(10_000)
    ));
}

#[test]
fn retransmitted_ready_uses_outer_schedule_with_the_full_paced_forecast_margin() {
    let now = Instant::now();
    for (local, remote, pairs) in [
        (parameters(0, 2), parameters(0, 32), 32),
        (parameters(40_001, 2), parameters(50_001, 2), 4),
        (parameters(0, 0), parameters(0, 0), 0),
    ] {
        let mut value = plan(local, remote);
        value.scheduled_start = now + Duration::from_secs(2);
        value.forecast_first_send_deadline = value.scheduled_start;
        value.ready_retransmitted = true;
        value.ready_rtt = Some(Duration::from_secs(20)); // ambiguous, must not influence start
        let margin = if pairs == 0 {
            Duration::ZERO
        } else {
            crate::udp::hard_hard_first_wave_pacing_margin(pairs)
        };
        let start = hard_hard_choose_start(&value, now).unwrap();
        assert_eq!(start.server_time_ms, 10_000 - margin.as_millis() as u64);
        assert_eq!(
            value.forecast_first_send_deadline,
            now + Duration::from_secs(2)
        );
        value.ready_rtt = None;
        assert_eq!(hard_hard_choose_start(&value, now), Some(start));
        value.scheduled_start = now + margin + Duration::from_millis(149);
        assert!(
            hard_hard_choose_start(&value, now).is_none(),
            "SYNC still needs a bounded delivery window"
        );
    }
    let mut value = plan(parameters(0, 32), parameters(0, 32));
    value.scheduled_start = now + Duration::from_millis(200);
    value.ready_rtt = Some(Duration::from_millis(50));
    assert!(
        hard_hard_choose_start(&value, now).is_none(),
        "lead equal to remaining leaves no predicted first-wave time"
    );
}

#[test]
fn conservative_start_leaves_the_entire_confirmation_window_inside_original_lifetime() {
    let now = Instant::now();
    let original_expiry = 18_100;
    let latest = crate::peer::hard_hard_latest_start_for_session(original_expiry, 10_000, now);
    for (local, remote) in [
        (parameters(0, 32), parameters(0, 32)),
        (parameters(40_001, 2), parameters(50_001, 2)),
        (parameters(0, 0), parameters(0, 0)),
    ] {
        let mut value = plan(local, remote);
        value.ready_retransmitted = true;
        value.scheduled_start = now + Duration::from_millis(3_500);
        value.forecast_first_send_deadline = value.scheduled_start;
        let chosen = hard_hard_choose_start_with_lifetime(&value, now, latest).unwrap();
        let actual = value.scheduled_start
            - Duration::from_millis(value.canonical_server_deadline - chosen.server_time_ms);
        assert!(actual <= latest.unwrap());
        assert!(
            actual + HARD_HARD_SWEEP_DEADLINE + HARD_HARD_DIRECT_CONFIRMATION_GRACE
                <= now + Duration::from_millis(original_expiry - 10_000)
        );
        assert_eq!(
            value.forecast_first_send_deadline,
            now + Duration::from_millis(3_500)
        );
        assert_eq!(
            value.scheduled_start, value.forecast_first_send_deadline,
            "selection is a snapshot, not a lifetime mutation"
        );
        assert_eq!(
            hard_hard_choose_start_with_lifetime(
                &value,
                now,
                crate::peer::hard_hard_latest_start_for_session(15_100, 10_000, now)
            ),
            Err(HardHardStartWindowRejection::ConfirmationWindowInsufficient)
        );
    }
}

#[tokio::test]
async fn both_roles_reject_activation_that_would_truncate_confirmation_without_renewing_ttl() {
    let (offer, _, offered, _) = transcript();
    for initiator in [true, false] {
        let peers = PeerManager::new(
            Config::generate_default("https://ctrl.test", "start-lifetime").unwrap(),
        );
        let mut record = initial_record(&offer, &offered);
        record.initiator = initiator;
        record.expires_at_ms = hard_hard_now_ms() + 6_000;
        let expiry = record.expires_at_ms;
        let base = HardHardAgreedPlan {
            strategy: HardHardProbeStrategy::Birthday,
            digest: [42; 16],
        };
        let value = record.coordinated_plan.as_mut().unwrap();
        value.agreement = Some(base);
        value.ready_received = !initiator;
        value.ready_ack_received = initiator;
        value.scheduled_start = Instant::now() + Duration::from_millis(1_500);
        value.forecast_first_send_deadline = value.scheduled_start;
        let original_start = value.scheduled_start;
        let too_late = crate::peer::HardHardAgreedStart {
            server_time_ms: value.canonical_server_deadline,
            agreement: crate::peer::hard_hard_start_agreement(
                base,
                value.canonical_server_deadline,
            ),
        };
        let fits = crate::peer::HardHardAgreedStart {
            server_time_ms: value.canonical_server_deadline - 700,
            agreement: crate::peer::hard_hard_start_agreement(
                base,
                value.canonical_server_deadline - 700,
            ),
        };
        assert!(peers.hard_hard_register_session(record.clone()).await);
        assert!(
            !peers
                .hard_hard_activate_start(&record.peer_id, &record.session_token, too_late)
                .await
        );
        let retained = peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
            .unwrap();
        assert!(retained.coordinated_plan.as_ref().unwrap().start.is_none());
        assert_eq!(retained.expires_at_ms, expiry);
        assert!(
            peers
                .hard_hard_activate_start(&record.peer_id, &record.session_token, fits)
                .await
        );
        assert!(
            peers
                .hard_hard_activate_start(&record.peer_id, &record.session_token, fits)
                .await,
            "same start remains idempotent"
        );
        let retained = peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
            .unwrap();
        assert_eq!(retained.expires_at_ms, expiry);
        let value = retained.coordinated_plan.unwrap();
        assert_eq!(value.forecast_first_send_deadline, original_start);
        assert_eq!(
            value.scheduled_start,
            original_start - Duration::from_millis(700)
        );
    }
}
