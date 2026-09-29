use super::*;

fn observation_fixture(
    hh2: bool,
) -> (
    HardHardAttemptEvidence,
    HardHardObservationIdentity,
    HardHardPairKey,
    HardHardAttemptReport,
) {
    let pair = HardHardPairKey {
        socket_index: 4096,
        local_endpoint: "127.0.0.1:40000".parse().unwrap(),
        remote_endpoint: "198.51.100.2:41000".parse().unwrap(),
    };
    let identity = HardHardObservationIdentity {
        session_id: "attempt-a".into(),
        socket: HardHardFreshSocketIdentity {
            peer_id: "peer".into(),
            session_token: "token-a".into(),
            network_generation: 2,
            remote_candidate_epoch: 3,
            local_profile_generation: 4,
            remote_profile_generation: 5,
            punch_generation: 6,
            socket_index: pair.socket_index,
            socket_local_endpoint: pair.local_endpoint,
        },
        peer_session: PeerSessionGeneration(7),
        socket_indices: vec![pair.socket_index],
    };
    let mut evidence = HardHardAttemptEvidence::default();
    evidence.bind(
        identity.clone(),
        1,
        Some(HardHardProbeStrategy::Predictable),
        hh2,
    );
    let report = HardHardAttemptReport {
        network_generation: 2,
        remote_candidate_epoch: 3,
        local_profile_generation: 4,
        remote_profile_generation: 5,
        punch_generation: 6,
        peer_session_generation: 7,
        socket_index: Some(pair.socket_index),
        attempt: 1,
        ..HardHardAttemptReport::default()
    };
    (evidence, identity, pair, report)
}

#[test]
fn archived_terminal_survives_peer_replacement_without_double_recording() {
    let (_, _, _, mut report) = observation_fixture(true);
    report.session_tag = "0123456789abcdef".into();
    report.plan_tag = "abcdef0123456789".into();
    report.counts.send_success_datagrams = 24;
    let timeline = ConnectionTimeline::new("node-a", 0);
    let mut terminal = HardHardTerminalObservation {
        report: Some(report),
        peer_id: "peer".into(),
        timeline: Some(timeline.clone()),
    };

    terminal.archive("terminal_identity_superseded");
    drop(terminal);
    let summaries = timeline.snapshot().hard_hard_terminal_summaries;
    assert_eq!(summaries.len(), 1);
    assert!(!summaries[0].current_connection_committed);
    assert_eq!(
        summaries[0].archive_reason.as_deref(),
        Some("terminal_identity_superseded")
    );
    assert_eq!(summaries[0].send_success_datagrams, 24);
}

#[test]
fn historical_terminal_retention_is_fixed_size() {
    let (_, _, _, report) = observation_fixture(true);
    let timeline = ConnectionTimeline::new("node-a", 0);
    for index in 0..(crate::connection_timeline::HARD_HARD_TERMINAL_SUMMARY_MAX_ENTRIES + 4) {
        timeline.record_hard_hard_terminal(&format!("peer-{index}"), &report, true, None);
    }
    let summaries = timeline.snapshot().hard_hard_terminal_summaries;
    assert_eq!(
        summaries.len(),
        crate::connection_timeline::HARD_HARD_TERMINAL_SUMMARY_MAX_ENTRIES
    );
    assert_eq!(summaries[0].peer_id, "peer-4");
    assert_eq!(summaries.last().unwrap().peer_id, "peer-19");
}

#[test]
fn observation_isolates_rebound_token_and_caps_pair_detail() {
    let (evidence, mut identity, pair, _) = observation_fixture(true);
    for port in 41000..41100 {
        let mut received_pair = pair.clone();
        received_pair.remote_endpoint.set_port(port);
        evidence.record_receive(
            received_pair,
            HardHardReceiveObservation::AuthenticatedPunch,
            10,
        );
    }
    assert_eq!(
        evidence
            .receive_snapshot()
            .authenticated_probe_packets_received,
        100
    );
    assert_eq!(
        evidence.0.lock().unwrap().pairs.len(),
        HARD_HARD_PAIR_MAX_CANDIDATES
    );
    let mut wrong_socket = pair.clone();
    wrong_socket.socket_index += 1;
    evidence.record_receive(wrong_socket, HardHardReceiveObservation::MatchedAck, 11);
    assert_eq!(evidence.receive_snapshot().probe_acks_received, 0);

    let mut replacement = evidence.clone();
    identity.socket.session_token = "token-b".into();
    replacement.bind(identity, 0, None, true);
    assert_ne!(replacement, evidence);
    assert_eq!(
        replacement.receive_snapshot(),
        crate::udp::UdpProbeRxSnapshot::default()
    );
    replacement.record_receive(pair, HardHardReceiveObservation::AuthenticatedAck, 12);
    assert_eq!(
        evidence
            .receive_snapshot()
            .authenticated_probe_acks_observed,
        0
    );
}

#[test]
fn terminal_freeze_and_once_only_seal_survive_same_identity_rebind() {
    let (mut evidence, identity, pair, mut report) = observation_fixture(true);
    evidence.record_receive(
        pair.clone(),
        HardHardReceiveObservation::AuthenticatedAck,
        10,
    );
    evidence.record_receive(pair.clone(), HardHardReceiveObservation::MatchedAck, 11);
    evidence.record_confirmation_handoff(HardHardConfirmationPurpose::ValidationRequest, 80);
    let frozen = evidence
        .freeze_receive_snapshot(&identity.socket, identity.peer_session, 1)
        .unwrap();
    evidence.record_receive(pair, HardHardReceiveObservation::AuthenticatedPunch, 12);
    evidence.record_confirmation_handoff(HardHardConfirmationPurpose::ValidationRequest, 80);
    assert_eq!(evidence.receive_snapshot(), frozen);
    assert!(evidence.seal_report("peer", "token-a", &mut report));
    assert_eq!(
        report
            .confirmation
            .as_ref()
            .unwrap()
            .validation_request
            .datagrams,
        1
    );
    evidence.bind(identity, 1, Some(HardHardProbeStrategy::Predictable), true);
    assert!(!evidence.seal_report("peer", "token-a", &mut report));
}

#[test]
fn confirmation_unknown_is_not_zero_and_failed_admission_is_not_handoff() {
    let (legacy, _, _, mut legacy_report) = observation_fixture(false);
    legacy.record_confirmation_handoff(HardHardConfirmationPurpose::ProbeAck, 64);
    assert!(legacy.seal_report("peer", "token-a", &mut legacy_report));
    assert!(legacy_report.confirmation.is_none());
    let legacy_json = serde_json::to_value(&legacy_report).unwrap();
    assert!(legacy_json.get("confirmation").is_none());
    assert!(serde_json::from_value::<HardHardAttemptReport>(legacy_json)
        .unwrap()
        .confirmation
        .is_none());

    let (evidence, _, _, mut report) = observation_fixture(true);
    evidence.record_send_outcome(HardHardPairSendOutcome::BudgetDeferred);
    evidence.record_send_outcome(HardHardPairSendOutcome::DeliveryUnknown);
    evidence.record_send_outcome(HardHardPairSendOutcome::RetryableNotSent);
    evidence.record_send_outcome(HardHardPairSendOutcome::Stopped);
    evidence.record_confirmation_handoff(HardHardConfirmationPurpose::Nomination, 64);
    assert!(evidence.seal_report("peer", "token-a", &mut report));
    let costs = report.confirmation.unwrap();
    assert_eq!(
        (
            costs.budget_deferred,
            costs.delivery_unknown,
            costs.retryable_not_sent,
            costs.stopped
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(
        costs.nomination,
        HardHardDatagramCost {
            datagrams: 1,
            bytes: 64
        }
    );
    assert_eq!(costs.triggered_check.datagrams, 0);
    assert_eq!(report.counts.send_success_datagrams, 0);
}

#[test]
fn owner_committed_winner_and_response_epoch_update_terminal_identity() {
    let (mut evidence, mut identity, _, mut report) = observation_fixture(true);
    identity.socket_indices.push(4097);
    evidence.bind(
        identity.clone(),
        1,
        Some(HardHardProbeStrategy::Birthday),
        true,
    );
    let mut winner = identity.socket.clone();
    winner.remote_candidate_epoch += 1;
    winner.socket_index = 4097;
    winner.punch_generation += 1;
    winner.socket_local_endpoint.set_port(40001);
    evidence.owner_committed_socket(&winner);
    assert!(
        !evidence.seal_report("peer", "token-a", &mut report),
        "initial primary identity is no longer the authoritative winner"
    );
    let current = evidence.socket_snapshot().unwrap();
    report.remote_candidate_epoch = current.remote_candidate_epoch;
    report.socket_index = Some(current.socket_index);
    report.punch_generation = current.punch_generation;
    assert!(evidence.seal_report("peer", "token-a", &mut report));
    assert_eq!(report.mode, "birthday");
    assert!(report.confirmation.is_some());
}

#[test]
fn wrong_attempt_or_identity_cannot_freeze_the_current_worker() {
    let (evidence, identity, pair, mut report) = observation_fixture(true);
    let mut old_report = report.clone();
    old_report.attempt = 0;
    assert!(evidence
        .freeze_receive_snapshot(&identity.socket, identity.peer_session, 0)
        .is_none());
    assert!(!evidence.seal_report("peer", "token-a", &mut old_report));
    let mut stale_socket = identity.socket.clone();
    stale_socket.remote_candidate_epoch += 1;
    assert!(evidence
        .freeze_receive_snapshot(&stale_socket, identity.peer_session, 1)
        .is_none());
    evidence.record_receive(
        pair.clone(),
        HardHardReceiveObservation::AuthenticatedPunch,
        10,
    );
    evidence.record_confirmation_handoff(HardHardConfirmationPurpose::TriggeredCheck, 64);
    assert_eq!(
        evidence
            .receive_snapshot()
            .authenticated_probe_packets_received,
        1
    );
    let received = evidence
        .freeze_receive_snapshot(&identity.socket, identity.peer_session, 1)
        .unwrap();
    assert_eq!(received.authenticated_probe_packets_received, 1);
    evidence.record_receive(pair, HardHardReceiveObservation::AuthenticatedPunch, 11);
    assert_eq!(evidence.receive_snapshot(), received);
    assert!(evidence.seal_report("peer", "token-a", &mut report));
    assert_eq!(report.confirmation.unwrap().triggered_check.datagrams, 1);
}
