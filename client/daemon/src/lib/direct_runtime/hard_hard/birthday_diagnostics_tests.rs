#[test]
fn birthday_details_are_optional_in_existing_schema_two_json() {
    let report = crate::peer::HardHardAttemptReport {
        schema_version: 2,
        ..Default::default()
    };
    let mut old_json = serde_json::to_value(&report).unwrap();
    assert!(old_json.get("birthday_sweep").is_none());
    let old_report: crate::peer::HardHardAttemptReport =
        serde_json::from_value(old_json.clone()).unwrap();
    assert_eq!(old_report.schema_version, 2);
    assert!(old_report.birthday_sweep.is_none());
    old_json["birthday_sweep"] = serde_json::Value::Null;
    assert!(
        serde_json::from_value::<crate::peer::HardHardAttemptReport>(old_json)
            .unwrap()
            .birthday_sweep
            .is_none()
    );
    assert_eq!(crate::peer::HARD_HARD_ATTEMPT_REPORT_SCHEMA_VERSION, 2);
}

#[test]
fn absent_birthday_ledger_does_not_manufacture_zero_count_evidence() {
    let report = PunchSendReport {
        packets_sent: 3,
        physical_datagrams_sent: 3,
        per_socket_sent: vec![(7, 3)],
        first_send_at_ms: Some(1_700_000_000_000),
        ..Default::default()
    };
    assert!(hard_hard_birthday_sweep_diagnostics(&report).is_none());
}

#[test]
fn birthday_terminal_snapshot_preserves_counts_without_serializing_endpoints() {
    let report = PunchSendReport {
        birthday: Some(BirthdaySweepReport {
            requested_level: 64,
            generated_candidate_count: 96,
            signaled_candidate_count: 64,
            effective_target_count: 64,
            requested_socket_count: 4,
            attached_socket_count: 3,
            usable_socket_count: 2,
            unavailable_socket_count: 2,
            socket_count: 2,
            degraded_reason: Some("partial_socket_unavailable".to_string()),
            waves_planned: 2,
            waves_started: 2,
            waves_fully_completed: 1,
            waves_completed: 1,
            packets_planned: 128,
            targets_assigned: 128,
            targets_examined: 80,
            targets_attempted: 76,
            logical_probes_attempted: 72,
            logical_probes_sent: 68,
            logical_probe_send_failures: 4,
            physical_datagrams_sent: 70,
            physical_send_errors: 6,
            partial_physical_send_errors: 2,
            targets_budget_skipped: 4,
            targets_cancelled: 52,
            stop_reason: Some("deadline".to_string()),
        }),
        packets_sent: 68,
        physical_datagrams_sent: 70,
        physical_bytes_sent: 4480,
        physical_send_errors: 6,
        physical_send_error_bytes: 384,
        unique_target_endpoints: 64,
        budget_skipped: 4,
        probe_path_errors: 1,
        failure_kind: Some(BirthdaySweepFailureKind::Send),
        per_socket_sent: vec![(9, 30), (7, 40)],
        first_send_at_ms: Some(1_700_000_000_007),
        last_send_at_ms: Some(1_700_000_000_103),
        pacing_deadline_reached: true,
        // Raw targets belong to the send ledger, never its public snapshot.
        sent_target_endpoints: vec!["198.51.100.229:49001".parse().unwrap()],
        ..Default::default()
    };
    let snapshot = hard_hard_birthday_sweep_diagnostics(&report).unwrap();
    let expected = crate::peer::HardHardBirthdaySweepDiagnostics {
        requested_level: 64,
        generated_candidate_count: 96,
        signaled_candidate_count: 64,
        effective_target_count: 64,
        requested_socket_count: 4,
        attached_socket_count: 3,
        usable_socket_count: 2,
        unavailable_socket_count: 2,
        socket_count: 2,
        degraded_reason: Some("partial_socket_unavailable".to_string()),
        waves_planned: 2,
        waves_started: 2,
        waves_fully_completed: 1,
        waves_completed: 1,
        packets_planned: 128,
        targets_assigned: 128,
        targets_examined: 80,
        targets_attempted: 76,
        logical_probes_attempted: 72,
        logical_probes_sent: 68,
        logical_probe_send_failures: 4,
        physical_datagrams_sent: 70,
        physical_send_errors: 6,
        partial_physical_send_errors: 2,
        targets_budget_skipped: 4,
        targets_cancelled: 52,
        stop_reason: Some("deadline".to_string()),
        packets_sent: 68,
        unique_target_endpoints: 64,
        budget_skipped: 4,
        physical_bytes_sent: 4480,
        physical_send_error_bytes: 384,
        probe_path_errors: 1,
        failure_kind: Some("send_error".to_string()),
        per_socket_sent: vec![(7, 40), (9, 30)],
        first_send_at_ms: Some(1_700_000_000_007),
        last_send_at_ms: Some(1_700_000_000_103),
        epoch_budget_exhausted: false,
        candidate_iteration_capped: false,
        pacing_deadline_reached: true,
        worker_failed: false,
        target_processing_completed: false,
        sweep_budget_stop: None,
    };
    assert_eq!(*snapshot, expected);
    assert_eq!(report.per_socket_sent, [(9, 30), (7, 40)]);
    let formal = crate::peer::HardHardAttemptReport {
        schema_version: crate::peer::HARD_HARD_ATTEMPT_REPORT_SCHEMA_VERSION,
        birthday_sweep: Some(snapshot),
        ..Default::default()
    };
    let serialized = serde_json::to_string(&formal).unwrap();
    for secret in [
        "198.51.100.229",
        "49001",
        "sent_target_endpoints",
        "session_token",
    ] {
        assert!(!serialized.contains(secret), "leaked {secret}");
    }
    let round_trip: crate::peer::HardHardAttemptReport = serde_json::from_str(&serialized).unwrap();
    assert_eq!(round_trip, formal);
}
