use super::*;

fn completed(targets: u32) -> PunchSendReport {
    PunchSendReport {
        targets_assigned: targets,
        targets_examined: targets,
        targets_attempted: targets,
        target_processing_completed: true,
        logical_probes_attempted: targets,
        logical_probes_sent: targets,
        per_socket_sent: vec![(1, targets)],
        ..PunchSendReport::default()
    }
}

#[test]
fn first_nonempty_report_initializes_completion_before_counts_are_added() {
    let mut aggregate = PunchSendReport::default();
    merge_punch_send_reports(&mut aggregate, completed(3));
    assert!(aggregate.target_processing_completed);
    assert_eq!(aggregate.targets_assigned, 3);
    merge_punch_send_reports(&mut aggregate, completed(2));
    assert!(aggregate.target_processing_completed);
    assert_eq!(aggregate.targets_assigned, 5);
    assert_eq!(aggregate.targets_attempted, 5);
    assert_eq!(aggregate.logical_probes_sent, 5);
    assert_eq!(aggregate.physical_datagrams_sent, 5);
}

#[test]
fn empty_reports_neither_create_completion_nor_erase_real_completed_work() {
    let mut aggregate = PunchSendReport::default();
    for completion_flag in [false, true] {
        merge_punch_send_reports(
            &mut aggregate,
            PunchSendReport {
                target_processing_completed: completion_flag,
                ..PunchSendReport::default()
            },
        );
        assert!(!aggregate.target_processing_completed);
        assert_eq!(aggregate.targets_assigned, 0);
    }
    merge_punch_send_reports(&mut aggregate, completed(2));
    merge_punch_send_reports(&mut aggregate, PunchSendReport::default());
    assert!(aggregate.target_processing_completed);
    assert_eq!(aggregate.targets_assigned, 2);
}

#[test]
fn incomplete_or_cancelled_work_cannot_be_repaired_by_another_complete_report() {
    for cancelled in [false, true] {
        for failed_first in [false, true] {
            let partial = PunchSendReport {
                targets_assigned: 2,
                targets_examined: 1,
                targets_attempted: 1,
                targets_cancelled: u32::from(cancelled),
                // Even an inconsistent producer's true flag cannot turn a
                // cancelled target into evidence of a complete attempt.
                target_processing_completed: cancelled,
                ..PunchSendReport::default()
            };
            let mut aggregate = PunchSendReport::default();
            let reports = if failed_first {
                [partial, completed(3)]
            } else {
                [completed(3), partial]
            };
            for report in reports {
                merge_punch_send_reports(&mut aggregate, report);
            }
            assert!(!aggregate.target_processing_completed);
            assert_eq!(aggregate.targets_assigned, 5);
            assert_eq!(aggregate.targets_cancelled, u32::from(cancelled));
        }
    }
}

#[test]
fn failure_without_returned_assignment_count_is_not_an_empty_success() {
    for failure in [
        PunchSendReport {
            worker_failed: true,
            ..PunchSendReport::default()
        },
        PunchSendReport {
            failure_kind: Some(BirthdaySweepFailureKind::WorkerJoin),
            ..PunchSendReport::default()
        },
        PunchSendReport {
            targets_cancelled: 2,
            ..PunchSendReport::default()
        },
        PunchSendReport {
            probe_path_errors: 1,
            ..PunchSendReport::default()
        },
    ] {
        for failure_first in [false, true] {
            let mut aggregate = PunchSendReport::default();
            let reports = if failure_first {
                [failure.clone(), completed(3)]
            } else {
                [completed(3), failure.clone()]
            };
            for report in reports {
                merge_punch_send_reports(&mut aggregate, report);
            }
            assert!(!aggregate.target_processing_completed);
        }
    }
}

#[test]
fn processing_completion_does_not_fabricate_physical_send_success() {
    let mut aggregate = PunchSendReport::default();
    merge_punch_send_reports(
        &mut aggregate,
        PunchSendReport {
            targets_assigned: 2,
            targets_examined: 2,
            targets_attempted: 2,
            target_processing_completed: true,
            logical_probes_attempted: 2,
            logical_probe_send_failures: 2,
            physical_send_errors: 2,
            ..PunchSendReport::default()
        },
    );
    assert!(aggregate.target_processing_completed);
    assert_eq!(aggregate.logical_probes_sent, 0);
    assert_eq!(aggregate.physical_datagrams_sent, 0);
    assert_eq!(aggregate.physical_send_errors, 2);
}
