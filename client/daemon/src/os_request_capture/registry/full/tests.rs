//! Pure coverage controls only; no SystemTun read/write or owner is minted.
use super::*;
use crate::os_request_capture::plan::RegistrationPlan;
use serde_json::json;

async fn descriptor_scope() -> (
    crate::os_request_capture::control::CaptureSetup,
    std::os::unix::net::UnixStream,
) {
    use std::io::Write;
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[]});
    let peers = Arc::new(PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    let mut encoded = serde_json::to_vec(&value).unwrap();
    encoded.push(b'\n');
    parent.write_all(&encoded).unwrap();
    let setup = crate::os_request_capture::control::CaptureSetup::from_owned_descriptor(
        child.into(),
        &peers,
    )
    .await
    .unwrap();
    (setup, parent)
}

// These guards can only record a missing observation. No fixture constructs a
// KernelRead, physical publication, SystemTun write or native positive fact.
fn negative_observer(scope: &Arc<CaptureSession>) -> OriginalFullObservation {
    OriginalFullObservation {
        scope: Arc::downgrade(scope),
        armed: false,
    }
}

fn assert_no_full_credit(scope: &CaptureSession, complete: bool) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["original_full_retention_complete"], complete);
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn original_full_unknown_cannot_rearm_after_later_completion_or_registration() {
    let (setup, _parent) = descriptor_scope().await;
    drop(negative_observer(&setup.session));
    let mut not_handed = negative_observer(&setup.session);
    not_handed.arm();
    not_handed.complete();
    drop(not_handed);
    assert_no_full_credit(&setup.session, true);
    let mut lost = negative_observer(&setup.session);
    lost.arm();
    drop(lost);
    let mut later = negative_observer(&setup.session);
    later.arm();
    later.complete();
    drop(later);
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"33333333333333333333333333333333","flows":[{
            "protocol":"udp","kind":"request","peer_id":"full-negative-peer",
            "run_nonce":"44444444444444444444444444444444","round_nonce":"55555555555555555555555555555555",
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,
            "payload_bytes":128,"request_nonces":["66666666666666666666666666666666"]}]});
    let receipt = setup
        .session
        .register(RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap()).unwrap())
        .unwrap();
    assert_eq!(serde_json::to_value(receipt).unwrap()["added_requests"], 1);
    assert_no_full_credit(&setup.session, false);
    assert_eq!(setup.session.gaps.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn original_full_loss_does_not_wait_for_the_contended_history_mutex() {
    let (setup, _parent) = descriptor_scope().await;
    let held = setup.session.state.try_lock().unwrap();
    let mut observer = negative_observer(&setup.session);
    observer.arm();
    drop(observer);
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert!(setup.session.read_complete.load(Ordering::Acquire));
    assert!(setup.session.inbound_complete.load(Ordering::Acquire));
    drop(held);
    assert_no_full_credit(&setup.session, false);
}

#[tokio::test]
async fn original_full_observer_cannot_keep_retired_descriptor_scope_alive() {
    let (setup, parent) = descriptor_scope().await;
    let weak = Arc::downgrade(&setup.session);
    let mut observer = negative_observer(&setup.session);
    observer.arm();
    drop(setup);
    drop(parent);
    assert!(weak.upgrade().is_none());
    drop(observer);
}

#[tokio::test]
async fn original_full_loss_is_scoped_and_never_restored_by_another_observer() {
    let (first, _first_parent) = descriptor_scope().await;
    let (second, _second_parent) = descriptor_scope().await;
    let mut observer = negative_observer(&first.session);
    observer.arm();
    drop(observer);
    let mut other = negative_observer(&second.session);
    other.arm();
    other.complete();
    drop(other);
    assert_no_full_credit(&first.session, false);
    assert_no_full_credit(&second.session, true);
}

fn plan(protocol: &str, count: usize) -> RegisteredFlowPlan {
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[{
            "protocol":protocol,"kind":"response","peer_id":"frame-span-peer",
            "run_nonce":"33333333333333333333333333333333","round_nonce":"44444444444444444444444444444444",
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,"payload_bytes":128,
            "request_nonces":(1..=count).map(|n| format!("{n:032x}")).collect::<Vec<_>>()}]});
    RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .flows
        .remove(0)
}

#[test]
fn original_frame_spans_accumulate_split_coalesced_and_duplicate_ranges() {
    let plan = plan("tcp", 3);
    let mut coverage = FrameSpanCoverage::new(&plan, 1).unwrap();
    assert!(!coverage.add(&ReadFrameSpan::new(0, 0, 195)).unwrap());
    assert!(coverage.add(&ReadFrameSpan::new(1, 100, 195)).unwrap());
    assert!(!coverage.add(&ReadFrameSpan::new(1, 100, 195)).unwrap());
    assert!(!coverage.is_complete());
    assert!(coverage.add(&ReadFrameSpan::new(1, 0, 120)).unwrap());
    assert!(coverage.is_complete());
    assert!(!coverage.add(&ReadFrameSpan::new(2, 0, 195)).unwrap());
    assert!(spans_complete(
        [
            ReadFrameSpan::new(1, 100, 195),
            ReadFrameSpan::new(1, 0, 120)
        ]
        .iter(),
        1,
        &plan
    ));
}

#[test]
fn original_frame_spans_reject_gap_empty_overlong_and_unknown_slot() {
    let plan = plan("tcp", 1);
    let mut coverage = FrameSpanCoverage::new(&plan, 0).unwrap();
    assert!(coverage.add(&ReadFrameSpan::new(0, 0, 194)).unwrap());
    assert!(!coverage.is_complete());
    assert_eq!(
        coverage.add(&ReadFrameSpan::new(0, 0, 0)),
        Err(CaptureFailure::InvalidPlan)
    );
    assert_eq!(
        coverage.add(&ReadFrameSpan::new(0, 190, 196)),
        Err(CaptureFailure::InvalidPlan)
    );
    assert!(FrameSpanCoverage::new(&plan, 1).is_none());
    assert!(!spans_complete(
        [ReadFrameSpan::new(0, 0, 194)].iter(),
        0,
        &plan
    ));
}

#[test]
fn original_frame_spans_keep_udp_slots_distinct_and_bound_tcp_bitmap() {
    let plan = plan("udp", 2);
    let mut coverage = FrameSpanCoverage::new(&plan, 0).unwrap();
    assert!(!coverage.add(&ReadFrameSpan::new(1, 0, 1)).unwrap());
    assert!(!coverage.is_complete());
    assert!(coverage.add(&ReadFrameSpan::new(0, 0, 1)).unwrap());
    assert!(coverage.is_complete());
    assert!(!coverage.add(&ReadFrameSpan::new(0, 0, 1)).unwrap());
    let mut oversized = plan;
    oversized.protocol = Protocol::Tcp;
    oversized.payload_bytes = MAX_FRAME_WIRE_BYTES as u16;
    assert!(FrameSpanCoverage::new(&oversized, 0).is_none());
}

#[tokio::test]
async fn full_loss_diagnostic_keeps_first_site_without_restoring_credit() {
    let (setup, _parent) = descriptor_scope().await;
    assert!(setup.session.full_loss.snapshot().is_none());
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::HistoryContended);
    let mut later = negative_observer(&setup.session);
    later.arm();
    drop(later);
    let value = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(
        value["first_original_full_retention_loss"],
        "history_contended"
    );
    assert_eq!(setup.session.gaps.load(Ordering::Relaxed), 2);
    assert_no_full_credit(&setup.session, false);
}

#[tokio::test]
async fn full_loss_diagnostic_is_nonblocking_scoped_and_survives_retirement() {
    let (first, _first_parent) = descriptor_scope().await;
    let (second, _second_parent) = descriptor_scope().await;
    let held = first.session.state.try_lock().unwrap();
    let mut observer = negative_observer(&first.session);
    observer.arm();
    drop(observer);
    first.session.retire();
    assert_eq!(
        first.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::ObservationDropped)
    );
    assert!(second.session.full_loss.snapshot().is_none());
    drop(held);
    assert_no_full_credit(&first.session, false);
    assert_no_full_credit(&second.session, true);
}

#[test]
fn full_loss_diagnostic_serializes_all_sites_without_publication_authority() {
    use super::super::FullRetentionLoss;
    use FullRetentionLossReason::*;
    for (reason, expected) in [
        (ObservationDropped, "observation_dropped"),
        (EncryptionCaptureFailed, "encryption_capture_failed"),
        (PublicationClockUnavailable, "publication_clock_unavailable"),
        (
            PublicationClockAlreadyRecorded,
            "publication_clock_already_recorded",
        ),
        (PublicationMissing, "publication_missing"),
        (PublicationIdentityMismatch, "publication_identity_mismatch"),
        (
            PublicationObservationMissing,
            "publication_observation_missing",
        ),
        (RetentionClockUnavailable, "retention_clock_unavailable"),
        (HistoryContended, "history_contended"),
        (HistoryCapacity, "history_capacity"),
        (HistoryInvalid, "history_invalid"),
    ] {
        let loss = FullRetentionLoss::new();
        loss.record(reason);
        loss.record(HistoryInvalid);
        assert_eq!(serde_json::to_value(loss.snapshot()).unwrap(), expected);
    }
    assert_eq!(
        FullRetentionLossReason::history(CaptureFailure::Capacity),
        HistoryCapacity
    );
    assert_eq!(
        FullRetentionLossReason::history(CaptureFailure::InvalidPlan),
        HistoryInvalid
    );
}
