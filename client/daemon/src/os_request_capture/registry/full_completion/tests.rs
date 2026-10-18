//! Scheduler/descriptor negatives; no KernelRead, Full or owner is minted.
use super::super::full::tests::descriptor_scope;
use super::*;
use serde_json::json;

fn assert_no_credit(scope: &CaptureSession) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn full_metadata_notification_without_original_facts_grants_no_credit() {
    let (setup, _parent) = descriptor_scope().await;
    setup.session.pending_full.request();
    setup.session.complete_pending_fulls();
    assert!(!setup.session.full_completion_pending());
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn full_metadata_contention_keeps_pending_until_original_lock_release() {
    let (setup, _parent) = descriptor_scope().await;
    let held = setup.session.state.try_lock().unwrap();
    setup.session.pending_full.request();
    setup.session.complete_pending_fulls();
    assert!(setup.session.full_completion_pending());
    assert!(setup.session.full_complete.load(Ordering::Acquire));
    drop(held);
    setup.session.full_metadata_released().await;
    setup.session.complete_pending_fulls();
    assert!(!setup.session.full_completion_pending());
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn full_metadata_retirement_cannot_resume_or_restore_a_lost_scope() {
    let (setup, _parent) = descriptor_scope().await;
    setup
        .session
        .original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
    setup.session.pending_full.request();
    setup.session.retire();
    setup.session.complete_pending_fulls();
    assert_eq!(
        setup.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::ObservationDropped)
    );
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert_no_credit(&setup.session);
}

#[tokio::test]
async fn full_metadata_poison_is_terminal_and_never_waits_or_rearms() {
    let (setup, _parent) = descriptor_scope().await;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = setup.session.state.try_lock().unwrap();
        panic!("intentional full metadata poison control");
    }));
    assert!(result.is_err());
    setup.session.pending_full.request();
    setup.session.complete_pending_fulls();
    assert!(!setup.session.full_completion_pending());
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    assert_eq!(
        setup.session.full_loss.snapshot(),
        Some(FullRetentionLossReason::HistoryContended)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn full_metadata_actor_keeps_partial_command_and_closes_without_extra_task() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (setup, parent) = descriptor_scope().await;
    parent.set_nonblocking(true).unwrap();
    let mut parent = BufReader::new(tokio::net::UnixStream::from_std(parent).unwrap());
    let session = setup.session.clone();
    let actor = tokio::spawn(setup.channel.run());
    parent.get_mut().write_all(b"{\"op\":\"snap").await.unwrap();
    tokio::task::yield_now().await;
    let held = session.state.try_lock().unwrap();
    session.pending_full.request();
    tokio::task::yield_now().await;
    assert!(session.full_completion_pending());
    drop(held);
    tokio::task::yield_now().await;
    parent.get_mut().write_all(b"shot\"}\n").await.unwrap();
    let mut reply = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        parent.read_line(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["physical_send_verified"], false);
    assert_eq!(value["retained_original_reads"], 0);
    assert!(!session.full_completion_pending());
    parent
        .get_mut()
        .write_all(b"{\"op\":\"close\"}\n")
        .await
        .unwrap();
    actor.await.unwrap().unwrap();
    assert!(!session.is_live(std::time::Instant::now()));
    assert_no_credit(&session);
}
