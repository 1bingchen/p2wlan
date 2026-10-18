//! Actual mutex/scheduler controls only; no kernel, packet or owner is minted.
use super::*;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn control_metadata_wait_yields_while_packet_admission_stays_try_only() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { *other.lock_until(end).await.unwrap() });
    tokio::task::yield_now().await;
    assert!(!child.is_finished());
    assert!(matches!(state.try_lock(), Err(TryLockError::WouldBlock)));
    drop(held);
    assert_eq!(
        tokio::time::timeout_at(end, child).await.unwrap().unwrap(),
        7
    );
}

#[tokio::test(flavor = "current_thread")]
async fn original_metadata_deadline_is_not_refilled_after_contention() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    let end = tokio::time::Instant::now() + Duration::from_millis(30);
    let child = tokio::spawn(async move {
        matches!(
            other.lock_until(end).await,
            Err(CaptureFailure::ControlNotReady)
        )
    });
    assert!(child.await.unwrap());
    drop(held);
    assert!(matches!(
        state.lock_until(end).await,
        Err(CaptureFailure::ControlNotReady)
    ));
    assert_eq!(*state.try_lock().unwrap(), 7);
}

#[tokio::test(flavor = "current_thread")]
async fn control_metadata_has_one_waiter_and_cancellation_releases_only_its_slot() {
    let state = Arc::new(ControlState::new(7usize));
    let held = state.try_lock().unwrap();
    let other = state.clone();
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let child = tokio::spawn(async move { *other.lock_until(end).await.unwrap() });
    tokio::task::yield_now().await;
    assert!(state.waiting.load(Ordering::Acquire));
    assert!(matches!(
        state.lock_until(end).await,
        Err(CaptureFailure::Contended)
    ));
    child.abort();
    assert!(child.await.unwrap_err().is_cancelled());
    assert!(!state.waiting.load(Ordering::Acquire));
    drop(held);
    assert_eq!(*state.lock_until(end).await.unwrap(), 7);
}

#[tokio::test]
async fn poisoned_metadata_remains_terminal_without_waiting_for_a_new_owner() {
    let state = ControlState::new(7usize);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = state.try_lock().unwrap();
        panic!("intentional metadata poison control");
    }));
    assert!(result.is_err());
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    assert!(matches!(
        state.lock_until(end).await,
        Err(CaptureFailure::Contended)
    ));
    assert!(!state.waiting.load(Ordering::Acquire));
}
