//! Actual registry/emit mutex diagnostics only; no IO or kernel fact is minted.
use super::*;

fn metadata_owner() -> OriginalKernelTransportCurrent {
    OriginalKernelTransportCurrent {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        emit: Arc::new(Mutex::new(HashMap::new())),
    }
}

#[test]
fn original_kernel_emit_registry_contention_is_distinct_from_peer_emit_contention() {
    let owner = metadata_owner();
    let held = owner.emit.try_lock().unwrap();
    assert!(matches!(
        owner.try_emit_guard("peer"),
        Err(OriginalKernelEmitFailure::Registry)
    ));
    drop(held);
    let emit = owner.try_emit_guard("peer").unwrap();
    assert!(matches!(
        owner.try_emit_guard("peer"),
        Err(OriginalKernelEmitFailure::Emit)
    ));
    drop(emit);
}

#[test]
fn original_kernel_idle_emit_registry_uses_the_actual_new_lock_incarnation() {
    let owner = metadata_owner();
    let emit = owner.try_emit_guard("peer").unwrap();
    let first = owner.emit.try_lock().unwrap()["peer"].clone();
    assert!(first.upgrade().is_some());
    drop(emit);
    assert!(first.upgrade().is_none());
    let next = owner.try_emit_guard("peer").unwrap();
    let second = owner.emit.try_lock().unwrap()["peer"].clone();
    assert!(!first.ptr_eq(&second));
    assert!(second.upgrade().is_some());
    drop(next);
}
