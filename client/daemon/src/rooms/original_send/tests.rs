use super::*;
use std::time::Duration;

const LOCAL: &str = "10.21.1.2";
const REMOTE: &str = "10.21.1.3";
const PEER: &str = "original-room-peer";

#[test]
fn original_request_capture_keeps_the_captured_deadline_after_renewal() {
    let room = RoomAuthorization::new("room-request-capture");
    let started = Instant::now();
    assert!(room.replace(LOCAL, roster(), started, 1));
    let original = room
        .try_capture_original_send_permit(PEER, REMOTE, LOCAL)
        .unwrap()
        .unwrap();
    assert!(room.replace(LOCAL, roster(), started, 30));
    let guard = room
        .try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL)
        .unwrap();
    assert!(guard.is_current_at(started + Duration::from_millis(999)));
    assert!(!guard.is_current_at(started + Duration::from_secs(1)));
}

#[test]
fn original_request_capture_is_try_only_and_rejects_wrong_flow() {
    let (room, _) = authorized();
    assert!(matches!(
        room.try_capture_original_send_permit(PEER, "10.21.1.4", LOCAL),
        Err(OriginalRoomSendFailure::Stale)
    ));
    room.with_original_snapshot_held_for_test(|| {
        assert!(matches!(
            room.try_capture_original_send_permit(PEER, REMOTE, LOCAL),
            Err(OriginalRoomSendFailure::Contended)
        ))
    });
    assert!(RoomAuthorization::new("default")
        .try_capture_original_send_permit(PEER, REMOTE, LOCAL)
        .unwrap()
        .is_none());
    assert!(matches!(
        RoomAuthorization::new("room-unregistered")
            .try_capture_original_send_permit(PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::MissingOriginal)
    ));
}

fn roster() -> [(String, String); 1] {
    [(PEER.to_string(), REMOTE.to_string())]
}

fn authorized() -> (RoomAuthorization, RoomSendPermit) {
    let room = RoomAuthorization::new("room-original-permit");
    assert!(room.replace(LOCAL, roster(), Instant::now(), 30));
    let original = room.send_permit(PEER, REMOTE, LOCAL).unwrap();
    (room, original)
}

#[test]
fn personal_owner_accepts_only_its_original_unrestricted_input() {
    let room = RoomAuthorization::new("default");
    let guard = room
        .try_original_send_guard(None, PEER, REMOTE, LOCAL)
        .unwrap();
    assert!(guard.is_current_at(Instant::now()));
    let (_other, original) = authorized();
    assert!(matches!(
        room.try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::Stale)
    ));
}

#[test]
fn current_room_retains_original_owner_and_locks_snapshot_until_commit() {
    let (room, original) = authorized();
    let guard = room
        .try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL)
        .unwrap();
    assert!(guard.is_current_at(Instant::now()));
    assert!(matches!(
        room.snapshot.try_lock(),
        Err(TryLockError::WouldBlock)
    ));
    drop(guard);
    assert!(room.snapshot.try_lock().is_ok());
}

#[test]
fn enabled_room_without_original_permit_stays_unknown() {
    let (room, _) = authorized();
    assert!(matches!(
        room.try_original_send_guard(None, PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::MissingOriginal)
    ));
}

#[test]
fn current_roster_never_substitutes_another_owners_original_permit() {
    let (room, original) = authorized();
    let (other, _) = authorized();
    assert!(matches!(
        other.try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::Stale)
    ));
    for (peer, remote, local) in [
        ("different", REMOTE, LOCAL),
        (PEER, "10.21.1.4", LOCAL),
        (PEER, REMOTE, "10.21.1.5"),
    ] {
        assert!(matches!(
            room.try_original_send_guard(Some(&original), peer, remote, local),
            Err(OriginalRoomSendFailure::Stale)
        ));
    }
}

#[test]
fn ordinary_renewal_does_not_extend_original_commit_deadline() {
    let room = RoomAuthorization::new("room-original-expiry");
    let started = Instant::now();
    assert!(room.replace(LOCAL, roster(), started, 1));
    let original = room.send_permit(PEER, REMOTE, LOCAL).unwrap();
    assert!(room.replace(LOCAL, roster(), started, 30));
    let guard = room
        .try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL)
        .unwrap();
    assert!(guard.is_current_at(started + Duration::from_millis(999)));
    assert!(!guard.is_current_at(started + Duration::from_secs(1)));
    assert!(!guard.is_current_at(started + Duration::from_secs(2)));
}

#[test]
fn shortened_lease_retires_recorded_original_even_with_same_membership() {
    let (room, original) = authorized();
    assert!(room.replace(LOCAL, roster(), Instant::now(), 10));
    assert!(matches!(
        room.try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::Stale)
    ));
    let fresh = room.send_permit(PEER, REMOTE, LOCAL).unwrap();
    assert!(room
        .try_original_send_guard(Some(&fresh), PEER, REMOTE, LOCAL)
        .unwrap()
        .is_current_at(Instant::now()));
}

#[test]
fn revocation_then_same_roster_reauthorization_does_not_resurrect_original() {
    let (room, original) = authorized();
    room.invalidate();
    assert!(room.replace(LOCAL, roster(), Instant::now(), 30));
    assert!(matches!(
        room.try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::Stale)
    ));
}

#[test]
fn held_original_snapshot_returns_contention_without_waiting() {
    let (room, original) = authorized();
    let _held = room.snapshot.lock().unwrap();
    assert!(matches!(
        room.try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::Contended)
    ));
}

#[test]
fn poisoned_original_snapshot_never_grants_credit() {
    let (room, original) = authorized();
    // Explicit local mutex-poison control; no production owner is fabricated.
    let _ = std::panic::catch_unwind(|| {
        let _held = room.snapshot.lock().unwrap();
        panic!("synthetic original room snapshot poison");
    });
    assert!(matches!(
        room.try_original_send_guard(Some(&original), PEER, REMOTE, LOCAL),
        Err(OriginalRoomSendFailure::MissingOriginal)
    ));
}
