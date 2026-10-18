//! Actual room-authority and negative-result controls. These tests never
//! construct a KernelRead, KernelWrite, or positive response source input.
use super::*;
use std::time::Duration;

const LOCAL: &str = "10.21.1.2";
const REMOTE: &str = "10.21.1.3";
const PEER: &str = "response-original-room-peer";

fn roster() -> [(String, String); 1] {
    [(PEER.into(), REMOTE.into())]
}

fn captured(room: &Arc<RoomAuthorization>) -> Arc<OriginalIncomingRoom> {
    Arc::new(OriginalIncomingRoom {
        owner: Arc::downgrade(room),
        permit: room.try_capture_original_send_permit(PEER, REMOTE, LOCAL),
    })
}

#[test]
fn unknown_sampling_keeps_forwarding_policy_but_known_original_still_bounds_coalesced_packet() {
    let room = Arc::new(RoomAuthorization::new("room-response-partial-sampling"));
    let started = Instant::now();
    assert!(room.replace(LOCAL, roster(), started, 1));
    let first = captured(&room);
    let unknown = room.with_original_snapshot_held_for_test(|| captured(&room));
    assert!(matches!(
        unknown.permit,
        Err(OriginalRoomSendFailure::Contended)
    ));
    assert!(known_route_room([&unknown].into_iter(), Some(&room)).is_none());
    assert!(room.replace(LOCAL, roster(), started, 30));
    let later = captured(&room);
    let selected = known_route_room([&unknown, &first, &later].into_iter(), Some(&room))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(Some(&selected), first.permit.as_ref().unwrap().as_ref());
    let guard = room
        .try_original_send_guard(Some(&selected), PEER, REMOTE, LOCAL)
        .unwrap();
    assert!(guard.is_current_at(started + Duration::from_millis(999)));
    assert!(!guard.is_current_at(started + Duration::from_secs(1)));
    drop(guard);
    let incomplete = ResponseCapture {
        flow: 0,
        slot: 0,
        room: Some(first),
        original: Err(OverlayCreditOutcome::Unknown(
            OverlayCreditUnknown::OriginalPublication,
        )),
    };
    let value = serde_json::to_value(incomplete.snapshot()).unwrap();
    assert_eq!(value["known"], false);
    assert_eq!(value["original_room_captured"], true);
    assert_eq!(value["original_system_write_contributors"], 0);
}

#[test]
fn known_original_route_grant_does_not_wait_on_sampling_or_room_snapshot_lock() {
    let room = Arc::new(RoomAuthorization::new("room-response-no-observer-gate"));
    assert!(room.replace(LOCAL, roster(), Instant::now(), 30));
    let first = captured(&room);
    room.with_original_snapshot_held_for_test(|| {
        let selected = known_route_room([&first].into_iter(), Some(&room))
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(Some(&selected), first.permit.as_ref().unwrap().as_ref());
        assert!(selected.is_valid());
    });
}

#[test]
fn poisoned_room_owner_cannot_forward_using_an_older_known_grant() {
    let room = Arc::new(RoomAuthorization::new("room-response-poisoned-owner"));
    assert!(room.replace(LOCAL, roster(), Instant::now(), 30));
    let first = captured(&room);
    let _ = std::panic::catch_unwind(|| {
        room.with_original_snapshot_held_for_test(|| panic!("synthetic room-owner poison"));
    });
    assert!(room.original_snapshot_is_poisoned());
    assert_eq!(
        known_route_room([&first].into_iter(), Some(&room)),
        Some(Err(OverlayCreditOutcome::Stale(
            OverlayCreditStale::RoomAuthority
        )))
    );
}

#[test]
fn known_original_route_grant_rejects_foreign_room_revocation_and_restricted_mix() {
    let room = Arc::new(RoomAuthorization::new("room-response-current-owner"));
    let other = Arc::new(RoomAuthorization::new("room-response-other-owner"));
    assert!(room.replace(LOCAL, roster(), Instant::now(), 30));
    assert!(other.replace(LOCAL, roster(), Instant::now(), 30));
    let first = captured(&room);
    let stale = Some(Err(OverlayCreditOutcome::Stale(
        OverlayCreditStale::RoomAuthority,
    )));
    assert_eq!(known_route_room([&first].into_iter(), Some(&other)), stale);
    let unrestricted = Arc::new(RoomAuthorization::new("default"));
    let unrestricted = captured(&unrestricted);
    assert_eq!(
        known_route_room([&first, &unrestricted].into_iter(), Some(&room)),
        stale
    );
    room.invalidate();
    assert_eq!(known_route_room([&first].into_iter(), Some(&room)), stale);
    assert!(room.replace(LOCAL, roster(), Instant::now(), 30));
    assert_eq!(known_route_room([&first].into_iter(), Some(&room)), stale);
}
