//! Real room and PeerManager controls; metadata collection never creates a
//! KernelRead, system write, physical Full, or final native-credit permission.
use super::*;
use crate::control::PeerInfo;
use crate::os_request_capture::control::CaptureSetup;
use ingress::known_route_room;
use serde_json::json;
use std::io::Write;
use std::time::Duration;

const PEER: &str = "first-request-room-peer";
const LOCAL: &str = "10.21.1.2";
const REMOTE: &str = "10.21.1.3";

async fn setup(
    room: &Arc<RoomAuthorization>,
    label: &str,
) -> (
    CaptureSetup,
    std::os::unix::net::UnixStream,
    Arc<PeerManager>,
) {
    let peers = Arc::new(PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            node_id: PEER.into(),
            public_key: "room-boundary-key".into(),
            endpoint: "127.0.0.1:44321".into(),
            virtual_ip: REMOTE.into(),
            online: true,
            ..Default::default()
        })
        .await;
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[{
            "protocol":"udp","kind":"request","peer_id":label,
            "run_nonce":"33333333333333333333333333333333","round_nonce":"44444444444444444444444444444444",
            "bind_ip":LOCAL,"bind_port":32123,"target_ip":REMOTE,"target_port":43210,"payload_bytes":128,
            "request_nonces":["55555555555555555555555555555555"]}]});
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    let mut encoded = serde_json::to_vec(&value).unwrap();
    encoded.push(b'\n');
    parent.write_all(&encoded).unwrap();
    let setup = CaptureSetup::from_owned_descriptor(child.into(), &peers)
        .await
        .unwrap();
    setup.session.inbound_runtime(room);
    (setup, parent, peers)
}

fn collect(scope: &CaptureSession) -> Arc<OriginalIncomingRoom> {
    let mut state = scope.state.lock().unwrap();
    let room = state.original_room_owner.clone();
    let flow = &mut state.flows[0];
    scope.first_read_peers(flow, &[0]);
    scope
        .first_read_request_rooms(flow, &[0], room.as_ref())
        .remove(0)
}

fn room(name: &str, seconds: u64) -> (Arc<RoomAuthorization>, Instant) {
    let room = Arc::new(RoomAuthorization::new(&format!("room-{name}")));
    assert!(room.enabled());
    let started = Instant::now();
    assert!(room.replace(LOCAL, [(PEER.into(), REMOTE.into())], started, seconds));
    (room, started)
}

fn no_kernel_credit(scope: &CaptureSession) {
    let value = serde_json::to_value(scope.snapshot().unwrap()).unwrap();
    assert_eq!(value["requests"][0]["read_events"], 0);
    assert_eq!(value["requests"][0]["kernel_frame_read_complete"], false);
    assert_eq!(value["historical_full_packets"], json!([]));
    assert_eq!(value["system_tun_full_writes"], json!([]));
    assert_eq!(value["canonical_current_owner_verified"], false);
}

#[tokio::test]
async fn first_request_room_keeps_original_deadline_after_renewal_and_duplicate() {
    let (room, started) = room("first-request-short-grant", 1);
    let (setup, _parent, _peers) = setup(&room, PEER).await;
    let first = collect(&setup.session);
    let original = first.permit.as_ref().unwrap().as_ref().unwrap().clone();
    assert!(room.replace(LOCAL, [(PEER.into(), REMOTE.into())], started, 30));
    let duplicate = collect(&setup.session);
    assert!(Arc::ptr_eq(&first, &duplicate));
    let saved = frozen_request_permit(std::slice::from_ref(&first), 1)
        .unwrap()
        .unwrap();
    assert_eq!(saved, original);
    let fresh = room
        .try_capture_original_send_permit(PEER, REMOTE, LOCAL)
        .unwrap()
        .unwrap();
    assert_ne!(saved, fresh);
    let guard = room
        .try_original_send_guard(Some(&saved), PEER, REMOTE, LOCAL)
        .unwrap();
    assert!(guard.is_current_at(started + Duration::from_millis(999)));
    assert!(!guard.is_current_at(started + Duration::from_secs(1)));
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_request_room_unknown_cannot_refill_after_snapshot_contention() {
    let (room, started) = room("first-request-room-contended", 1);
    let (setup, _parent, _peers) = setup(&room, PEER).await;
    let first = room.with_original_snapshot_held_for_test(|| collect(&setup.session));
    assert!(matches!(
        first.permit,
        Err(OriginalRoomSendFailure::Contended)
    ));
    assert!(room.replace(LOCAL, [(PEER.into(), REMOTE.into())], started, 30));
    assert!(Arc::ptr_eq(&first, &collect(&setup.session)));
    assert!(frozen_request_permit(std::slice::from_ref(&first), 1).is_err());
    assert!(known_route_room([&first].into_iter(), Some(&room)).is_none());
    assert!(room
        .try_capture_original_send_permit(PEER, REMOTE, LOCAL)
        .is_ok());
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn first_request_room_requires_actual_peer_expectation_even_when_unrestricted() {
    let room = Arc::new(RoomAuthorization::new("default"));
    assert!(!room.enabled());
    let (setup, _parent, _peers) = setup(&room, "unregistered-peer-label").await;
    let first = collect(&setup.session);
    assert!(first.permit.is_err());
    assert!(known_route_room([&first].into_iter(), Some(&room)).is_none());
    assert!(frozen_request_permit(&[first], 1).is_err());
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn original_scope_room_owner_cannot_be_replaced_or_rearmed() {
    let (room, _) = room("first-request-original-scope", 30);
    let (setup, _parent, _peers) = setup(&room, PEER).await;
    let foreign = Arc::new(RoomAuthorization::new("room-first-request-foreign-scope"));
    assert!(foreign.enabled());
    setup.session.inbound_runtime(&foreign);
    assert!(!setup.session.read_complete.load(Ordering::Acquire));
    assert!(!setup.session.inbound_complete.load(Ordering::Acquire));
    setup.session.inbound_runtime(&room);
    assert!(!setup.session.read_complete.load(Ordering::Acquire));
    let state = setup.session.state.lock().unwrap();
    assert!(state
        .original_room_owner
        .as_ref()
        .unwrap()
        .ptr_eq(&Arc::downgrade(&room)));
    drop(state);
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn original_unrestricted_room_with_known_peer_keeps_a_known_absent_permit() {
    let room = Arc::new(RoomAuthorization::new("default"));
    assert!(!room.enabled());
    let (setup, _parent, _peers) = setup(&room, PEER).await;
    let first = collect(&setup.session);
    assert!(matches!(first.permit, Ok(None)));
    assert_eq!(
        frozen_request_permit(std::slice::from_ref(&first), 1),
        Ok(None)
    );
    assert_eq!(
        known_route_room([&first].into_iter(), Some(&room)),
        Some(Ok(None))
    );
    no_kernel_credit(&setup.session);
}

#[tokio::test]
async fn original_room_history_survives_revocation_without_keeping_owner_alive() {
    let (room, _) = room("first-request-weak-room-owner", 30);
    let (setup, _parent, _peers) = setup(&room, PEER).await;
    let first = collect(&setup.session);
    let original = frozen_request_permit(std::slice::from_ref(&first), 1)
        .unwrap()
        .unwrap();
    room.invalidate();
    assert!(!original.is_valid());
    assert_eq!(
        frozen_request_permit(std::slice::from_ref(&first), 1).unwrap(),
        Some(original)
    );
    assert!(known_route_room([&first].into_iter(), Some(&room))
        .unwrap()
        .is_err());
    assert_eq!(Arc::strong_count(&room), 1);
    let weak = Arc::downgrade(&room);
    drop(room);
    assert!(weak.upgrade().is_none());
    no_kernel_credit(&setup.session);
}
