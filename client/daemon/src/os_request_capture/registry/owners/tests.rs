//! Actual owner constructors/control descriptor, with no system IO fact mint.
use super::*;
use crate::os_request_capture::control::CaptureSetup;
use serde_json::json;
use std::io::Write;

async fn setup() -> (CaptureSetup, std::os::unix::net::UnixStream) {
    let peers = Arc::new(PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    let mut raw=serde_json::to_vec(&json!({"schema_version":1,"capture_id":"11".repeat(16),"producer_scope":"22".repeat(16),"flows":[]})).unwrap();
    raw.push(b'\n');
    parent.write_all(&raw).unwrap();
    let setup = CaptureSetup::from_owned_descriptor(child.into(), &peers)
        .await
        .unwrap();
    (setup, parent)
}

#[tokio::test]
async fn original_current_owner_binding_cannot_replace_or_rearm_root_registries() {
    let (setup, _parent) = setup().await;
    let (wireguard, _out) = WireGuardTransport::new();
    let (foreign, _foreign_out) = WireGuardTransport::new();
    let udp = Arc::new(RwLock::new(None));
    let relay = Arc::new(RwLock::new(None));
    let room = Arc::new(RoomAuthorization::new("default"));
    setup
        .session
        .bind_original_current_owners(&wireguard, &udp, &relay, &room);
    setup
        .session
        .bind_original_current_owners(&foreign, &udp, &relay, &room);
    setup
        .session
        .bind_original_current_owners(&wireguard, &udp, &relay, &room);
    assert!(!setup.session.read_complete.load(Ordering::Acquire));
    assert!(!setup.session.inbound_complete.load(Ordering::Acquire));
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
    let snapshot = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["canonical_current_owner_verified"], false);
    assert_eq!(snapshot["retained_original_reads"], 0);
}

#[tokio::test]
async fn original_current_owner_context_has_no_strong_worker_or_slot_keeper() {
    let (setup, _parent) = setup().await;
    let (wireguard, out) = WireGuardTransport::new();
    let udp = Arc::new(RwLock::new(None));
    let relay = Arc::new(RwLock::new(None));
    let room = Arc::new(RoomAuthorization::new("default"));
    setup
        .session
        .bind_original_current_owners(&wireguard, &udp, &relay, &room);
    assert_eq!(Arc::strong_count(&udp), 1);
    assert_eq!(Arc::strong_count(&relay), 1);
    assert_eq!(Arc::strong_count(&room), 1);
    let weak = wireguard.original_kernel_transport_owners();
    drop(wireguard);
    drop(out);
    assert!(weak.upgrade().is_none());
    assert!(setup
        .session
        .state
        .lock()
        .unwrap()
        .current_owners
        .as_ref()
        .unwrap()
        .upgrade()
        .is_none());
}

#[tokio::test]
async fn original_current_owner_room_and_slot_identity_are_fixed() {
    let (setup, _parent) = setup().await;
    let (wireguard, _out) = WireGuardTransport::new();
    let udp = Arc::new(RwLock::new(None));
    let relay = Arc::new(RwLock::new(None));
    let room = Arc::new(RoomAuthorization::new("default"));
    setup
        .session
        .bind_original_current_owners(&wireguard, &udp, &relay, &room);
    let foreign = Arc::new(RwLock::new(None));
    setup
        .session
        .bind_original_current_owners(&wireguard, &foreign, &relay, &room);
    let foreign_room = Arc::new(RoomAuthorization::new("default"));
    setup
        .session
        .bind_original_current_owners(&wireguard, &udp, &relay, &foreign_room);
    let state = setup.session.state.lock().unwrap();
    assert!(state
        .current_owners
        .as_ref()
        .unwrap()
        .udp
        .ptr_eq(&Arc::downgrade(&udp)));
    assert!(state
        .current_owners
        .as_ref()
        .unwrap()
        .room
        .ptr_eq(&Arc::downgrade(&room)));
    assert!(!setup.session.full_complete.load(Ordering::Acquire));
}
