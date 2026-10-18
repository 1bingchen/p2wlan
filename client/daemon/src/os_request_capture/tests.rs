//! Data/descriptor controls only. No test constructs a fake KernelRead or
//! claims that a registration/MockTun value proves a system device read.
#[cfg(unix)]
use super::control::CaptureSetup;
use super::plan::{CaptureFailure, RegistrationPlan, MAX_PLAN_BYTES, MAX_REQUESTS};
use crate::overlay_requests::RequestSendToken;
use serde_json::{json, Value};
use std::sync::Arc;

#[cfg(unix)]
mod registration;

fn plan() -> Value {
    json!({
        "schema_version":1,
        "capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222",
        "flows":[{
            "protocol":"udp", "kind":"request", "peer_id":"peer-b",
            "run_nonce":"33333333333333333333333333333333",
            "round_nonce":"44444444444444444444444444444444",
            "bind_ip":"10.21.1.2", "bind_port":32123,
            "target_ip":"10.21.1.3", "target_port":43210,
            "payload_bytes":128,
            "request_nonces":["55555555555555555555555555555555"]
        }]
    })
}
fn decode(value: &Value) -> Result<RegistrationPlan, CaptureFailure> {
    RegistrationPlan::decode(&serde_json::to_vec(value).unwrap())
}
#[cfg(unix)]
fn peers() -> Arc<crate::peer::PeerManager> {
    Arc::new(crate::peer::PeerManager::new(
        crate::Config::generate_default("http://ctrl.test", "default").unwrap(),
    ))
}

#[test]
fn full128_fields_and_protocol_remain_distinct_labels() {
    let mut value = plan();
    value["flows"][0]["request_nonces"][0] = json!("a5555555555555555555555555555555");
    let parsed = decode(&value).unwrap();
    assert_eq!(parsed.capture_id, [0x11; 16]);
    assert_eq!(parsed.producer_scope, [0x22; 16]);
    assert_eq!(parsed.flows[0].requests[0].request_nonce[0], 0xa5);
    assert_eq!(parsed.flows[0].requests[0].request_nonce[15], 0x55);
    let mut other = value["flows"][0].clone();
    other["protocol"] = json!("tcp");
    value["flows"].as_array_mut().unwrap().push(other);
    assert_eq!(decode(&value).unwrap().flows.len(), 2);
}

#[test]
fn maximum_original_request_capacity_is_retained_and_excess_rejected() {
    let mut value = plan();
    value["flows"][0]["request_nonces"] = json!((1..=MAX_REQUESTS)
        .map(|n| format!("{n:032x}"))
        .collect::<Vec<_>>());
    assert_eq!(
        decode(&value).unwrap().flows[0].requests.len(),
        MAX_REQUESTS
    );
    value["flows"][0]["request_nonces"]
        .as_array_mut()
        .unwrap()
        .push(json!("ffffffffffffffffffffffffffffffff"));
    assert!(matches!(decode(&value), Err(CaptureFailure::Capacity)));
}

#[test]
fn duplicate_nonces_flows_and_json_fields_are_rejected() {
    let mut duplicate = plan();
    duplicate["flows"][0]["request_nonces"] = json!([
        "55555555555555555555555555555555",
        "55555555555555555555555555555555"
    ]);
    assert!(decode(&duplicate).is_err());
    let mut duplicate = plan();
    let flow = duplicate["flows"][0].clone();
    duplicate["flows"].as_array_mut().unwrap().push(flow);
    assert!(decode(&duplicate).is_err());
    let raw = serde_json::to_string(&plan()).unwrap();
    let duplicated = raw.replacen('{', "{\"schema_version\":1,", 1);
    assert!(RegistrationPlan::decode(duplicated.as_bytes()).is_err());
}

#[test]
fn untrusted_source_or_owner_fields_never_construct_a_registration() {
    for field in [
        "owner",
        "pid",
        "kernel_tun_verified",
        "physical_send_verified",
        "original_response_input",
        "original_write_window",
        "original_request_room",
        "original_full_retention_complete",
    ] {
        let mut value = plan();
        value[field] = json!(true);
        assert!(decode(&value).is_err(), "{field}");
    }
    for field in ["owner", "source", "current_session"] {
        let mut value = plan();
        value["flows"][0][field] = json!(1);
        assert!(decode(&value).is_err(), "{field}");
    }
}

#[test]
fn malformed_nonce_flow_and_numeric_shapes_are_rejected() {
    for nonce in [
        "",
        "AA555555555555555555555555555555",
        "5555555555555555555555555555555",
        "g5555555555555555555555555555555",
    ] {
        let mut value = plan();
        value["flows"][0]["request_nonces"][0] = json!(nonce);
        assert!(decode(&value).is_err());
    }
    for (field, bad) in [
        ("bind_port", json!(0)),
        ("target_port", json!(65536)),
        ("bind_ip", json!("0.0.0.0")),
        ("target_ip", json!("224.0.0.1")),
        ("payload_bytes", json!(false)),
        ("payload_bytes", json!(1200)),
        ("peer_id", json!("a\nb")),
        ("kind", json!("kernel")),
    ] {
        let mut value = plan();
        value["flows"][0][field] = bad;
        assert!(decode(&value).is_err(), "{field}");
    }
}

#[test]
fn malformed_non_utf8_and_oversized_plan_have_no_native_owner() {
    assert!(RegistrationPlan::decode(&[0xff, b'{']).is_err());
    assert!(RegistrationPlan::decode(&vec![b' '; MAX_PLAN_BYTES + 1]).is_err());
    assert!(RegistrationPlan::decode(br#"{"schema_version":1.0}"#).is_err());
}

#[test]
fn raw_plan_any_and_mock_context_cannot_become_a_kernel_read_token() {
    assert!(RequestSendToken::from_read_context(Box::new(plan())).is_none());
    assert!(RequestSendToken::from_read_context(Box::new(decode(&plan()).unwrap())).is_none());
    assert!(RequestSendToken::from_read_context(Box::new(17_u64)).is_none());
}

#[test]
fn new_source_variant_does_not_enlarge_the_original_inline_token() {
    use crate::overlay_requests::{CanonicalOverlayRequest, OriginalEchoInput};
    use std::mem::size_of;
    use std::sync::Weak;
    assert_eq!(
        size_of::<RequestSendToken>(),
        size_of::<Weak<CanonicalOverlayRequest>>() + size_of::<Option<Arc<OriginalEchoInput>>>()
    );
}

#[cfg(unix)]
async fn setup(value: Value) -> (CaptureSetup, std::os::unix::net::UnixStream) {
    use std::io::Write;
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    parent.write_all(&bytes).unwrap();
    let setup = CaptureSetup::from_owned_descriptor(child.into(), &peers())
        .await
        .unwrap();
    (setup, parent)
}

#[cfg(unix)]
#[tokio::test]
async fn actual_connected_descriptor_accepts_labels_without_any_read_send_credit() {
    use std::io::Write;
    use tokio::io::AsyncBufReadExt;
    let (setup, mut parent) = setup(plan()).await;
    parent
        .write_all(b"{\"op\":\"snapshot\"}\n{\"op\":\"close\"}\n")
        .unwrap();
    parent.set_nonblocking(true).unwrap();
    let mut reader = tokio::io::BufReader::new(tokio::net::UnixStream::from_std(parent).unwrap());
    let task = tokio::spawn(setup.channel.run());
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let snapshot: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(snapshot["scope"], "registered_kernel_read_only");
    assert_eq!(snapshot["requests"][0]["read_events"], 0);
    assert_eq!(snapshot["requests"][0]["kernel_frame_read_complete"], false);
    assert_eq!(snapshot["daemon_registration_verified"], false);
    assert_eq!(snapshot["physical_send_verified"], false);
    assert_eq!(snapshot["canonical_current_owner_verified"], false);
    task.await.unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["active"],
        false
    );
}

#[cfg(unix)]
#[tokio::test]
async fn cancellation_retires_the_actual_descriptor_scope_and_releases_it() {
    use tokio::io::AsyncReadExt;
    let (setup, parent) = setup(plan()).await;
    let weak = Arc::downgrade(&setup.session);
    parent.set_nonblocking(true).unwrap();
    let mut parent = tokio::net::UnixStream::from_std(parent).unwrap();
    let task = tokio::spawn(setup.channel.run());
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["active"],
        false
    );
    drop(setup.session);
    assert!(
        weak.upgrade().is_none(),
        "no device/packet keeper retains the registry"
    );
    let mut byte = [0];
    assert_eq!(parent.read(&mut byte).await.unwrap(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn successful_integer_registration_does_not_adopt_or_close_callers_descriptor() {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    let (mut parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    let original = child.as_raw_fd();
    let before = unsafe { libc::fcntl(original, libc::F_GETFL) };
    let mut bytes = serde_json::to_vec(&plan()).unwrap();
    bytes.push(b'\n');
    parent.write_all(&bytes).unwrap();
    let setup = CaptureSetup::from_inherited_fd(original, &peers())
        .await
        .unwrap();
    drop(setup.channel);
    assert_eq!(unsafe { libc::fcntl(original, libc::F_GETFL) }, before);
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["active"],
        false
    );
    // The original is still the caller's usable socket after our duplicate
    // retires. This would fail if a raw integer were adopted into OwnedFd.
    child.write_all(b"x").unwrap();
    let mut byte = [0];
    parent.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b'x']);
    drop(child);
    assert_eq!(parent.read(&mut byte).unwrap(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn malformed_command_retires_scope_without_returning_positive_snapshot() {
    use std::io::Write;
    let (setup, mut parent) = setup(plan()).await;
    parent
        .write_all(b"{\"op\":\"snapshot\",\"kernel_tun_verified\":true}\n")
        .unwrap();
    assert_eq!(
        setup.channel.run().await,
        Err(CaptureFailure::ControlProtocol)
    );
    let snapshot = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["active"], false);
    assert_eq!(snapshot["requests"][0]["kernel_frame_read_complete"], false);
}

#[cfg(unix)]
#[tokio::test]
async fn invalid_blocking_or_regular_descriptor_keeps_original_owned_fd_and_flags() {
    use std::os::fd::AsRawFd;
    let (_, child) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = child.as_raw_fd();
    let before = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(matches!(
        CaptureSetup::from_inherited_fd(fd, &peers()).await,
        Err(CaptureFailure::InvalidDescriptor)
    ));
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, before);
    let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let before = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert!(matches!(
        CaptureSetup::from_inherited_fd(file.as_raw_fd(), &peers()).await,
        Err(CaptureFailure::InvalidDescriptor)
    ));
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) },
        before
    );
}

#[cfg(unix)]
#[tokio::test]
async fn truncated_initial_plan_fails_and_preserves_callers_original_descriptor() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    parent.write_all(b"{\"schema_version\":1").unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    let before = unsafe { libc::fcntl(child.as_raw_fd(), libc::F_GETFL) };
    assert!(matches!(
        CaptureSetup::from_inherited_fd(child.as_raw_fd(), &peers()).await,
        Err(CaptureFailure::ControlProtocol)
    ));
    assert_eq!(
        unsafe { libc::fcntl(child.as_raw_fd(), libc::F_GETFL) },
        before
    );
}
