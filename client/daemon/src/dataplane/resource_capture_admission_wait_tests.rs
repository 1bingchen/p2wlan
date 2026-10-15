// Actual original reserve ownership; channel residency remains unmeasured.

use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::dataplane_resources::{
    BufferSnapshot, BufferStage, ResourceCapture, ResourceSnapshot, VecSite,
};
use crate::request_carriage::RawOutboundReceiver;
use crate::rooms::RoomAuthorization;
use futures_util::FutureExt;
use p2pnet_tun::{mock::MockTunController, Ipv4Packet, MockTunDevice};
use std::future::{poll_fn, Future};
use std::panic::AssertUnwindSafe;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::time::{timeout_at, Instant as TokioInstant};

const STAGE: BufferStage = BufferStage::DataplaneAdmissionWait;
const LOCAL_VIP: &str = "10.21.1.2";
const PEER_VIP: &str = "10.21.1.3";

#[derive(Clone, Copy, Debug)]
enum Channel {
    Legacy,
    Tracked,
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Cancel,
    ReceiverClosed,
    Handoff,
    RoomRevoked,
}

struct Fixture {
    plane: Option<DataPlane<MockTunDevice>>,
    controller: MockTunController,
    receiver: Option<RawOutboundReceiver>,
    capture: Arc<ResourceCapture>,
    auth: Arc<RoomAuthorization>,
    packet: Vec<u8>,
}

impl Fixture {
    async fn new(channel: Channel) -> std::result::Result<Self, String> {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "room-admission-wait")
                .map_err(|error| error.to_string())?,
        ));
        peers
            .add_peer(&PeerInfo {
                capabilities: crate::control::PeerCapabilities::default(),
                registration_seq: 0,
                node_id: "peer-wait".into(),
                virtual_ip: PEER_VIP.into(),
                public_key: "pk".into(),
                device_name: String::new(),
                app_version: String::new(),
                endpoint: String::new(),
                nat_type: String::new(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
        let auth = Arc::new(RoomAuthorization::new("room-admission-wait"));
        if !auth.replace(
            LOCAL_VIP,
            [("peer-wait".into(), PEER_VIP.into())],
            Instant::now(),
            30,
        ) {
            return Err("original room setup rejected".into());
        }
        let (tun, controller) = MockTunDevice::new_pair("wait0", 1420, LOCAL_VIP);
        let (plane, receiver) = match channel {
            Channel::Legacy => {
                let (plane, receiver) = DataPlane::new(tun, peers);
                (plane, RawOutboundReceiver::from(receiver))
            }
            Channel::Tracked => {
                let (plane, receiver) = DataPlane::new_with_request_carriage(tun, peers);
                (plane, RawOutboundReceiver::from(receiver))
            }
        };
        let capture = ResourceCapture::new([0xa5; 16]);
        let plane = plane
            .with_resource_capture(capture.clone())
            .map_err(|error| format!("capture setup: {error:?}"))?
            .with_room_authorization(auth.clone());
        if plane.outbound_tx.max_capacity() != 1024 {
            return Err("original channel capacity changed".into());
        }
        for sequence in 0..1024u16 {
            plane
                .outbound_tx
                .try_send(OutboundPacket {
                    room_authorization: None,
                    trace: None,
                    peer_id: "filler".into(),
                    dst_ip: PEER_VIP.into(),
                    packet: filler(sequence),
                })
                .map_err(|error| format!("original filler admission: {error:?}"))?;
        }
        let packet = Ipv4Packet::build_icmp_echo_request(
            LOCAL_VIP
                .parse()
                .map_err(|error| format!("local VIP: {error}"))?,
            PEER_VIP
                .parse()
                .map_err(|error| format!("peer VIP: {error}"))?,
            0x1234,
            1,
            b"actual-local-reserve-owner",
        );
        Ok(Self {
            plane: Some(plane),
            controller,
            receiver: Some(receiver),
            capture,
            auth,
            packet,
        })
    }
}

fn filler(sequence: u16) -> Vec<u8> {
    let bytes = sequence.to_be_bytes();
    vec![0xf1, bytes[0], bytes[1]]
}

struct Evidence {
    held: ResourceSnapshot,
    after_operation: ResourceSnapshot,
    route_result: Option<crate::error::Result<()>>,
    live_queue_len: usize,
    live_capacity: usize,
    after_queue_len: usize,
    fifo_exact: bool,
    actual_packet: Option<RawRequestDelivery>,
    actual_permit_valid_at_receive: bool,
}

async fn exercise(case: Case) {
    // One original 1s fixture window includes both selected original channels,
    // setup, work and cleanup. No per-step or retry deadline is restarted.
    let end = TokioInstant::now() + Duration::from_secs(1);
    for channel in [Channel::Legacy, Channel::Tracked] {
        let mut fixture = timeout_at(end, Fixture::new(channel))
            .await
            .expect("original 1s fixture setup deadline")
            .expect("original fixture setup");
        let capture = fixture.capture.clone();
        let original_len = fixture.packet.len() as u64;
        let original_packet = fixture.packet.clone();
        let mut plane = fixture.plane.take().unwrap();
        let sender = plane.outbound_tx.clone();
        let body = timeout_at(
            end,
            AssertUnwindSafe(async {
                fixture
                    .controller
                    .inject(fixture.packet.clone())
                    .await
                    .map_err(|error| format!("original MockTun inject: {error}"))?;
                let mut read_buffer = [0u8; 512];
                let mut route = Box::pin(plane.read_and_route_once(&mut read_buffer));
                let first = poll_fn(|cx| Poll::Ready(route.as_mut().poll(cx))).await;
                if let Poll::Ready(result) = first {
                    // Never repoll an already-completed original future.
                    return Err(format!(
                        "original full-channel route completed instead of Pending: {result:?}"
                    ));
                }
                let held = capture.snapshot();
                let live_queue_len = fixture.receiver.as_ref().unwrap().len();
                let live_capacity = sender.capacity();
                let mut fifo_exact = true;
                let mut actual_packet = None;
                let mut actual_permit_valid_at_receive = false;
                let route_result = match case {
                    Case::Cancel => {
                        drop(route);
                        None
                    }
                    Case::ReceiverClosed => {
                        drop(fixture.receiver.take());
                        Some(route.await)
                    }
                    Case::Handoff | Case::RoomRevoked => {
                        if matches!(case, Case::RoomRevoked) {
                            fixture.auth.invalidate();
                        }
                        let receiver = fixture.receiver.as_mut().unwrap();
                        fifo_exact &= receiver
                            .try_recv()
                            .map(|packet| packet.packet == filler(0))
                            .unwrap_or(false);
                        let result = route.await;
                        Some(result)
                    }
                };
                // Save the release while the channel still contains its own Vecs.
                // Resource assertions happen only after every fixture owner drops.
                let after_operation = capture.snapshot();
                let after_queue_len = fixture
                    .receiver
                    .as_ref()
                    .map_or(0, RawOutboundReceiver::len);
                if matches!(case, Case::Handoff | Case::RoomRevoked) {
                    let receiver = fixture.receiver.as_mut().unwrap();
                    for sequence in 1..1024u16 {
                        fifo_exact &= receiver
                            .try_recv()
                            .map(|packet| packet.packet == filler(sequence))
                            .unwrap_or(false);
                    }
                    if matches!(case, Case::Handoff) {
                        actual_packet = receiver.try_recv().ok();
                        actual_permit_valid_at_receive = actual_packet
                            .as_ref()
                            .and_then(|packet| packet.room_authorization.as_ref())
                            .is_some_and(|permit| permit.is_valid());
                    }
                    fifo_exact &= receiver.try_recv().is_err();
                }
                Ok::<_, String>(Evidence {
                    held,
                    after_operation,
                    route_result,
                    live_queue_len,
                    live_capacity,
                    after_queue_len,
                    fifo_exact,
                    actual_packet,
                    actual_permit_valid_at_receive,
                })
            })
            .catch_unwind(),
        )
        .await;
        // No task was spawned. Timeout/error/panic drops the same original
        // route future; close/drop both original channel owners before assert.
        drop(sender);
        drop(plane);
        drop(fixture);
        capture.finish();
        let evidence = match body {
            Ok(Ok(result)) => result.expect("original reserve workflow failed after owned cleanup"),
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            Err(error) => panic!("original 1s fixture deadline after owned cleanup: {error}"),
        };
        assert!(evidence.held.valid && evidence.after_operation.valid && capture.snapshot().valid);
        assert_eq!((evidence.live_queue_len, evidence.live_capacity), (1024, 0));
        assert!(
            evidence.held.buffer_scope_observed(STAGE),
            "actual admission wait hook missing after owned cleanup: {case:?}/{channel:?}"
        );
        let observed = evidence.held.buffer(STAGE);
        assert_eq!((observed.live_buffers, observed.len), (1, original_len));
        assert!(observed.capacity >= observed.len);
        let actual_copy = evidence.held.vec_site(VecSite::TxRoutedPacketCopy);
        assert_eq!(actual_copy.materialization_ops, 1);
        assert_eq!(actual_copy.destination_len_observed_sum, observed.len);
        assert_eq!(
            actual_copy.destination_capacity_observed_sum, observed.capacity,
            "capacity must equal the same actual routed Vec observation, not a guessed allocation"
        );
        assert_eq!(
            evidence.after_operation.buffer(STAGE),
            BufferSnapshot::default()
        );
        assert_eq!(capture.snapshot().buffer(STAGE), BufferSnapshot::default());
        assert!(evidence.fifo_exact);
        match case {
            Case::Cancel => {
                assert!(evidence.route_result.is_none());
                assert_eq!(evidence.after_queue_len, 1024);
            }
            Case::ReceiverClosed => {
                assert!(matches!(
                    evidence.route_result,
                    Some(Err(DaemonError::Network(_)))
                ));
                assert_eq!(evidence.after_queue_len, 0);
            }
            Case::Handoff => {
                assert!(matches!(evidence.route_result, Some(Ok(()))));
                assert_eq!(evidence.after_queue_len, 1024);
                let actual = evidence
                    .actual_packet
                    .expect("original queued routed packet missing");
                assert_eq!(actual.packet, original_packet);
                assert_eq!(actual.peer_id, "peer-wait");
                // Dropping the actual room owner during cleanup revokes its
                // permit. Assert the saved real handoff observation instead.
                assert!(evidence.actual_permit_valid_at_receive);
                assert!(!actual.room_authorization.as_ref().unwrap().is_valid());
            }
            Case::RoomRevoked => {
                assert!(matches!(evidence.route_result, Some(Ok(()))));
                assert_eq!(evidence.after_queue_len, 1023);
                assert!(evidence.actual_packet.is_none());
            }
        }
        for snapshot in [
            &evidence.held,
            &evidence.after_operation,
            &capture.snapshot(),
        ] {
            assert!(
                !snapshot.channel_bytes_measured
                    && !snapshot.session_backlog_measured
                    && !snapshot.relay_writer_bytes_measured
                    && !snapshot.active_attempt_bytes_measured
                    && !snapshot.total_pipeline_bytes_measured
                    && !snapshot.coherent
                    && !snapshot.allocator_alloc_calls_measured
                    && !snapshot.allocator_free_calls_measured
            );
        }
    }
}

#[tokio::test]
async fn actual_full_channel_reserve_cancel_releases_only_local_wait_owner() {
    exercise(Case::Cancel).await;
}

#[tokio::test]
async fn actual_receiver_close_during_reserve_releases_local_wait_owner_on_original_error() {
    exercise(Case::ReceiverClosed).await;
}

#[tokio::test]
async fn actual_channel_dequeue_handoff_ends_wait_lease_before_queued_packet_is_consumed() {
    exercise(Case::Handoff).await;
}

#[tokio::test]
async fn actual_room_revoke_during_reserve_rejects_handoff_and_releases_wait_owner() {
    exercise(Case::RoomRevoked).await;
}
