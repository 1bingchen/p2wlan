//! The original tracked channel, without a parallel queue or fixture worker.
use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::dataplane_resources::ResourceCapture;
use crate::request_carriage::{EncryptedRequestDelivery, RawOutboundReceiver};
use p2pnet_tun::{Ipv4Packet, MockTunDevice};
use std::net::Ipv4Addr;
use std::time::Duration;

async fn fixed_reader_storage_tun_lifetime(enabled: bool, bidirectional: bool, close: bool) {
    use crate::dataplane_resources::ResidencyStage;
    use std::future::{poll_fn, Future};
    use std::task::Poll;
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "default").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            node_id: "storage-peer".into(),
            virtual_ip: "10.20.0.2".into(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let capture = ResourceCapture::new([0xe3; 16]);
    let (tun, controller) = MockTunDevice::new_pair("storage0", 1420, "10.20.0.1");
    let (plane, mut outbound, _inbound) = if bidirectional {
        let (plane, outbound, inbound) = DataPlane::new_bidirectional(tun, peers);
        (plane, outbound, Some(inbound))
    } else {
        let (plane, outbound) = DataPlane::new(tun, peers);
        (plane, outbound, None)
    };
    let mut plane = if enabled {
        plane.with_resource_capture(capture.clone()).unwrap()
    } else {
        plane
    };
    let mut pump = Box::pin(plane.run());
    eprintln!(
        "tun_reader_future_layout={}",
        std::mem::size_of_val(pump.as_ref().get_ref())
    );
    poll_fn(|cx| {
        assert!(pump.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let snapshot = capture.residency_snapshot();
    assert!(snapshot.coherent && snapshot.valid);
    let storage = snapshot.stage(ResidencyStage::TunReaderStorage).unwrap();
    assert_eq!(storage.live_buffers, u64::from(enabled));
    assert_eq!(storage.len_bytes, if enabled { 65_535 } else { 0 });
    assert_eq!(snapshot.total, Some(storage));
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        1,
        1,
        b"fixed-reader-original-packet",
    );
    controller.inject(packet.clone()).await.unwrap();
    let routed = tokio::time::timeout_at(end, async {
        tokio::select! {
            packet = outbound.recv() => packet.unwrap(),
            result = pump.as_mut() => panic!("original pump ended before routing: {result:?}"),
        }
    })
    .await
    .unwrap();
    assert_eq!(routed.packet, packet);
    assert_eq!(routed.peer_id, "storage-peer");
    assert_eq!(
        capture
            .residency_snapshot()
            .stage(ResidencyStage::TunReaderStorage),
        Some(storage)
    );
    capture.finish();
    assert_eq!(
        capture
            .residency_snapshot()
            .stage(ResidencyStage::TunReaderStorage),
        Some(storage)
    );
    if close {
        drop(controller);
        let result = tokio::time::timeout_at(end, pump.as_mut()).await.unwrap();
        assert!(matches!(result, Err(DaemonError::Network(_))));
    }
    drop(pump);
    assert_eq!(
        capture
            .residency_snapshot()
            .stage(ResidencyStage::TunReaderStorage)
            .unwrap()
            .live_buffers,
        0
    );
    assert_eq!(
        capture
            .residency_snapshot()
            .stage(ResidencyStage::TunReaderStorage)
            .unwrap()
            .capacity_bytes,
        0
    );
}

#[tokio::test]
async fn fixed_reader_storage_tun_cancel_preserves_routing_and_drains_owner() {
    for enabled in [false, true] {
        for bidirectional in [false, true] {
            fixed_reader_storage_tun_lifetime(enabled, bidirectional, false).await;
        }
    }
}

#[tokio::test]
async fn fixed_reader_storage_tun_close_preserves_routing_and_drains_owner() {
    for enabled in [false, true] {
        for bidirectional in [false, true] {
            fixed_reader_storage_tun_lifetime(enabled, bidirectional, true).await;
        }
    }
}

#[tokio::test]
async fn actual_tracked_raw_channel_retains_original_payload_without_whole_pipeline_claim() {
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "default").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            node_id: "resource-peer".into(),
            virtual_ip: "10.20.0.2".into(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let (tun, controller) = MockTunDevice::new_pair("resource0", 1420, "10.20.0.1");
    let (plane, receiver) = DataPlane::new_with_request_carriage(tun, peers);
    let capture = ResourceCapture::new([0xbc; 16]);
    let mut plane = plane.with_resource_capture(capture.clone()).unwrap();
    let mut receiver = RawOutboundReceiver::from(receiver);
    let original = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        1,
        1,
        b"actual-channel-owner",
    );
    let mut scratch = [0; 2048];
    tokio::time::timeout_at(end, async {
        controller.inject(original.clone()).await.unwrap();
        plane.read_and_route_once(&mut scratch).await.unwrap();
    })
    .await
    .expect("original one-second route bound");
    let queued = capture.snapshot();
    let queued_owners = capture.residency_snapshot();
    assert_eq!(receiver.len(), 1);
    assert!(!queued.channel_bytes_measured);
    assert!(!queued.total_pipeline_bytes_measured);
    let delivered = receiver.try_recv().unwrap();
    assert_eq!(delivered.packet, original);
    use crate::dataplane_resources::ResidencyStage;
    assert!(queued_owners.valid && queued_owners.coherent);
    assert_eq!(queued_owners.unknown_bits, 0);
    let owners = queued_owners.stage(ResidencyStage::RawChannel).unwrap();
    assert_eq!(owners.live_buffers, 1);
    assert_eq!(owners.len_bytes, delivered.packet.len() as u64);
    assert_eq!(owners.capacity_bytes, delivered.packet.capacity() as u64);
    assert_eq!(queued_owners.total, Some(owners));
    assert!(!queued_owners.whole_pipeline_bytes_measured);
    let dequeued = capture.residency_snapshot();
    assert_eq!(dequeued.total, queued_owners.total);
    assert_eq!(
        dequeued
            .stage(ResidencyStage::RawChannel)
            .unwrap()
            .live_buffers,
        0
    );
    assert_eq!(dequeued.stage(ResidencyStage::DetachedRaw), Some(owners));
    eprintln!(
        "actual_raw_channel_payload_len={} capacity={} raw_layout={} encrypted_layout={} capture_layout={} generic_channel_bytes_known={} whole_pipeline_known={}",
        delivered.packet.len(),
        delivered.packet.capacity(),
        std::mem::size_of::<RawRequestDelivery>(),
        std::mem::size_of::<EncryptedRequestDelivery>(),
        std::mem::size_of::<ResourceCapture>(),
        queued.channel_bytes_measured,
        queued.total_pipeline_bytes_measured,
    );
    drop(delivered);
    assert!(receiver.try_recv().is_err());
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 0);
}

#[test]
fn default_delivery_layout_does_not_grow_for_optional_residency_metadata() {
    // These are the original field layouts, without an observer. This checks
    // the default cost on the current target, including non-64-bit targets.
    #[allow(dead_code)]
    struct OriginalRaw {
        raw: OutboundPacket,
        binding: Option<crate::request_carriage::RequestBinding>,
    }
    #[allow(dead_code)]
    struct OriginalEncrypted {
        packet: crate::transport::EncryptedPeerPacket,
        binding: Option<crate::request_carriage::RequestBinding>,
        source: Option<crate::transport::OriginalEncryptionSource>,
        echo_emit: Option<std::sync::Weak<tokio::sync::OwnedMutexGuard<()>>>,
    }
    assert!(std::mem::size_of::<RawRequestDelivery>() <= std::mem::size_of::<OriginalRaw>());
    assert!(
        std::mem::size_of::<EncryptedRequestDelivery>() <= std::mem::size_of::<OriginalEncrypted>()
    );
    if cfg!(target_os = "macos") && std::mem::size_of::<usize>() == 8 {
        // The separately preserved baseline was measured on 64-bit Darwin.
        assert_eq!(std::mem::size_of::<OriginalRaw>(), 240);
        assert_eq!(std::mem::size_of::<OriginalEncrypted>(), 216);
    }
}
