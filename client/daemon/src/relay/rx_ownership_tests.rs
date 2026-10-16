//! Actual Relay server/client handoff; library frames remain outside the ledger.
use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::dataplane_resources::{EncryptedRxSink, ResidencyStage, ResourceCapture};
use futures_util::FutureExt;
use p2pnet_relay::RelayServer;
use std::{
    future::{poll_fn, Future},
    panic::AssertUnwindSafe,
    task::Poll,
};

#[tokio::test]
async fn rx_ownership_real_relay_handoff_waits_moves_and_cancels_original_values() {
    let end = tokio::time::Instant::now() + Duration::from_secs(3);
    let server = RelayServer::start_random().await.unwrap();
    let address = server.addr.to_string();
    let capture = ResourceCapture::new([0xe7; 16]);
    let body = AssertUnwindSafe(async {
        let a = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "default").unwrap(),
        ));
        let b = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "default").unwrap(),
        ));
        a.add_peer(&PeerInfo {
            node_id: "rx-b".into(),
            virtual_ip: "10.20.0.2".into(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
        b.add_peer(&PeerInfo {
            node_id: "rx-a".into(),
            virtual_ip: "10.20.0.1".into(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
        let (relay_a, _unused) = RelayTransport::connect(&address, "rx-a", a).await.unwrap();
        let (relay_b, frames) = RelayTransport::connect(&address, "rx-b", b).await.unwrap();
        let (tx, mut rx) = EncryptedRxSink::channel(1, Some(capture.clone()));
        let mut inbound = Box::pin(relay_b.run_inbound_for_read(frames, tx, None));
        for byte in [11, 23] {
            let packet = EncryptedPeerPacket {
                room_authorization: None,
                peer_id: "rx-b".into(),
                wire_bytes: vec![byte; byte as usize],
                probe_budget: None,
                is_business: false,
            };
            relay_a.send_packet(&packet).await.unwrap();
            tokio::time::timeout_at(end, async {
                loop {
                    poll_fn(|cx| {
                        assert!(inbound.as_mut().poll(cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    let stage = if byte == 11 {
                        ResidencyStage::RxWireChannel
                    } else {
                        ResidencyStage::RxWireAdmission
                    };
                    if capture
                        .residency_snapshot()
                        .stage(stage)
                        .unwrap()
                        .live_buffers
                        == 1
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        let s = capture.residency_snapshot();
        assert!(s.coherent && s.valid);
        assert_eq!(s.unknown_bits, 0);
        assert_eq!(s.total.unwrap().live_buffers, 2);
        assert_eq!(s.total.unwrap().len_bytes, 34);
        let first = rx.recv(Some(&capture)).await.unwrap();
        assert_eq!(first.wire_bytes, vec![11; 11]);
        assert_eq!(first.relay_peer_id.as_deref(), Some("rx-a"));
        assert_eq!(first.relay_endpoint.as_deref(), Some(address.as_str()));
        assert!(first.source.is_none());
        poll_fn(|cx| {
            assert!(inbound.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(capture.residency_snapshot().total, s.total);
        assert_eq!(
            capture
                .residency_snapshot()
                .stage(ResidencyStage::RxWireActive)
                .unwrap()
                .live_buffers,
            1
        );
        capture.finish();
        drop(first);
        drop(inbound);
        assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 1);
        let last = rx.recv(Some(&capture)).await.unwrap();
        assert_eq!(last.wire_bytes, vec![23; 23]);
        drop(last);
        drop(rx);
        assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 0);
        assert_eq!(capture.residency_snapshot().unknown_bits, 0);
    })
    .catch_unwind();
    let result = tokio::time::timeout_at(end, body).await;
    server.shutdown().await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(error) => panic!("fixed Relay test deadline: {error}"),
    }
}
