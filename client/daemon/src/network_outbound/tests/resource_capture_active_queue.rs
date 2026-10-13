//! A real preparation timeout returns plaintext to its original FIFO lease.

use super::super::super::test_support::{establish_sessions, test_peer};
use super::*;
use crate::config::Config;
use crate::dataplane_resources::{BufferSnapshot, BufferStage, FifoSnapshot, ResourceCapture};
use tokio::sync::oneshot;
use tokio::time::{timeout_at, Instant as TokioInstant};

#[tokio::test]
async fn actual_preparation_timeout_reparks_without_live_buffer_and_fifo_double_count() {
    let cleanup = TokioInstant::now() + Duration::from_secs(5);
    let work = cleanup - Duration::from_secs(1);
    let capture = ResourceCapture::new([0xc4; 16]);
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let endpoint = "127.0.0.1:41000".parse().unwrap();
    peers.add_peer(&test_peer("peer-a", endpoint)).await;
    peers
        .record_direct_probe_success_with_latency(
            "peer-a",
            endpoint,
            Some(Duration::from_millis(1)),
        )
        .await;
    peers.record_direct_success("peer-a", Some(endpoint)).await;
    let (session, _) = establish_sessions();
    let (transport, mut receiver) = WireGuardTransport::new();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    assert!(!transport.add_session("peer-a", session).await);
    let held = timeout_at(work, transport.acquire_outbound_emit_guard("peer-a"))
        .await
        .unwrap();
    let generation = peers.current_network_generation_sync();
    let mut queue = PeerPendingQueue::new();
    queue.attach_resource_capture(transport.resource_capture());
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(&[0x45, 0, 0, 20]);
    queue.enqueue(PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.2".into(),
        packet: bytes,
        trace: None,
    }));
    queue.wait_generation = Some(generation);
    queue.wait_started = Some(Instant::now());
    queue.wait_deadline = Some(Instant::now() + Duration::from_secs(3));
    let original_deadline = queue.wait_deadline;
    queue.relocate_resources(QueueStage::TaskOrUnjoinedFifo);
    let (ready, ready_rx) = oneshot::channel();
    // Keep the actual channel producer alive through the no-output assertion;
    // joining the worker alone must not turn Empty into Disconnected.
    let worker_transport = transport.clone();
    let mut worker = tokio::spawn(async move {
        let mut flush = Box::pin(super::super::flush_one_peer_until_stopped(
            "peer-a".into(),
            queue,
            worker_transport,
            peers,
            true,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
            false,
            ConnectionTimeline::new("resource-active-repark", 0),
            Arc::new(AtomicBool::new(false)),
        ));
        let pending = matches!(
            futures_util::poll!(flush.as_mut()),
            std::task::Poll::Pending
        );
        let _ = ready.send(pending);
        flush.await
    });
    let ready = timeout_at(work, ready_rx).await;
    let live = capture.snapshot();
    let result = timeout_at(work, &mut worker).await;
    // If work timed out, retain the handle through cancellation and join before
    // reporting it. Missing-hook assertions never substitute for owner cleanup.
    let mut timed_out_cleanup = None;
    let returned = match result {
        Ok(result) => Some(result),
        Err(_) => {
            worker.abort();
            timed_out_cleanup = Some(timeout_at(cleanup, &mut worker).await);
            None
        }
    };
    drop(held);
    if let Some(joined) = timed_out_cleanup {
        assert!(
            matches!(joined, Ok(Err(ref error)) if error.is_cancelled()),
            "original repark worker did not join after cancellation"
        );
    }
    let (_, mut returned) = returned
        .expect("real original two-second preparation timeout must return")
        .unwrap();
    let after_return = capture.snapshot();
    let actual_capacity = returned.queue.front().map(PendingPacket::stored_capacity);
    let actual_bytes = returned.bytes;
    let same_deadline = returned.wait_deadline == original_deadline;
    returned.relocate_resources(QueueStage::ActorFifo);
    let after_relocate = capture.snapshot();
    drop(returned);
    capture.finish();
    let dropped = capture.snapshot();
    assert!(ready.unwrap().unwrap());
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(same_deadline);
    assert_eq!(actual_bytes, 4);
    assert!(live.valid);
    assert_eq!(
        live.fifo(QueueStage::TaskOrUnjoinedFifo),
        FifoSnapshot::default()
    );
    for stage in [
        BufferStage::ActiveOriginal,
        BufferStage::RetryPlaintext,
        BufferStage::PreparationPlaintext,
    ] {
        assert!(
            live.buffer_scope_observed(stage),
            "actual preparation hook {stage:?} missing after joined cleanup"
        );
        assert_eq!(live.buffer(stage).live_buffers, 1);
        assert_eq!(live.buffer(stage).len, 4);
    }
    let parked = FifoSnapshot {
        live_packets: 1,
        plaintext_len: 4,
        vec_capacity: actual_capacity.unwrap() as u64,
    };
    assert_eq!(after_return.fifo(QueueStage::TaskOrUnjoinedFifo), parked);
    assert_eq!(
        after_return.fifo(QueueStage::ActorFifo),
        FifoSnapshot::default()
    );
    assert_eq!(after_relocate.fifo(QueueStage::ActorFifo), parked);
    assert_eq!(
        after_relocate.fifo(QueueStage::TaskOrUnjoinedFifo),
        FifoSnapshot::default()
    );
    for stage in [
        BufferStage::ActiveOriginal,
        BufferStage::RetryPlaintext,
        BufferStage::PreparationPlaintext,
        BufferStage::SerializedWire,
    ] {
        assert_eq!(after_return.buffer(stage), BufferSnapshot::default());
        assert_eq!(after_relocate.buffer(stage), BufferSnapshot::default());
        assert_eq!(dropped.buffer(stage), BufferSnapshot::default());
    }
    assert!(dropped.valid);
    assert!(!dropped.coherent);
    assert!(!dropped.total_pipeline_bytes_measured);
    assert_eq!(dropped.fifo(QueueStage::ActorFifo), FifoSnapshot::default());
    assert_eq!(
        dropped.fifo(QueueStage::TaskOrUnjoinedFifo),
        FifoSnapshot::default()
    );
}
