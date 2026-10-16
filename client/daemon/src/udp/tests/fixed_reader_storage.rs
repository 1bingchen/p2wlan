//! Poll the original receive future, without a parallel reader or readiness sleep.
use super::*;
use crate::dataplane_resources::{ResidencyStage, ResourceCapture, VecSite};
use std::future::{poll_fn, Future};
use std::task::Poll;
use tokio::sync::{oneshot, watch};

enum Exit {
    Shutdown,
    ClosedShutdown,
    Cancel,
}

async fn reader_lifetime(enabled: bool, exit: Exit) {
    let end = tokio::time::Instant::now() + Duration::from_secs(1);
    let capture = ResourceCapture::new([0xe2; 16]);
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap();
    let udp = if enabled {
        udp.with_resource_capture(capture.clone()).unwrap()
    } else {
        udp
    };
    let (inbound, _received) = mpsc::channel(1);
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let (ready, mut readiness) = oneshot::channel();
    let mut reader = Box::pin(udp.run_inbound_socket_inner(
        0,
        udp.socket.clone(),
        inbound,
        Some(&mut shutdown_rx),
        Some(ready),
    ));
    eprintln!(
        "udp_reader_future_layout={}",
        std::mem::size_of_val(reader.as_ref().get_ref())
    );
    poll_fn(|cx| {
        assert!(reader.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(
        readiness.try_recv().unwrap(),
        "the real recv_from was Pending"
    );
    let snapshot = capture.residency_snapshot();
    assert!(snapshot.coherent && snapshot.valid);
    let storage = snapshot.stage(ResidencyStage::UdpReaderStorage).unwrap();
    assert_eq!(storage.live_buffers, u64::from(enabled));
    assert_eq!(storage.len_bytes, if enabled { 65_535 } else { 0 });
    assert_eq!(snapshot.total, Some(storage));
    assert_eq!(
        capture
            .snapshot()
            .vec_site(VecSite::UdpReaderBuffer)
            .materialization_ops,
        u64::from(enabled)
    );
    capture.finish();
    assert_eq!(capture.residency_snapshot().total, Some(storage));
    match exit {
        Exit::Shutdown => {
            shutdown.send(true).unwrap();
            tokio::time::timeout_at(end, reader.as_mut())
                .await
                .unwrap()
                .unwrap();
        }
        Exit::ClosedShutdown => {
            drop(shutdown);
            tokio::time::timeout_at(end, reader.as_mut())
                .await
                .unwrap()
                .unwrap();
        }
        Exit::Cancel => { /* Cancellation drops the original future below. */ }
    }
    drop(reader);
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 0);
    assert_eq!(
        capture.residency_snapshot().total.unwrap().capacity_bytes,
        0
    );
}

#[tokio::test]
async fn fixed_reader_storage_udp_shutdown_drains_idle_owner() {
    for enabled in [false, true] {
        reader_lifetime(enabled, Exit::Shutdown).await;
    }
}

#[tokio::test]
async fn fixed_reader_storage_udp_closed_shutdown_drains_idle_owner() {
    for enabled in [false, true] {
        reader_lifetime(enabled, Exit::ClosedShutdown).await;
    }
}

#[tokio::test]
async fn fixed_reader_storage_udp_cancel_drains_idle_owner() {
    for enabled in [false, true] {
        reader_lifetime(enabled, Exit::Cancel).await;
    }
}
