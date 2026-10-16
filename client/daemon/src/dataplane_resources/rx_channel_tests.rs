use super::*;
use crate::dataplane::InboundPacket;
use crate::dataplane_resources::{ResidencySnapshot, ResidencyStage};
use std::{
    future::{poll_fn, Future},
    task::Poll,
};

fn packet(len: usize) -> InboundPacket {
    InboundPacket {
        peer_id: "rx-owner".into(),
        packet: vec![0x45; len],
        session_instance: None,
        from_previous_session: false,
        authenticated_ingress: None,
        trace: None,
    }
}

fn coherent(capture: &ResourceCapture) -> ResidencySnapshot {
    let s = capture.residency_snapshot();
    assert!(s.coherent && s.valid);
    let sum = s.stages.unwrap().iter().fold((0, 0, 0), |a, b| {
        (
            a.0 + b.live_buffers,
            a.1 + b.len_bytes,
            a.2 + b.capacity_bytes,
        )
    });
    let t = s.total.unwrap();
    assert_eq!((t.live_buffers, t.len_bytes, t.capacity_bytes), sum);
    assert!(!s.whole_pipeline_bytes_measured);
    s
}

#[tokio::test]
async fn rx_ownership_real_queue_wait_cancel_dequeue_and_finish_have_one_total() {
    let c = ResourceCapture::new([0xf1; 16]);
    let (tx, mut rx) = PlaintextRxSink::channel(1, Some(c.clone()));
    tx.send(packet(17)).await.unwrap();
    assert_eq!(tx.capacity(), 0);
    let mut blocked = Box::pin(tx.send(packet(23)));
    poll_fn(|cx| {
        assert!(blocked.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let s = coherent(&c);
    assert_eq!(s.unknown_bits, 0);
    assert_eq!(
        s.stage(ResidencyStage::RxPlaintextAdmission)
            .unwrap()
            .len_bytes,
        23
    );
    assert_eq!(
        s.stage(ResidencyStage::RxPlaintextChannel)
            .unwrap()
            .len_bytes,
        17
    );
    assert_eq!(s.total.unwrap().capacity_bytes, 40);
    assert_eq!(s.capacity_high_water_bytes, Some(40));
    drop(blocked);
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 1);
    let value = rx.recv(Some(&c)).await.unwrap();
    assert_eq!(value.packet, vec![0x45; 17]);
    assert_eq!(
        coherent(&c)
            .stage(ResidencyStage::RxPlaintextChannel)
            .unwrap()
            .live_buffers,
        0
    );
    assert_eq!(
        coherent(&c)
            .stage(ResidencyStage::RxPlaintextActive)
            .unwrap()
            .live_buffers,
        1
    );
    c.finish();
    assert_eq!(coherent(&c).total.unwrap().capacity_bytes, 17);
    drop(value);
    let s = coherent(&c);
    assert_eq!(s.total.unwrap().live_buffers, 0);
    assert_eq!(s.capacity_high_water_bytes, Some(40));
    drop(tx);
    assert!(rx.recv(Some(&c)).await.is_none());
}

#[tokio::test]
async fn rx_ownership_receiver_close_drops_queued_and_waiting_real_values() {
    let c = ResourceCapture::new([0xf2; 16]);
    let (tx, rx) = PlaintextRxSink::channel(1, Some(c.clone()));
    tx.send(packet(11)).await.unwrap();
    let mut blocked = Box::pin(tx.send(packet(29)));
    poll_fn(|cx| {
        assert!(blocked.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 2);
    drop(rx);
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 1);
    assert!(blocked.as_mut().await.is_err());
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 0);
    drop(blocked);
    assert_eq!(coherent(&c).total.unwrap().capacity_bytes, 0);
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 0);
}

#[tokio::test]
async fn rx_ownership_mismatched_observers_keep_one_owner_and_mark_both_unknown() {
    let a = ResourceCapture::new([0xf3; 16]);
    let b = ResourceCapture::new([0xf4; 16]);
    let (tx, mut rx) = PlaintextRxSink::channel(1, Some(a.clone()));
    tx.send_owned(RxOwned::observe(
        packet(31),
        Some(&b),
        ResidencyStage::RxAuthenticatedPlaintext,
    ))
    .await
    .unwrap();
    assert_eq!(coherent(&a).total.unwrap().live_buffers, 0);
    assert_eq!(coherent(&b).total.unwrap().live_buffers, 1);
    assert_ne!(coherent(&a).unknown_bits & 1, 0);
    assert_ne!(coherent(&b).unknown_bits & 1, 0);
    let owned = rx.recv(Some(&a)).await.unwrap();
    assert_eq!(owned.packet.len(), 31);
    assert_eq!(
        coherent(&a).total.unwrap().live_buffers + coherent(&b).total.unwrap().live_buffers,
        1
    );
    drop(owned);
    assert_eq!(coherent(&b).total.unwrap().live_buffers, 0);
}

#[tokio::test]
async fn rx_ownership_finished_source_mismatch_marks_both_without_duplicate_credit() {
    let source = ResourceCapture::new([0xfa; 16]);
    let target = ResourceCapture::new([0xfb; 16]);
    source.finish();
    let (tx, mut rx) = PlaintextRxSink::channel(1, Some(target.clone()));
    tx.send_with_capture(packet(31), Some(&source))
        .await
        .unwrap();
    assert_eq!(coherent(&source).total.unwrap().live_buffers, 0);
    assert_eq!(coherent(&target).total.unwrap().live_buffers, 1);
    assert_ne!(coherent(&source).unknown_bits & 1, 0);
    assert_ne!(coherent(&target).unknown_bits & 1, 0);
    let owned = rx.recv(Some(&target)).await.unwrap();
    assert_eq!(owned.packet, vec![0x45; 31]);
    drop(owned);
    assert_eq!(coherent(&source).total.unwrap().live_buffers, 0);
    assert_eq!(coherent(&target).total.unwrap().live_buffers, 0);
}

#[tokio::test]
async fn rx_ownership_legacy_boundary_is_explicitly_unknown_without_duplicate_credit() {
    let c = ResourceCapture::new([0xf5; 16]);
    let (tx, raw_rx) = mpsc::channel(1);
    let tx = PlaintextRxSink::from(tx);
    let mut rx = RxReceiver::from(raw_rx);
    tx.send_with_capture(packet(37), Some(&c)).await.unwrap();
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 0);
    assert_ne!(coherent(&c).unknown_bits & 1, 0);
    let owned = rx.recv(Some(&c)).await.unwrap();
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 1);
    assert_eq!(coherent(&c).capacity_high_water_bytes, Some(37));
    drop(owned);
    assert_eq!(coherent(&c).total.unwrap().live_buffers, 0);
}

#[test]
fn rx_ownership_default_queues_retain_original_public_element_types_and_layouts() {
    use crate::dataplane::OutboundPacket;
    use crate::transport::{ReceivedEncryptedPacket, WireGuardTransport};
    let (tx, rx) = EncryptedRxSink::channel(1024, None);
    let (RxSink::Legacy(tx), RxReceiver::Legacy(rx)) = (tx, rx) else {
        panic!("default selected observed queue")
    };
    let _: mpsc::Sender<ReceivedEncryptedPacket> = tx;
    let _: mpsc::Receiver<ReceivedEncryptedPacket> = rx;
    let (tx, rx) = PlaintextRxSink::channel(1024, None);
    assert_eq!(tx.max_capacity(), 1024);
    let (RxSink::Legacy(tx), RxReceiver::Legacy(rx)) = (tx, rx) else {
        panic!("default selected observed queue")
    };
    let _: mpsc::Sender<InboundPacket> = tx;
    let _: mpsc::Receiver<InboundPacket> = rx;
    let (wg, _out) = WireGuardTransport::new();
    let (_tx, rx) = mpsc::channel(1024);
    let (tx, _rx) = mpsc::channel(1024);
    let future = wg.run_inbound(rx, tx);
    let sizes = (
        std::mem::size_of::<ReceivedEncryptedPacket>(),
        std::mem::size_of::<InboundPacket>(),
        std::mem::size_of::<OutboundPacket>(),
    );
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        assert_eq!(sizes, (376, 200, 216));
    }
    eprintln!("rx_ownership_layout received={} inbound={} outbound={} default_wg_future={} capture={} observed_wire={} observed_plain={}",sizes.0,sizes.1,sizes.2,std::mem::size_of_val(&future),std::mem::size_of::<ResourceCapture>(),std::mem::size_of::<RxOwned<ReceivedEncryptedPacket>>(),std::mem::size_of::<RxOwned<InboundPacket>>());
}
