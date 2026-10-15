//! Fixed actual channel/clone workload. Timing is a readout, never a pass bar
//! or a throughput, allocator, encrypted-send or whole-pipeline claim.
use super::*;
use std::hint::black_box;
use tokio::sync::mpsc;

const BLOCKS: usize = 8;
const PACKETS_PER_BLOCK: usize = 4096;
const PAYLOAD_LEN: usize = 128;

fn run_block(sink: &RawOutboundSink, receiver: &mut RawOutboundReceiver) -> u128 {
    let start = Instant::now();
    for sequence in 0..PACKETS_PER_BLOCK {
        let mut bytes = Vec::with_capacity(512);
        bytes.resize(PAYLOAD_LEN, sequence as u8);
        sink.try_send(OutboundPacket {
            peer_id: "resource-peer".into(),
            dst_ip: "10.20.0.2".into(),
            packet: bytes,
            trace: None,
            room_authorization: None,
        })
        .unwrap();
        let original = receiver.try_recv().unwrap();
        let mut retry = original.clone();
        retry.relocate_resources(ResidencyStage::RetryPlaintext);
        let mut preparation = retry.clone();
        preparation.relocate_resources(ResidencyStage::PreparationPlaintext);
        assert_eq!(black_box(&preparation.packet)[0], sequence as u8);
        assert_eq!(black_box(&retry.packet).len(), PAYLOAD_LEN);
        drop(preparation);
        drop(retry);
        drop(original);
    }
    start.elapsed().as_nanos()
}

#[test]
fn residency_fixed_actual_channel_clone_workload_reports_opt_in_cost() {
    let capture = ResourceCapture::new([0xe5; 16]);
    let (plain_tx, plain_rx) = mpsc::channel(1);
    let plain = RawOutboundSink::Tracked(plain_tx);
    let mut plain_rx = RawOutboundReceiver::from(plain_rx);
    let (observed_tx, observed_rx) = mpsc::channel(1);
    let observed = RawOutboundSink::Tracked(observed_tx).with_resource_capture(capture.clone());
    let mut observed_rx = RawOutboundReceiver::from(observed_rx);
    let mut samples = Vec::with_capacity(BLOCKS);
    for block in 0..BLOCKS {
        let (disabled_ns, enabled_ns) = if block % 2 == 0 {
            let disabled = run_block(&plain, &mut plain_rx);
            (disabled, run_block(&observed, &mut observed_rx))
        } else {
            let enabled = run_block(&observed, &mut observed_rx);
            (run_block(&plain, &mut plain_rx), enabled)
        };
        samples.push(
            serde_json::json!({"block":block, "disabled_first":block % 2 == 0,
            "disabled_ns":disabled_ns, "enabled_ns":enabled_ns}),
        );
    }
    let snapshot = capture.residency_snapshot();
    let clone_ops = (BLOCKS * PACKETS_PER_BLOCK * 2) as u64;
    assert!(snapshot.coherent && snapshot.valid);
    assert_eq!(snapshot.unknown_bits, 0);
    assert_eq!(snapshot.total.unwrap().live_buffers, 0);
    assert_eq!(snapshot.clone_ops, Some(clone_ops));
    assert_eq!(
        snapshot.cloned_len_bytes,
        Some(clone_ops * PAYLOAD_LEN as u64)
    );
    assert_eq!(snapshot.capacity_high_water_bytes, Some(512 + 128 + 128));
    assert!(plain_rx.try_recv().is_err() && observed_rx.try_recv().is_err());
    assert!(!snapshot.whole_pipeline_bytes_measured);
    eprintln!(
        "residency_overhead_readout={}",
        serde_json::json!({
            "blocks":BLOCKS, "packets_per_block":PACKETS_PER_BLOCK,
            "payload_len":PAYLOAD_LEN, "original_capacity":512,
            "raw_layout":std::mem::size_of::<RawRequestDelivery>(),
            "encrypted_layout":std::mem::size_of::<EncryptedRequestDelivery>(),
            "capture_layout":std::mem::size_of::<ResourceCapture>(),
            "lease_layout":std::mem::size_of::<crate::dataplane_resources::ResidencyLease>(),
            "observed_metadata_layout":std::mem::size_of::<residency_metadata::ObservedDelivery>(),
            "clones_per_enabled_packet":2, "samples":samples,
            "scope":"actual bounded raw channel and two existing clone operations; test profile",
            "allocator_calls_measured":false, "whole_pipeline_measured":false,
            "performance_acceptance_threshold":null
        })
    );
}
