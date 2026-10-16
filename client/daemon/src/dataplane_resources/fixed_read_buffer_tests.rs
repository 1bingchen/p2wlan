use super::*;

#[test]
fn fixed_reader_storage_keeps_bytes_and_allocation_while_slice_is_mutated() {
    for mut buffer in [FixedReadBuffer::udp(None), FixedReadBuffer::tun(None)] {
        assert!(buffer._lease.is_none());
        assert_eq!(buffer.len(), 65_535);
        assert!(buffer.iter().all(|b| *b == 0));
        let pointer = buffer.as_ptr();
        let capacity = buffer.bytes.capacity();
        buffer[..4].copy_from_slice(&[4, 3, 2, 1]);
        buffer[65_534] = 0xfe;
        assert_eq!(&buffer[..4], &[4, 3, 2, 1]);
        assert_eq!(buffer[65_534], 0xfe);
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer.bytes.capacity(), capacity);
        assert_eq!(buffer.len(), 65_535);
    }
    eprintln!(
        "fixed_reader_layout={} original_vec_layout={} optional_lease_layout={} capture_layout={}",
        std::mem::size_of::<FixedReadBuffer>(),
        std::mem::size_of::<Vec<u8>>(),
        std::mem::size_of::<Option<ResidencyLease>>(),
        std::mem::size_of::<ResourceCapture>(),
    );
}

#[test]
fn fixed_reader_storage_and_tx_owners_share_one_total_and_drain_after_finish() {
    let capture = ResourceCapture::new([0xe1; 16]);
    let udp = FixedReadBuffer::udp(Some(&capture));
    let tun = FixedReadBuffer::tun(Some(&capture));
    let tx = vec![0; 19];
    let tx_lease = ResidencyLease::observe(&capture, ResidencyStage::RawChannel, &tx).unwrap();
    let snapshot = capture.residency_snapshot();
    assert!(snapshot.coherent && snapshot.valid);
    let total = snapshot.total.unwrap();
    assert_eq!(total.live_buffers, 3);
    assert_eq!(total.len_bytes, (udp.len() + tun.len() + tx.len()) as u64);
    assert_eq!(
        total.capacity_bytes,
        (udp.bytes.capacity() + tun.bytes.capacity() + tx.capacity()) as u64
    );
    assert_eq!(
        snapshot.capacity_high_water_bytes,
        Some(total.capacity_bytes)
    );
    let stages = snapshot.stages.unwrap();
    assert_eq!(stages.iter().map(|s| s.live_buffers).sum::<u64>(), 3);
    assert_eq!(
        stages.iter().map(|s| s.len_bytes).sum::<u64>(),
        total.len_bytes
    );
    assert_eq!(
        stages.iter().map(|s| s.capacity_bytes).sum::<u64>(),
        total.capacity_bytes
    );
    assert_eq!(
        snapshot
            .stage(ResidencyStage::UdpReaderStorage)
            .unwrap()
            .live_buffers,
        1
    );
    assert_eq!(
        snapshot
            .stage(ResidencyStage::TunReaderStorage)
            .unwrap()
            .live_buffers,
        1
    );
    assert!(!snapshot.whole_pipeline_bytes_measured);
    capture.finish();
    let late = FixedReadBuffer::udp(Some(&capture));
    assert!(late._lease.is_none());
    assert_eq!(capture.residency_snapshot().total, Some(total));
    drop((udp, tun));
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 1);
    // The old TX owner also frees its storage before its existing lease.
    drop(tx);
    drop(tx_lease);
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 0);
    let legacy = capture.snapshot().vec_site(VecSite::UdpReaderBuffer);
    assert_eq!(legacy.materialization_ops, 1);
    assert_eq!(legacy.copy_ops, 0);
}

#[test]
fn fixed_reader_storage_exports_distinct_stages_and_retains_rx_payload_exclusion() {
    let config = crate::config::DiagnosticsConfig {
        enabled: true,
        resource_capture: true,
        ..Default::default()
    };
    let runtime = super::super::RuntimeResourceCapture::from_config(&config).unwrap();
    let capture = runtime.capture().clone();
    let udp = FixedReadBuffer::udp(Some(&capture));
    let tun = FixedReadBuffer::tun(Some(&capture));
    let readout = runtime.readout();
    let stages = readout["capture"]["observed_owner_residency"]["stages"]
        .as_array()
        .unwrap();
    assert_eq!(stages.len(), ResidencyStage::COUNT);
    for name in ["udp_reader_storage", "tun_reader_storage"] {
        let stage = stages.iter().find(|s| s["stage"] == name).unwrap();
        assert_eq!(stage["scope_observed"], true);
        assert_eq!(stage["totals"]["live_buffers"], 1);
        assert_eq!(stage["totals"]["len_bytes"], 65_535);
    }
    assert!(readout["capture"]["coverage"]["excludes"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("rx_ownership")));
    assert_eq!(
        readout["capture"]["coverage"]["whole_pipeline_bytes_measured"],
        false
    );
    drop(runtime);
    assert!(capture.snapshot().ended);
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 2);
    drop((udp, tun));
    assert_eq!(
        capture.residency_snapshot().total.unwrap().capacity_bytes,
        0
    );
}
