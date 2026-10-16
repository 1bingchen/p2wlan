use super::*;

#[test]
fn runtime_resource_busy_and_damaged_readouts_keep_unavailable_values_null() {
    let config = crate::config::DiagnosticsConfig {
        enabled: true,
        resource_capture: true,
        ..Default::default()
    };
    let run = crate::dataplane_resources::RuntimeResourceCapture::from_config(&config).unwrap();
    let capture = run.capture();
    let bytes = vec![0; 32];
    let lease = ResidencyLease::observe(capture, ResidencyStage::RawChannel, &bytes).unwrap();
    let _udp = super::super::FixedReadBuffer::udp(Some(capture));
    let _tun = super::super::FixedReadBuffer::tun(Some(capture));
    let rx: Vec<_> = [
        ResidencyStage::RxWireAdmission,
        ResidencyStage::RxWireChannel,
        ResidencyStage::RxWireActive,
        ResidencyStage::RxParsedPayload,
        ResidencyStage::RxAuthenticatedPlaintext,
        ResidencyStage::RxPlaintextAdmission,
        ResidencyStage::RxPlaintextChannel,
        ResidencyStage::RxPlaintextActive,
        ResidencyStage::RxTunPacket,
        ResidencyStage::RxTunNormalized,
    ]
    .into_iter()
    .map(|stage| super::super::RxOwned::observe(vec![0; 17], Some(capture), stage))
    .collect();
    // Deterministic writer-entry hold, using the real ledger's bounded reader.
    capture.residency.writers.store(1, Ordering::SeqCst);
    let busy = run.readout();
    let owners = &busy["capture"]["observed_owner_residency"];
    assert_eq!(owners["coherent"], false);
    for key in [
        "total",
        "capacity_high_water_bytes",
        "revision",
        "clone_ops",
        "cloned_len_bytes",
    ] {
        assert!(owners[key].is_null(), "busy {key} fabricated a measurement");
    }
    for stage in owners["stages"].as_array().unwrap() {
        assert!(stage["totals"].is_null() && stage["scope_observed"].is_null());
    }
    assert_eq!(owners["stages"].as_array().unwrap().len(), 22);
    capture.residency.writers.store(0, Ordering::SeqCst);
    assert_eq!(
        run.readout()["capture"]["observed_owner_residency"]["total"]["live_buffers"],
        13
    );
    capture.residency.gap(RecordDisposition::CounterOverflow);
    let damaged = run.readout();
    let owners = &damaged["capture"]["observed_owner_residency"];
    assert_eq!(owners["coherent"], true);
    assert_eq!(owners["valid"], false);
    assert!(owners["total"].is_null());
    assert_ne!(owners["gap_bits"], 0);
    for stage in owners["stages"].as_array().unwrap() {
        assert!(stage["totals"].is_null());
    }
    drop(rx);
    drop(lease);
}

fn bytes(len: usize, capacity: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(capacity);
    bytes.resize(len, 0x45);
    bytes
}

fn coherent(capture: &ResourceCapture) -> ResidencySnapshot {
    let snapshot = capture.residency_snapshot();
    assert!(snapshot.coherent && snapshot.valid);
    let stages = snapshot.stages.unwrap();
    let sum = stages
        .iter()
        .fold(ResidencyTotals::default(), |mut sum, stage| {
            sum.live_buffers += stage.live_buffers;
            sum.len_bytes += stage.len_bytes;
            sum.capacity_bytes += stage.capacity_bytes;
            sum
        });
    assert_eq!(snapshot.total, Some(sum));
    assert!(!snapshot.whole_pipeline_bytes_measured);
    snapshot
}

#[test]
fn original_vec_moves_and_real_clone_have_one_coherent_owner_total() {
    let capture = ResourceCapture::new([0xd1; 16]);
    let original = bytes(13, 128);
    let mut lease =
        ResidencyLease::observe(&capture, ResidencyStage::ChannelReserve, &original).unwrap();
    for stage in [
        ResidencyStage::RawChannel,
        ResidencyStage::PendingFifo,
        ResidencyStage::DetachedRaw,
    ] {
        lease.relocate(stage, &original);
        let snapshot = coherent(&capture);
        assert_eq!(snapshot.total.unwrap().live_buffers, 1);
        assert_eq!(
            snapshot.total.unwrap().capacity_bytes,
            original.capacity() as u64
        );
    }
    let copied = original.clone();
    let copy_lease = lease.clone_for(&copied).unwrap();
    let copied_state = coherent(&capture);
    assert_eq!(copied_state.total.unwrap().live_buffers, 2);
    assert_eq!(copied_state.clone_ops, Some(1));
    assert_eq!(copied_state.cloned_len_bytes, Some(copied.len() as u64));
    assert_eq!(
        copied_state.capacity_high_water_bytes,
        Some((original.capacity() + copied.capacity()) as u64)
    );
    capture.finish();
    assert!(ResidencyLease::observe(&capture, ResidencyStage::DetachedRaw, &original).is_none());
    drop(lease);
    assert_eq!(coherent(&capture).total.unwrap().live_buffers, 1);
    drop(copy_lease);
    assert_eq!(
        coherent(&capture).total.unwrap(),
        ResidencyTotals::default()
    );
}

#[test]
fn capacity_high_water_is_not_the_sum_of_separate_lifetime_peaks() {
    let capture = ResourceCapture::new([0xd2; 16]);
    let a = bytes(100, 100);
    let lease = ResidencyLease::observe(&capture, ResidencyStage::PendingFifo, &a).unwrap();
    drop(lease);
    let b = bytes(10, 200);
    let _lease = ResidencyLease::observe(&capture, ResidencyStage::SerializedWire, &b).unwrap();
    let snapshot = coherent(&capture);
    assert_eq!(
        snapshot.total.unwrap(),
        ResidencyTotals {
            live_buffers: 1,
            len_bytes: 10,
            capacity_bytes: 200
        }
    );
    assert_eq!(snapshot.capacity_high_water_bytes, Some(200));
}

#[test]
fn a_busy_read_is_unknown_and_never_prevents_other_owner_updates() {
    let capture = ResourceCapture::new([0xd3; 16]);
    capture.residency.writers.store(1, Ordering::SeqCst);
    let original = bytes(17, 64);
    let lease = ResidencyLease::observe(&capture, ResidencyStage::RawChannel, &original).unwrap();
    let busy = capture.residency_snapshot();
    assert!(!busy.valid && !busy.coherent);
    assert!(
        busy.total.is_none() && busy.stages.is_none() && busy.capacity_high_water_bytes.is_none()
    );
    assert_eq!(busy.gap_bits, 0);
    capture.residency.writers.store(0, Ordering::SeqCst);
    assert_eq!(coherent(&capture).total.unwrap().capacity_bytes, 64);
    drop(lease);
    assert_eq!(coherent(&capture).total.unwrap().live_buffers, 0);
}

#[test]
fn arithmetic_damage_is_unknown_while_an_empty_buffer_is_a_real_owner() {
    let capture = ResourceCapture::new([0xd4; 16]);
    let empty = Vec::new();
    let lease = ResidencyLease::observe(&capture, ResidencyStage::RawChannel, &empty).unwrap();
    assert_eq!(
        coherent(&capture).total.unwrap(),
        ResidencyTotals {
            live_buffers: 1,
            len_bytes: 0,
            capacity_bytes: 0
        }
    );
    capture.residency.total.buffers.store(0, Ordering::Relaxed);
    drop(lease);
    let damaged = capture.residency_snapshot();
    assert!(damaged.coherent && !damaged.valid);
    assert!(damaged.total.is_none());
    assert_ne!(damaged.gap_bits, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_original_owners_move_without_false_zero_or_inflated_capacity_peak() {
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;
    use std::time::Duration;
    use tokio::sync::{mpsc, watch};
    let end = tokio::time::Instant::now() + Duration::from_secs(2);
    let work = end - Duration::from_millis(250);
    let capture = ResourceCapture::new([0xd5; 16]);
    let (ready, mut readiness) = mpsc::channel(4);
    let (release, released) = watch::channel(false);
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let capture = capture.clone();
        let ready = ready.clone();
        let mut released = released.clone();
        workers.spawn(async move {
            let original = bytes(16, 128);
            let mut lease =
                ResidencyLease::observe(&capture, ResidencyStage::RawChannel, &original).unwrap();
            let copy = original.clone();
            let _copy_lease = lease.clone_for(&copy).unwrap();
            for i in 0..128 {
                lease.relocate(
                    if i % 2 == 0 {
                        ResidencyStage::PendingFifo
                    } else {
                        ResidencyStage::DetachedRaw
                    },
                    &original,
                );
            }
            ready
                .send((
                    original.len() + copy.len(),
                    original.capacity() + copy.capacity(),
                ))
                .await
                .unwrap();
            let _ = released.changed().await;
        });
    }
    drop(ready);
    let body = tokio::time::timeout_at(
        work,
        AssertUnwindSafe(async {
            let mut expected_len = 0;
            let mut expected_capacity = 0;
            for _ in 0..4 {
                let (len, capacity) = tokio::time::timeout_at(work, readiness.recv())
                    .await
                    .unwrap()
                    .unwrap();
                expected_len += len;
                expected_capacity += capacity;
            }
            let snapshot = coherent(&capture);
            assert_eq!(
                snapshot.total.unwrap(),
                ResidencyTotals {
                    live_buffers: 8,
                    len_bytes: expected_len as u64,
                    capacity_bytes: expected_capacity as u64
                }
            );
            assert_eq!(
                snapshot.capacity_high_water_bytes,
                Some(expected_capacity as u64)
            );
            assert_eq!(snapshot.clone_ops, Some(4));
        })
        .catch_unwind(),
    )
    .await;
    drop(release);
    if !matches!(body, Ok(Ok(()))) {
        workers.abort_all();
    }
    let mut joined = 0;
    let mut join_errors = Vec::new();
    while let Some(result) = tokio::time::timeout_at(end, workers.join_next())
        .await
        .unwrap()
    {
        if let Err(error) = result {
            join_errors.push(error);
        }
        joined += 1;
    }
    assert_eq!(joined, 4);
    match body {
        Ok(Ok(())) => assert!(join_errors.is_empty()),
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(error) => panic!("fixed work deadline after owned joins: {error}"),
    }
    assert_eq!(
        coherent(&capture).total.unwrap(),
        ResidencyTotals::default()
    );
}
