use crate::dataplane_resources::{ResidencySnapshot, ResidencyStage, ResourceCapture};
use crate::request_carriage::{RawOutboundReceiver, RawRequestDelivery, RequestEncryptionAttempt};

#[tokio::test]
async fn residency_observed_delivery_survives_plain_tracked_channel_backpressure() {
    use crate::request_carriage::RawOutboundSink;
    timeout(Duration::from_secs(1), async {
        let capture = ResourceCapture::new([0xe7; 16]);
        let (transport, receiver) = WireGuardTransport::new_with_request_carriage();
        let transport = transport.with_resource_capture(capture.clone()).unwrap();
        let mut source = RawOutboundReceiver::from(receiver);
        let (sender, receiver) = mpsc::channel(1);
        let sink = RawOutboundSink::Tracked(sender);
        let mut receiver = RawOutboundReceiver::from(receiver);
        let raw = channel_input(&transport, &mut source, 1).await;
        let ptr = raw.packet.as_ptr();
        sink.try_send(raw).unwrap();
        let queued = owners(&capture, 1);
        assert_eq!(
            queued.total,
            queued.stage(ResidencyStage::RawChannel),
            "an existing observer must follow the actual original tracked channel"
        );
        let raw = receiver.recv().await.unwrap();
        assert_eq!(raw.packet.as_ptr(), ptr);
        assert_eq!(
            owners(&capture, 1).total,
            owners(&capture, 1).stage(ResidencyStage::DetachedRaw)
        );
        drop(raw);
        owners(&capture, 0);

        sink.try_send(s3a_outbound(0)).unwrap();
        let raw = channel_input(&transport, &mut source, 2).await;
        let ptr = raw.packet.as_ptr();
        let mpsc::error::TrySendError::Full(raw) = *sink.try_send(raw).unwrap_err() else {
            panic!("original channel is full")
        };
        assert_eq!(raw.packet.as_ptr(), ptr);
        assert_eq!(
            owners(&capture, 1).total,
            owners(&capture, 1).stage(ResidencyStage::ChannelReserve)
        );
        let mut pending = Box::pin(sink.send(raw));
        assert!(matches!(
            futures_util::poll!(pending.as_mut()),
            std::task::Poll::Pending
        ));
        assert_eq!(
            owners(&capture, 1).total,
            owners(&capture, 1).stage(ResidencyStage::ChannelReserve)
        );
        drop(pending);
        owners(&capture, 0);
        drop(receiver.try_recv().unwrap());

        for sequence in [3, 4] {
            let raw = channel_input(&transport, &mut source, sequence).await;
            if sequence == 3 {
                sink.reserve().await.unwrap().send(raw).unwrap();
            } else {
                sink.send(raw).await.unwrap();
            }
            let queued = owners(&capture, 1);
            assert_eq!(queued.total, queued.stage(ResidencyStage::RawChannel));
            assert_eq!(queued.unknown_bits, 0);
            drop(receiver.recv().await.unwrap());
            owners(&capture, 0);
        }
        capture.finish();
        assert_eq!(owners(&capture, 0).clone_ops, Some(0));
    })
    .await
    .expect("fixed original tracked channel work and owned cancellation bound");
}

fn owners(capture: &ResourceCapture, count: u64) -> ResidencySnapshot {
    let snapshot = capture.residency_snapshot();
    assert!(snapshot.coherent && snapshot.valid);
    assert_eq!(snapshot.gap_bits, 0);
    assert_eq!(snapshot.total.unwrap().live_buffers, count);
    assert!(!snapshot.whole_pipeline_bytes_measured);
    snapshot
}

async fn channel_input(
    transport: &WireGuardTransport,
    receiver: &mut RawOutboundReceiver,
    sequence: u16,
) -> RawRequestDelivery {
    transport
        .outbound_tx
        .send(s3a_outbound(sequence))
        .await
        .unwrap();
    receiver.recv().await.unwrap()
}

#[tokio::test]
async fn residency_real_resized_crypto_input_refreshes_capacity_without_inventing_history() {
    timeout(Duration::from_secs(1), async {
        let capture = ResourceCapture::new([0xe6; 16]);
        let (transport, receiver) = WireGuardTransport::new_with_request_carriage();
        let transport = transport.with_resource_capture(capture.clone()).unwrap();
        let mut receiver = RawOutboundReceiver::from(receiver);
        let mut raw = channel_input(&transport, &mut receiver, 1).await;
        raw.relocate_resources(ResidencyStage::PreparationPlaintext);
        raw.packet.reserve(1024);
        let actual_capacity = raw.packet.capacity() as u64;
        let emit = transport.acquire_outbound_emit_guard("peer-a").await;
        let RequestEncryptionAttempt::Unavailable { packet, reason } =
            transport.try_encrypt_request_with_emit_guard_for_session(raw, 1)
        else {
            panic!("no installed session must retain original input")
        };
        assert_eq!(reason, SessionUnavailableReason::PeerSessionsMissing);
        let live = owners(&capture, 1);
        assert_eq!(live.total.unwrap().capacity_bytes, actual_capacity);
        assert_eq!(live.stage(ResidencyStage::PreparationPlaintext), live.total);
        assert_eq!(live.unknown_bits, 2);
        assert_eq!(live.clone_ops, Some(0));
        drop(packet);
        drop(emit);
        owners(&capture, 0);
    })
    .await
    .expect("fixed real input mutation and cleanup bound");
}

#[tokio::test]
async fn residency_actual_fast_and_slow_crypto_keep_owners_and_original_counter_once() {
    timeout(Duration::from_secs(2), async {
        let capture = ResourceCapture::new([0xe1; 16]);
        let (transport, receiver) = WireGuardTransport::new_with_request_carriage();
        let transport = transport.with_resource_capture(capture.clone()).unwrap();
        let mut receiver = RawOutboundReceiver::from(receiver);
        let (session, mut remote) = establish_sessions();
        assert!(!transport.add_session("peer-a", session).await);
        let instance = transport
            .session_status("peer-a")
            .await
            .active_session_instance
            .unwrap();
        let mut raw = channel_input(&transport, &mut receiver, 1).await;
        let original = raw.packet.clone();
        let original_ptr = raw.packet.as_ptr();
        raw.relocate_resources(ResidencyStage::PreparationPlaintext);
        let emit = transport.acquire_outbound_emit_guard("peer-a").await;
        let held = transport.sessions.lock().await;
        let RequestEncryptionAttempt::Contended(raw) =
            transport.try_encrypt_request_with_emit_guard_for_session(raw, instance)
        else {
            panic!("held original registry must return original plaintext")
        };
        assert_eq!(raw.packet.as_ptr(), original_ptr);
        assert_eq!(
            owners(&capture, 1)
                .stage(ResidencyStage::PreparationPlaintext)
                .unwrap()
                .live_buffers,
            1
        );
        drop(held);
        let RequestEncryptionAttempt::Unavailable {
            packet: raw,
            reason,
        } = transport.try_encrypt_request_with_emit_guard_for_session(raw, instance + 1)
        else {
            panic!("foreign cached instance must not encrypt")
        };
        assert_eq!(reason, SessionUnavailableReason::SessionInstanceMismatch);
        assert_eq!(raw.packet.as_ptr(), original_ptr);
        let RequestEncryptionAttempt::Encrypted {
            packet, plaintext, ..
        } = transport.try_encrypt_request_with_emit_guard_for_session(raw, instance)
        else {
            panic!("same actual available slot must encrypt")
        };
        let live = owners(&capture, 2);
        assert_eq!(live.unknown_bits, 0);
        assert_eq!(live.clone_ops, Some(0));
        assert_eq!(
            live.stage(ResidencyStage::PreparationPlaintext)
                .unwrap()
                .live_buffers,
            1
        );
        assert_eq!(
            live.stage(ResidencyStage::SerializedWire)
                .unwrap()
                .live_buffers,
            1
        );
        assert_eq!(
            live.total.unwrap().capacity_bytes,
            (plaintext.packet.capacity() + packet.wire_bytes.capacity()) as u64
        );
        assert_eq!(
            live.capacity_high_water_bytes,
            Some(live.total.unwrap().capacity_bytes)
        );
        assert_eq!(plaintext.packet.as_ptr(), original_ptr);
        assert_eq!(wire_counter(&packet.wire_bytes), Some(0));
        assert_eq!(
            remote.decrypt_from_bytes(&packet.wire_bytes).unwrap(),
            original
        );
        assert!(remote.decrypt_from_bytes(&packet.wire_bytes).is_err());
        drop(plaintext);
        assert_eq!(
            owners(&capture, 1)
                .stage(ResidencyStage::SerializedWire)
                .unwrap()
                .live_buffers,
            1
        );
        drop(packet);
        owners(&capture, 0);
        drop(emit);

        let mut raw = channel_input(&transport, &mut receiver, 2).await;
        let plaintext_capacity = raw.packet.capacity() as u64;
        let original = raw.packet.clone();
        raw.relocate_resources(ResidencyStage::PreparationPlaintext);
        let emit = transport.acquire_outbound_emit_guard("peer-a").await;
        let encrypted = transport
            .encrypt_request_with_emit_guard(raw)
            .await
            .unwrap()
            .unwrap();
        let live = owners(&capture, 1);
        assert_eq!(live.unknown_bits, 0);
        assert_eq!(live.clone_ops, Some(0));
        assert_eq!(live.total, live.stage(ResidencyStage::SerializedWire));
        assert!(
            live.capacity_high_water_bytes.unwrap()
                >= plaintext_capacity + encrypted.wire_bytes.capacity() as u64
        );
        assert_eq!(wire_counter(&encrypted.wire_bytes), Some(1));
        assert_eq!(
            remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
            original
        );
        drop(encrypted);
        drop(emit);
        capture.finish();
        owners(&capture, 0);
        assert!(receiver.try_recv().is_err());
    })
    .await
    .expect("fixed original crypto work and cleanup bound");
}

#[tokio::test]
async fn residency_cross_capture_and_disabled_crypto_mark_original_input_unknown() {
    timeout(Duration::from_secs(2), async {
        for fast in [false, true] {
            for observed_output in [false, true] {
                let original = ResourceCapture::new([0xe2; 16]);
                let (source, receiver) = WireGuardTransport::new_with_request_carriage();
                let source = source.with_resource_capture(original.clone()).unwrap();
                let mut receiver = RawOutboundReceiver::from(receiver);
                let raw = channel_input(&source, &mut receiver, 1).await;
                let expected = raw.packet.clone();
                let output = ResourceCapture::new([0xe3; 16]);
                let (target, _) = WireGuardTransport::new_with_request_carriage();
                let target = if observed_output {
                    target.with_resource_capture(output.clone()).unwrap()
                } else {
                    target
                };
                let (session, mut remote) = establish_sessions();
                assert!(!target.add_session("peer-a", session).await);
                let instance = target
                    .session_status("peer-a")
                    .await
                    .active_session_instance
                    .unwrap();
                let emit = target.acquire_outbound_emit_guard("peer-a").await;
                let encrypted = if fast {
                    let RequestEncryptionAttempt::Encrypted {
                        packet, plaintext, ..
                    } = target.try_encrypt_request_with_emit_guard_for_session(raw, instance)
                    else {
                        panic!("actual target slot must encrypt")
                    };
                    assert_eq!(owners(&original, 1).unknown_bits, 1);
                    drop(plaintext);
                    packet
                } else {
                    target
                        .encrypt_request_with_emit_guard(raw)
                        .await
                        .unwrap()
                        .unwrap()
                };
                assert_eq!(owners(&original, 0).unknown_bits, 1);
                let output_state = owners(&output, u64::from(observed_output));
                assert_eq!(output_state.unknown_bits, u32::from(observed_output));
                assert_eq!(
                    remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
                    expected
                );
                assert_eq!(wire_counter(&encrypted.wire_bytes), Some(0));
                drop(encrypted);
                drop(emit);
                owners(&output, 0);
            }
        }
    })
    .await
    .expect("fixed cross-scope crypto work and cleanup bound");
}

#[tokio::test]
async fn residency_actual_session_overflow_and_cancelled_flush_drain_original_owners() {
    timeout(Duration::from_secs(2), async {
        let capture = ResourceCapture::new([0xe4; 16]);
        let (transport, receiver) = WireGuardTransport::new_with_request_carriage();
        let transport = transport.with_resource_capture(capture.clone()).unwrap();
        let mut receiver = RawOutboundReceiver::from(receiver);
        let mut expected_len = 0;
        let mut expected_capacity = 0;
        for sequence in 0..=MAX_PENDING_OUTBOUND_PER_PEER {
            let packet = channel_input(&transport, &mut receiver, sequence as u16).await;
            if sequence > 0 {
                expected_len += packet.packet.len() as u64;
                expected_capacity += packet.packet.capacity() as u64;
            }
            transport
                .queue_pending_outbound(packet, "session not ready")
                .await;
        }
        let parked = owners(&capture, MAX_PENDING_OUTBOUND_PER_PEER as u64);
        assert_eq!(parked.unknown_bits, 0);
        assert_eq!(parked.total, parked.stage(ResidencyStage::SessionBacklog));
        assert_eq!(parked.total.unwrap().len_bytes, expected_len);
        assert_eq!(parked.total.unwrap().capacity_bytes, expected_capacity);
        {
            let pending = transport.pending_outbound.lock().await;
            assert_eq!(pending["peer-a"].len(), MAX_PENDING_OUTBOUND_PER_PEER);
            assert_eq!(
                pending["peer-a"].front().unwrap().packet.packet,
                s3a_outbound(1).packet
            );
        }
        let mut fillers_len = 0;
        let mut fillers_capacity = 0;
        for _ in 0..transport.outbound_tx.max_capacity() {
            let filler = s3a_outbound(0);
            fillers_len += filler.packet.len() as u64;
            fillers_capacity += filler.packet.capacity() as u64;
            transport.outbound_tx.try_send(filler).unwrap();
        }
        let mut flush = Box::pin(transport.flush_pending_outbound_for_peer("peer-a"));
        assert!(matches!(
            futures_util::poll!(flush.as_mut()),
            std::task::Poll::Pending
        ));
        let held = owners(&capture, (MAX_PENDING_OUTBOUND_PER_PEER + 1024) as u64);
        assert_eq!(
            held.stage(ResidencyStage::SessionBacklog)
                .unwrap()
                .live_buffers,
            0
        );
        assert_eq!(
            held.stage(ResidencyStage::SessionFlush)
                .unwrap()
                .live_buffers,
            (MAX_PENDING_OUTBOUND_PER_PEER - 1) as u64
        );
        assert_eq!(
            held.stage(ResidencyStage::ChannelReserve)
                .unwrap()
                .live_buffers,
            1
        );
        assert_eq!(
            held.stage(ResidencyStage::RawChannel).unwrap().live_buffers,
            1024
        );
        assert_eq!(held.total.unwrap().len_bytes, fillers_len + expected_len);
        assert_eq!(
            held.total.unwrap().capacity_bytes,
            fillers_capacity + expected_capacity
        );
        drop(flush); // The original future owns its unforwarded Vec iterator.
        assert!(transport.pending_outbound.lock().await.is_empty());
        let cancelled = owners(&capture, 1024);
        assert_eq!(cancelled.total, cancelled.stage(ResidencyStage::RawChannel));
        assert_eq!(cancelled.total.unwrap().capacity_bytes, fillers_capacity);
        drop(receiver);
        capture.finish();
        let drained = owners(&capture, 0);
        assert_eq!(drained.unknown_bits, 0);
        assert_eq!(drained.clone_ops, Some(0));
    })
    .await
    .expect("fixed actual session queue and owned flush cleanup bound");
}
