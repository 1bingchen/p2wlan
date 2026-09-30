/// Normal joining can leave a probe on the previous fresh socket when HH2
/// commits its measured replacement. Draining that probe must retain the old
/// reader without spending the new plan's READY/SYNC window.
#[tokio::test]
async fn hard_hard_handoff_does_not_wait_for_predecessor_probe_drain() {
    let (peers, transport, _nat) = generation_env().await;
    let (inbound_tx, _inbound_rx) = mpsc::channel(64);
    let inbound_transport = transport.clone();
    let inbound = tokio::spawn(async move {
        let _ = (*inbound_transport).clone().run_inbound(inbound_tx).await;
    });
    let (old_index, old_socket) = transport.bind_fresh_punch_socket().await.unwrap();
    let old_guard = transport
        .attach_dynamic_punch_socket("peer-b", old_index, old_socket, 0, 1, None)
        .await
        .unwrap();
    assert!(old_guard
        .commit_and_pin(&transport, "peer-b", old_index, 0, 1)
        .await
        .committed());
    assert!(old_guard.finalize().await);
    let (_, old_socket, old_lease) = transport
        .resolve_dynamic_socket_for_send("peer-b")
        .await
        .unwrap();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let nonce = transport
        .send_probe_on_socket(
            old_index,
            old_socket.clone(),
            Some("peer-b"),
            remote.local_addr().unwrap(),
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
        .unwrap();
    assert!(transport.pending_probes.lock().await.contains_key(&nonce));

    let (new_index, new_socket) = transport.bind_fresh_punch_socket().await.unwrap();
    let cancellation = Arc::new(crate::PunchSessionCancellation::default());
    let new_guard = transport
        .attach_dynamic_punch_socket("peer-b", new_index, new_socket, 0, 2, Some(&cancellation))
        .await
        .unwrap();
    assert!(new_guard
        .commit_and_pin(&transport, "peer-b", new_index, 0, 2)
        .await
        .committed());
    assert!(timeout(Duration::from_millis(500), new_guard.finalize())
        .await
        .expect("old probe drain must not delay the new rendezvous"));
    assert!(!transport
        .socket_state
        .lock()
        .await
        .dynamic
        .contains_key(&old_index));
    assert!(transport.pending_probes.lock().await.contains_key(&nonce));
    assert_eq!(
        transport.dynamic_socket_index_for_peer("peer-b").await,
        Some(new_index)
    );

    // A late authenticated ACK must still reach the retired reader, but its
    // older stamped evidence must not re-pin over the replacement generation.
    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let ack = build_authenticated_punch_ack(nonce, "peer-b", "peer-a", 0, &key);
    remote
        .send_to(&ack, old_socket.local_addr().unwrap())
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while transport.pending_probes.lock().await.contains_key(&nonce) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the draining reader must still consume its matching ACK");
    assert_eq!(transport.probe_rx_snapshot().await.probe_acks_received, 1);
    assert_eq!(
        transport.dynamic_socket_index_for_peer("peer-b").await,
        Some(new_index)
    );
    assert!(transport
        .dynamic_socket_diagnostics
        .lock()
        .await
        .contains_key(&old_index));
    cancellation.cancel();
    drop(new_guard);
    drop(old_lease);
    timeout(Duration::from_secs(1), async {
        while transport
            .dynamic_socket_diagnostics
            .lock()
            .await
            .contains_key(&old_index)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the existing watcher must finish retirement after the lease drains");
    assert_eq!(
        transport.dynamic_socket_index_for_peer("peer-b").await,
        Some(new_index)
    );
    transport
        .detach_all_dynamic_punch_sockets("test_cleanup")
        .await;
    inbound.abort();
}
