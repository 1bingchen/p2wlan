use super::*;

async fn wait_for_rejections(gate: &TestUdpIngressGate, expected: u64) {
    timeout(Duration::from_secs(1), async {
        while gate.rejected_datagrams() < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the socket reader must reject the exact bypass datagram");
    assert_eq!(gate.rejected_datagrams(), expected);
}

#[tokio::test]
async fn nat_ingress_gate_blocks_private_bypass_on_primary_pool_and_dynamic_readers() {
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.2", None)).await;
    let gate = Arc::new(TestUdpIngressGate::default());
    let (tx, mut rx) = mpsc::channel(8);
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(2)
        .await
        .unwrap()
        .with_test_ingress_gate(gate.clone())
        .with_inbound_channel(tx.clone());
    let reader_udp = udp.clone();
    let reader = tokio::spawn(async move { reader_udp.run_inbound(tx).await });
    let private_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let nat_source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"synthetic-encrypted-datagram";

    // Already-cloned readers must stay closed while the harness is being
    // constructed, then share its one immutable source configuration.
    private_peer
        .send_to(payload, udp.local_addr().unwrap())
        .await
        .unwrap();
    wait_for_rejections(&gate, 1).await;
    gate.allow_sources_once([
        nat_source.local_addr().unwrap(),
        observer.local_addr().unwrap(),
    ]);

    let (dynamic_index, dynamic) = udp.bind_fresh_punch_socket().await.unwrap();
    let dynamic_guard = udp
        .attach_dynamic_punch_socket(
            "peer-b",
            dynamic_index,
            dynamic.clone(),
            peers.current_network_generation_sync(),
            peers.next_punch_generation("peer-b").await,
            None,
        )
        .await
        .unwrap();
    let mut targets: Vec<_> = udp
        .active_sockets()
        .iter()
        .enumerate()
        .map(|(index, socket)| (index, socket.local_addr().unwrap()))
        .collect();
    targets.push((dynamic_index, dynamic.local_addr().unwrap()));

    for (position, (index, endpoint)) in targets.into_iter().enumerate() {
        let transaction = [position as u8 + 1; 12];
        let stun = StunMessage::with_transaction_id(BINDING_RESPONSE, transaction).encode();
        let (completion, mut response) = oneshot::channel();
        let _lease = udp.stun_waiters.register(transaction, completion).unwrap();
        // A valid STUN envelope cannot bypass the source boundary either.
        // These sends deliberately address the real private socket, so no
        // random birthday-port collision is needed to exercise the defect.
        private_peer.send_to(payload, endpoint).await.unwrap();
        private_peer.send_to(&stun, endpoint).await.unwrap();
        wait_for_rejections(&gate, 3 + 2 * position as u64).await;
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        nat_source.send_to(payload, endpoint).await.unwrap();
        let delivered = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.socket_index, Some(index));
        assert_eq!(delivered.source, Some(nat_source.local_addr().unwrap()));
        assert_eq!(delivered.wire_bytes, payload);
        observer.send_to(&stun, endpoint).await.unwrap();
        let observed = timeout(Duration::from_secs(1), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.source, observer.local_addr().unwrap());
        assert_eq!(observed.data, stun);
    }
    assert_eq!(gate.rejected_datagrams(), 7);
    drop(dynamic_guard);
    udp.detach_dynamic_socket_by_index(dynamic_index, "test_complete")
        .await;
    reader.abort();
    let _ = reader.await;
}

#[tokio::test]
async fn nat_ingress_gate_is_disabled_on_an_independent_transport_by_default() {
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap();
    assert!(udp.test_ingress_gate.is_none());
    let endpoint = udp.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    let reader = tokio::spawn(udp.run_inbound(tx));
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(b"default-transport", endpoint)
        .await
        .unwrap();
    let packet = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet.source, Some(sender.local_addr().unwrap()));
    assert_eq!(packet.wire_bytes, b"default-transport");
    reader.abort();
    let _ = reader.await;
}
