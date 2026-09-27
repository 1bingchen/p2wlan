async fn assert_validation_request_during_emit_contention(replace_session: bool) {
    let (mut remote_session, local_session) = establish_sessions();
    let (transport, _outbound_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local_session).await;
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("http://127.0.0.1:1", "validation-contention").unwrap(),
    ));
    peers
        .add_peer(&PeerInfo {
            capabilities: crate::control::PeerCapabilities::default(),
            registration_seq: 0,
            node_id: "peer-a".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            ..PeerInfo::default()
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let remote_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request_id = 0x7101;
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        request_id,
        0,
        &build_direct_validation_payload(DirectValidationKind::Request, 0, request_id, 0, 19),
    );
    let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
    encrypted_tx
        .send(ReceivedEncryptedPacket {
            source: Some(remote_socket.local_addr().unwrap()),
            local_endpoint: udp.local_addr().ok(),
            relay_endpoint: None,
            relay_connection_id: None,
            relay_peer_id: None,
            socket_index: Some(0),
            direct_socket: None,
            udp_transport_owner: None,
            network_generation: Some(0),
            profile_sampled: false,
            udp_received: None,
            transport_queue_send_started: None,
            wire_bytes: remote_session.encrypt_to_bytes(&packet).unwrap(),
        })
        .await
        .unwrap();
    drop(encrypted_tx);

    let emit_lock = transport.outbound_emit_lock("peer-a").await;
    let emit_guard = emit_lock.lock().await;
    let mut inbound = Box::pin(transport.run_inbound_with_peers(
        encrypted_rx,
        inbound_tx,
        Some(peers.clone()),
        Some(udp),
    ));
    assert!(
        futures_util::poll!(&mut inbound).is_pending(),
        "a decrypted request must wait for transient emit contention instead of being discarded"
    );
    assert!(!peers
        .get_connection("peer-a")
        .await
        .unwrap()
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_validation_request_received"));

    if replace_session {
        let (_, new_local) = establish_sessions();
        let mut replacement = Box::pin(transport.add_session("peer-a", new_local));
        assert!(futures_util::poll!(&mut replacement).is_pending());
        drop(emit_guard);
        assert!(replacement.await);
    } else {
        drop(emit_guard);
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    timeout(Duration::from_millis(20), inbound)
        .await
        .expect("bounded evidence wait must resolve after emit releases")
        .unwrap();
    assert!(inbound_rx.recv().await.is_none());

    let connection = peers.get_connection("peer-a").await.unwrap();
    let request_seen = connection
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_validation_request_received");
    let ack_sent = connection
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_validation_ack_sent");
    assert_eq!(request_seen, !replace_session);
    assert_eq!(ack_sent, !replace_session);
    assert_ne!(connection.state, ConnectionState::Direct);
    let mut buffer = [0u8; 2048];
    if replace_session {
        assert!(
            matches!(remote_socket.try_recv_from(&mut buffer), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    } else {
        let (size, _) = timeout(
            Duration::from_millis(20),
            remote_socket.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        let message = MessageTransport::from_bytes(&buffer[..size]).unwrap();
        let ack = remote_session.decrypt(&message).unwrap();
        let token = parse_direct_validation_token(&ack).unwrap();
        assert_eq!(token.kind, DirectValidationKind::Ack);
        assert_eq!(token.request_id, request_id);
        assert_eq!(token.owner_token, 19);
    }
}

#[tokio::test(start_paused = true)]
async fn direct_validation_emit_contention_preserves_first_request_ack() {
    assert_validation_request_during_emit_contention(false).await;
}

#[tokio::test(start_paused = true)]
async fn direct_validation_emit_contention_still_rejects_replaced_session() {
    assert_validation_request_during_emit_contention(true).await;
}

#[tokio::test(start_paused = true)]
async fn direct_validation_emit_contention_has_one_bounded_fence_wait() {
    let (_, local_session) = establish_sessions();
    let (transport, _outbound_rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local_session).await;
    let emit_lock = transport.outbound_emit_lock("peer-a").await;
    let _emit_guard = emit_lock.lock().await;
    let mut wait = Box::pin(transport.acquire_direct_validation_session_guard("peer-a", Some(1)));
    assert!(futures_util::poll!(&mut wait).is_pending());
    tokio::time::advance(DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT).await;
    assert!(matches!(
        wait.await,
        CurrentSessionEvidenceGuardOutcome::Contended
    ));
}
