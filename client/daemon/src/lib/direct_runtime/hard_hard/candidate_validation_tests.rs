async fn candidate_validation_fixture() -> (
    Daemon,
    PendingPeerOffer,
    UdpTransport,
    crate::udp::DirectValidationSessionLease,
) {
    let (daemon, record, _, _) = barrier_fixture().await;
    daemon
        .peers
        .clear_hard_hard_sessions(Some(&record.peer_id))
        .await;
    let offer = startup_offer(&daemon, &record, 1, true).await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    *daemon.udp_transport.write().await = Some(udp.clone());
    let crate::udp::DirectValidationSessionStart::Spawn(lease) = udp
        .begin_or_merge_direct_validation(&record.peer_id, "127.0.0.1:41001".parse().unwrap(), 0)
        .await
    else {
        panic!("existing encrypted validation must own the peer")
    };
    (daemon, offer, udp, lease)
}

#[tokio::test(start_paused = true)]
async fn hard_hard_candidate_offer_preserves_inflight_validation_ack() {
    let (daemon, offer, udp, lease) = candidate_validation_fixture().await;
    let target = *lease.target_rx.borrow();
    let peer = offer.from_node_id.clone();
    assert!(
        udp.expect_direct_validation_ack_owned(&peer, 7, 0, lease.owner_token, target.endpoint)
            .await
    );
    let before = daemon.peers.current_remote_candidate_epoch(&peer).await;
    let (reservation, offer) = startup_reserve(&daemon, offer);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(
        futures_util::poll!(&mut worker).is_pending(),
        "new HH candidates must yield to the already-sent validation"
    );
    assert_eq!(
        daemon.peers.current_remote_candidate_epoch(&peer).await,
        before
    );
    assert!(!lease.target_rx.borrow().cancelled);
    assert!(
        udp.consume_direct_validation_ack(
            &peer,
            7,
            0,
            lease.owner_token,
            0,
            target.endpoint,
            None,
            false
        )
        .await
        .is_ok(),
        "the old exact ACK must remain consumable while the HH candidate waits"
    );
    assert!(
        udp.finish_direct_validation_session(&peer, lease.owner_token)
            .await
    );
    tokio::time::timeout(Duration::from_millis(100), worker)
        .await
        .unwrap();
    assert_eq!(
        daemon
            .peers
            .get_connection(&peer)
            .await
            .unwrap()
            .last_candidate_generation(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn hard_hard_candidate_validation_wait_is_bounded() {
    let (daemon, offer, _udp, lease) = candidate_validation_fixture().await;
    let peer = offer.from_node_id.clone();
    let (reservation, offer) = startup_reserve(&daemon, offer);
    let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
    assert!(futures_util::poll!(&mut worker).is_pending());
    tokio::time::advance(Duration::from_millis(249)).await;
    assert!(futures_util::poll!(&mut worker).is_pending());
    assert!(!lease.target_rx.borrow().cancelled);
    tokio::time::timeout(Duration::from_millis(2), worker)
        .await
        .unwrap();
    assert!(lease.target_rx.borrow().cancelled);
    assert_eq!(
        daemon
            .peers
            .get_connection(&peer)
            .await
            .unwrap()
            .last_candidate_generation(),
        1
    );
    assert!(daemon
        .timeline
        .snapshot()
        .events
        .iter()
        .any(|event| event.reason_code.as_deref() == Some("direct_validation_wait_expired")));
}

#[tokio::test(start_paused = true)]
async fn hard_hard_candidate_validation_wait_rechecks_lifecycle() {
    for network_changed in [false, true] {
        let (daemon, offer, _udp, _lease) = candidate_validation_fixture().await;
        let peer = offer.from_node_id.clone();
        let (reservation, offer) = startup_reserve(&daemon, offer);
        let mut worker = Box::pin(daemon.run_candidate_offer_worker(*offer, reservation));
        assert!(futures_util::poll!(&mut worker).is_pending());
        if network_changed {
            daemon
                .peers
                .advance_network_generation("candidate validation wait test")
                .await;
        } else {
            daemon.pending_handshakes.lock().clear_peer(&peer);
        }
        tokio::time::timeout(Duration::from_millis(100), worker)
            .await
            .unwrap();
        assert_eq!(
            daemon
                .peers
                .get_connection(&peer)
                .await
                .unwrap()
                .last_candidate_generation(),
            0
        );
    }
}

#[tokio::test(start_paused = true)]
async fn hard_hard_candidate_answer_does_not_wait_for_validation() {
    let (daemon, mut offer, _udp, lease) = candidate_validation_fixture().await;
    let mut coordination =
        HardHardCoordination::parse(offer.session_id.as_deref().unwrap()).unwrap();
    coordination.role = HardHardRole::Responder;
    coordination.v2.as_mut().unwrap().stage = HardHardV2Stage::Answer;
    offer.session_id = Some(coordination.encode());
    let (mut reservation, offer) = startup_reserve(&daemon, offer);
    assert!(tokio::time::timeout(
        Duration::from_millis(1),
        daemon.wait_for_hard_hard_candidate_owner(&offer, &mut reservation)
    )
    .await
    .unwrap());
    assert!(!lease.target_rx.borrow().cancelled);
}
