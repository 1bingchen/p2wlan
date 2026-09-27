use super::*;
use crate::peer::{DirectCommitHooks, HardHardPairEvidence, HardHardPairKey};

fn pair(fixture: &WinnerFixture, position: usize, remote: SocketAddr) -> HardHardPairKey {
    HardHardPairKey {
        socket_index: fixture.indices[position],
        local_endpoint: fixture.sockets[position].local_addr().unwrap(),
        remote_endpoint: remote,
    }
}

async fn observe(
    fixture: &WinnerFixture,
    pair: &HardHardPairKey,
    evidence: HardHardPairEvidence,
) -> bool {
    fixture
        .peers
        .hard_hard_pair_observe("peer-b", TOKEN, pair.clone(), evidence)
        .await
}

async fn confirmed(fixture: &WinnerFixture) -> HardHardValidationScope {
    let pair = pair(fixture, 0, fixture.remote.local_addr().unwrap());
    assert!(observe(fixture, &pair, HardHardPairEvidence::ConnectivityAck).await);
    assert!(observe(fixture, &pair, HardHardPairEvidence::NominationAck).await);
    fixture
        .udp
        .hard_hard_validation_scope("peer-b", pair.socket_index, pair.remote_endpoint)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn hard_hard_hh2_crossed_checks_converge_only_after_one_nomination() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let controlling = WinnerFixture::with_protocol(true, true).await;
    let controlled = WinnerFixture::with_protocol(false, true).await;
    // The first checks succeed on opposite pairs. Only the controller may
    // freeze a choice; the controlled side's earlier ACK is only validity.
    let chosen_a = pair(&controlling, 0, controlled.sockets[1].local_addr().unwrap());
    let chosen_b = pair(&controlled, 1, controlling.sockets[0].local_addr().unwrap());
    let other_b = pair(&controlled, 0, controlling.sockets[1].local_addr().unwrap());
    assert!(observe(&controlled, &other_b, HardHardPairEvidence::ConnectivityAck).await);
    assert!(
        !controlled
            .peers
            .hard_hard_pair_is_prepared("peer-b", TOKEN)
            .await
    );
    assert!(
        observe(
            &controlling,
            &chosen_a,
            HardHardPairEvidence::ConnectivityAck
        )
        .await
    );
    assert!(
        observe(
            &controlled,
            &chosen_b,
            HardHardPairEvidence::NominationRequest
        )
        .await
    );
    assert_eq!(
        controlled
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(None)
    );
    // Lost nomination ACK: the same request is idempotent and a conflicting
    // nomination cannot switch the controlled side to its earlier valid pair.
    assert!(
        observe(
            &controlled,
            &chosen_b,
            HardHardPairEvidence::NominationRequest
        )
        .await
    );
    assert!(
        !observe(
            &controlled,
            &other_b,
            HardHardPairEvidence::NominationRequest
        )
        .await
    );
    assert!(!observe(&controlled, &chosen_b, HardHardPairEvidence::NominationAck).await);
    assert!(
        observe(
            &controlled,
            &chosen_b,
            HardHardPairEvidence::ConnectivityAck
        )
        .await
    );
    assert!(observe(&controlling, &chosen_a, HardHardPairEvidence::NominationAck).await);
    assert_eq!(
        controlled
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(Some((TOKEN.into(), chosen_b.clone())))
    );
    assert_eq!(
        controlling
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(Some((TOKEN.into(), chosen_a.clone())))
    );
    assert_eq!(
        controlling
            .peers
            .hard_hard_winner_for_token("peer-b", TOKEN)
            .await,
        None
    );
    assert_eq!(
        controlled
            .peers
            .hard_hard_winner_for_token("peer-b", TOKEN)
            .await,
        None
    );
    assert!(
        !controlled
            .udp
            .permits_ordinary_send_on_socket(
                "peer-b",
                chosen_b.socket_index,
                &controlled.sockets[1]
            )
            .await
    );
    controlling.cleanup().await;
    controlled.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_ack_requires_exact_tuple_and_preserves_session_diagnostics() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    assert!(
        fixture
            .peers
            .set_probe_session_id("peer-b", Some("hh2-probe-session".into()))
            .await
    );
    let sent = fixture.send(0).await;
    let key = crate::peer::hard_hard_scoped_probe_key(
        &fixture.peers.probe_key_for_peer("peer-b").await.unwrap(),
        TOKEN,
    );
    let wire = build_authenticated_punch_ack(sent.nonce, "peer-b", "peer-a", 0, &key);
    assert!(decode_authenticated_punch_packet(
        &wire,
        &crate::peer::hard_hard_scoped_probe_key(
            &fixture.peers.probe_key_for_peer("peer-b").await.unwrap(),
            "other-token"
        )
    )
    .is_none());
    let ack = decode_authenticated_punch_packet(&wire, &key).unwrap();
    let wrong = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let session = fixture
        .peers
        .peer_session_generation_sync("peer-b")
        .unwrap();
    fixture
        .udp
        .handle_hard_hard_pair_packet(
            "peer-b",
            TOKEN,
            &ack,
            &key,
            session,
            Some("hh2-probe-session"),
            fixture.indices[0],
            &fixture.sockets[0],
            wrong.local_addr().unwrap(),
        )
        .await;
    assert!(fixture
        .udp
        .pending_probes
        .lock()
        .await
        .contains_key(&sent.nonce));
    assert!(
        !fixture
            .peers
            .hard_hard_pair_is_prepared("peer-b", TOKEN)
            .await
    );
    fixture
        .udp
        .handle_hard_hard_pair_packet(
            "peer-b",
            TOKEN,
            &ack,
            &key,
            session,
            Some("hh2-probe-session"),
            fixture.indices[0],
            &fixture.sockets[0],
            fixture.remote.local_addr().unwrap(),
        )
        .await;
    assert!(!fixture
        .udp
        .pending_probes
        .lock()
        .await
        .contains_key(&sent.nonce));
    let stats = fixture
        .udp
        .probe_rx_snapshot_for_peer_session("peer-b", 0, Some("hh2-probe-session"))
        .await;
    assert_eq!(stats.probe_acks_received, 1);
    assert_eq!(
        fixture
            .udp
            .probe_rx_snapshot_for_peer_session("peer-b", 0, None)
            .await
            .probe_acks_received,
        0
    );
    // A connectivity ACK prepares a pair but cannot itself confirm nomination.
    assert_eq!(
        fixture
            .peers
            .hard_hard_pair_validation_target("peer-b")
            .await,
        Some(None)
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_retired_detached_arc_never_accepts_legacy_or_validation() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let retained = fixture.sockets[0].clone();
    assert!(
        fixture
            .peers
            .hard_hard_retire_session("peer-b", "winner-cleanup-session", TOKEN)
            .await
    );
    fixture
        .udp
        .detach_hard_hard_sockets_for_token("peer-b", TOKEN, None, "hh2_retired_test")
        .await;
    assert!(
        retained.local_addr().is_ok(),
        "the exact Arc remains usable by the OS"
    );
    assert!(
        !fixture
            .udp
            .permits_legacy_punch_on_socket(fixture.indices[0])
            .await
    );
    assert!(
        !fixture
            .udp
            .permits_ordinary_send_on_socket("peer-b", fixture.indices[0], &retained)
            .await
    );
    assert!(
        !fixture
            .udp
            .hard_hard_validation_scope_is_current("peer-b", &scope)
            .await
    );
    assert!(
        fixture.udp.permits_legacy_punch_on_socket(0).await,
        "legacy primary compatibility is unchanged"
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_validation_syscall_rechecks_cancel_after_permission_snapshot() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let cancellation = fixture
        .peers
        .hard_hard_session_by_token("peer-b", TOKEN)
        .await
        .unwrap()
        .cancellation;
    let gate = Arc::new(
        super::super::super::hard_hard_pair_validation::HardHardValidationSendGate::default(),
    );
    *fixture.udp.hh2_validation_send_gate.lock().await = Some(gate.clone());
    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![0; 85],
        is_business: false,
    };
    let udp = fixture.udp.clone();
    let socket = fixture.sockets[0].clone();
    let send = tokio::spawn(async move {
        udp.send_direct_validation_packet_on_socket(
            &socket,
            scope.pair.socket_index,
            &packet,
            scope.pair.remote_endpoint,
        )
        .await
    });
    timeout(Duration::from_secs(1), gate.reached.notified())
        .await
        .unwrap();
    cancellation.cancel_for_hard_hard_cleanup();
    gate.release.notify_one();
    let error = send.await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("hh2 validation socket revoked"),
        "{error}"
    );
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_probe_ack_syscall_rechecks_exact_socket_and_cancellation() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let wrong_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    assert!(fixture
        .udp
        .send_hh2_probe_ack(
            &epoch,
            "peer-b",
            TOKEN,
            &scope.pair,
            &wrong_socket,
            b"ack",
            false,
        )
        .await
        .is_err());
    drop(epoch);
    let cancellation = fixture
        .peers
        .hard_hard_session_by_token("peer-b", TOKEN)
        .await
        .unwrap()
        .cancellation;
    let gate = Arc::new(
        super::super::super::hard_hard_pair_validation::HardHardValidationSendGate::default(),
    );
    *fixture.udp.hh2_probe_ack_send_gate.lock().await = Some(gate.clone());
    // Prime OS readiness before freezing time. The explicit gate, not a
    // scheduler delay, establishes cancellation after permission capture.
    fixture.sockets[0].writable().await.unwrap();
    tokio::time::pause();
    let udp = fixture.udp.clone();
    let socket = fixture.sockets[0].clone();
    let send = tokio::spawn(async move {
        let epoch = udp.network_epoch_gate.lock().await;
        udp.send_hh2_probe_ack(&epoch, "peer-b", TOKEN, &scope.pair, &socket, b"ack", false)
            .await
    });
    gate.reached.notified().await;
    cancellation.cancel_for_hard_hard_cleanup();
    gate.release.notify_one();
    assert_eq!(
        send.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    tokio::time::resume();
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_probe_ack_syscall_rechecks_original_action_deadline() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    let deadline = fixture
        .peers
        .hard_hard_pair_send_deadline("peer-b", TOKEN, &scope.pair, false)
        .await
        .unwrap();
    let gate = Arc::new(
        super::super::super::hard_hard_pair_validation::HardHardValidationSendGate::default(),
    );
    *fixture.udp.hh2_probe_ack_send_gate.lock().await = Some(gate.clone());
    fixture.sockets[0].writable().await.unwrap();
    tokio::time::pause();
    tokio::time::advance((deadline - tokio::time::Instant::now()) - Duration::from_millis(1)).await;
    let udp = fixture.udp.clone();
    let socket = fixture.sockets[0].clone();
    let send = tokio::spawn(async move {
        let epoch = udp.network_epoch_gate.lock().await;
        udp.send_hh2_probe_ack(&epoch, "peer-b", TOKEN, &scope.pair, &socket, b"ack", false)
            .await
    });
    gate.reached.notified().await;
    // Exceed the original phase deadline while remaining inside the ACK's
    // separate 25ms lock/IO bound: rejection must happen at final handoff.
    tokio::time::advance(Duration::from_millis(2)).await;
    gate.release.notify_one();
    assert_eq!(
        send.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    tokio::time::resume();
    let mut bytes = [0; 128];
    assert_eq!(
        fixture.remote.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn hard_hard_hh2_prepare_bounds_scope_preflight_connection_contention() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    assert!(
        fixture
            .udp
            .mark_hh2_data_validated("peer-b", Some(&scope))
            .await
    );
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    let connections = fixture.peers.hold_connections_writer_for_test().await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    assert!(fixture
        .udp
        .prepare_hh2_direct_commit(&epoch, "peer-b", Some(&scope))
        .await
        .is_err());
    assert!(started.elapsed() <= Duration::from_millis(100));
    drop(connections);
    drop(epoch);
    tokio::time::resume();
    assert!(!fixture.peers.is_direct_sync("peer-b"));
    fixture.cleanup().await;
}

struct MirrorCheckedCommit<'a> {
    inner: super::super::super::hard_hard_pair_commit::HardHardDirectCommit<'a>,
    fixture: &'a WinnerFixture,
    finished: bool,
}

impl DirectCommitHooks for MirrorCheckedCommit<'_> {
    fn is_current(&self) -> bool {
        self.inner.is_current()
    }
    fn committed(&mut self) {
        self.inner.committed();
        assert!(
            self.fixture.udp.socket_state.try_lock().is_err(),
            "cleanup must remain fenced inside the reducer closure"
        );
    }
    fn finish(&mut self) {
        assert!(
            self.fixture.peers.is_direct_sync("peer-b"),
            "Direct mirror must precede socket unlock"
        );
        assert!(self
            .fixture
            .peers
            .direct_commit_pair_snapshot_sync("peer-b")
            .is_some());
        assert!(self.fixture.udp.socket_state.try_lock().is_err());
        self.inner.finish();
        assert!(self.fixture.udp.socket_state.try_lock().is_ok());
        self.finished = true;
    }
}

#[tokio::test]
async fn hard_hard_hh2_direct_mirrors_precede_winner_unlock_and_stale_cleanup() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let fixture = WinnerFixture::with_protocol(true, true).await;
    let scope = confirmed(&fixture).await;
    assert!(
        fixture
            .udp
            .mark_hh2_data_validated("peer-b", Some(&scope))
            .await
    );
    let epoch = fixture.udp.network_epoch_gate.lock().await;
    assert!(
        fixture
            .peers
            .learn_authenticated_endpoint_in_epoch(&epoch, "peer-b", scope.pair.remote_endpoint)
            .await
    );
    fixture
        .peers
        .record_direct_probe_success_with_local_endpoint(
            "peer-b",
            scope.pair.remote_endpoint,
            Some(scope.pair.local_endpoint),
        )
        .await;
    let remote_epoch = fixture
        .peers
        .current_remote_candidate_epoch("peer-b")
        .await
        .unwrap();
    let inner = fixture
        .udp
        .prepare_hh2_direct_commit(&epoch, "peer-b", Some(&scope))
        .await
        .unwrap()
        .unwrap();
    let mut hooks = MirrorCheckedCommit {
        inner,
        fixture: &fixture,
        finished: false,
    };
    assert!(
        fixture
            .peers
            .record_direct_success_with_commit_hooks(
                &epoch,
                "peer-b",
                Some(scope.pair.remote_endpoint),
                scope.generation,
                Some(scope.pair.local_endpoint),
                Some(Duration::from_millis(1)),
                Some(remote_epoch),
                None,
                Some(&mut hooks)
            )
            .await
    );
    assert!(hooks.finished && hooks.inner.committed);
    drop(hooks);
    drop(epoch);
    fixture.assert_winner().await;
    let snapshot = fixture
        .peers
        .direct_commit_pair_snapshot_sync("peer-b")
        .unwrap();
    assert!(snapshot.path_revision.is_some());
    assert_eq!(snapshot.remote_endpoint, scope.pair.remote_endpoint);
    assert_eq!(snapshot.peer_session_generation, scope.peer_session);
    // Both pre-decrypt tuple admission and post-decrypt ordinary admission
    // use the synchronous exact projection even under connection contention.
    let connections = fixture.peers.hold_connections_writer_for_test().await;
    timeout(Duration::from_millis(100), async {
        assert!(
            fixture
                .udp
                .hh2_validation_pair_matches(
                    "peer-b",
                    scope.pair.socket_index,
                    scope.pair.remote_endpoint
                )
                .await
        );
        assert!(
            fixture
                .udp
                .permits_hh2_encrypted_ingress(
                    "peer-b",
                    scope.pair.socket_index,
                    scope.pair.remote_endpoint,
                    false
                )
                .await
        );
        let wrong_remote = "127.0.0.1:1".parse().unwrap();
        assert!(
            !fixture
                .udp
                .permits_hh2_encrypted_ingress(
                    "peer-b",
                    scope.pair.socket_index,
                    wrong_remote,
                    false
                )
                .await
        );
        let wrong_local = HardHardPairKey {
            local_endpoint: wrong_remote,
            ..scope.pair.clone()
        };
        assert!(!fixture.peers.hard_hard_committed_pair_is_current_sync(
            "peer-b",
            &wrong_local,
            scope.generation
        ));
    })
    .await
    .unwrap();
    drop(connections);
    // Model a cleanup descriptor that computed preserve=None before the ACK.
    assert!(
        fixture
            .peers
            .hard_hard_retire_session("peer-b", "winner-cleanup-session", TOKEN)
            .await
    );
    fixture
        .udp
        .detach_hard_hard_sockets_for_token("peer-b", TOKEN, None, "stale_discard_decision")
        .await;
    assert!(
        fixture
            .udp
            .permits_ordinary_send_on_socket("peer-b", scope.pair.socket_index, &fixture.sockets[0])
            .await
    );
    assert!(
        fixture
            .udp
            .hh2_validation_pair_matches(
                "peer-b",
                scope.pair.socket_index,
                scope.pair.remote_endpoint
            )
            .await
    );
    fixture.peers.remove_peer("peer-b").await;
    assert!(!fixture.peers.hard_hard_committed_pair_is_current_sync(
        "peer-b",
        &scope.pair,
        scope.generation
    ));
    fixture.cleanup().await;
}
