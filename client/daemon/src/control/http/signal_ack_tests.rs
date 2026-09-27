use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn registration(
    base_url: &str,
) -> tokio::sync::watch::Sender<Option<super::super::CriticalControlAuth>> {
    tokio::sync::watch::channel(Some(super::super::CriticalControlAuth {
        accepted_peer_capabilities: super::super::PeerCapabilities::current(),
        base_url: base_url.to_string(),
        token: "ack-test-token".into(),
        self_node_id: "ack-test-node".into(),
        registration_seq: Some(41),
        signal_signing_identity: None,
    }))
    .0
}

async fn read_ack(stream: &mut TcpStream) -> (String, serde_json::Value) {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0u8; 2048];
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0, "ACK request ended before its JSON body");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            if bytes.len() >= end + 4 + length {
                return (
                    head,
                    serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap(),
                );
            }
        }
    }
}

fn delivery(id: &str, seq: u64, lease: &str) -> LeasedSignalDelivery {
    LeasedSignalDelivery {
        signal_id: id.into(),
        signal_seq: Some(seq),
        signal_type: "peer_offer".into(),
        from_node_id: "remote-peer".into(),
        ack: SignalAckRequest {
            id: id.into(),
            delivery_token: lease.into(),
        },
        ack_timing: SignalAckTiming::Ordinary,
        prepared: PreparedSignalDelivery::Apply(Box::new(ControlEvent::PeerOffer {
            from_node_id: "remote-peer".into(),
            candidates: vec![],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            candidate_generation: seq,
            candidates_expires_at_ms: None,
            handshake_init: vec![],
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: None,
        })),
    }
}

#[tokio::test]
async fn lost_ack_response_retries_same_delete_without_reapplying_or_overtaking() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let auth = registration(&base);
    let ack_registration = SignalAckRegistration::capture(
        &base,
        "ack-test-token",
        "ack-test-node",
        Some(41),
        auth.subscribe(),
    )
    .unwrap();
    let (requests_tx, mut requests_rx) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let mut deleted = HashSet::new();
        for attempt in 0..4 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (head, body) = read_ack(&mut stream).await;
            assert!(head
                .to_ascii_lowercase()
                .contains("x-p2wlan-registration-seq: 41"));
            deleted.insert(body["signals"][0]["id"].as_str().unwrap().to_string());
            requests_tx.send(body).unwrap();
            if attempt == 0 {
                // The DELETE committed; the response is lost. The second
                // identical request must be harmless even though no row remains.
                drop(stream);
                continue;
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                .await
                .unwrap();
        }
        deleted
    });
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    spawn_signal_application_lane(
        reqwest::Client::builder().no_proxy().build().unwrap(),
        base,
        "ack-test-token".into(),
        "ack-test-node".into(),
        ack_registration,
        events_tx,
        Arc::new(tokio::sync::Mutex::new(SignalDeliveryTracker::default())),
        vec![
            delivery("first", 1, "lease-1"),
            delivery("first", 1, "lease-2"),
            delivery("second", 2, "lease-3"),
        ],
    );
    let first = tokio::time::timeout(Duration::from_secs(3), events_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let ControlEvent::DeliveredSignal {
        signal_id, receipt, ..
    } = first
    else {
        panic!("expected application receipt")
    };
    assert_eq!(signal_id, "first");
    assert!(
        requests_rx.try_recv().is_err(),
        "application must precede ACK"
    );
    receipt.complete(SignalApplyOutcome::Applied);
    let second = tokio::time::timeout(Duration::from_secs(3), events_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let ControlEvent::DeliveredSignal {
        signal_id, receipt, ..
    } = second
    else {
        panic!("expected application receipt")
    };
    assert_eq!(signal_id, "second", "redelivery must never reapply first");
    let first_request = requests_rx.try_recv().unwrap();
    assert_eq!(
        requests_rx.try_recv().unwrap(),
        first_request,
        "retry keeps the exact lease token"
    );
    assert_eq!(
        requests_rx.try_recv().unwrap()["signals"][0]["delivery_token"],
        "lease-2"
    );
    receipt.complete(SignalApplyOutcome::Applied);
    let deleted = tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deleted.len(), 2);
    assert!(events_rx.try_recv().is_err());
}

#[tokio::test]
async fn ack_registration_revocation_fences_before_io_and_after_response() {
    let base = "http://127.0.0.1:1";
    let auth = registration(base);
    let mut fence = SignalAckRegistration::capture(
        base,
        "ack-test-token",
        "ack-test-node",
        Some(41),
        auth.subscribe(),
    )
    .unwrap();
    let result = fence
        .run(
            tokio::time::Instant::now() + Duration::from_secs(1),
            async {
                auth.send_replace(None);
                42
            },
        )
        .await;
    assert!(
        result.is_err(),
        "a response from a revoked registration cannot succeed"
    );
    let ran = std::sync::atomic::AtomicBool::new(false);
    let result = fence
        .run(
            tokio::time::Instant::now() + Duration::from_secs(1),
            async {
                ran.store(true, Ordering::SeqCst);
            },
        )
        .await;
    assert!(result.is_err());
    assert!(
        !ran.load(Ordering::SeqCst),
        "a revoked registration cannot start another I/O"
    );
}

#[tokio::test(start_paused = true)]
async fn ack_registration_change_interrupts_a_pending_response() {
    let base = "http://127.0.0.1:1";
    let auth = registration(base);
    let mut fence = SignalAckRegistration::capture(
        base,
        "ack-test-token",
        "ack-test-node",
        Some(41),
        auth.subscribe(),
    )
    .unwrap();
    let mut pending = Box::pin(fence.run(
        tokio::time::Instant::now() + Duration::from_secs(1),
        std::future::pending::<()>(),
    ));
    assert!(futures_util::poll!(&mut pending).is_pending());
    let mut changed = auth.borrow().as_ref().unwrap().clone();
    changed.token = "replacement-token-same-sequence".into();
    auth.send_replace(Some(changed));
    assert!(pending.await.is_err());
}

#[test]
fn ack_budgets_keep_original_phase_and_bound_expired_cleanup() {
    let now = tokio::time::Instant::now();
    let phase_end = now + Duration::from_millis(175);
    assert_eq!(
        SignalAckTiming::HardHard(phase_end).budget(now),
        (phase_end, HARD_HARD_ACK_ATTEMPT_TIMEOUT, 3)
    );
    assert_eq!(
        SignalAckTiming::HardHard(now).budget(now),
        (
            now + HARD_HARD_ACK_ATTEMPT_TIMEOUT,
            HARD_HARD_ACK_ATTEMPT_TIMEOUT,
            1
        )
    );
    let (deadline, _, attempts) = SignalAckTiming::Ordinary.budget(now);
    assert_eq!(deadline, now + SIGNAL_SEND_TIMEOUT);
    assert_eq!(attempts, 3);
    for status in [400, 401, 403, 404, 409, 422] {
        assert!(!signal_ack_status_retryable(
            reqwest::StatusCode::from_u16(status).unwrap()
        ));
    }
    for status in [408, 429, 500, 503] {
        assert!(signal_ack_status_retryable(
            reqwest::StatusCode::from_u16(status).unwrap()
        ));
    }
}
