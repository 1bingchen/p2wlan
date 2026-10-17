use super::*;
use std::sync::Condvar;

#[derive(Default)]
struct EarlyProbeGate {
    token: StdMutex<Option<String>>,
    response_queued: Notify,
    winner_observed: StdMutex<bool>,
    winner_ready: Condvar,
    responder_resumed_after_winner: AtomicBool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_early_one_way_probe_before_responder_scatter_stays_on_relay() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    set_hard_hard_test_now_ms(Some(hard_hard_now_for_test()));
    let _clock = HardHardClockReset;
    let mut harness = build_two_peer_harness(true, false, false).await;
    harness.link.set_drop_b_to_a(true);
    let deadline = tokio::time::Instant::now() + HARD_HARD_E2E_TIMEOUT;
    let gate = Arc::new(EarlyProbeGate::default());
    let observer = tokio::spawn({
        let gate = gate.clone();
        let peers = harness.peers_b.clone();
        async move {
            let observed = tokio::time::timeout_at(deadline, async {
                gate.response_queued.notified().await;
                let token = gate.token.lock().unwrap().clone().unwrap();
                loop {
                    if peers
                        .hard_hard_winner_for_token(HARD_HARD_A, &token)
                        .await
                        .is_some()
                    {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
            if observed {
                *gate.winner_observed.lock().unwrap() = true;
                gate.winner_ready.notify_one();
            }
        }
    });
    harness.udp_tasks.push(observer);
    *harness.signal_post_hook_b_to_a.lock().unwrap() = Some(Arc::new({
        let gate = gate.clone();
        move |signal: &TestControlSignal| {
            let Some(encoded) = signal
                .session_id
                .as_deref()
                .filter(|s| s.starts_with("hh1:r:"))
            else {
                return;
            };
            let coordination = HardHardCoordination::parse(encoded).unwrap();
            assert!(gate
                .token
                .lock()
                .unwrap()
                .replace(coordination.token)
                .is_none());
            gate.response_queued.notify_one();
            // This is after the REAL response has entered A's control queue.
            // Pause this publisher until real UDP ingress selects B's winner;
            // no test helper promotes a socket or commits Direct.
            let observed = tokio::task::block_in_place(|| {
                let observed = gate.winner_observed.lock().unwrap();
                let remaining = deadline
                    .into_std()
                    .saturating_duration_since(std::time::Instant::now());
                let (observed, _) = gate
                    .winner_ready
                    .wait_timeout_while(observed, remaining, |ready| !*ready)
                    .unwrap();
                *observed
            });
            gate.responder_resumed_after_winner
                .store(observed, Ordering::Release);
        }
    }));
    trigger_hard_hard_protocol_attempt(&harness).await;
    let (a, b) = tokio::time::timeout_at(deadline, async {
        tokio::join!(
            wait_for_hard_hard_attempt_report(&harness.peers_a, HARD_HARD_B),
            wait_for_hard_hard_attempt_report(&harness.peers_b, HARD_HARD_A),
        )
    })
    .await
    .expect("early-probe reports must meet the original evidence deadline");
    assert!(gate.responder_resumed_after_winner.load(Ordering::Acquire));
    assert_eq!(b.role, "responder");
    assert!(a.counts.logical_probes_attempted > 0, "{a:?}");
    assert!(a.counts.send_success_datagrams > 0, "{a:?}");
    assert!(b.authenticated_probe_packets_received > 0, "{b:?}");
    assert_eq!(b.counts.logical_probes_attempted, 0, "{b:?}");
    assert_eq!(b.counts.send_success_datagrams, 0, "{b:?}");
    assert_eq!(b.failure_class, "probe_hit_validation_failed", "{b:?}");
    for report in [&a, &b] {
        assert!(!report.direct_confirmed, "{report:?}");
        assert_eq!(
            report.terminal_reason, "no_authenticated_direct_confirmation",
            "{report:?}"
        );
    }
    harness.link.set_drop_a_to_b(true);
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);
    assert_relay_remains_available(&harness).await;
    wait_for_failed_attempt_cleanup(&harness).await;
    harness.shutdown().await;
}
