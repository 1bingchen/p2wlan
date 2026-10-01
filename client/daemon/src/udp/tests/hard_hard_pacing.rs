use super::*;

async fn preload_short_budget(transport: &UdpTransport, age: Duration) {
    let sent_at = Instant::now() - age;
    transport.outbound_probe_budget.lock().await.insert(
        OutboundProbeBudgetKey::PeerRemoteIp("peer-b".into(), Ipv4Addr::LOCALHOST.into()),
        std::iter::repeat_n(sent_at, OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP).collect(),
    );
}

#[tokio::test]
async fn hard_hard_pacing_preserves_targets_across_short_budget_contention() {
    let (_peers, transport, _nat, index) = exact_send_report_fixture().await;
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    preload_short_budget(&transport, Duration::from_millis(800)).await;
    let report = transport
        .punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session_and_live(
            "peer-b",
            index,
            vec![sink.local_addr().unwrap()],
            Duration::ZERO,
            1,
            None,
            None,
            None,
            Some(Arc::new(HardHardProbePacer::new())),
        )
        .await
        .unwrap();
    assert_eq!(report.logical_probes_sent, 1);
    assert_eq!(
        report.targets_examined, 1,
        "retries must not inflate target counts"
    );
    assert_eq!(report.targets_attempted, 1);
    assert_eq!(report.budget_skipped, 0);
    assert!(!report.pacing_deadline_reached);
    let mut bytes = [0; 2048];
    assert!(timeout(Duration::from_secs(1), sink.recv_from(&mut bytes))
        .await
        .is_ok());
}

#[tokio::test]
async fn hard_hard_pacing_rechecks_generation_after_budget_wait() {
    let (peers, transport, _nat, index) = exact_send_report_fixture().await;
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    preload_short_budget(&transport, Duration::ZERO).await;
    let live = Arc::new(StdMutex::new(LiveBirthdayProgress::default()));
    let work = {
        let transport = transport.clone();
        let live = live.clone();
        let target = sink.local_addr().unwrap();
        tokio::spawn(async move {
            transport
                .punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session_and_live(
                    "peer-b",
                    index,
                    vec![target],
                    Duration::ZERO,
                    1,
                    None,
                    None,
                    Some(live),
                    Some(Arc::new(HardHardProbePacer::new())),
                )
                .await
                .unwrap()
        })
    };
    timeout(Duration::from_secs(1), async {
        while live.lock().unwrap().counters.targets_attempted == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    peers
        .advance_network_generation("pacing wait network change")
        .await;
    let report = timeout(Duration::from_secs(1), work)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.logical_probes_sent, 0);
    assert_eq!(
        report.failure_kind,
        Some(BirthdaySweepFailureKind::NetworkGenerationChanged)
    );
    assert_eq!(report.targets_examined, 1);
    let mut bytes = [0; 2048];
    assert!(sink.try_recv_from(&mut bytes).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_pacing_shared_workers_complete_beyond_one_rate_window() {
    let (_peers, transport, _nat, index) = exact_send_report_fixture().await;
    let mut sinks = Vec::new();
    let mut targets = Vec::new();
    for _ in 0..256 {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        targets.push(sink.local_addr().unwrap());
        sinks.push(sink);
    }
    let pacing = Arc::new(HardHardProbePacer::new());
    let mut workers = JoinSet::new();
    for targets in targets.chunks(64) {
        let targets = targets.to_vec();
        let transport = transport.clone();
        let pacing = pacing.clone();
        workers.spawn(async move {
            transport
                .punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session_and_live(
                    "peer-b",
                    index,
                    targets,
                    Duration::ZERO,
                    1,
                    None,
                    None,
                    None,
                    Some(pacing),
                )
                .await
                .unwrap()
        });
    }
    let mut sent = 0;
    while let Some(report) = workers.join_next().await {
        let report = report.unwrap();
        assert_eq!(report.logical_probes_sent, 64);
        assert_eq!(report.budget_skipped, 0);
        assert!(!report.pacing_deadline_reached);
        sent += report.logical_probes_sent;
    }
    assert_eq!(sent, 256);
    let mut bytes = [0; 2048];
    for sink in sinks {
        assert!(timeout(Duration::from_secs(1), sink.recv_from(&mut bytes))
            .await
            .is_ok());
    }
}
