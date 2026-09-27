use super::*;

const PEER: &str = "admission-peer";

async fn fixture() -> (
    Arc<PeerManager>,
    UdpTransport,
    Arc<GlobalOutboundProbeBudget>,
    crate::peer::RecoveryEpochIdentity,
) {
    let peers = peer_manager();
    peers.add_peer(&peer(PEER, "10.20.0.9", None)).await;
    let crate::peer::RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(PEER).await
    else {
        panic!("fixture must own a live recovery epoch");
    };
    let reservation = peers
        .try_begin_hard_hard_generation_for_epoch(PEER, epoch)
        .await
        .unwrap();
    let identity = reservation.identity();
    reservation.commit();
    let global = Arc::new(GlobalOutboundProbeBudget::new());
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_global_probe_budget(global.clone());
    (peers, udp, global, identity)
}

async fn remaining(peers: &PeerManager) -> u32 {
    peers.recovery_epoch_budget_report(PEER).await.unwrap().1
}

#[tokio::test]
async fn rejected_exact_recovery_gate_never_debits_global_or_local_budget() {
    let (peers, udp, global, identity) = fixture().await;
    let endpoint = "203.0.113.8:41000".parse().unwrap();
    let purpose = crate::peer::RecoveryProbePurpose::HardHardExploration;
    let stale = identity;
    peers
        .recovery_epoch_end(PEER, "replace fixture allocation")
        .await;
    let crate::peer::RecoveryAdmission::Accepted { epoch } = peers.recovery_epoch_admit(PEER).await
    else {
        panic!("replacement recovery allocation must be admitted");
    };
    let replacement = peers
        .try_begin_hard_hard_generation_for_epoch(PEER, epoch)
        .await
        .unwrap();
    let identity = replacement.identity();
    replacement.commit();
    assert_ne!(stale, identity);
    assert_eq!(
        udp.admit_connectivity_probe_for_purpose(PEER, endpoint, 0, purpose, Some(stale))
            .await,
        OutboundProbeAdmission::RecoveryIdentityStale,
    );
    assert_eq!(
        remaining(&peers).await,
        crate::peer::RECOVERY_EPOCH_PROBE_CREDIT
    );

    for _ in purpose.confirmation_credit_reserve()..crate::peer::RECOVERY_EPOCH_PROBE_CREDIT {
        assert!(peers.try_consume_recovery_probe_credit(PEER).await);
    }
    assert_eq!(
        udp.admit_connectivity_probe_for_purpose(PEER, endpoint, 0, purpose, Some(identity))
            .await,
        OutboundProbeAdmission::HardHardRecoveryConfirmationReserved,
    );
    assert_eq!(
        remaining(&peers).await,
        purpose.confirmation_credit_reserve()
    );
    while peers.try_consume_recovery_probe_credit(PEER).await {}
    assert_eq!(
        udp.admit_connectivity_probe_for_purpose(PEER, endpoint, 0, purpose, Some(identity))
            .await,
        OutboundProbeAdmission::EpochCreditExhausted,
    );
    assert!(global.state.lock().await.is_empty());
    assert!(udp.outbound_probe_budget.lock().await.is_empty());
}

#[tokio::test(start_paused = true)]
async fn budget_lock_contention_shares_one_deadline_and_releases_all_guards() {
    let (peers, udp, global, identity) = fixture().await;
    let reached = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let holder = {
        let peers = peers.clone();
        let reached = reached.clone();
        let release = release.clone();
        tokio::spawn(async move {
            peers
                .hold_recovery_epoch_write_for_test(reached, release)
                .await;
        })
    };
    reached.notified().await;
    let global_guard = global.state.lock().await;
    let mut admission = Box::pin(udp.admit_connectivity_probe_for_purpose(
        PEER,
        "203.0.113.8:41000".parse().unwrap(),
        0,
        crate::peer::RecoveryProbePurpose::HardHardExploration,
        Some(identity),
    ));
    assert!(futures_util::poll!(&mut admission).is_pending());
    assert!(udp.outbound_probe_budget.try_lock().is_err());
    tokio::time::advance(Duration::from_millis(60)).await;
    drop(global_guard);
    assert!(futures_util::poll!(&mut admission).is_pending());
    assert!(global.state.try_lock().is_err());
    tokio::time::advance(Duration::from_millis(40)).await;
    assert_eq!(admission.await, OutboundProbeAdmission::AdmissionDeferred);
    assert!(global.state.try_lock().unwrap().is_empty());
    assert!(udp.outbound_probe_budget.try_lock().unwrap().is_empty());
    release.notify_one();
    holder.await.unwrap();
    assert_eq!(
        remaining(&peers).await,
        crate::peer::RECOVERY_EPOCH_PROBE_CREDIT
    );
}

#[tokio::test(start_paused = true)]
async fn cancelled_recovery_wait_keeps_all_credits_and_next_admission_commits_once() {
    let (peers, udp, global, identity) = fixture().await;
    let reached = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let holder = {
        let peers = peers.clone();
        let reached = reached.clone();
        let release = release.clone();
        tokio::spawn(async move {
            peers
                .hold_recovery_epoch_write_for_test(reached, release)
                .await;
        })
    };
    reached.notified().await;
    let endpoint = "203.0.113.8:41000".parse().unwrap();
    let purpose = crate::peer::RecoveryProbePurpose::HardHardExploration;
    let mut admission = Box::pin(udp.admit_connectivity_probe_for_purpose(
        PEER,
        endpoint,
        0,
        purpose,
        Some(identity),
    ));
    assert!(futures_util::poll!(&mut admission).is_pending());
    assert!(global.state.try_lock().is_err());
    drop(admission);
    assert!(global.state.try_lock().unwrap().is_empty());
    assert!(udp.outbound_probe_budget.try_lock().unwrap().is_empty());
    release.notify_one();
    holder.await.unwrap();
    assert_eq!(
        remaining(&peers).await,
        crate::peer::RECOVERY_EPOCH_PROBE_CREDIT
    );
    assert_eq!(
        udp.admit_connectivity_probe_for_purpose(PEER, endpoint, 0, purpose, Some(identity))
            .await,
        OutboundProbeAdmission::Accepted,
    );
    assert_eq!(
        remaining(&peers).await,
        crate::peer::RECOVERY_EPOCH_PROBE_CREDIT - 1
    );
    let state = global.state.lock().await;
    assert_eq!(state.len(), 9);
    assert!(state.values().all(|entries| entries.len() == 1));
    let local = udp.outbound_probe_budget.lock().await;
    assert_eq!(local.len(), 3);
    assert!(local.values().all(|entries| entries.len() == 1));
}

#[tokio::test]
async fn global_rejection_does_not_consume_recovery_credit() {
    let (peers, udp, global, identity) = fixture().await;
    global.state.lock().await.insert(
        OutboundProbeBudgetKey::NetworkPersistent,
        std::iter::repeat_n(
            Instant::now(),
            probe_budget::OUTBOUND_PROBE_PERSISTENT_PER_NETWORK,
        )
        .collect(),
    );
    assert_eq!(
        udp.admit_connectivity_probe_for_purpose(
            PEER,
            "203.0.113.8:41000".parse().unwrap(),
            0,
            crate::peer::RecoveryProbePurpose::HardHardExploration,
            Some(identity),
        )
        .await,
        OutboundProbeAdmission::GlobalNetworkPersistentRateLimited,
    );
    assert_eq!(
        remaining(&peers).await,
        crate::peer::RECOVERY_EPOCH_PROBE_CREDIT
    );
    assert!(udp.outbound_probe_budget.lock().await.is_empty());
}

#[tokio::test]
async fn dynamic_sweep_stops_at_first_exhausted_allocation_without_visiting_next_wave() {
    let (peers, udp, global, _) = fixture().await;
    while peers.try_consume_recovery_probe_credit(PEER).await {}
    let targets = (41000..41008)
        .map(|port| SocketAddr::from(([203, 0, 113, 8], port)))
        .collect();
    let pacing = Arc::new(HardHardProbePacer::new());
    // The resolved entry is deliberately reached with the primary socket:
    // exhausted admission must stop before any build or physical send.
    let report = udp
        .punch_candidates_from_dynamic_socket_resolved(
            PEER,
            0,
            udp.socket.clone(),
            targets,
            Duration::ZERO,
            2,
            None,
            None,
            None,
            Some(pacing.clone()),
        )
        .await
        .unwrap();
    let stop = probe_budget::OutboundProbeSweepStop::EpochCreditExhausted;
    assert_eq!(report.sweep_budget_stop, Some(stop));
    assert_eq!(pacing.stop_reason(), Some(stop));
    assert_eq!(report.targets_examined, 1);
    assert_eq!(report.targets_attempted, 1);
    assert_eq!(report.budget_skipped, 1);
    assert_eq!(report.logical_probes_attempted, 0);
    assert_eq!(report.physical_datagrams_sent, 0);
    assert!(report.epoch_budget_exhausted);
    assert!(!report.target_processing_completed);
    assert!(!report.pacing_deadline_reached);
    assert!(global.state.lock().await.is_empty());
    assert!(udp.outbound_probe_budget.lock().await.is_empty());
}
