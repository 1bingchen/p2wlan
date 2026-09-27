/// Exercise the production queue/receipt wiring while retaining the exact
/// response sender observed by the existing candidate worker.
fn pending_hard_hard_start_ack() -> (
    Arc<HardHardStartAckDelivery>,
    oneshot::Sender<PeerOfferSendOutcome>,
) {
    let mut client = ControlClient::disabled_for_test();
    let (candidate_tx, mut candidate_rx) = mpsc::channel(1);
    client.candidate_offer_tx = candidate_tx;
    let delivery = client
        .queue_hard_hard_start_ack(
            "peer",
            &["192.0.2.1:41000".to_string()],
            &HashMap::new(),
            1,
            1,
            "start-ack-receipt-test".to_string(),
            Arc::new(crate::PunchSessionCancellation::default()),
            Instant::now() + Duration::from_secs(1),
            1,
        )
        .expect("the bounded test queue must accept the ACK");
    let command = candidate_rx
        .try_recv()
        .expect("ACK must use candidate lane");
    (delivery, command.response_tx)
}

#[tokio::test]
async fn hard_hard_start_ack_last_owner_drop_closes_worker_response() {
    let (delivery, mut response_tx) = pending_hard_hard_start_ack();
    let snapshot = delivery.clone();
    assert!(!response_tx.is_closed());
    drop(delivery);
    assert!(
        !response_tx.is_closed(),
        "a live plan snapshot retains delivery"
    );
    drop(snapshot);
    assert!(
        response_tx.is_closed(),
        "the final owner must revoke delivery"
    );
    // This is the same cancellation future selected by the candidate worker.
    response_tx.closed().await;
}

#[tokio::test]
async fn hard_hard_start_ack_pending_and_failed_are_not_server_acceptance() {
    for outcome in [
        PeerOfferSendOutcome::Failed,
        PeerOfferSendOutcome::Cancelled,
    ] {
        let (delivery, response_tx) = pending_hard_hard_start_ack();
        assert!(!delivery.server_accepted());
        assert!(
            !response_tx.is_closed(),
            "polling pending must retain its receiver"
        );
        assert!(!delivery.server_accepted());
        response_tx.send(outcome).unwrap();
        assert!(!delivery.server_accepted());
        assert!(
            !delivery.server_accepted(),
            "failure cannot become accepted later"
        );
    }
}

#[tokio::test]
async fn hard_hard_start_ack_closed_lane_is_not_server_acceptance() {
    let (delivery, response_tx) = pending_hard_hard_start_ack();
    drop(response_tx);
    assert!(!delivery.server_accepted());
    assert!(!delivery.server_accepted());
}

#[tokio::test]
async fn hard_hard_start_ack_success_is_cached_across_plan_snapshots() {
    let (delivery, response_tx) = pending_hard_hard_start_ack();
    let snapshot = delivery.clone();
    assert!(!delivery.server_accepted());
    response_tx.send(PeerOfferSendOutcome::Sent).unwrap();
    assert!(delivery.server_accepted());
    // The oneshot has been consumed, so the second snapshot must see the
    // cached server result rather than downgrade it to a closed channel.
    drop(delivery);
    assert!(snapshot.server_accepted());
    assert!(snapshot.server_accepted());
}
