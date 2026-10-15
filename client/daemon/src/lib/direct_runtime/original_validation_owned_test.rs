// Only fixture cancellation/join visibility. No validation permission, owner
// replacement, production JoinError policy or current state is added here.
async fn run_original_validation_scheduler_until_joined_for_test(
    observations: DirectValidationIngress,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::result::Result<(), String> {
    let mut workers = tokio::task::JoinSet::new();
    {
        let scheduler = run_direct_validation_scheduler_with_owned_workers(
            observations,
            udp.clone(),
            peers,
            transport,
            local_virtual_ip,
            new_direct_validation_worker_permits(),
            &mut workers,
        );
        tokio::pin!(scheduler);
        tokio::select! {
            _ = &mut scheduler => {},
            _ = async {
                while !*shutdown_rx.borrow_and_update() {
                    if shutdown_rx.changed().await.is_err() { break; }
                }
            } => {},
        }
    }
    udp.cancel_all_direct_validation_sessions().await;
    workers.abort_all();
    let mut failures = Vec::new();
    while let Some(joined) = workers.join_next().await {
        if let Err(error) = joined {
            if !error.is_cancelled() {
                failures.push(format!("original validation child join: {error}"));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
