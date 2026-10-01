#[tokio::test(start_paused = true)]
async fn gateway_cache_locks_share_one_deadline_and_timeout_cannot_commit_a_result() {
    let identity = crate::gateway_mapping::GatewayMappingIdentity {
        bind_endpoint: "0.0.0.0:51820".parse().unwrap(),
        local_endpoint: "192.168.1.7:51820".parse().unwrap(),
        gateway: Some("192.168.1.1".parse().unwrap()),
        network_generation: 4,
        transport_instance: 2,
        publication_owner: 3,
    };
    let runtime = RwLock::new(GatewayMappingRuntime::default());
    let diagnostics = RwLock::new(GatewayMappingDiagnostics::default());
    let mut held_runtime = runtime.write().await;
    held_runtime.bind_identity(identity);
    assert!(held_runtime.record_success(
        identity,
        "203.0.113.8:51820".into(),
        "upnp",
        Duration::from_secs(120),
    ));
    let held_diagnostics = diagnostics.write().await;
    let mut pending = Box::pin(async {
        let Some(mut commit) =
            lock_gateway_mapping_commit(&runtime, &diagnostics, "discovery_result").await
        else {
            return false;
        };
        commit.diagnostics.candidate_endpoint = Some("203.0.113.9:51820".into());
        commit
            .runtime
            .record_failure(identity, Duration::from_secs(60))
    });
    assert!(futures_util::poll!(&mut pending).is_pending());
    tokio::time::advance(Duration::from_millis(80)).await;
    drop(held_runtime);
    assert!(futures_util::poll!(&mut pending).is_pending());
    assert!(
        runtime.try_write().is_err(),
        "runtime is held while diagnostics waits"
    );

    // The second lock gets only the remainder of the original 100ms budget,
    // not another full timeout. Its permanent holder must not pin the cache.
    tokio::time::advance(Duration::from_millis(20)).await;
    assert!(!pending.await);
    let current = runtime
        .try_write()
        .expect("timeout releases the first guard");
    assert_eq!(
        current.candidate_endpoint.as_deref(),
        Some("203.0.113.8:51820")
    );
    assert!(
        current.retry_at.is_none(),
        "timed-out result cannot install backoff"
    );
    assert!(held_diagnostics.candidate_endpoint.is_none());
}

#[tokio::test(start_paused = true)]
async fn cancellation_while_waiting_for_gateway_diagnostics_releases_the_cache() {
    let runtime = RwLock::new(GatewayMappingRuntime::default());
    let diagnostics = RwLock::new(GatewayMappingDiagnostics::default());
    let held_diagnostics = diagnostics.write().await;
    let mut pending = Box::pin(lock_gateway_mapping_commit(
        &runtime,
        &diagnostics,
        "cache_lookup",
    ));
    assert!(futures_util::poll!(&mut pending).is_pending());
    assert!(runtime.try_write().is_err());
    drop(pending);
    assert!(
        runtime.try_write().is_ok(),
        "cancelled commit releases the cache guard"
    );
    drop(held_diagnostics);
    assert!(
        lock_gateway_mapping_commit(&runtime, &diagnostics, "cache_lookup")
            .await
            .is_some()
    );
}
