//! Authorized Rust network hint and actual supervisor socket/native recovery.
//! Initial route/STUN/HTTP work is suspended; this is a local LAN slice.
use super::*;
use crate::overlay_requests::OverlayCreditStale;

fn context(
    endpoint: &Endpoint,
    publication: UdpTransportPublication,
    observation: Arc<C01UdpOwnersForTest>,
    shutdown_rx: watch::Receiver<bool>,
    network_rx: tokio::sync::broadcast::Receiver<AndroidNetworkChangeHint>,
) -> Result<UdpDirectTaskContext, String> {
    Ok(UdpDirectTaskContext {
        udp_bind: "127.0.0.1:0"
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?,
        fresh_mapping_harness_loopback: true,
        peers: endpoint.peers.clone(),
        control: ControlClient::disabled_for_test(),
        local_candidates: Arc::new(RwLock::new(Vec::new())),
        local_candidate_sources: Arc::new(RwLock::new(HashMap::new())),
        local_network_identity: Arc::new(RwLock::new(Vec::new())),
        candidate_snapshot: Arc::new(RwLock::new(None)),
        candidate_refresh_lock: Arc::new(Mutex::new(())),
        nat_profile: Arc::new(RwLock::new(None)),
        gateway_mapping_runtime: Arc::new(RwLock::new(GatewayMappingRuntime::default())),
        gateway_mapping_diagnostics: Arc::new(RwLock::new(GatewayMappingDiagnostics::default())),
        udp_transport_publication: publication,
        direct_validation_transport: endpoint.wireguard.clone(),
        direct_validation_local_ip: endpoint.vip.into(),
        udp_inbound_tx: endpoint
            .supervisor_encrypted_input
            .as_ref()
            .ok_or("supervised original WG ingress sender missing")?
            .clone(),
        local_node_id: endpoint.node.into(),
        stun_servers: Vec::new(),
        stun_server_specs: vec!["off".into()],
        udp_observer_specs: Vec::new(),
        runtime_stun_servers: Arc::new(RwLock::new(Vec::new())),
        stun_timeout: Duration::from_millis(10),
        udp_advertise: None,
        upnp_enabled: false,
        socket_pool_enabled: false,
        socket_pool_size: 1,
        keepalive_interval: Duration::ZERO,
        punch_deduplicator: PunchAttemptDeduplicator::default(),
        udp_punch_interval: Duration::from_millis(10),
        udp_punch_attempts: 1,
        boot_epoch_ms: 0,
        proxy_env: crate::netenv::ProxyEnvironment::default(),
        excluded_interfaces: Vec::new(),
        shutdown_rx,
        android_network_change_rx: Some(Arc::new(Mutex::new(network_rx))),
        android_network_change_observed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        original_owners_for_test: Some(observation),
    })
}

async fn publication_after(
    updates: &mut watch::Receiver<Option<UdpTransport>>,
    previous: Option<u64>,
    budget: Budget,
) -> Result<UdpTransport, String> {
    budget
        .step("actual original supervisor publication", async {
            loop {
                let current = updates.borrow_and_update().clone();
                if let Some(udp) = current {
                    if previous != Some(udp.transport_instance_id()) {
                        return Ok(udp);
                    }
                }
                updates
                    .changed()
                    .await
                    .map_err(|_| "original UDP publication closed".to_string())?;
            }
        })
        .await?
}

fn retain_actual_socket_observations(
    udp: &UdpTransport,
    index: usize,
    ports: &mut [Option<SocketAddr>; 6],
    ipv6: &mut [Option<std::sync::Weak<UdpSocket>>; 3],
) -> Check {
    ports[index * 2] = Some(udp.local_addr().map_err(|e| e.to_string())?);
    if let Some(socket) = udp.ipv6_socket() {
        ports[index * 2 + 1] = Some(socket.local_addr().map_err(|e| e.to_string())?);
        ipv6[index] = Some(Arc::downgrade(&socket));
    }
    Ok(())
}

pub(in super::super) async fn exercise_network_change() -> Check {
    let budget = Budget::new();
    let mut owners = Owners::default();
    let original = Arc::new(C01UdpOwnersForTest::default());
    let mut ports = [None; 6];
    let mut ipv6 = std::array::from_fn(|_| None);
    let mut hint_to_fresh = None;
    let body = AssertUnwindSafe(tokio::time::timeout_at(budget.body_end(), async {
        let mut a =
            Endpoint::create_supervised(NODE_A, VIP_A, NODE_B, VIP_B, &mut owners, budget).await?;
        let publication = a
            .supervisor_publication
            .as_ref()
            .ok_or("same authoritative supervisor publication missing")?
            .clone();
        let mut updates = publication.subscribe();
        let (stop, stopped) = watch::channel(false);
        owners.readers_stop.push(stop);
        let (network_tx, network_rx) = tokio::sync::broadcast::channel(8);
        let ctx = context(
            &a,
            publication.clone(),
            original.clone(),
            stopped,
            network_rx,
        )?;
        owners.spawn_graceful("actual original UDP hint supervisor", async move {
            run_udp_direct_task_with_binder(ctx, |bind, peers| async move {
                Ok(UdpDirectBinding {
                    udp: UdpTransport::bind(bind, peers).await?,
                    route_signature: Vec::new(),
                })
            })
            .await
            .map_err(|e| e.to_string())
        });
        let mut old_udp = Some(publication_after(&mut updates, None, budget).await?);
        let old = old_udp.as_ref().unwrap();
        retain_actual_socket_observations(old, 0, &mut ports, &mut ipv6)?;
        let old_instance = old.transport_instance_id();
        let old_owner = old.inbound_publication_owner();
        let old_generation = a.peers.current_network_generation_sync();
        let mut b = Endpoint::create(
            NODE_B,
            VIP_B,
            NODE_A,
            VIP_A,
            PathKind::Direct,
            None,
            &mut owners,
            budget,
            false,
        )
        .await?;
        let b_udp = budget
            .step("borrow actual remote UDP", b.udp.read())
            .await?
            .as_ref()
            .cloned()
            .ok_or("actual remote UDP missing")?;
        retain_actual_socket_observations(&b_udp, 2, &mut ports, &mut ipv6)?;
        drop(b_udp);
        lifecycle::readmit_actual_pair(&a, &b, PathKind::Direct, budget).await?;
        let (old_request, _, old_ack) =
            original_request_and_echo(&mut a, &mut b, PathKind::Direct, budget).await?;
        qualify_actual_path(&a, &old_request, &old_ack, PathKind::Direct)?;
        require(
            !old_request.native_ack_credited_for_test() && a.stats.verified_round_trips == 0,
            "old actual ACK was credited before physical handover",
        )?;

        let started = tokio::time::Instant::now();
        network_tx
            .send(AndroidNetworkChangeHint {
                kotlin_network_generation: 2,
                network_identity_hash: "c01-local-authorized-network-edge".into(),
            })
            .map_err(|_| "original supervisor hint receiver lost")?;
        let new_udp = publication_after(&mut updates, Some(old_instance), budget).await?;
        retain_actual_socket_observations(&new_udp, 1, &mut ports, &mut ipv6)?;
        require(
            a.peers.current_network_generation_sync() == old_generation + 1,
            "original hint supervisor did not advance generation exactly once",
        )?;
        require(
            old_owner != 0
                && old_udp.as_ref().unwrap().inbound_publication_owner() == 0
                && new_udp.inbound_publication_owner() != old_owner,
            "actual old publication was not withdrawn before replacement",
        )?;
        require(
            !old_ack
                .source
                .as_ref()
                .and_then(|source| source.original_udp_read())
                .ok_or("old actual UDP ACK source missing")?
                .belongs_to_transport(&new_udp),
            "old actual reader borrowed the replacement transport",
        )?;
        require(
            commit(&a, &old_request, &old_ack)?
                == OverlayCreditOutcome::Stale(OverlayCreditStale::Generation),
            "old actual generation ACK did not reach the strict stale-generation rejection",
        )?;
        native_handler(&mut a, old_ack, budget).await?;
        require(
            !old_request.native_ack_credited_for_test()
                && a.stats.verified_round_trips == 0
                && a.stats.received_valid == 0,
            "old native ACK polluted once/stats after rebind",
        )?;
        old_udp.take();

        // Real original LAN admission/session APIs; no source/Full/token is fabricated.
        lifecycle::readmit_actual_pair(&a, &b, PathKind::Direct, budget).await?;
        let mut previous = old_request.clone();
        for _ in 0..2 {
            let (next, _, ack) =
                original_request_and_echo(&mut a, &mut b, PathKind::Direct, budget).await?;
            require(
                !Arc::ptr_eq(&next, &previous)
                    && next.nonce != previous.nonce
                    && next.generation == old_generation + 1,
                "recovery reused an old canonical/request generation",
            )?;
            native_fresh(&mut a, &next, ack, PathKind::Direct, budget).await?;
            previous = next;
        }
        hint_to_fresh = Some(started.elapsed());
        eprintln!(
            "c01_local_hint_to_second_native_fresh_ms={} actual_request_count=2 scope=loopback_lan",
            hint_to_fresh.unwrap().as_millis()
        );
        require(
            a.stats.verified_round_trips == 2
                && a.stats.received_valid == 2
                && !old_request.native_ack_credited_for_test(),
            "two recovered actual canonicals did not add exactly two or credited the old canonical",
        )
    }))
    .catch_unwind()
    .await;
    let mut cleanup = owners.close(budget).await;
    let report = original.cleanup_report();
    if let Err(error) = &report {
        cleanup = Err(format!(
            "{cleanup:?}; original supervisor ownership: {error}"
        ));
    }
    let acquired_ports = ports.iter().flatten().count();
    let acquired_ipv6 = ipv6.iter().flatten().count();
    for socket in ipv6.iter().flatten() {
        if socket.upgrade().is_some() {
            cleanup = Err(format!(
                "{cleanup:?}; actual original IPv6 member still retained after joins"
            ));
        }
    }
    let mut rebound = 0;
    for port in ports.into_iter().flatten() {
        match tokio::time::timeout_at(budget.end, p2pnet_netbind::bind_udp(port, None)).await {
            Ok(Ok(socket)) => {
                drop(socket);
                rebound += 1;
            }
            other => cleanup = Err(format!("{cleanup:?}; original UDP port rebind: {other:?}")),
        }
    }
    if cleanup.is_ok() {
        eprintln!("c01_original_hint_owned_cleanup {} fixture_handles_joined={}/{} ports_rebound={rebound}/{acquired_ports} actual_ipv6_weaks_released={acquired_ipv6} original_end_unchanged=true",
            report.unwrap(), owners.tasks.iter().filter(|task| task.handle.is_none()).count(), owners.tasks.len());
    }
    let body = match body {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("C01 body exceeded unchanged nine-second end".into()),
        Err(payload) => {
            eprintln!("c01_original_hint_body_panic_cleanup {cleanup:?}");
            std::panic::resume_unwind(payload)
        }
    };
    match (body, cleanup) {
        (Ok(()), Ok(())) => require(
            original.handover_shape_is_complete()
                && acquired_ports >= 3
                && rebound == acquired_ports
                && hint_to_fresh.is_some(),
            "actual C01 handover/owned cleanup shape was incomplete",
        ),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}
