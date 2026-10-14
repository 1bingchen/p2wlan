//! Actual asymmetric receive source with independently owned Direct validation.
//! The proxy only forwards original datagrams; it never decrypts or mints facts.
use super::*;
use crate::peer::{ActiveBusinessPath, PeerPathLifecycle};
use tokio::net::UdpSocket;
#[path = "asymmetric_invalidation.rs"]
mod invalidation;

async fn register_noise_peer(
    endpoint: &Endpoint,
    remote_key: String,
    session: TransportSession,
    candidate: SocketAddr,
    budget: Budget,
) -> Check {
    budget
        .step(
            "register original asymmetric peer",
            endpoint.peers.add_peer(&PeerInfo {
                node_id: endpoint.remote_node.into(),
                public_key: remote_key,
                endpoint: candidate.to_string(),
                virtual_ip: endpoint.remote_vip.into(),
                online: true,
                ..PeerInfo::default()
            }),
        )
        .await?;
    let life = endpoint
        .peers
        .peer_session_generation_sync(endpoint.remote_node)
        .ok_or("original asymmetric peer life missing")?;
    budget
        .step(
            "install original authorized Noise session",
            endpoint
                .wireguard
                .replace_session_for_lifecycle(endpoint.remote_node, session, life),
        )
        .await?;
    budget
        .step(
            "register actual validation candidate",
            endpoint.peers.add_candidates_with_sources(
                endpoint.remote_node,
                &[candidate.to_string()],
                &HashMap::from([(candidate.to_string(), "host".into())]),
            ),
        )
        .await?;
    Ok(())
}

fn owned_return_identity(endpoint: &Endpoint, remote: SocketAddr) -> bool {
    let Some(snapshot) = endpoint
        .peers
        .committed_business_path_snapshot_sync(endpoint.remote_node)
    else {
        return false;
    };
    let ActiveBusinessPath::Direct(identity) = snapshot.active else {
        return false;
    };
    let map = endpoint.peers.connection_map_for_test();
    let Ok(connections) = map.try_read() else {
        return false;
    };
    let Some(conn) = connections.get(endpoint.remote_node) else {
        return false;
    };
    snapshot.lifecycle == PeerPathLifecycle::Online
        && conn.has_current_authoritative_direct(endpoint.peers.current_network_generation_sync())
        && identity.epoch.remote_candidate_epoch == conn.remote_candidate_epoch()
        && conn
            .selected_direct_endpoint_for_consent(endpoint.peers.current_network_generation_sync())
            == Some(remote)
        && identity.epoch.network_generation == endpoint.peers.current_network_generation_sync()
        && Some(identity.epoch.peer_session_generation)
            == endpoint
                .peers
                .peer_session_generation_sync(endpoint.remote_node)
        && identity.owner_token.is_some()
        && identity.request_id.is_some()
        && identity.commit_endpoint() == Some(remote)
}

async fn start_actual_validator(
    endpoint: &Endpoint,
    target: SocketAddr,
    owners: &mut Owners,
    budget: Budget,
) -> Check {
    let udp = budget
        .step("borrow original validator UDP", endpoint.udp.read())
        .await?
        .as_ref()
        .cloned()
        .ok_or("original validation UDP publication absent")?;
    let peers = endpoint.peers.clone();
    let wireguard = endpoint.wireguard.clone();
    let peer_id = endpoint.remote_node.to_string();
    let vip = endpoint.vip;
    owners.spawn("original explicit encrypted validator", async move {
        crate::run_direct_encrypted_validation(
            crate::PeerReflexiveObservation {
                peer_id,
                observed_endpoint: target,
            },
            udp,
            peers,
            wireguard,
            vip,
        )
        .await;
        Ok(())
    });
    budget
        .step("actual owned validator nominates return endpoint", async {
            loop {
                if owned_return_identity(endpoint, target) {
                    return Ok(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await?
}

async fn start_actual_dpl(endpoint: &Endpoint, owners: &mut Owners, budget: Budget) -> Check {
    let udp = budget
        .step("borrow original DPL UDP", endpoint.udp.read())
        .await?
        .as_ref()
        .cloned()
        .ok_or("original DPL UDP missing")?;
    let peers = endpoint.peers.clone();
    let wireguard = endpoint.wireguard.clone();
    let (stop, stopped) = watch::channel(false);
    owners.readers_stop.push(stop);
    owners.spawn_graceful("original DPL scheduler with joined children", async move {
        crate::run_dplpmtud_scheduler_until_cancelled(udp, peers, wireguard, stopped).await;
        Ok(())
    });
    Ok(())
}

async fn require_real_budget(endpoint: &Endpoint, budget: Budget) -> Check {
    let udp = budget
        .step("borrow actual managed publication", endpoint.udp.read())
        .await?
        .as_ref()
        .cloned()
        .ok_or("managed publication missing")?;
    budget
        .step("real DPL probes and ACKs establish managed budget", async {
            loop {
                let ready = udp
                    .dplpmtud_runtime()
                    .snapshot_for_peer(endpoint.remote_node)
                    .is_some_and(|s| s.state == crate::dplpmtud::DplpmtudState::SearchComplete);
                if ready && udp.direct_business_budget_ready_for_peer(endpoint.remote_node) {
                    return Ok(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await?
}

async fn prepare_asymmetric_echo(
    a: &mut Endpoint,
    b: &mut Endpoint,
    request_endpoint: SocketAddr,
    proxy_source: SocketAddr,
    return_endpoint: SocketAddr,
    budget: Budget,
) -> Result<(Arc<CanonicalOverlayRequest>, RawRequestDelivery), String> {
    let (canonical, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, PathKind::Direct, budget).await?;
    let full = canonical
        .physical_publication
        .record()
        .ok_or("actual canonical Full absent")?;
    let tx = full.udp().ok_or("actual canonical UDP Full absent")?;
    require(
        tx.fence() == crate::udp::UdpSendFence::ManagedPublication,
        "asymmetric canonical did not use actual Managed Full",
    )?;
    require(
        tx.endpoint() == request_endpoint,
        "actual canonical Full did not target its independent validated proxy endpoint",
    )?;
    require(
        tx.original_managed_token().is_some(),
        "actual exact budget token missing",
    )?;
    let request = actual_delivery(b, budget).await?;
    require(
        request.event.packet == canonical.original_packet(),
        "proxy changed original REQUEST bytes",
    )?;
    require(
        request.source.as_ref().and_then(|s| s.source()) == Some(proxy_source),
        "actual reader did not retain the distinct proxy receive source",
    )?;
    require(
        proxy_source != return_endpoint && owned_return_identity(b, return_endpoint),
        "asymmetric source/independently verified return prerequisite missing",
    )?;
    let conn = budget
        .step(
            "actual current return peer",
            b.peers.get_connection(b.remote_node),
        )
        .await?
        .ok_or("current return peer missing")?;
    require(
        tx.original_direct_commit().is_some(),
        "actual canonical Full lost current Direct commit sequence",
    )?;
    require(
        conn.selected_direct_endpoint_for_consent(b.peers.current_network_generation_sync())
            == Some(return_endpoint),
        "current consent selected an unverified raw source",
    )?;
    let echo = inject_actual_echo(b, request, budget).await?;
    Ok((canonical, echo))
}

async fn asymmetric_round(
    a: &mut Endpoint,
    b: &mut Endpoint,
    request_endpoint: SocketAddr,
    proxy_source: SocketAddr,
    return_endpoint: SocketAddr,
    budget: Budget,
) -> Check {
    let (canonical, echo) = prepare_asymmetric_echo(
        a,
        b,
        request_endpoint,
        proxy_source,
        return_endpoint,
        budget,
    )
    .await?;
    let sent = budget
        .step(
            "actual original sealed Echo send",
            crate::network_outbound::send_original_for_test(
                echo.clone(),
                &b.wireguard,
                &b.peers,
                b.peers.current_network_generation_sync(),
                true,
                &b.udp,
                &b.relay,
                false,
            ),
        )
        .await?;
    // Baseline 8d must reach this assertion after genuine validator, DPL,
    // original Full, reader, decrypt, MockTun and sealed route prerequisites.
    assert!(
        sent,
        "pr209 asymmetric original Echo must use independently verified return endpoint"
    );
    let ack = actual_delivery(a, budget).await?;
    native_fresh(a, &canonical, ack, PathKind::Direct, budget).await?;
    let roundtrips = a.stats.verified_round_trips;
    let valid = a.stats.received_valid;
    let duplicate = repeat_actual_echo(a, b, echo, PathKind::Direct, budget).await?;
    native_handler(a, duplicate, budget).await?;
    require(
        a.stats.verified_round_trips == roundtrips
            && a.stats.received_valid == valid
            && canonical.native_ack_credited_for_test(),
        "duplicate actual asymmetric Echo added native credit",
    )
}

pub(in super::super) async fn exercise_asymmetric_endpoint() -> Check {
    exercise_asymmetric(false).await
}

pub(in super::super) async fn exercise_asymmetric_invalidation() -> Check {
    exercise_asymmetric(true).await
}

async fn exercise_asymmetric(with_invalidation: bool) -> Check {
    let budget = Budget::new();
    let mut owners = Owners::default();
    let mut sockets = Vec::new();
    let body = AssertUnwindSafe(tokio::time::timeout_at(budget.body_end(), async {
        let mut a = Endpoint::create_for_validation(NODE_A, VIP_A, NODE_B, VIP_B, &mut owners, budget).await?;
        let mut b = Endpoint::create_for_validation(NODE_B, VIP_B, NODE_A, VIP_A, &mut owners, budget).await?;
        let a_addr = a.local_udp().await?.ok_or("A original UDP missing")?;
        let b_addr = b.local_udp().await?.ok_or("B original UDP missing")?;
        let front = Arc::new(budget.step("bind proxy front", UdpSocket::bind("127.0.0.1:0")).await?
            .map_err(|e| e.to_string())?);
        let back = Arc::new(budget.step("bind proxy back", UdpSocket::bind("127.0.0.1:0")).await?
            .map_err(|e| e.to_string())?);
        let front_addr = front.local_addr().map_err(|e| e.to_string())?;
        let back_addr = back.local_addr().map_err(|e| e.to_string())?;
        require(front_addr != back_addr && back_addr != a_addr, "proxy endpoints collapsed")?;
        sockets.push((Arc::downgrade(&front), front_addr));
        sockets.push((Arc::downgrade(&back), back_addr));
        owners.spawn("actual opaque one-proxy UDP forwarding", async move {
            let mut from_front = [0u8; 65536];
            let mut from_back = [0u8; 65536];
            loop {
                tokio::select! {
                    got = front.recv_from(&mut from_front) => {
                        let (len, source) = got.map_err(|e| e.to_string())?;
                        require(source == a_addr, "front got non-original A source")?;
                        let sent = back.send_to(&from_front[..len], b_addr).await.map_err(|e| e.to_string())?;
                        require(sent == len, "proxy short REQUEST write")?;
                    }
                    got = back.recv_from(&mut from_back) => {
                        let (len, source) = got.map_err(|e| e.to_string())?;
                        require(source == b_addr, "back got non-original B source")?;
                        let sent = front.send_to(&from_back[..len], a_addr).await.map_err(|e| e.to_string())?;
                        require(sent == len, "proxy short ACK write")?;
                    }
                }
            }
        });
        let (sa, sb, ak, bk) = session_pair_for(&a.identity, &b.identity)?;
        register_noise_peer(&a, bk, sa, front_addr, budget).await?;
        register_noise_peer(&b, ak, sb, a_addr, budget).await?;
        // B's owned real validator is direct; A's distinct real validator is
        // through P/S. No automatic callback creates unowned validation tasks.
        start_actual_validator(&b, a_addr, &mut owners, budget).await?;
        start_actual_validator(&a, front_addr, &mut owners, budget).await?;
        start_actual_dpl(&a, &mut owners, budget).await?;
        start_actual_dpl(&b, &mut owners, budget).await?;
        require_real_budget(&a, budget).await?;
        require_real_budget(&b, budget).await?;
        if with_invalidation {
            invalidation::exercise(&mut a, &mut b, front_addr, back_addr, a_addr, &mut owners, budget).await
        } else {
        asymmetric_round(&mut a, &mut b, front_addr, back_addr, a_addr, budget).await?;
        let previous = a.stats.verified_round_trips;
        asymmetric_round(&mut a, &mut b, front_addr, back_addr, a_addr, budget).await?;
        require(a.stats.verified_round_trips == previous + 1,
            "new canonical asymmetric request did not add exactly one")
        }
    })).catch_unwind().await;
    let total = owners.tasks.len();
    let cleanup = owners.close(budget).await;
    let remaining = owners.tasks.iter().filter(|t| t.handle.is_some()).count();
    let mut cleanup = cleanup;
    let acquired_proxy_ports = sockets.len();
    for (socket, addr) in sockets {
        if socket.upgrade().is_some() {
            cleanup = Err("owned proxy socket survived actual joins".into());
            continue;
        }
        match tokio::time::timeout_at(budget.end, UdpSocket::bind(addr)).await {
            Ok(Ok(_rebound)) => {}
            other => {
                cleanup = Err(format!(
                    "proxy port not reclaimed within original end: {other:?}"
                ))
            }
        }
    }
    if cleanup.is_ok() {
        eprintln!("pr209_asymmetric_owned_cleanup_complete joined={}/{} remaining_handles={} proxy_ports_rebound={} original_end_unchanged=true", total - remaining, total, remaining, acquired_proxy_ports);
    } else {
        eprintln!(
            "pr209_asymmetric_owned_cleanup_failed joined={}/{} cleanup={cleanup:?}",
            total - remaining,
            total
        );
    }
    let body = match body {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(Err(_)) => Err("asymmetric original body exceeded fixed end".into()),
        Ok(Ok(body)) => body,
    };
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}
