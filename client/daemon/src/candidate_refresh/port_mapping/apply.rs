/// Validate only the captured transport identity here. The caller separately
/// fences its candidate-snapshot commit after this unlocked discovery returns.
fn gateway_mapping_identity_is_current(
    identity: crate::gateway_mapping::GatewayMappingIdentity,
    udp: &UdpTransport,
    peers: &PeerManager,
) -> bool {
    identity.publication_owner != 0
        && udp.inbound_publication_owner() == identity.publication_owner
        && udp.transport_instance_id() == identity.transport_instance
        && udp.local_addr().ok() == Some(identity.bind_endpoint)
        && peers.current_network_generation_sync() == identity.network_generation
}

const GATEWAY_MAPPING_COMMIT_TIMEOUT: Duration = Duration::from_millis(100);

/// The single gateway cache and its diagnostic snapshot commit together.
/// No discovery I/O is allowed while these guards are held.
struct GatewayMappingCommit<'a> {
    runtime: tokio::sync::RwLockWriteGuard<'a, GatewayMappingRuntime>,
    diagnostics: tokio::sync::RwLockWriteGuard<'a, GatewayMappingDiagnostics>,
}

async fn lock_gateway_mapping_commit<'a>(
    runtime: &'a RwLock<GatewayMappingRuntime>,
    diagnostics: &'a RwLock<GatewayMappingDiagnostics>,
    phase: &'static str,
) -> Option<GatewayMappingCommit<'a>> {
    let deadline = tokio::time::Instant::now() + GATEWAY_MAPPING_COMMIT_TIMEOUT;
    let acquire = async {
        let runtime = runtime.write().await;
        let diagnostics = diagnostics.write().await;
        GatewayMappingCommit {
            runtime,
            diagnostics,
        }
    };
    // One deadline covers both waits. Timing out the second acquisition
    // drops the first guard, allowing a new network's cache owner to proceed.
    match tokio::time::timeout_at(deadline, acquire).await {
        Ok(commit) => Some(commit),
        Err(_) => {
            debug!(
                event = "gateway_mapping_commit_skipped",
                reason_code = "gateway_mapping_commit_lock_timeout",
                phase,
                "Skipping gateway mapping cache commit after bounded local contention"
            );
            None
        }
    }
}

pub(super) async fn maybe_add_port_mapping_udp_candidate(
    (udp, peers): (&UdpTransport, &PeerManager),
    existing_candidates: &[String],
    existing_candidate_sources: &HashMap<String, String>,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
    runtime: Arc<RwLock<GatewayMappingRuntime>>,
    diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
) {
    let Ok(bind_endpoint) = udp.local_addr() else {
        return;
    };
    let network_generation = peers.current_network_generation_sync();
    let publication_owner = udp.inbound_publication_owner();
    if publication_owner == 0 {
        return;
    }
    let mut identity = crate::gateway_mapping::GatewayMappingIdentity {
        bind_endpoint,
        local_endpoint: bind_endpoint,
        gateway: None,
        network_generation,
        transport_instance: udp.transport_instance_id(),
        publication_owner,
    };
    // Keep the existing single gateway lookup per gather; retaining a cache
    // never starts an extra discovery or a background retry task.
    let gateway = default_ipv4_gateway().await;
    let Some(local_addr) = port_mapping_local_addr(
        Some(bind_endpoint),
        existing_candidates,
        existing_candidate_sources,
        gateway,
    ) else {
        let mut diagnostics = diagnostics.write().await;
        if !gateway_mapping_identity_is_current(identity, udp, peers) {
            return;
        }
        diagnostics.local_endpoint = None;
        diagnostics.upnp.status = "unavailable".to_string();
        diagnostics.upnp.last_error = Some("no LAN IPv4 UDP endpoint available".to_string());
        debug!("Skipping port-mapping UDP candidate because no LAN IPv4 local address was found");
        return;
    };
    identity.local_endpoint = local_addr;
    identity.gateway = gateway;

    {
        let Some(GatewayMappingCommit {
            mut runtime,
            mut diagnostics,
        }) = lock_gateway_mapping_commit(&runtime, &diagnostics, "cache_lookup").await
        else {
            return;
        };
        if !gateway_mapping_identity_is_current(identity, udp, peers) {
            return;
        }
        runtime.bind_identity(identity);
        let now = Instant::now();
        if runtime.retain_candidate(identity, now) {
            if let (Some(endpoint), Some(source)) = (
                runtime.candidate_endpoint.as_ref(),
                runtime.candidate_source,
            ) {
                if !candidates.contains(endpoint) {
                    candidates.insert(0, endpoint.clone());
                    candidate_sources.insert(endpoint.clone(), source.to_string());
                }
                *diagnostics = runtime.snapshot(true, PORT_MAPPING_LEASE_SECS, diagnostics.clone());
                return;
            }
        }
        if !runtime.needs_discovery(identity, now) {
            *diagnostics = runtime.snapshot(true, PORT_MAPPING_LEASE_SECS, diagnostics.clone());
            return;
        }
    }

    let discovered = discover_port_mapping_udp_candidate(local_addr).await;
    let Some(GatewayMappingCommit {
        mut runtime,
        mut diagnostics,
    }) = lock_gateway_mapping_commit(&runtime, &diagnostics, "discovery_result").await
    else {
        return;
    };
    // Check after every await, immediately before committing either success
    // or failure. A retired discovery cannot revive a lease or install a
    // failure backoff on the replacement network's cache. There is no await
    // between this check and the cache/output commit below.
    if !gateway_mapping_identity_is_current(identity, udp, peers)
        || !runtime.matches_identity(identity)
    {
        debug!("Discarding gateway discovery from a replaced network or UDP transport");
        return;
    }
    let GatewayMappingDiscovery {
        candidate,
        upnp,
        pcp,
        nat_pmp,
    } = discovered;
    record_method_result(&mut diagnostics.upnp, upnp);
    if let Some(result) = pcp {
        record_method_result(&mut diagnostics.pcp, result);
    }
    if let Some(result) = nat_pmp {
        record_method_result(&mut diagnostics.nat_pmp, result);
    }
    if let Some(candidate) = candidate {
        if !candidates.contains(&candidate.endpoint) {
            info!(
                "{} mapped UDP {local_addr} as {}",
                candidate.source, candidate.endpoint
            );
            // Gateway-created mappings must survive the signaling cap.
            candidates.insert(0, candidate.endpoint.clone());
        }
        candidate_sources.insert(candidate.endpoint.clone(), candidate.source.to_string());
        runtime.record_success(
            identity,
            candidate.endpoint,
            candidate.source,
            Duration::from_secs(PORT_MAPPING_LEASE_SECS.into()),
        );
    } else {
        runtime.record_failure(identity, PORT_MAPPING_FAILURE_RETRY);
        debug!("No UPnP/PCP/NAT-PMP UDP mapping candidate discovered for {local_addr}");
    }
    *diagnostics = runtime.snapshot(true, PORT_MAPPING_LEASE_SECS, diagnostics.clone());
}

#[cfg(test)]
mod gateway_mapping_commit_tests {
    use super::*;

    include!("apply_tests.rs");
}
