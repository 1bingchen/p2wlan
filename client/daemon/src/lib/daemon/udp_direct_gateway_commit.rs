/// Commit a discovered gateway candidate only while its socket publication and
/// network generation still own the destination snapshot. All awaited locks
/// share a 100ms deadline; epoch/publication guards are acquired without waiting
/// after the candidate locks, and the final validation and mutation are synchronous.
#[allow(clippy::too_many_arguments)]
async fn commit_gateway_mapping_candidates(
    publication: &UdpTransportPublication,
    owner: UdpTransportOwner,
    peers: &PeerManager,
    generation: u64,
    refresh_lock: &Arc<Mutex<()>>,
    snapshot: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    local_candidates: &Arc<RwLock<Vec<String>>>,
    local_sources: &Arc<RwLock<HashMap<String, String>>>,
    discovered: Vec<String>,
    discovered_sources: HashMap<String, String>,
) -> std::result::Result<(), &'static str> {
    timeout(Duration::from_millis(100), async {
        let _refresh = refresh_lock.lock().await;
        let mut snapshot = snapshot.write().await;
        let mut candidates_mirror = local_candidates.write().await;
        let mut sources_mirror = local_sources.write().await;
        let epoch_gate = peers.network_epoch_gate();
        let _epoch = epoch_gate
            .try_lock()
            .map_err(|_| "network_epoch_contended")?;
        let state = publication
            .inner
            .state
            .try_lock()
            .map_err(|_| "udp_publication_contended")?;
        if state.current_owner != Some(owner) {
            return Err("udp_transport_replaced");
        }
        if peers.current_network_generation_sync() != generation {
            return Err("network_generation_changed");
        }
        let Some(current) = snapshot.as_mut() else {
            return Err("candidate_snapshot_missing");
        };
        for endpoint in discovered {
            if !current.candidates.contains(&endpoint) {
                current.candidates.push(endpoint.clone());
            }
            if let Some(source) = discovered_sources.get(&endpoint) {
                current.candidate_sources.insert(endpoint, source.clone());
            }
        }
        current.version = current.version.saturating_add(1);
        current.hash = candidate_set_hash(&current.candidates, &current.candidate_sources);
        // Gateway discovery does not remeasure the retained STUN candidates.
        // Keep their original freshness/readiness and network identity.
        *candidates_mirror = current.candidates.clone();
        *sources_mirror = current.candidate_sources.clone();
        Ok(())
    })
    .await
    .map_err(|_| "candidate_commit_contended")?
}
