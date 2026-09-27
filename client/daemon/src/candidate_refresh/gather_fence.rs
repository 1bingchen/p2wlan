/// Identity of the committed candidate state from which one unlocked gather
/// started. A later gather or peer-reflexive publication must not be replaced
/// by this older result just because its gateway discovery completed last.
#[derive(Debug, Clone, Copy)]
struct CandidateGatherFence {
    snapshot_version: Option<u64>,
    network_generation: u64,
    transport_instance: u64,
    publication_owner: u64,
    local_addr: Option<SocketAddr>,
}

impl CandidateGatherFence {
    async fn capture(
        _refresh_guard: &tokio::sync::MutexGuard<'_, ()>,
        udp: &UdpTransport,
        peers: &PeerManager,
        snapshots: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    ) -> Self {
        let snapshot_version = snapshots
            .read()
            .await
            .as_ref()
            .map(|snapshot| snapshot.version);
        Self {
            snapshot_version,
            network_generation: peers.current_network_generation_sync(),
            transport_instance: udp.transport_instance_id(),
            publication_owner: udp.inbound_publication_owner(),
            local_addr: udp.local_addr().ok(),
        }
    }

    /// The caller keeps the existing refresh lock through the ensuing local
    /// profile/candidate commit, so a checked snapshot version cannot change
    /// between this comparison and that commit. Generation and publication
    /// checks also reject changes during discovery; they do not claim to make
    /// the existing later generation-advance/publication path one transaction.
    async fn stale_reason(
        &self,
        refresh_guard: &tokio::sync::MutexGuard<'_, ()>,
        udp: &UdpTransport,
        peers: &PeerManager,
        snapshots: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    ) -> Option<&'static str> {
        let current = Self::capture(refresh_guard, udp, peers, snapshots).await;
        if current.snapshot_version != self.snapshot_version {
            Some("candidate_snapshot_replaced")
        } else if current.network_generation != self.network_generation {
            Some("network_generation_changed")
        } else if current.transport_instance != self.transport_instance
            || current.publication_owner != self.publication_owner
            || current.local_addr != self.local_addr
        {
            Some("udp_transport_replaced")
        } else {
            None
        }
    }
}
