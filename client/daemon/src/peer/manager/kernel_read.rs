// Immutable expectation captured by the original system-read observer.
// It retains no peer owner and grants no current-owner or once permission.
pub(crate) struct OriginalKernelReadPeer {
    owner: std::sync::Weak<PeerManager>,
    peer: String,
    target: std::net::Ipv4Addr,
    generation: u64,
    lifecycle: PeerSessionGeneration,
    observed_at: Instant,
}

impl OriginalKernelReadPeer {
    #[cfg(unix)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(unix)]
    pub(crate) fn lifecycle(&self) -> PeerSessionGeneration {
        self.lifecycle
    }

    pub(crate) fn matches_original_encryption(
        &self,
        owner: &std::sync::Weak<PeerManager>,
        generation: u64,
        encryption: &crate::transport::OriginalEncryptionSource,
    ) -> bool {
        self.owner.ptr_eq(owner)
            && self.generation == generation
            && self.peer == encryption.peer_id()
            && Some(self.lifecycle) == encryption.authorized_peer_lifecycle()
            && self.observed_at <= encryption.encrypted_at()
    }

    /// A synchronous identity observation only; callers must still perform the
    /// sole final transaction after every handoff before granting any credit.
    pub(crate) fn try_identity_at(
        &self,
        peers: &PeerManager,
        at: Instant,
    ) -> std::result::Result<(), OverlayCreditOutcome> {
        use OverlayCreditOutcome::Stale;
        if !std::ptr::eq(self.owner.as_ptr(), peers) || at < self.observed_at {
            return Err(Stale(CreditStale::Identity));
        }
        let (generation, lifecycle) = peers.try_kernel_read_peer_values(&self.peer, self.target)?;
        if generation != self.generation {
            return Err(Stale(CreditStale::Generation));
        }
        if lifecycle != self.lifecycle {
            return Err(Stale(CreditStale::Lifecycle));
        }
        Ok(())
    }
}

impl PeerManager {
    #[cfg(test)]
    pub(crate) fn with_original_kernel_peer_connections_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _held = self.connections.try_write().unwrap();
        operation()
    }

    #[cfg(test)]
    pub(crate) fn with_original_kernel_peer_membership_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _held = self.peer_membership.try_lock().unwrap();
        operation()
    }

    pub(crate) fn try_capture_original_kernel_read_peer(
        self: &Arc<Self>,
        peer: &str,
        target: std::net::Ipv4Addr,
    ) -> std::result::Result<OriginalKernelReadPeer, OverlayCreditOutcome> {
        let (generation, lifecycle) = self.try_kernel_read_peer_values(peer, target)?;
        Ok(OriginalKernelReadPeer {
            owner: Arc::downgrade(self),
            peer: peer.to_owned(),
            target,
            generation,
            lifecycle,
            observed_at: Instant::now(),
        })
    }

    fn try_kernel_read_peer_values(
        &self,
        peer: &str,
        target: std::net::Ipv4Addr,
    ) -> std::result::Result<(u64, PeerSessionGeneration), OverlayCreditOutcome> {
        use OverlayCreditOutcome::{Contended, Stale};
        let _epoch = self
            .network_epoch_gate
            .try_lock()
            .map_err(|_| Contended(CreditLock::Epoch))?;
        let connections = self
            .connections
            .try_read()
            .map_err(|_| Contended(CreditLock::Connections))?;
        let membership = self
            .peer_membership
            .try_lock()
            .map_err(|_| Contended(CreditLock::Membership))?;
        let lifecycle = membership
            .active_generation(peer)
            .filter(|value| *value != PeerSessionGeneration::UNBOUND)
            .ok_or(Stale(CreditStale::Lifecycle))?;
        connections
            .get(peer)
            .filter(|connection| {
                connection.online
                    && connection.state != ConnectionState::Closed
                    && connection.virtual_ip.parse::<std::net::Ipv4Addr>() == Ok(target)
            })
            .ok_or(Stale(CreditStale::PeerState))?;
        Ok((self.current_network_generation_sync(), lifecycle))
    }
}
