use super::*;
use crate::peer::HardHardPairKey;

#[cfg(test)]
#[derive(Default)]
pub(super) struct HardHardValidationSendGate {
    pub(super) reached: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
}

#[derive(Debug, Clone)]
pub(crate) struct HardHardSocketMode {
    pub(super) peer: String,
    pub(super) token: String,
    pub(super) socket: std::sync::Weak<UdpSocket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HardHardValidationScope {
    pub(crate) token: String,
    pub(crate) pair: HardHardPairKey,
    pub(crate) generation: u64,
    pub(crate) peer_session: PeerSessionGeneration,
}

impl UdpTransport {
    /// Called after hh2 ledger registration and before publication or probing.
    /// Mode stamps survive ledger retirement and never own/retain a socket.
    pub(crate) async fn enable_hard_hard_pair_sockets(&self, peer: &str, token: &str) -> bool {
        let _epoch = self.network_epoch_gate.lock().await;
        let Some(record) = self.peers.hard_hard_pair_scope(peer, token).await else {
            return false;
        };
        if !self.peers.hard_hard_pair_arm(peer, token).await {
            return false;
        }
        let mut state = self.socket_state.lock().await;
        state
            .hard_hard_pair_modes
            .retain(|_, mode| mode.socket.strong_count() > 0);
        let new_count = record
            .requested_socket_indices
            .iter()
            .filter(|index| !state.hard_hard_pair_modes.contains_key(index))
            .count();
        if state.hard_hard_pair_modes.len().saturating_add(new_count) > 256
            || record.requested_socket_indices.is_empty()
            || record.requested_socket_indices.iter().any(|index| {
                !state.dynamic.get(index).is_some_and(|entry| {
                    entry.peer_id == peer
                        && entry.network_generation == record.local_network_generation
                        && entry.phase.is_usable()
                        && entry.authenticated_evidence == 0
                        && entry.hard_hard_session_token.as_deref() == Some(token)
                }) || state
                    .hard_hard_pair_modes
                    .get(index)
                    .is_some_and(|mode| mode.peer != peer || mode.token != token)
            })
        {
            return false;
        }
        for index in record.requested_socket_indices {
            let Some(entry) = state.dynamic.get_mut(&index) else {
                return false;
            };
            entry.hard_hard_pair_required = true;
            let socket = Arc::downgrade(&entry.socket);
            state.hard_hard_pair_modes.insert(
                index,
                HardHardSocketMode {
                    peer: peer.into(),
                    token: token.into(),
                    socket,
                },
            );
        }
        true
    }

    pub(super) async fn hard_hard_socket_mode(&self, index: usize) -> Option<HardHardSocketMode> {
        self.socket_state
            .lock()
            .await
            .hard_hard_pair_modes
            .get(&index)
            .cloned()
    }

    /// Retired hh2 remains hh2. A previously committed pair may answer a
    /// validation on the still-current Direct path after rendezvous cleanup.
    /// An uncommitted retired pair can never use the legacy branch.
    pub(super) async fn hard_hard_validation_scope(
        &self,
        peer: &str,
        index: usize,
        remote: SocketAddr,
    ) -> std::result::Result<Option<HardHardValidationScope>, ()> {
        let snapshot = {
            let state = self.socket_state.lock().await;
            if let Some(mode) = state.hard_hard_pair_modes.get(&index) {
                let entry = state.dynamic.get(&index).ok_or(())?;
                if mode.peer != peer
                    || entry.peer_id != peer
                    || !entry.phase.is_usable()
                    || entry.network_generation != self.peers.current_network_generation_sync()
                    || !mode
                        .socket
                        .upgrade()
                        .is_some_and(|socket| Arc::ptr_eq(&socket, &entry.socket))
                {
                    return Err(());
                }
                Some((
                    mode.token.clone(),
                    entry.socket.local_addr().map_err(|_| ())?,
                    entry.network_generation,
                    entry.hard_hard_committed_remote,
                ))
            } else {
                None
            }
        };
        let Some((token, local_endpoint, generation, committed_remote)) = snapshot else {
            return if self
                .peers
                .hard_hard_pair_validation_target(peer)
                .await
                .is_some()
            {
                Err(())
            } else {
                Ok(None)
            };
        };
        let pair = HardHardPairKey {
            socket_index: index,
            local_endpoint,
            remote_endpoint: remote,
        };
        let committed = committed_remote == Some(remote)
            && self
                .peers
                .hard_hard_committed_pair_is_current_sync(peer, &pair, generation);
        if !committed {
            match self.peers.hard_hard_pair_validation_target(peer).await {
                Some(Some((selected_token, selected)))
                    if selected_token == token
                        && selected == pair
                        && self
                            .peers
                            .hard_hard_pair_scope(peer, &token)
                            .await
                            .is_some() => {}
                _ => return Err(()),
            }
        }
        let peer_session = self.peers.peer_session_generation_sync(peer).ok_or(())?;
        Ok(Some(HardHardValidationScope {
            token,
            pair,
            generation,
            peer_session,
        }))
    }

    pub(crate) async fn hh2_validation_pair_matches(
        &self,
        peer: &str,
        index: usize,
        remote: SocketAddr,
    ) -> bool {
        self.hard_hard_validation_scope(peer, index, remote)
            .await
            .is_ok()
    }

    pub(super) async fn hard_hard_committed_socket_matches(
        &self,
        peer: &str,
        index: usize,
        remote: SocketAddr,
    ) -> bool {
        let pair = {
            let state = self.socket_state.lock().await;
            let Some(entry) = state.dynamic.get(&index) else {
                return false;
            };
            if entry.peer_id != peer
                || !entry.permits_ordinary_traffic()
                || entry.hard_hard_committed_remote != Some(remote)
            {
                return false;
            }
            let Ok(local_endpoint) = entry.socket.local_addr() else {
                return false;
            };
            (
                HardHardPairKey {
                    socket_index: index,
                    local_endpoint,
                    remote_endpoint: remote,
                },
                entry.network_generation,
            )
        };
        self.peers
            .hard_hard_committed_pair_is_current_sync(peer, &pair.0, pair.1)
    }

    /// A nominated but uncommitted pair may carry only the owned validation
    /// protocol. Other decrypted traffic must not learn endpoints or reach TUN.
    pub(crate) async fn permits_hh2_encrypted_ingress(
        &self,
        peer: &str,
        index: usize,
        remote: SocketAddr,
        validation: bool,
    ) -> bool {
        if self.hard_hard_socket_mode(index).await.is_none() {
            return true;
        }
        if validation {
            self.hh2_validation_pair_matches(peer, index, remote).await
        } else {
            self.hard_hard_committed_socket_matches(peer, index, remote)
                .await
        }
    }

    pub(super) async fn hard_hard_validation_scope_is_current(
        &self,
        peer: &str,
        scope: &HardHardValidationScope,
    ) -> bool {
        self.hard_hard_validation_scope(peer, scope.pair.socket_index, scope.pair.remote_endpoint)
            .await
            .is_ok_and(|current| current.as_ref() == Some(scope))
    }

    /// Only this API may transmit encrypted validation on an uncommitted hh2
    /// mapping. It never changes ordinary-send permission or peer affinity.
    pub(crate) async fn send_direct_validation_packet_on_socket(
        &self,
        socket: &Arc<UdpSocket>,
        index: usize,
        packet: &EncryptedPeerPacket,
        endpoint: SocketAddr,
    ) -> Result<usize> {
        if self.hard_hard_socket_mode(index).await.is_none() {
            if !self
                .hh2_validation_pair_matches(&packet.peer_id, index, endpoint)
                .await
            {
                return Err(DaemonError::Network(
                    "validation pair is not nominated".into(),
                ));
            }
            return self
                .send_encrypted_packet_on_socket(socket, index, packet, endpoint)
                .await;
        }
        let send = async {
            loop {
                socket
                    .writable()
                    .await
                    .map_err(|e| DaemonError::Network(e.to_string()))?;
                let _epoch = self.network_epoch_gate.lock().await;
                let Some(scope) = self
                    .hard_hard_validation_scope(&packet.peer_id, index, endpoint)
                    .await
                    .map_err(|_| DaemonError::Network("hh2 validation owner revoked".into()))?
                else {
                    return Err(DaemonError::Network("hh2 validation mode changed".into()));
                };
                let permit = self
                    .peers
                    .hard_hard_validation_send_permit(&packet.peer_id, &scope.token, &scope.pair)
                    .await;
                #[cfg(test)]
                {
                    let gate = self.hh2_validation_send_gate.lock().await.clone();
                    if let Some(gate) = gate {
                        gate.reached.notify_one();
                        gate.release.notified().await;
                    }
                }
                let state = self.socket_state.lock().await;
                if !state.dynamic.get(&index).is_some_and(|entry| {
                    Arc::ptr_eq(&entry.socket, socket)
                        && entry.peer_id == packet.peer_id
                        && entry.network_generation == scope.generation
                        && entry.hard_hard_session_token.as_deref() == Some(scope.token.as_str())
                        && (entry.hard_hard_committed_remote == Some(endpoint)
                            || permit
                                .as_ref()
                                .is_some_and(|permit| permit.is_current(&self.peers)))
                }) || packet
                    .room_authorization
                    .as_ref()
                    .is_some_and(|permit| !permit.is_valid())
                {
                    return Err(DaemonError::Network("hh2 validation socket revoked".into()));
                }
                // Nonblocking handoff while the epoch/socket transaction is
                // held. Backpressure releases every guard before awaiting.
                match socket.try_send_to(&packet.wire_bytes, endpoint) {
                    Ok(sent) => return Ok(sent),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(DaemonError::Network(error.to_string())),
                }
            }
        };
        let sent = timeout(Duration::from_millis(100), send)
            .await
            .map_err(|_| DaemonError::Network("hh2 validation send timed out".into()))??;
        self.update_socket_diagnostics(index, |m| m.encrypted_packets_sent += 1)
            .await;
        Ok(sent)
    }

    pub(crate) async fn mark_hh2_data_validated(
        &self,
        peer: &str,
        scope: Option<&HardHardValidationScope>,
    ) -> bool {
        let Some(scope) = scope else {
            return true;
        };
        if !self
            .hard_hard_validation_scope_is_current(peer, scope)
            .await
        {
            return false;
        }
        if self
            .socket_state
            .lock()
            .await
            .dynamic
            .get(&scope.pair.socket_index)
            .is_some_and(|entry| {
                entry.hard_hard_committed_remote == Some(scope.pair.remote_endpoint)
            })
        {
            return true;
        }
        self.peers
            .hard_hard_pair_mark_validated(peer, &scope.token, &scope.pair)
            .await
    }
}
