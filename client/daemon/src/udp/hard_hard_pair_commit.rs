use super::*;
use crate::peer::{DirectCommitHooks, HardHardPairCommitGuard};

struct PairCommitLocks<'a> {
    state: tokio::sync::MutexGuard<'a, SocketState>,
    pending: tokio::sync::MutexGuard<'a, HashMap<ProbeNonce, PendingProbe>>,
    bindings: tokio::sync::MutexGuard<'a, HashMap<ProbeNonce, String>>,
    diagnostics: tokio::sync::MutexGuard<'a, HashMap<usize, UdpSocketPoolMemberDiagnostics>>,
    manager: HardHardPairCommitGuard<'a>,
}

/// Exists only in the authenticated ACK's existing adoption/epoch section.
/// Waiting for the connection writer is bounded by `deadline`; no IO occurs
/// while these guards are held. The reducer's synchronous commit releases
/// them before its later registry/diagnostic awaits.
pub(crate) struct HardHardDirectCommit<'a> {
    locks: Option<PairCommitLocks<'a>>,
    peer: String,
    scope: HardHardValidationScope,
    pub(crate) deadline: tokio::time::Instant,
    pub(crate) committed: bool,
}

impl DirectCommitHooks for HardHardDirectCommit<'_> {
    fn is_current(&self) -> bool {
        self.locks
            .as_ref()
            .is_some_and(|locks| locks.manager.is_current())
    }

    fn committed(&mut self) {
        let Some(locks) = self.locks.as_mut() else {
            return;
        };
        let winner_index = self.scope.pair.socket_index;
        let loser_indices = locks
            .state
            .dynamic
            .iter()
            .filter(|(index, entry)| {
                **index != winner_index
                    && entry.peer_id == self.peer
                    && entry.network_generation == self.scope.generation
                    && entry.hard_hard_session_token.as_deref() == Some(self.scope.token.as_str())
            })
            .map(|(index, _)| *index)
            .collect::<HashSet<_>>();
        locks.manager.commit();
        let epoch = locks.state.next_epoch();
        locks.state.affinity.insert(
            self.peer.clone(),
            PeerSocketPin {
                socket_index: winner_index,
                epoch,
            },
        );
        let winner = locks
            .state
            .dynamic
            .get_mut(&winner_index)
            .expect("exact socket held through reducer");
        winner.authenticated_evidence = winner.authenticated_evidence.saturating_add(1);
        winner.phase = DynamicSocketPhase::Finalized;
        winner.hard_hard_committed_remote = Some(self.scope.pair.remote_endpoint);
        for index in &loser_indices {
            if let Some(loser) = locks.state.dynamic.remove(index) {
                loser.shutdown_tx.send_replace(true);
                loser.reader.abort();
            }
        }
        locks
            .pending
            .retain(|_, probe| !loser_indices.contains(&probe.socket_index));
        locks
            .bindings
            .retain(|nonce, _| locks.pending.contains_key(nonce));
        locks
            .diagnostics
            .retain(|index, _| !loser_indices.contains(index));
        self.committed = true;
    }

    fn finish(&mut self) {
        // Called only after the connection reducer has synchronized every
        // mirror. Cleanup can now safely inspect both halves of the commit.
        if self.committed {
            if let Some(locks) = self.locks.as_ref() {
                let _ = locks.manager.record_strategy_success_after_direct_commit();
            }
        }
        self.locks.take();
    }
}

impl UdpTransport {
    pub(crate) async fn prepare_hh2_direct_commit<'a>(
        &'a self,
        _epoch: &tokio::sync::MutexGuard<'_, ()>,
        peer: &str,
        scope: Option<&HardHardValidationScope>,
    ) -> std::result::Result<Option<HardHardDirectCommit<'a>>, ()> {
        let Some(scope) = scope else {
            return Ok(None);
        };
        let acquire = async {
            if !self
                .hard_hard_validation_scope_is_current(peer, scope)
                .await
            {
                return Err(());
            }
            let state = self.socket_state.lock().await;
            let Some(entry) = state.dynamic.get(&scope.pair.socket_index) else {
                return Err(());
            };
            if entry.peer_id != peer
                || entry.network_generation != scope.generation
                || !entry.phase.is_usable()
                || !entry.hard_hard_pair_required
                || entry.hard_hard_session_token.as_deref() != Some(scope.token.as_str())
                || entry.socket.local_addr().ok() != Some(scope.pair.local_endpoint)
            {
                return Err(());
            }
            // An already committed exact pair needs no new HH authority.
            if entry.hard_hard_committed_remote == Some(scope.pair.remote_endpoint) {
                return Ok(None);
            }
            let punch_generation = entry.punch_generation;
            let pending = self.pending_probes.lock().await;
            let bindings = self.hard_hard_probe_bindings.lock().await;
            let diagnostics = self.dynamic_socket_diagnostics.lock().await;
            let manager = self
                .peers
                .hard_hard_pair_commit_guard(peer, &scope.token, &scope.pair, punch_generation)
                .await
                .ok_or(())?;
            let deadline = manager.deadline;
            Ok(Some(HardHardDirectCommit {
                locks: Some(PairCommitLocks {
                    state,
                    pending,
                    bindings,
                    diagnostics,
                    manager,
                }),
                peer: peer.to_owned(),
                scope: scope.clone(),
                deadline,
                committed: false,
            }))
        };
        timeout(Duration::from_millis(100), acquire)
            .await
            .map_err(|_| ())?
    }
}
