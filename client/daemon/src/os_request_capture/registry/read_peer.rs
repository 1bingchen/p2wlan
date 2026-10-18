//! First-read peer expectations. Neither retries nor encryption can refill a
//! missing first capture. No connection state or final once authority lives here.
use super::*;
use crate::overlay_requests::{OverlayCreditOutcome, OverlayCreditUnknown};
use crate::peer::OriginalKernelReadPeer;
use crate::transport::OriginalEncryptionSource;

pub(super) struct FirstReadPeer {
    original: Result<OriginalKernelReadPeer, OverlayCreditOutcome>,
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct ReadPeerSnapshot {
    known: bool,
    network_generation: Option<u64>,
    peer_lifecycle: Option<u64>,
    capture_failure: Option<String>,
}

impl FirstReadPeer {
    fn capture(scope: &CaptureSession, plan: &RegisteredFlowPlan) -> Self {
        let original = scope
            .peers
            .upgrade()
            .ok_or(OverlayCreditOutcome::Unknown(
                OverlayCreditUnknown::OriginalAuthorization,
            ))
            .and_then(|peers| {
                peers.try_capture_original_kernel_read_peer(&plan.peer, plan.flow.dst_v4)
            });
        if original.is_err() {
            scope.gap();
        }
        Self { original }
    }

    fn is_current(&self, peers: &PeerManager, at: Instant) -> bool {
        self.original
            .as_ref()
            .is_ok_and(|original| original.try_identity_at(peers, at).is_ok())
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> ReadPeerSnapshot {
        ReadPeerSnapshot {
            known: self.original.is_ok(),
            network_generation: self.original.as_ref().ok().map(|peer| peer.generation()),
            peer_lifecycle: self
                .original
                .as_ref()
                .ok()
                .map(|peer| peer.lifecycle().value()),
            // Diagnostic only. This text is never parsed to drive control flow.
            capture_failure: self
                .original
                .as_ref()
                .err()
                .map(|failure| format!("{failure:?}")),
        }
    }
}

impl CaptureSession {
    pub(super) fn first_read_peers(
        &self,
        flow: &mut FlowState,
        slots: &[usize],
    ) -> Vec<Arc<FirstReadPeer>> {
        // One bounded, synchronous observation before the original read
        // context is handed to any async forwarding/route/crypto consumer.
        let observed = Arc::new(FirstReadPeer::capture(self, &flow.plan));
        slots
            .iter()
            .map(|slot| {
                flow.requests[*slot]
                    .first_peer
                    .get_or_insert_with(|| observed.clone())
                    .clone()
            })
            .collect()
    }
}

impl KernelReadBinding {
    pub(super) fn original_peer_identity_is_current(
        &self,
        scope: &CaptureSession,
        at: Instant,
    ) -> bool {
        scope.peers.upgrade().is_some_and(|peers| {
            !self.original_peers.is_empty()
                && self.original_peers.len() == self.slots.len()
                && self
                    .original_peers
                    .iter()
                    .all(|original| original.is_current(&peers, at))
        })
    }

    pub(crate) fn original_peer_matches_encryption(
        &self,
        owner: &Weak<PeerManager>,
        generation: u64,
        encryption: &OriginalEncryptionSource,
    ) -> bool {
        !self.original_peers.is_empty()
            && self.original_peers.len() == self.slots.len()
            && self.original_peers.iter().all(|original| {
                original.original.as_ref().is_ok_and(|peer| {
                    peer.matches_original_encryption(owner, generation, encryption)
                })
            })
    }
}

#[cfg(all(unix, test))]
mod tests;
