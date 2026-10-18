//! Weak handles to the actual daemon session/emit registries. A retained
//! capture must not keep the WireGuard worker or its outbound sink alive.
use super::*;

type EmitRegistry = Mutex<HashMap<String, Weak<Mutex<()>>>>;

pub(crate) struct OriginalKernelTransportOwners {
    sessions: Weak<Mutex<HashMap<String, PeerTransportSessions>>>,
    emit: Weak<EmitRegistry>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) struct OriginalKernelTransportCurrent {
    sessions: Arc<Mutex<HashMap<String, PeerTransportSessions>>>,
    emit: Arc<EmitRegistry>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OriginalKernelEmitFailure {
    Registry,
    Emit,
}

impl WireGuardTransport {
    pub(crate) fn original_kernel_transport_owners(&self) -> OriginalKernelTransportOwners {
        OriginalKernelTransportOwners {
            sessions: Arc::downgrade(&self.sessions),
            emit: Arc::downgrade(&self.outbound_emit_locks),
        }
    }
}

impl OriginalKernelTransportOwners {
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        self.sessions.ptr_eq(&other.sessions) && self.emit.ptr_eq(&other.emit)
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(crate) fn upgrade(&self) -> Option<OriginalKernelTransportCurrent> {
        Some(OriginalKernelTransportCurrent {
            sessions: self.sessions.upgrade()?,
            emit: self.emit.upgrade()?,
        })
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl OriginalKernelTransportCurrent {
    pub(crate) fn try_emit_guard(
        &self,
        peer: &str,
    ) -> std::result::Result<OwnedMutexGuard<()>, OriginalKernelEmitFailure> {
        WireGuardTransport::try_outbound_emit_lock_in(&self.emit, peer)
            .ok_or(OriginalKernelEmitFailure::Registry)?
            .try_lock_owned()
            .map_err(|_| OriginalKernelEmitFailure::Emit)
    }

    pub(crate) fn try_session_guard<'a>(
        &'a self,
        peer: &'a str,
        tx: &OriginalEncryptionSource,
        rx: &OriginalSessionSource,
    ) -> std::result::Result<OriginalOverlaySessionGuard<'a>, OriginalOverlaySessionFailure> {
        OriginalOverlaySessionGuard::try_original_registry(&self.sessions, peer, tx, rx)
    }
}

#[cfg(all(unix, test))]
mod tests;
