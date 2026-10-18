//! Borrowed original active-session qualification; no credit or second state.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OriginalOverlaySessionFailure {
    Contended,
    UnknownAuthorization,
    Stale,
}

pub(crate) struct OriginalOverlaySessionGuard<'a> {
    owner: Weak<Mutex<HashMap<String, PeerTransportSessions>>>,
    sessions: tokio::sync::MutexGuard<'a, HashMap<String, PeerTransportSessions>>,
    peer_id: &'a str,
    session_instance: u64,
    lifecycle: PeerSessionGeneration,
}

impl OriginalOverlaySessionGuard<'_> {
    pub(crate) fn matches_original_sources(
        &self,
        tx: &OriginalEncryptionSource,
        rx: &OriginalSessionSource,
    ) -> bool {
        self.owner.ptr_eq(&rx.owner)
            && tx.matches_original_receive_source(rx)
            && rx.peer_id() == self.peer_id
            && rx.session_instance() == self.session_instance
            && rx.authorized_peer_lifecycle() == Some(self.lifecycle)
    }

    pub(crate) fn lifecycle(&self) -> PeerSessionGeneration {
        self.lifecycle
    }

    /// Called again after all publication guards and just before the once CAS.
    /// Time-based expiry is checked here, without mutating or pruning sessions.
    pub(crate) fn is_current(&self) -> bool {
        self.sessions
            .get(self.peer_id)
            .and_then(|peer| peer.active.as_ref())
            .is_some_and(|active| {
                active.session_instance == self.session_instance
                    && active.authorized_peer_lifecycle == Some(self.lifecycle)
                    && !active.session.is_expired()
            })
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl<'a> OriginalOverlaySessionGuard<'a> {
    pub(in crate::transport) fn try_original_registry(
        registry: &'a Arc<Mutex<HashMap<String, PeerTransportSessions>>>,
        peer_id: &'a str,
        tx: &OriginalEncryptionSource,
        rx: &OriginalSessionSource,
    ) -> std::result::Result<Self, OriginalOverlaySessionFailure> {
        use OriginalOverlaySessionFailure as Failure;
        if !rx.owner.ptr_eq(&Arc::downgrade(registry))
            || rx.peer_id() != peer_id
            || rx.original_role() != OriginalSessionRole::Active
        {
            return Err(Failure::Stale);
        }
        let lifecycle = tx
            .authorized_peer_lifecycle()
            .filter(|life| *life != PeerSessionGeneration::UNBOUND)
            .ok_or(Failure::UnknownAuthorization)?;
        if !tx.matches_original_receive_source(rx) {
            return Err(Failure::Stale);
        }
        let guard = Self {
            owner: Arc::downgrade(registry),
            sessions: registry.try_lock().map_err(|_| Failure::Contended)?,
            peer_id,
            session_instance: rx.session_instance(),
            lifecycle,
        };
        guard.is_current().then_some(guard).ok_or(Failure::Stale)
    }
}

impl WireGuardTransport {
    pub(crate) fn try_original_overlay_ingress_session_guard<'a>(
        &'a self,
        peer_id: &'a str,
        rx: &OriginalSessionSource,
    ) -> std::result::Result<OriginalOverlaySessionGuard<'a>, OriginalOverlaySessionFailure> {
        use OriginalOverlaySessionFailure as Failure;
        if !rx.belongs_to(self)
            || rx.peer_id() != peer_id
            || rx.original_role() != OriginalSessionRole::Active
        {
            return Err(Failure::Stale);
        }
        let lifecycle = rx
            .authorized_peer_lifecycle()
            .filter(|life| *life != PeerSessionGeneration::UNBOUND)
            .ok_or(Failure::UnknownAuthorization)?;
        let sessions = self.sessions.try_lock().map_err(|_| Failure::Contended)?;
        let guard = OriginalOverlaySessionGuard {
            owner: Arc::downgrade(&self.sessions),
            sessions,
            peer_id,
            session_instance: rx.session_instance(),
            lifecycle,
        };
        if !guard.is_current() {
            return Err(Failure::Stale);
        }
        Ok(guard)
    }
    /// Caller holds original per-peer emit, then original network epoch.
    /// Historical pending/previous keys cannot inherit a later promotion.
    pub(crate) fn try_original_overlay_session_guard<'a>(
        &'a self,
        peer_id: &'a str,
        tx: &OriginalEncryptionSource,
        rx: &OriginalSessionSource,
    ) -> std::result::Result<OriginalOverlaySessionGuard<'a>, OriginalOverlaySessionFailure> {
        use OriginalOverlaySessionFailure as Failure;
        if !tx.belongs_to(self)
            || !rx.belongs_to(self)
            || tx.peer_id() != peer_id
            || rx.peer_id() != peer_id
            || tx.original_role() != OriginalSessionRole::Active
            || rx.original_role() != OriginalSessionRole::Active
            || tx.session_instance() != rx.session_instance()
        {
            return Err(Failure::Stale);
        }
        let lifecycle = tx
            .authorized_peer_lifecycle()
            .filter(|life| *life != PeerSessionGeneration::UNBOUND)
            .ok_or(Failure::UnknownAuthorization)?;
        if rx.authorized_peer_lifecycle() != Some(lifecycle) {
            return Err(Failure::Stale);
        }
        let guard = self.try_original_overlay_ingress_session_guard(peer_id, rx)?;
        if !guard.matches_original_sources(tx, rx) {
            return Err(Failure::Stale);
        }
        Ok(guard)
    }
}
