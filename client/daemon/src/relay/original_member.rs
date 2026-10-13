//! Borrowed qualification against original Relay membership/lifecycle owners.
//! No final credit consumer: the caller must separately freeze the outer slot,
//! authenticated peer/session, generation and canonical request through commit.
use super::{
    send_origin::RelayBranchDisposition, RelayFullSendFact, RelayTransport, RendezvousRoutes,
};
use p2pnet_relay::{
    OriginalRelayFrameRead, RelayClient, RelayClientOpenError, RelayClientOpenGuard,
};
use std::sync::{atomic::Ordering, Arc, Mutex, MutexGuard, TryLockError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelayMemberFailure {
    UnknownWrite,
    StalePublication,
    Stopped,
    StaleMember,
    UnknownReader,
    Retired,
    #[allow(dead_code)] // Staged close qualifier, not yet a final credit consumer.
    Closed,
    ContendedRoutes,
    ContendedLive,
    #[allow(dead_code)] // Staged close qualifier, not yet a final credit consumer.
    ContendedClose,
}

pub(crate) struct RelayMemberGuard<'a> {
    transport: &'a RelayTransport,
    endpoint: &'a str,
    routes: Option<MutexGuard<'a, RendezvousRoutes>>,
    _live: MutexGuard<'a, bool>,
}

fn try_guard<T>(
    lock: &Mutex<T>,
    conflict: RelayMemberFailure,
) -> Result<MutexGuard<'_, T>, RelayMemberFailure> {
    match lock.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(TryLockError::WouldBlock) => Err(conflict),
    }
}

impl RelayMemberGuard<'_> {
    fn client(&self) -> Result<&Arc<RelayClient>, RelayMemberFailure> {
        match &self.routes {
            Some(routes) => routes
                .clients
                .get(self.endpoint)
                .ok_or(RelayMemberFailure::StaleMember),
            None => Ok(&self.transport.client),
        }
    }

    /// Borrow from this stable member guard instead of building a self-referential
    /// routes+client guard or retaining a strong client after membership removal.
    #[allow(dead_code)] // Staged until the separate final transaction is connected.
    pub(crate) fn try_open_guard(&self) -> Result<RelayClientOpenGuard<'_>, RelayMemberFailure> {
        self.client()?
            .try_open_guard()
            .map_err(|error| match error {
                RelayClientOpenError::Closed => RelayMemberFailure::Closed,
                RelayClientOpenError::Contended => RelayMemberFailure::ContendedClose,
            })
    }
}

impl RelayTransport {
    /// Caller must hold the original current Relay slot read guard through use.
    /// The RX id must come from its original envelope, never a current snapshot.
    /// Acquire routes -> live here, then close via the returned member guard.
    /// All acquisition is try-only; no IO/await/callback may occur while held.
    #[allow(dead_code)] // Staged primitive: canonical once/native credit is separate.
    pub(crate) fn try_original_member_guard<'a>(
        &'a self,
        tx: &'a RelayFullSendFact,
        rx: &OriginalRelayFrameRead,
        original_rx_connection_id: u64,
    ) -> Result<RelayMemberGuard<'a>, RelayMemberFailure> {
        if tx.disposition() != RelayBranchDisposition::FullWrite || tx.original().is_none() {
            return Err(RelayMemberFailure::UnknownWrite);
        }
        if original_rx_connection_id != self.connection_id()
            || !tx.matches_publication(self.connection_id(), &self.write_boundaries_live)
        {
            return Err(RelayMemberFailure::StalePublication);
        }
        let routes = match &self.rendezvous {
            Some(pool) => {
                let routes = try_guard(&pool.routes, RelayMemberFailure::ContendedRoutes)?;
                if pool.stopped.load(Ordering::Acquire) {
                    return Err(RelayMemberFailure::Stopped);
                }
                Some(routes)
            }
            None if tx.endpoint() == self.endpoint() => None,
            None => return Err(RelayMemberFailure::StaleMember),
        };
        let live = try_guard(
            &self.write_boundaries_live,
            RelayMemberFailure::ContendedLive,
        )?;
        if !*live {
            return Err(RelayMemberFailure::Retired);
        }
        let guard = RelayMemberGuard {
            transport: self,
            endpoint: tx.endpoint(),
            routes,
            _live: live,
        };
        let client = guard.client()?;
        if !tx.matches_client(client) {
            return Err(RelayMemberFailure::StaleMember);
        }
        if !rx.belongs_to_client(client) {
            return Err(RelayMemberFailure::UnknownReader);
        }
        Ok(guard)
    }
}
