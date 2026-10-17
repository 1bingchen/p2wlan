//! Try-only original-permit qualification held through the sole final commit.
use super::{RoomAuthorization, RoomSendPermit, RoomSnapshot};
use std::sync::{MutexGuard, TryLockError};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OriginalRoomSendFailure {
    MissingOriginal,
    Contended,
    Stale,
}

pub(crate) struct OriginalRoomSendGuard<'a> {
    snapshot: Option<MutexGuard<'a, Option<RoomSnapshot>>>,
    original: Option<&'a RoomSendPermit>,
}

impl OriginalRoomSendGuard<'_> {
    pub(crate) fn is_current_at(&self, now: Instant) -> bool {
        match (&self.snapshot, self.original) {
            (None, None) => true,
            (Some(snapshot), Some(original)) => snapshot.as_ref().is_some_and(|current| {
                std::sync::Arc::ptr_eq(&current.live, &original.live)
                    && original.live.load(std::sync::atomic::Ordering::Acquire)
                    && now < original.expires_at
                    && now < current.expires_at
            }),
            _ => false,
        }
    }
}

impl RoomAuthorization {
    /// Capture once at the original REQUEST entrance, before any wait/queue.
    pub(crate) fn try_capture_original_send_permit(
        &self,
        peer_id: &str,
        peer_ip: &str,
        local_ip: &str,
    ) -> Result<Option<RoomSendPermit>, OriginalRoomSendFailure> {
        use OriginalRoomSendFailure::*;
        if !self.enabled {
            return Ok(None);
        }
        let snapshot = match self.snapshot.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(Contended),
            Err(TryLockError::Poisoned(_)) => return Err(MissingOriginal),
        };
        let current = snapshot.as_ref().ok_or(MissingOriginal)?;
        if !current.live.load(std::sync::atomic::Ordering::Acquire)
            || Instant::now() >= current.expires_at
            || current.local_ip != local_ip
            || current.peers.get(peer_id).is_none_or(|ip| ip != peer_ip)
        {
            return Err(Stale);
        }
        Ok(Some(RoomSendPermit {
            live: current.live.clone(),
            expires_at: current.expires_at,
        }))
    }

    #[cfg(test)]
    pub(crate) fn with_original_snapshot_held_for_test<R>(&self, action: impl FnOnce() -> R) -> R {
        let _held = self.snapshot.lock().unwrap();
        action()
    }

    pub(crate) fn try_original_send_guard<'a>(
        &'a self,
        original: Option<&'a RoomSendPermit>,
        peer_id: &str,
        peer_ip: &str,
        local_ip: &str,
    ) -> Result<OriginalRoomSendGuard<'a>, OriginalRoomSendFailure> {
        use OriginalRoomSendFailure::*;
        if !self.enabled {
            return if original.is_none() {
                Ok(OriginalRoomSendGuard {
                    snapshot: None,
                    original: None,
                })
            } else {
                Err(Stale)
            };
        }
        let original = original.ok_or(MissingOriginal)?;
        let snapshot = match self.snapshot.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(Contended),
            Err(TryLockError::Poisoned(_)) => return Err(MissingOriginal),
        };
        if !snapshot.as_ref().is_some_and(|current| {
            current.local_ip == local_ip
                && current.peers.get(peer_id).is_some_and(|ip| ip == peer_ip)
                && std::sync::Arc::ptr_eq(&current.live, &original.live)
        }) {
            return Err(Stale);
        }
        let guard = OriginalRoomSendGuard {
            snapshot: Some(snapshot),
            original: Some(original),
        };
        if !guard.is_current_at(Instant::now()) {
            return Err(Stale);
        }
        Ok(guard)
    }
}

#[cfg(test)]
mod tests;
