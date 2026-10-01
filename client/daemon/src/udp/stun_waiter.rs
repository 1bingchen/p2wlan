//! Reader-owned STUN completions with cancellation-safe registration leases.
//! The mutex protects only short map operations; no I/O or await holds it.

use super::{oneshot, Arc, HashMap, StdMutex, StunResponse, StunTransactionId};

const MAX_STUN_WAITERS: usize = 256;

struct Entry {
    owner: Arc<()>,
    sender: oneshot::Sender<StunResponse>,
}

#[derive(Clone, Default)]
pub(super) struct StunWaiters(Arc<StdMutex<HashMap<StunTransactionId, Entry>>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistrationError {
    Full,
    Duplicate,
}

impl RegistrationError {
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Full => "stun_waiter_capacity",
            Self::Duplicate => "stun_transaction_in_use",
        }
    }
}

pub(super) struct StunWaiterLease {
    waiters: StunWaiters,
    transaction: StunTransactionId,
    owner: Arc<()>,
}

impl StunWaiters {
    pub(super) fn register(
        &self,
        transaction: StunTransactionId,
        sender: oneshot::Sender<StunResponse>,
    ) -> Result<StunWaiterLease, RegistrationError> {
        let mut entries = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.contains_key(&transaction) {
            return Err(RegistrationError::Duplicate);
        }
        if entries.len() >= MAX_STUN_WAITERS {
            return Err(RegistrationError::Full);
        }
        let owner = Arc::new(());
        entries.insert(
            transaction,
            Entry {
                owner: owner.clone(),
                sender,
            },
        );
        Ok(StunWaiterLease {
            waiters: self.clone(),
            transaction,
            owner,
        })
    }

    pub(super) fn take(
        &self,
        transaction: &StunTransactionId,
    ) -> Option<oneshot::Sender<StunResponse>> {
        let entry = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(transaction);
        entry.map(|entry| entry.sender)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl Drop for StunWaiterLease {
    fn drop(&mut self) {
        let removed = {
            let mut entries = self
                .waiters
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if entries
                .get(&self.transaction)
                .is_some_and(|entry| Arc::ptr_eq(&entry.owner, &self.owner))
            {
                entries.remove(&self.transaction)
            } else {
                None
            }
        };
        // A receiver wake must not run while the registry mutex is held.
        drop(removed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_a_pending_request_reclaims_its_waiter_without_another_packet() {
        let waiters = StunWaiters::default();
        let (sender, receiver) = oneshot::channel();
        let lease = waiters.register([1; 12], sender).unwrap();
        let mut pending = Box::pin(async move {
            let _lease = lease;
            receiver.await
        });
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(pending.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(waiters.len(), 1);
        drop(pending);
        assert_eq!(waiters.len(), 0);
    }

    #[test]
    fn a_completed_old_lease_cannot_remove_a_reused_transaction() {
        let waiters = StunWaiters::default();
        let (first, _first_receiver) = oneshot::channel();
        let old = waiters.register([2; 12], first).unwrap();
        let (duplicate, _) = oneshot::channel();
        assert!(matches!(
            waiters.register([2; 12], duplicate),
            Err(RegistrationError::Duplicate)
        ));
        assert!(waiters.take(&[2; 12]).is_some());
        let (second, _second_receiver) = oneshot::channel();
        let current = waiters.register([2; 12], second).unwrap();
        drop(old);
        assert_eq!(waiters.len(), 1);
        drop(current);
        assert_eq!(waiters.len(), 0);
    }

    #[test]
    fn live_waiter_capacity_rejects_without_evicting_existing_requests() {
        let waiters = StunWaiters::default();
        let mut leases = Vec::new();
        for id in 0..MAX_STUN_WAITERS {
            let mut transaction = [0; 12];
            transaction[..8].copy_from_slice(&(id as u64).to_be_bytes());
            let (sender, receiver) = oneshot::channel();
            leases.push((waiters.register(transaction, sender).unwrap(), receiver));
        }
        let (sender, _) = oneshot::channel();
        assert!(matches!(
            waiters.register([255; 12], sender),
            Err(RegistrationError::Full)
        ));
        assert_eq!(waiters.len(), MAX_STUN_WAITERS);
        drop(leases);
        assert_eq!(waiters.len(), 0);
    }
}
