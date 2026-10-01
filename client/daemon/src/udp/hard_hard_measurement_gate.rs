//! Per-transport exclusion for the allocation-sensitive HH measurement window.
//!
//! The bounded HH session owner acquires this before measurement and retains it
//! until its first scheduled probe, or the complete first socket wave for a
//! fixed anchor. Ordinary traffic never acquires this gate: it limits local
//! HH measurement interference, but does not isolate the shared NAT allocator.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::UdpTransport;
use crate::PunchSessionCancellation;

const GENERATION_RECHECK_INTERVAL: Duration = Duration::from_millis(25);

/// Clones refer to the same permit. Releasing any clone releases all of them;
/// otherwise dropping the final session/snapshot owner releases the permit.
#[derive(Clone, Debug)]
pub(crate) struct HardHardMeasurementLease {
    permit: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
}

impl HardHardMeasurementLease {
    pub(super) fn on_probe_handoff(&self, strategy: crate::peer::HardHardProbeStrategy) {
        if strategy != crate::peer::HardHardProbeStrategy::FixedAnchor {
            self.release();
        }
    }

    /// Uses the same permit, not a second owner. Dropping the sweep future or
    /// returning early also releases it while other record snapshots survive.
    pub(super) fn release_after_scope(self) -> HardHardMeasurementReleaseGuard {
        HardHardMeasurementReleaseGuard { lease: Some(self) }
    }

    pub(crate) fn release(&self) {
        // No user code or await runs under this mutex. Recovering a poisoned
        // lock still drops the permit instead of permanently blocking HH work.
        let permit = self
            .permit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(permit);
    }
}

pub(super) struct HardHardMeasurementReleaseGuard {
    lease: Option<HardHardMeasurementLease>,
}

impl HardHardMeasurementReleaseGuard {
    pub(super) fn release(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.release();
        }
    }
}

impl Drop for HardHardMeasurementReleaseGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl UdpTransport {
    /// Wait only within the caller's session deadline. Generation is checked
    /// while queued and again after admission; callers still fence identity at
    /// measurement and send boundaries because this lease is not that owner.
    pub(crate) async fn acquire_hard_hard_measurement_lease(
        &self,
        network_generation: u64,
        cancellation: &Arc<PunchSessionCancellation>,
        deadline: Instant,
    ) -> Option<HardHardMeasurementLease> {
        acquire_measurement_lease(
            self.hard_hard_measurement_gate.clone(),
            network_generation,
            || self.peers.current_network_generation_sync(),
            cancellation,
            deadline,
        )
        .await
    }
}

async fn acquire_measurement_lease(
    gate: Arc<Semaphore>,
    network_generation: u64,
    current_generation: impl Fn() -> u64,
    cancellation: &PunchSessionCancellation,
    deadline: Instant,
) -> Option<HardHardMeasurementLease> {
    // Keep the same acquisition future across generation checks so unrelated
    // timer ticks cannot discard this waiter's place in the semaphore queue.
    let acquire = gate.acquire_owned();
    tokio::pin!(acquire);
    loop {
        let rejection = if cancellation.is_cancelled() {
            Some("hard_hard_measurement_lease_cancelled")
        } else if current_generation() != network_generation {
            Some("hard_hard_measurement_lease_network_changed")
        } else if Instant::now() >= deadline {
            Some("hard_hard_measurement_lease_deadline")
        } else {
            None
        };
        if let Some(reason) = rejection {
            tracing::debug!(reason, network_generation, "HH measurement lease refused");
            return None;
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => continue,
            _ = tokio::time::sleep_until(deadline.into()) => continue,
            result = &mut acquire => {
                let permit = result.ok()?;
                // A cancellation, deadline or generation advance can race the
                // semaphore wake. Drop the granted permit on every stale exit.
                if cancellation.is_cancelled()
                    || current_generation() != network_generation
                    || Instant::now() >= deadline
                {
                    return None;
                }
                return Some(HardHardMeasurementLease {
                    permit: Arc::new(Mutex::new(Some(permit))),
                });
            }
            _ = tokio::time::sleep(GENERATION_RECHECK_INTERVAL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[tokio::test]
    async fn fixed_anchor_keeps_the_same_permit_until_all_first_wave_sockets_finish() {
        for sockets in [2, 4, 8] {
            let gate = Arc::new(Semaphore::new(1));
            let cancellation = PunchSessionCancellation::default();
            let lease = acquire_measurement_lease(gate.clone(), 3, || 3, &cancellation, deadline())
                .await
                .unwrap();
            let mut first_wave = lease.clone().release_after_scope();
            for _ in 0..sockets {
                lease.on_probe_handoff(crate::peer::HardHardProbeStrategy::FixedAnchor);
                assert_eq!(gate.available_permits(), 0);
                assert!(gate.clone().try_acquire_owned().is_err());
            }
            first_wave.release();
            assert_eq!(gate.available_permits(), 1);
            // The authoritative record can still retain this clone, and the
            // retransmission wave must not consume a second measurement slot.
            lease.on_probe_handoff(crate::peer::HardHardProbeStrategy::FixedAnchor);
            assert_eq!(gate.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn ordinary_strategy_releases_on_first_handoff_and_abort_releases_anchor_scope() {
        for strategy in [
            crate::peer::HardHardProbeStrategy::Predictable,
            crate::peer::HardHardProbeStrategy::Birthday,
        ] {
            let gate = Arc::new(Semaphore::new(1));
            let cancellation = PunchSessionCancellation::default();
            let lease = acquire_measurement_lease(gate.clone(), 3, || 3, &cancellation, deadline())
                .await
                .unwrap();
            lease.on_probe_handoff(strategy);
            assert_eq!(gate.available_permits(), 1);
        }
        let gate = Arc::new(Semaphore::new(1));
        let cancellation = PunchSessionCancellation::default();
        let record_snapshot =
            acquire_measurement_lease(gate.clone(), 3, || 3, &cancellation, deadline())
                .await
                .unwrap();
        let guard = record_snapshot.clone().release_after_scope();
        let mut worker = Box::pin(async move {
            let _first_wave = guard;
            std::future::pending::<()>().await;
        });
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(worker.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(gate.available_permits(), 0);
        drop(worker);
        assert_eq!(gate.available_permits(), 1);
        drop(record_snapshot);
        assert_eq!(gate.available_permits(), 1);
    }

    #[tokio::test]
    async fn prepared_or_failed_first_wave_releases_even_with_unfinished_socket_count() {
        for completed in 0..4 {
            let gate = Arc::new(Semaphore::new(1));
            let cancellation = PunchSessionCancellation::default();
            let lease = acquire_measurement_lease(gate.clone(), 3, || 3, &cancellation, deadline())
                .await
                .unwrap();
            {
                let _first_wave = lease.clone().release_after_scope();
                for _ in 0..completed {
                    lease.on_probe_handoff(crate::peer::HardHardProbeStrategy::FixedAnchor);
                }
                assert_eq!(gate.available_permits(), 0);
                // A prepared pair or a terminal worker failure exits scope;
                // no count-based owner can leave an unreachable permit here.
            }
            assert_eq!(gate.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn release_and_last_clone_drop_return_the_single_permit() {
        let gate = Arc::new(Semaphore::new(1));
        let cancellation = PunchSessionCancellation::default();
        let first = acquire_measurement_lease(gate.clone(), 3, || 3, &cancellation, deadline())
            .await
            .unwrap();
        let retained = first.clone();
        drop(first);
        assert_eq!(gate.available_permits(), 0);
        retained.release();
        retained.release();
        assert_eq!(gate.available_permits(), 1);
        let second = acquire_measurement_lease(gate.clone(), 3, || 3, &cancellation, deadline())
            .await
            .unwrap();
        drop(retained);
        assert_eq!(gate.available_permits(), 0);
        drop(second);
        assert_eq!(gate.available_permits(), 1);
    }

    #[tokio::test]
    async fn queued_waiter_cannot_survive_cancel_generation_or_deadline() {
        for boundary in ["cancel", "generation", "deadline"] {
            let gate = Arc::new(Semaphore::new(1));
            let held = gate.clone().acquire_owned().await.unwrap();
            let generation = AtomicU64::new(7);
            let cancellation = PunchSessionCancellation::default();
            let expires = if boundary == "deadline" {
                Instant::now() + Duration::from_millis(5)
            } else {
                deadline()
            };
            let waiting = acquire_measurement_lease(
                gate.clone(),
                7,
                || generation.load(Ordering::Acquire),
                &cancellation,
                expires,
            );
            tokio::pin!(waiting);
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(waiting.as_mut(), cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            match boundary {
                "cancel" => cancellation.cancel_for_hard_hard_cleanup(),
                "generation" => generation.store(8, Ordering::Release),
                _ => {}
            }
            assert!(tokio::time::timeout(Duration::from_millis(200), waiting)
                .await
                .unwrap()
                .is_none());
            assert_eq!(gate.available_permits(), 0);
            drop(held);
            assert_eq!(gate.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn aborted_waiter_does_not_block_its_successor() {
        let gate = Arc::new(Semaphore::new(1));
        let held = gate.clone().acquire_owned().await.unwrap();
        let cancellation = PunchSessionCancellation::default();
        let mut waiting = Box::pin(acquire_measurement_lease(
            gate.clone(),
            1,
            || 1,
            &cancellation,
            deadline(),
        ));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(waiting.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(waiting);
        drop(held);
        let successor = acquire_measurement_lease(gate.clone(), 1, || 1, &cancellation, deadline())
            .await
            .unwrap();
        assert_eq!(gate.available_permits(), 0);
        drop(successor);
        assert_eq!(gate.available_permits(), 1);
    }
}
