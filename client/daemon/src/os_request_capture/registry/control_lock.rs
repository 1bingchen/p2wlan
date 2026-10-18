//! One metadata owner. Packet callbacks only try; the single control actor may
//! yield within its caller's existing deadline. No guard crosses an IO await.
use crate::os_request_capture::plan::CaptureFailure;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::LockResult;
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError, TryLockResult};
use tokio::sync::Notify;

pub(super) struct ControlState<T> {
    inner: Mutex<T>,
    changed: Notify,
    waiting: AtomicBool,
}

pub(super) struct StateGuard<'a, T> {
    inner: Option<MutexGuard<'a, T>>,
    changed: &'a Notify,
}

struct Waiter<'a>(&'a AtomicBool);
impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<T> ControlState<T> {
    #[cfg(any(target_os = "linux", test))]
    pub(super) fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            changed: Notify::new(),
            waiting: AtomicBool::new(false),
        }
    }

    fn wrap<'a>(&'a self, inner: MutexGuard<'a, T>) -> StateGuard<'a, T> {
        StateGuard {
            inner: Some(inner),
            changed: &self.changed,
        }
    }

    pub(super) fn try_lock(&self) -> TryLockResult<StateGuard<'_, T>> {
        match self.inner.try_lock() {
            Ok(guard) => Ok(self.wrap(guard)),
            Err(TryLockError::WouldBlock) => Err(TryLockError::WouldBlock),
            Err(TryLockError::Poisoned(error)) => Err(TryLockError::Poisoned(PoisonError::new(
                self.wrap(error.into_inner()),
            ))),
        }
    }

    #[cfg(test)]
    pub(super) fn lock(&self) -> LockResult<StateGuard<'_, T>> {
        self.inner
            .lock()
            .map(|guard| self.wrap(guard))
            .map_err(|error| PoisonError::new(self.wrap(error.into_inner())))
    }

    /// At most one control waiter; no packet worker enters this path. The
    /// deadline belongs to the original command/window, never a new timeout.
    pub(super) async fn lock_until(
        &self,
        end: tokio::time::Instant,
    ) -> Result<StateGuard<'_, T>, CaptureFailure> {
        self.waiting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CaptureFailure::Contended)?;
        let _waiter = Waiter(&self.waiting);
        loop {
            if tokio::time::Instant::now() >= end {
                return Err(CaptureFailure::ControlNotReady);
            }
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // Subscribe before trying, so release between try and await is
            // retained. Poison remains terminal instead of being waited out.
            changed.as_mut().enable();
            match self.try_lock() {
                Ok(guard) => {
                    if tokio::time::Instant::now() >= end {
                        return Err(CaptureFailure::ControlNotReady);
                    }
                    return Ok(guard);
                }
                Err(TryLockError::Poisoned(_)) => return Err(CaptureFailure::Contended),
                Err(TryLockError::WouldBlock) => {}
            }
            tokio::time::timeout_at(end, changed)
                .await
                .map_err(|_| CaptureFailure::ControlNotReady)?;
        }
    }
}

impl<T> Deref for StateGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner
            .as_deref()
            .expect("state guard exists until drop")
    }
}
impl<T> DerefMut for StateGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner
            .as_deref_mut()
            .expect("state guard exists until drop")
    }
}
impl<T> Drop for StateGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.inner.take());
        // Waking can call an executor's waker; release the metadata first.
        self.changed.notify_one();
    }
}

#[cfg(test)]
mod tests;
