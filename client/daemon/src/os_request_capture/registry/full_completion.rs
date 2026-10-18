//! Resume metadata work on the existing descriptor actor after a real Full.
//! No task, packet retry, fresh deadline or replacement native fact is created.
use super::{CaptureSession, FullRetentionLossReason, KernelReadBinding};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, TryLockError};
use tokio::sync::Notify;

pub(super) struct CompletionSignal {
    pending: AtomicBool,
    ready: Notify,
}

impl CompletionSignal {
    pub(super) fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            ready: Notify::new(),
        }
    }

    fn request(&self) {
        self.pending.store(true, Ordering::Release);
        self.ready.notify_one();
    }
}

impl KernelReadBinding {
    pub(super) fn complete_original_full_or_notify(self: &Arc<Self>, scope: &Arc<CaptureSession>) {
        match scope.state.try_lock() {
            Ok(mut state) => scope.try_complete_original_frames(&mut state, self.flow, &self.slots),
            Err(TryLockError::WouldBlock) => {
                // This read already owns a sealed actual Full observation.
                // Its marker is bounded by the same 1024-entry read index.
                self.full_completion_pending.store(true, Ordering::Release);
                scope.pending_full.request();
            }
            Err(TryLockError::Poisoned(_)) => {
                scope.original_full_retention_lost(FullRetentionLossReason::HistoryContended);
            }
        }
    }
}

impl CaptureSession {
    pub(in crate::os_request_capture) async fn full_completion_ready(&self) {
        self.pending_full.ready.notified().await;
    }

    pub(in crate::os_request_capture) async fn full_metadata_released(&self) {
        self.state.completion_released().await;
    }

    pub(in crate::os_request_capture) fn full_completion_pending(&self) -> bool {
        self.pending_full.pending.load(Ordering::Acquire)
    }

    pub(in crate::os_request_capture) fn complete_pending_fulls(self: &Arc<Self>) {
        if !self.full_completion_pending() || !self.is_live(std::time::Instant::now()) {
            return;
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(_)) => {
                self.pending_full.pending.store(false, Ordering::Release);
                self.original_full_retention_lost(FullRetentionLossReason::HistoryContended);
                return;
            }
        };
        // Clear only after acquisition. A contended attempt keeps its marker
        // and waits for an unlock, rather than polling or losing the event.
        self.pending_full.pending.store(false, Ordering::Release);
        for index in 0..state.read_history.len() {
            let read = &state.read_history[index];
            if !read.full_completion_pending.swap(false, Ordering::AcqRel) {
                continue;
            }
            let read = read.clone();
            // The original transaction still checks its original window and
            // current owners try-only. Existing terminal outcomes are skipped.
            self.try_complete_original_frames(&mut state, read.flow, &read.slots);
        }
    }
}

#[cfg(test)]
mod tests;
