//! Move-only observations of concrete local Vec owners, without payloads.

use super::{RecordDisposition, ResourceCapture};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BufferStage {
    ActiveOriginal,
    RetryPlaintext,
    PreparationPlaintext,
    SerializedWire,
    /// Only the routed Vec still owned locally around DataPlane reserve.
    DataplaneAdmissionWait,
}

impl BufferStage {
    pub(super) const COUNT: usize = 5;

    pub(super) fn index(self) -> usize {
        self as usize
    }
}

#[derive(Default)]
pub(super) struct BufferCounters {
    pub(super) scope_observed: AtomicBool,
    pub(super) live_buffers: AtomicU64,
    pub(super) len: AtomicU64,
    pub(super) capacity: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BufferSnapshot {
    pub(crate) live_buffers: u64,
    pub(crate) len: u64,
    pub(crate) capacity: u64,
}

/// One observed immutable buffer at its lexical owner, never a cloneable lease.
/// Moving a Vec between owners must end/move its existing lease before another
/// observation. No address, bytes, packet identity or source owner is retained.
pub(crate) struct OwnedBufferLease {
    capture: Arc<ResourceCapture>,
    stage: BufferStage,
    len: u64,
    capacity: u64,
}

impl OwnedBufferLease {
    #[allow(clippy::ptr_arg)] // Destination capacity is the measured property.
    pub(crate) fn observe(
        capture: Option<&Arc<ResourceCapture>>,
        stage: BufferStage,
        destination: &Vec<u8>,
    ) -> Option<Self> {
        let capture = capture?;
        if capture.is_finished() {
            return None;
        }
        let (Ok(len), Ok(capacity)) = (
            u64::try_from(destination.len()),
            u64::try_from(destination.capacity()),
        ) else {
            capture.gap(RecordDisposition::InvalidObservation);
            return None;
        };
        capture.buffers[stage.index()]
            .scope_observed
            .store(true, Ordering::Relaxed);
        let lease = Self {
            capture: capture.clone(),
            stage,
            len,
            capacity,
        };
        lease.adjust(true);
        Some(lease)
    }

    fn adjust(&self, increase: bool) {
        let counters = &self.capture.buffers[self.stage.index()];
        for (counter, amount) in [
            (&counters.live_buffers, 1),
            (&counters.len, self.len),
            (&counters.capacity, self.capacity),
        ] {
            // Keep the owner's exact stored sizes even if a bounded diagnostic
            // update fails. Existing typed gap bits then invalidate the readout.
            self.capture.adjust(counter, amount, increase);
        }
    }
}

impl Drop for OwnedBufferLease {
    fn drop(&mut self) {
        self.adjust(false);
    }
}
