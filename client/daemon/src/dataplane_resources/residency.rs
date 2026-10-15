//! Fixed-size accounting at real message owners. Writers never take a shared
//! mutex or retry: bounded atomic updates publish a completion revision. A
//! reader accepts only a quiescent, unchanged revision within eight attempts.
//! Capacity high-water is one scalar, never a tuple of unrelated maxima.
use super::{RecordDisposition, ResourceCapture};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResidencyStage {
    ChannelReserve,
    RawChannel,
    DetachedRaw,
    PendingFifo,
    DiscardBatch,
    RetryPlaintext,
    PreparationPlaintext,
    SerializedWire,
    SessionBacklog,
    SessionFlush,
}
impl ResidencyStage {
    pub(crate) const COUNT: usize = 10;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ResidencyTotals {
    /// Real buffer owners; deep copies count separately from application packets.
    pub(crate) live_buffers: u64,
    pub(crate) len_bytes: u64,
    pub(crate) capacity_bytes: u64,
}
#[allow(clippy::ptr_arg)] // Capacity belongs to this concrete Vec owner.
impl ResidencyTotals {
    fn observed(bytes: &Vec<u8>) -> Option<Self> {
        Some(Self {
            live_buffers: 1,
            len_bytes: u64::try_from(bytes.len()).ok()?,
            capacity_bytes: u64::try_from(bytes.capacity()).ok()?,
        })
    }
}
#[derive(Default)]
struct AtomicTotals {
    buffers: AtomicU64,
    len: AtomicU64,
    capacity: AtomicU64,
}
impl AtomicTotals {
    fn read(&self) -> ResidencyTotals {
        ResidencyTotals {
            live_buffers: self.buffers.load(Ordering::Relaxed),
            len_bytes: self.len.load(Ordering::Relaxed),
            capacity_bytes: self.capacity.load(Ordering::Relaxed),
        }
    }
}
#[derive(Default)]
pub(super) struct ResidencyLedger {
    stages: [AtomicTotals; ResidencyStage::COUNT],
    observed: [AtomicBool; ResidencyStage::COUNT],
    total: AtomicTotals,
    capacity_high_water: AtomicU64,
    writers: AtomicU64,
    revision: AtomicU64,
    clone_ops: AtomicU64,
    cloned_len_bytes: AtomicU64,
    gaps: AtomicU32,
    unknown: AtomicU32,
}
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // Private opt-in readout, without default status export.
pub(crate) struct ResidencySnapshot {
    pub(crate) coherent: bool,
    pub(crate) valid: bool,
    pub(crate) gap_bits: u32,
    pub(crate) unknown_bits: u32,
    pub(crate) revision: Option<u64>,
    pub(crate) total: Option<ResidencyTotals>,
    pub(crate) capacity_high_water_bytes: Option<u64>,
    pub(crate) observed: [bool; ResidencyStage::COUNT],
    pub(crate) stages: Option<[ResidencyTotals; ResidencyStage::COUNT]>,
    pub(crate) clone_ops: Option<u64>,
    pub(crate) cloned_len_bytes: Option<u64>,
    /// Observed message-owner capacity, not RSS, allocator internals, metadata,
    /// control/RX/Relay-frame buffers or a whole-pipeline memory claim.
    pub(crate) whole_pipeline_bytes_measured: bool,
}
#[allow(dead_code)] // Private readout accessor.
impl ResidencySnapshot {
    pub(crate) fn stage(&self, stage: ResidencyStage) -> Option<ResidencyTotals> {
        self.stages.map(|s| s[stage as usize])
    }
}
impl ResidencyLedger {
    fn gap(&self, reason: RecordDisposition) -> RecordDisposition {
        self.gaps.fetch_or(reason.gap_bit(), Ordering::SeqCst);
        reason
    }
    pub(crate) fn unobserved_exit(&self) {
        self.unknown.fetch_or(1, Ordering::SeqCst);
    }
    fn adjust(&self, value: &AtomicU64, old: u64, new: u64) -> Option<u64> {
        if old == new {
            return Some(value.load(Ordering::Relaxed));
        }
        let next = if new > old {
            let delta = new - old;
            value.fetch_add(delta, Ordering::Relaxed).checked_add(delta)
        } else {
            let delta = old - new;
            value.fetch_sub(delta, Ordering::Relaxed).checked_sub(delta)
        };
        if next.is_none() {
            self.gap(if new > old {
                RecordDisposition::CounterOverflow
            } else {
                RecordDisposition::GaugeUnderflow
            });
        }
        next
    }
    fn adjust_totals(&self, counters: &AtomicTotals, old: ResidencyTotals, new: ResidencyTotals) {
        self.adjust(&counters.buffers, old.live_buffers, new.live_buffers);
        self.adjust(&counters.len, old.len_bytes, new.len_bytes);
        self.adjust(&counters.capacity, old.capacity_bytes, new.capacity_bytes);
    }
    fn change(
        &self,
        previous: Option<(ResidencyStage, ResidencyTotals)>,
        next: Option<(ResidencyStage, ResidencyTotals)>,
        is_clone: bool,
    ) -> RecordDisposition {
        if self.writers.fetch_add(1, Ordering::SeqCst) == u64::MAX {
            self.gap(RecordDisposition::CounterOverflow);
        }
        // Publish writer entry through any following sampled atomic field.
        // Reading a changed relaxed field then crossing the reader's Acquire
        // fence makes this entry happen-before its final validation loads.
        std::sync::atomic::fence(Ordering::Release);
        let old = previous.map_or(ResidencyTotals::default(), |(_, v)| v);
        let new = next.map_or(ResidencyTotals::default(), |(_, v)| v);
        match (previous, next) {
            (Some((a, _)), Some((b, _))) if a == b => {
                self.adjust_totals(&self.stages[a as usize], old, new)
            }
            (a, b) => {
                if let Some((stage, value)) = a {
                    self.adjust_totals(
                        &self.stages[stage as usize],
                        value,
                        ResidencyTotals::default(),
                    );
                }
                if let Some((stage, value)) = b {
                    self.adjust_totals(
                        &self.stages[stage as usize],
                        ResidencyTotals::default(),
                        value,
                    );
                }
            }
        }
        self.adjust(&self.total.buffers, old.live_buffers, new.live_buffers);
        self.adjust(&self.total.len, old.len_bytes, new.len_bytes);
        let capacity = self.adjust(&self.total.capacity, old.capacity_bytes, new.capacity_bytes);
        if new.capacity_bytes > old.capacity_bytes {
            if let Some(capacity) = capacity {
                self.capacity_high_water
                    .fetch_max(capacity, Ordering::Relaxed);
            }
        }
        if let Some((stage, _)) = next {
            self.observed[stage as usize].store(true, Ordering::Relaxed);
        }
        if is_clone {
            self.adjust(&self.clone_ops, 0, 1);
            self.adjust(&self.cloned_len_bytes, 0, new.len_bytes);
        }
        if self.revision.fetch_add(1, Ordering::SeqCst) == u64::MAX {
            self.gap(RecordDisposition::CounterOverflow);
        }
        self.writers.fetch_sub(1, Ordering::SeqCst);
        // An arithmetic gap invalidates this capture, but the owner must still
        // remember every applied increment so its real Drop can drain it.
        RecordDisposition::Recorded
    }
    pub(super) fn snapshot(&self) -> ResidencySnapshot {
        for _ in 0..8 {
            let revision = self.revision.load(Ordering::SeqCst);
            if self.writers.load(Ordering::SeqCst) != 0 {
                continue;
            }
            let stages = std::array::from_fn(|i| self.stages[i].read());
            let total = self.total.read();
            let peak = self.capacity_high_water.load(Ordering::Relaxed);
            let observed = std::array::from_fn(|i| self.observed[i].load(Ordering::Relaxed));
            let clone_ops = self.clone_ops.load(Ordering::Relaxed);
            let cloned_len_bytes = self.cloned_len_bytes.load(Ordering::Relaxed);
            let gaps = self.gaps.load(Ordering::SeqCst);
            let unknown = self.unknown.load(Ordering::SeqCst);
            // Keep the sampled relaxed fields before the validation loads.
            std::sync::atomic::fence(Ordering::Acquire);
            if self.writers.load(Ordering::SeqCst) == 0
                && self.revision.load(Ordering::SeqCst) == revision
            {
                return ResidencySnapshot {
                    coherent: true,
                    valid: gaps == 0,
                    gap_bits: gaps,
                    unknown_bits: unknown,
                    revision: Some(revision),
                    total: (gaps == 0).then_some(total),
                    capacity_high_water_bytes: (gaps == 0).then_some(peak),
                    observed,
                    stages: (gaps == 0).then_some(stages),
                    clone_ops: (gaps == 0).then_some(clone_ops),
                    cloned_len_bytes: (gaps == 0).then_some(cloned_len_bytes),
                    whole_pipeline_bytes_measured: false,
                };
            }
        }
        // A busy read is unavailable, not a permanently damaged capture. It
        // cannot fabricate measured zeros or slow any data-plane producer.
        ResidencySnapshot {
            coherent: false,
            valid: false,
            gap_bits: self.gaps.load(Ordering::SeqCst),
            unknown_bits: self.unknown.load(Ordering::SeqCst),
            revision: None,
            total: None,
            capacity_high_water_bytes: None,
            observed: [false; ResidencyStage::COUNT],
            stages: None,
            clone_ops: None,
            cloned_len_bytes: None,
            whole_pipeline_bytes_measured: false,
        }
    }
}

/// A lease moves with one concrete buffer owner. It contains sizes only; its
/// capture is an observer, never a peer/session/publication capability.
pub(crate) struct ResidencyLease {
    capture: Arc<ResourceCapture>,
    stage: ResidencyStage,
    totals: ResidencyTotals,
}

#[allow(clippy::ptr_arg)] // The owner's actual Vec capacity is observed.
impl ResidencyLease {
    pub(crate) fn observe(
        capture: &Arc<ResourceCapture>,
        stage: ResidencyStage,
        bytes: &Vec<u8>,
    ) -> Option<Self> {
        Self::new(capture, stage, bytes, false)
    }

    fn new(
        capture: &Arc<ResourceCapture>,
        stage: ResidencyStage,
        bytes: &Vec<u8>,
        is_clone: bool,
    ) -> Option<Self> {
        if capture.is_finished() {
            return None;
        }
        let Some(totals) = ResidencyTotals::observed(bytes) else {
            capture.residency.gap(RecordDisposition::InvalidObservation);
            return None;
        };
        if capture
            .residency
            .change(None, Some((stage, totals)), is_clone)
            != RecordDisposition::Recorded
        {
            return None;
        }
        Some(Self {
            capture: capture.clone(),
            stage,
            totals,
        })
    }

    pub(crate) fn clone_for(&self, bytes: &Vec<u8>) -> Option<Self> {
        Self::new(&self.capture, ResidencyStage::DetachedRaw, bytes, true)
    }

    pub(crate) fn relocate(&mut self, stage: ResidencyStage, bytes: &Vec<u8>) {
        let Some(next) = ResidencyTotals::observed(bytes) else {
            self.capture
                .residency
                .gap(RecordDisposition::InvalidObservation);
            return;
        };
        if self.stage == stage && self.totals == next {
            return;
        }
        if next != self.totals {
            // In-place mutations may have had unobserved intermediate capacity.
            self.capture
                .residency
                .unknown
                .fetch_or(2, Ordering::Relaxed);
        }
        if self.capture.residency.change(
            Some((self.stage, self.totals)),
            Some((stage, next)),
            false,
        ) == RecordDisposition::Recorded
        {
            self.stage = stage;
            self.totals = next;
        }
    }

    pub(crate) fn capture(&self) -> &Arc<ResourceCapture> {
        &self.capture
    }

    pub(crate) fn refresh(&mut self, bytes: &Vec<u8>) {
        self.relocate(self.stage, bytes);
    }

    pub(crate) fn unobserved_exit(&self) {
        self.capture.residency.unobserved_exit();
    }
}

impl Drop for ResidencyLease {
    fn drop(&mut self) {
        self.capture
            .residency
            .change(Some((self.stage, self.totals)), None, false);
    }
}

#[cfg(test)]
#[path = "residency_tests.rs"]
mod tests;
