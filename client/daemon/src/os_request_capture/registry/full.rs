//! Historical Fulls from the existing original physical-attempt producer.
//! No current connection state or final once permission is owned here.
use super::{CaptureSession, FullRetentionLossReason, KernelReadBinding, RegisteredFlowPlan};
use crate::os_request_capture::clock::monotonic_ns;
use crate::os_request_capture::plan::{CaptureFailure, Protocol};
use crate::peer::PeerManager;
#[cfg(unix)]
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::Instant;

// One scope, at most 1000 registered requests, and an independent packet-fact
// capacity. Fragmentation/retransmission cannot grow retained metadata forever.
pub(super) const MAX_FULL_PACKETS: usize = 1024;
const MAX_FRAME_WIRE_BYTES: usize = 1204;

/// A negative observation guard, never a Full or current-owner permission.
/// Only an actual KernelRead supplies its weak scope. Preparation alone does
/// not arm it; the original physical-attempt owner arms it before opening.
pub(crate) struct OriginalFullObservation {
    scope: Weak<CaptureSession>,
    armed: bool,
}

impl OriginalFullObservation {
    pub(crate) fn arm(&mut self) {
        self.armed = true;
    }

    /// Called only after the original Full callback or a definitely-not-handed
    /// terminal. Disarming this observer cannot restore a previously lost one.
    pub(crate) fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for OriginalFullObservation {
    fn drop(&mut self) {
        if self.armed {
            if let Some(scope) = self.scope.upgrade() {
                scope.original_full_retention_lost(FullRetentionLossReason::ObservationDropped);
            }
        }
    }
}

impl CaptureSession {
    fn original_full_retention_lost(&self, reason: FullRetentionLossReason) {
        // No lock or retry: loss must remain observable even when the history
        // mutex itself caused the miss. Later duplicates never rearm a scope.
        self.full_loss.record(reason);
        self.full_complete.store(false, Ordering::Release);
        self.gap();
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(unix, derive(Serialize))]
pub(super) struct ReadFrameSpan {
    slot: usize,
    start: u16,
    end: u16,
}

impl ReadFrameSpan {
    pub(super) fn new(slot: usize, start: u16, end: u16) -> Self {
        Self { slot, start, end }
    }

    pub(super) fn slot(&self) -> usize {
        self.slot
    }

    fn fits(&self, plan: &RegisteredFlowPlan) -> bool {
        let length = match plan.protocol {
            Protocol::Udp => 1,
            Protocol::Tcp => 4 + 63 + usize::from(plan.payload_bytes),
        };
        self.slot < plan.requests.len()
            && self.start < self.end
            && usize::from(self.end) <= length
            && length <= MAX_FRAME_WIRE_BYTES
    }
}

#[derive(Clone)]
pub(super) struct FrameSpanCoverage {
    slot: usize,
    length: usize,
    seen: [u64; MAX_FRAME_WIRE_BYTES.div_ceil(64)],
    covered: usize,
}

impl FrameSpanCoverage {
    pub(super) fn new(plan: &RegisteredFlowPlan, slot: usize) -> Option<Self> {
        let length = match plan.protocol {
            Protocol::Udp => 1,
            Protocol::Tcp => 4 + 63 + usize::from(plan.payload_bytes),
        };
        (slot < plan.requests.len() && length <= MAX_FRAME_WIRE_BYTES).then_some(Self {
            slot,
            length,
            seen: [0; MAX_FRAME_WIRE_BYTES.div_ceil(64)],
            covered: 0,
        })
    }

    /// True only when this original span contributes previously missing bytes.
    pub(super) fn add(&mut self, span: &ReadFrameSpan) -> Result<bool, CaptureFailure> {
        if span.slot != self.slot {
            return Ok(false);
        }
        let (start, end) = (usize::from(span.start), usize::from(span.end));
        if start >= end || end > self.length {
            return Err(CaptureFailure::InvalidPlan);
        }
        let before = self.covered;
        for byte in start..end {
            let bit = 1 << (byte % 64);
            if self.seen[byte / 64] & bit == 0 {
                self.seen[byte / 64] |= bit;
                self.covered += 1;
            }
        }
        Ok(self.covered != before)
    }

    pub(super) fn is_complete(&self) -> bool {
        self.covered == self.length
    }
}

#[cfg(unix)]
pub(super) fn spans_complete<'a>(
    spans: impl Iterator<Item = &'a ReadFrameSpan>,
    slot: usize,
    plan: &RegisteredFlowPlan,
) -> bool {
    let Some(mut coverage) = FrameSpanCoverage::new(plan, slot) else {
        return false;
    };
    for span in spans {
        if coverage.add(span).is_err() {
            return false;
        }
    }
    coverage.is_complete()
}

struct FullPacketHistory {
    read: Arc<KernelReadBinding>,
    observed_monotonic_ns: u64,
}

pub(super) struct FullHistory {
    packets: Vec<FullPacketHistory>,
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct FullPacketSnapshot {
    flow: usize,
    read_ordinal: u64,
    read_monotonic_ns: u64,
    full_observed_monotonic_ns: u64,
    publication_observed_monotonic_ns: Option<u64>,
    packet_len: usize,
    packet_sha256: String,
    spans: Vec<ReadFrameSpan>,
    attempt_id: u64,
    encryption_generation: u64,
    encryption_session_instance: u64,
    encryption_peer_lifecycle: Option<u64>,
    physical_path: &'static str,
}

impl FullHistory {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new() -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    fn retain(
        &mut self,
        read: &Arc<KernelReadBinding>,
        observed_monotonic_ns: u64,
    ) -> Result<(), CaptureFailure> {
        if observed_monotonic_ns < read.read.monotonic_ns()
            || read.spans.is_empty()
            || !read.spans.iter().all(|span| span.fits(&read.plan))
        {
            return Err(CaptureFailure::InvalidPlan);
        }
        if self.packets.len() >= MAX_FULL_PACKETS {
            return Err(CaptureFailure::Capacity);
        }
        // The publication's original CAS already permits one successful
        // producer. This additional identity check makes retention idempotent.
        if self
            .packets
            .iter()
            .any(|old| old.observed_monotonic_ns != 0 && Arc::ptr_eq(&old.read, read))
        {
            return Ok(());
        }
        self.packets
            .try_reserve(1)
            .map_err(|_| CaptureFailure::Capacity)?;
        self.packets.push(FullPacketHistory {
            read: read.clone(),
            observed_monotonic_ns,
        });
        read.full_retained_ns
            .set(observed_monotonic_ns)
            .map_err(|_| CaptureFailure::InvalidPlan)?;
        Ok(())
    }

    #[cfg(unix)]
    pub(super) fn frame_complete(
        &self,
        flow: usize,
        slot: usize,
        plan: &RegisteredFlowPlan,
    ) -> bool {
        spans_complete(
            self.packets
                .iter()
                .filter(|packet| packet.read.flow == flow && packet.observed_monotonic_ns != 0)
                .flat_map(|packet| &packet.read.spans),
            slot,
            plan,
        )
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> Vec<FullPacketSnapshot> {
        self.packets
            .iter()
            .filter_map(|packet| {
                let read = &packet.read;
                let record = read.physical_publication.record()?;
                Some(FullPacketSnapshot {
                    flow: read.flow,
                    read_ordinal: read.read.ordinal(),
                    read_monotonic_ns: read.read.monotonic_ns(),
                    full_observed_monotonic_ns: packet.observed_monotonic_ns,
                    publication_observed_monotonic_ns: read.original_publication_ns.get().copied(),
                    packet_len: read.packet_len,
                    packet_sha256: hex::encode(read.packet_sha256),
                    spans: read.spans.clone(),
                    attempt_id: record.attempt_id(),
                    encryption_generation: record.encryption_generation(),
                    encryption_session_instance: record.encryption().session_instance(),
                    encryption_peer_lifecycle: record
                        .encryption()
                        .authorized_peer_lifecycle()
                        .map(|life| life.value()),
                    physical_path: if record.udp().is_some() {
                        "udp"
                    } else {
                        "relay"
                    },
                })
            })
            .collect()
    }
}

impl KernelReadBinding {
    /// The sole actual Full producer calls this just before publishing its
    /// Instant observation. This clock precedes that boundary; later retention
    /// time is a different upper bound and must not stand in for publication.
    pub(crate) fn observe_original_publication_clock(&self) {
        let Some(at) = monotonic_ns().filter(|at| *at != 0) else {
            self.full_retention_lost(FullRetentionLossReason::PublicationClockUnavailable);
            return;
        };
        if self.original_publication_ns.set(at).is_err() {
            self.full_retention_lost(FullRetentionLossReason::PublicationClockAlreadyRecorded);
        }
    }

    pub(crate) fn original_full_observation(&self) -> OriginalFullObservation {
        OriginalFullObservation {
            scope: self.scope.clone(),
            armed: false,
        }
    }

    pub(crate) fn original_full_retention_lost(&self, reason: FullRetentionLossReason) {
        self.full_retention_lost(reason);
    }

    fn full_retention_lost(&self, reason: FullRetentionLossReason) {
        if let Some(scope) = self.scope.upgrade() {
            scope.original_full_retention_lost(reason);
        }
    }

    pub(crate) fn physical_publication(&self) -> &crate::overlay_requests::PhysicalSendPublication {
        &self.physical_publication
    }

    pub(crate) fn peer_id(&self) -> &str {
        &self.plan.peer
    }

    pub(crate) fn read_at(&self) -> Instant {
        self.read.at()
    }

    pub(crate) fn original_peer_owner(&self, peers: &PeerManager) -> Option<Weak<PeerManager>> {
        let scope = self.scope.upgrade()?;
        std::ptr::eq(scope.peers.as_ptr(), peers).then(|| scope.peers.clone())
    }

    pub(crate) fn original_peer_owner_ptr_matches(&self, peers: &Weak<PeerManager>) -> bool {
        self.scope
            .upgrade()
            .is_some_and(|scope| scope.peers.ptr_eq(peers))
    }

    pub(crate) fn retain_original_full(self: &Arc<Self>) {
        let Some(scope) = self.scope.upgrade() else {
            return;
        };
        let retain = || -> Result<(), FullRetentionLossReason> {
            let record = self
                .physical_publication
                .record()
                .ok_or(FullRetentionLossReason::PublicationMissing)?;
            if !record.matches_original_kernel_read(self) {
                return Err(FullRetentionLossReason::PublicationIdentityMismatch);
            }
            if self.physical_publication.recorded_observed_at().is_none() {
                return Err(FullRetentionLossReason::PublicationObservationMissing);
            }
            // A native observation AFTER the actual original Full is an upper
            // bound, never a reconstructed syscall timestamp. The original
            // application deadline is compared separately, without rearming.
            let observed = monotonic_ns()
                .filter(|at| *at != 0)
                .ok_or(FullRetentionLossReason::RetentionClockUnavailable)?;
            let mut state = scope
                .state
                .try_lock()
                .map_err(|_| FullRetentionLossReason::HistoryContended)?;
            state
                .full_history
                .retain(self, observed)
                .map_err(FullRetentionLossReason::history)?;
            #[cfg(any(target_os = "linux", all(unix, test)))]
            scope.try_complete_original_frames(&mut state, self.flow, &self.slots);
            Ok(())
        };
        if let Err(reason) = retain() {
            scope.original_full_retention_lost(reason);
        }
    }
}

#[cfg(all(unix, test))]
mod tests;
