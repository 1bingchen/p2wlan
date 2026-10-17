//! Historical Fulls from the existing original physical-attempt producer.
//! No current connection state or final once permission is owned here.
use super::{KernelReadBinding, RegisteredFlowPlan};
use crate::os_request_capture::clock::monotonic_ns;
use crate::os_request_capture::plan::{CaptureFailure, Protocol};
use crate::peer::PeerManager;
#[cfg(unix)]
use serde::Serialize;
use std::sync::{Arc, Weak};
use std::time::Instant;

// One scope, at most 1000 registered requests, and an independent packet-fact
// capacity. Fragmentation/retransmission cannot grow retained metadata forever.
const MAX_FULL_PACKETS: usize = 1024;
const MAX_FRAME_WIRE_BYTES: usize = 1204;

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
    packet_len: usize,
    packet_sha256: String,
    spans: Vec<ReadFrameSpan>,
    attempt_id: u64,
    encryption_generation: u64,
    encryption_session_instance: u64,
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
        Ok(())
    }

    #[cfg(unix)]
    pub(super) fn frame_complete(
        &self,
        flow: usize,
        slot: usize,
        plan: &RegisteredFlowPlan,
    ) -> bool {
        let length = match plan.protocol {
            Protocol::Udp => 1,
            Protocol::Tcp => 4 + 63 + usize::from(plan.payload_bytes),
        };
        if length > MAX_FRAME_WIRE_BYTES {
            return false;
        }
        let mut seen = [0u64; MAX_FRAME_WIRE_BYTES.div_ceil(64)];
        let mut covered = 0;
        for packet in &self.packets {
            if packet.read.flow != flow || packet.observed_monotonic_ns == 0 {
                continue;
            }
            for span in packet.read.spans.iter().filter(|span| span.slot == slot) {
                let (start, end) = (usize::from(span.start), usize::from(span.end));
                if start >= end || end > length {
                    return false;
                }
                for byte in start..end {
                    let bit = 1 << (byte % 64);
                    if seen[byte / 64] & bit == 0 {
                        seen[byte / 64] |= bit;
                        covered += 1;
                    }
                }
            }
        }
        covered == length
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
                    packet_len: read.packet_len,
                    packet_sha256: hex::encode(read.packet_sha256),
                    spans: read.spans.clone(),
                    attempt_id: record.attempt_id(),
                    encryption_generation: record.encryption_generation(),
                    encryption_session_instance: record.encryption().session_instance(),
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
        let retain = || -> Result<(), CaptureFailure> {
            let record = self
                .physical_publication
                .record()
                .ok_or(CaptureFailure::InvalidPlan)?;
            if !record.matches_original_kernel_read(self)
                || self.physical_publication.recorded_observed_at().is_none()
            {
                return Err(CaptureFailure::InvalidPlan);
            }
            // A native observation AFTER the actual original Full is an upper
            // bound, never a reconstructed syscall timestamp. The original
            // application deadline is compared separately, without rearming.
            let observed = monotonic_ns()
                .filter(|at| *at != 0)
                .ok_or(CaptureFailure::InvalidPlan)?;
            let mut state = scope
                .state
                .try_lock()
                .map_err(|_| CaptureFailure::Contended)?;
            state.full_history.retain(self, observed)
        };
        if retain().is_err() {
            scope.gap();
        }
    }
}
