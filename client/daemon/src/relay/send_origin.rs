//! Neutral metadata on the original RelayTransport selected writer branches.
//! This is not canonical A/B/G, current-owner qualification, final credit or ACK.
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use super::{EncryptedPeerPacket, RelayClient};
use p2pnet_relay::OriginalRelayWriteFact;

const EMPTY: u8 = 0;
const CAPTURING: u8 = 1;
const FULL: u8 = 2;
const CLOSED: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RelayBranchDisposition {
    Unresolved = 0,
    HandedUnknown = 1,
    DefinitelyNotHanded = 2,
    Unknown = 3,
    FullWrite = 4,
}

pub(super) struct SelectedRelayWriter {
    endpoint: String,
    writer: Weak<RelayClient>,
}
impl SelectedRelayWriter {
    pub(super) fn capture(endpoint: &str, client: &Arc<RelayClient>) -> Option<Self> {
        let mut copy = String::new();
        copy.try_reserve_exact(endpoint.len()).ok()?;
        copy.push_str(endpoint);
        Some(Self {
            endpoint: copy,
            writer: Arc::downgrade(client),
        })
    }
    pub(super) fn single(endpoint: &str, client: &Arc<RelayClient>) -> Option<Vec<Self>> {
        let mut selected = Vec::new();
        selected.try_reserve_exact(1).ok()?;
        selected.push(Self::capture(endpoint, client)?);
        Some(selected)
    }
}

// Each cell has exactly the original FnOnce observer as its only fact setter.
// It holds Weak source identities and has no reference back to the capture/slot.
pub(crate) struct RelayFullSendFact {
    endpoint: String,
    writer: Weak<RelayClient>,
    live: Weak<std::sync::Mutex<bool>>,
    connection_id: u64,
    wire: (usize, Option<u64>, u64),
    disposition: AtomicU8,
    original: OnceLock<OriginalRelayWriteFact>,
}
#[allow(dead_code)] // Staged read-only neutral evidence; no product credit consumer.
impl RelayFullSendFact {
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub(crate) fn connection_id(&self) -> u64 {
        self.connection_id
    }
    pub(crate) fn wire(&self) -> (usize, Option<u64>, u64) {
        self.wire
    }
    pub(crate) fn original(&self) -> Option<&OriginalRelayWriteFact> {
        self.original.get()
    }
    pub(crate) fn source_is_live(&self) -> bool {
        // Allocation identity/liveness only. Never inspect this gate's bool or
        // infer revocation, current writer, peer authorization or receipt.
        self.live.upgrade().is_some()
            && self.writer.upgrade().is_some_and(|writer| {
                self.original
                    .get()
                    .is_some_and(|fact| fact.belongs_to_writer(&writer))
            })
    }
    pub(crate) fn disposition(&self) -> RelayBranchDisposition {
        match self.disposition.load(Ordering::Acquire) {
            0 => RelayBranchDisposition::Unresolved,
            1 => RelayBranchDisposition::HandedUnknown,
            2 => RelayBranchDisposition::DefinitelyNotHanded,
            4 => RelayBranchDisposition::FullWrite,
            _ => RelayBranchDisposition::Unknown,
        }
    }
}

struct FirstRelayWrite {
    phase: AtomicU8,
    full: OnceLock<Arc<RelayFullSendFact>>,
    #[cfg(test)]
    after_full: OnceLock<TestAfterFull>,
}

// Only metadata Arcs are captured by the queue callbacks. FirstRelayWrite may
// own its winning cell; the cell never owns FirstRelayWrite, so no cycle exists.
pub(crate) struct RelaySendCapture {
    destination: String,
    wire: (usize, Option<u64>, u64),
    branches: OnceLock<Vec<Arc<RelayFullSendFact>>>,
    metadata_failed: AtomicBool,
    configured: AtomicBool,
    first: Arc<FirstRelayWrite>,
}
#[allow(dead_code)] // Neutral finish result is consumed by tests/next integration.
pub(crate) enum RelayCaptureOutcome {
    Full(Arc<RelayFullSendFact>),
    DefinitelyNotHanded,
    Uncertain,
    MetadataFailed,
}
impl RelaySendCapture {
    #[allow(dead_code)] // Explicit opt-in construction; public None never calls it.
    pub(crate) fn new(packet: &EncryptedPeerPacket) -> Option<Arc<Self>> {
        let mut destination = String::new();
        destination.try_reserve_exact(packet.peer_id.len()).ok()?;
        destination.push_str(&packet.peer_id);
        Some(Arc::new(Self {
            destination,
            wire: wire(packet),
            branches: OnceLock::new(),
            metadata_failed: AtomicBool::new(false),
            configured: AtomicBool::new(false),
            first: Arc::new(FirstRelayWrite {
                phase: AtomicU8::new(EMPTY),
                full: OnceLock::new(),
                #[cfg(test)]
                after_full: OnceLock::new(),
            }),
        }))
    }
    pub(super) fn configure(
        &self,
        packet: &EncryptedPeerPacket,
        selected: Option<Vec<SelectedRelayWriter>>,
        connection_id: u64,
        live: Weak<std::sync::Mutex<bool>>,
    ) {
        // One configure winner rejects reuse before obtaining any observers.
        // Neither a second vector setter nor a second cell setter is admitted.
        if self
            .configured
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        }
        // Prepare every original branch before the first queue call. No
        // endpoint is reconstructed after this original selection snapshot.
        if self.destination != packet.peer_id || self.wire != wire(packet) {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        }
        let Some(selected) = selected else {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        };
        let mut branches = Vec::new();
        if branches.try_reserve_exact(selected.len()).is_err() {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        }
        for selected in selected {
            branches.push(Arc::new(RelayFullSendFact {
                endpoint: selected.endpoint,
                writer: selected.writer,
                live: live.clone(),
                connection_id,
                wire: self.wire,
                disposition: AtomicU8::new(RelayBranchDisposition::Unresolved as u8),
                original: OnceLock::new(),
            }));
        }
        // The original configure caller is the sole setter. Reusing a capture
        // is rejected as metadata failure; it cannot create a new attempt.
        if self.branches.set(branches).is_err() {
            self.metadata_failed.store(true, Ordering::Release);
        }
    }
    pub(super) fn branch(&self, index: usize) -> Option<RelayWriteObserver> {
        if self.metadata_failed.load(Ordering::Acquire) {
            return None;
        }
        Some(RelayWriteObserver {
            cell: self.branches.get()?.get(index)?.clone(),
            first: self.first.clone(),
        })
    }
    #[allow(dead_code)] // Staged finite reader; no drain, retry or spinning.
    pub(crate) fn branches(&self) -> Option<&[Arc<RelayFullSendFact>]> {
        self.branches.get().map(Vec::as_slice)
    }
    #[allow(dead_code)] // Only the future sole attempt owner will use this result.
    pub(crate) fn finish(&self) -> RelayCaptureOutcome {
        // One RMW seals capture. A callback still in Capturing is uncertain;
        // this reader never waits on a setter or retries its load/CAS.
        let previous = self.first.phase.swap(CLOSED, Ordering::AcqRel);
        // Failure/reuse is sticky and takes precedence over any earlier full
        // cell. Historical facts remain readable, but cannot be returned as
        // this invalid capture's result or a different send's success.
        if self.metadata_failed.load(Ordering::Acquire) {
            return RelayCaptureOutcome::MetadataFailed;
        }
        if previous == FULL {
            if let Some(full) = self.first.full.get() {
                return RelayCaptureOutcome::Full(full.clone());
            }
            return RelayCaptureOutcome::MetadataFailed;
        }
        if previous == CLOSED || previous == CAPTURING {
            return RelayCaptureOutcome::Uncertain;
        }
        // Includes explicitly configured zero selection. Missing/JoinError/
        // accepted-pending branches never equal DefinitelyNotHanded.
        if self.branches.get().is_some_and(|branches| {
            branches
                .iter()
                .all(|branch| branch.disposition() == RelayBranchDisposition::DefinitelyNotHanded)
        }) {
            RelayCaptureOutcome::DefinitelyNotHanded
        } else {
            RelayCaptureOutcome::Uncertain
        }
    }
    #[cfg(test)]
    pub(super) fn after_full_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        // Explicit test-only completion-loss/barrier fault outside the finite
        // production callback. This is not evidence of a partial TCP write.
        let _ = self
            .first
            .after_full
            .set(std::sync::Mutex::new(Some(Box::new(hook))));
    }
}
impl Drop for RelaySendCapture {
    fn drop(&mut self) {
        // Queued observers may outlive the caller, but cannot reopen capture.
        self.first.phase.swap(CLOSED, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub(super) struct RelayWriteObserver {
    cell: Arc<RelayFullSendFact>,
    first: Arc<FirstRelayWrite>,
}
impl RelayWriteObserver {
    pub(super) fn note_handed(&self) {
        let _ = self.cell.disposition.compare_exchange(
            RelayBranchDisposition::Unresolved as u8,
            RelayBranchDisposition::HandedUnknown as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    pub(super) fn note_unknown(&self) {
        let previous = self.cell.disposition.load(Ordering::Acquire);
        if previous != RelayBranchDisposition::FullWrite as u8 {
            let _ = self.cell.disposition.compare_exchange(
                previous,
                RelayBranchDisposition::Unknown as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
    pub(super) fn note_result(&self, result: &std::result::Result<(), p2pnet_relay::RelayError>) {
        use p2pnet_relay::RelayError;
        if matches!(
            result,
            Err(RelayError::CommandQueueFull
                | RelayError::WriterStoppedBeforeAccept
                | RelayError::WriteBoundaryRejected)
        ) {
            if self
                .cell
                .disposition
                .compare_exchange(
                    RelayBranchDisposition::Unresolved as u8,
                    RelayBranchDisposition::DefinitelyNotHanded as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                self.note_unknown();
            }
        } else if self.cell.disposition() != RelayBranchDisposition::FullWrite {
            self.note_unknown();
        }
    }
    pub(super) fn observe(self, fact: OriginalRelayWriteFact) {
        // This FnOnce has no clocks, locks, allocation, I/O, logging, panic,
        // await, spin or retry in production. Both facts/setters are genuine:
        // the private B16 factory runs only after its original full writer Ok.
        if self.cell.original.set(fact).is_err() {
            self.note_unknown();
            return;
        }
        self.cell
            .disposition
            .store(RelayBranchDisposition::FullWrite as u8, Ordering::Release);
        if self
            .first
            .phase
            .compare_exchange(EMPTY, CAPTURING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Only the CAS winner can call set; competing observers never enter
        // OnceLock::set and therefore cannot wait for this writer callback.
        if self.first.full.set(self.cell.clone()).is_err() {
            let _ = self.first.phase.compare_exchange(
                CAPTURING,
                CLOSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return;
        }
        // Matching CAS is essential: finish may already have sealed Capturing.
        // A late full fact is historical cell evidence, never capture reopening.
        let published = self
            .first
            .phase
            .compare_exchange(CAPTURING, FULL, Ordering::Release, Ordering::Acquire)
            .is_ok();
        #[cfg(test)]
        if published {
            if let Some(hook) = self.first.after_full.get() {
                if let Some(hook) = hook.lock().unwrap_or_else(|p| p.into_inner()).take() {
                    hook();
                }
            }
        }
        #[cfg(not(test))]
        let _ = published;
    }
}

fn wire(packet: &EncryptedPeerPacket) -> (usize, Option<u64>, u64) {
    (
        packet.wire_bytes.len(),
        crate::transport::wire_counter(&packet.wire_bytes),
        crate::transport::wire_fingerprint(&packet.wire_bytes),
    )
}

#[cfg(test)]
type TestAfterFull = std::sync::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>;
#[cfg(test)]
#[path = "send_origin/tests.rs"]
mod tests;
