//! The original full128 frame's frozen local sources and terminal once result.
//! Only PeerManager can consume the once; controller metadata grants no IO fact.
use super::*;
use crate::business_evidence::RequestKind;
use crate::overlay_requests::{
    OverlayCreditOutcome as Outcome, OverlayCreditStale as Stale, OverlayCreditUnknown as Unknown,
    PhysicalPublicationState,
};
use crate::rooms::RoomSendPermit;

type Check<T> = Result<T, Outcome>;
mod selection;

pub(crate) struct OriginalKernelExchange {
    scope: Weak<CaptureSession>,
    device: Weak<DeviceLease>,
    plan: Arc<RegisteredFlowPlan>,
    slot: usize,
    peer: Arc<read_peer::FirstReadPeer>,
    room: Option<RoomSendPermit>,
    window: write_window::WriteWindow,
    reads: Vec<Arc<KernelReadBinding>>,
    skipped: Vec<(
        Arc<KernelReadBinding>,
        crate::overlay_requests::OriginalNonDeliveryFence,
    )>,
    writes: Vec<Arc<KernelIngressBinding>>,
    local: String,
    target: String,
}

pub(super) struct NativeFrameOutcome {
    outcome: Outcome,
    owner_check: &'static str,
    committed: bool,
    commit_ns: Option<u64>,
    read_ordinals: Vec<u64>,
    write_ordinals: Vec<u64>,
    skipped_read_attempts: Vec<(u64, u64)>,
}

pub(crate) struct OriginalKernelOnce<'a> {
    committed: &'a mut bool,
    commit_ns: &'a mut Option<u64>,
}

impl OriginalKernelOnce<'_> {
    pub(crate) fn consume(
        &mut self,
        _permit: crate::peer::OriginalKernelAckCommitPermit,
        monotonic_ns: u64,
    ) -> bool {
        if *self.committed {
            return false;
        }
        *self.committed = true;
        *self.commit_ns = Some(monotonic_ns);
        true
    }
}

#[derive(Serialize)]
pub(super) struct NativeFrameSnapshot {
    status: &'static str,
    outcome: String,
    owner_check: &'static str,
    once_committed: bool,
    commit_monotonic_ns: Option<u64>,
    original_kernel_read_ordinals: Vec<u64>,
    original_system_write_ordinals: Vec<u64>,
    original_non_delivery_attempts: Vec<(u64, u64)>,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
    native_os_write_verified: bool,
    network_generation: Option<u64>,
    physical_path: Option<&'static str>,
}

impl NativeFrameOutcome {
    fn failure(outcome: Outcome) -> Self {
        Self {
            outcome,
            owner_check: "not_entered",
            committed: false,
            commit_ns: None,
            read_ordinals: Vec::new(),
            write_ordinals: Vec::new(),
            skipped_read_attempts: Vec::new(),
        }
    }

    pub(super) fn verified(&self) -> bool {
        self.committed && self.commit_ns.is_some() && matches!(self.outcome, Outcome::Fresh(_))
    }

    pub(super) fn snapshot(&self) -> NativeFrameSnapshot {
        NativeFrameSnapshot {
            owner_check: self.owner_check,
            status: match self.outcome {
                Outcome::Fresh(_) => "committed",
                Outcome::AlreadyCommitted => "already_committed",
                Outcome::Unknown(_) => "unknown",
                Outcome::Stale(_) => "stale",
                Outcome::Contended(_) => "contended",
            },
            outcome: format!("{:?}", self.outcome),
            once_committed: self.committed,
            commit_monotonic_ns: self.commit_ns,
            original_kernel_read_ordinals: self.read_ordinals.clone(),
            original_system_write_ordinals: self.write_ordinals.clone(),
            original_non_delivery_attempts: self.skipped_read_attempts.clone(),
            physical_send_verified: self.verified(),
            canonical_current_owner_verified: self.verified(),
            native_os_write_verified: false,
            network_generation: match self.outcome {
                Outcome::Fresh(receipt) => Some(receipt.generation),
                _ => None,
            },
            physical_path: match self.outcome {
                Outcome::Fresh(receipt) => Some(match receipt.path {
                    crate::peer::NetworkPath::Direct => "udp",
                    crate::peer::NetworkPath::Relay => "relay",
                }),
                _ => None,
            },
        }
    }
}

fn unknown() -> Outcome {
    Outcome::Unknown(Unknown::OriginalPublication)
}

impl OriginalKernelExchange {
    fn capture(
        scope: &Arc<CaptureSession>,
        state: &RegistryState,
        flow: usize,
        slot: usize,
    ) -> Check<Option<Self>> {
        if !scope.read_complete.load(Ordering::Acquire)
            || !scope.full_complete.load(Ordering::Acquire)
            || !scope.inbound_complete.load(Ordering::Acquire)
        {
            return Err(unknown());
        }
        let original = &state.flows[flow];
        if original.invalid || original.inbound.invalid {
            return Err(Outcome::Stale(Stale::Identity));
        }
        let Some(window) = &original.requests[slot].original_write_window else {
            return Ok(None);
        };
        if !window.contains(monotonic_ns().ok_or(unknown())?) {
            return Err(Outcome::Stale(Stale::OriginalWindow));
        }
        let Some(indices) = selection::select(
            &original.plan,
            slot,
            state
                .read_history
                .iter()
                .enumerate()
                .filter(|(_, read)| read.flow == flow)
                .map(|(index, read)| {
                    (
                        index,
                        read.spans.as_slice(),
                        read.physical_publication.state(),
                        read.full_observed_ns().is_some(),
                    )
                }),
        )?
        else {
            return Ok(None);
        };
        let mut reads = Vec::new();
        reads
            .try_reserve(indices.selected.len())
            .map_err(|_| unknown())?;
        for index in indices.selected {
            let read = state.read_history.get(index).ok_or(unknown())?;
            let record = read.physical_publication.record().ok_or(unknown())?;
            if !record.matches_original_kernel_read(read)
                || !Arc::ptr_eq(&read.plan, &original.plan)
            {
                return Err(Outcome::Stale(Stale::Identity));
            }
            reads.push(read.clone());
        }
        let mut skipped = Vec::new();
        skipped
            .try_reserve(indices.skipped.len())
            .map_err(|_| unknown())?;
        for index in indices.skipped {
            let read = state.read_history.get(index).ok_or(unknown())?;
            let Some(fence) = read.physical_publication.original_non_delivery_fence() else {
                return Ok(None);
            };
            skipped.push((read.clone(), fence));
        }
        let peer = original.requests[slot]
            .first_peer
            .as_ref()
            .ok_or(Outcome::Unknown(Unknown::OriginalAuthorization))?
            .clone();
        let expected = peer.original()?;
        let writes = if original.plan.requests[slot].kind == RequestKind::Response {
            let sources = original.requests[slot]
                .first_response
                .as_ref()
                .ok_or(unknown())?
                .original_sources()?;
            let mut writes = Vec::new();
            writes.try_reserve(sources.len()).map_err(|_| unknown())?;
            writes.extend(sources.iter().cloned());
            writes
        } else {
            let mut coverage =
                full::FrameSpanCoverage::new(&original.plan, slot).ok_or(unknown())?;
            let mut writes = Vec::new();
            for write in state
                .inbound_history
                .original_packets()
                .iter()
                .filter(|write| write.frame_flow() == flow)
            {
                let mut contributes = false;
                for span in write.frame_spans() {
                    contributes |= coverage.add(span).map_err(|_| unknown())?;
                }
                if !contributes {
                    continue;
                }
                if !expected.matches_original_response(write.original_source()) {
                    return Err(Outcome::Stale(Stale::Identity));
                }
                writes.try_reserve(1).map_err(|_| unknown())?;
                writes.push(write.clone());
                if coverage.is_complete() {
                    break;
                }
            }
            if !coverage.is_complete() || writes.is_empty() {
                return Ok(None);
            }
            writes
        };
        let mut room: Option<Option<RoomSendPermit>> = None;
        for read in &reads {
            let record = read.physical_publication.record().ok_or(unknown())?;
            room = Some(match room {
                None => record.room_authorization().cloned(),
                Some(old) => {
                    ingress::merge_original_permits(old, record.room_authorization().cloned())?
                }
            });
        }
        for source in &writes {
            if !source.original_scope().ptr_eq(&Arc::downgrade(scope))
                || source.frame_spans().len() != source.original_rooms().len()
            {
                return Err(unknown());
            }
            for (span, saved) in source.frame_spans().iter().zip(source.original_rooms()) {
                if span.slot() != slot {
                    continue;
                }
                let permit = saved.permit.clone().map_err(Outcome::from)?;
                room = Some(match room {
                    None => permit,
                    Some(old) => ingress::merge_original_permits(old, permit)?,
                });
            }
        }
        let candidate = Self {
            scope: Arc::downgrade(scope),
            device: state.system_device.clone().ok_or(unknown())?,
            plan: original.plan.clone(),
            slot,
            peer,
            room: room.ok_or(Outcome::Unknown(Unknown::RoomAuthority))?,
            window: window.clone(),
            reads,
            skipped,
            writes,
            local: original.plan.flow.src_v4.to_string(),
            target: original.plan.flow.dst_v4.to_string(),
        };
        candidate.check_history()?;
        Ok(Some(candidate))
    }

    fn check_history(&self) -> Check<()> {
        let kind = self.plan.requests[self.slot].kind;
        for read in &self.reads {
            let observed = read
                .physical_publication
                .recorded_observed_at()
                .ok_or(unknown())?;
            if !self.window.contains(read.read.monotonic_ns())
                || read
                    .original_publication_ns
                    .get()
                    .is_none_or(|at| !self.window.contains(*at))
                || !self
                    .window
                    .contains(read.full_observed_ns().ok_or(unknown())?)
            {
                return Err(Outcome::Stale(Stale::OriginalWindow));
            }
            for source in &self.writes {
                let write = source.original_write().ok_or(unknown())?;
                let rx = source.original_source();
                let received = match (rx.original_udp_read(), rx.original_relay_read()) {
                    (Some(rx), None) => rx.received_at(),
                    (None, Some(rx)) => rx.completed_at(),
                    _ => return Err(Outcome::Unknown(Unknown::OriginalSource)),
                };
                if !write.same_device_as(&read.read)
                    || !self.window.contains(write.monotonic_ns())
                    || source
                        .authenticated_ns()
                        .is_none_or(|at| !self.window.contains(at))
                {
                    return Err(Outcome::Stale(Stale::Identity));
                }
                if kind == RequestKind::Request && received < observed {
                    return Err(Outcome::Stale(Stale::ReadBeforePublication));
                }
                if kind == RequestKind::Response && write.at() > read.read.at() {
                    return Err(Outcome::Stale(Stale::ReadBeforePublication));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn peer(&self) -> &str {
        &self.plan.peer
    }
    pub(crate) fn local(&self) -> &str {
        &self.local
    }
    pub(crate) fn target(&self) -> &str {
        &self.target
    }
    pub(crate) fn original_peer(&self) -> Check<&crate::peer::OriginalKernelReadPeer> {
        self.peer.original()
    }
    pub(crate) fn room(&self) -> Option<&RoomSendPermit> {
        self.room.as_ref()
    }
    pub(crate) fn reads(&self) -> &[Arc<KernelReadBinding>] {
        &self.reads
    }
    pub(crate) fn writes(&self) -> &[Arc<KernelIngressBinding>] {
        &self.writes
    }

    /// The monotonic point is taken only after all current-owner guards. These
    /// sealed owner flags only retire (never rearm); true afterward proves they
    /// were live at that point. After once only fixed-size state updates remain;
    /// no fallible source sampling, lock, IO or allocation follows it.
    pub(crate) fn live_after_point(&self, peers: &PeerManager, at: Instant, ns: u64) -> bool {
        self.scope.upgrade().is_some_and(|scope| {
            std::ptr::eq(scope.peers.as_ptr(), peers)
                && scope.is_live(at)
                && scope.read_complete.load(Ordering::Acquire)
                && scope.full_complete.load(Ordering::Acquire)
                && scope.inbound_complete.load(Ordering::Acquire)
        }) && self.window.contains(ns)
            && self
                .skipped
                .iter()
                .all(|(read, fence)| read.physical_publication.still_original_non_delivery(fence))
            && self
                .reads
                .iter()
                .all(|read| read.read.is_current() && read.read.belongs_to(&self.device))
            && self.writes.iter().all(|source| {
                source
                    .original_write()
                    .is_some_and(|write| write.is_current() && write.belongs_to(&self.device))
            })
    }
}

impl CaptureSession {
    pub(super) fn try_complete_original_frames(
        self: &Arc<Self>,
        state: &mut RegistryState,
        flow: usize,
        slots: &[usize],
    ) {
        for &slot in slots {
            if state.flows[flow].requests[slot].native_credit.is_some() {
                continue;
            }
            let candidate = match OriginalKernelExchange::capture(self, state, flow, slot) {
                Ok(Some(candidate)) => candidate,
                Ok(None) => continue,
                Err(reason) => {
                    state.flows[flow].requests[slot].native_credit =
                        Some(NativeFrameOutcome::failure(reason));
                    continue;
                }
            };
            let mut result = NativeFrameOutcome::failure(unknown());
            if result
                .read_ordinals
                .try_reserve(candidate.reads.len())
                .is_err()
                || result
                    .write_ordinals
                    .try_reserve(candidate.writes.len())
                    .is_err()
                || result
                    .skipped_read_attempts
                    .try_reserve(candidate.skipped.len())
                    .is_err()
            {
                state.flows[flow].requests[slot].native_credit = Some(result);
                continue;
            }
            result
                .read_ordinals
                .extend(candidate.reads.iter().map(|read| read.read.ordinal()));
            result.skipped_read_attempts.extend(
                candidate
                    .skipped
                    .iter()
                    .map(|(read, fence)| (read.read.ordinal(), fence.attempt_id())),
            );
            result.write_ordinals.extend(
                candidate
                    .writes
                    .iter()
                    .filter_map(|source| source.original_write().map(|write| write.ordinal())),
            );
            if let (Some(peers), Some(owners)) = (
                self.peers.upgrade(),
                state
                    .current_owners
                    .as_ref()
                    .and_then(owners::OriginalKernelOwners::upgrade),
            ) {
                let mut once = OriginalKernelOnce {
                    committed: &mut result.committed,
                    commit_ns: &mut result.commit_ns,
                };
                result.outcome = peers.try_commit_original_kernel_exchange(
                    &owners,
                    &candidate,
                    &mut once,
                    &mut result.owner_check,
                );
            }
            state.flows[flow].requests[slot].native_credit = Some(result);
        }
    }
}
