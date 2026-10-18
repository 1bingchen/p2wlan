//! Original authenticated input and concrete system Full-write history.
//! No current connection state or final once permission is maintained here.
use super::full::ReadFrameSpan;
use super::*;
use crate::business_evidence::{OsUdpReqKey, RegisteredFlow, RequestKind};
use crate::dataplane::InboundPacket;
use crate::os_request_capture::device::KernelWrite;
use crate::rooms::{OriginalRoomSendFailure, RoomAuthorization, RoomSendPermit};
#[cfg(unix)]
use crate::transport::OriginalSessionRole;
use crate::transport::{OriginalOverlayIngressSource, WireGuardTransport};
use p2pnet_tun::PacketWriteContext;
use std::sync::OnceLock;

const MAX_SYSTEM_WRITES: usize = 1024;
const MAX_ORIGINAL_ENDPOINT_BYTES: usize = 4096;

mod response;
#[cfg(all(unix, test))]
pub(super) use response::known_route_room;
pub(super) use response::merge_original_permits;
pub(super) use response::ResponseCapture;
#[cfg(unix)]
pub(super) use response::ResponseSnapshot;

pub(crate) struct KernelCaptureRuntime {
    scope: Weak<CaptureSession>,
    room: Weak<RoomAuthorization>,
}

pub(super) struct OriginalIncomingRoom {
    pub(super) owner: Weak<RoomAuthorization>,
    pub(super) permit: Result<Option<RoomSendPermit>, OriginalRoomSendFailure>,
}

pub(super) struct InboundFlow {
    tcp_open: Option<u32>,
    pub(super) invalid: bool,
    coverage: Vec<Option<TcpFrameCoverage>>,
    original_room: Vec<Option<Arc<OriginalIncomingRoom>>>,
}

impl InboundFlow {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new(requests: usize) -> Self {
        Self {
            tcp_open: None,
            invalid: false,
            coverage: (0..requests).map(|_| None).collect(),
            original_room: (0..requests).map(|_| None).collect(),
        }
    }
}

pub(crate) struct KernelIngressBinding {
    scope: Weak<CaptureSession>,
    source: Arc<OriginalOverlayIngressSource>,
    flow: usize,
    spans: Vec<ReadFrameSpan>,
    original_rooms: Vec<Arc<OriginalIncomingRoom>>,
    packet_len: usize,
    packet_sha256: [u8; 32],
    authenticated_observed_monotonic_ns: Option<u64>,
    write: OnceLock<KernelWrite>,
}

pub(super) struct InboundHistory {
    writes: Vec<Arc<KernelIngressBinding>>,
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct WriteSnapshot {
    scope: &'static str,
    flow: usize,
    spans: Vec<ReadFrameSpan>,
    write_ordinal: u64,
    write_observed_monotonic_ns: u64,
    authenticated_observed_monotonic_ns: Option<u64>,
    packet_len: usize,
    packet_sha256: String,
    network_generation: Option<u64>,
    session_instance: u64,
    original_session_role: &'static str,
    original_room_captured: Vec<bool>,
    original_room_restricted: Vec<bool>,
    original_room_owner_live: Vec<bool>,
    canonical_current_owner_verified: bool,
}

fn reverse(flow: RegisteredFlow) -> RegisteredFlow {
    RegisteredFlow {
        src_v4: flow.dst_v4,
        dst_v4: flow.src_v4,
        src_port: flow.dst_port,
        dst_port: flow.src_port,
    }
}

fn opposite(key: OsUdpReqKey) -> OsUdpReqKey {
    OsUdpReqKey {
        kind: match key.kind {
            RequestKind::Request => RequestKind::Response,
            RequestKind::Response => RequestKind::Request,
        },
        ..key
    }
}

impl CaptureSession {
    pub(crate) fn inbound_runtime(
        self: &Arc<Self>,
        room: &Arc<RoomAuthorization>,
    ) -> KernelCaptureRuntime {
        let expected = Arc::downgrade(room);
        let bound = self.state.try_lock().is_ok_and(|mut state| {
            if let Some(original) = &state.original_room_owner {
                original.ptr_eq(&expected)
            } else {
                state.original_room_owner = Some(expected.clone());
                true
            }
        });
        if !bound {
            self.read_complete.store(false, Ordering::Release);
            self.inbound_complete.store(false, Ordering::Release);
            self.gap();
        }
        KernelCaptureRuntime {
            scope: Arc::downgrade(self),
            room: expected,
        }
    }

    pub(in crate::os_request_capture) fn observe_system_write(
        self: &Arc<Self>,
        original: KernelWrite,
        binding: Arc<KernelIngressBinding>,
        packet: &[u8],
    ) {
        let retain = || -> Result<(), CaptureFailure> {
            if !original.is_current()
                || !self.is_live(original.at())
                || !binding.scope.ptr_eq(&Arc::downgrade(self))
                || !binding.exact_input(self, packet, original.at())
                || binding
                    .authenticated_observed_monotonic_ns
                    .is_none_or(|at| at > original.monotonic_ns())
            {
                return Err(CaptureFailure::InvalidPlan);
            }
            let mut state = self
                .state
                .try_lock()
                .map_err(|_| CaptureFailure::Contended)?;
            if state
                .system_device
                .as_ref()
                .is_none_or(|device| !original.belongs_to(device))
            {
                return Err(CaptureFailure::ForeignDevice);
            }
            if state.flows[binding.flow].inbound.invalid {
                return Err(CaptureFailure::FrameConflict);
            }
            if state.inbound_history.writes.len() >= MAX_SYSTEM_WRITES {
                return Err(CaptureFailure::Capacity);
            }
            state
                .inbound_history
                .writes
                .try_reserve(1)
                .map_err(|_| CaptureFailure::Capacity)?;
            binding
                .write
                .set(original)
                .map_err(|_| CaptureFailure::DuplicateWrite)?;
            state.inbound_history.writes.push(binding);
            Ok(())
        };
        if retain().is_err() {
            // A lost Full-write observation cannot be repaired by a later
            // duplicate sampled after a lifecycle change or room renewal.
            self.inbound_complete.store(false, Ordering::Release);
            self.gap();
        }
    }
}

impl KernelCaptureRuntime {
    pub(crate) fn capture_authenticated(
        &self,
        transport: &WireGuardTransport,
        source: &OriginalOverlayIngressSource,
        packet: &InboundPacket,
    ) -> Option<Arc<KernelIngressBinding>> {
        let scope = self.scope.upgrade()?;
        let captured = self.capture_inner(&scope, transport, source, packet);
        match captured {
            Ok(binding) => binding,
            Err(_) => {
                // A missing first input cannot be repaired by a later copy
                // borrowing a renewed room permit. This scope never rearms.
                scope.inbound_complete.store(false, Ordering::Release);
                scope.gap();
                None
            }
        }
    }

    fn capture_inner(
        &self,
        scope: &Arc<CaptureSession>,
        transport: &WireGuardTransport,
        source: &OriginalOverlayIngressSource,
        packet: &InboundPacket,
    ) -> Result<Option<Arc<KernelIngressBinding>>, CaptureFailure> {
        if !scope.inbound_complete.load(Ordering::Acquire) {
            return Ok(None);
        }
        let udp = parse_os_udp(&packet.packet).ok();
        let tcp = parse_tcp_segment(&packet.packet).ok();
        if udp.is_none() && tcp.is_none() {
            return Ok(None);
        }
        if tcp
            .as_ref()
            .is_some_and(|segment| segment.is_control_only() && !segment.is_syn())
        {
            return Ok(None);
        }
        let mut state = scope
            .state
            .try_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        let Some(index) = state.flows.iter().position(|flow| {
            flow.plan.peer == packet.peer_id
                && match flow.plan.protocol {
                    Protocol::Udp => udp
                        .as_ref()
                        .is_some_and(|parsed| parsed.flow == reverse(flow.plan.flow)),
                    Protocol::Tcp => tcp
                        .as_ref()
                        .is_some_and(|segment| segment.flow() == reverse(flow.plan.flow)),
                }
        }) else {
            return Ok(None);
        };
        if udp.as_ref().is_some_and(|parsed| {
            parsed.payload_bytes != state.flows[index].plan.payload_bytes
                || !state.flows[index]
                    .plan
                    .requests
                    .iter()
                    .any(|key| opposite(*key) == parsed.key)
        }) {
            return Ok(None);
        }
        let authenticated = source.session().authenticated_at();
        let read_at = match (source.original_udp_read(), source.original_relay_read()) {
            (Some(read), None) => read.received_at(),
            (None, Some(read)) => read.completed_at(),
            _ => return Err(CaptureFailure::OriginalIngressSource),
        };
        if !scope.is_live(authenticated)
            || read_at > authenticated
            || !source.session().belongs_to(transport)
            || source.session().peer_id() != packet.peer_id
            || packet.session_instance != Some(source.session().session_instance())
            || packet.from_previous_session != source.session().is_previous_session()
            || source.network_generation().is_none()
            || source
                .relay_endpoint()
                .is_some_and(|value| value.len() > MAX_ORIGINAL_ENDPOINT_BYTES)
            || source
                .relay_reader_endpoint()
                .is_some_and(|value| value.len() > MAX_ORIGINAL_ENDPOINT_BYTES)
            || (source.original_relay_read().is_some()
                && source.relay_peer_id() != Some(packet.peer_id.as_str()))
        {
            return Err(CaptureFailure::InvalidPlan);
        }
        let flow = &mut state.flows[index];
        if flow.inbound.invalid {
            return Err(CaptureFailure::FrameConflict);
        }
        let mut spans = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
        if let Some(parsed) = udp {
            if parsed.payload_bytes != flow.plan.payload_bytes {
                return Ok(None);
            }
            let Some(slot) = flow
                .plan
                .requests
                .iter()
                .position(|key| opposite(*key) == parsed.key)
            else {
                return Ok(None);
            };
            spans.push(ReadFrameSpan::new(slot, 0, 1));
        } else if let Some(segment) = tcp {
            if segment.is_syn() {
                let base = segment.sequence().wrapping_add(1);
                if flow.inbound.tcp_open.is_some_and(|old| old != base) {
                    flow.inbound.invalid = true;
                    return Err(CaptureFailure::FrameConflict);
                }
                flow.inbound.tcp_open = Some(base);
                return Ok(None);
            }
            if segment.is_control_only() {
                return Ok(None);
            }
            let base = flow
                .inbound
                .tcp_open
                .ok_or(CaptureFailure::MissingTcpOpen)?;
            let length = 4 + 63 + u32::from(flow.plan.payload_bytes);
            let mut slots = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
            for slot in 0..flow.plan.requests.len() {
                if segment.overlaps_frame(base.wrapping_add(slot as u32 * length), length as usize)
                {
                    if slots.len() == MAX_BINDINGS_PER_PACKET {
                        flow.inbound.invalid = true;
                        return Err(CaptureFailure::Capacity);
                    }
                    slots.push(slot);
                }
            }
            for slot in slots {
                if flow.inbound.coverage[slot].is_none() {
                    let key = opposite(flow.plan.requests[slot]);
                    let frame = TcpFramePlan::new(
                        reverse(flow.plan.flow),
                        TcpFrameKey {
                            run: key.run,
                            round: key.round,
                            sequence: key.sequence,
                            request_nonce: key.request_nonce,
                            kind: key.kind,
                        },
                        flow.plan.payload_bytes,
                    )
                    .ok_or(CaptureFailure::InvalidPlan)?;
                    flow.inbound.coverage[slot] = TcpFrameCoverage::new(
                        frame,
                        base.wrapping_add(slot as u32 * length),
                        authenticated,
                        scope.expires,
                    );
                }
                let coverage = flow.inbound.coverage[slot]
                    .as_mut()
                    .ok_or(CaptureFailure::InvalidPlan)?;
                if matches!(
                    coverage.observe(&segment, authenticated),
                    TcpCoverageResult::Conflict | TcpCoverageResult::Invalidated
                ) {
                    flow.inbound.invalid = true;
                    return Err(CaptureFailure::FrameConflict);
                }
                let (start, end) = coverage
                    .matching_span(&segment)
                    .ok_or(CaptureFailure::FrameConflict)?;
                spans.push(ReadFrameSpan::new(slot, start, end));
            }
        }
        if spans.is_empty() {
            return Ok(None);
        }
        // Try-only, before any post-decrypt await. First input for a frame owns
        // its original permit result, including unknown/contended results.
        let room = self.room.upgrade();
        let permit = room
            .as_ref()
            .ok_or(OriginalRoomSendFailure::MissingOriginal)
            .and_then(|room| {
                room.try_capture_original_send_permit(
                    &packet.peer_id,
                    &flow.plan.flow.dst_v4.to_string(),
                    &flow.plan.flow.src_v4.to_string(),
                )
            });
        let new_room = Arc::new(OriginalIncomingRoom {
            owner: self.room.clone(),
            permit,
        });
        let mut original_rooms = Vec::with_capacity(spans.len());
        for span in &spans {
            let saved =
                flow.inbound.original_room[span.slot()].get_or_insert_with(|| new_room.clone());
            original_rooms.push(saved.clone());
        }
        Ok(Some(Arc::new(KernelIngressBinding {
            scope: Arc::downgrade(scope),
            source: Arc::new(source.clone()),
            flow: index,
            spans,
            original_rooms,
            packet_len: packet.packet.len(),
            packet_sha256: Sha256::digest(&packet.packet).into(),
            authenticated_observed_monotonic_ns: super::super::clock::monotonic_ns(),
            write: OnceLock::new(),
        })))
    }
}

impl KernelIngressBinding {
    fn exact_input(&self, scope: &CaptureSession, packet: &[u8], at: Instant) -> bool {
        scope.is_live(at)
            && scope.inbound_complete.load(Ordering::Acquire)
            && self.source.session().authenticated_at() <= at
            && self.packet_len == packet.len()
            && self.packet_sha256 == <[u8; 32]>::from(Sha256::digest(packet))
            && !self.spans.is_empty()
            && self.spans.len() <= MAX_BINDINGS_PER_PACKET
    }

    pub(crate) fn write_context(
        self: &Arc<Self>,
        peers: &Arc<PeerManager>,
        packet: &[u8],
    ) -> Option<PacketWriteContext> {
        let scope = self.scope.upgrade()?;
        if !scope.peers.ptr_eq(&Arc::downgrade(peers))
            || !self.exact_input(&scope, packet, Instant::now())
            || self.original_rooms.len() != self.spans.len()
            || self
                .original_rooms
                .iter()
                .any(|room| room.permit.is_err() || room.owner.strong_count() == 0)
        {
            scope.gap();
            return None;
        }
        Some(Box::new(self.clone()))
    }
}

impl InboundHistory {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new() -> Self {
        Self { writes: Vec::new() }
    }

    #[cfg(unix)]
    pub(super) fn frame_complete(
        &self,
        flow: usize,
        slot: usize,
        plan: &RegisteredFlowPlan,
    ) -> bool {
        super::full::spans_complete(
            self.writes
                .iter()
                .filter(|binding| binding.flow == flow && binding.write.get().is_some())
                .flat_map(|binding| &binding.spans),
            slot,
            plan,
        )
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> Vec<WriteSnapshot> {
        self.writes
            .iter()
            .filter_map(|binding| {
                let write = binding.write.get()?;
                Some(WriteSnapshot {
                    scope: "original_authenticated_system_tun_full_history_only",
                    flow: binding.flow,
                    spans: binding.spans.clone(),
                    write_ordinal: write.ordinal(),
                    write_observed_monotonic_ns: write.monotonic_ns(),
                    authenticated_observed_monotonic_ns: binding
                        .authenticated_observed_monotonic_ns,
                    packet_len: binding.packet_len,
                    packet_sha256: hex::encode(binding.packet_sha256),
                    network_generation: binding.source.network_generation(),
                    session_instance: binding.source.session().session_instance(),
                    original_session_role: match binding.source.session().original_role() {
                        OriginalSessionRole::Active => "active",
                        OriginalSessionRole::Pending => "pending",
                        OriginalSessionRole::Previous => "previous",
                    },
                    original_room_captured: binding
                        .original_rooms
                        .iter()
                        .map(|room| room.permit.is_ok())
                        .collect(),
                    original_room_restricted: binding
                        .original_rooms
                        .iter()
                        .map(|room| matches!(room.permit, Ok(Some(_))))
                        .collect(),
                    original_room_owner_live: binding
                        .original_rooms
                        .iter()
                        .map(|room| room.owner.upgrade().is_some())
                        .collect(),
                    canonical_current_owner_verified: false,
                })
            })
            .collect()
    }
}

#[cfg(all(unix, test))]
mod tests;
