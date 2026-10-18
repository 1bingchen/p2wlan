#[cfg(unix)]
use super::clock::{monotonic_ns, NativeClockScope};
use super::device::{DeviceLease, KernelRead};
use super::plan::{CaptureFailure, Protocol, RegisteredFlowPlan, MAX_BINDINGS_PER_PACKET};
#[cfg(any(target_os = "linux", all(unix, test)))]
use super::plan::{RegistrationPlan, CAPTURE_TTL_SECS, MAX_REQUESTS};
use crate::business_evidence::parse_os_udp;
use crate::business_evidence::tcp_frame::{
    parse_tcp_segment, TcpCoverageResult, TcpFrameCoverage, TcpFrameKey, TcpFramePlan,
};
use crate::dataplane::OutboundPacket;
use crate::peer::PeerManager;
#[cfg(unix)]
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
#[cfg(any(target_os = "linux", all(unix, test)))]
use std::time::Duration;
use std::time::Instant;

mod full;
mod ingress;
mod read_peer;
pub(crate) use ingress::{KernelCaptureRuntime, KernelIngressBinding};

#[cfg(any(target_os = "linux", all(unix, test)))]
static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);

pub(crate) struct CaptureSession {
    #[cfg(unix)]
    owner: u64,
    active: AtomicBool,
    inbound_complete: AtomicBool,
    read_complete: AtomicBool,
    expires: Instant,
    peers: Weak<PeerManager>,
    #[cfg(unix)]
    capture_id: [u8; 16],
    #[cfg(unix)]
    producer_scope: [u8; 16],
    #[cfg(unix)]
    clock_scope: Option<NativeClockScope>,
    state: Mutex<RegistryState>,
    gaps: AtomicU64,
}

struct RegistryState {
    flows: Vec<FlowState>,
    original_device: Option<Arc<KernelRead>>,
    system_device: Option<Weak<DeviceLease>>,
    full_history: full::FullHistory,
    inbound_history: ingress::InboundHistory,
    #[cfg(unix)]
    requests: usize,
    #[cfg(unix)]
    revision: u64,
    #[cfg(unix)]
    producers: std::collections::BTreeSet<[u8; 16]>,
}
struct FlowState {
    plan: Arc<RegisteredFlowPlan>,
    #[cfg(unix)]
    producer_scope: [u8; 16],
    tcp_open: Option<u32>,
    invalid: bool,
    requests: Vec<RequestReadState>,
    inbound: ingress::InboundFlow,
}
struct RequestReadState {
    first_peer: Option<Arc<read_peer::FirstReadPeer>>,
    first_response: Option<Arc<ingress::ResponseCapture>>,
    read_events: u64,
    first_read: Option<Arc<KernelRead>>,
    last_read: Option<Arc<KernelRead>>,
    tcp: Option<TcpFrameCoverage>,
    udp_complete: bool,
}

/// Private fields and no deserializer: registration JSON and arbitrary Any
/// values cannot construct this type. Arc clones retain the same observation;
/// device and scope owners remain weak, including after queue/crypto handoff.
pub(crate) struct KernelReadBinding {
    scope: Weak<CaptureSession>,
    read: Arc<KernelRead>,
    flow: usize,
    slots: Vec<usize>,
    packet_len: usize,
    packet_sha256: [u8; 32],
    plan: Arc<RegisteredFlowPlan>,
    spans: Vec<full::ReadFrameSpan>,
    physical_publication: crate::overlay_requests::PhysicalSendPublication,
    original_peers: Vec<Arc<read_peer::FirstReadPeer>>,
    original_responses: Vec<Arc<ingress::ResponseCapture>>,
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct ReadSnapshot {
    pub(super) schema_version: u8,
    scope: &'static str,
    owner: u64,
    capture_id: String,
    producer_scope: String,
    clock_scope: Option<NativeClockScope>,
    observed_monotonic_ns: Option<u64>,
    registration_revision: u64,
    total_registered_requests: usize,
    registration_sets: usize,
    active: bool,
    gaps: u64,
    requests: Vec<RequestSnapshot>,
    historical_full_packets: Vec<full::FullPacketSnapshot>,
    system_tun_full_writes: Vec<ingress::WriteSnapshot>,
    daemon_registration_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
    incoming_provenance_complete: bool,
    original_read_observation_complete: bool,
}
#[cfg(unix)]
#[derive(Serialize)]
struct RequestSnapshot {
    flow: usize,
    producer_scope: String,
    sequence: u32,
    run_nonce: String,
    round_nonce: String,
    request_nonce: String,
    kind: &'static str,
    protocol: &'static str,
    read_events: u64,
    first_read_ordinal: Option<u64>,
    last_read_ordinal: Option<u64>,
    first_read_monotonic_ns: Option<u64>,
    last_read_monotonic_ns: Option<u64>,
    kernel_frame_read_complete: bool,
    flow_invalid: bool,
    historical_frame_full_complete: bool,
    incoming_frame_system_write_complete: bool,
    incoming_flow_invalid: bool,
    original_peer: Option<read_peer::ReadPeerSnapshot>,
    original_response_input: Option<ingress::ResponseSnapshot>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
#[derive(Serialize)]
pub(super) struct RegistrationReceipt {
    scope: &'static str,
    owner: u64,
    capture_id: String,
    producer_scope: String,
    registration_revision: u64,
    added_requests: usize,
    total_requests: usize,
}

impl CaptureSession {
    // Only the control module calls this after adopting its actual connected
    // descriptor. The plan itself remains labels, never a system read proof.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn from_control_descriptor(
        plan: RegistrationPlan,
        peers: &Arc<PeerManager>,
    ) -> Result<Arc<Self>, CaptureFailure> {
        let owner = NEXT_SCOPE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CaptureFailure::CounterExhausted)?;
        let expires = Instant::now()
            .checked_add(Duration::from_secs(CAPTURE_TTL_SECS))
            .ok_or(CaptureFailure::Capacity)?;
        let session = Arc::new(Self {
            owner,
            active: AtomicBool::new(true),
            inbound_complete: AtomicBool::new(true),
            read_complete: AtomicBool::new(true),
            expires,
            peers: Arc::downgrade(peers),
            capture_id: plan.capture_id,
            producer_scope: plan.producer_scope,
            clock_scope: NativeClockScope::capture(),
            state: Mutex::new(RegistryState {
                flows: Vec::new(),
                original_device: None,
                system_device: None,
                full_history: full::FullHistory::new(),
                inbound_history: ingress::InboundHistory::new(),
                requests: 0,
                revision: 0,
                producers: std::collections::BTreeSet::new(),
            }),
            gaps: AtomicU64::new(0),
        });
        if !plan.flows.is_empty() {
            session.register(plan)?;
        }
        Ok(session)
    }

    /// Append immutable expected inputs under the actual descriptor scope.
    /// No flow is replaced, rearmed or assigned connection-owner authority.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn register(
        &self,
        plan: RegistrationPlan,
    ) -> Result<RegistrationReceipt, CaptureFailure> {
        if plan.capture_id != self.capture_id || plan.flows.is_empty() {
            return Err(CaptureFailure::InvalidPlan);
        }
        let producer = plan.producer_scope;
        let added: usize = plan.flows.iter().map(|flow| flow.requests.len()).sum();
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        if !self.is_live(Instant::now()) {
            return Err(CaptureFailure::Expired);
        }
        let total = state
            .requests
            .checked_add(added)
            .filter(|n| *n <= MAX_REQUESTS)
            .ok_or(CaptureFailure::Capacity)?;
        if state.producers.contains(&producer)
            || plan.flows.iter().any(|incoming| {
                state.flows.iter().any(|old| {
                    (old.plan.protocol == incoming.protocol && old.plan.flow == incoming.flow)
                        || (old.plan.protocol == incoming.protocol
                            && incoming
                                .requests
                                .iter()
                                .any(|key| old.plan.requests.contains(key)))
                })
            })
        {
            return Err(CaptureFailure::RegistrationConflict);
        }
        let revision = state
            .revision
            .checked_add(1)
            .ok_or(CaptureFailure::CounterExhausted)?;
        let incoming: Vec<_> = plan
            .flows
            .into_iter()
            .map(|plan| {
                let requests = plan
                    .requests
                    .iter()
                    .map(|_| RequestReadState {
                        first_peer: None,
                        first_response: None,
                        read_events: 0,
                        first_read: None,
                        last_read: None,
                        tcp: None,
                        udp_complete: false,
                    })
                    .collect();
                FlowState {
                    inbound: ingress::InboundFlow::new(plan.requests.len()),
                    plan: Arc::new(plan),
                    producer_scope: producer,
                    tcp_open: None,
                    invalid: false,
                    requests,
                }
            })
            .collect();
        state.flows.extend(incoming);
        state.producers.insert(producer);
        state.requests = total;
        state.revision = revision;
        Ok(RegistrationReceipt {
            scope: "registered_expected_inputs_only",
            owner: self.owner,
            capture_id: hex::encode(self.capture_id),
            producer_scope: hex::encode(producer),
            registration_revision: revision,
            added_requests: added,
            total_requests: total,
        })
    }

    pub(crate) fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }

    pub(super) fn bind_system_device(&self, device: &Arc<DeviceLease>) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            self.gap();
            return false;
        };
        if state.system_device.is_some() || !self.is_live(Instant::now()) {
            self.gap();
            return false;
        }
        state.system_device = Some(Arc::downgrade(device));
        true
    }
    #[cfg(unix)]
    pub(super) fn expires(&self) -> Instant {
        self.expires
    }
    fn is_live(&self, at: Instant) -> bool {
        self.active.load(Ordering::Acquire) && at < self.expires
    }
    fn gap(&self) {
        // No retry/lock: saturated diagnostic coverage never wraps or grants
        // evidence, and can never stop the original packet's forwarding.
        let _ = self
            .gaps
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1));
    }

    pub(super) fn observe_system_read(
        self: &Arc<Self>,
        original: KernelRead,
        packet: &[u8],
    ) -> Option<KernelReadBinding> {
        if !original.is_current()
            || !self.is_live(original.at())
            || !self.read_complete.load(Ordering::Acquire)
        {
            return None;
        }
        match self.capture_read(original, packet) {
            Ok(binding) => binding,
            Err(_) => {
                // A lost original read cannot be replaced by a later copy
                // sampled under a newer peer lifecycle or network generation.
                self.read_complete.store(false, Ordering::Release);
                self.gap();
                None
            }
        }
    }

    fn capture_read(
        self: &Arc<Self>,
        original: KernelRead,
        packet: &[u8],
    ) -> Result<Option<KernelReadBinding>, CaptureFailure> {
        let udp = parse_os_udp(packet).ok();
        let tcp = parse_tcp_segment(packet).ok();
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
        let Some(index) = state
            .flows
            .iter()
            .position(|flow| match flow.plan.protocol {
                Protocol::Udp => udp
                    .as_ref()
                    .is_some_and(|parsed| parsed.flow == flow.plan.flow),
                Protocol::Tcp => tcp
                    .as_ref()
                    .is_some_and(|parsed| parsed.flow() == flow.plan.flow),
            })
        else {
            return Ok(None);
        };
        if state
            .original_device
            .as_ref()
            .is_some_and(|first| !first.same_device(&original))
        {
            return Err(CaptureFailure::ForeignDevice);
        }
        let original = Arc::new(original);
        if state.original_device.is_none() {
            state.original_device = Some(original.clone());
        }
        let flow = &mut state.flows[index];
        let plan = flow.plan.clone();
        if flow.invalid {
            return Err(CaptureFailure::FrameConflict);
        }
        let mut slots = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
        let mut spans = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
        if let Some(parsed) = udp {
            if plan.protocol != Protocol::Udp || parsed.payload_bytes != plan.payload_bytes {
                return Ok(None);
            }
            if let Some(slot) = plan.requests.iter().position(|key| *key == parsed.key) {
                slots.push(slot);
                spans.push(full::ReadFrameSpan::new(slot, 0, 1));
                flow.requests[slot].udp_complete = true;
            }
        } else if let Some(segment) = tcp {
            if plan.protocol != Protocol::Tcp {
                return Ok(None);
            }
            if segment.is_syn() {
                let opened = segment.sequence().wrapping_add(1);
                if flow.tcp_open.is_some_and(|previous| previous != opened) {
                    flow.invalid = true;
                    return Err(CaptureFailure::FrameConflict);
                }
                flow.tcp_open = Some(opened);
                // SYN/SYN-ACK are only sequence anchors, never application data.
                return Ok(None);
            }
            if segment.is_control_only() {
                return Ok(None);
            }
            let base = flow.tcp_open.ok_or(CaptureFailure::MissingTcpOpen)?;
            let wire_len = 4 + 63 + u32::from(plan.payload_bytes);
            // First find all overlaps. The batch bound is checked before any
            // coverage mutation, so overflow cannot leave partial acceptance.
            for slot in 0..plan.requests.len() {
                let start = base.wrapping_add((slot as u32).wrapping_mul(wire_len));
                if segment.overlaps_frame(start, wire_len as usize) {
                    if slots.len() == MAX_BINDINGS_PER_PACKET {
                        flow.invalid = true;
                        return Err(CaptureFailure::Capacity);
                    }
                    slots.push(slot);
                }
            }
            for slot in &slots {
                let key = plan.requests[*slot];
                let read = &mut flow.requests[*slot];
                if read.tcp.is_none() {
                    let frame = TcpFramePlan::new(
                        plan.flow,
                        TcpFrameKey {
                            run: key.run,
                            round: key.round,
                            sequence: key.sequence,
                            request_nonce: key.request_nonce,
                            kind: key.kind,
                        },
                        plan.payload_bytes,
                    )
                    .ok_or(CaptureFailure::InvalidPlan)?;
                    read.tcp = TcpFrameCoverage::new(
                        frame,
                        base.wrapping_add((*slot as u32).wrapping_mul(wire_len)),
                        original.at(),
                        self.expires,
                    );
                }
                let coverage = read.tcp.as_mut().ok_or(CaptureFailure::InvalidPlan)?;
                if matches!(
                    coverage.observe(&segment, original.at()),
                    TcpCoverageResult::Conflict | TcpCoverageResult::Invalidated
                ) {
                    flow.invalid = true;
                    return Err(CaptureFailure::FrameConflict);
                }
                let (start, end) = coverage
                    .matching_span(&segment)
                    .ok_or(CaptureFailure::FrameConflict)?;
                spans.push(full::ReadFrameSpan::new(*slot, start, end));
            }
        }
        if slots.is_empty() {
            return Ok(None);
        }
        let original_peers = self.first_read_peers(flow, &slots);
        for slot in &slots {
            let read = &mut flow.requests[*slot];
            read.read_events = read
                .read_events
                .checked_add(1)
                .ok_or(CaptureFailure::CounterExhausted)?;
            if read.first_read.is_none() {
                read.first_read = Some(original.clone());
            }
            read.last_read = Some(original.clone());
        }
        let original_responses = self.first_response_inputs(&mut state, index, &slots, &original);
        Ok(Some(KernelReadBinding {
            scope: Arc::downgrade(self),
            read: original,
            flow: index,
            slots,
            packet_len: packet.len(),
            packet_sha256: Sha256::digest(packet).into(),
            plan,
            spans,
            physical_publication: crate::overlay_requests::PhysicalSendPublication::new(),
            original_peers,
            original_responses,
        }))
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> Result<ReadSnapshot, CaptureFailure> {
        let state = self
            .state
            .try_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        let mut requests = Vec::new();
        for (flow_index, flow) in state.flows.iter().enumerate() {
            let plan = &flow.plan;
            for (key, read) in plan.requests.iter().zip(&flow.requests) {
                requests.push(RequestSnapshot {
                    flow: flow_index,
                    producer_scope: hex::encode(flow.producer_scope),
                    sequence: key.sequence,
                    run_nonce: hex::encode(key.run),
                    round_nonce: hex::encode(key.round),
                    request_nonce: hex::encode(key.request_nonce),
                    kind: match key.kind {
                        crate::business_evidence::RequestKind::Request => "request",
                        crate::business_evidence::RequestKind::Response => "response",
                    },
                    protocol: match plan.protocol {
                        Protocol::Udp => "udp",
                        Protocol::Tcp => "tcp",
                    },
                    read_events: read.read_events,
                    first_read_ordinal: read.first_read.as_ref().map(|read| read.ordinal()),
                    last_read_ordinal: read.last_read.as_ref().map(|read| read.ordinal()),
                    first_read_monotonic_ns: read
                        .first_read
                        .as_ref()
                        .map(|read| read.monotonic_ns()),
                    last_read_monotonic_ns: read.last_read.as_ref().map(|read| read.monotonic_ns()),
                    kernel_frame_read_complete: !flow.invalid
                        && (read.udp_complete
                            || read.tcp.as_ref().is_some_and(|tcp| tcp.is_complete())),
                    flow_invalid: flow.invalid,
                    historical_frame_full_complete: !flow.invalid
                        && state.full_history.frame_complete(
                            flow_index,
                            key.sequence as usize,
                            plan,
                        ),
                    incoming_frame_system_write_complete: !flow.inbound.invalid
                        && state.inbound_history.frame_complete(
                            flow_index,
                            key.sequence as usize,
                            plan,
                        ),
                    incoming_flow_invalid: flow.inbound.invalid,
                    original_peer: read.first_peer.as_ref().map(|peer| peer.snapshot()),
                    original_response_input: read
                        .first_response
                        .as_ref()
                        .map(|input| input.snapshot()),
                });
            }
        }
        Ok(ReadSnapshot {
            schema_version: 1,
            scope: "registered_kernel_read_only",
            owner: self.owner,
            capture_id: hex::encode(self.capture_id),
            producer_scope: hex::encode(self.producer_scope),
            clock_scope: self.clock_scope.clone(),
            observed_monotonic_ns: monotonic_ns(),
            registration_revision: state.revision,
            total_registered_requests: state.requests,
            registration_sets: state.producers.len(),
            active: self.is_live(Instant::now()),
            gaps: self.gaps.load(Ordering::Relaxed),
            requests,
            historical_full_packets: state.full_history.snapshot(),
            system_tun_full_writes: state.inbound_history.snapshot(),
            // These remain false: registration data and completed system reads
            // are not a complete original OS-write/daemon/physical/once chain.
            daemon_registration_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
            incoming_provenance_complete: self.inbound_complete.load(Ordering::Acquire),
            original_read_observation_complete: self.read_complete.load(Ordering::Acquire),
        })
    }
}

impl KernelReadBinding {
    pub(crate) fn is_current_at(&self, observed_at: Instant) -> bool {
        self.scope.upgrade().is_some_and(|scope| {
            scope.is_live(observed_at)
                && scope.read_complete.load(Ordering::Acquire)
                && self.read.is_current()
                && self.read.at() <= observed_at
                && scope
                    .state
                    .try_lock()
                    .is_ok_and(|state| !state.flows[self.flow].invalid)
        })
    }

    pub(crate) fn exact_input(
        &self,
        peers: &Arc<PeerManager>,
        packet: &[u8],
        observed_at: Instant,
    ) -> bool {
        self.is_current_at(observed_at)
            && self.scope.upgrade().is_some_and(|scope| {
                Weak::ptr_eq(&scope.peers, &Arc::downgrade(peers))
                    && self.original_peer_identity_is_current(&scope, observed_at)
                    && scope.is_live(observed_at)
                    && self.read.is_current()
                    && self.read.at() <= observed_at
                    && self.packet_len == packet.len()
                    && self.packet_sha256 == <[u8; 32]>::from(Sha256::digest(packet))
                    && !self.slots.is_empty()
                    && self.slots.len() <= MAX_BINDINGS_PER_PACKET
            })
    }

    pub(crate) fn exact_route(
        &self,
        peers: &Arc<PeerManager>,
        packet: &OutboundPacket,
        observed_at: Instant,
    ) -> bool {
        self.exact_input(peers, &packet.packet, observed_at)
            && packet.peer_id == self.plan.peer
            && packet.dst_ip == self.plan.flow.dst_v4.to_string()
            && self.original_response_matches_permit(packet.room_authorization.as_ref())
    }
}
