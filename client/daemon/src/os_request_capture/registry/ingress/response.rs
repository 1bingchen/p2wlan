//! Original REQUEST system-write contributors frozen at the first RESPONSE
//! system read. Unknown input never inherits a later write or renewed lease.
use super::*;
use crate::os_request_capture::registry::full::FrameSpanCoverage;
use crate::overlay_requests::{OverlayCreditOutcome, OverlayCreditStale, OverlayCreditUnknown};
use crate::transport::OriginalEncryptionSource;

type Outcome<T> = Result<T, OverlayCreditOutcome>;

pub(in crate::os_request_capture::registry) struct ResponseCapture {
    flow: usize,
    slot: usize,
    room: Option<Arc<OriginalIncomingRoom>>,
    original: Outcome<KernelResponseInput>,
}

struct KernelResponseInput {
    scope: Weak<CaptureSession>,
    read_at: Instant,
    read_monotonic_ns: u64,
    sources: Vec<Arc<KernelIngressBinding>>,
    room: Arc<OriginalIncomingRoom>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl ResponseCapture {
    pub(in crate::os_request_capture::registry) fn original_sources(
        &self,
    ) -> Outcome<&[Arc<KernelIngressBinding>]> {
        self.original
            .as_ref()
            .map(|input| input.sources.as_slice())
            .map_err(|reason| *reason)
    }
}

#[cfg(unix)]
#[derive(Serialize)]
pub(in crate::os_request_capture::registry) struct ResponseSnapshot {
    known: bool,
    original_room_captured: bool,
    original_system_write_contributors: usize,
    original_room_restricted: bool,
    capture_failure: Option<String>,
}

impl KernelResponseInput {
    fn capture(
        scope: &Arc<CaptureSession>,
        state: &RegistryState,
        flow_index: usize,
        slot: usize,
        read: &KernelRead,
    ) -> Outcome<Self> {
        use OverlayCreditOutcome::{Stale, Unknown};
        let flow = &state.flows[flow_index];
        if !scope.inbound_complete.load(Ordering::Acquire) || flow.inbound.invalid {
            return Err(Unknown(OverlayCreditUnknown::OriginalSource));
        }
        if flow.plan.requests[slot].kind != RequestKind::Response {
            return Err(Stale(OverlayCreditStale::Identity));
        }
        let mut coverage = FrameSpanCoverage::new(&flow.plan, slot)
            .ok_or(Unknown(OverlayCreditUnknown::OriginalPublication))?;
        let first_peer = flow.requests[slot]
            .first_peer
            .as_ref()
            .ok_or(Unknown(OverlayCreditUnknown::OriginalAuthorization))?;
        let room = flow.inbound.original_room[slot]
            .as_ref()
            .ok_or(Unknown(OverlayCreditUnknown::RoomAuthority))?;
        let mut sources = Vec::new();
        // The history is append-only in actual SystemTun write order and has
        // at most MAX_SYSTEM_WRITES. Take earliest contributors, not later
        // retransmissions which could replace an original key/room source.
        for source in state
            .inbound_history
            .writes
            .iter()
            .filter(|source| source.flow == flow_index)
        {
            let Some(write) = source.write.get() else {
                continue;
            };
            if write.at() > read.at() || write.monotonic_ns() > read.monotonic_ns() {
                continue;
            }
            let mut contributes = false;
            for span in &source.spans {
                contributes |= coverage
                    .add(span)
                    .map_err(|_| Unknown(OverlayCreditUnknown::OriginalPublication))?;
            }
            if !contributes {
                continue;
            }
            if !write.is_current()
                || !write.same_device_as(read)
                || !source.scope.ptr_eq(&Arc::downgrade(scope))
                || !first_peer.matches_original_ingress(&source.source, read.at())
                || source.spans.len() != source.original_rooms.len()
                || source
                    .spans
                    .iter()
                    .zip(&source.original_rooms)
                    .any(|(span, saved)| span.slot() == slot && !Arc::ptr_eq(saved, room))
            {
                return Err(Stale(OverlayCreditStale::Identity));
            }
            sources
                .try_reserve(1)
                .map_err(|_| Unknown(OverlayCreditUnknown::OriginalPublication))?;
            sources.push(source.clone());
            if coverage.is_complete() {
                break;
            }
        }
        if !coverage.is_complete() || sources.is_empty() {
            return Err(Unknown(OverlayCreditUnknown::OriginalPublication));
        }
        room.permit
            .as_ref()
            .map_err(|reason| OverlayCreditOutcome::from(*reason))?;
        Ok(Self {
            scope: Arc::downgrade(scope),
            read_at: read.at(),
            read_monotonic_ns: read.monotonic_ns(),
            sources,
            room: room.clone(),
        })
    }

    fn original_permit(&self) -> Outcome<Option<RoomSendPermit>> {
        self.room.permit.clone().map_err(OverlayCreditOutcome::from)
    }

    // Intrinsic history only. Later retirement must not erase actual Full
    // observations; the sole final owner separately checks current lifetimes.
    fn matches_original_read(&self, scope: &Weak<CaptureSession>, read: &KernelRead) -> bool {
        self.scope.ptr_eq(scope)
            && self.read_at <= read.at()
            && !self.sources.is_empty()
            && self.sources.iter().all(|source| {
                source.write.get().is_some_and(|write| {
                    write.same_device_as(read)
                        && write.at() <= self.read_at
                        && write.monotonic_ns() <= self.read_monotonic_ns
                })
            })
    }
}

impl CaptureSession {
    pub(in crate::os_request_capture::registry) fn first_response_inputs(
        self: &Arc<Self>,
        state: &mut RegistryState,
        flow: usize,
        slots: &[usize],
        read: &KernelRead,
    ) -> Vec<Arc<ResponseCapture>> {
        let mut inputs = Vec::new();
        for slot in slots {
            if state.flows[flow].plan.requests[*slot].kind != RequestKind::Response {
                continue;
            }
            if state.flows[flow].requests[*slot].first_response.is_none() {
                let original = KernelResponseInput::capture(self, state, flow, *slot, read);
                if original.is_err() {
                    self.gap();
                }
                state.flows[flow].requests[*slot].first_response =
                    Some(Arc::new(ResponseCapture {
                        flow,
                        slot: *slot,
                        room: state.flows[flow].inbound.original_room[*slot].clone(),
                        original,
                    }));
            }
            if let Some(input) = &state.flows[flow].requests[*slot].first_response {
                inputs.push(input.clone());
            }
        }
        inputs
    }
}

pub(in crate::os_request_capture::registry) fn merge_original_permits(
    left: Option<RoomSendPermit>,
    right: Option<RoomSendPermit>,
) -> Outcome<Option<RoomSendPermit>> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(old), Some(other)) => Ok(Some(old.intersect_original(&other)?)),
        _ => Err(OverlayCreditOutcome::Stale(
            OverlayCreditStale::RoomAuthority,
        )),
    }
}

/// Missing sampling never replaces the original business policy. Any known
/// original grant still constrains the entire packet, including coalesced
/// frames whose source proof is incomplete. This is not a native-credit guard.
pub(in crate::os_request_capture::registry) fn known_route_room<'a>(
    rooms: impl Iterator<Item = &'a Arc<OriginalIncomingRoom>>,
    current: Option<&Arc<RoomAuthorization>>,
) -> Option<Outcome<Option<RoomSendPermit>>> {
    let mut saved = None;
    for room in rooms {
        let Ok(permit) = &room.permit else {
            continue;
        };
        let valid = match permit {
            None => current.is_none_or(|current| !current.enabled()),
            Some(permit) => {
                permit.is_valid()
                    && current.is_some_and(|current| {
                        room.owner.ptr_eq(&Arc::downgrade(current))
                            && !current.original_snapshot_is_poisoned()
                    })
            }
        };
        if !valid {
            return Some(Err(OverlayCreditOutcome::Stale(
                OverlayCreditStale::RoomAuthority,
            )));
        }
        saved = Some(match saved {
            None => permit.clone(),
            Some(previous) => match merge_original_permits(previous, permit.clone()) {
                Ok(merged) => merged,
                Err(reason) => return Some(Err(reason)),
            },
        });
    }
    saved.map(Ok)
}

impl KernelReadBinding {
    fn is_response(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| self.plan.requests[*slot].kind == RequestKind::Response)
    }

    fn response_inputs(&self) -> Outcome<Vec<&KernelResponseInput>> {
        if self.original_responses.len() != self.slots.len()
            || self.slots.is_empty()
            || self.slots.len() > MAX_BINDINGS_PER_PACKET
        {
            return Err(OverlayCreditOutcome::Unknown(
                OverlayCreditUnknown::OriginalSource,
            ));
        }
        self.original_responses
            .iter()
            .zip(&self.slots)
            .map(|(input, slot)| {
                if input.flow != self.flow || input.slot != *slot {
                    return Err(OverlayCreditOutcome::Stale(OverlayCreditStale::Identity));
                }
                input.original.as_ref().map_err(|reason| *reason)
            })
            .collect()
    }

    fn frozen_response_permit(&self) -> Outcome<Option<RoomSendPermit>> {
        let mut saved: Option<Option<RoomSendPermit>> = None;
        for input in self.response_inputs()? {
            let permit = input.original_permit()?;
            saved = Some(match (saved, permit) {
                (None, permit) => permit,
                (Some(old), other) => merge_original_permits(old, other)?,
            });
        }
        saved.ok_or(OverlayCreditOutcome::Unknown(
            OverlayCreditUnknown::RoomAuthority,
        ))
    }

    pub(crate) fn original_room_matches_permit(&self, permit: Option<&RoomSendPermit>) -> bool {
        if !self.is_response() {
            return self.original_request_room_matches_permit(permit);
        }
        self.response_inputs().is_ok_and(|inputs| {
            inputs
                .iter()
                .all(|input| input.matches_original_read(&self.scope, &self.read))
        }) && self
            .frozen_response_permit()
            .is_ok_and(|saved| saved.as_ref() == permit)
    }

    pub(crate) fn original_response_matches_encryption(
        &self,
        tx: &OriginalEncryptionSource,
    ) -> bool {
        !self.is_response()
            || self.response_inputs().is_ok_and(|inputs| {
                inputs.iter().all(|input| {
                    input.sources.iter().all(|source| {
                        tx.matches_original_receive_source(source.source.session())
                            && source.source.session().authenticated_at() <= tx.encrypted_at()
                    })
                })
            })
    }

    /// Unknown sampling keeps the original forwarding policy and is excluded
    /// from native proof above. A known original grant cannot borrow renewal.
    pub(crate) fn original_room_for_route(
        &self,
        current: Option<&Arc<RoomAuthorization>>,
        peer: &str,
        target: &str,
        local: &str,
    ) -> Option<Outcome<Option<RoomSendPermit>>> {
        let original = if self.is_response() {
            known_route_room(
                self.original_responses
                    .iter()
                    .filter_map(|input| input.room.as_ref()),
                current,
            )
        } else {
            known_route_room(self.original_request_rooms.iter(), current)
        };
        original.map(|original| {
            if peer != self.plan.peer
                || target != self.plan.flow.dst_v4.to_string()
                || local != self.plan.flow.src_v4.to_string()
            {
                return Err(OverlayCreditOutcome::Stale(OverlayCreditStale::Identity));
            }
            original
        })
    }
}

#[cfg(unix)]
impl ResponseCapture {
    pub(in crate::os_request_capture::registry) fn snapshot(&self) -> ResponseSnapshot {
        ResponseSnapshot {
            known: self.original.is_ok(),
            original_room_captured: self.room.as_ref().is_some_and(|room| room.permit.is_ok()),
            original_system_write_contributors: self
                .original
                .as_ref()
                .map_or(0, |input| input.sources.len()),
            original_room_restricted: self
                .room
                .as_ref()
                .is_some_and(|room| matches!(room.permit, Ok(Some(_)))),
            capture_failure: self
                .original
                .as_ref()
                .err()
                .map(|reason| format!("{reason:?}")),
        }
    }
}

#[cfg(all(unix, test))]
mod tests;
