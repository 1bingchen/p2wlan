//! First request-read room permission, before routing can suspend. Unknown
//! sampling remains unknown; the original business policy still forwards.
use super::*;
use crate::business_evidence::RequestKind;
use crate::overlay_requests::{OverlayCreditOutcome, OverlayCreditUnknown};
use crate::rooms::{OriginalRoomSendFailure, RoomAuthorization, RoomSendPermit};
use ingress::{merge_original_permits, OriginalIncomingRoom};

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct ReadRoomSnapshot {
    known: bool,
    restricted: bool,
    capture_failure: Option<String>,
}

impl OriginalIncomingRoom {
    fn capture_request_read(
        room: Option<&Weak<RoomAuthorization>>,
        peer: &read_peer::FirstReadPeer,
        plan: &RegisteredFlowPlan,
    ) -> Self {
        let owner = room.cloned().unwrap_or_default();
        // Registration labels cannot constrain business traffic. A real
        // first-read PeerManager expectation must have matched this target.
        let permit = if peer.is_known() {
            owner
                .upgrade()
                .ok_or(OriginalRoomSendFailure::MissingOriginal)
                .and_then(|room| {
                    room.try_capture_original_send_permit(
                        &plan.peer,
                        &plan.flow.dst_v4.to_string(),
                        &plan.flow.src_v4.to_string(),
                    )
                })
        } else {
            Err(OriginalRoomSendFailure::MissingOriginal)
        };
        Self { owner, permit }
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> ReadRoomSnapshot {
        ReadRoomSnapshot {
            known: self.permit.is_ok(),
            restricted: self.permit.as_ref().is_ok_and(Option::is_some),
            capture_failure: self.permit.as_ref().err().map(|e| format!("{e:?}")),
        }
    }
}

impl CaptureSession {
    pub(super) fn first_read_request_rooms(
        &self,
        flow: &mut FlowState,
        slots: &[usize],
        room: Option<&Weak<RoomAuthorization>>,
    ) -> Vec<Arc<OriginalIncomingRoom>> {
        if slots
            .iter()
            .any(|slot| flow.plan.requests[*slot].kind != RequestKind::Request)
        {
            return Vec::new();
        }
        slots
            .iter()
            .map(|slot| {
                let request = &mut flow.requests[*slot];
                request
                    .first_request_room
                    .get_or_insert_with(|| {
                        let captured = match request.first_peer.as_ref() {
                            Some(peer) => {
                                OriginalIncomingRoom::capture_request_read(room, peer, &flow.plan)
                            }
                            None => OriginalIncomingRoom {
                                owner: room.cloned().unwrap_or_default(),
                                permit: Err(OriginalRoomSendFailure::MissingOriginal),
                            },
                        };
                        if captured.permit.is_err() {
                            self.gap();
                        }
                        Arc::new(captured)
                    })
                    .clone()
            })
            .collect()
    }
}

impl KernelReadBinding {
    /// Pure original permission comparison. A genuine historical Full is not
    /// erased when the room expires or is revoked after its actual write.
    pub(super) fn original_request_room_matches_permit(
        &self,
        permit: Option<&RoomSendPermit>,
    ) -> bool {
        frozen_request_permit(&self.original_request_rooms, self.slots.len())
            .is_ok_and(|original| original.as_ref() == permit)
    }
}

fn frozen_request_permit(
    rooms: &[Arc<OriginalIncomingRoom>],
    slots: usize,
) -> Result<Option<RoomSendPermit>, OverlayCreditOutcome> {
    let unknown = OverlayCreditOutcome::Unknown(OverlayCreditUnknown::RoomAuthority);
    if slots == 0 || slots > MAX_BINDINGS_PER_PACKET || rooms.len() != slots {
        return Err(unknown);
    }
    let mut saved = None;
    for room in rooms {
        let permit = room.permit.as_ref().map_err(|_| unknown)?.clone();
        saved = Some(match saved {
            None => permit,
            Some(previous) => merge_original_permits(previous, permit)?,
        });
    }
    saved.ok_or(unknown)
}

#[cfg(all(unix, test))]
mod tests;
