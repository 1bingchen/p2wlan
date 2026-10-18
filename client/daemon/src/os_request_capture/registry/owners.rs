//! Fixed weak identities of real daemon owners. No actor or queue is retained
//! by a historical request; upgrades live only during its synchronous commit.
use super::*;
use crate::{
    relay::RelayTransport, rooms::RoomAuthorization, transport::WireGuardTransport,
    udp::UdpTransport,
};
use tokio::sync::RwLock;

pub(super) struct OriginalKernelOwners {
    wireguard: crate::transport::OriginalKernelTransportOwners,
    udp: Weak<RwLock<Option<UdpTransport>>>,
    relay: Weak<RwLock<Option<RelayTransport>>>,
    room: Weak<RoomAuthorization>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) struct OriginalKernelCurrentOwners {
    pub(crate) wireguard: crate::transport::OriginalKernelTransportCurrent,
    pub(crate) udp: Arc<RwLock<Option<UdpTransport>>>,
    pub(crate) relay: Arc<RwLock<Option<RelayTransport>>>,
    pub(crate) room: Arc<RoomAuthorization>,
}

impl OriginalKernelOwners {
    fn same_owner(&self, other: &Self) -> bool {
        self.wireguard.same_owner(&other.wireguard)
            && self.udp.ptr_eq(&other.udp)
            && self.relay.ptr_eq(&other.relay)
            && self.room.ptr_eq(&other.room)
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn upgrade(&self) -> Option<OriginalKernelCurrentOwners> {
        Some(OriginalKernelCurrentOwners {
            wireguard: self.wireguard.upgrade()?,
            udp: self.udp.upgrade()?,
            relay: self.relay.upgrade()?,
            room: self.room.upgrade()?,
        })
    }
}

impl CaptureSession {
    pub(crate) fn bind_original_current_owners(
        &self,
        wireguard: &WireGuardTransport,
        udp: &Arc<RwLock<Option<UdpTransport>>>,
        relay: &Arc<RwLock<Option<RelayTransport>>>,
        room: &Arc<RoomAuthorization>,
    ) {
        let original = OriginalKernelOwners {
            wireguard: wireguard.original_kernel_transport_owners(),
            udp: Arc::downgrade(udp),
            relay: Arc::downgrade(relay),
            room: Arc::downgrade(room),
        };
        let bound = self.state.try_lock().is_ok_and(|mut state| {
            if state
                .original_room_owner
                .as_ref()
                .is_some_and(|owner| !owner.ptr_eq(&original.room))
            {
                return false;
            }
            if let Some(previous) = &state.current_owners {
                previous.same_owner(&original)
            } else {
                state.current_owners = Some(original);
                true
            }
        });
        if !bound {
            self.read_complete.store(false, Ordering::Release);
            self.inbound_complete.store(false, Ordering::Release);
            self.full_complete.store(false, Ordering::Release);
            self.gap();
        }
    }
}

#[cfg(all(unix, test))]
mod tests;
