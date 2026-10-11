//! Original successful-encryption identity, without network or send authority.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Instant;

use tokio::sync::Mutex;

use super::super::{PeerTransportSessions, TransportSessionSlot};
use crate::dataplane::OutboundPacket;
use crate::error::DaemonError;
use crate::peer::PeerSessionGeneration;
use crate::transport::{
    EncryptedPeerPacket, SessionBoundEncryption, SessionUnavailableReason, WireGuardTransport,
};

/// Identifies the actual slot that encrypted this ciphertext. No raw key bytes,
/// network generation, current-owner qualification or physical-send success.
pub(crate) struct OriginalEncryptionSource {
    owner: Weak<Mutex<HashMap<String, PeerTransportSessions>>>,
    peer_id: String,
    session_instance: u64,
    authorized_peer_lifecycle: Option<PeerSessionGeneration>,
    encrypted_at: Instant,
}

impl OriginalEncryptionSource {
    // Only the encryption parent may capture after encrypt_to_bytes Ok, while
    // the same original sessions guard still owns this actual active slot.
    pub(super) fn capture_successful_slot(
        transport: &WireGuardTransport,
        peer_id: &str,
        slot: &TransportSessionSlot,
        encrypted_at: Instant,
    ) -> Self {
        Self {
            owner: Arc::downgrade(&transport.sessions),
            peer_id: peer_id.to_string(),
            session_instance: slot.session_instance,
            authorized_peer_lifecycle: slot.authorized_peer_lifecycle,
            encrypted_at,
        }
    }
}

// Metadata consumers are the next stage; keep the allowance on these immutable
// accessors only, not on the module or crypto implementation.
#[allow(dead_code)]
impl OriginalEncryptionSource {
    pub(crate) fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub(crate) fn session_instance(&self) -> u64 {
        self.session_instance
    }

    pub(crate) fn authorized_peer_lifecycle(&self) -> Option<PeerSessionGeneration> {
        self.authorized_peer_lifecycle
    }

    pub(crate) fn encrypted_at(&self) -> Instant {
        self.encrypted_at
    }

    pub(crate) fn belongs_to(&self, transport: &WireGuardTransport) -> bool {
        Weak::ptr_eq(&self.owner, &Arc::downgrade(&transport.sessions))
    }
}

/// Public ciphertext remains unchanged. Only actual crypto can construct this
/// private success carrier. Compatibility entry points select capture=false:
/// they carry None and never create an original source just to discard it.
pub(crate) struct EncryptedOutboundWithSource {
    packet: EncryptedPeerPacket,
    source: Option<OriginalEncryptionSource>,
}

impl EncryptedOutboundWithSource {
    pub(super) fn new(
        packet: EncryptedPeerPacket,
        source: Option<OriginalEncryptionSource>,
    ) -> Self {
        Self { packet, source }
    }

    pub(crate) fn into_packet(self) -> EncryptedPeerPacket {
        self.packet
    }

    #[allow(dead_code)]
    pub(crate) fn packet(&self) -> &EncryptedPeerPacket {
        &self.packet
    }

    #[allow(dead_code)]
    pub(crate) fn source(&self) -> Option<&OriginalEncryptionSource> {
        self.source.as_ref()
    }

    #[allow(dead_code)]
    pub(crate) fn into_parts(self) -> (EncryptedPeerPacket, Option<OriginalEncryptionSource>) {
        (self.packet, self.source)
    }
}

pub(crate) enum SessionBoundEncryptionWithSource {
    Encrypted {
        packet: EncryptedOutboundWithSource,
        plaintext: OutboundPacket,
        session_lock_wait_us: u64,
        crypto_us: u64,
    },
    Contended(OutboundPacket),
    Unavailable {
        packet: OutboundPacket,
        reason: SessionUnavailableReason,
    },
    Failed {
        packet: OutboundPacket,
        error: DaemonError,
    },
}

impl SessionBoundEncryptionWithSource {
    pub(super) fn into_legacy(self) -> SessionBoundEncryption {
        match self {
            Self::Encrypted {
                packet,
                plaintext,
                session_lock_wait_us,
                crypto_us,
            } => SessionBoundEncryption::Encrypted {
                packet: packet.into_packet(),
                plaintext,
                session_lock_wait_us,
                crypto_us,
            },
            Self::Contended(packet) => SessionBoundEncryption::Contended(packet),
            Self::Unavailable { packet, reason } => {
                SessionBoundEncryption::Unavailable { packet, reason }
            }
            Self::Failed { packet, error } => SessionBoundEncryption::Failed { packet, error },
        }
    }
}
