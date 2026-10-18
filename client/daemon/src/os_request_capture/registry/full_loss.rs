//! First loss site only. This metadata cannot authorize a read, Full or owner.
use super::CaptureFailure;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(unix, derive(serde::Serialize))]
#[cfg_attr(unix, serde(rename_all = "snake_case"))]
#[repr(u8)]
pub(crate) enum FullRetentionLossReason {
    ObservationDropped = 1,
    EncryptionCaptureFailed,
    PublicationClockUnavailable,
    PublicationClockAlreadyRecorded,
    PublicationMissing,
    PublicationIdentityMismatch,
    PublicationObservationMissing,
    RetentionClockUnavailable,
    // Deferred completion uses the Unix descriptor actor. Other platforms
    // have no such lock failure; keep subsequent diagnostic byte codes fixed.
    #[cfg(unix)]
    HistoryContended,
    HistoryCapacity = 10,
    HistoryInvalid,
    InputScopeUnavailable,
    InputScopeNotLive,
    InputReadObservationIncomplete,
    InputDeviceRetired,
    InputClockBeforeRead,
    InputRegistryContended,
    InputRegistryPoisoned,
    InputFlowInvalid,
    InputRouteMismatch,
    InputPeerMismatch,
    InputPeerOwnerUnavailable,
    PeerEncryptionMismatch,
    ResponseEncryptionMismatch,
    RoomPermitMismatch,
    CipherOwnerMismatch,
    EncryptionCopyFailed,
    InputBindingNotRouted,
    InputOwnerMismatch,
    InputReadPeerRejected,
    InputPacketLengthMismatch,
    InputPacketDigestMismatch,
    InputFrameBindingsInvalid,
    RoutedPeerMismatch,
    RoutedDestinationMismatch,
    RoutedRoomPermitRejected,
}

impl FullRetentionLossReason {
    pub(super) fn history(error: CaptureFailure) -> Self {
        match error {
            CaptureFailure::Capacity => Self::HistoryCapacity,
            _ => Self::HistoryInvalid,
        }
    }
}

pub(super) struct FullRetentionLoss(AtomicU8);

impl FullRetentionLoss {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    // One fixed byte, no allocation, lock, wait, retry or later replacement.
    pub(super) fn record(&self, reason: FullRetentionLossReason) {
        let _ = self
            .0
            .compare_exchange(0, reason as u8, Ordering::Release, Ordering::Relaxed);
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> Option<FullRetentionLossReason> {
        use FullRetentionLossReason::*;
        match self.0.load(Ordering::Acquire) {
            1 => Some(ObservationDropped),
            2 => Some(EncryptionCaptureFailed),
            3 => Some(PublicationClockUnavailable),
            4 => Some(PublicationClockAlreadyRecorded),
            5 => Some(PublicationMissing),
            6 => Some(PublicationIdentityMismatch),
            7 => Some(PublicationObservationMissing),
            8 => Some(RetentionClockUnavailable),
            9 => Some(HistoryContended),
            10 => Some(HistoryCapacity),
            11 => Some(HistoryInvalid),
            12 => Some(InputScopeUnavailable),
            13 => Some(InputScopeNotLive),
            14 => Some(InputReadObservationIncomplete),
            15 => Some(InputDeviceRetired),
            16 => Some(InputClockBeforeRead),
            17 => Some(InputRegistryContended),
            18 => Some(InputRegistryPoisoned),
            19 => Some(InputFlowInvalid),
            20 => Some(InputRouteMismatch),
            21 => Some(InputPeerMismatch),
            22 => Some(InputPeerOwnerUnavailable),
            23 => Some(PeerEncryptionMismatch),
            24 => Some(ResponseEncryptionMismatch),
            25 => Some(RoomPermitMismatch),
            26 => Some(CipherOwnerMismatch),
            27 => Some(EncryptionCopyFailed),
            28 => Some(InputBindingNotRouted),
            29 => Some(InputOwnerMismatch),
            30 => Some(InputReadPeerRejected),
            31 => Some(InputPacketLengthMismatch),
            32 => Some(InputPacketDigestMismatch),
            33 => Some(InputFrameBindingsInvalid),
            34 => Some(RoutedPeerMismatch),
            35 => Some(RoutedDestinationMismatch),
            36 => Some(RoutedRoomPermitRejected),
            _ => None,
        }
    }
}
