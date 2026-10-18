//! First loss site only. This metadata cannot authorize a read, Full or owner.
use super::CaptureFailure;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(unix, derive(serde::Serialize))]
#[cfg_attr(unix, serde(rename_all = "snake_case"))]
#[repr(u8)]
pub(super) enum FullRetentionLossReason {
    ObservationDropped = 1,
    EncryptionCaptureFailed,
    PublicationClockUnavailable,
    PublicationClockAlreadyRecorded,
    PublicationMissing,
    PublicationIdentityMismatch,
    PublicationObservationMissing,
    RetentionClockUnavailable,
    HistoryContended,
    HistoryCapacity,
    HistoryInvalid,
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
            _ => None,
        }
    }
}
