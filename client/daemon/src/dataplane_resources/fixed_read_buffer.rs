//! Fixed initialized read storage, including the time an idle reader is parked.
//! Slice-only access keeps the observed Vec length/capacity stable. These sizes
//! describe storage, not the valid bytes of the last packet or allocator RSS.
use super::{ResidencyLease, ResidencyStage, ResourceCapture, VecOperation, VecSite};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

pub(crate) struct FixedReadBuffer {
    // Rust drops fields in declaration order: free storage before releasing
    // its logical owner observation. No lease can outlive its owning wrapper.
    bytes: Vec<u8>,
    _lease: Option<ResidencyLease>,
}

impl FixedReadBuffer {
    pub(crate) fn udp(capture: Option<&Arc<ResourceCapture>>) -> Self {
        Self::new(capture, ResidencyStage::UdpReaderStorage)
    }

    pub(crate) fn tun(capture: Option<&Arc<ResourceCapture>>) -> Self {
        Self::new(capture, ResidencyStage::TunReaderStorage)
    }

    fn new(capture: Option<&Arc<ResourceCapture>>, stage: ResidencyStage) -> Self {
        let bytes = vec![0; 65_535];
        let lease = capture.and_then(|capture| {
            if stage == ResidencyStage::UdpReaderStorage {
                capture.observe_vec(
                    VecSite::UdpReaderBuffer,
                    VecOperation::FixedReadBuffer,
                    None,
                    &bytes,
                );
            }
            ResidencyLease::observe(capture, stage, &bytes)
        });
        Self {
            bytes,
            _lease: lease,
        }
    }
}

impl Deref for FixedReadBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for FixedReadBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

#[cfg(test)]
#[path = "fixed_read_buffer_tests.rs"]
mod tests;
