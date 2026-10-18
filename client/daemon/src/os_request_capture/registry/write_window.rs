//! Original controller observations, bounded by this process's actual clock.
//! This metadata cannot construct a KernelRead, OS-write fact, Full, or owner.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::os_request_capture) struct WireWriteWindow {
    producer_scope: String,
    sequence: u32,
    request_nonce: String,
    boot_id: String,
    original_started_ns: u64,
    original_sent_ns: u64,
    original_deadline_ns: u64,
    complete_returned_ns: u64,
    frame_bytes: usize,
    frame_sha256: String,
}

#[derive(Clone, Serialize)]
pub(super) struct WriteWindow {
    scope: &'static str,
    request_nonce: String,
    original_started_ns: u64,
    original_sent_ns: u64,
    original_deadline_ns: u64,
    complete_returned_ns: u64,
    received_monotonic_ns: u64,
    frame_bytes: usize,
    frame_sha256: String,
    native_os_write_verified: bool,
    canonical_current_owner_verified: bool,
}

impl WriteWindow {
    pub(super) fn contains(&self, now: u64) -> bool {
        self.original_sent_ns <= now && now < self.original_deadline_ns
    }
}

impl WireWriteWindow {
    /// Both daemon endpoints receive the initiator's original REQUEST write
    /// window. Match its exact tool bytes, including the full run/round/nonce
    /// and TCP length prefix; the target's registered RESPONSE kind is not the
    /// initiator's write. This remains a metadata constraint, never OS proof.
    fn matches_registered_request_frame(&self, plan: &RegisteredFlowPlan) -> bool {
        let Some(key) = plan.requests.get(self.sequence as usize) else {
            return false;
        };
        if plan.payload_bytes != 128 {
            return false;
        }
        let mut supplied = [0; 32];
        if hex::decode_to_slice(&self.frame_sha256, &mut supplied).is_err() {
            return false;
        }
        let mut expected = Sha256::new();
        if plan.protocol == Protocol::Tcp {
            expected.update(191_u32.to_be_bytes());
        }
        expected.update(match plan.protocol {
            Protocol::Udp => b"P2WUDE1\0",
            Protocol::Tcp => b"P2WTCE1\0",
        });
        expected.update([0]); // The original initiator's REQUEST.
        expected.update(key.run);
        expected.update(key.round);
        expected.update(key.sequence.to_be_bytes());
        expected.update(key.request_nonce);
        expected.update(plan.payload_bytes.to_be_bytes());
        expected.update([0xa5; 128]);
        supplied == <[u8; 32]>::from(expected.finalize())
    }

    fn validate(
        &self,
        now: u64,
        expected_frame_bytes: usize,
        expected_nonce: &[u8; 16],
    ) -> Result<[u8; 16], CaptureFailure> {
        let producer = super::super::plan::nonce(&self.producer_scope)?;
        if super::super::plan::nonce(&self.request_nonce)? != *expected_nonce {
            return Err(CaptureFailure::InvalidPlan);
        }
        let end = self.original_started_ns.checked_add(10_000_000_000);
        let first = self
            .original_started_ns
            .checked_add(u64::from(self.sequence) * 100_000_000);
        let request_end = self.original_sent_ns.checked_add(1_000_000_000);
        if self.sequence >= 8
            || self.original_started_ns == 0
            || self.boot_id.len() != 36
            || end.is_none()
            || first.is_none()
            || request_end.is_none()
            || first.is_some_and(|first| self.original_sent_ns < first)
            || end.is_some_and(|end| self.original_sent_ns >= end)
            || self.original_deadline_ns != end.unwrap_or(0).min(request_end.unwrap_or(0))
            || self.complete_returned_ns < self.original_sent_ns
            || now < self.complete_returned_ns
            || now >= self.original_deadline_ns
            || self.frame_bytes != expected_frame_bytes
            || self.frame_sha256.len() != 64
            || !self
                .frame_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CaptureFailure::InvalidPlan);
        }
        Ok(producer)
    }
}

impl CaptureSession {
    /// Only an already-owned control channel can deliver this observation.
    /// Receipt before the existing deadline is mandatory; no fresh clock starts.
    pub(in crate::os_request_capture) fn observe_original_write_window(
        self: &Arc<Self>,
        wire: WireWriteWindow,
    ) -> Result<(), CaptureFailure> {
        let now = monotonic_ns().ok_or(CaptureFailure::InvalidPlan)?;
        if !self
            .clock_scope
            .as_ref()
            .is_some_and(|clock| clock.same_boot(&wire.boot_id))
            || !self.is_live(Instant::now())
        {
            return Err(CaptureFailure::InvalidPlan);
        }
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        let producer = super::super::plan::nonce(&wire.producer_scope)?;
        let mut flows = state
            .flows
            .iter_mut()
            .enumerate()
            .filter(|(_, f)| f.producer_scope == producer);
        let (flow_index, flow) = flows.next().ok_or(CaptureFailure::InvalidPlan)?;
        if flows.next().is_some() || flow.requests.len() != 8 || flow.plan.payload_bytes != 128 {
            return Err(CaptureFailure::InvalidPlan);
        }
        if flow.requests.iter().any(|request| {
            request
                .original_write_window
                .as_ref()
                .is_some_and(|old| old.original_started_ns != wire.original_started_ns)
        }) {
            return Err(CaptureFailure::FrameConflict);
        }
        let frame_bytes = 63 + 128 + usize::from(flow.plan.protocol == Protocol::Tcp) * 4;
        let expected_nonce = flow
            .plan
            .requests
            .get(wire.sequence as usize)
            .ok_or(CaptureFailure::InvalidPlan)?
            .request_nonce;
        wire.validate(now, frame_bytes, &expected_nonce)?;
        if !wire.matches_registered_request_frame(&flow.plan) {
            return Err(CaptureFailure::FrameConflict);
        }
        let request = flow
            .requests
            .get_mut(wire.sequence as usize)
            .ok_or(CaptureFailure::InvalidPlan)?;
        if request.original_write_window.is_some() {
            return Err(CaptureFailure::DuplicateWrite);
        }
        request.original_write_window = Some(WriteWindow {
            scope: "original_controller_write_window_only",
            request_nonce: wire.request_nonce,
            original_started_ns: wire.original_started_ns,
            original_sent_ns: wire.original_sent_ns,
            original_deadline_ns: wire.original_deadline_ns,
            complete_returned_ns: wire.complete_returned_ns,
            received_monotonic_ns: now,
            frame_bytes: wire.frame_bytes,
            frame_sha256: wire.frame_sha256,
            native_os_write_verified: false,
            canonical_current_owner_verified: false,
        });
        let slot = wire.sequence as usize;
        self.try_complete_original_frames(&mut state, flow_index, &[slot]);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
