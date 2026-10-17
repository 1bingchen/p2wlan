/// Endpoint-free cost and timing facts for one local Hard↔Hard STUN
/// measurement.  Durations use the transport's process-local monotonic clock;
/// callers translate them onto the daemon timeline only after the measurement
/// future completes.  This structure is observation-only and is never read by
/// candidate generation or send admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HardHardMeasurementStats {
    /// Successful UDP sends to STUN observers, including samples that timed
    /// out or returned an unusable response.
    pub(crate) stun_datagrams_sent: u32,
    pub(crate) stun_bytes_sent: u64,
    /// STUN UDP sends rejected by the kernel.
    pub(crate) stun_send_errors: u32,
    pub(crate) stun_send_error_bytes: u64,
    /// Usable STUN binding responses retained by the model input.
    pub(crate) stun_responses: u32,
    /// Transport-local monotonic milestones. They are translated onto the
    /// daemon timeline as one group and are never exposed directly.
    pub(crate) measurement_started_at_ms: Option<u64>,
    pub(crate) last_measurement_send_at_ms: Option<u64>,
    pub(crate) measurement_completed_at_ms: Option<u64>,
}

impl HardHardMeasurementStats {
    pub(super) fn accumulate(&mut self, other: Self) {
        self.stun_datagrams_sent = self
            .stun_datagrams_sent
            .saturating_add(other.stun_datagrams_sent);
        self.stun_bytes_sent = self.stun_bytes_sent.saturating_add(other.stun_bytes_sent);
        self.stun_send_errors = self.stun_send_errors.saturating_add(other.stun_send_errors);
        self.stun_send_error_bytes = self
            .stun_send_error_bytes
            .saturating_add(other.stun_send_error_bytes);
        self.stun_responses = self.stun_responses.saturating_add(other.stun_responses);
        self.measurement_started_at_ms = match (
            self.measurement_started_at_ms,
            other.measurement_started_at_ms,
        ) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (None, value) | (value, None) => value,
        };
        self.last_measurement_send_at_ms = match (
            self.last_measurement_send_at_ms,
            other.last_measurement_send_at_ms,
        ) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) | (value, None) => value,
        };
        self.measurement_completed_at_ms = match (
            self.measurement_completed_at_ms,
            other.measurement_completed_at_ms,
        ) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) | (value, None) => value,
        };
    }
}
