//! Advisory short-request timing. This does not estimate the peer READY RTT:
//! queueing and peer installation must be measured by the HH protocol itself.
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControlTimingHint {
    pub(crate) rtt_ms: u64,
    pub(crate) uncertainty_ms: u64,
    pub(crate) age_ms: u64,
}

/// Immutable request owner. A response cannot publish across registration,
/// physical-network invalidation, or replacement of the HTTP connection pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ControlTimingIdentity {
    registration_seq: u64,
    network_epoch: u64,
    http_pool_id: u64,
}

#[derive(Debug)]
struct ShortRequestSample {
    identity: ControlTimingIdentity,
    rtt_ms: u64,
    uncertainty_ms: u64,
    observed_at: Instant,
}

#[derive(Debug, Default)]
struct TimingState {
    network_epoch: u64,
    http_pool_id: u64,
    sample: Option<ShortRequestSample>,
}

impl TimingState {
    fn invalidate(&mut self, discard_pool: bool) {
        self.sample = None;
        // Saturation fails closed instead of reusing an earlier identity.
        self.network_epoch = self.network_epoch.checked_add(1).unwrap_or(u64::MAX);
        if discard_pool || self.network_epoch == u64::MAX {
            self.http_pool_id = 0;
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct ServerClockEstimate {
    offset_ms: AtomicI64,
    observed_at_local_ms: AtomicU64,
    timing: Mutex<TimingState>,
}

impl ServerClockEstimate {
    pub(super) const MAX_AGE_MS: u64 = 30_000;
    const MAX_RTT_MS: u64 = 2_000;

    // Legacy hh1 deadline translation is deliberately unchanged.
    pub(super) fn observe(&self, server_time_ms: u64, local_time_ms: u64) {
        let offset = i128::from(server_time_ms) - i128::from(local_time_ms);
        let Ok(offset) = i64::try_from(offset) else {
            return;
        };
        self.offset_ms.store(offset, Ordering::Relaxed);
        self.observed_at_local_ms
            .store(local_time_ms, Ordering::Release);
    }

    pub(super) fn server_deadline_for_local(&self, deadline: u64, now: u64) -> Option<u64> {
        let observed = self.observed_at_local_ms.load(Ordering::Acquire);
        if observed == 0 || now.abs_diff(observed) > Self::MAX_AGE_MS {
            return None;
        }
        u64::try_from(
            i128::from(deadline).checked_add(i128::from(self.offset_ms.load(Ordering::Relaxed)))?,
        )
        .ok()
    }

    pub(super) fn activate_http_pool(&self, pool_id: u64) {
        let Ok(mut state) = self.timing.lock() else {
            return;
        };
        if state.http_pool_id != pool_id {
            state.invalidate(false);
            if state.network_epoch != u64::MAX {
                state.http_pool_id = pool_id;
            }
        }
    }

    pub(super) fn invalidate_network(&self) {
        if let Ok(mut state) = self.timing.lock() {
            state.invalidate(true);
        }
    }

    pub(super) fn invalidate_registration(&self) {
        if let Ok(mut state) = self.timing.lock() {
            state.invalidate(false);
        }
    }

    pub(super) fn request_identity(
        &self,
        registration_seq: Option<u64>,
        pool_id: u64,
    ) -> Option<ControlTimingIdentity> {
        let registration_seq = registration_seq.filter(|seq| *seq > 0)?;
        let state = self.timing.lock().ok()?;
        if pool_id == 0 || pool_id != state.http_pool_id || state.network_epoch == u64::MAX {
            return None;
        }
        Some(ControlTimingIdentity {
            registration_seq,
            network_epoch: state.network_epoch,
            http_pool_id: pool_id,
        })
    }

    pub(super) fn observe_short_request(
        &self,
        identity: ControlTimingIdentity,
        server_time_ms: u64,
        sent_wall_ms: u64,
        received_wall_ms: u64,
        elapsed: Duration,
        received_at: Instant,
    ) {
        let Ok(mut state) = self.timing.lock() else {
            return;
        };
        if state.network_epoch != identity.network_epoch
            || state.http_pool_id != identity.http_pool_id
        {
            return;
        }
        let Ok(rtt_ms) = u64::try_from(elapsed.as_millis()) else {
            state.sample = None;
            return;
        };
        let Some(wall_elapsed) = received_wall_ms.checked_sub(sent_wall_ms) else {
            state.sample = None;
            return;
        };
        if rtt_ms > Self::MAX_RTT_MS || wall_elapsed.abs_diff(rtt_ms) > 25 || server_time_ms == 0 {
            state.sample = None;
            return;
        }
        let jitter_ms = state
            .sample
            .as_ref()
            .filter(|previous| {
                previous.identity == identity
                    && received_at
                        .saturating_duration_since(previous.observed_at)
                        .as_millis()
                        <= u128::from(Self::MAX_AGE_MS)
            })
            .map_or(0, |previous| previous.rtt_ms.abs_diff(rtt_ms));
        state.sample = Some(ShortRequestSample {
            identity,
            rtt_ms,
            // A conservative scheduling heuristic for this short RPC only;
            // never a proof of peer one-way delay or clock synchronization.
            uncertainty_ms: rtt_ms
                .div_ceil(2)
                .saturating_add(jitter_ms)
                .saturating_add(1),
            observed_at: received_at,
        });
    }

    pub(super) fn timing_hint(
        &self,
        now: Instant,
        registration_seq: u64,
    ) -> Option<ControlTimingHint> {
        let state = self.timing.lock().ok()?;
        let sample = state.sample.as_ref()?;
        if sample.identity.registration_seq != registration_seq
            || sample.identity.network_epoch != state.network_epoch
            || sample.identity.http_pool_id != state.http_pool_id
        {
            return None;
        }
        let age_ms =
            u64::try_from(now.checked_duration_since(sample.observed_at)?.as_millis()).ok()?;
        if age_ms > Self::MAX_AGE_MS {
            return None;
        }
        Some(ControlTimingHint {
            rtt_ms: sample.rtt_ms,
            uncertainty_ms: sample.uncertainty_ms,
            age_ms,
        })
    }

    pub(super) fn clear_timing(&self) {
        if let Ok(mut state) = self.timing.lock() {
            state.sample = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        clock: &ServerClockEstimate,
        identity: ControlTimingIdentity,
        now: Instant,
        rtt: u64,
    ) {
        clock.observe_short_request(
            identity,
            20_000 + rtt,
            10_000,
            10_000 + rtt,
            Duration::from_millis(rtt),
            now,
        );
    }

    #[test]
    fn long_poll_observations_do_not_create_or_extend_short_request_timing() {
        let clock = ServerClockEstimate::default();
        let now = Instant::now();
        clock.observe(20_000, 10_000);
        assert!(clock.timing_hint(now, 1).is_none());
        assert_eq!(
            clock.server_deadline_for_local(13_500, 10_000),
            Some(23_500)
        );
        clock.activate_http_pool(7);
        sample(
            &clock,
            clock.request_identity(Some(1), 7).unwrap(),
            now,
            200,
        );
        clock.observe(80_000, 70_000);
        assert!(clock
            .timing_hint(now + Duration::from_millis(30_001), 1)
            .is_none());
    }

    #[test]
    fn network_pool_and_registration_edges_reject_inflight_samples() {
        let clock = ServerClockEstimate::default();
        let now = Instant::now();
        clock.activate_http_pool(7);
        let old = clock.request_identity(Some(1), 7).unwrap();
        sample(&clock, old, now, 100);
        assert!(clock.timing_hint(now, 1).is_some());
        assert!(clock.timing_hint(now, 2).is_none());
        clock.invalidate_network();
        sample(&clock, old, now, 100);
        assert!(clock.timing_hint(now, 1).is_none());
        assert!(clock.request_identity(Some(1), 7).is_none());
        clock.activate_http_pool(8);
        sample(&clock, old, now, 100);
        assert!(clock.timing_hint(now, 1).is_none());
        let current = clock.request_identity(Some(2), 8).unwrap();
        sample(&clock, current, now, 100);
        assert!(clock.timing_hint(now, 2).is_some());
        clock.invalidate_registration();
        sample(&clock, current, now, 100);
        assert!(clock.timing_hint(now, 2).is_none());
    }

    #[test]
    fn short_request_tracks_jitter_and_rejects_stalls_and_wall_clock_jumps() {
        let clock = ServerClockEstimate::default();
        clock.activate_http_pool(7);
        let id = clock.request_identity(Some(1), 7).unwrap();
        let now = Instant::now();
        sample(&clock, id, now, 200);
        assert_eq!(clock.timing_hint(now, 1).unwrap().uncertainty_ms, 101);
        sample(&clock, id, now + Duration::from_secs(1), 300);
        assert_eq!(
            clock
                .timing_hint(now + Duration::from_secs(1), 1)
                .unwrap()
                .uncertainty_ms,
            251
        );
        for (received, elapsed) in [(13_000, 3_000), (10_500, 200), (9_999, 200)] {
            sample(&clock, id, now, 100);
            clock.observe_short_request(
                id,
                20_200,
                10_000,
                received,
                Duration::from_millis(elapsed),
                now,
            );
            assert!(clock.timing_hint(now, 1).is_none());
        }
    }
}
