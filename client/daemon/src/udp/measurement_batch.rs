use super::*;

pub(in crate::udp) fn last_mapping_send_is_unobserved(
    attempts: &[p2pnet_nat::AllocationAttempt],
) -> bool {
    attempts
        .iter()
        .rev()
        .find(|attempt| attempt.outcome != p2pnet_nat::AllocationAttemptOutcome::SendFailed)
        .is_some_and(|attempt| {
            attempt.outcome == p2pnet_nat::AllocationAttemptOutcome::SentUnobserved
        })
}

pub(super) fn primary_mapping_tail_after_gap(
    attempts: &[p2pnet_nat::AllocationAttempt],
    primary: SocketAddr,
    observers: &[SocketAddr],
    request_limit: usize,
) -> Option<Vec<SocketAddr>> {
    if attempts.last()?.outcome == p2pnet_nat::AllocationAttemptOutcome::Observed {
        return None;
    }
    // A timed-out or failed pair is never retried as a fresh allocation. The
    // successful suffix must use three still-uncontacted primary destinations.
    let mut used = attempts
        .iter()
        .filter(|attempt| attempt.local_endpoint == primary)
        .map(|attempt| attempt.destination)
        .collect::<HashSet<_>>();
    let tail = observers
        .iter()
        .copied()
        .filter(|observer| used.insert(*observer))
        .take(3)
        .collect::<Vec<_>>();
    (tail.len() == 3 && attempts.len().saturating_add(tail.len()) <= request_limit).then_some(tail)
}

pub(super) fn ordered_mapping_request_timeout(
    per_sample_cap: Duration,
    started_ms: u64,
    now_ms: u64,
    remaining_requests: usize,
) -> Option<Duration> {
    let remaining_ms = FRESH_MAPPING_MEASURE_BUDGET
        .as_millis()
        .saturating_sub(u128::from(now_ms.saturating_sub(started_ms)));
    let timeout = per_sample_cap.min(Duration::from_millis(
        remaining_ms
            .checked_div(remaining_requests as u128)?
            .min(u128::from(u64::MAX)) as u64,
    ));
    (!timeout.is_zero()).then_some(timeout)
}

pub(super) fn trace_mapping_observations(
    peer_id: &str,
    network_generation: u64,
    punch_generation: u64,
    batch: &MappingBatch,
) {
    for observation in &batch.observations {
        debug!(
                target: super::MAPPING_OBSERVATION_TARGET,
            event = "fresh_mapping_observer",
            peer_id = %peer_id,
            network_generation = network_generation,
            punch_generation = punch_generation,
            socket_local = %observation.local_endpoint,
            sequence = observation.sequence,
            observer = %observation.observer,
            srflx = %observation.observed,
            rtt_ms = observation.rtt_ms().unwrap_or(0),
            "fresh_mapping_observer peer_id={} punch_generation={} seq={} observer={} srflx={} rtt_ms={}",
            peer_id,
            punch_generation,
            observation.sequence,
            observation.observer,
            observation.observed,
            observation.rtt_ms().unwrap_or(0)
        );
    }
}
