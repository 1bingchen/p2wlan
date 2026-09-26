//! Bounded prediction and ordering for a scheduled first peer-directed send.
//!
//! Model age and forecast horizon are different quantities: a current sample
//! may predict a bounded future rendezvous, but an already stale sample cannot.

use super::{
    model_is_fresh, predict_ports_with_learning, ModelRejection, PortModel, PredictionCandidate,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct RendezvousPredictionTiming {
    pub measurement_span_ms: u64,
    pub last_measurement_send_at_ms: u64,
    pub now_ms: u64,
    pub send_delay_ms: u64,
    pub max_send_delay_ms: u64,
    pub max_model_age: Duration,
}

/// Forecast the allocation at the first peer send, including the remaining
/// signaling/rendezvous delay. All timestamps are in the same local monotonic
/// clock; a remote wall clock must be translated by the coordinator first.
pub fn predict_for_rendezvous(
    model: &PortModel,
    last: u16,
    timing: RendezvousPredictionTiming,
    step_estimate: Option<i16>,
    reverse_window: bool,
) -> Result<Vec<PredictionCandidate>, ModelRejection> {
    if !model_is_fresh(model, timing.max_model_age, timing.now_ms)
        || timing.last_measurement_send_at_ms > timing.now_ms
        || timing.send_delay_ms > timing.max_send_delay_ms
    {
        return Err(ModelRejection::BatchStale);
    }
    let gap_ms = timing
        .now_ms
        .saturating_sub(timing.last_measurement_send_at_ms)
        .saturating_add(timing.send_delay_ms);
    Ok(predict_ports_with_learning(
        model,
        last,
        timing.measurement_span_ms,
        gap_ms,
        step_estimate,
        reverse_window,
    ))
}

/// Keep the freshest eight ranked hypotheses, then cover the rest of the
/// generated window evenly (including its far edge), inside the existing cap.
/// This is deterministic coverage, not a calibrated probability distribution.
pub fn bounded_prediction_window(ports: &[u16], cap: usize) -> Vec<u16> {
    let mut seen = HashSet::new();
    let ports = ports
        .iter()
        .copied()
        .filter(|port| *port != 0 && seen.insert(*port))
        .collect::<Vec<_>>();
    if ports.len() <= cap {
        return ports;
    }
    if cap == 0 {
        return Vec::new();
    }
    let prefix = 8.min(cap.saturating_sub(1)).max(1).min(cap);
    let mut result = ports[..prefix].to_vec();
    let remaining = cap - prefix;
    for slot in 1..=remaining {
        let index = prefix - 1 + slot * (ports.len() - prefix) / remaining;
        result.push(ports[index]);
    }
    result
}

/// A toy-model ordering primitive. The protocol must keep the initiator's
/// received candidate order unchanged (as hh1 does), and callers must prove
/// both windows are complete, equal-width fixed-step sequences before use.
/// This changes only the responder's local schedule, never the wire window.
/// The initial clean successor stays first. Alternate phases belong to fresh
/// socket generations, never retransmissions of already allocated mappings.
///
/// For initiator rank i and responder rank l, reciprocity requires
/// i = d_b + l and order(l) = d_a + i. Reversing only the tail gives
/// 2*l = M - (d_a+d_b), with M=N or N-1. The two phases cover both parities
/// for 1 <= d_a+d_b <= N-3 while retaining the clean d_a=d_b=0 pair.
/// This proof assumes no intervening allocations, loss, or candidate gaps;
/// it is not a success guarantee for a real shared NAT.
pub fn fixed_step_rendezvous_order(
    count: usize,
    responder: bool,
    alternate_phase: bool,
) -> Vec<usize> {
    let mut order = (0..count).collect::<Vec<_>>();
    if responder && count >= 3 {
        let end = count - usize::from(alternate_phase);
        order[1..end].reverse();
    }
    order
}

/// Validate the exact advertised windows before applying the local schedule.
/// No wire candidate is invented or removed. Unequal, sparse, mixed-IP,
/// duplicate, or ambiguous half-ring windows retain the caller's old order.
pub fn fixed_step_rendezvous_targets(
    local: &[SocketAddr],
    remote: &[SocketAddr],
    responder: bool,
    alternate_phase: bool,
) -> Option<Vec<SocketAddr>> {
    fn complete_window(endpoints: &[SocketAddr]) -> bool {
        let Some(first) = endpoints.first() else {
            return false;
        };
        let mut seen = HashSet::new();
        if endpoints.iter().any(|endpoint| {
            endpoint.ip() != first.ip() || endpoint.port() == 0 || !seen.insert(endpoint.port())
        }) {
            return false;
        }
        let step = super::modular_difference(endpoints[0].port(), endpoints[1].port());
        step != 0
            && step != i16::MIN
            && endpoints
                .windows(2)
                .all(|pair| super::modular_difference(pair[0].port(), pair[1].port()) == step)
    }
    if local.len() != remote.len()
        || !(3..=32).contains(&local.len())
        || !complete_window(local)
        || !complete_window(remote)
    {
        return None;
    }
    Some(
        fixed_step_rendezvous_order(remote.len(), responder, alternate_phase)
            .into_iter()
            .map(|rank| remote[rank])
            .collect(),
    )
}
