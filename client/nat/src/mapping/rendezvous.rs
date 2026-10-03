//! Bounded prediction and ordering for a scheduled first peer-directed send.
//!
//! Model age and forecast horizon are different quantities: a current sample
//! may predict a bounded future rendezvous, but an already stale sample cannot.

use super::{
    model_is_fresh, predict_ports_with_learning, ModelRejection, PortModel, PortModelKind,
    PredictionCandidate, PredictionReason, MAX_PREDICTED_PORTS,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

const PRESERVED_PREDICTION_PREFIX: usize = 8;

/// Bounded guesses for a shared allocator, not evidence of its scope or an
/// anchor. A short regular tail does not prove that competing clients will
/// stop allocating while signaling completes. Keep a dense successor window
/// instead of replacing its far half with guesses across all 65,535 ports.
/// The caller must validate the tail's identity, ledger and freshness first.
/// No port-domain wrap is inferred from these hypotheses.
pub fn contention_candidate_window(model: &PortModel, cap: usize) -> Vec<u16> {
    if !matches!(
        model.kind,
        PortModelKind::FixedStep { .. }
            | PortModelKind::Linear { .. }
            | PortModelKind::NoisyLinear { .. }
            | PortModelKind::MonotonicWindow { .. }
    ) || model.sequence.len() < 3
        || model.sequence.contains(&0)
    {
        return Vec::new();
    }
    let deltas = model
        .sequence
        .windows(2)
        .map(|pair| i32::from(pair[1]) - i32::from(pair[0]))
        .collect::<Vec<_>>();
    let direction = deltas[0].signum();
    if direction == 0 || deltas.iter().any(|d| d.signum() != direction) {
        return Vec::new();
    }
    let stride = deltas.iter().fold(0, |mut a, delta| {
        let mut b = delta.abs();
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    });
    if stride > 2048 || deltas.iter().any(|d| d.abs() > stride * 8) {
        return Vec::new();
    }
    let last = i32::from(*model.sequence.last().unwrap_or(&0));
    (1..=cap.min(96))
        .map_while(|distance| {
            let port = last + direction * stride * distance as i32;
            (1..=65535).contains(&port).then_some(port as u16)
        })
        .collect()
}

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
    let mut candidates = predict_ports_with_learning(
        model,
        last,
        timing.measurement_span_ms,
        gap_ms,
        step_estimate,
        reverse_window,
    );
    // A short, perfectly regular STUN batch is evidence of stride, not of
    // zero competing allocations throughout the future rendezvous wait.
    // Spend the existing bounded successor budget for scheduled fixed-step
    // rendezvous, retaining every original ranked hypothesis. This also gives
    // the reciprocal role schedule room for modest first-send drift. It is
    // deterministic coverage, not a reduced model confidence or a promise of
    // predicting arbitrary shared-NAT activity.
    if timing.send_delay_ms > 0 && !candidates.is_empty() {
        if let PortModelKind::FixedStep { step } = model.kind {
            let mut seen = candidates
                .iter()
                .map(|candidate| candidate.port)
                .collect::<HashSet<_>>();
            for distance in 1..=MAX_PREDICTED_PORTS {
                if candidates.len() >= MAX_PREDICTED_PORTS {
                    break;
                }
                let port = super::modular_add_wide(last, i64::from(step) * distance as i64);
                if port != 0 && seen.insert(port) {
                    candidates.push(PredictionCandidate {
                        port,
                        rank: candidates.len() as u8,
                        reason: PredictionReason::SuccessorWindow {
                            distance: (distance - 1) as u8,
                        },
                    });
                }
            }
        }
    }
    if step_estimate.is_none() {
        add_contention_hypothesis_prefix(model, last, &mut candidates);
    }
    Ok(candidates)
}

/// A non-fixed median is not proof that every mapping consumes that stride.
/// For observed +1,+2, retain +2 first but insert +1 before +4,+6,..., inside
/// the same candidate count. With a clean subsequent +1 allocator, the first
/// two pairs cross-match; with +2, rank zero still matches. The signed gcd is
/// only another hypothesis, and neither the model nor its confidence changes.
///
/// More generally, for median s=m*g, the first m offsets are s,s-g,...,g.
/// When both windows have the same m, actual strides g (with each endpoint's
/// own magnitude/sign) have reciprocal indices i+j=m-1; actual strides s
/// retain the first pair. One legacy endpoint also works: its first target s
/// meets the updated endpoint's (m-1)-th target g. This covers these clean
/// hypotheses only, not unequal ratios, arbitrary drift or interleaving.
///
/// Preserve two original median successors after this prefix: differences
/// -g,(2*m-1)*g,m*g are distinct for m>1, so even the circular rank validator
/// rejects this mixed shape and leaves its proven prefix order unchanged.
fn add_contention_hypothesis_prefix(
    model: &PortModel,
    last: u16,
    candidates: &mut Vec<PredictionCandidate>,
) {
    let PortModelKind::Linear { step } = model.kind else {
        return;
    };
    let step = i32::from(step);
    if step == 0 || model.sequence.len() < 3 || model.sequence.last() != Some(&last) {
        return;
    }
    // Do not infer a port ring from legacy modular deltas, or reinterpret a
    // learned/sparse/wrapped window. HH2 applies its own evidenced-domain path
    // to fixed models; this helper only handles ordinary signed arithmetic.
    let deltas = model
        .sequence
        .windows(2)
        .map(|pair| i32::from(pair[1]) - i32::from(pair[0]))
        .collect::<Vec<_>>();
    if model.sequence.contains(&0)
        || deltas.len() != model.deltas.len()
        || deltas
            .iter()
            .zip(&model.deltas)
            .any(|(raw, modeled)| *raw != i32::from(*modeled) || raw.signum() != step.signum())
        || candidates.iter().enumerate().any(|(index, candidate)| {
            i32::from(candidate.port) != i32::from(last) + step * (index as i32 + 1)
        })
    {
        return;
    }
    let gcd = deltas.iter().fold(0, |mut a, delta| {
        let mut b = delta.abs();
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    });
    if gcd == 0 || step.checked_rem(gcd) != Some(0) {
        return;
    }
    let prefix_len = (step.abs() / gcd) as usize;
    let budget = candidates.len();
    if !(2..=PRESERVED_PREDICTION_PREFIX).contains(&prefix_len)
        || prefix_len.saturating_add(2) > budget
    {
        return;
    }
    let hypothesis_step = gcd * step.signum();
    let mut result = Vec::with_capacity(budget);
    result.push(candidates[0]);
    for distance in (1..prefix_len).rev() {
        // These offsets lie strictly between last and the already validated
        // first candidate, so they cannot wrap, become zero or overflow u16.
        result.push(PredictionCandidate {
            port: (i32::from(last) + hypothesis_step * distance as i32) as u16,
            rank: result.len() as u8,
            reason: PredictionReason::ContentionHypothesis {
                step: hypothesis_step as i16,
                distance: distance as u8,
            },
        });
    }
    for candidate in candidates.iter().skip(1).take(budget - prefix_len) {
        result.push(PredictionCandidate {
            rank: result.len() as u8,
            ..*candidate
        });
    }
    *candidates = result;
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
    let prefix = PRESERVED_PREDICTION_PREFIX
        .min(cap.saturating_sub(1))
        .max(1)
        .min(cap);
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
/// both participating prefixes are complete, equal-width fixed-step sequences
/// before use. Wider advertised windows may retain their unmodified suffix.
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
/// No wire candidate is invented or removed. When complete windows have
/// different widths, only their common prefix participates in the proof above;
/// the responder retains the rest of its remote targets in their original order.
/// Old initiators already scan their received window in order, including that
/// common prefix, so this requires no change to the negotiated transcript.
/// Sparse, mixed-IP, duplicate, or ambiguous half-ring windows retain the
/// caller's old order, even when their common prefixes alone look regular.
/// A wrapped window may use the predictor's observed port domain instead of
/// the legacy 65536 ring. The check below proves only consecutive candidate
/// ranks in the advertised list; it never creates port-domain/NAT evidence.
/// A list sparse under linear arithmetic may be complete under a circular
/// domain. Accepting that shape does not establish that the NAT uses it;
/// allocation evidence and freshness remain the caller's responsibility.
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
        let deltas = endpoints
            .windows(2)
            .map(|pair| i32::from(pair[1].port()) - i32::from(pair[0].port()))
            .collect::<Vec<_>>();
        let Some(&min_delta) = deltas.iter().min() else {
            return false;
        };
        let Some(&max_delta) = deltas.iter().max() else {
            return false;
        };
        if min_delta == max_delta {
            return min_delta != 0;
        }
        // A constant circular step has exactly two raw deltas, separated by
        // its modulus W. Both have the same residue modulo W. Requiring the
        // whole port span to fit inside W prevents a sparse multi-range list
        // from masquerading as a cycle; no absolute pool boundary is inferred.
        let width = max_delta - min_delta;
        let (min_port, max_port) = endpoints
            .iter()
            .fold((first.port(), first.port()), |(min, max), endpoint| {
                (min.min(endpoint.port()), max.max(endpoint.port()))
            });
        min_delta < 0
            && max_delta > 0
            && min_delta != -max_delta
            && width <= 65_536
            && i32::from(max_port) - i32::from(min_port) < width
            && deltas
                .iter()
                .all(|delta| *delta == min_delta || *delta == max_delta)
    }
    if !(3..=96).contains(&local.len())
        || !(3..=96).contains(&remote.len())
        || !complete_window(local)
        || !complete_window(remote)
    {
        return None;
    }
    let common_width = local.len().min(remote.len());
    Some(
        fixed_step_rendezvous_order(common_width, responder, alternate_phase)
            .into_iter()
            .chain(common_width..remote.len())
            .map(|rank| remote[rank])
            .collect(),
    )
}
