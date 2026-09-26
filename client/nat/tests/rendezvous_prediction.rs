use p2pnet_nat::mapping::rendezvous::{
    bounded_prediction_window, fixed_step_rendezvous_order, fixed_step_rendezvous_targets,
    predict_for_rendezvous, RendezvousPredictionTiming,
};
use p2pnet_nat::mapping::{build_model, predict_ports, ModelRejection};
use std::net::SocketAddr;
use std::time::Duration;

fn timing(delay_ms: u64) -> RendezvousPredictionTiming {
    RendezvousPredictionTiming {
        measurement_span_ms: 100,
        last_measurement_send_at_ms: 200,
        now_ms: 210,
        send_delay_ms: delay_ms,
        max_send_delay_ms: 3_500,
        max_model_age: Duration::from_millis(2_500),
    }
}

#[test]
fn scheduled_gap_covers_busy_allocator_drift_without_changing_top_one() {
    let model = build_model(&[1000, 1001, 1002, 1006], None, 100);
    let immediate = predict_for_rendezvous(&model, 1006, timing(0), None, false).unwrap();
    let scheduled = predict_for_rendezvous(&model, 1006, timing(600), None, false).unwrap();
    assert_eq!(scheduled[0], immediate[0]);
    assert_eq!(scheduled.len(), 24);
    assert!(scheduled.len() > immediate.len());
    assert!(scheduled.iter().any(|candidate| candidate.port == 1030));
    assert!(!immediate.iter().any(|candidate| candidate.port == 1030));
}

#[test]
fn forecast_horizon_and_current_sample_freshness_are_separate() {
    let model = build_model(&[1000, 1001, 1002], None, 100);
    assert!(predict_for_rendezvous(&model, 1002, timing(3_500), None, false).is_ok());
    assert_eq!(
        predict_for_rendezvous(&model, 1002, timing(3_501), None, false),
        Err(ModelRejection::BatchStale)
    );
    let mut stale = timing(0);
    stale.now_ms = 2_601;
    assert_eq!(
        predict_for_rendezvous(&model, 1002, stale, None, false),
        Err(ModelRejection::BatchStale)
    );
    let mut invalid_clock = timing(0);
    invalid_clock.last_measurement_send_at_ms = invalid_clock.now_ms + 1;
    assert_eq!(
        predict_for_rendezvous(&model, 1002, invalid_clock, None, false),
        Err(ModelRejection::BatchStale)
    );
}

#[test]
fn immediate_clean_forecast_keeps_exact_existing_ranked_window() {
    for sequence in [[1000, 1001, 1002], [6000, 5998, 5996], [65530, 65533, 0]] {
        let model = build_model(&sequence, None, 100);
        assert_eq!(
            predict_for_rendezvous(&model, sequence[2], timing(0), None, false).unwrap(),
            predict_ports(&model, sequence[2])
        );
    }
}

#[test]
fn scheduled_clean_batch_keeps_ranked_prefix_and_covers_unobserved_drift() {
    for sequence in [
        [1000, 1001, 1002],
        [6000, 5998, 5996],
        [65525, 65528, 65531],
    ] {
        let model = build_model(&sequence, None, 100);
        let immediate = predict_ports(&model, sequence[2]);
        let scheduled =
            predict_for_rendezvous(&model, sequence[2], timing(3_500), None, false).unwrap();
        assert_eq!(&scheduled[..immediate.len()], immediate.as_slice());
        assert_eq!(scheduled.len(), p2pnet_nat::mapping::MAX_PREDICTED_PORTS);
        assert!(scheduled.iter().all(|candidate| candidate.port != 0));
        let unique = scheduled
            .iter()
            .map(|candidate| candidate.port)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), scheduled.len());
    }
    let model = build_model(&[1000, 1001, 1002], None, 100);
    let count = predict_for_rendezvous(&model, 1002, timing(3_500), None, false)
        .unwrap()
        .len();
    let a = fixed_step_rendezvous_order(count, false, false);
    let b = fixed_step_rendezvous_order(count, true, true);
    assert!(reciprocal_pair(&a, &b, 2, 3));
    assert!(!reciprocal_pair(
        &a[..6],
        &fixed_step_rendezvous_order(6, true, true),
        2,
        3
    ));
}

#[test]
fn scheduled_expansion_does_not_override_confidence_or_wrap_safety() {
    let mut model = build_model(&[1000, 1001, 1002], None, 100);
    model.confidence = 59;
    assert!(
        predict_for_rendezvous(&model, 1002, timing(3_500), None, false)
            .unwrap()
            .is_empty()
    );
    let model = build_model(&[65531, 65532, 65533], None, 100);
    let scheduled = predict_for_rendezvous(&model, 65533, timing(3_500), None, false).unwrap();
    assert!(scheduled.len() <= p2pnet_nat::mapping::MAX_PREDICTED_PORTS);
    assert_eq!(scheduled[0].port, 65534);
    assert!(scheduled.iter().all(|candidate| candidate.port != 0));
    let unique = scheduled
        .iter()
        .map(|candidate| candidate.port)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), scheduled.len());
}

#[test]
fn bounded_window_preserves_prefix_and_reaches_far_drift_inside_same_cap() {
    let ports = (10_001..=10_096).collect::<Vec<_>>();
    let window = bounded_prediction_window(&ports, 32);
    assert_eq!(window.len(), 32);
    assert_eq!(&window[..8], &ports[..8]);
    assert_eq!(window.last(), ports.last());
    assert!(window.contains(&10_096));
    assert!(!ports[..32].contains(&10_096));
    assert!(window.windows(2).all(|pair| pair[1] > pair[0]));
    for cap in 0..=96 {
        let window = bounded_prediction_window(&ports, cap);
        assert!(window.len() <= cap);
        assert!(window.iter().all(|port| ports.contains(port)));
        if cap > 0 {
            assert_eq!(window[0], ports[0]);
        }
    }
    assert_eq!(
        bounded_prediction_window(&[0, 1000, 1000, 1001], 32),
        vec![1000, 1001]
    );
}

// Strict APDM/APDF toy model: contacting the i-th distinct destination
// allocates source rank d+i; the mapping only admits that exact destination.
fn reciprocal_pair(a: &[usize], b: &[usize], drift_a: usize, drift_b: usize) -> bool {
    a.iter().enumerate().any(|(i, target_b)| {
        b.iter()
            .enumerate()
            .any(|(l, target_a)| *target_b == drift_b + l && *target_a == drift_a + i)
    })
}

#[test]
fn two_fresh_generation_phases_cover_bounded_positive_drift_in_strict_toy_model() {
    for count in 3..=32 {
        let initiator = fixed_step_rendezvous_order(count, false, false);
        let phase_a = fixed_step_rendezvous_order(count, true, false);
        let phase_b = fixed_step_rendezvous_order(count, true, true);
        assert_eq!(phase_a[0], 0);
        assert_eq!(phase_b[0], 0);
        assert!(reciprocal_pair(&initiator, &phase_a, 0, 0));
        assert!(reciprocal_pair(&initiator, &phase_b, 0, 0));
        for drift_a in 0..count {
            for drift_b in 0..count {
                let sum = drift_a + drift_b;
                if (1..=count - 3).contains(&sum) {
                    assert!(!reciprocal_pair(&initiator, &initiator, drift_a, drift_b));
                    assert!(
                        reciprocal_pair(&initiator, &phase_a, drift_a, drift_b)
                            || reciprocal_pair(&initiator, &phase_b, drift_a, drift_b),
                        "count={count} drift_a={drift_a} drift_b={drift_b}"
                    );
                }
            }
        }
    }
}

fn endpoints(ip: &str, ports: &[u16]) -> Vec<SocketAddr> {
    ports
        .iter()
        .map(|port| format!("{ip}:{port}").parse().unwrap())
        .collect()
}

#[test]
fn role_order_requires_complete_equal_fixed_step_windows() {
    let local = endpoints("192.0.2.1", &[65532, 65534, 0, 2]);
    let remote = endpoints("198.51.100.2", &[4004, 4003, 4002, 4001]);
    assert!(fixed_step_rendezvous_targets(&local, &remote, true, false).is_none());
    let local = endpoints("192.0.2.1", &[65533, 65535, 1, 3]);
    let reordered = fixed_step_rendezvous_targets(&local, &remote, true, false).unwrap();
    assert_eq!(reordered, vec![remote[0], remote[3], remote[2], remote[1]]);
    assert!(fixed_step_rendezvous_targets(&local[..3], &remote, true, false).is_none());
    let sparse = endpoints("198.51.100.2", &[4004, 4003, 4001, 4000]);
    assert!(fixed_step_rendezvous_targets(&local, &sparse, true, false).is_none());
    let mut mixed_ip = remote.clone();
    mixed_ip[1] = "198.51.100.3:4003".parse().unwrap();
    assert!(fixed_step_rendezvous_targets(&local, &mixed_ip, true, false).is_none());
    let duplicate = endpoints("198.51.100.2", &[4004, 4003, 4003, 4002]);
    assert!(fixed_step_rendezvous_targets(&local, &duplicate, true, false).is_none());
}

#[test]
fn filtering_evidence_requires_an_uncontacted_source_ip() {
    use p2pnet_nat::ice::classify_filtering_probe_response;
    use p2pnet_nat::FilteringBehavior;
    let server = "192.0.2.1:3478".parse().unwrap();
    let alternate = "192.0.2.2:3479".parse().unwrap();
    assert_eq!(
        classify_filtering_probe_response(server, alternate, &[server]),
        Some(FilteringBehavior::EndpointIndependent)
    );
    assert_eq!(
        classify_filtering_probe_response(server, alternate, &[server, alternate]),
        None
    );
    assert_eq!(
        classify_filtering_probe_response(server, "192.0.2.1:3479".parse().unwrap(), &[server]),
        None
    );
}

#[test]
fn concurrent_discovery_is_a_low_confidence_hint_until_fresh_measurement() {
    use p2pnet_nat::{
        candidate_report_from_observations, candidate_report_from_unordered_observations,
        FilteringBehavior, NatCapabilities, StunObservation,
    };
    let observations = (0..4)
        .map(|index| StunObservation {
            server: format!("192.0.2.{}:3478", index + 1),
            mapped_address: Some(format!("198.51.100.1:{}", 4000 + index)),
            rtt_ms: Some(5),
            error: None,
        })
        .collect::<Vec<_>>();
    let local = "0.0.0.0:40000".parse().unwrap();
    let ordered = candidate_report_from_observations(local, false, observations.clone());
    let unordered = candidate_report_from_unordered_observations(local, false, observations);
    assert_eq!(ordered.nat_profile.confidence, 90);
    assert_eq!(unordered.nat_profile.confidence, 60);
    assert_eq!(
        unordered.nat_profile.filtering_behavior,
        FilteringBehavior::Unknown
    );
    assert!(NatCapabilities::from_profile(&unordered.nat_profile).hard_allocation_is_predictable());
    // Admission remains possible; neither the profile score nor candidate
    // list substitutes for the dedicated socket's ordered allocation model.
    let endpoints = |report: &p2pnet_nat::CandidateGatherReport| {
        report
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.endpoint.to_string(),
                    candidate.source,
                    candidate.priority,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(endpoints(&unordered), endpoints(&ordered));
}
