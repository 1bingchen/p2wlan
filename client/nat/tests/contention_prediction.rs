use p2pnet_nat::mapping::rendezvous::{
    bounded_prediction_window, fixed_step_rendezvous_targets, predict_for_rendezvous,
    RendezvousPredictionTiming,
};
use p2pnet_nat::mapping::{
    build_model, predict_ports_with_learning, PortModel, PortModelKind, PredictionReason,
};
use std::net::SocketAddr;
use std::time::Duration;

fn timing(delay_ms: u64) -> RendezvousPredictionTiming {
    RendezvousPredictionTiming {
        measurement_span_ms: 100,
        last_measurement_send_at_ms: 200,
        now_ms: 200,
        send_delay_ms: delay_ms,
        max_send_delay_ms: 3_500,
        max_model_age: Duration::from_millis(2_500),
    }
}

fn advertised(model: &PortModel, last: u16, updated: bool, ip: &str) -> Vec<SocketAddr> {
    let predictions = if updated {
        predict_for_rendezvous(model, last, timing(3_000), None, false).unwrap()
    } else {
        predict_ports_with_learning(model, last, 100, 3_000, None, false)
    };
    // The actual HH2 publication keeps this capped window, then prefixes it
    // to the birthday guesses. Predictable sends only this advertised prefix.
    bounded_prediction_window(
        &predictions
            .iter()
            .map(|candidate| candidate.port)
            .collect::<Vec<_>>(),
        32,
    )
    .into_iter()
    .map(|port| SocketAddr::new(ip.parse().unwrap(), port))
    .collect()
}

// Strict APDM/APDF after measurement, without subsequent competing traffic:
// first physical sends create one mapping each; retransmitting the same
// (socket, target) pair preserves that mapping. Count actual send indices,
// not advertised ranks. This mirrors the HH2 initiator's unchanged order and
// the responder's real shape-validated reorder/fallback.
fn reciprocal_after_sweep_order(
    a: &[SocketAddr],
    b: &[SocketAddr],
    last_a: u16,
    last_b: u16,
    actual_step_a: i32,
    actual_step_b: i32,
    phase: bool,
) -> bool {
    let responder = fixed_step_rendezvous_targets(b, a, true, phase).unwrap_or_else(|| a.to_vec());
    b.iter().enumerate().any(|(i, target_b)| {
        responder.iter().enumerate().any(|(j, target_a)| {
            i32::from(target_b.port()) == i32::from(last_b) + actual_step_b * (j as i32 + 1)
                && i32::from(target_a.port()) == i32::from(last_a) + actual_step_a * (i as i32 + 1)
        })
    })
}

#[test]
fn median_only_competing_allocation_case_misses_both_existing_phases() {
    let a = build_model(&[40003, 40004, 40006], None, 100);
    let b = build_model(&[50003, 50004, 50006], None, 100);
    assert_eq!(a.kind, PortModelKind::Linear { step: 2 });
    assert_eq!(a.confidence, 86);
    let old_a = advertised(&a, 40006, false, "192.0.2.1");
    let old_b = advertised(&b, 50006, false, "198.51.100.1");
    assert_eq!(old_a.len(), 12);
    for phase in [false, true] {
        // j=2*i+1 and i=2*q(j)+1 reduce to 5*i=23 or 21;
        // neither phase has an integer pair, including its retained endpoints.
        assert!(!reciprocal_after_sweep_order(
            &old_a, &old_b, 40006, 50006, 1, 1, phase,
        ));
    }
}

#[test]
fn bounded_hypothesis_prefix_preserves_median_and_recovers_clean_smaller_stride() {
    for direction in [-2, -1, 1, 2] {
        for multiplier in 2..=8 {
            let sequence = |last: i32| -> [u16; 3] {
                if direction > 0 {
                    [
                        last - direction * (2 * multiplier - 1),
                        last - direction * multiplier,
                        last,
                    ]
                    .map(|p| p as u16)
                } else {
                    [
                        last - direction * (2 * multiplier + 1),
                        last - direction * (multiplier + 1),
                        last,
                    ]
                    .map(|p| p as u16)
                }
            };
            let a = build_model(&sequence(40000), None, 100);
            let b = build_model(&sequence(50000), None, 100);
            assert_eq!(
                a.kind,
                PortModelKind::Linear {
                    step: (direction * multiplier) as i16
                }
            );
            let old_a = advertised(&a, 40000, false, "192.0.2.1");
            let new_a = advertised(&a, 40000, true, "192.0.2.1");
            assert_eq!(new_a.len(), old_a.len(), "candidate budget must not grow");
            assert_eq!(new_a[0], old_a[0], "retain the original median hypothesis");
            assert_eq!(
                new_a
                    .iter()
                    .take(multiplier as usize)
                    .map(|p| p.port())
                    .collect::<Vec<_>>(),
                (1..=multiplier)
                    .rev()
                    .map(|offset| (40000 + direction * offset) as u16)
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                new_a.iter().collect::<std::collections::HashSet<_>>().len(),
                new_a.len()
            );
            for (updated_a, updated_b) in [(true, true), (true, false), (false, true)] {
                let published_a = advertised(&a, 40000, updated_a, "192.0.2.1");
                let published_b = advertised(&b, 50000, updated_b, "198.51.100.1");
                for phase in [false, true] {
                    assert!(
                        fixed_step_rendezvous_targets(&published_b, &published_a, true, phase,)
                            .is_none(),
                        "the mixed hypothesis must not become a circular fixed window"
                    );
                    for actual_step in [direction, direction * multiplier] {
                        assert!(reciprocal_after_sweep_order(
                            &published_a, &published_b, 40000, 50000, actual_step, actual_step, phase,
                        ), "direction={direction} multiplier={multiplier} updated=({updated_a},{updated_b}) phase={phase} actual_step={actual_step}");
                    }
                }
            }
        }
    }
}

#[test]
fn common_hypothesis_ratio_handles_opposite_directions_and_unequal_window_lengths() {
    let a = build_model(&[40003, 40004, 40006], None, 100);
    let b = build_model(&[50010, 50006, 50000], None, 100);
    for (updated_a, updated_b) in [(true, true), (true, false), (false, true)] {
        let a = advertised(&a, 40006, updated_a, "192.0.2.1");
        let b = advertised(&b, 50000, updated_b, "198.51.100.1");
        assert_eq!(a.len(), 12);
        assert_eq!(b.len(), 24);
        for phase in [false, true] {
            assert!(fixed_step_rendezvous_targets(&b, &a, true, phase).is_none());
            for (step_a, step_b) in [(1, -2), (2, -4)] {
                assert!(reciprocal_after_sweep_order(
                    &a, &b, 40006, 50000, step_a, step_b, phase,
                ));
            }
        }
    }
}

#[test]
fn hypothesis_does_not_change_other_models_learning_or_unproven_wraps() {
    for sequence in [
        vec![1000, 1002, 1004],
        vec![1000, 1001, 1002, 1006],
        vec![1000, 1000, 1000],
        vec![1000, 1003, 1010],
        vec![1000, 1001, 1008, 1009, 1016, 1017],
        vec![1000, 1005, 1001, 1009, 1002],
        vec![1000, 1008, 1017], // gcd multiplier 9 exceeds the preserved prefix.
        vec![1003, 1002, 1000], // The median already equals the signed gcd.
        vec![65534, 65535, 1],  // The samples crossed an unproven boundary.
        vec![3, 1, 65534],
        vec![65530, 65531, 65533], // The proposed median window would wrap.
    ] {
        let last = *sequence.last().unwrap();
        let model = build_model(&sequence, None, 100);
        assert_eq!(
            predict_for_rendezvous(&model, last, timing(0), None, false).unwrap(),
            predict_ports_with_learning(&model, last, 100, 0, None, false),
            "sequence={sequence:?}",
        );
    }
    let model = build_model(&[1000, 1001, 1003], None, 100);
    let updated = predict_for_rendezvous(&model, 1003, timing(0), None, false).unwrap();
    assert!(matches!(
        updated[1].reason,
        PredictionReason::ContentionHypothesis {
            step: 1,
            distance: 1
        }
    ));
    for learned in [Some(1), Some(2), Some(-1)] {
        assert_eq!(
            predict_for_rendezvous(&model, 1003, timing(0), learned, false).unwrap(),
            predict_ports_with_learning(&model, 1003, 100, 0, learned, false),
        );
    }
    // A manually supplied confidence tier may leave too few original slots
    // to keep the complete prefix plus two shape-disambiguating successors.
    let mut narrow = build_model(&[1000, 1004, 1009], None, 100);
    narrow.confidence = 95;
    assert_eq!(
        predict_for_rendezvous(&narrow, 1009, timing(0), None, false).unwrap(),
        predict_ports_with_learning(&narrow, 1009, 100, 0, None, false),
    );
}
