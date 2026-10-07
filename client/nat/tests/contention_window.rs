use p2pnet_nat::build_model;
use p2pnet_nat::mapping::rendezvous::{contention_candidate_window, fixed_step_rendezvous_targets};
use std::net::SocketAddr;

#[test]
fn contention_window_covers_drift_beyond_a_short_prediction_without_wrapping() {
    for (samples, step) in [
        (vec![26024, 26027, 26030], 3),
        (vec![40006, 40002, 40000], -2),
    ] {
        let model = build_model(&samples, None, 100);
        let ports = contention_candidate_window(&model, 64);
        assert_eq!(ports.len(), 64);
        let last = i32::from(*samples.last().unwrap());
        for (rank, port) in ports.iter().enumerate() {
            assert_eq!(i32::from(*port), last + step * (rank as i32 + 1));
        }
        assert_eq!(contention_candidate_window(&model, 1024).len(), 96);
        assert!(contention_candidate_window(&model, 0).is_empty());
    }
    let model = build_model(&[65529, 65531, 65533], None, 100);
    assert_eq!(contention_candidate_window(&model, 64), vec![65535]);
    let model = build_model(&[7, 5, 3], None, 100);
    assert_eq!(contention_candidate_window(&model, 64), vec![1]);
    for sequence in [
        &[12, 16, 14][..],
        &[65531, 65533, 1],
        &[0, 2, 4],
        &[12, 12, 12],
    ] {
        assert!(contention_candidate_window(&build_model(sequence, None, 100), 64).is_empty());
    }
}

#[test]
fn wide_birthday_role_order_retains_every_advertised_candidate() {
    let window = |ip: &str, base: u16, step: u16| -> Vec<SocketAddr> {
        (1..=64)
            .map(|rank| SocketAddr::new(ip.parse().unwrap(), base + rank * step))
            .collect()
    };
    let a = window("192.0.2.1", 16300, 2);
    let b = window("198.51.100.1", 26030, 3);
    for phase in [false, true] {
        assert_eq!(
            fixed_step_rendezvous_targets(&a, &b, false, phase).unwrap(),
            b
        );
        let mut reordered = fixed_step_rendezvous_targets(&b, &a, true, phase).unwrap();
        assert_eq!(reordered[0], a[0]);
        reordered.sort_unstable();
        assert_eq!(reordered, a);
    }
    let mut sparse = b.clone();
    sparse[63].set_port(b[63].port() + 3);
    assert!(fixed_step_rendezvous_targets(&a, &sparse, true, false).is_none());
}
