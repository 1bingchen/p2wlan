use p2pnet_nat::mapping::allocation::validate_allocation_prediction_tail;
use p2pnet_nat::{
    infer_port_domain, infer_scoped_allocation, plan_fixed_anchor, validate_allocation_attempts,
    AllocationAttempt, AllocationAttemptOutcome, AllocationEvidenceRejection as Reject,
    AllocationIdentity, AllocationSample, AllocationScope, MappingObservation, PortDomainEvidence,
};
use std::net::SocketAddr;
use std::time::Duration;

fn identity() -> AllocationIdentity {
    AllocationIdentity {
        network_generation: 7,
        measurement_generation: 9,
        egress: "192.0.2.1:4000".parse().unwrap(),
    }
}

fn grid(ports: &[u16]) -> Vec<AllocationSample> {
    let pairs = [(0, 0), (1, 0), (1, 1), (0, 1), (0, 2), (0, 3)];
    ports
        .iter()
        .enumerate()
        .map(|(i, port)| {
            let (socket, destination) = pairs[i];
            AllocationSample {
                socket_id: socket,
                observation: MappingObservation {
                    sequence: i as u16,
                    observer: format!("203.0.113.{}:3478", destination + 1)
                        .parse()
                        .unwrap(),
                    observed: SocketAddr::new("198.51.100.1".parse().unwrap(), *port),
                    sent_at_ms: 100 + i as u64 * 10,
                    responded_at_ms: 101 + i as u64 * 10,
                    local_endpoint: format!("192.0.2.1:{}", 5000 + socket).parse().unwrap(),
                },
            }
        })
        .collect()
}

#[test]
fn port_range_requires_a_real_unique_boundary_in_either_direction() {
    let range = PortDomainEvidence::ObservedRange {
        first: 1024,
        last: 65535,
    };
    assert_eq!(
        infer_port_domain(&[65534, 65535, 1024, 1025]),
        Ok((1, range))
    );
    assert_eq!(
        infer_port_domain(&[1025, 1024, 65535, 65534]),
        Ok((-1, range))
    );
    assert_eq!(range.advance(1024, -1), Some(65535));
    assert_eq!(range.advance(65535, 1), Some(1024));
    assert_eq!(
        infer_port_domain(&[2003, 2002, 2001]),
        Ok((-1, PortDomainEvidence::Unobserved))
    );
    assert_eq!(PortDomainEvidence::Unobserved.advance(1, -1), None);
    assert_eq!(PortDomainEvidence::Unobserved.advance(65535, 1), None);
    // With stride four the same wrap is compatible with several boundaries.
    assert_eq!(
        infer_port_domain(&[65530, 65534, 1026, 1030]),
        Err(Reject::AmbiguousPortDomain)
    );
}

#[test]
fn a_controlled_grid_is_required_before_cross_socket_anchor_admission() {
    let samples = grid(&[40000, 40001, 40002, 40003, 40004, 40005]);
    let evidence =
        infer_scoped_allocation(&samples, identity(), 160, Duration::from_secs(1)).unwrap();
    assert_eq!(evidence.scope, AllocationScope::ObservedSharedSequence);
    let mut same_socket = samples.clone();
    for (i, sample) in same_socket.iter_mut().enumerate() {
        sample.socket_id = 0;
        sample.observation.local_endpoint = "192.0.2.1:5000".parse().unwrap();
        sample.observation.observer = format!("203.0.113.{}:3478", i + 1).parse().unwrap();
    }
    let evidence =
        infer_scoped_allocation(&same_socket, identity(), 160, Duration::from_secs(1)).unwrap();
    assert_eq!(
        evidence.scope,
        AllocationScope::SameSocketMultipleDestinations
    );
    assert_eq!(
        plan_fixed_anchor(&evidence, identity(), 160, Duration::from_secs(1), 4, 3),
        Err(Reject::ScopeUnproven)
    );
    let mut same_ip = samples;
    for sample in &mut same_ip {
        let port = 3478
            + u16::from(match sample.observation.observer.ip() {
                std::net::IpAddr::V4(ip) => ip.octets()[3],
                _ => 0,
            });
        sample.observation.observer = SocketAddr::new("203.0.113.1".parse().unwrap(), port);
    }
    assert_eq!(
        infer_scoped_allocation(&same_ip, identity(), 160, Duration::from_secs(1)),
        Err(Reject::ScopeUnproven)
    );
}

#[test]
fn fixed_anchor_covers_bounded_prefix_drift_before_a_contiguous_socket_burst() {
    for step in [-4, -1, 1, 4] {
        let ports = (0..6)
            .map(|i| (40000 + i * step) as u16)
            .collect::<Vec<_>>();
        let evidence =
            infer_scoped_allocation(&grid(&ports), identity(), 160, Duration::from_secs(1))
                .unwrap();
        for sockets in [2, 4, 8] {
            let plan = plan_fixed_anchor(
                &evidence,
                identity(),
                160,
                Duration::from_secs(1),
                sockets,
                sockets - 1,
            )
            .unwrap();
            for drift in 0..sockets {
                let allocated = (1..=sockets)
                    .map(|i| {
                        evidence
                            .domain
                            .advance(evidence.last_port, i64::from(step) * (drift + i) as i64)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                assert!(
                    allocated.contains(&plan.local_anchor.port()),
                    "sockets={sockets} drift={drift} step={step}"
                );
            }
            assert_eq!(
                plan_fixed_anchor(
                    &evidence,
                    identity(),
                    160,
                    Duration::from_secs(1),
                    sockets,
                    sockets
                ),
                Err(Reject::DriftExceedsCoverage)
            );
        }
    }
}

#[test]
fn one_interleaved_allocation_can_consume_the_anchor_inside_the_prefix_bound() {
    let evidence = infer_scoped_allocation(
        &grid(&[9995, 9996, 9997, 9998, 9999, 10000]),
        identity(),
        160,
        Duration::from_secs(1),
    )
    .unwrap();
    let plan = plan_fixed_anchor(&evidence, identity(), 160, Duration::from_secs(1), 4, 3).unwrap();
    assert_eq!(plan.local_anchor.port(), 10004);
    // A,B,C allocate first; a foreign flow consumes 10004; D then gets 10005.
    // One external allocation <=3 is NOT the same as one prefix allocation.
    let local_allocations = [10001, 10002, 10003, 10005];
    assert!(!local_allocations.contains(&plan.local_anchor.port()));
}

#[test]
fn a_timed_out_last_send_cannot_disappear_from_a_complete_observed_prefix() {
    let samples = grid(&[40000, 40001, 40002, 40003, 40004, 40005]);
    let mut attempts = samples
        .iter()
        .map(|sample| AllocationAttempt {
            sequence: sample.observation.sequence,
            local_endpoint: sample.observation.local_endpoint,
            destination: sample.observation.observer,
            sent_at_ms: sample.observation.sent_at_ms,
            datagram_bytes: 40,
            outcome: AllocationAttemptOutcome::Observed,
        })
        .collect::<Vec<_>>();
    assert_eq!(validate_allocation_attempts(&samples, &attempts), Ok(()));
    attempts[5].outcome = AllocationAttemptOutcome::SentUnobserved;
    assert_eq!(
        validate_allocation_attempts(&samples[..5], &attempts),
        Err(Reject::UnobservedAllocation)
    );
    // A kernel send failure is retained too, without claiming it allocated.
    attempts[5].outcome = AllocationAttemptOutcome::SendFailed;
    assert_eq!(
        validate_allocation_attempts(&samples[..5], &attempts),
        Err(Reject::UnobservedAllocation)
    );
    // If the final request was never attempted, the five observed sends are
    // a valid ledger; their last mapping, not the six-request plan, is base.
    attempts.pop();
    assert_eq!(
        validate_allocation_attempts(&samples[..5], &attempts),
        Ok(())
    );
}

fn attempted(samples: &[AllocationSample]) -> Vec<AllocationAttempt> {
    samples
        .iter()
        .map(|sample| AllocationAttempt {
            sequence: sample.observation.sequence,
            local_endpoint: sample.observation.local_endpoint,
            destination: sample.observation.observer,
            sent_at_ms: sample.observation.sent_at_ms,
            datagram_bytes: 40,
            outcome: AllocationAttemptOutcome::Observed,
        })
        .collect()
}

#[test]
fn an_early_unknown_allocation_can_rebase_only_a_complete_final_primary_tail() {
    for outcome in [
        AllocationAttemptOutcome::SentUnobserved,
        AllocationAttemptOutcome::SendFailed,
    ] {
        let mut samples = grid(&[40000, 40001, 40002, 40003, 40004, 40005]);
        let mut attempts = attempted(&samples);
        attempts[1].outcome = outcome;
        samples.remove(1);
        let endpoint = samples[0].observation.local_endpoint;
        let tail = validate_allocation_prediction_tail(&samples, &attempts, 0, endpoint).unwrap();
        assert_eq!(
            tail.iter()
                .map(|sample| sample.observation.sequence)
                .collect::<Vec<_>>(),
            [3, 4, 5]
        );
        assert_eq!(tail.last().unwrap().observation.observed.port(), 40005);
        // A valid local suffix never upgrades the incomplete shared grid.
        assert_eq!(
            validate_allocation_attempts(&samples, &attempts),
            Err(Reject::UnobservedAllocation)
        );
        assert!(
            infer_scoped_allocation(&samples, identity(), 160, Duration::from_secs(1)).is_err()
        );
    }
}

#[test]
fn prediction_tail_rejects_unknown_final_sends_and_too_short_rebases() {
    for missing in [3, 4, 5] {
        let mut samples = grid(&[40000, 40001, 40002, 40003, 40004, 40005]);
        let mut attempts = attempted(&samples);
        attempts[missing].outcome = AllocationAttemptOutcome::SentUnobserved;
        samples.remove(missing);
        let result = validate_allocation_prediction_tail(
            &samples,
            &attempts,
            0,
            samples[0].observation.local_endpoint,
        );
        assert_eq!(
            result,
            Err(if missing == 5 {
                Reject::UnobservedAllocation
            } else {
                Reject::SampleCount
            })
        );
    }
}

#[test]
fn prediction_rebase_still_reconciles_every_pair_identity_time_and_observation() {
    let mut samples = grid(&[40000, 40001, 40002, 40003, 40004, 40005]);
    let mut attempts = attempted(&samples);
    attempts[1].outcome = AllocationAttemptOutcome::SentUnobserved;
    samples.remove(1);
    let endpoint = samples[0].observation.local_endpoint;
    // An unknown request must not secretly carry a sample anyway.
    let mut extra = samples.clone();
    extra.insert(1, grid(&[40000, 40001])[1].clone());
    assert_eq!(
        validate_allocation_prediction_tail(&extra, &attempts, 0, endpoint),
        Err(Reject::InconsistentOrder)
    );
    let mut mismatched = samples.clone();
    mismatched[3].observation.sent_at_ms += 1;
    assert_eq!(
        validate_allocation_prediction_tail(&mismatched, &attempts, 0, endpoint),
        Err(Reject::InconsistentOrder)
    );
    let mut mismatched = samples.clone();
    mismatched[3].socket_id = 9;
    assert!(validate_allocation_prediction_tail(&mismatched, &attempts, 0, endpoint).is_err());
    let mut late = samples.clone();
    late[1].observation.responded_at_ms = attempts[3].sent_at_ms + 1;
    assert_eq!(
        validate_allocation_prediction_tail(&late, &attempts, 0, endpoint),
        Err(Reject::InconsistentOrder)
    );
    let mut changed_ip = samples.clone();
    changed_ip[4]
        .observation
        .observed
        .set_ip("198.51.100.2".parse().unwrap());
    assert_eq!(
        validate_allocation_prediction_tail(&changed_ip, &attempts, 0, endpoint),
        Err(Reject::PublicIpChanged)
    );
    // Reusing an earlier timed-out primary destination does not allocate a
    // defensible new sample, even when three replies later look consecutive.
    attempts[0].outcome = AllocationAttemptOutcome::SentUnobserved;
    samples.remove(0);
    attempts[0].destination = attempts[3].destination;
    assert_eq!(
        validate_allocation_prediction_tail(&samples, &attempts, 0, endpoint),
        Err(Reject::ReusedMappingPair)
    );
}

#[test]
fn gaps_reused_pairs_and_stale_identity_cannot_produce_anchor_evidence() {
    let samples = grid(&[40000, 40001, 40002, 40003, 40004, 40005]);
    let mut missing = samples.clone();
    missing.remove(2);
    assert_eq!(
        infer_scoped_allocation(&missing, identity(), 160, Duration::from_secs(1)),
        Err(Reject::InconsistentOrder)
    );
    let mut reused = samples.clone();
    reused[5].observation.observer = reused[4].observation.observer;
    assert_eq!(
        infer_scoped_allocation(&reused, identity(), 160, Duration::from_secs(1)),
        Err(Reject::ReusedMappingPair)
    );
    let evidence =
        infer_scoped_allocation(&samples, identity(), 160, Duration::from_secs(1)).unwrap();
    let mut next = identity();
    next.network_generation += 1;
    assert_eq!(
        plan_fixed_anchor(&evidence, next, 160, Duration::from_secs(1), 4, 3),
        Err(Reject::IdentityChanged)
    );
    assert_eq!(
        plan_fixed_anchor(&evidence, identity(), 1200, Duration::from_secs(1), 4, 3),
        Err(Reject::Stale)
    );
}
#[test]
fn publication_age_does_not_confuse_future_forecast_with_sample_freshness() {
    use p2pnet_nat::mapping::allocation::validate_allocation_publication_timing;
    use p2pnet_nat::AllocationEvidenceRejection as Reject;
    use std::time::Duration;
    let sample_age = Duration::from_millis(2_500);
    let horizon = Duration::from_millis(3_500);
    // The sample is currently fresh. T is 3.5s after it, which is explicitly
    // forecasted and need not fit within the 2.5s publication-age limit.
    assert_eq!(
        validate_allocation_publication_timing(1_000, 2_000, 4_500, sample_age, horizon),
        Ok(())
    );
    assert_eq!(
        validate_allocation_publication_timing(1_000, 3_500, 4_500, sample_age, horizon),
        Ok(())
    );
    assert_eq!(
        validate_allocation_publication_timing(1_000, 3_501, 4_500, sample_age, horizon),
        Err(Reject::Stale)
    );
    assert_eq!(
        validate_allocation_publication_timing(1_000, 999, 4_500, sample_age, horizon),
        Err(Reject::Stale)
    );
    assert_eq!(
        validate_allocation_publication_timing(1_000, 2_000, 2_000, sample_age, horizon),
        Err(Reject::ForecastExpired)
    );
    assert_eq!(
        validate_allocation_publication_timing(1_000, 2_000, 4_501, sample_age, horizon),
        Err(Reject::ForecastHorizonExceeded)
    );
    // Revalidation later cannot legitimize extending T by measuring its
    // horizon from the new current time instead of the original sample.
    assert_eq!(
        validate_allocation_publication_timing(1_000, 3_000, 5_000, sample_age, horizon),
        Err(Reject::ForecastHorizonExceeded)
    );
}
