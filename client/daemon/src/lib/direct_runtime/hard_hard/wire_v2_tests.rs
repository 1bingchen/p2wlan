#[cfg(test)]
mod hard_hard_wire_v2_tests {
    use super::*;
    use crate::peer::{
        HardHardAgreedPlan, HardHardCoordinatedPlan, HardHardOfferParameters, HardHardProbeStrategy,
    };
    use base64::Engine as _;

    fn parameters(anchor_port: u16, prediction_count: u8) -> HardHardOfferParameters {
        HardHardOfferParameters {
            socket_count: 4,
            prediction_count,
            anchor_port,
        }
    }

    fn endpoints(first_port: u16) -> Vec<SocketAddr> {
        (0..4)
            .map(|offset| SocketAddr::from(([203, 0, 113, 20], first_port + offset)))
            .collect()
    }

    fn envelope(stage: HardHardV2Stage) -> HardHardCoordination {
        let is_offer = stage == HardHardV2Stage::Offer;
        HardHardCoordination {
            v2: Some(HardHardV2Envelope {
                stage,
                local: parameters(40_001, 2),
                remote: if is_offer {
                    HardHardOfferParameters::default()
                } else {
                    parameters(50_001, 3)
                },
                phase: true,
                strategy_order: 0,
                agreement: (!is_offer).then_some(HardHardAgreedPlan {
                    strategy: HardHardProbeStrategy::FixedAnchor,
                    digest: [0xa5; 16],
                }),
                rtt_ms: 37,
                uncertainty_ms: 11,
            }),
            role: if matches!(
                stage,
                HardHardV2Stage::Answer | HardHardV2Stage::ReadyAck | HardHardV2Stage::SyncAck
            ) {
                HardHardRole::Responder
            } else {
                HardHardRole::Initiator
            },
            token: "00112233445566778899aabbccddeeff".to_string(),
            local_network_generation: 11,
            remote_candidate_epoch: 12,
            local_profile_generation: 13,
            remote_profile_generation: 14,
            local_prediction_confidence: 100,
            remote_prediction_confidence: 60,
            local_prediction_model: "fixed_step".to_string(),
            remote_prediction_model: "high_entropy".to_string(),
            remote_network_generation: 15,
        }
    }

    fn wire_bytes(value: &HardHardCoordination) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.encode().strip_prefix("hh2:").unwrap())
            .unwrap()
    }

    fn wire_from_bytes(bytes: &[u8]) -> String {
        format!(
            "hh2:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        )
    }

    #[test]
    fn all_six_stages_round_trip_with_maximum_integer_width() {
        for stage in [
            HardHardV2Stage::Offer,
            HardHardV2Stage::Answer,
            HardHardV2Stage::Ready,
            HardHardV2Stage::ReadyAck,
            HardHardV2Stage::Sync,
            HardHardV2Stage::SyncAck,
        ] {
            let mut value = envelope(stage);
            value.token = "ff".repeat(16);
            value.local_network_generation = u64::MAX;
            value.remote_candidate_epoch = u64::MAX;
            value.local_profile_generation = u64::MAX;
            value.remote_profile_generation = u64::MAX;
            value.remote_network_generation = u64::MAX;
            let meta = value.v2.as_mut().unwrap();
            meta.local = HardHardOfferParameters {
                socket_count: 8,
                prediction_count: 32,
                anchor_port: u16::MAX,
            };
            if stage != HardHardV2Stage::Offer {
                meta.remote = meta.local;
            }
            meta.rtt_ms = u16::MAX;
            meta.uncertainty_ms = u16::MAX;
            let encoded = value.encode();
            assert_eq!(encoded.len(), 124);
            assert!(encoded.len() <= 128, "{stage:?}");
            assert_eq!(HardHardCoordination::parse(&encoded), Some(value));
        }
    }

    #[test]
    fn malformed_lengths_versions_and_encoding_are_rejected() {
        let bytes = wire_bytes(&envelope(HardHardV2Stage::Offer));
        for len in [0, 1, 89, 91, 94] {
            let mut malformed = bytes.clone();
            malformed.resize(len, 0);
            assert!(HardHardCoordination::parse(&wire_from_bytes(&malformed)).is_none());
        }
        for malformed in ["hh2:", "hh2:***", "hh2:é", "hh3:ignored", "hh20:ignored"] {
            assert!(HardHardCoordination::parse(malformed).is_none());
        }
        assert!(HardHardCoordination::looks_like("hh3:ignored"));
        assert!(HardHardCoordination::looks_like("hh20:ignored"));
        let mut oversized = envelope(HardHardV2Stage::Offer).encode();
        oversized.push_str("AAAAA");
        assert!(oversized.len() > 128);
        assert!(HardHardCoordination::parse(&oversized).is_none());
    }

    #[test]
    fn unknown_flags_models_strategy_and_invalid_bounds_are_rejected() {
        let original = wire_bytes(&envelope(HardHardV2Stage::Answer));
        for (offset, replacement) in [
            (0, 0x85), // Reserved high bit; 0x45 is a valid SyncAck.
            (0, 0x42), // Unknown stage 6.
            (0, 0x47), // Unknown stage 7.
            (0, 0x35),
            (57, 101),
            (58, 101),
            (59, 10),
            (60, 255),
            (61, 0),
            (61, 3),
            (62, 33),
            (65, 0),
            (65, 16),
            (66, 33),
            (69, 0),
            (69, 4),
            (69, 255),
        ] {
            let mut bytes = original.clone();
            bytes[offset] = replacement;
            assert!(
                HardHardCoordination::parse(&wire_from_bytes(&bytes)).is_none(),
                "offset {offset}, value {replacement}"
            );
        }
        for stage in [
            HardHardV2Stage::Offer,
            HardHardV2Stage::Answer,
            HardHardV2Stage::Ready,
            HardHardV2Stage::ReadyAck,
            HardHardV2Stage::Sync,
            HardHardV2Stage::SyncAck,
        ] {
            let mut bytes = wire_bytes(&envelope(stage));
            bytes[0] ^= 4;
            assert!(
                HardHardCoordination::parse(&wire_from_bytes(&bytes)).is_none(),
                "{stage:?}"
            );
        }
    }

    #[test]
    fn sync_stages_use_the_known_extended_stage_bit() {
        for (stage, flags) in [
            (HardHardV2Stage::Sync, 0x40),
            (HardHardV2Stage::SyncAck, 0x45),
        ] {
            let mut value = envelope(stage);
            value.v2.as_mut().unwrap().phase = false;
            let bytes = wire_bytes(&value);
            assert_eq!(bytes[0], flags);
            assert_eq!(
                HardHardCoordination::parse(&wire_from_bytes(&bytes)),
                Some(value)
            );
        }
    }

    #[test]
    fn initial_offer_cannot_claim_a_remote_offer_or_agreement() {
        let original = wire_bytes(&envelope(HardHardV2Stage::Offer));
        for (offset, replacement) in [(65, 2), (66, 1), (68, 1), (69, 1), (70, 1)] {
            let mut bytes = original.clone();
            bytes[offset] = replacement;
            assert!(HardHardCoordination::parse(&wire_from_bytes(&bytes)).is_none());
        }
    }

    #[test]
    fn unsupported_models_and_malformed_tokens_cannot_be_encoded() {
        let mut value = envelope(HardHardV2Stage::Offer);
        for token in [
            "",
            "00",
            "gg112233445566778899aabbccddeeff",
            "00112233-45566778899aabbccddeeff",
        ] {
            value.token = token.to_string();
            assert!(value.encode_v2(value.v2.as_ref().unwrap()).is_none());
        }
        value = envelope(HardHardV2Stage::Offer);
        value.local_prediction_model = "future-model".to_string();
        assert!(value.encode_v2(value.v2.as_ref().unwrap()).is_none());
        value = envelope(HardHardV2Stage::Offer);
        value.remote_prediction_model = "future-model".to_string();
        assert!(value.encode_v2(value.v2.as_ref().unwrap()).is_none());
    }

    #[test]
    fn strategy_order_round_trips_echoes_and_rejects_unknown_value() {
        for order in 0..=2 {
            let mut value = envelope(HardHardV2Stage::Offer);
            value.v2.as_mut().unwrap().strategy_order = order;
            let wire = value.encode();
            assert_eq!(wire.len(), 124);
            assert_eq!(HardHardCoordination::parse(&wire), Some(value.clone()));
            let response = value.as_response(
                crate::peer::HardHardPlanSnapshot {
                    local_network_generation: 21,
                    remote_candidate_epoch: 22,
                    local_profile_generation: 23,
                    remote_profile_generation: 24,
                },
                90,
                "fixed_step".to_string(),
            );
            assert_eq!(response.v2.unwrap().strategy_order, order);
        }
        let mut invalid = envelope(HardHardV2Stage::Offer);
        invalid.v2.as_mut().unwrap().strategy_order = 3;
        assert!(invalid.encode_v2(invalid.v2.as_ref().unwrap()).is_none());
        let mut bytes = wire_bytes(&envelope(HardHardV2Stage::Offer));
        bytes[0] |= 3 << 4;
        assert!(HardHardCoordination::parse(&wire_from_bytes(&bytes)).is_none());
    }

    fn transcript() -> (
        HardHardCoordination,
        HardHardCoordination,
        Vec<SocketAddr>,
        Vec<SocketAddr>,
    ) {
        let offer = envelope(HardHardV2Stage::Offer);
        let mut answer = envelope(HardHardV2Stage::Answer);
        let meta = answer.v2.as_mut().unwrap();
        meta.local = parameters(50_001, 2);
        meta.remote = offer.v2.as_ref().unwrap().local;
        (offer, answer, endpoints(40_001), endpoints(50_001))
    }

    fn digest(
        offer: &HardHardCoordination,
        answer: &HardHardCoordination,
        offered: &[SocketAddr],
        answered: &[SocketAddr],
    ) -> Option<[u8; 16]> {
        hard_hard_plan_digest(
            offer,
            answer,
            offered,
            answered,
            (101, 202),
            10_000,
            HardHardProbeStrategy::FixedAnchor,
        )
    }

    #[test]
    fn digest_binds_every_candidate_including_unselected_tail_and_order() {
        let (offer, answer, offered, answered) = transcript();
        let baseline = digest(&offer, &answer, &offered, &answered).unwrap();
        for side in 0..2 {
            for position in 1..4 {
                let mut local = offered.clone();
                let mut remote = answered.clone();
                let changed = if side == 0 { &mut local } else { &mut remote };
                let changed_port = changed[position].port() + 100;
                changed[position].set_port(changed_port);
                assert_ne!(digest(&offer, &answer, &local, &remote).unwrap(), baseline);
            }
            let mut local = offered.clone();
            let mut remote = answered.clone();
            let changed = if side == 0 { &mut local } else { &mut remote };
            changed.swap(0, 3);
            assert_ne!(digest(&offer, &answer, &local, &remote).unwrap(), baseline);
        }
    }

    #[test]
    fn digest_binds_registrations_phase_deadline_and_all_directional_generations() {
        let (offer, answer, offered, answered) = transcript();
        let baseline = digest(&offer, &answer, &offered, &answered).unwrap();
        for (registrations, deadline) in [
            ((102, 202), 10_000),
            ((101, 203), 10_000),
            ((202, 101), 10_000),
            ((101, 202), 10_001),
        ] {
            assert_ne!(
                hard_hard_plan_digest(
                    &offer,
                    &answer,
                    &offered,
                    &answered,
                    registrations,
                    deadline,
                    HardHardProbeStrategy::FixedAnchor
                )
                .unwrap(),
                baseline
            );
        }
        let mut phased_offer = offer.clone();
        let mut phased_answer = answer.clone();
        phased_offer.v2.as_mut().unwrap().phase = false;
        phased_answer.v2.as_mut().unwrap().phase = false;
        assert_ne!(
            digest(&phased_offer, &phased_answer, &offered, &answered).unwrap(),
            baseline
        );
        for side in 0..2 {
            for field in 0..5 {
                let mut changed_offer = offer.clone();
                let mut changed_answer = answer.clone();
                let changed = if side == 0 {
                    &mut changed_offer
                } else {
                    &mut changed_answer
                };
                match field {
                    0 => changed.local_network_generation += 1,
                    1 => changed.remote_candidate_epoch += 1,
                    2 => changed.local_profile_generation += 1,
                    3 => changed.remote_profile_generation += 1,
                    _ => changed.remote_network_generation += 1,
                }
                assert_ne!(
                    digest(&changed_offer, &changed_answer, &offered, &answered).unwrap(),
                    baseline
                );
            }
        }
    }

    #[test]
    fn digest_rejects_invalid_transcripts_and_ignores_recursive_agreement_field() {
        let (offer, answer, offered, answered) = transcript();
        for invalid in 0..6 {
            let mut changed_offer = offer.clone();
            let mut changed_answer = answer.clone();
            match invalid {
                0 => changed_offer.role = HardHardRole::Responder,
                1 => changed_answer.role = HardHardRole::Initiator,
                2 => changed_offer.v2.as_mut().unwrap().stage = HardHardV2Stage::Ready,
                3 => changed_answer.v2.as_mut().unwrap().phase = false,
                4 => changed_answer.token = "11".repeat(16),
                _ => changed_answer.v2.as_mut().unwrap().remote.prediction_count += 1,
            }
            assert!(digest(&changed_offer, &changed_answer, &offered, &answered).is_none());
        }
        for (registrations, deadline, strategy) in [
            ((0, 202), 10_000, HardHardProbeStrategy::FixedAnchor),
            ((101, 0), 10_000, HardHardProbeStrategy::FixedAnchor),
            ((101, 202), 0, HardHardProbeStrategy::FixedAnchor),
            ((101, 202), 10_000, HardHardProbeStrategy::Birthday),
            ((101, 202), 10_000, HardHardProbeStrategy::Predictable),
        ] {
            assert!(hard_hard_plan_digest(
                &offer,
                &answer,
                &offered,
                &answered,
                registrations,
                deadline,
                strategy
            )
            .is_none());
        }
        let baseline = digest(&offer, &answer, &offered, &answered).unwrap();
        let mut different_checksum = answer.clone();
        different_checksum
            .v2
            .as_mut()
            .unwrap()
            .agreement
            .as_mut()
            .unwrap()
            .digest = [0x3c; 16];
        assert_eq!(
            digest(&offer, &different_checksum, &offered, &answered),
            Some(baseline)
        );
    }

    #[test]
    fn digest_binds_strategy_order_even_when_selected_strategy_is_unchanged() {
        let (mut offer, mut answer, offered, answered) = transcript();
        offer.v2.as_mut().unwrap().local.prediction_count = 0;
        answer.v2.as_mut().unwrap().local.prediction_count = 0;
        answer.v2.as_mut().unwrap().remote = offer.v2.as_ref().unwrap().local;
        let baseline = digest(&offer, &answer, &offered, &answered).unwrap();
        offer.v2.as_mut().unwrap().strategy_order = 1;
        assert!(digest(&offer, &answer, &offered, &answered).is_none());
        answer.v2.as_mut().unwrap().strategy_order = 1;
        assert_ne!(
            digest(&offer, &answer, &offered, &answered).unwrap(),
            baseline
        );
    }

    #[test]
    fn bilateral_strategy_selection_is_symmetric_and_requires_both_sides_evidence() {
        for (a, b, expected) in [
            (
                parameters(40_001, 0),
                parameters(50_001, 0),
                HardHardProbeStrategy::FixedAnchor,
            ),
            (
                parameters(40_001, 2),
                parameters(50_001, 2),
                HardHardProbeStrategy::FixedAnchor,
            ),
            (
                parameters(40_001, 2),
                parameters(0, 2),
                HardHardProbeStrategy::Predictable,
            ),
            (
                parameters(0, 2),
                parameters(0, 2),
                HardHardProbeStrategy::Predictable,
            ),
            (
                parameters(40_001, 0),
                parameters(0, 2),
                HardHardProbeStrategy::Birthday,
            ),
            (
                parameters(0, 0),
                parameters(0, 0),
                HardHardProbeStrategy::Birthday,
            ),
        ] {
            assert_eq!(HardHardProbeStrategy::select(a, b), expected);
            assert_eq!(HardHardProbeStrategy::select(b, a), expected);
            assert_eq!(
                HardHardProbeStrategy::from_wire(expected as u8),
                Some(expected)
            );
        }
        for unknown in [0, 4, 127, 255] {
            assert!(HardHardProbeStrategy::from_wire(unknown).is_none());
        }
    }

    #[test]
    fn learned_order_only_changes_priority_among_bilaterally_available_models() {
        for order in 0..=2 {
            for local_anchor in [0, 40_001] {
                for remote_anchor in [0, 50_001] {
                    for local_prediction in [0, 2] {
                        for remote_prediction in [0, 2] {
                            let local = parameters(local_anchor, local_prediction);
                            let remote = parameters(remote_anchor, remote_prediction);
                            let selected =
                                HardHardProbeStrategy::select_with_order(local, remote, order);
                            assert_eq!(
                                selected,
                                HardHardProbeStrategy::select_with_order(remote, local, order)
                            );
                            let anchor_available = local_anchor != 0 && remote_anchor != 0;
                            let prediction_available =
                                local_prediction != 0 && remote_prediction != 0;
                            let expected = if order == 2 {
                                HardHardProbeStrategy::Birthday
                            } else if prediction_available && (order == 1 || !anchor_available) {
                                HardHardProbeStrategy::Predictable
                            } else if anchor_available {
                                HardHardProbeStrategy::FixedAnchor
                            } else {
                                HardHardProbeStrategy::Birthday
                            };
                            assert_eq!(selected, expected);
                        }
                    }
                }
            }
        }
        let candidates = endpoints(50_001);
        let mut prioritized = plan(parameters(40_001, 2), parameters(50_003, 2));
        prioritized.strategy_order = 1;
        assert!(prioritized.remote_targets(&candidates).is_none());
        prioritized.agreement.as_mut().unwrap().strategy = HardHardProbeStrategy::Predictable;
        assert_eq!(
            prioritized.remote_targets(&candidates),
            Some(candidates[..2].to_vec())
        );
        prioritized.strategy_order = 2;
        assert!(prioritized.remote_targets(&candidates).is_none());
        prioritized.agreement.as_mut().unwrap().strategy = HardHardProbeStrategy::Birthday;
        assert_eq!(prioritized.remote_targets(&candidates), Some(candidates));
    }

    fn plan(
        local: HardHardOfferParameters,
        remote: HardHardOfferParameters,
    ) -> HardHardCoordinatedPlan {
        HardHardCoordinatedPlan {
            measurement_lease: None,
            recovery_identity: None,
            strategy_order: 0,
            local_offer: local,
            remote_offer: Some(remote),
            local_registration_seq: 101,
            remote_registration_seq: 202,
            phase: false,
            canonical_server_deadline: 10_000,
            scheduled_start: std::time::Instant::now(),
            forecast_first_send_deadline: std::time::Instant::now(),
            agreement: Some(HardHardAgreedPlan {
                strategy: HardHardProbeStrategy::select(local, remote),
                digest: [0xa5; 16],
            }),
            ready_received: false,
            ready_ack_received: false,
            ready_sent_at: None,
            ready_retransmitted: false,
            ready_rtt: None,
            sync_uncertainty: Duration::from_millis(25),
            start: None,
            start_ack_received: false,
            start_ack_queued: false,
            start_ack_delivery: None,
        }
    }

    #[test]
    fn selected_strategy_extracts_exact_anchor_prefix_or_full_ordered_window() {
        let candidates = endpoints(50_001);
        let fixed = plan(parameters(40_001, 2), parameters(50_003, 2));
        assert_eq!(fixed.remote_targets(&candidates), Some(vec![candidates[2]]));
        let predicted = plan(parameters(0, 2), parameters(50_003, 2));
        assert_eq!(
            predicted.remote_targets(&candidates),
            Some(candidates[..2].to_vec())
        );
        let birthday = plan(parameters(0, 0), parameters(50_003, 2));
        assert_eq!(
            birthday.remote_targets(&candidates),
            Some(candidates.clone())
        );
        let mut reversed = candidates;
        reversed.reverse();
        assert_eq!(
            predicted.remote_targets(&reversed),
            Some(reversed[..2].to_vec())
        );
        assert_eq!(birthday.remote_targets(&reversed), Some(reversed));
    }

    #[test]
    fn malformed_candidates_or_inconsistent_agreement_cannot_produce_targets() {
        let candidates = endpoints(50_001);
        let valid = plan(parameters(40_001, 2), parameters(50_003, 2));
        let mut duplicate = candidates.clone();
        duplicate[3] = duplicate[1];
        let mut zero = candidates.clone();
        zero[3].set_port(0);
        let mut mixed_ip = candidates.clone();
        mixed_ip[3].set_ip("203.0.113.21".parse().unwrap());
        let too_many: Vec<_> = (0..=crate::MAX_SIGNAL_CANDIDATES)
            .map(|offset| SocketAddr::from(([203, 0, 113, 20], 50_001 + offset as u16)))
            .collect();
        for invalid in [
            vec![],
            duplicate,
            zero,
            mixed_ip,
            too_many,
            candidates[..2].to_vec(),
        ] {
            assert!(valid.remote_targets(&invalid).is_none());
        }
        let mut missing_agreement = valid.clone();
        missing_agreement.agreement = None;
        assert!(missing_agreement.remote_targets(&candidates).is_none());
        let mut missing_remote = valid;
        missing_remote.remote_offer = None;
        assert!(missing_remote.remote_targets(&candidates).is_none());
        let mut empty_prediction = plan(parameters(0, 0), parameters(0, 0));
        empty_prediction.agreement.as_mut().unwrap().strategy = HardHardProbeStrategy::Predictable;
        assert!(empty_prediction.remote_targets(&candidates).is_none());
        for socket_count in [0, 1, 3, 16] {
            let mut invalid = parameters(0, 2);
            invalid.socket_count = socket_count;
            assert!(!invalid.is_valid(&candidates));
        }
        assert!(!parameters(0, 5).is_valid(&candidates));
        assert!(!parameters(0, 33).is_valid(&candidates));
    }

    #[test]
    fn readiness_requires_the_correct_role_acknowledgement_and_agreement() {
        let mut value = plan(parameters(0, 2), parameters(0, 2));
        assert!(!value.ready(true));
        assert!(!value.ready(false));
        value.ready_received = true;
        assert!(!value.ready(true));
        assert!(!value.ready(false));
        value.start = Some(crate::peer::HardHardAgreedStart {
            server_time_ms: 9_000,
            agreement: crate::peer::hard_hard_start_agreement(value.agreement.unwrap(), 9_000),
        });
        value.start_ack_queued = true;
        assert!(value.ready(false));
        value.ready_received = false;
        value.ready_ack_received = true;
        assert!(!value.ready(true));
        value.start_ack_received = true;
        assert!(value.ready(true));
        assert!(!value.ready(false));
        value.ready_received = true;
        value.agreement = None;
        assert!(!value.ready(true));
        assert!(!value.ready(false));
    }

    #[test]
    fn start_uses_this_round_rtt_and_never_extends_outer_deadline() {
        let mut value = plan(parameters(0, 2), parameters(0, 2));
        let now = Instant::now();
        value.scheduled_start = now + Duration::from_millis(2_000);
        value.ready_rtt = Some(Duration::from_millis(50));
        value.sync_uncertainty = Duration::from_millis(25);
        let fast = hard_hard_choose_start(&value, now).unwrap();
        assert_eq!(fast.server_time_ms, 8_200);
        value.ready_rtt = Some(Duration::from_millis(200));
        let slow = hard_hard_choose_start(&value, now).unwrap();
        assert_eq!(slow.server_time_ms, 8_500);
        assert_ne!(fast.agreement.digest, slow.agreement.digest);
        value.ready_rtt = Some(Duration::from_secs(1));
        assert!(hard_hard_choose_start(&value, now).is_none());
        value.ready_rtt = None;
        assert!(hard_hard_choose_start(&value, now).is_none());
    }

    #[test]
    fn incomplete_or_confirmation_failure_is_not_negative_strategy_evidence() {
        let complete = PunchSendReport {
            packets_sent: 8,
            logical_probes_sent: 8,
            target_processing_completed: true,
            ..Default::default()
        };
        assert!(hard_hard_complete_unanswered_exploration(
            &complete,
            8,
            Default::default()
        ));
        assert!(!hard_hard_complete_unanswered_exploration(
            &complete,
            9,
            Default::default()
        ));
        for report in [
            PunchSendReport {
                budget_skipped: 1,
                ..complete.clone()
            },
            PunchSendReport {
                targets_cancelled: 1,
                ..complete.clone()
            },
            PunchSendReport {
                physical_send_errors: 1,
                ..complete.clone()
            },
            PunchSendReport {
                probe_path_errors: 1,
                ..complete.clone()
            },
            PunchSendReport {
                pacing_deadline_reached: true,
                ..complete.clone()
            },
        ] {
            assert!(!hard_hard_complete_unanswered_exploration(
                &report,
                8,
                Default::default()
            ));
        }
        assert!(!hard_hard_complete_unanswered_exploration(
            &complete,
            8,
            UdpProbeRxSnapshot {
                authenticated_probe_acks_observed: 1,
                ..Default::default()
            }
        ));
    }
    include!("negotiation_tests.rs");
    include!("barrier_tests.rs");
    include!("ingress_regression_tests.rs");
}
