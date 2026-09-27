fn hard_hard_measurement_publication_is_current(
    measurement: &HardHardLocalMeasurement,
    peers: &PeerManager,
    peer: &str,
    offer: Option<crate::peer::HardHardOfferParameters>,
) -> bool {
    let HardHardLocalMeasurement::Prepared(result) = measurement else {
        return true;
    };
    let Some(offer) = offer else {
        return false;
    };
    match result.validate_publication(
        peers.current_network_generation_sync(),
        usize::from(offer.prediction_count),
        offer.anchor_port,
    ) {
        Ok(()) => true,
        Err(reason) => {
            peers.record_direct_event_non_queuing(
                peer,
                "hard_hard_publication_rejected",
                None,
                None,
                None,
                format!("reason={}", reason.label()),
            );
            false
        }
    }
}

fn hard_hard_prepared_payload(
    result: &crate::udp::HardHardPreparedMeasurement,
    boot_epoch_ms: u64,
    network_generation: u64,
) -> std::result::Result<HardHardMeasurementPayload, HardHardPayloadRejection> {
    let birthday = &result.birthday;
    let primary = birthday
        .sockets
        .first()
        .ok_or(HardHardPayloadRejection::EmptyPredictionWindow)?;
    let source = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot_epoch_ms,
        generation: primary.punch_generation,
    });
    let cap = birthday.level.min(crate::MAX_SIGNAL_CANDIDATES);
    if result.identity.network_generation != network_generation {
        return Err(HardHardPayloadRejection::BatchStale);
    }
    let mut endpoints = result
        .prediction_candidates(network_generation, HARD_HARD_MAX_PREDICTION_TARGETS)
        .unwrap_or_default();
    let prediction_count = endpoints.len() as u8;
    let anchor = result
        .fixed_anchor_plan(
            network_generation,
            birthday.sockets.len(),
            birthday.sockets.len().saturating_sub(1),
        )
        .ok();
    if let Some(anchor) = anchor {
        if !endpoints.contains(&anchor.local_anchor) {
            endpoints.push(anchor.local_anchor);
        }
    }
    for endpoint in &birthday.candidate_endpoints {
        if endpoints.len() >= cap {
            break;
        }
        if !endpoints.contains(endpoint) {
            endpoints.push(*endpoint);
        }
    }
    endpoints.truncate(cap);
    let offer = crate::peer::HardHardOfferParameters {
        socket_count: birthday.sockets.len() as u8,
        prediction_count,
        anchor_port: anchor.map_or(0, |anchor| anchor.local_anchor.port()),
    };
    if !offer.is_valid(&endpoints) {
        return Err(HardHardPayloadRejection::EmptyPredictionWindow);
    }
    let candidates = endpoints
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .map(|endpoint| (endpoint.clone(), source.clone()))
        .collect();
    let (candidates, candidate_sources, candidate_contract) =
        crate::candidate_refresh::normalize_signal_candidates_with_counts(
            &candidates,
            &sources,
            birthday.requested_level,
            candidates.len(),
        );
    // All alternatives use the same fresh batch label. Preserve the measured
    // prefix because both peers bind its exact order in the agreement digest.
    if hard_hard_prediction_targets(&candidates, cap) != endpoints {
        return Err(HardHardPayloadRejection::EmptyPredictionWindow);
    }
    Ok(HardHardMeasurementPayload {
        v2_offer: Some(offer),
        candidates,
        candidate_sources,
        candidate_contract,
        local_confidence: result
            .predictable
            .as_ref()
            .map_or(birthday.model_confidence, |prediction| {
                prediction.model.confidence
            })
            .max(1),
        local_model: result.predictable.as_ref().map_or_else(
            || birthday.model_label.clone(),
            |prediction| hard_hard_model_label(&prediction.model.kind).to_string(),
        ),
        strategy_candidate_cap: cap,
    })
}

async fn hard_hard_new_coordinated_plan(
    peers: &PeerManager,
    control: &ControlClient,
    peer: &str,
    offer: crate::peer::HardHardOfferParameters,
    phase: bool,
    punch_at_ms: u64,
    server_deadline: u64,
) -> Option<crate::peer::HardHardCoordinatedPlan> {
    let local_registration_seq = control.local_hh2_registration_seq()?;
    let remote_registration_seq = peers.peer_hh2_registration_seq(peer).await?;
    let scheduled_start =
        Instant::now() + Duration::from_millis(punch_at_ms.saturating_sub(hard_hard_now_ms()));
    Some(crate::peer::HardHardCoordinatedPlan {
        measurement_lease: None,
        recovery_identity: None,
        strategy_order: 0,
        local_offer: offer,
        remote_offer: None,
        local_registration_seq,
        remote_registration_seq,
        phase,
        canonical_server_deadline: server_deadline,
        scheduled_start,
        forecast_first_send_deadline: scheduled_start,
        agreement: None,
        ready_received: false,
        ready_ack_received: false,
        ready_sent_at: None,
        ready_rtt: None,
        sync_uncertainty: HARD_HARD_RESPONSE_DEADLINE_TOLERANCE,
        start: None,
        start_ack_received: false,
        start_ack_queued: false,
        start_ack_delivery: None,
    })
}
