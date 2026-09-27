async fn hard_hard_plan_registration_is_current(
    peers: &PeerManager,
    control: &ControlClient,
    peer: &str,
    plan: &crate::peer::HardHardCoordinatedPlan,
) -> bool {
    control.local_hh2_registration_seq() == Some(plan.local_registration_seq)
        && peers.peer_hh2_registration_seq(peer).await == Some(plan.remote_registration_seq)
}

async fn hard_hard_accept_answer(
    peers: &PeerManager,
    control: &ControlClient,
    record: &HardHardSessionRecord,
    answer: &HardHardCoordination,
    remote: &[SocketAddr],
) -> Option<(HardHardCoordination, HardHardSessionRecord)> {
    let plan = record.coordinated_plan.as_ref()?;
    let meta = answer.v2.as_ref()?;
    let offer = HardHardCoordination::parse(&record.session_id)?;
    if meta.stage != HardHardV2Stage::Answer
        || meta.phase != plan.phase
        || meta.strategy_order != plan.strategy_order
        || meta.remote != plan.local_offer
        || !meta.local.is_valid(remote)
        || !hard_hard_plan_registration_is_current(peers, control, &record.peer_id, plan).await
    {
        return None;
    }
    let strategy = crate::peer::HardHardProbeStrategy::select_with_order(
        plan.local_offer,
        meta.local,
        plan.strategy_order,
    );
    let digest = hard_hard_plan_digest(
        &offer,
        answer,
        &record.prediction_window,
        remote,
        (plan.local_registration_seq, plan.remote_registration_seq),
        plan.canonical_server_deadline,
        strategy,
    )?;
    let agreement = crate::peer::HardHardAgreedPlan { strategy, digest };
    if meta.agreement != Some(agreement) {
        return None;
    }
    let committed = peers
        .hard_hard_agree_plan(
            &record.peer_id,
            &record.session_token,
            crate::peer::HardHardPlanAgreement {
                remote_offer: meta.local,
                agreement,
                remote_prediction: remote,
                remote_network_generation: answer.local_network_generation,
                remote_confidence: answer.local_prediction_confidence,
                sync_uncertainty: hard_hard_sync_uncertainty(offer.v2.as_ref()?, meta),
            },
        )
        .await?;
    let mut ready = offer;
    ready.remote_network_generation = answer.local_network_generation;
    ready.remote_prediction_confidence = answer.local_prediction_confidence;
    ready.remote_prediction_model = answer.local_prediction_model.clone();
    let ready_meta = ready.v2.as_mut()?;
    ready_meta.remote = meta.local;
    ready_meta.stage = HardHardV2Stage::Ready;
    ready_meta.agreement = Some(agreement);
    Some((ready, committed))
}

fn hard_hard_sync_uncertainty(a: &HardHardV2Envelope, b: &HardHardV2Envelope) -> Duration {
    let hint = |meta: &HardHardV2Envelope| {
        if meta.rtt_ms == 0 || meta.uncertainty_ms == 0 {
            HARD_HARD_RESPONSE_DEADLINE_TOLERANCE
        } else {
            Duration::from_millis(u64::from(meta.uncertainty_ms))
        }
    };
    hint(a).max(hint(b)).max(Duration::from_millis(25))
}

/// READY and its acknowledgement travel through the existing authenticated
/// Control channel but bypass candidate replacement. This future stays in
/// the existing punch owner and never extends its rendezvous deadline.
async fn hard_hard_exchange_ready(
    peers: &PeerManager,
    signal: &HolePunchSignalContext,
    record: &HardHardSessionRecord,
    envelope: HardHardCoordination,
) -> bool {
    let deadline = record
        .coordinated_plan
        .as_ref()
        .map(|plan| plan.scheduled_start);
    let Some(deadline) = deadline else {
        return true;
    };
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        hard_hard_exchange_barriers(peers, signal, record, envelope),
    )
    .await
    .unwrap_or(false)
}

async fn hard_hard_exchange_barriers(
    peers: &PeerManager,
    signal: &HolePunchSignalContext,
    record: &HardHardSessionRecord,
    mut envelope: HardHardCoordination,
) -> bool {
    let Some(initial) = record.coordinated_plan.as_ref() else {
        return true;
    };
    let Some(meta) = envelope.v2.as_mut() else {
        return false;
    };
    meta.stage = if record.initiator {
        HardHardV2Stage::Ready
    } else {
        HardHardV2Stage::ReadyAck
    };
    let encoded = envelope.encode();
    if HardHardCoordination::parse(&encoded).is_none() {
        return false;
    }
    let local_candidates = record
        .prediction_window
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let source = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: signal.boot_epoch_ms,
        generation: record.fresh_socket.punch_generation,
    });
    let sources = local_candidates
        .iter()
        .map(|endpoint| (endpoint.clone(), source.clone()))
        .collect::<HashMap<_, _>>();
    let deadline = tokio::time::Instant::from_std(initial.scheduled_start);
    let mut attempts = 0u8;
    let mut next_send = tokio::time::Instant::now();
    loop {
        if record.cancellation.is_cancelled() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        let Some(current) = peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
        else {
            return false;
        };
        let Some(plan) = current.coordinated_plan.as_ref() else {
            return false;
        };
        if plan.agreement != initial.agreement
            || !peers
                .hard_hard_session_identity_is_current(&current.fresh_socket)
                .await
            || !hard_hard_plan_registration_is_current(
                peers,
                &signal.control,
                &record.peer_id,
                plan,
            )
            .await
        {
            return false;
        }
        if (record.initiator && plan.ready_ack_received)
            || (!record.initiator && plan.start.is_some())
        {
            break;
        }
        let permitted = record.initiator || plan.ready_received;
        if permitted
            && attempts < HARD_HARD_BARRIER_MAX_ATTEMPTS
            && tokio::time::Instant::now() >= next_send
        {
            let Some(recovery_identity) = plan.recovery_identity else {
                return false;
            };
            if !peers
                .try_consume_recovery_http_quota_for_identity(&record.peer_id, recovery_identity)
                .await
            {
                return false;
            }
            if record.initiator
                && !peers
                    .hard_hard_mark_ready_sent(&record.peer_id, &record.session_token)
                    .await
            {
                return false;
            }
            attempts += 1;
            let sent = tokio::select! {
                biased;
                advanced = hard_hard_wait_for_barrier_progress(peers, record, false) => advanced,
                sent = signal.control.send_hard_hard_barrier(
                    &record.peer_id, &local_candidates, &sources, record.punch_at_ms,
                    plan.canonical_server_deadline, encoded.clone(), record.cancellation.clone(),
                    initial.scheduled_start, plan.local_registration_seq,
                ) => sent.is_ok(),
            };
            // The responder already received the initiator's agreement. Its
            // ACK is idempotent; the durable Control delivery retries loss.
            if !record.initiator && sent {
                break;
            }
            next_send = tokio::time::Instant::now() + Duration::from_millis(100);
        }
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_millis(20)).min(deadline),
        )
        .await;
    }
    hard_hard_exchange_start(peers, signal, record, envelope, &local_candidates, &sources).await
}

/// Use the actual READY round trip to choose a final activation. Both peers
/// subtract the same advance from their original monotonic schedule, so later
/// wall-clock estimates cannot move an agreed start or extend its forecast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardHardStartWindowRejection {
    TimingUnavailable,
    ForecastWindowInsufficient,
    ConfirmationWindowInsufficient,
}

impl HardHardStartWindowRejection {
    fn label(self) -> &'static str {
        match self {
            Self::TimingUnavailable => "start_timing_unavailable",
            Self::ForecastWindowInsufficient => "start_forecast_window_insufficient",
            Self::ConfirmationWindowInsufficient => "confirmation_window_exceeds_session_ttl",
        }
    }
}

#[cfg(test)]
fn hard_hard_choose_start(
    plan: &crate::peer::HardHardCoordinatedPlan,
    now: Instant,
) -> Option<crate::peer::HardHardAgreedStart> {
    hard_hard_choose_start_with_lifetime(
        plan,
        now,
        plan.scheduled_start.checked_add(Duration::from_millis(2)),
    )
    .ok()
}

fn hard_hard_choose_start_with_lifetime(
    plan: &crate::peer::HardHardCoordinatedPlan,
    now: Instant,
    latest_session_start: Option<Instant>,
) -> std::result::Result<crate::peer::HardHardAgreedStart, HardHardStartWindowRejection> {
    use HardHardStartWindowRejection as Rejection;
    let remote = plan.remote_offer.ok_or(Rejection::TimingUnavailable)?;
    let agreement = plan.agreement.ok_or(Rejection::TimingUnavailable)?;
    let first_wave_pairs = match agreement.strategy {
        crate::peer::HardHardProbeStrategy::Predictable => usize::from(
            plan.local_offer
                .prediction_count
                .max(remote.prediction_count),
        ),
        crate::peer::HardHardProbeStrategy::FixedAnchor => {
            usize::from(plan.local_offer.socket_count.max(remote.socket_count))
        }
        crate::peer::HardHardProbeStrategy::Birthday => 0,
    };
    let forecast_margin = if first_wave_pairs == 0 {
        Duration::ZERO
    } else {
        crate::udp::hard_hard_first_wave_pacing_margin(first_wave_pairs)
    };
    let lead = if plan.ready_retransmitted {
        // A delayed ACK cannot identify its READY transmission. Keep the
        // conservative schedule, advancing only enough to retain both the
        // physical first-wave margin and the entire immutable session window.
        plan.sync_uncertainty
            .saturating_mul(2)
            .saturating_add(Duration::from_millis(50))
            .max(Duration::from_millis(150))
    } else {
        plan.ready_rtt
            .ok_or(Rejection::TimingUnavailable)?
            .saturating_mul(2)
            .saturating_add(plan.sync_uncertainty.saturating_mul(2))
            .saturating_add(Duration::from_millis(50))
            .max(Duration::from_millis(150))
    };
    let earliest = now.checked_add(lead).ok_or(Rejection::TimingUnavailable)?;
    let latest_forecast = plan
        .scheduled_start
        .checked_sub(forecast_margin)
        .ok_or(Rejection::ForecastWindowInsufficient)?;
    if earliest > latest_forecast {
        return Err(Rejection::ForecastWindowInsufficient);
    }
    // Selection keeps two milliseconds beyond the acceptance bound so a
    // later wall/monotonic conversion cannot reject the same valid start due
    // solely to millisecond quantization. Neither bound renews the TTL.
    let latest_session_start = latest_session_start
        .and_then(|latest| latest.checked_sub(Duration::from_millis(2)))
        .ok_or(Rejection::ConfirmationWindowInsufficient)?;
    if earliest > latest_session_start {
        return Err(Rejection::ConfirmationWindowInsufficient);
    }
    let latest = latest_forecast.min(latest_session_start);
    let target = if plan.ready_retransmitted {
        latest
    } else {
        earliest
    };
    let advance = plan
        .scheduled_start
        .checked_duration_since(target)
        .ok_or(Rejection::TimingUnavailable)?;
    // The wire start has millisecond precision. Conservative late starts
    // round toward earlier activation; RTT-based starts retain their full
    // delivery lead and are then checked against both upper bounds.
    let advance_ms = if plan.ready_retransmitted {
        advance.as_nanos().div_ceil(1_000_000)
    } else {
        advance.as_millis()
    };
    let advance_ms = u64::try_from(advance_ms).map_err(|_| Rejection::TimingUnavailable)?;
    let actual = plan
        .scheduled_start
        .checked_sub(Duration::from_millis(advance_ms))
        .ok_or(Rejection::TimingUnavailable)?;
    if actual < earliest || actual > latest_session_start {
        return Err(Rejection::ConfirmationWindowInsufficient);
    }
    if actual > latest_forecast {
        return Err(Rejection::ForecastWindowInsufficient);
    }
    let server_time_ms = plan
        .canonical_server_deadline
        .checked_sub(advance_ms)
        .filter(|value| *value > 0)
        .ok_or(Rejection::TimingUnavailable)?;
    Ok(crate::peer::HardHardAgreedStart {
        server_time_ms,
        agreement: crate::peer::hard_hard_start_agreement(agreement, server_time_ms),
    })
}

async fn hard_hard_wait_for_barrier_progress(
    peers: &PeerManager,
    record: &HardHardSessionRecord,
    final_start: bool,
) -> bool {
    loop {
        if record.cancellation.is_cancelled() {
            return false;
        }
        let Some(current) = peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
        else {
            return false;
        };
        let Some(plan) = current.coordinated_plan.as_ref() else {
            return false;
        };
        let advanced = if final_start {
            plan.start_ack_received
        } else if record.initiator {
            plan.ready_ack_received
        } else {
            plan.start.is_some()
        };
        if advanced {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn hard_hard_exchange_start(
    peers: &PeerManager,
    signal: &HolePunchSignalContext,
    record: &HardHardSessionRecord,
    mut envelope: HardHardCoordination,
    candidates: &[String],
    sources: &HashMap<String, String>,
) -> bool {
    if record.initiator {
        let Some(current) = peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
        else {
            return false;
        };
        let Some(plan) = current.coordinated_plan.as_ref() else {
            return false;
        };
        let now = Instant::now();
        let latest_start = crate::peer::hard_hard_latest_start_for_session(
            current.expires_at_ms,
            hard_hard_now_ms(),
            now,
        );
        let start = match hard_hard_choose_start_with_lifetime(plan, now, latest_start) {
            Ok(start) => start,
            Err(reason) => {
                peers.record_direct_event_non_queuing(
                    &record.peer_id,
                    "hard_hard_start_rejected",
                    None,
                    None,
                    None,
                    format!("reason_code={}", reason.label()),
                );
                return false;
            }
        };
        if !peers
            .hard_hard_activate_start(&record.peer_id, &record.session_token, start)
            .await
        {
            return false;
        }
    }
    let mut attempts = 0u8;
    let mut next_send = Instant::now();
    loop {
        let Some(current) = peers
            .hard_hard_session_by_token(&record.peer_id, &record.session_token)
            .await
        else {
            return false;
        };
        let Some(plan) = current.coordinated_plan.as_ref() else {
            return false;
        };
        if current.cancellation.is_cancelled()
            || !hard_hard_plan_registration_is_current(
                peers,
                &signal.control,
                &record.peer_id,
                plan,
            )
            .await
            || !peers
                .hard_hard_session_identity_is_current(&current.fresh_socket)
                .await
        {
            return false;
        }
        if record.initiator && plan.ready(true) {
            return true;
        }
        if Instant::now() >= plan.scheduled_start {
            return false;
        }
        if let Some(start) = plan
            .start
            .filter(|_| attempts < HARD_HARD_BARRIER_MAX_ATTEMPTS && Instant::now() >= next_send)
        {
            let Some(recovery) = plan.recovery_identity else {
                return false;
            };
            if !peers
                .try_consume_recovery_http_quota_for_identity(&record.peer_id, recovery)
                .await
            {
                return false;
            }
            let Some(meta) = envelope.v2.as_mut() else {
                return false;
            };
            meta.stage = if record.initiator {
                HardHardV2Stage::Sync
            } else {
                HardHardV2Stage::SyncAck
            };
            meta.agreement = Some(start.agreement);
            let encoded = envelope.encode();
            if HardHardCoordination::parse(&encoded).is_none() {
                return false;
            }
            attempts += 1;
            let local_time_ms = hard_hard_now_ms().saturating_add(
                plan.scheduled_start
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64,
            );
            if !record.initiator {
                // The first attempt was paid above. Reserve each optional
                // retry before handing this immutable ACK to the worker;
                // retries never acquire extra credits or extend the start.
                let mut prepaid_attempts = 1;
                while prepaid_attempts < crate::control::HARD_HARD_START_ACK_MAX_ATTEMPTS {
                    if !peers
                        .try_consume_recovery_http_quota_for_identity(&record.peer_id, recovery)
                        .await
                    {
                        break;
                    }
                    prepaid_attempts += 1;
                }
                // Queue ownership is enough for the final ACK. Keep its
                // receipt alive in this plan so the existing bounded Control
                // worker can finish while the UDP owner waits for start.
                if let Ok(delivery) = signal
                    .control
                    .queue_hard_hard_start_ack(
                        &record.peer_id,
                        candidates,
                        sources,
                        local_time_ms,
                        start.server_time_ms,
                        encoded,
                        record.cancellation.clone(),
                        plan.scheduled_start,
                        prepaid_attempts,
                        plan.local_registration_seq,
                    )
                    .await
                {
                    return peers
                        .hard_hard_confirm_start(
                            &record.peer_id,
                            &record.session_token,
                            start,
                            false,
                            Some(delivery),
                        )
                        .await;
                }
                // Queue wait already consumed the original deadline or was
                // cancelled/closed. Never charge another prepaid command.
                peers.record_direct_event_non_queuing(
                    &record.peer_id,
                    "hard_hard_start_rejected",
                    None,
                    None,
                    None,
                    "reason_code=final_ack_queue_admission_failed",
                );
                return false;
            }
            let _sent = tokio::select! {
                biased;
                advanced = hard_hard_wait_for_barrier_progress(peers, record, true) => advanced,
                sent = signal.control.send_hard_hard_barrier(
                    &record.peer_id, candidates, sources, local_time_ms, start.server_time_ms,
                    encoded, record.cancellation.clone(), plan.scheduled_start, plan.local_registration_seq) => sent.is_ok(),
            };
            next_send = Instant::now() + Duration::from_millis(100);
        }
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            (Instant::now() + Duration::from_millis(20)).min(plan.scheduled_start),
        ))
        .await;
    }
}

fn hard_hard_sweep_plan(
    record: &HardHardSessionRecord,
    advertised_remote: &[SocketAddr],
) -> Option<(Vec<SocketAddr>, Option<Vec<usize>>)> {
    let Some(plan) = record.coordinated_plan.as_ref() else {
        return Some((
            advertised_remote.to_vec(),
            record
                .birthday
                .then(|| record.requested_socket_indices.clone()),
        ));
    };
    if !plan.ready(record.initiator) {
        return None;
    }
    let mut targets = plan.remote_targets(advertised_remote)?;
    let strategy = plan.agreement?.strategy;
    if strategy == crate::peer::HardHardProbeStrategy::Predictable {
        if !record.initiator {
            let local = record
                .prediction_window
                .get(..usize::from(plan.local_offer.prediction_count))?;
            // Both endpoints use the one phase from their agreed transcript.
            // Non-fixed windows simply retain their original order.
            targets = p2pnet_nat::mapping::rendezvous::fixed_step_rendezvous_targets(
                local, &targets, true, plan.phase,
            )
            .unwrap_or(targets);
        }
        Some((targets, None))
    } else {
        Some((targets, Some(record.requested_socket_indices.clone())))
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_hard_hard_initiator_response(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    coordination: HardHardCoordination,
    remote_prediction: Vec<SocketAddr>,
    punch_at_ms: u64,
) -> HardHardRemoteStart {
    spawn_hard_hard_initiator_response_with_signal(
        udp,
        peers,
        punch_deduplicator,
        peer_id,
        coordination,
        remote_prediction,
        punch_at_ms,
        None,
    )
    .await
}
