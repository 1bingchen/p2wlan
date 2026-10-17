enum HardHardLocalMeasurement {
    Predictable {
        result: Box<FreshMappingResult>,
        handoff: Box<ProvisionalSocketGuard>,
    },
    Birthday(Box<HardHardBirthdayResult>),
    Prepared(Box<crate::udp::HardHardPreparedMeasurement>),
}

/// The completed measurement snapshot grants no send, handoff or plan authority.
struct HardHardMeasurementFailure {
    rejection: FreshMappingRejection,
    measurement: Option<crate::udp::HardHardMeasurementStats>,
}

/// Borrowed inputs for a single measurement; cancellation and the scheduled
/// send remain owned by the existing rendezvous session.
struct HardHardMeasurementRequest<'a> {
    observers: &'a [SocketAddr],
    stun_timeout: Duration,
    session_token: &'a str,
    cancellation: Option<&'a Arc<crate::PunchSessionCancellation>>,
    punch_at_ms: u64,
    coordinated: bool,
}

async fn run_hard_hard_local_measurement(
    udp: &UdpTransport,
    peers: &PeerManager,
    peer_id: &str,
    request: HardHardMeasurementRequest<'_>,
) -> std::result::Result<HardHardLocalMeasurement, HardHardMeasurementFailure> {
    let HardHardMeasurementRequest {
        observers,
        stun_timeout,
        session_token,
        cancellation,
        punch_at_ms,
        coordinated,
    } = request;
    let mut measurement = None;
    let outcome = if coordinated {
        let level = hard_hard_birthday_level(peers, peer_id).await;
        udp.run_hard_hard_prepared_generation(
            peer_id,
            observers,
            stun_timeout,
            level,
            session_token,
            cancellation,
            Duration::from_millis(punch_at_ms.saturating_sub(hard_hard_now_ms())),
            HARD_HARD_PUNCH_LEAD,
            Some(&mut measurement),
        )
        .await
        .map(|result| HardHardLocalMeasurement::Prepared(Box::new(result)))
    } else if peers
        .hard_hard_plan_uses_birthday(peer_id)
        .await
        .unwrap_or(false)
    {
        let level = hard_hard_birthday_level(peers, peer_id).await;
        udp.run_hard_hard_birthday_generation(
            peer_id,
            crate::udp::HardHardBirthdayRequest {
                observers,
                stun_timeout,
                level,
                session_token,
                cancellation,
            },
            Some(&mut measurement),
        )
        .await
        .map(|result| HardHardLocalMeasurement::Birthday(Box::new(result)))
    } else {
        match udp
            .run_hard_hard_fresh_mapping_generation(
                peer_id,
                observers,
                stun_timeout,
                cancellation,
                Duration::from_millis(punch_at_ms.saturating_sub(hard_hard_now_ms())),
                HARD_HARD_PUNCH_LEAD,
                Some(&mut measurement),
            )
            .await
        {
            FreshMappingOutcome::Accepted(result, handoff) => {
                if !udp
                    .tag_hard_hard_socket(peer_id, result.socket_index, session_token)
                    .await
                {
                    Err(FreshMappingRejection::Superseded)
                } else {
                    Ok(HardHardLocalMeasurement::Predictable { result, handoff })
                }
            }
            FreshMappingOutcome::Rejected(rejection) => Err(rejection),
        }
    };
    outcome.map_err(|rejection| HardHardMeasurementFailure {
        rejection,
        measurement,
    })
}
