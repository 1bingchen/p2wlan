fn hard_hard_measurement_stats(
    measurement: &HardHardLocalMeasurement,
) -> crate::udp::HardHardMeasurementStats {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => result.measurement,
        HardHardLocalMeasurement::Birthday(result) => result.measurement,
        HardHardLocalMeasurement::Prepared(result) => result.measurement_cost(),
    }
}

fn hard_hard_measurement_observation(
    peers: &PeerManager,
    measurement: &HardHardLocalMeasurement,
    measurement_completed_at_ms: Option<u64>,
    punch_at_ms: u64,
) -> crate::peer::HardHardMeasurementObservation {
    hard_hard_measurement_observation_from_stats(
        peers,
        hard_hard_measurement_stats(measurement),
        measurement_completed_at_ms,
        punch_at_ms,
    )
}

fn hard_hard_measurement_observation_from_stats(
    peers: &PeerManager,
    stats: crate::udp::HardHardMeasurementStats,
    measurement_completed_at_ms: Option<u64>,
    punch_at_ms: u64,
) -> crate::peer::HardHardMeasurementObservation {
    let timeline_now_ms = peers.timeline_uptime_ms();
    let transport_now_ms = crate::udp::monotonic_millis();
    let measurement_started_at_ms = hard_hard_translate_transport_time(
        stats.measurement_started_at_ms,
        transport_now_ms,
        timeline_now_ms,
    );
    let last_measurement_send_at_ms = hard_hard_translate_transport_time(
        stats.last_measurement_send_at_ms,
        transport_now_ms,
        timeline_now_ms,
    );
    let measurement_completed_at_ms = hard_hard_translate_transport_time(
        stats.measurement_completed_at_ms,
        transport_now_ms,
        timeline_now_ms,
    )
    .or(measurement_completed_at_ms);
    let wall_now_ms = hard_hard_now_ms();
    let planned_send_at_ms = timeline_now_ms.map(|timeline_now| {
        if punch_at_ms >= wall_now_ms {
            timeline_now.saturating_add(punch_at_ms - wall_now_ms)
        } else {
            timeline_now.saturating_sub(wall_now_ms - punch_at_ms)
        }
    });
    crate::peer::HardHardMeasurementObservation {
        measurement_started_at_ms,
        last_measurement_send_at_ms,
        measurement_completed_at_ms,
        planned_send_at_ms,
        stun_datagrams_sent: stats.stun_datagrams_sent,
        stun_bytes_sent: stats.stun_bytes_sent,
        stun_send_errors: stats.stun_send_errors,
        stun_send_error_bytes: stats.stun_send_error_bytes,
        stun_responses: stats.stun_responses,
        ..crate::peer::HardHardMeasurementObservation::default()
    }
}

fn hard_hard_rejected_measurement_observation(
    peers: &PeerManager,
    failure: &HardHardMeasurementFailure,
    punch_at_ms: u64,
) -> Option<crate::peer::HardHardMeasurementObservation> {
    failure
        .measurement
        .map(|stats| hard_hard_measurement_observation_from_stats(peers, stats, None, punch_at_ms))
}
