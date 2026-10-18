use super::*;

fn flow() -> RegisteredFlow {
    RegisteredFlow {
        src_v4: Ipv4Addr::new(10, 21, 1, 2),
        dst_v4: Ipv4Addr::new(10, 21, 1, 3),
        src_port: 41000,
        dst_port: 42000,
    }
}

fn key() -> TcpFrameKey {
    TcpFrameKey {
        run: [0x11; 16],
        round: [0x22; 16],
        sequence: 7,
        request_nonce: [0x33; 16],
        kind: RequestKind::Request,
    }
}

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn coverage(first: u32, started: Instant) -> TcpFrameCoverage {
    TcpFrameCoverage::new(
        TcpFramePlan::new(flow(), key(), 128).unwrap(),
        first,
        started,
        started + Duration::from_secs(1),
    )
    .unwrap()
}

fn segment(sequence: u32, payload: &[u8]) -> TcpSegment<'_> {
    TcpSegment {
        flow: flow(),
        sequence,
        flags: 0x18,
        payload,
    }
}

#[test]
fn actual_existing_python_tool_frames_and_independent_ip_tcp_checksums_match() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("tool_vectors.json")).unwrap();
    let rows = document["vectors"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        let key = TcpFrameKey {
            run: bytes(row["run"].as_str().unwrap()).try_into().unwrap(),
            round: bytes(row["round"].as_str().unwrap()).try_into().unwrap(),
            request_nonce: bytes(row["request_nonce"].as_str().unwrap())
                .try_into()
                .unwrap(),
            sequence: row["sequence"].as_u64().unwrap() as u32,
            kind: if row["kind"] == 0 {
                RequestKind::Request
            } else {
                RequestKind::Response
            },
        };
        let plan =
            TcpFramePlan::new(flow(), key, row["payload_bytes"].as_u64().unwrap() as u16).unwrap();
        let wire = bytes(row["wire"].as_str().unwrap());
        assert_eq!(&plan.wire[..plan.wire_len], wire);
        let packet = bytes(row["ipv4_packet"].as_str().unwrap());
        let parsed = parse_tcp_segment(&packet).unwrap();
        assert_eq!(parsed.flow, flow());
        assert_eq!(
            parsed.sequence,
            row["first_tcp_sequence"].as_u64().unwrap() as u32
        );
        assert_eq!(parsed.payload, wire);
        let now = Instant::now();
        let mut coverage =
            TcpFrameCoverage::new(plan, parsed.sequence, now, now + Duration::from_secs(1))
                .unwrap();
        assert_eq!(
            coverage.observe(&parsed, now),
            TcpCoverageResult::Added(wire.len())
        );
        assert!(coverage.is_complete());
    }
}

#[test]
fn out_of_order_segments_retransmissions_and_overlap_cover_each_byte_once() {
    let now = Instant::now();
    let mut coverage = coverage(1000, now);
    let wire = coverage.plan.wire[..coverage.plan.wire_len].to_vec();
    assert_eq!(
        coverage.observe(&segment(1080, &wire[80..]), now),
        TcpCoverageResult::Added(115)
    );
    assert!(!coverage.is_complete());
    assert_eq!(
        coverage.observe(&segment(1080, &wire[80..]), now),
        TcpCoverageResult::Retransmission
    );
    assert_eq!(
        coverage.observe(&segment(1000, &wire[..100]), now),
        TcpCoverageResult::Added(80)
    );
    assert!(coverage.is_complete());
    assert_eq!(coverage.covered, wire.len());
}

#[test]
fn sequence_wrap_and_neighboring_frame_bytes_are_clipped_to_this_frame() {
    let now = Instant::now();
    let first = u32::MAX - 15;
    let mut coverage = coverage(first, now);
    let wire = coverage.plan.wire[..coverage.plan.wire_len].to_vec();
    let mut before = vec![0xcc; 8];
    before.extend_from_slice(&wire[..100]);
    assert_eq!(
        coverage.matching_span(&segment(first.wrapping_sub(8), &before)),
        Some((0, 100))
    );
    assert_eq!(
        coverage.observe(&segment(first.wrapping_sub(8), &before), now),
        TcpCoverageResult::Added(100)
    );
    let mut after = wire[80..].to_vec();
    after.extend_from_slice(&[0xdd; 10]);
    assert_eq!(
        coverage.matching_span(&segment(first.wrapping_add(80), &after)),
        Some((80, 195))
    );
    assert_eq!(
        coverage.observe(&segment(first.wrapping_add(80), &after), now),
        TcpCoverageResult::Added(95)
    );
    assert!(coverage.is_complete());
    assert_eq!(coverage.covered, 195);
}

#[test]
fn a_conflicting_retransmission_invalidates_the_frame_without_repair() {
    let now = Instant::now();
    let mut coverage = coverage(1000, now);
    let wire = coverage.plan.wire[..coverage.plan.wire_len].to_vec();
    assert_eq!(
        coverage.observe(&segment(1000, &wire[..100]), now),
        TcpCoverageResult::Added(100)
    );
    let mut changed = wire.clone();
    changed[10] ^= 1;
    assert_eq!(coverage.matching_span(&segment(1000, &changed)), None);
    assert_eq!(
        coverage.observe(&segment(1000, &changed), now),
        TcpCoverageResult::Conflict
    );
    assert_eq!(coverage.covered, 100);
    assert_eq!(
        coverage.observe(&segment(1000, &wire), now),
        TcpCoverageResult::Invalidated
    );
    assert!(!coverage.is_complete());
    assert_eq!(coverage.matching_span(&segment(1000, &wire)), None);
}

#[test]
fn full_nonce_tails_sequence_and_direction_are_not_interchangeable() {
    let plan = TcpFramePlan::new(flow(), key(), 128).unwrap();
    for field in 0..5 {
        let mut other = key();
        match field {
            0 => other.run[15] ^= 1,
            1 => other.round[15] ^= 1,
            2 => other.request_nonce[15] ^= 1,
            3 => other.sequence ^= 1,
            _ => other.kind = RequestKind::Response,
        }
        let different = TcpFramePlan::new(flow(), other, 128).unwrap();
        assert_ne!(different.wire, plan.wire);
        let now = Instant::now();
        let mut coverage = coverage(1000, now);
        assert_eq!(
            coverage.observe(&segment(1000, &different.wire[..different.wire_len]), now),
            TcpCoverageResult::Conflict
        );
        assert!(!coverage.is_complete());
    }
}

#[test]
fn pure_ack_syn_and_reset_do_not_count_as_application_bytes() {
    let now = Instant::now();
    let mut coverage = coverage(1000, now);
    let wire = coverage.plan.wire[..coverage.plan.wire_len].to_vec();
    for flags in [0x10, 0x11] {
        let mut packet = segment(1000, &[]);
        packet.flags = flags;
        assert_eq!(
            coverage.observe(&packet, now),
            TcpCoverageResult::ControlOnly
        );
    }
    for flags in [0x02, 0x04, 0x12] {
        let mut packet = segment(1000, &wire);
        packet.flags = flags;
        assert_eq!(
            coverage.observe(&packet, now),
            TcpCoverageResult::ControlOnly
        );
    }
    assert_eq!(coverage.covered, 0);
    let mut packet = segment(1000, &wire);
    packet.flags = 0x11;
    assert_eq!(
        coverage.observe(&packet, now),
        TcpCoverageResult::Added(195)
    );
    assert!(
        coverage.is_complete(),
        "data followed by FIN retains application bytes"
    );
}

#[test]
fn flow_sequence_window_and_original_deadline_reject_unrelated_segments() {
    let now = Instant::now();
    let mut coverage = coverage(1000, now);
    let wire = coverage.plan.wire[..coverage.plan.wire_len].to_vec();
    let mut wrong = segment(1000, &wire);
    wrong.flow.src_port += 1;
    assert_eq!(
        coverage.observe(&wrong, now),
        TcpCoverageResult::FlowMismatch
    );
    assert_eq!(
        coverage.observe(&segment(5000, &wire), now),
        TcpCoverageResult::OutsideFrame
    );
    assert_eq!(
        coverage.observe(&segment(0, &wire), now),
        TcpCoverageResult::OutsideFrame
    );
    assert_eq!(
        coverage.observe(&segment(1000, &wire), now - Duration::from_nanos(1)),
        TcpCoverageResult::BeforeCapture
    );
    assert_eq!(
        coverage.observe(&segment(1000, &wire[..100]), now),
        TcpCoverageResult::Added(100)
    );
    assert_eq!(
        coverage.observe(&segment(1100, &wire[100..]), now + Duration::from_secs(1)),
        TcpCoverageResult::Expired
    );
    assert_eq!(coverage.covered, 100);
    assert!(!coverage.is_complete());
}

#[test]
fn fixed_frame_and_capture_bounds_reject_oversize_invalid_flow_or_deadlines() {
    assert!(TcpFramePlan::new(flow(), key(), 1137).is_some());
    assert!(TcpFramePlan::new(flow(), key(), 1138).is_none());
    assert!(TcpFramePlan::new(flow(), key(), u16::MAX).is_none());
    let mut invalid = flow();
    invalid.src_port = 0;
    assert!(TcpFramePlan::new(invalid, key(), 0).is_none());
    let now = Instant::now();
    for deadline in [
        now,
        now - Duration::from_nanos(1),
        now + Duration::from_secs(MAX_TTL_SECS + 1),
    ] {
        assert!(TcpFrameCoverage::new(
            TcpFramePlan::new(flow(), key(), 0).unwrap(),
            0,
            now,
            deadline
        )
        .is_none());
    }
}

#[test]
fn ip_tcp_parser_rejects_fragmentation_length_and_both_checksum_corruptions() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("tool_vectors.json")).unwrap();
    let original = bytes(document["vectors"][1]["ipv4_packet"].as_str().unwrap());
    for (offset, value, expected) in [
        (9, 17, TcpParseError::NotIpv4Tcp),
        (6, 0x60, TcpParseError::Fragmented),
        (7, 1, TcpParseError::Fragmented),
        (3, 0, TcpParseError::Length),
        (0, 0x44, TcpParseError::Length),
        (24 + 12, 0x40, TcpParseError::Length),
        (24 + 12, 0xf0, TcpParseError::Checksum),
    ] {
        let mut packet = original.clone();
        packet[offset] = value;
        assert!(matches!(parse_tcp_segment(&packet), Err(actual) if actual == expected));
    }
    for offset in [10, 24 + 16, original.len() - 1] {
        let mut packet = original.clone();
        packet[offset] ^= 1;
        assert!(matches!(
            parse_tcp_segment(&packet),
            Err(TcpParseError::Checksum)
        ));
    }
    for length in 0..original.len() {
        assert!(parse_tcp_segment(&original[..length]).is_err());
    }
}
