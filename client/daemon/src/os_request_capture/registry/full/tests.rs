//! Pure coverage controls only; no SystemTun read/write or owner is minted.
use super::*;
use crate::os_request_capture::plan::RegistrationPlan;
use serde_json::json;

fn plan(protocol: &str, count: usize) -> RegisteredFlowPlan {
    let value = json!({"schema_version":1,"capture_id":"11111111111111111111111111111111",
        "producer_scope":"22222222222222222222222222222222","flows":[{
            "protocol":protocol,"kind":"response","peer_id":"frame-span-peer",
            "run_nonce":"33333333333333333333333333333333","round_nonce":"44444444444444444444444444444444",
            "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,"payload_bytes":128,
            "request_nonces":(1..=count).map(|n| format!("{n:032x}")).collect::<Vec<_>>()}]});
    RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .flows
        .remove(0)
}

#[test]
fn original_frame_spans_accumulate_split_coalesced_and_duplicate_ranges() {
    let plan = plan("tcp", 3);
    let mut coverage = FrameSpanCoverage::new(&plan, 1).unwrap();
    assert!(!coverage.add(&ReadFrameSpan::new(0, 0, 195)).unwrap());
    assert!(coverage.add(&ReadFrameSpan::new(1, 100, 195)).unwrap());
    assert!(!coverage.add(&ReadFrameSpan::new(1, 100, 195)).unwrap());
    assert!(!coverage.is_complete());
    assert!(coverage.add(&ReadFrameSpan::new(1, 0, 120)).unwrap());
    assert!(coverage.is_complete());
    assert!(!coverage.add(&ReadFrameSpan::new(2, 0, 195)).unwrap());
    assert!(spans_complete(
        [
            ReadFrameSpan::new(1, 100, 195),
            ReadFrameSpan::new(1, 0, 120)
        ]
        .iter(),
        1,
        &plan
    ));
}

#[test]
fn original_frame_spans_reject_gap_empty_overlong_and_unknown_slot() {
    let plan = plan("tcp", 1);
    let mut coverage = FrameSpanCoverage::new(&plan, 0).unwrap();
    assert!(coverage.add(&ReadFrameSpan::new(0, 0, 194)).unwrap());
    assert!(!coverage.is_complete());
    assert_eq!(
        coverage.add(&ReadFrameSpan::new(0, 0, 0)),
        Err(CaptureFailure::InvalidPlan)
    );
    assert_eq!(
        coverage.add(&ReadFrameSpan::new(0, 190, 196)),
        Err(CaptureFailure::InvalidPlan)
    );
    assert!(FrameSpanCoverage::new(&plan, 1).is_none());
    assert!(!spans_complete(
        [ReadFrameSpan::new(0, 0, 194)].iter(),
        0,
        &plan
    ));
}

#[test]
fn original_frame_spans_keep_udp_slots_distinct_and_bound_tcp_bitmap() {
    let plan = plan("udp", 2);
    let mut coverage = FrameSpanCoverage::new(&plan, 0).unwrap();
    assert!(!coverage.add(&ReadFrameSpan::new(1, 0, 1)).unwrap());
    assert!(!coverage.is_complete());
    assert!(coverage.add(&ReadFrameSpan::new(0, 0, 1)).unwrap());
    assert!(coverage.is_complete());
    assert!(!coverage.add(&ReadFrameSpan::new(0, 0, 1)).unwrap());
    let mut oversized = plan;
    oversized.protocol = Protocol::Tcp;
    oversized.payload_bytes = MAX_FRAME_WIRE_BYTES as u16;
    assert!(FrameSpanCoverage::new(&oversized, 0).is_none());
}
