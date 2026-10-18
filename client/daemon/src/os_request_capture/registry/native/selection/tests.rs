//! Pure phase/range controls; no KernelRead, Full, socket or owner is created.
use super::*;
use crate::os_request_capture::plan::RegistrationPlan;
use serde_json::json;

fn plan() -> RegisteredFlowPlan {
    let value = json!({"schema_version":1,"capture_id":"11".repeat(16),"producer_scope":"22".repeat(16),"flows":[{
        "protocol":"tcp","kind":"request","peer_id":"selection-peer","run_nonce":"33".repeat(16),"round_nonce":"44".repeat(16),
        "bind_ip":"10.21.1.2","bind_port":32123,"target_ip":"10.21.1.3","target_port":43210,"payload_bytes":128,"request_nonces":["55".repeat(16)]}]});
    RegistrationPlan::decode(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .flows
        .remove(0)
}

#[test]
fn original_read_selection_cannot_replace_an_unresolved_earlier_producer() {
    let spans = [full::ReadFrameSpan::new(0, 0, 195)];
    for phase in [
        PhysicalPublicationState::Idle,
        PhysicalPublicationState::Open,
        PhysicalPublicationState::Publishing,
        PhysicalPublicationState::Recorded,
    ] {
        assert!(matches!(
            select(
                &plan(),
                0,
                [
                    (0, spans.as_slice(), phase, false),
                    (
                        1,
                        spans.as_slice(),
                        PhysicalPublicationState::Recorded,
                        true
                    )
                ]
                .into_iter()
            ),
            Ok(None)
        ));
    }
}

#[test]
fn original_read_selection_unknown_is_terminal_and_definite_nondelivery_can_be_skipped() {
    let spans = [full::ReadFrameSpan::new(0, 0, 195)];
    for phase in [
        PhysicalPublicationState::CancelledOrUncertain,
        PhysicalPublicationState::MetadataFailed,
        PhysicalPublicationState::Exhausted,
    ] {
        assert!(select(
            &plan(),
            0,
            [
                (0, spans.as_slice(), phase, false),
                (
                    1,
                    spans.as_slice(),
                    PhysicalPublicationState::Recorded,
                    true
                )
            ]
            .into_iter()
        )
        .is_err());
    }
    assert!(
        matches!(select(&plan(),0,[(0,spans.as_slice(),PhysicalPublicationState::DefinitelyNotHanded,false),(1,spans.as_slice(),PhysicalPublicationState::Recorded,true)].into_iter()),Ok(Some(indices)) if indices.selected==[1] && indices.skipped==[0])
    );
}

#[test]
fn original_read_selection_keeps_earliest_partial_contributors_and_rejects_a_hole() {
    let first = [full::ReadFrameSpan::new(0, 0, 100)];
    let overlapping = [full::ReadFrameSpan::new(0, 50, 195)];
    let later = [full::ReadFrameSpan::new(0, 0, 195)];
    let packets = [
        (
            0,
            first.as_slice(),
            PhysicalPublicationState::Recorded,
            true,
        ),
        (
            1,
            overlapping.as_slice(),
            PhysicalPublicationState::Recorded,
            true,
        ),
        (
            2,
            later.as_slice(),
            PhysicalPublicationState::Recorded,
            true,
        ),
    ];
    assert!(
        matches!(select(&plan(),0,packets.into_iter()),Ok(Some(indices)) if indices.selected==[0,1] && indices.skipped.is_empty())
    );
    let last = [full::ReadFrameSpan::new(0, 101, 195)];
    assert!(matches!(
        select(
            &plan(),
            0,
            [
                (
                    0,
                    first.as_slice(),
                    PhysicalPublicationState::Recorded,
                    true
                ),
                (1, last.as_slice(), PhysicalPublicationState::Recorded, true)
            ]
            .into_iter()
        ),
        Ok(None)
    ));
    let wrong = [full::ReadFrameSpan::new(0, 0, 196)];
    assert!(select(
        &plan(),
        0,
        [(
            0,
            wrong.as_slice(),
            PhysicalPublicationState::Recorded,
            true
        )]
        .into_iter()
    )
    .is_err());
}

#[test]
fn original_read_selection_bounds_even_noncontributing_metadata() {
    let none: [full::ReadFrameSpan; 0] = [];
    assert!(select(
        &plan(),
        0,
        (0..=full::MAX_FULL_PACKETS).map(|index| (
            index,
            none.as_slice(),
            PhysicalPublicationState::Idle,
            false
        ))
    )
    .is_err());
}
