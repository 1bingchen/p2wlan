//! Original full send/ACK ownership with an actual room permit; MockTun scope only.
use super::*;
use fixture::RoomCase;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_fresh_direct() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Room(RoomCase::Fresh)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_fresh_relay() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Room(RoomCase::Fresh)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_renewed_direct() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Room(RoomCase::Renewed)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_renewed_relay() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Room(RoomCase::Renewed)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_shortened_direct() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Room(RoomCase::Shortened)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_shortened_relay() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Room(RoomCase::Shortened)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_revoked_direct() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Room(RoomCase::Revoked)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_revoked_relay() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Room(RoomCase::Revoked)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_foreignowner_direct() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Room(RoomCase::ForeignOwner)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_foreignowner_relay() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Room(RoomCase::ForeignOwner)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_disabledreplacement_direct() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Room(RoomCase::DisabledReplacement),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_disabledreplacement_relay() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Room(RoomCase::DisabledReplacement),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_contended_direct() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Room(RoomCase::Contended)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_contended_relay() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Room(RoomCase::Contended)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestrenewedafterroute_direct() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Room(RoomCase::RequestRenewedAfterRoute),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestrenewedafterroute_relay() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Room(RoomCase::RequestRenewedAfterRoute),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestshortenedafterroute_direct() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Room(RoomCase::RequestShortenedAfterRoute),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestshortenedafterroute_relay() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Room(RoomCase::RequestShortenedAfterRoute),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestrevokedafterroute_direct() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Room(RoomCase::RequestRevokedAfterRoute),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestrevokedafterroute_relay() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Room(RoomCase::RequestRevokedAfterRoute),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestinitialcontention_direct() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Room(RoomCase::RequestInitialContention),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestinitialcontention_relay() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Room(RoomCase::RequestInitialContention),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestwaitingrevoked_direct() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Room(RoomCase::RequestWaitingRevoked),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestwaitingrevoked_relay() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Room(RoomCase::RequestWaitingRevoked),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestexpiredafterrenewal_direct() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Room(RoomCase::RequestExpiredAfterRenewal),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b01_original_room_requestexpiredafterrenewal_relay() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Room(RoomCase::RequestExpiredAfterRenewal),
    )
    .await
}
