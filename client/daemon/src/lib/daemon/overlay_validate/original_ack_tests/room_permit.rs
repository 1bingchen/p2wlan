//! Real WG/UDP or Relay originals; MockTun remains explicitly a fixture source.
use super::*;
use crate::overlay_requests::{OverlayCreditLockSite, OverlayCreditStale};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum RoomCase {
    Fresh,
    Renewed,
    Shortened,
    Revoked,
    ForeignOwner,
    DisabledReplacement,
    Contended,
    RequestRenewedAfterRoute,
    RequestShortenedAfterRoute,
    RequestRevokedAfterRoute,
    RequestInitialContention,
    RequestWaitingRevoked,
    RequestExpiredAfterRenewal,
}

pub(super) fn authorization(
    vip: &str,
    remote: &str,
    peer: &str,
) -> Result<Arc<crate::rooms::RoomAuthorization>, String> {
    let room = Arc::new(crate::rooms::RoomAuthorization::new(
        "room-original-native-ack",
    ));
    require(
        room.replace(
            vip,
            [(peer.to_string(), remote.to_string())],
            Instant::now(),
            30,
        ),
        "actual fixture room roster rejected",
    )?;
    Ok(room)
}

pub(super) async fn exercise_room(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: RoomCase,
    budget: Budget,
) -> Check {
    if matches!(
        case,
        RoomCase::RequestRenewedAfterRoute
            | RoomCase::RequestShortenedAfterRoute
            | RoomCase::RequestRevokedAfterRoute
            | RoomCase::RequestInitialContention
            | RoomCase::RequestWaitingRevoked
            | RoomCase::RequestExpiredAfterRenewal
    ) {
        return Box::pin(room_request::exercise_request_room(
            a, b, path, case, budget,
        ))
        .await;
    }
    let (request, _echo, ack) = original_request_and_echo(a, b, path, budget).await?;
    let record = request
        .physical_publication
        .record()
        .ok_or("actual original Full missing")?;
    let original = record
        .room_authorization()
        .ok_or("original route -> encryption -> Full lost room permit")?;
    let at_send = a
        .room
        .send_permit(a.remote_node, a.remote_vip, a.vip)
        .ok_or("actual original roster not current")?;
    require(original == &at_send, "Full replaced original packet permit")?;
    let old_owner = a.room.clone();
    match case {
        RoomCase::Fresh => return native_fresh(a, &request, ack, path, budget).await,
        RoomCase::Renewed => {
            require(
                a.room.replace(
                    a.vip,
                    [(a.remote_node.to_string(), a.remote_vip.to_string())],
                    Instant::now(),
                    30,
                ),
                "renewal failed",
            )?;
            return native_fresh(a, &request, ack, path, budget).await;
        }
        RoomCase::Contended => {
            let result =
                old_owner.with_original_snapshot_held_for_test(|| commit(a, &request, &ack));
            require(
                result? == OverlayCreditOutcome::Contended(OverlayCreditLockSite::RoomAuthority),
                "held actual room snapshot did not return try-only contention",
            )?;
            require(
                !request.native_ack_credited_for_test(),
                "contention consumed original once",
            )?;
            return native_fresh(a, &request, ack, path, budget).await;
        }
        RoomCase::Shortened => {
            require(
                a.room.replace(
                    a.vip,
                    [(a.remote_node.to_string(), a.remote_vip.to_string())],
                    Instant::now(),
                    10,
                ),
                "shortened grant failed",
            )?;
        }
        RoomCase::Revoked => {
            a.room.invalidate();
            require(
                a.room.replace(
                    a.vip,
                    [(a.remote_node.to_string(), a.remote_vip.to_string())],
                    Instant::now(),
                    30,
                ),
                "reauthorization failed",
            )?;
        }
        RoomCase::ForeignOwner => a.room = authorization(a.vip, a.remote_vip, a.remote_node)?,
        RoomCase::DisabledReplacement => {
            a.room = Arc::new(crate::rooms::RoomAuthorization::new("default"))
        }
        _ => return Err("unexpected ACK room case".into()),
    }
    let rounds = a.stats.verified_round_trips;
    let received = a.stats.received_valid;
    require(
        commit(a, &request, &ack)?
            == OverlayCreditOutcome::Stale(OverlayCreditStale::RoomAuthority),
        "stale original room permit gained credit",
    )?;
    native_handler(a, ack, budget).await?;
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == rounds
            && a.stats.received_valid == received,
        "room rejection consumed once or diagnostics",
    )?;
    a.room = old_owner;
    let (next, _echo, next_ack) = original_request_and_echo(a, b, path, budget).await?;
    require(
        !Arc::ptr_eq(&request, &next),
        "later request reused old canonical",
    )?;
    native_fresh(a, &next, next_ack, path, budget).await?;
    require(
        !request.native_ack_credited_for_test(),
        "fresh current request resurrected old room once",
    )
}
