//! Original room REQUEST authorization survives its existing waits and queues.
use super::*;
use crate::overlay_requests::{OverlayCreditLockSite, OverlayCreditStale};

pub(super) async fn exercise_request_room(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    case: RoomCase,
    budget: Budget,
) -> Check {
    let expiring = Instant::now();
    if case == RoomCase::RequestExpiredAfterRenewal {
        require(
            b.room.replace(
                b.vip,
                [(b.remote_node.to_string(), b.remote_vip.to_string())],
                expiring,
                3,
            ),
            "initial three-second room grant failed",
        )?;
    }
    let owners_before = Arc::strong_count(&b.room);
    let (request, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, path, budget).await?;
    let received = actual_delivery(b, budget).await?;
    if case == RoomCase::RequestInitialContention {
        let room = b.room.clone();
        let result = room.with_original_snapshot_held_for_test(|| {
            call_native_request(b, received, budget).now_or_never()
        });
        let result = result.ok_or("original room capture waited on its mutex")??;
        require(
            result
                == OriginalRequestEchoOutcome::Rejected(OverlayCreditOutcome::Contended(
                    OverlayCreditLockSite::RoomAuthority,
                )),
            "initial room contention did not fail closed",
        )?;
    } else if case == RoomCase::RequestWaitingRevoked {
        let peers = b.peers.clone();
        let room = b.room.clone();
        let vip = b.vip;
        let peer = b.remote_node;
        let remote = b.remote_vip;
        let held = budget
            .step(
                "hold original REQUEST connection owner",
                peers.hold_connections_writer_for_test(),
            )
            .await?;
        let (result, changed) = tokio::join!(call_native_request(b, received, budget), async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            room.invalidate();
            let changed = room.replace(
                vip,
                [(peer.to_string(), remote.to_string())],
                Instant::now(),
                30,
            );
            drop(held);
            changed
        });
        require(changed, "waiting room reauthorization failed")?;
        require(
            result?
                == OriginalRequestEchoOutcome::Rejected(OverlayCreditOutcome::Stale(
                    OverlayCreditStale::RoomAuthority,
                )),
            "waiting REQUEST borrowed reauthorization",
        )?;
    } else {
        let echo = inject_actual_echo(b, received, budget).await?;
        require(
            Arc::strong_count(&b.room) == owners_before,
            "sealed original input kept its room owner alive",
        )?;
        let input = echo
            .original_echo()
            .ok_or("original room echo source missing")?;
        let original = echo
            .room_authorization
            .as_ref()
            .ok_or("routed room echo lost original permit")?
            .clone();
        require(
            input.room_authorization() == Some(&original),
            "route substituted a later permit",
        )?;
        match case {
            RoomCase::RequestRenewedAfterRoute | RoomCase::RequestExpiredAfterRenewal => {
                require(
                    b.room.replace(
                        b.vip,
                        [(b.remote_node.to_string(), b.remote_vip.to_string())],
                        Instant::now(),
                        30,
                    ),
                    "room renewal failed",
                )?;
                let fresh = b
                    .room
                    .send_permit(b.remote_node, b.remote_vip, b.vip)
                    .ok_or("renewed permit missing")?;
                require(
                    original != fresh,
                    "renewal did not establish a distinct later deadline",
                )?;
                let mut changed = echo.clone();
                changed.room_authorization = Some(fresh);
                echo_transfer::rejected_original_send(b, changed, path, budget).await?;
                if case == RoomCase::RequestRenewedAfterRoute {
                    actual_send(b, echo, path, budget).await?;
                    let ack = actual_delivery(a, budget).await?;
                    return native_fresh(a, &request, ack, path, budget).await;
                }
                // Use the original fixture body end; never refill a request or
                // lease deadline. This controlled original grant expires at 3s.
                tokio::time::timeout_at(
                    budget.body_end(),
                    tokio::time::sleep_until(tokio::time::Instant::from_std(
                        expiring + Duration::from_secs(3),
                    )),
                )
                .await
                .map_err(|_| "original room-expiry fixture body end")?;
            }
            RoomCase::RequestShortenedAfterRoute => require(
                b.room.replace(
                    b.vip,
                    [(b.remote_node.to_string(), b.remote_vip.to_string())],
                    Instant::now(),
                    10,
                ),
                "shortened room grant failed",
            )?,
            RoomCase::RequestRevokedAfterRoute => {
                b.room.invalidate();
                require(
                    b.room.replace(
                        b.vip,
                        [(b.remote_node.to_string(), b.remote_vip.to_string())],
                        Instant::now(),
                        30,
                    ),
                    "room reauthorization failed",
                )?;
            }
            _ => return Err("unexpected room REQUEST case".into()),
        }
        echo_transfer::rejected_original_send(b, echo, path, budget).await?;
    }
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == 0
            && b.stats.verified_round_trips == 0,
        "rejected original room REQUEST gained roundtrip credit",
    )?;
    require(
        matches!(a.overlay.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "rejected original room echo produced an authenticated ACK",
    )?;
    require(
        matches!(b.routed.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "rejected original room REQUEST left another routed echo",
    )?;
    lifecycle::new_actual_positive(a, b, &request, path, budget).await
}
