//! A real Relay REQUEST may still need its original return after Direct wins.
use super::*;
use crate::peer::ActiveBusinessPath;

fn current_direct(endpoint: &Endpoint) -> bool {
    endpoint
        .peers
        .committed_business_path_snapshot_sync(endpoint.remote_node)
        .is_some_and(|snapshot| matches!(snapshot.active, ActiveBusinessPath::Direct(_)))
}

pub(super) async fn exercise_relay_return(
    a: &mut Endpoint,
    b: &mut Endpoint,
    owners: &mut Owners,
    budget: Budget,
) -> Check {
    let (canonical, routed) = mint_actual(a, budget).await?;
    actual_send(a, routed, PathKind::Relay, budget).await?;
    let received = actual_delivery(b, budget).await?;
    require(
        received.source.as_ref().is_some_and(|source| {
            source.original_relay_read().is_some() && source.original_udp_read().is_none()
        }),
        "actual REQUEST did not arrive on its real Relay reader",
    )?;
    let echo = inject_actual_echo(b, received, budget).await?;
    let a_udp = a.local_udp().await?.ok_or("actual A UDP missing")?;
    let b_udp = b.local_udp().await?.ok_or("actual B UDP missing")?;
    for (endpoint, remote) in [(&*a, b_udp), (&*b, a_udp)] {
        budget
            .step(
                "register actual encrypted validation candidate",
                endpoint.peers.add_candidates_with_sources(
                    endpoint.remote_node,
                    &[remote.to_string()],
                    &HashMap::from([(remote.to_string(), "srflx".to_string())]),
                ),
            )
            .await?;
    }
    asymmetric_endpoint::start_actual_validator(b, a_udp, owners, budget).await?;
    asymmetric_endpoint::start_actual_validator(a, b_udp, owners, budget).await?;
    asymmetric_endpoint::start_actual_dpl(a, owners, budget).await?;
    asymmetric_endpoint::start_actual_dpl(b, owners, budget).await?;
    asymmetric_endpoint::require_real_budget(a, budget).await?;
    asymmetric_endpoint::require_real_budget(b, budget).await?;
    require(
        current_direct(a) && current_direct(b),
        "real encrypted validation did not commit both Direct owners",
    )?;
    let selection = budget
        .step(
            "original generic selector now prefers real Direct",
            b.peers.select_path_for_data_with_local_endpoint_in_epoch(
                b.remote_node,
                true,
                true,
                Some(b_udp),
                b.peers.current_network_generation_sync(),
                false,
            ),
        )
        .await?;
    require(
        selection.path == Some(NetworkPath::Direct) && selection.direct_confirmed,
        "original selector did not actually reach the Direct transition",
    )?;
    let original_relay = budget
        .step("withdraw original Relay publication", b.relay.write())
        .await?
        .take()
        .ok_or("actual original Relay publication missing")?;
    let rejected = budget
        .step(
            "original echo must not borrow healthy Direct after Relay withdrawal",
            crate::network_outbound::send_original_for_test(
                echo.clone(),
                &b.wireguard,
                &b.peers,
                b.peers.current_network_generation_sync(),
                true,
                &b.udp,
                &b.relay,
                true,
            ),
        )
        .await?;
    require(
        !rejected && !canonical.native_ack_credited_for_test(),
        "withdrawn original Relay source borrowed another live path",
    )?;
    *budget
        .step("restore same owned Relay publication", b.relay.write())
        .await? = Some(original_relay);
    let sent = budget
        .step(
            "send held original Relay echo after real Direct promotion",
            crate::network_outbound::send_original_for_test(
                echo.clone(),
                &b.wireguard,
                &b.peers,
                b.peers.current_network_generation_sync(),
                true,
                &b.udp,
                &b.relay,
                true,
            ),
        )
        .await?;
    require(
        sent,
        "actual Relay-sourced echo was misrouted after real Direct promotion",
    )?;
    let ack = actual_delivery(a, budget).await?;
    require(
        ack.source
            .as_ref()
            .is_some_and(|source| source.original_relay_read().is_some()),
        "actual original echo returned through a different transport",
    )?;
    native_fresh(a, &canonical, ack, PathKind::Relay, budget).await?;
    let before = (a.stats.received_valid, a.stats.verified_round_trips);
    let duplicate = repeat_actual_echo(a, b, echo, PathKind::Relay, budget).await?;
    native_handler(a, duplicate, budget).await?;
    require(
        before == (1, 1) && before == (a.stats.received_valid, a.stats.verified_round_trips),
        "actual duplicate original echo changed native once",
    )?;
    require(
        current_direct(a) && current_direct(b),
        "original Relay echo downgraded the actual Direct owners",
    )
}
