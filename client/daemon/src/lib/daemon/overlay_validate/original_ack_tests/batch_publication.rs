//! Real wire facts exercise batched owner guards. These canonical fixtures do
//! not construct a kernel frame or claim any system-TUN/OS-write positive.
use super::*;

pub(super) async fn exercise_batch(
    a: &mut Endpoint,
    b: &mut Endpoint,
    path: PathKind,
    budget: Budget,
) -> Check {
    let (first, _, ack_a) = original_request_and_echo(a, b, path, budget).await?;
    let (foreign, _, ack_b) = original_request_and_echo(b, a, path, budget).await?;
    let first = first
        .physical_publication
        .record()
        .ok_or("actual first Full missing")?;
    let foreign = foreign
        .physical_publication
        .record()
        .ok_or("actual foreign Full missing")?;
    let source = ack_a
        .source
        .as_ref()
        .ok_or("actual first original source missing")?;
    let other = ack_b
        .source
        .as_ref()
        .ok_or("actual foreign original source missing")?;
    let _emit = budget
        .step(
            "actual batch emit guard",
            a.wireguard.acquire_outbound_emit_guard(a.remote_node),
        )
        .await?;
    let epoch = a.peers.network_epoch_gate();
    let _epoch = budget.step("actual batch epoch", epoch.lock()).await?;
    match path {
        PathKind::Direct => {
            let slot = a.udp.try_read().map_err(|e| e.to_string())?;
            let udp = slot.as_ref().ok_or("actual UDP absent")?;
            let tx = first.udp().ok_or("actual first UDP Full absent")?;
            let bad_tx = foreign.udp().ok_or("actual foreign UDP Full absent")?;
            let rx = source
                .original_udp_read()
                .ok_or("actual first UDP reader absent")?;
            let bad_rx = other
                .original_udp_read()
                .ok_or("actual foreign UDP reader absent")?;
            let generation = a.peers.current_network_generation_sync();
            let guard = udp
                .try_original_direct_publication_batch_guard(
                    a.remote_node,
                    generation,
                    &[rx, rx],
                    &[tx, tx],
                )
                .map_err(|e| format!("same actual publication batch: {e:?}"))?;
            drop(guard);
            require(
                matches!(
                    udp.try_original_direct_publication_batch_guard(
                        a.remote_node,
                        generation,
                        &[rx],
                        &[tx, bad_tx]
                    ),
                    Err(crate::udp::DirectOriginFailure::Stale)
                ),
                "batch accepted a genuine foreign final TX fact",
            )?;
            require(
                matches!(
                    udp.try_original_direct_publication_batch_guard(
                        a.remote_node,
                        generation,
                        &[rx, bad_rx],
                        &[tx]
                    ),
                    Err(crate::udp::DirectOriginFailure::Stale)
                ),
                "batch accepted a genuine foreign final RX fact",
            )?;
        }
        PathKind::Relay => {
            let slot = a.relay.try_read().map_err(|e| e.to_string())?;
            let relay = slot.as_ref().ok_or("actual Relay absent")?;
            let tx = first.relay().ok_or("actual first Relay Full absent")?;
            let bad_tx = foreign.relay().ok_or("actual foreign Relay Full absent")?;
            let rx = source
                .original_relay_read()
                .ok_or("actual first Relay reader absent")?;
            let bad_rx = other
                .original_relay_read()
                .ok_or("actual foreign Relay reader absent")?;
            let id = source
                .relay_connection_id()
                .ok_or("actual first Relay envelope id absent")?;
            let bad_id = other
                .relay_connection_id()
                .ok_or("actual foreign Relay envelope id absent")?;
            let guard = relay
                .try_original_member_guard(tx, rx, id)
                .map_err(|e| format!("actual Relay member: {e:?}"))?;
            let _open = guard
                .try_open_guard()
                .map_err(|e| format!("actual Relay close: {e:?}"))?;
            guard
                .matches_original_fragment(tx, rx, id)
                .map_err(|e| format!("same actual Relay fragment: {e:?}"))?;
            require(
                guard.matches_original_fragment(bad_tx, rx, id).is_err(),
                "batch accepted a genuine foreign final Relay TX",
            )?;
            require(
                guard.matches_original_fragment(tx, bad_rx, bad_id).is_err(),
                "batch accepted a genuine foreign final Relay RX",
            )?;
        }
    }
    Ok(())
}
