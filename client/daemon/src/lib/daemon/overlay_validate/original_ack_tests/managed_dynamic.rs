//! Distinct real Managed/dynamic extensions. No budget/source/Full is installed
//! by the test; every successful canonical uses the original wire pipeline.
use super::*;
use crate::overlay_requests::{OverlayCreditLockSite as LockSite, OverlayCreditStale as Stale};
#[path = "managed_dynamic/dynamic.rs"]
mod dynamic;
pub(super) use dynamic::{
    close_dynamic_owners, DynamicGuardOwner, DynamicRetiredOwner, DynamicSocketDescriptor,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum PublicationMode {
    ManagedPrimary,
    DynamicLan,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) enum PublicationCase {
    ManagedFresh,
    ManagedBudgetRevoke,
    ManagedContention,
    ManagedQueuedEcho,
    DynamicFresh,
    DynamicDetach,
    DynamicCapacity,
}

pub(super) fn start_original_schedulers(
    udp: crate::udp::UdpTransport,
    peers: Arc<PeerManager>,
    wireguard: WireGuardTransport,
    ingress: crate::DirectValidationIngress,
    vip: &'static str,
    owners: &mut Owners,
) {
    let (stop, stopped) = watch::channel(false);
    owners.readers_stop.push(stop);
    let validation_udp = udp.clone();
    let validation_peers = peers.clone();
    let validation_wg = wireguard.clone();
    owners.spawn_managed_graceful(
        "original validation scheduler and joined children",
        async move {
            crate::run_original_validation_scheduler_until_joined_for_test(
                ingress,
                validation_udp,
                validation_peers,
                validation_wg,
                vip.into(),
                stopped,
            )
            .await
        },
    );
    let (stop, stopped) = watch::channel(false);
    owners.readers_stop.push(stop);
    owners.spawn_managed_graceful("original DPL scheduler and joined children", async move {
        crate::run_dplpmtud_scheduler_until_cancelled(udp, peers, wireguard, stopped).await;
        Ok(())
    });
}

async fn original_udp(
    endpoint: &Endpoint,
    budget: Budget,
) -> Result<crate::udp::UdpTransport, String> {
    budget
        .step("borrow actual UDP owner", endpoint.udp.read())
        .await?
        .as_ref()
        .cloned()
        .ok_or("actual UDP owner absent".into())
}

async fn wait_real_managed(endpoint: &Endpoint, budget: Budget) -> Check {
    let udp = original_udp(endpoint, budget).await?;
    budget
        .step(
            "real validation and DPL wire ACKs publish stable managed budget",
            async {
                loop {
                    let runtime = udp.dplpmtud_runtime();
                    let stable = runtime
                        .snapshot_for_peer(endpoint.remote_node)
                        .is_some_and(|s| s.state == crate::dplpmtud::DplpmtudState::SearchComplete);
                    if stable && udp.direct_business_budget_ready_for_peer(endpoint.remote_node) {
                        return Ok(());
                    }
                    tokio::task::yield_now().await;
                }
            },
        )
        .await?
}

async fn admit_real_managed(a: &Endpoint, b: &Endpoint, budget: Budget) -> Check {
    for (endpoint, other) in [(a, b), (b, a)] {
        let remote = other
            .local_udp()
            .await?
            .ok_or("opposite real UDP missing")?;
        budget
            .step(
                "register actual validation candidate",
                endpoint.peers.add_candidates_with_sources(
                    endpoint.remote_node,
                    &[remote.to_string()],
                    &HashMap::from([(remote.to_string(), "host".to_string())]),
                ),
            )
            .await?;
        let ingress = endpoint
            .validation_ingress
            .as_ref()
            .ok_or("real validation ingress absent")?;
        let admission = ingress.submit(crate::PeerReflexiveObservation {
            peer_id: endpoint.remote_node.into(),
            observed_endpoint: remote,
        });
        require(
            matches!(
                admission,
                crate::udp::DirectValidationAdmission::Queued
                    | crate::udp::DirectValidationAdmission::Coalesced
            ),
            "original validation ingress refused real pair",
        )?;
    }
    wait_real_managed(a, budget).await?;
    wait_real_managed(b, budget).await
}

fn require_actual_managed(request: &CanonicalOverlayRequest, ack: &ActualDelivery) -> Check {
    let record = request
        .physical_publication
        .record()
        .ok_or("actual Full missing")?;
    let tx = record.udp().ok_or("actual UDP Full missing")?;
    require(
        tx.fence() == crate::udp::UdpSendFence::ManagedPublication,
        "managed loop fell back to LAN/LegacyUnknown",
    )?;
    let token = tx
        .original_managed_token()
        .ok_or("actual managed token missing")?;
    let read = ack
        .source
        .as_ref()
        .and_then(|s| s.original_udp_read())
        .ok_or("actual ACK UDP source missing")?;
    require(
        token.udp_publication_owner == read.publication_owner()
            && token.path_identity.socket.socket_index == tx.socket_index()
            && token.path_identity.socket.transport_instance_id == tx.transport_instance()
            && tx.original_direct_commit().is_some(),
        "actual ManagedFull/current reader identities disagree",
    )
}

async fn reject_actual(
    a: &mut Endpoint,
    request: &CanonicalOverlayRequest,
    ack: &ActualDelivery,
    expected: OverlayCreditOutcome,
    budget: Budget,
) -> Check {
    let rounds = a.stats.verified_round_trips;
    let valid = a.stats.received_valid;
    let got = commit(a, request, ack)?;
    require(
        got == expected,
        &format!("actual managed rejection {got:?}; expected {expected:?}"),
    )?;
    native_handler(a, ack.clone(), budget).await?;
    require(
        !request.native_ack_credited_for_test()
            && a.stats.verified_round_trips == rounds
            && a.stats.received_valid == valid,
        "rejected managed ACK polluted native credit",
    )
}

async fn fresh_new(
    a: &mut Endpoint,
    b: &mut Endpoint,
    old: &Arc<CanonicalOverlayRequest>,
    budget: Budget,
) -> Check {
    let (next, _, ack) = original_request_and_echo(a, b, PathKind::Direct, budget).await?;
    require_actual_managed(&next, &ack)?;
    require(
        !Arc::ptr_eq(old, &next) && next.nonce != old.nonce,
        "recovery reused old canonical A",
    )?;
    native_fresh(a, &next, ack, PathKind::Direct, budget).await
}

async fn managed_case(
    a: &mut Endpoint,
    b: &mut Endpoint,
    case: PublicationCase,
    owners: &mut Owners,
    budget: Budget,
) -> Check {
    if case == PublicationCase::ManagedQueuedEcho {
        let (request, routed) = mint_actual(a, budget).await?;
        actual_send(a, routed, PathKind::Direct, budget).await?;
        let received = actual_delivery(b, budget).await?;
        let echo = inject_actual_echo(b, received, budget).await?;
        let old = original_udp(b, budget).await?;
        require(
            old.clear_inbound_publication_owner_if_matches(28002),
            "actual B publication not withdrawn",
        )?;
        let sent = budget
            .step(
                "queued managed echo rechecks original publication",
                crate::network_outbound::send_original_managed_for_test(
                    echo,
                    &b.wireguard,
                    &b.peers,
                    &b.udp,
                    &b.relay,
                ),
            )
            .await?;
        require(
            !sent
                && !request.native_ack_credited_for_test()
                && a.stats.verified_round_trips == 0
                && b.stats.verified_round_trips == 0,
            "withdrawn managed queued echo emitted/granted",
        )?;
        replace_managed_reader(b, owners, budget).await?;
        budget
            .step("retire actual A peer", a.peers.remove_peer(a.remote_node))
            .await?;
        budget
            .step("retire actual B peer", b.peers.remove_peer(b.remote_node))
            .await?;
        let (sa, sb, ak, bk) = session_pair_for(&a.identity, &b.identity)?;
        a.install_peer(bk, b.local_udp().await?, sa, PathKind::Direct, budget)
            .await?;
        b.install_peer(ak, a.local_udp().await?, sb, PathKind::Direct, budget)
            .await?;
        admit_real_managed(a, b, budget).await?;
        return fresh_new(a, b, &request, budget).await;
    }
    let (request, echo, ack) = original_request_and_echo(a, b, PathKind::Direct, budget).await?;
    require_actual_managed(&request, &ack)?;
    let udp = original_udp(a, budget).await?;
    match case {
        PublicationCase::ManagedFresh => {
            native_fresh(a, &request, ack, PathKind::Direct, budget).await?;
            let rounds = a.stats.verified_round_trips;
            let valid = a.stats.received_valid;
            let duplicate = repeat_actual_echo(a, b, echo, PathKind::Direct, budget).await?;
            require(
                commit(a, &request, &duplicate)? == OverlayCreditOutcome::AlreadyCommitted,
                "managed duplicate committed again",
            )?;
            native_handler(a, duplicate, budget).await?;
            require(
                a.stats.verified_round_trips == rounds && a.stats.received_valid == valid,
                "managed duplicate inflated diagnostics",
            )?;
        }
        PublicationCase::ManagedBudgetRevoke => {
            let record = request
                .physical_publication
                .record()
                .ok_or("actual managed Full missing")?;
            let token = record
                .udp()
                .and_then(|f| f.original_managed_token())
                .ok_or("actual original managed token missing")?
                .clone();
            require(
                udp.invalidate_direct_business_budget(&token),
                "original budget revoke not applied",
            )?;
            reject_actual(
                a,
                &request,
                &ack,
                OverlayCreditOutcome::Stale(Stale::DirectPublication),
                budget,
            )
            .await?;
            wait_real_managed(a, budget).await?;
            reject_actual(
                a,
                &request,
                &ack,
                OverlayCreditOutcome::Stale(Stale::DirectPublication),
                budget,
            )
            .await?;
        }
        PublicationCase::ManagedContention => {
            let runtime = udp.dplpmtud_runtime();
            let guard = runtime
                .try_original_business_publication_guard()
                .ok_or("fixture budget guard contended")?;
            let got = commit(a, &request, &ack)?;
            drop(guard);
            require(
                got == OverlayCreditOutcome::Contended(LockSite::DirectPublication)
                    && !request.native_ack_credited_for_test(),
                "managed try conflict consumed once/changed outcome",
            )?;
            require(
                a.wireguard
                    .try_acquire_outbound_emit_guard(a.remote_node)
                    .is_some()
                    && a.peers.network_epoch_gate().try_lock_owned().is_ok(),
                "managed conflict leaked guards",
            )?;
            native_fresh(a, &request, ack, PathKind::Direct, budget).await?;
        }
        _ => return Err("wrong managed control".into()),
    }
    fresh_new(a, b, &request, budget).await
}

async fn replace_managed_reader(b: &mut Endpoint, owners: &mut Owners, budget: Budget) -> Check {
    let ingress = crate::DirectValidationIngress::with_peer_manager(b.peers.clone());
    let trigger = ingress.clone();
    let udp = budget
        .step(
            "bind actual replacement managed UDP",
            crate::udp::UdpTransport::bind(
                "127.0.0.1:0"
                    .parse()
                    .map_err(|e: std::net::AddrParseError| e.to_string())?,
                b.peers.clone(),
            ),
        )
        .await?
        .map_err(|e| e.to_string())?
        .with_inbound_channel(b.encrypted.clone())
        .with_local_node_id(b.node)
        .with_wireguard_transport(b.wireguard.clone())
        .with_dplpmtud_local_virtual_ip(
            b.vip
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?,
        )
        .with_validation_admission_trigger(Arc::new(move |o| trigger.submit(o)));
    udp.set_inbound_publication_owner(28012);
    *budget
        .step("publish actual replacement UDP slot", b.udp.write())
        .await? = Some(udp.clone());
    b._udp_publication.send_replace(Some(udp.clone()));
    b.validation_ingress = Some(ingress.clone());
    start_original_schedulers(
        udp.clone(),
        b.peers.clone(),
        b.wireguard.clone(),
        ingress,
        b.vip,
        owners,
    );
    let (stop, stopped) = watch::channel(false);
    owners.readers_stop.push(stop);
    let encrypted = b.encrypted.clone();
    owners.spawn("actual replacement managed single reader", async move {
        udp.run_original_reader_until_for_test(encrypted, stopped)
            .await
            .map_err(|e| e.to_string())
    });
    Ok(())
}

pub(in super::super) async fn exercise_publication(
    mode: PublicationMode,
    case: PublicationCase,
) -> Check {
    let budget = Budget::new();
    let mut owners = Owners::default();
    let body = AssertUnwindSafe(tokio::time::timeout_at(budget.body_end(), async {
        let mut a = Endpoint::create_with_publication(
            NODE_A,
            VIP_A,
            NODE_B,
            VIP_B,
            PathKind::Direct,
            None,
            &mut owners,
            budget,
            Some(mode),
            false,
        )
        .await?;
        let mut b = Endpoint::create_with_publication(
            NODE_B,
            VIP_B,
            NODE_A,
            VIP_A,
            PathKind::Direct,
            None,
            &mut owners,
            budget,
            Some(mode),
            false,
        )
        .await?;
        let (sa, sb, ak, bk) = session_pair_for(&a.identity, &b.identity)?;
        a.install_peer(bk, b.local_udp().await?, sa, PathKind::Direct, budget)
            .await?;
        b.install_peer(ak, a.local_udp().await?, sb, PathKind::Direct, budget)
            .await?;
        match mode {
            PublicationMode::ManagedPrimary => {
                admit_real_managed(&a, &b, budget).await?;
                managed_case(&mut a, &mut b, case, &mut owners, budget).await
            }
            PublicationMode::DynamicLan => {
                dynamic::admit_pair(&mut a, &mut b, &mut owners, budget).await?;
                dynamic::exercise_dynamic(&mut a, &mut b, case, &mut owners, budget).await
            }
        }
    }))
    .catch_unwind()
    .await;
    let cleanup = owners.close(budget).await;
    if cleanup.is_ok() {
        eprintln!("b28_publication_owned_cleanup_complete: regular_joined={}/{} scheduler_joined={}/{} dynamic_attach_slots_completed={} retired_reader_slots_completed={} original_end_unchanged=true",
            owners.tasks.iter().filter(|task| task.handle.is_none()).count(), owners.tasks.len(),
            owners.graceful_tasks.iter().filter(|task| task.handle.is_none()).count(), owners.graceful_tasks.len(),
            owners.dynamic_guards.len(), owners.retired_dynamic.len());
    }
    let body = match body {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => Err("managed/dynamic body exceeded unchanged nine-second end".into()),
        Err(panic) => {
            eprintln!("b28_publication_panic_cleanup: cleanup={cleanup:?} regular_remaining={} scheduler_remaining={} original_end_unchanged=true",
                owners.tasks.iter().filter(|t|t.handle.is_some()).count(),owners.graceful_tasks.iter().filter(|t|t.handle.is_some()).count());
            std::panic::resume_unwind(panic)
        }
    };
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(c)) => Err(format!("{e}; cleanup: {c}")),
    }
}
