//! Real dynamic sockets in the complete original native ACK pipeline.
use super::*;
use tokio::net::UdpSocket;

pub(in super::super) struct DynamicSocketDescriptor {
    pub(in super::super) socket: Arc<UdpSocket>,
    index: usize,
}
pub(in super::super) struct DynamicGuardOwner {
    transport: crate::udp::UdpTransport,
    index: usize,
    guard: crate::udp::OriginalDynamicAttachForTest,
}
pub(in super::super) struct DynamicRetiredOwner {
    transport: crate::udp::UdpTransport,
    entry: crate::udp::OriginalDynamicRetirementForTest,
}

async fn attach_actual(
    endpoint: &mut Endpoint,
    owners: &mut Owners,
    budget: Budget,
    punch: u64,
) -> Check {
    let udp = original_udp(endpoint, budget).await?;
    let socket = Arc::new(
        budget
            .step("bind actual dynamic socket", UdpSocket::bind("127.0.0.1:0"))
            .await?
            .map_err(|e| e.to_string())?,
    );
    let index = udp.next_dynamic_index();
    let generation = endpoint.peers.current_network_generation_sync();
    owners.dynamic_guards.push(DynamicGuardOwner {
        transport: udp.clone(),
        index,
        guard: Default::default(),
    });
    let owner = &mut owners
        .dynamic_guards
        .last_mut()
        .ok_or("original attach owner slot absent")?
        .guard;
    budget
        .step(
            "attach original dynamic reader/watcher with retained outer owner",
            udp.attach_dynamic_owned_for_test(
                endpoint.remote_node,
                index,
                socket.clone(),
                generation,
                punch,
                None,
                owner,
            ),
        )
        .await?
        .map_err(|e| format!("actual dynamic attach: {e:?}"))?;
    let guard = owners
        .dynamic_guards
        .last()
        .and_then(|owner| owner.guard.original_guard())
        .ok_or("original dynamic guard lost")?;
    require(
        budget
            .step(
                "original dynamic commit and pin",
                guard.commit_and_pin_for_test(&udp, endpoint.remote_node, index, generation, punch),
            )
            .await?,
        "actual dynamic commit refused",
    )?;
    require(
        budget
            .step("original dynamic finalize", guard.finalize())
            .await?,
        "actual dynamic finalize refused",
    )?;
    endpoint.dynamic_publication = Some(DynamicSocketDescriptor { socket, index });
    Ok(())
}

pub(super) async fn admit_pair(
    a: &mut Endpoint,
    b: &mut Endpoint,
    owners: &mut Owners,
    budget: Budget,
) -> Check {
    attach_actual(a, owners, budget, 1).await?;
    attach_actual(b, owners, budget, 1).await?;
    let (sa, sb, ak, bk) = session_pair_for(&a.identity, &b.identity)?;
    a.install_peer(bk, b.local_udp().await?, sa, PathKind::Direct, budget)
        .await?;
    b.install_peer(ak, a.local_udp().await?, sb, PathKind::Direct, budget)
        .await?;
    Ok(())
}

fn require_actual_dynamic(
    a: &Endpoint,
    request: &CanonicalOverlayRequest,
    ack: &ActualDelivery,
) -> Check {
    let descriptor = a
        .dynamic_publication
        .as_ref()
        .ok_or("actual dynamic descriptor missing")?;
    let record = request
        .physical_publication
        .record()
        .ok_or("actual dynamic Full missing")?;
    let tx = record.udp().ok_or("actual dynamic UDP Full missing")?;
    let read = ack
        .source
        .as_ref()
        .and_then(|s| s.original_udp_read())
        .ok_or("actual dynamic ACK reader source absent")?;
    require(
        tx.fence() == crate::udp::UdpSendFence::LanPublication
            && tx.socket_index() == descriptor.index
            && read.socket_index() == descriptor.index
            && read.belongs_to_socket(&descriptor.socket)
            && tx.belongs_to_socket(&descriptor.socket)
            && tx.original_direct_commit().is_some(),
        "dynamic native loop borrowed a primary/fallback or replaced socket",
    )
}

async fn new_dynamic_positive(
    a: &mut Endpoint,
    b: &mut Endpoint,
    old: &Arc<CanonicalOverlayRequest>,
    budget: Budget,
) -> Check {
    let (next, _, ack) = original_request_and_echo(a, b, PathKind::Direct, budget).await?;
    require_actual_dynamic(a, &next, &ack)?;
    require(
        !Arc::ptr_eq(old, &next) && next.nonce != old.nonce,
        "dynamic recovery reused old A",
    )?;
    native_fresh(a, &next, ack, PathKind::Direct, budget).await
}

async fn retire_actual(endpoint: &Endpoint, owners: &mut Owners, budget: Budget) -> Check {
    let descriptor = endpoint
        .dynamic_publication
        .as_ref()
        .ok_or("actual dynamic owner absent")?;
    let udp = original_udp(endpoint, budget).await?;
    let entry = budget
        .step(
            "remove exact original dynamic entry",
            udp.take_original_dynamic_retirement_for_test(descriptor.index),
        )
        .await?
        .ok_or("original dynamic entry already absent")?;
    owners.retired_dynamic.push(DynamicRetiredOwner {
        transport: udp,
        entry,
    });
    let retired = owners
        .retired_dynamic
        .last_mut()
        .ok_or("retired original owner missing")?;
    budget
        .step(
            "original dynamic drain and real reader join",
            retired.entry.stop_and_join(&retired.transport),
        )
        .await?
        .map_err(|e| format!("actual retired reader join: {e}"))?;
    require(
        retired.entry.is_joined(),
        "actual retired reader handle did not join",
    )
}

async fn demote_current_direct(endpoint: &Endpoint, budget: Budget) -> Check {
    let current = budget
        .step(
            "actual current Direct snapshot",
            endpoint.peers.active_direct_path_snapshot(
                endpoint.remote_node,
                endpoint.peers.current_network_generation_sync(),
                true,
            ),
        )
        .await?
        .ok_or("actual Direct snapshot absent")?;
    let local_endpoint = endpoint.local_udp().await?;
    require(
        budget
            .step(
                "original exact Direct failure transition",
                endpoint
                    .peers
                    .record_direct_failure_for_active_path_snapshot(
                        endpoint.remote_node,
                        current,
                        crate::peer::REASON_DIRECT_PROBE_FAILED,
                        "actual_dynamic_detached",
                        local_endpoint,
                    ),
            )
            .await?,
        "original current Direct transition refused",
    )
}

async fn capacity_control(a: &mut Endpoint, owners: &mut Owners, budget: Budget) -> Check {
    let udp = original_udp(a, budget).await?;
    for i in 0..7u64 {
        let peer = format!("original-dynamic-cap-{i}");
        let remote = budget
            .step(
                "bind capacity peer's actual endpoint",
                UdpSocket::bind("127.0.0.1:0"),
            )
            .await?
            .map_err(|e| e.to_string())?;
        let endpoint = remote.local_addr().map_err(|e| e.to_string())?;
        budget
            .step(
                "register original capacity peer",
                a.peers.add_peer(&PeerInfo {
                    node_id: peer.clone(),
                    endpoint: endpoint.to_string(),
                    virtual_ip: String::new(),
                    online: true,
                    ..PeerInfo::default()
                }),
            )
            .await?;
        let socket = Arc::new(
            budget
                .step(
                    "bind actual protected capacity socket",
                    UdpSocket::bind("127.0.0.1:0"),
                )
                .await?
                .map_err(|e| e.to_string())?,
        );
        let index = udp.next_dynamic_index();
        let generation = a.peers.current_network_generation_sync();
        owners.dynamic_guards.push(DynamicGuardOwner {
            transport: udp.clone(),
            index,
            guard: Default::default(),
        });
        let owner = &mut owners
            .dynamic_guards
            .last_mut()
            .ok_or("original capacity owner slot absent")?
            .guard;
        budget
            .step(
                "attach actual capacity socket with original outer owner",
                udp.attach_dynamic_owned_for_test(
                    &peer,
                    index,
                    socket.clone(),
                    generation,
                    1,
                    None,
                    owner,
                ),
            )
            .await?
            .map_err(|e| format!("capacity setup attach: {e:?}"))?;
        let guard = owners
            .dynamic_guards
            .last()
            .and_then(|owner| owner.guard.original_guard())
            .ok_or("actual capacity guard absent")?;
        require(
            budget
                .step(
                    "original capacity commit",
                    guard.commit_and_pin_for_test(&udp, &peer, index, generation, 1),
                )
                .await?,
            "capacity commit refused",
        )?;
        require(
            budget
                .step("original capacity finalize", guard.finalize())
                .await?,
            "capacity finalize refused",
        )?;
        // Genuine original state-owner APIs establish only the cap's Direct
        // nonevictable prerequisite. Empty VIP excludes this non-business
        // filler from the original canonical minter; it is not native ACK proof.
        let local = socket.local_addr().map_err(|e| e.to_string())?;
        budget
            .step(
                "capacity actual host metadata",
                a.peers
                    .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
                        "127.0.0.1"
                            .parse()
                            .map_err(|e: std::net::AddrParseError| e.to_string())?,
                        8,
                    )]),
            )
            .await?;
        budget
            .step(
                "capacity actual host candidate",
                a.peers.add_candidates_with_sources(
                    &peer,
                    &[endpoint.to_string()],
                    &HashMap::from([(endpoint.to_string(), "host".into())]),
                ),
            )
            .await?;
        budget
            .step(
                "original capacity probe state",
                a.peers
                    .record_direct_probe_success_with_latency_and_local_endpoint(
                        &peer,
                        endpoint,
                        Some(Duration::from_millis(1)),
                        Some(local),
                    ),
            )
            .await?;
        budget
            .step(
                "original capacity Direct state",
                a.peers.record_direct_success_with_local_endpoint(
                    &peer,
                    Some(endpoint),
                    Some(local),
                ),
            )
            .await?;
        require(
            a.peers.is_direct_sync(&peer),
            "capacity peer is not actually nonevictable Direct",
        )?;
        require(
            budget
                .step(
                    "exact original dynamic count",
                    udp.original_dynamic_count_for_test(),
                )
                .await?
                == (i + 2) as usize,
            "original cap map count drifted",
        )?;
    }
    require(
        budget
            .step(
                "original fixed capacity eight",
                udp.original_dynamic_count_for_test(),
            )
            .await?
            == 8,
        "original dynamic cap is not eight",
    )?;
    let extra = Arc::new(
        budget
            .step(
                "bind ninth actual capacity candidate",
                UdpSocket::bind("127.0.0.1:0"),
            )
            .await?
            .map_err(|e| e.to_string())?,
    );
    let index = udp.next_dynamic_index();
    owners.dynamic_guards.push(DynamicGuardOwner {
        transport: udp.clone(),
        index,
        guard: Default::default(),
    });
    let owner = &mut owners
        .dynamic_guards
        .last_mut()
        .ok_or("original rejected owner slot absent")?
        .guard;
    let attempted = budget
        .step(
            "actual ninth attach retaining original rejected handles",
            udp.attach_dynamic_owned_for_test(
                a.remote_node,
                index,
                extra,
                a.peers.current_network_generation_sync(),
                2,
                None,
                owner,
            ),
        )
        .await?;
    budget
        .step(
            "actual rejected original reader and watcher joins",
            owner.stop_and_join(&udp),
        )
        .await??;
    require(
        matches!(
            attempted,
            Err(crate::udp::DynamicSocketAttachError::CapacityRejected)
        ),
        "ninth attach evicted a current Direct/predecessor",
    )?;
    require(
        budget
            .step(
                "original count after real capacity rejection",
                udp.original_dynamic_count_for_test(),
            )
            .await?
            == 8,
        "capacity rejection changed the actual map",
    )
}

pub(super) async fn exercise_dynamic(
    a: &mut Endpoint,
    b: &mut Endpoint,
    case: PublicationCase,
    owners: &mut Owners,
    budget: Budget,
) -> Check {
    let retained_original_socket = a
        .dynamic_publication
        .as_ref()
        .ok_or("original dynamic socket absent")?
        .socket
        .clone();
    let (request, _, ack) = original_request_and_echo(a, b, PathKind::Direct, budget).await?;
    require_actual_dynamic(a, &request, &ack)?;
    match case {
        PublicationCase::DynamicFresh => {
            let udp = original_udp(a, budget).await?;
            let got = budget
                .step(
                    "hold real dynamic socket registry for synchronous final",
                    udp.with_original_socket_state_held_for_test(|| commit(a, &request, &ack)),
                )
                .await??;
            require(
                got == OverlayCreditOutcome::Contended(LockSite::DirectSocket)
                    && !request.native_ack_credited_for_test()
                    && a.stats.verified_round_trips == 0,
                "actual dynamic socket conflict changed outcome/once",
            )?;
            require(
                a.wireguard
                    .try_acquire_outbound_emit_guard(a.remote_node)
                    .is_some()
                    && a.peers.network_epoch_gate().try_lock_owned().is_ok(),
                "dynamic conflict leaked original guards",
            )?;
            native_fresh(a, &request, ack, PathKind::Direct, budget).await?;
        }
        PublicationCase::DynamicDetach => {
            let old = a
                .dynamic_publication
                .take()
                .ok_or("actual old dynamic socket absent")?;
            // Retain its real Arc across detach/recovery, without rebinding the
            // immutable original source. The registry remains sole authority.
            a.dynamic_publication = Some(old);
            retire_actual(a, owners, budget).await?;
            reject_actual(
                a,
                &request,
                &ack,
                OverlayCreditOutcome::Stale(Stale::DirectPublication),
                budget,
            )
            .await?;
            demote_current_direct(a, budget).await?;
            demote_current_direct(b, budget).await?;
            attach_actual(a, owners, budget, 2).await?;
            let (sa, sb, ak, bk) = session_pair_for(&a.identity, &b.identity)?;
            a.install_peer(bk, b.local_udp().await?, sa, PathKind::Direct, budget)
                .await?;
            b.install_peer(ak, a.local_udp().await?, sb, PathKind::Direct, budget)
                .await?;
        }
        PublicationCase::DynamicCapacity => {
            capacity_control(a, owners, budget).await?;
            native_fresh(a, &request, ack, PathKind::Direct, budget).await?;
        }
        _ => return Err("wrong dynamic control".into()),
    }
    let result = new_dynamic_positive(a, b, &request, budget).await;
    // Keep the retired actual Arc live through the new complete roundtrip.
    drop(retained_original_socket);
    result
}

pub(in super::super) async fn close_dynamic_owners(owners: &mut Owners, budget: Budget) -> Check {
    let mut failures = Vec::new();
    for dynamic in &mut owners.dynamic_guards {
        match tokio::time::timeout_at(budget.end, dynamic.guard.stop_and_join(&dynamic.transport))
            .await
        {
            Ok(Ok(())) => {}
            other => failures.push(format!("original watcher join: {other:?}")),
        }
        if !dynamic.guard.is_joined() {
            failures.push("original watcher did not observe actual join".into());
        }
        let removed = tokio::time::timeout_at(
            budget.end,
            dynamic
                .transport
                .take_original_dynamic_retirement_for_test(dynamic.index),
        )
        .await;
        match removed {
            Ok(Some(entry)) => owners.retired_dynamic.push(DynamicRetiredOwner {
                transport: dynamic.transport.clone(),
                entry,
            }),
            Ok(None) => {}
            Err(_) => failures.push("original dynamic removal exceeded unchanged end".into()),
        }
    }
    for retired in &mut owners.retired_dynamic {
        match tokio::time::timeout_at(budget.end, retired.entry.stop_and_join(&retired.transport))
            .await
        {
            Ok(Ok(())) => {}
            other => failures.push(format!("original retired reader join: {other:?}")),
        }
    }
    if owners
        .retired_dynamic
        .iter()
        .any(|owner| !owner.entry.is_joined())
    {
        failures.push("original retired reader handle remains unjoined".into());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
