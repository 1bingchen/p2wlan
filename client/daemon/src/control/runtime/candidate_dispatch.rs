/// The router may retain exactly one prepaid HH command while its existing
/// per-peer lane is full. This future is polled by the router (no task spawn);
/// candidate intake pauses while answer/offer/control/shutdown lanes continue.
type CandidateQueueReservation =
    std::pin::Pin<Box<dyn std::future::Future<Output = Option<CandidateOfferCommand>> + Send>>;

struct CandidateOfferLane {
    sender: mpsc::Sender<CandidateOfferCommand>,
    task_id: tokio::task::Id,
}

struct CandidateDispatchCommand {
    command: CandidateOfferCommand,
    closed_retries_remaining: u8,
}

impl CandidateDispatchCommand {
    fn new(command: CandidateOfferCommand) -> Self {
        Self {
            command,
            closed_retries_remaining: 1,
        }
    }
}

/// The router owns one waiting command OR one queue reservation, never both.
/// Closed lanes remain in the task map until their accepted FIFO is drained.
enum PendingCandidateDispatch {
    Queue {
        reservation: CandidateQueueReservation,
        closed_retries_remaining: u8,
    },
    Lane {
        command: Option<CandidateDispatchCommand>,
        deadline: Instant,
        auth: Option<CriticalControlAuth>,
    },
}

impl PendingCandidateDispatch {
    fn wait_for_lane(
        command: CandidateDispatchCommand,
        auth_rx: &watch::Receiver<Option<CriticalControlAuth>>,
    ) -> Self {
        Self::Lane {
            deadline: command
                .command
                .not_after
                .unwrap_or_else(|| Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE),
            command: Some(command),
            auth: auth_rx.borrow().clone(),
        }
    }

    fn wait_for_closed_lane(
        mut command: CandidateDispatchCommand,
        auth_rx: &watch::Receiver<Option<CriticalControlAuth>>,
    ) -> Option<Self> {
        if command.closed_retries_remaining == 0 {
            warn!(peer_id = %command.command.to_node_id, reason_code = "candidate_offer_worker_recreate_failed", "Replacement candidate worker closed");
            let _ = command
                .command
                .response_tx
                .send(PeerOfferSendOutcome::Failed);
            return None;
        }
        command.closed_retries_remaining -= 1;
        Some(Self::wait_for_lane(command, auth_rx))
    }

    fn take_ready_lane_command(
        &mut self,
        lanes: &HashMap<String, CandidateOfferLane>,
        auth_rx: &watch::Receiver<Option<CriticalControlAuth>>,
    ) -> Option<CandidateDispatchCommand> {
        let Self::Lane {
            command,
            deadline,
            auth,
        } = self
        else {
            return None;
        };
        if candidate_command_revoked(
            &command.as_ref()?.command,
            *deadline,
            auth.as_ref(),
            auth_rx,
        ) {
            return None;
        }
        let peer = &command.as_ref()?.command.to_node_id;
        (!lanes.contains_key(peer) && lanes.len() < CANDIDATE_OFFER_MAX_LANES)
            .then(|| command.take())
            .flatten()
    }

    async fn poll(
        &mut self,
        mut auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    ) -> Option<CandidateDispatchCommand> {
        match self {
            Self::Queue {
                reservation,
                closed_retries_remaining,
            } => reservation
                .as_mut()
                .await
                .map(|command| CandidateDispatchCommand {
                    command,
                    closed_retries_remaining: *closed_retries_remaining,
                }),
            Self::Lane {
                command,
                deadline,
                auth,
            } => {
                let Some(command) = command.as_mut() else {
                    return None;
                };
                let command = &mut command.command;
                let ownership = command.fresh_ownership.clone();
                loop {
                    if candidate_command_revoked(command, *deadline, auth.as_ref(), &auth_rx) {
                        break;
                    }
                    tokio::select! {
                        biased;
                        _ = command.response_tx.closed() => break,
                        _ = async {
                            if let Some(owner) = ownership.as_ref() { owner.cancelled().await; }
                            else { std::future::pending::<()>().await; }
                        } => break,
                        _ = tokio::time::sleep_until((*deadline).into()) => break,
                        changed = auth_rx.changed() => { if changed.is_err() { break; } }
                    }
                }
                // The router drops this pending slot immediately after poll;
                // the caller's receiver then observes terminal queue failure.
                None
            }
        }
    }
}

fn candidate_command_revoked(
    command: &CandidateOfferCommand,
    deadline: Instant,
    auth: Option<&CriticalControlAuth>,
    auth_rx: &watch::Receiver<Option<CriticalControlAuth>>,
) -> bool {
    command.response_tx.is_closed()
        || command
            .fresh_ownership
            .as_ref()
            .is_some_and(|owner| owner.is_cancelled())
        || tokio::time::Instant::now() >= tokio::time::Instant::from_std(deadline)
        || auth_rx.has_changed().is_err()
        || command.expected_registration_seq.is_some_and(|expected| {
            auth_rx
                .borrow()
                .as_ref()
                .and_then(|current| current.registration_seq)
                != Some(expected)
        })
        || auth.is_some_and(|auth| {
            auth_rx
                .borrow()
                .as_ref()
                .is_none_or(|current| !auth.same_identity_as(current))
        })
}

/// Idle closure must retain every previously issued channel permit. Draining
/// after close avoids losing a command whose sender won the idle-boundary race.
async fn receive_candidate_offer(
    receiver: &mut mpsc::Receiver<CandidateOfferCommand>,
    retiring: &mut bool,
) -> Option<CandidateOfferCommand> {
    if !*retiring {
        match timeout(CANDIDATE_OFFER_IDLE_TIMEOUT, receiver.recv()).await {
            Ok(command) => return command,
            Err(_) => {
                receiver.close();
                *retiring = true;
            }
        }
    }
    receiver.recv().await
}

fn reap_candidate_offer_lane(
    lanes: &mut HashMap<String, CandidateOfferLane>,
    completed: std::result::Result<(tokio::task::Id, ()), tokio::task::JoinError>,
) {
    let task_id = match completed {
        Ok((id, ())) => id,
        Err(error) => error.id(),
    };
    lanes.retain(|_, lane| lane.task_id != task_id);
}

#[allow(clippy::too_many_arguments)]
fn route_candidate_offer(
    dispatch: CandidateDispatchCommand,
    lanes: &mut HashMap<String, CandidateOfferLane>,
    tasks: &mut JoinSet<()>,
    http: &RouteAwareControlHttpClient,
    auth_rx: &watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
) -> Option<PendingCandidateDispatch> {
    let CandidateDispatchCommand {
        command,
        closed_retries_remaining,
    } = dispatch;
    let deadline = command
        .not_after
        .unwrap_or_else(|| Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE);
    if candidate_command_revoked(&command, deadline, None, auth_rx) {
        let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
        return None;
    }
    let peer = command.to_node_id.clone();
    if !lanes.contains_key(&peer) {
        if lanes.len() >= CANDIDATE_OFFER_MAX_LANES {
            if command.not_after.is_some() {
                return Some(PendingCandidateDispatch::wait_for_lane(
                    CandidateDispatchCommand {
                        command,
                        closed_retries_remaining,
                    },
                    auth_rx,
                ));
            }
            warn!(peer_id = %peer, reason_code = "candidate_offer_lane_capacity", "Candidate lane capacity reached");
            let _ = command.response_tx.send(PeerOfferSendOutcome::Failed);
            return None;
        }
        lanes.insert(
            peer.clone(),
            spawn_candidate_offer_worker(tasks, http.clone(), auth_rx.clone(), event_tx.clone()),
        );
    }
    let Some(lane) = lanes.get(&peer) else {
        let _ = command.response_tx.send(PeerOfferSendOutcome::Failed);
        return None;
    };
    match lane.sender.try_send(command) {
        Ok(()) => None,
        Err(mpsc::error::TrySendError::Closed(command)) => {
            // Receiver.close() may still be draining accepted commands. Only
            // JoinSet completion can remove this lane and allow its successor.
            PendingCandidateDispatch::wait_for_closed_lane(
                CandidateDispatchCommand {
                    command,
                    closed_retries_remaining,
                },
                auth_rx,
            )
        }
        Err(mpsc::error::TrySendError::Full(command)) if command.not_after.is_some() => {
            Some(PendingCandidateDispatch::Queue {
                reservation: defer_prepaid_candidate_dispatch(
                    lane.sender.clone(),
                    command,
                    auth_rx.clone(),
                ),
                closed_retries_remaining,
            })
        }
        Err(mpsc::error::TrySendError::Full(command)) => {
            warn!(peer_id = %peer, reason_code = "candidate_offer_queue_full", "Candidate offer queue full");
            let _ = command.response_tx.send(PeerOfferSendOutcome::Failed);
            None
        }
    }
}

fn defer_prepaid_candidate_dispatch(
    sender: mpsc::Sender<CandidateOfferCommand>,
    mut command: CandidateOfferCommand,
    mut auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
) -> CandidateQueueReservation {
    Box::pin(async move {
        let Some(deadline) = command.not_after else {
            let _ = command.response_tx.send(PeerOfferSendOutcome::Failed);
            return None;
        };
        let auth = auth_rx.borrow().clone();
        let Some(auth) = auth.filter(|auth| {
            command.expected_registration_seq.is_some()
                && auth.registration_seq == command.expected_registration_seq
        }) else {
            let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
            return None;
        };
        let ownership = command.fresh_ownership.clone();
        let reservation = sender.reserve_owned();
        tokio::pin!(reservation);
        loop {
            if ownership.as_ref().is_some_and(|owner| owner.is_cancelled())
                || Instant::now() >= deadline
                || auth_rx.has_changed().is_err()
                || auth_rx
                    .borrow()
                    .as_ref()
                    .is_none_or(|current| !auth.same_identity_as(current))
            {
                let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
                return None;
            }
            let permit = tokio::select! {
                biased;
                _ = command.response_tx.closed() => return None,
                _ = async {
                    if let Some(owner) = ownership.as_ref() { owner.cancelled().await; }
                    else { std::future::pending::<()>().await; }
                } => {
                    let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
                    return None;
                }
                _ = tokio::time::sleep_until(deadline.into()) => {
                    let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
                    return None;
                }
                changed = auth_rx.changed() => {
                    if changed.is_err() {
                        let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
                        return None;
                    }
                    // Preserve this reservation's FIFO position for duplicate
                    // identity publications; changed identities fail above.
                    continue;
                }
                permit = &mut reservation => permit,
            };
            // Recheck after readiness, including simultaneous cancellation or
            // registration replacement, before the final queue handoff.
            if ownership.as_ref().is_some_and(|owner| owner.is_cancelled())
                || Instant::now() >= deadline
                || command.response_tx.is_closed()
                || auth_rx.has_changed().is_err()
                || auth_rx
                    .borrow()
                    .as_ref()
                    .is_none_or(|current| !auth.same_identity_as(current))
            {
                let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
                return None;
            }
            return match permit {
                Ok(permit) => {
                    permit.send(command);
                    None
                }
                // Only the router recreates a closed worker. Return this exact
                // command without consuming another HTTP credit or payload.
                Err(_) => Some(command),
            };
        }
    })
}
