/// At most one server batch of committed ACKs waits behind one HTTP request.
/// Matches the server's MaxSignalBatch; unexpected larger responses receive
/// bounded backpressure rather than spawning more ACK work.
const SIGNAL_ACK_PIPELINE_CAPACITY: usize = 500;

struct AppliedSignalAck {
    ack: SignalAckRequest,
    timing: SignalAckTiming,
    log_signal_id: String,
    log_from_node_id: String,
    log_signal_type: String,
    signal_seq: Option<u64>,
}

/// Application and transport acknowledgement share the existing lane task.
/// Application stays sequential; only a committed prefix enters the bounded
/// serial ACK queue. A lost ACK response cannot hold an already-leased SYNC
/// behind it, and no newer ACK can overtake the older exact lease token.
#[allow(clippy::too_many_arguments)]
fn spawn_signal_application_lane(
    http: reqwest::Client,
    release_http: RouteAwareControlHttpClient,
    base_url: String,
    token: String,
    self_node_id: String,
    ack_registration: SignalAckRegistration,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    delivery_tracker: Arc<tokio::sync::Mutex<SignalDeliveryTracker>>,
    deliveries: Vec<LeasedSignalDelivery>,
) {
    tokio::spawn(async move {
        let leased: Vec<_> = deliveries
            .iter()
            .map(|delivery| delivery.ack.clone())
            .collect();
        let (ack_tx, ack_rx) = mpsc::channel(SIGNAL_ACK_PIPELINE_CAPACITY);
        tokio::join!(
            apply_signal_batch(
                ack_registration.clone(),
                event_tx,
                delivery_tracker,
                deliveries,
                ack_tx,
            ),
            acknowledge_signal_batch(
                &http,
                &release_http,
                &base_url,
                &token,
                &self_node_id,
                ack_registration,
                ack_rx,
                &leased,
            ),
        );
    });
}

async fn apply_signal_batch(
    ack_registration: SignalAckRegistration,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    delivery_tracker: Arc<tokio::sync::Mutex<SignalDeliveryTracker>>,
    deliveries: Vec<LeasedSignalDelivery>,
    acknowledgements: mpsc::Sender<AppliedSignalAck>,
) {
    for delivery in deliveries {
        if acknowledgements.is_closed() || ack_registration.ensure_current().is_err() {
            break;
        }
        let log_signal_id = bounded_signal_log_value(&delivery.signal_id);
        let log_from_node_id = bounded_signal_log_value(&delivery.from_node_id);
        let log_signal_type = bounded_signal_log_value(&delivery.signal_type);
        let mut application_waiter = None;
        let mut application_wait_result = None;
        let mut already_applied = false;
        let outcome = match delivery.prepared {
            PreparedSignalDelivery::TerminalRejected => {
                already_applied = delivery_tracker.lock().await.already_applied(
                    &delivery.signal_id,
                    &delivery.from_node_id,
                    delivery.signal_seq,
                );
                if already_applied {
                    SignalApplyOutcome::Applied
                } else {
                    SignalApplyOutcome::TerminalRejected
                }
            }
            PreparedSignalDelivery::Apply(event) => {
                let tracked = delivery_tracker.lock().await.begin_application(
                    &delivery.signal_id,
                    &delivery.from_node_id,
                    delivery.signal_seq,
                    &delivery.signal_type,
                );
                match tracked {
                    TrackedSignalApplication::AlreadyApplied => {
                        already_applied = true;
                        SignalApplyOutcome::Applied
                    }
                    TrackedSignalApplication::Join(waiter) => {
                        info!(
                            "Control signal phase=join_in_flight id={} from={} type={} seq={:?}",
                            log_signal_id, log_from_node_id, log_signal_type, delivery.signal_seq
                        );
                        application_waiter = Some(waiter.clone());
                        let wait_result = wait_for_signal_application(
                            waiter,
                            &delivery.signal_id,
                            &delivery.from_node_id,
                            delivery.signal_seq,
                            &delivery.signal_type,
                        )
                        .await;
                        application_wait_result = Some(wait_result);
                        match wait_result {
                            SignalApplicationWait::Completed(outcome) => outcome,
                            SignalApplicationWait::TimedOut => SignalApplyOutcome::Retry,
                        }
                    }
                    TrackedSignalApplication::Start { receipt, waiter } => {
                        application_waiter = Some(waiter.clone());
                        // Acquiring the tracker may yield across a registration
                        // edge. Retire only this undispatched application;
                        // never enqueue it under the replacement identity.
                        if acknowledgements.is_closed()
                            || ack_registration.ensure_current().is_err()
                        {
                            delivery_tracker.lock().await.finish_application(
                                delivery.signal_id.clone(),
                                &delivery.from_node_id,
                                delivery.signal_seq,
                                application_waiter.as_ref(),
                                SignalApplyOutcome::Retry,
                            );
                            break;
                        }
                        let delivered = ControlEvent::DeliveredSignal {
                            signal_id: delivery.signal_id.clone(),
                            signal_seq: delivery.signal_seq,
                            signal_type: delivery.signal_type.clone(),
                            event,
                            receipt: receipt.clone(),
                        };
                        if event_tx.send(delivered).is_err() {
                            warn!(
                                "Control signal {} could not enter the daemon state machine; leaving its server lease unacknowledged",
                                log_signal_id
                            );
                            delivery_tracker.lock().await.finish_application(
                                delivery.signal_id.clone(),
                                &delivery.from_node_id,
                                delivery.signal_seq,
                                application_waiter.as_ref(),
                                SignalApplyOutcome::Retry,
                            );
                            break;
                        }
                        receipt.record_phase("queued", "daemon_event_channel");
                        info!(
                            "Control signal phase=queued id={} from={} type={} seq={:?}",
                            log_signal_id, log_from_node_id, log_signal_type, delivery.signal_seq
                        );
                        let wait_result = wait_for_signal_application(
                            waiter,
                            &delivery.signal_id,
                            &delivery.from_node_id,
                            delivery.signal_seq,
                            &delivery.signal_type,
                        )
                        .await;
                        application_wait_result = Some(wait_result);
                        match wait_result {
                            SignalApplicationWait::Completed(outcome) => outcome,
                            SignalApplicationWait::TimedOut => SignalApplyOutcome::Retry,
                        }
                    }
                }
            }
        };

        let application_timed_out = matches!(
            application_wait_result,
            Some(SignalApplicationWait::TimedOut)
        );
        if !already_applied && !application_timed_out {
            info!(
                "Control signal phase=application_completed id={} from={} type={} seq={:?} outcome={:?}",
                log_signal_id,
                log_from_node_id,
                log_signal_type,
                delivery.signal_seq,
                outcome
            );
        }

        if already_applied {
            debug!(
                "Skipping redelivered signal {} from {} at seq {:?}; state-machine application already committed",
                log_signal_id, log_from_node_id, delivery.signal_seq
            );
        } else if let Some(waiter) = application_waiter.as_ref() {
            let wait_result =
                application_wait_result.unwrap_or(SignalApplicationWait::Completed(outcome));
            delivery_tracker.lock().await.finish_application_wait(
                delivery.signal_id.clone(),
                &delivery.from_node_id,
                delivery.signal_seq,
                waiter,
                wait_result,
            );
        } else if !application_timed_out {
            delivery_tracker.lock().await.finish_application(
                delivery.signal_id.clone(),
                &delivery.from_node_id,
                delivery.signal_seq,
                None,
                outcome,
            );
        }

        if application_timed_out {
            warn!(
                "Control signal phase=retry_pending_application id={} from={} type={} seq={:?}; the original state-machine event remains in flight",
                log_signal_id,
                log_from_node_id,
                log_signal_type,
                delivery.signal_seq
            );
            break;
        }

        if !matches!(
            outcome,
            SignalApplyOutcome::Applied | SignalApplyOutcome::TerminalRejected
        ) {
            warn!(
                "Control signal phase=application_retry id={} from={} type={} seq={:?} outcome={:?}; leaving it and all later rows unacknowledged for ordered redelivery",
                log_signal_id, log_from_node_id, log_signal_type, delivery.signal_seq, outcome
            );
            break;
        }

        if acknowledgements
            .send(AppliedSignalAck {
                ack: delivery.ack,
                timing: delivery.ack_timing,
                log_signal_id,
                log_from_node_id,
                log_signal_type,
                signal_seq: delivery.signal_seq,
            })
            .await
            .is_err()
        {
            // The ACK owner failed or lost registration. Already committed
            // rows remain in the dedup tracker; no uncommitted row is ACKed.
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn acknowledge_signal_batch(
    http: &reqwest::Client,
    release_http: &RouteAwareControlHttpClient,
    base_url: &str,
    token: &str,
    self_node_id: &str,
    mut registration: SignalAckRegistration,
    mut acknowledgements: mpsc::Receiver<AppliedSignalAck>,
    leased: &[SignalAckRequest],
) {
    loop {
        if registration.ensure_current().is_err() {
            acknowledgements.close();
            release_revoked_signal_leases(release_http, registration, leased).await;
            return;
        }
        let applied = tokio::select! {
            biased;
            _ = registration.current.changed() => { continue; }
            applied = acknowledgements.recv() => {
                let Some(applied) = applied else { return; };
                applied
            }
        };
        if let Err(error) = ack_signals_with_retry(
            http,
            base_url,
            token,
            self_node_id,
            &mut registration,
            &applied.ack,
            applied.timing,
        )
        .await
        {
            warn!(
                "Signal {} applied but ACK failed; unacknowledged rows retain ordered lease redelivery: {error}",
                applied.log_signal_id,
            );
            // Closing the only receiver also stops the application producer
            // at its next boundary. The original per-row application timeout
            // still bounds an event already handed to the daemon owner.
            acknowledgements.close();
            if registration.ensure_current().is_err() {
                release_revoked_signal_leases(release_http, registration, leased).await;
            }
            return;
        }
        info!(
            "Control signal phase=acked id={} from={} type={} seq={:?}",
            applied.log_signal_id,
            applied.log_from_node_id,
            applied.log_signal_type,
            applied.signal_seq,
        );
    }
}
