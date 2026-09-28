const SIGNAL_RELEASE_AUTH_WAIT: Duration = Duration::from_secs(2);
const SIGNAL_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);

/// Relinquish delivery, never application: only the newly current identity may
/// release the exact old tokens. The next poll retains the server's pair order
/// and the application tracker joins/deduplicates any event still in flight.
async fn release_revoked_signal_leases(
    http: &RouteAwareControlHttpClient,
    mut registration: SignalAckRegistration,
    deliveries: &[SignalAckRequest],
) {
    if deliveries.is_empty() || deliveries.len() > SIGNAL_ACK_PIPELINE_CAPACITY {
        return;
    }
    let started = tokio::time::Instant::now();
    let auth_deadline = started + SIGNAL_RELEASE_AUTH_WAIT;
    let auth = loop {
        if tokio::time::Instant::now() >= auth_deadline {
            warn!("Control signal phase=lease_release reason_code=current_auth_unavailable requested={} fallback=lease_expiry", deliveries.len());
            return;
        }
        if registration.current.has_changed().is_err() {
            return;
        }
        let current = registration.current.borrow_and_update().clone();
        if let Some(auth) = current {
            if auth.base_url != registration.expected.base_url
                || auth.self_node_id != registration.expected.self_node_id
            {
                return;
            }
            break auth;
        }
        tokio::select! {
            changed = registration.current.changed() => {
                if changed.is_err() { return; }
            }
            _ = tokio::time::sleep_until(auth_deadline) => {
                warn!("Control signal phase=lease_release reason_code=current_auth_unavailable requested={} fallback=lease_expiry", deliveries.len());
                return;
            }
        }
    };
    let mut current = SignalAckRegistration {
        expected: auth.clone(),
        current: registration.current,
    };
    // The old batch's client may still be pinned to the vanished interface.
    // Resolve the existing transport owner's pool only after auth recovery.
    let Ok(http) = http.current() else {
        warn!("Control signal phase=lease_release reason_code=current_transport_unavailable requested={} fallback=lease_expiry", deliveries.len());
        return;
    };
    let request = with_registration_sequence(
        http.post(format!("{}/api/v1/signals/release", auth.base_url))
            .query(&[("node_id", &auth.self_node_id)])
            .bearer_auth(&auth.token)
            .timeout(SIGNAL_RELEASE_TIMEOUT)
            .json(&serde_json::json!({"signals": deliveries})),
        auth.registration_seq,
    );
    let outcome = current
        .run(
            (tokio::time::Instant::now() + SIGNAL_RELEASE_TIMEOUT)
                .min(auth_deadline + SIGNAL_RELEASE_TIMEOUT),
            request.send(),
        )
        .await;
    let reason = match outcome {
        Ok(Ok(response)) if response.status().is_success() => "ordered_redelivery_requested",
        Ok(Ok(response)) if matches!(response.status().as_u16(), 404 | 405) => "server_unsupported",
        Ok(Ok(_)) => "server_rejected",
        Ok(Err(_)) => "transport_failed",
        Err(_) => "registration_changed_or_deadline",
    };
    info!(
        "Control signal phase=lease_release reason_code={} requested={} elapsed_ms={} previous_registration_seq={:?} current_registration_seq={:?}",
        reason, deliveries.len(), started.elapsed().as_millis(),
        registration.expected.registration_seq, auth.registration_seq,
    );
}
