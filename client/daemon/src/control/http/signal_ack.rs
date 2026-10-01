const SIGNAL_ACK_ATTEMPTS: u8 = 3;
const SIGNAL_ACK_BACKOFF: Duration = Duration::from_millis(25);
const HARD_HARD_ACK_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(400);
const HARD_HARD_ACK_TOTAL_TIMEOUT: Duration = Duration::from_millis(1_250);

#[derive(Clone, Copy, Debug)]
enum SignalAckTiming {
    Ordinary,
    HardHard(tokio::time::Instant),
}

impl SignalAckTiming {
    fn for_signal(
        session_id: Option<&str>,
        punch_at_ms: Option<u64>,
        received_at_ms: u64,
        received_at: tokio::time::Instant,
    ) -> Self {
        if !session_id
            .and_then(crate::HardHardCoordination::parse)
            .is_some_and(|coordination| coordination.v2.is_some())
        {
            return Self::Ordinary;
        }
        // An untrusted timestamp can only shorten this bounded transport
        // budget. Missing/expired HH2 time gets a single cleanup ACK.
        let remaining = punch_at_ms
            .unwrap_or(received_at_ms)
            .saturating_sub(received_at_ms);
        Self::HardHard(
            received_at + Duration::from_millis(remaining).min(crate::HARD_HARD_PUNCH_LEAD),
        )
    }

    fn budget(self, now: tokio::time::Instant) -> (tokio::time::Instant, Duration, u8) {
        match self {
            Self::Ordinary => (
                now + SIGNAL_SEND_TIMEOUT,
                (SIGNAL_SEND_TIMEOUT - SIGNAL_ACK_BACKOFF * 2) / u32::from(SIGNAL_ACK_ATTEMPTS),
                SIGNAL_ACK_ATTEMPTS,
            ),
            Self::HardHard(deadline) if deadline > now => (
                deadline.min(now + HARD_HARD_ACK_TOTAL_TIMEOUT),
                HARD_HARD_ACK_ATTEMPT_TIMEOUT,
                SIGNAL_ACK_ATTEMPTS,
            ),
            // Application has already terminated. One bounded DELETE of the
            // exact lease prevents expired HH traffic blocking later cleanup;
            // it neither reapplies the signal nor revives the punch session.
            Self::HardHard(_) => (
                now + HARD_HARD_ACK_ATTEMPT_TIMEOUT,
                HARD_HARD_ACK_ATTEMPT_TIMEOUT,
                1,
            ),
        }
    }
}

#[derive(Clone)]
struct SignalAckRegistration {
    expected: super::CriticalControlAuth,
    current: tokio::sync::watch::Receiver<Option<super::CriticalControlAuth>>,
}

impl SignalAckRegistration {
    fn capture(
        base_url: &str,
        token: &str,
        self_node_id: &str,
        registration_seq: Option<u64>,
        current: tokio::sync::watch::Receiver<Option<super::CriticalControlAuth>>,
    ) -> Result<Self> {
        let expected = current
            .borrow()
            .clone()
            .filter(|auth| {
                auth.base_url == base_url
                    && auth.token == token
                    && auth.self_node_id == self_node_id
                    && auth.registration_seq == registration_seq
            })
            .ok_or_else(Self::revoked)?;
        let captured = Self { expected, current };
        captured.ensure_current()?;
        Ok(captured)
    }

    fn revoked() -> DaemonError {
        DaemonError::ControlPlane(
            "signal ACK registration revoked reason_code=signal_ack_registration_changed".into(),
        )
    }

    fn ensure_current(&self) -> Result<()> {
        if self.current.has_changed().is_err()
            || !self
                .current
                .borrow()
                .as_ref()
                .is_some_and(|auth| self.expected.same_identity_as(auth))
        {
            return Err(Self::revoked());
        }
        Ok(())
    }

    async fn run<F, T>(&mut self, deadline: tokio::time::Instant, work: F) -> Result<T>
    where
        F: std::future::Future<Output = T>,
    {
        tokio::pin!(work);
        loop {
            self.ensure_current()?;
            tokio::select! {
                biased;
                changed = self.current.changed() => {
                    if changed.is_err() { return Err(Self::revoked()); }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    self.ensure_current()?;
                    return Err(DaemonError::ControlPlane("signal ACK deadline elapsed reason_code=signal_ack_deadline".into()));
                }
                result = &mut work => {
                    self.ensure_current()?;
                    return Ok(result);
                }
            }
        }
    }
}

struct SignalAckFailure {
    error: DaemonError,
    retryable: bool,
}

fn signal_ack_status_retryable(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Retry only the immutable ACK after application has committed. The server
/// DELETE matches both id and delivery token and treats an absent row as success.
#[allow(clippy::too_many_arguments)]
async fn ack_signals_with_retry(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    self_node_id: &str,
    registration: &mut SignalAckRegistration,
    ack: &SignalAckRequest,
    timing: SignalAckTiming,
) -> Result<()> {
    let (deadline, attempt_timeout, attempts) = timing.budget(tokio::time::Instant::now());
    for attempt in 0..attempts {
        registration.ensure_current()?;
        let attempt_deadline = deadline.min(tokio::time::Instant::now() + attempt_timeout);
        if attempt_deadline <= tokio::time::Instant::now() {
            break;
        }
        // The outer registration fence also covers response-body decoding.
        // Attempt timeout lives inside it so transport timeouts can retry,
        // whereas identity revocation terminates the lane immediately.
        let request = ack_signals_once(
            http,
            base_url,
            token,
            self_node_id,
            registration.expected.registration_seq,
            ack,
            attempt_timeout,
        );
        let result = registration
            .run(deadline, tokio::time::timeout_at(attempt_deadline, request))
            .await?;
        let failure = match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(failure)) => failure,
            Err(_) => SignalAckFailure {
                error: DaemonError::ControlPlane("signal ACK attempt timed out".into()),
                retryable: true,
            },
        };
        if !failure.retryable
            || attempt + 1 == attempts
            || tokio::time::Instant::now() + SIGNAL_ACK_BACKOFF >= deadline
        {
            return Err(failure.error);
        }
        registration
            .run(deadline, tokio::time::sleep(SIGNAL_ACK_BACKOFF))
            .await?;
    }
    Err(DaemonError::ControlPlane(
        "signal ACK deadline elapsed reason_code=signal_ack_deadline".into(),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn ack_signals_once(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    self_node_id: &str,
    registration_seq: Option<u64>,
    ack: &SignalAckRequest,
    timeout: Duration,
) -> std::result::Result<(), SignalAckFailure> {
    let response = with_registration_sequence(
        http.post(format!(
            "{base_url}/api/v1/signals/ack?node_id={self_node_id}"
        ))
        .timeout(timeout)
        .bearer_auth(token)
        .json(&serde_json::json!({ "signals": [ack] })),
        registration_seq,
    )
    .send()
    .await
    .map_err(|error| SignalAckFailure {
        error: DaemonError::ControlPlane(format!("signal ack request failed: {error}")),
        retryable: true,
    })?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let (detail, error_code, current_seq) = control_error_detail(response).await;
    if let Some(error) = registration_conflict_error(status, error_code, current_seq, &detail) {
        return Err(SignalAckFailure {
            error,
            retryable: false,
        });
    }
    Err(SignalAckFailure {
        error: DaemonError::ControlPlane(format!("signal ack returned HTTP {status}: {detail}")),
        retryable: signal_ack_status_retryable(status),
    })
}

#[cfg(test)]
#[path = "signal_ack_tests.rs"]
mod signal_ack_tests;
