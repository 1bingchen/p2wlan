//! Idle application shadow through one original, physically matched consent.
//! No application request, native encrypted ACK or new health authority.

use super::*;
use futures_util::FutureExt;
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Instant as TokioInstant};

#[derive(Default)]
struct IdleOwners {
    remote: Option<Arc<UdpSocket>>,
    udp: Option<UdpTransport>,
    inbound: Option<JoinHandle<crate::error::Result<()>>>,
    responder: Option<JoinHandle<std::result::Result<[u8; 8], String>>>,
}

impl IdleOwners {
    fn abort_workers(&self) {
        if let Some(task) = self.inbound.as_ref() {
            task.abort();
        }
        if let Some(task) = self.responder.as_ref() {
            task.abort();
        }
    }
}

impl Drop for IdleOwners {
    fn drop(&mut self) {
        // Dropping the whole test is abort protection, never a claimed join.
        self.abort_workers();
    }
}

async fn collect_idle_worker<T>(
    slot: &mut Option<JoinHandle<T>>,
    end: TokioInstant,
) -> (bool, Option<T>, Option<String>) {
    let Some(task) = slot.as_mut() else {
        return (true, None, None); // No task acquired in a partial setup.
    };
    let result = match timeout_at(end, task).await {
        Ok(result) => result,
        Err(_) => return (false, None, Some("original worker join deadline".into())),
    };
    drop(slot.take()); // Consume Ready before handling any JoinError.
    match result {
        Ok(value) => (true, Some(value), None),
        Err(error) if error.is_cancelled() => (true, None, None),
        Err(error) => (true, None, Some(error.to_string())),
    }
}

#[tokio::test]
async fn c02_idle_application_healthy_consent_preserves_actual_selector() {
    let end = TokioInstant::now() + Duration::from_secs(2);
    let work_end = end - Duration::from_secs(1);
    let peers = peer_manager();
    let bursts = Arc::new(ProbeBurstCaptureForTest::new());
    let mut owners = IdleOwners::default();
    let mut remote_addr = None;
    let mut local_addr = None;
    let mut remote_weak = None;
    let mut primary = None;
    let mut ipv6 = None;

    let body = std::panic::AssertUnwindSafe(async {
        owners.remote = Some(Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?,
        ));
        let remote = owners.remote.as_ref().unwrap();
        remote_weak = Some(Arc::downgrade(remote));
        let endpoint = remote.local_addr().map_err(|e| e.to_string())?;
        remote_addr = Some(endpoint);
        peers
            .add_peer(&peer("peer-b", "10.20.0.2", Some(endpoint)))
            .await;
        peers
            .record_direct_probe_success_with_latency(
                "peer-b",
                endpoint,
                Some(Duration::from_millis(5)),
            )
            .await;
        peers.record_direct_success("peer-b", Some(endpoint)).await;
        let successes_before = peers
            .get_connection("peer-b")
            .await
            .ok_or("missing original idle peer")?
            .direct_health
            .success_count;
        owners.udp = Some(
            UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
                .await
                .map_err(|e| e.to_string())?,
        );
        let udp = owners.udp.as_mut().unwrap();
        udp.probe_burst_capture_for_test = Some(bursts.clone());
        primary = Some(Arc::downgrade(&udp.socket));
        ipv6 = udp.ipv6_socket.as_ref().map(Arc::downgrade);
        let source_endpoint = udp.local_addr().map_err(|e| e.to_string())?;
        local_addr = Some(source_endpoint);
        let (tx, _rx) = mpsc::channel(1);
        let inbound = udp.clone();
        // Each actual spawn result enters its external owner before an await.
        owners.inbound = Some(tokio::spawn(inbound.run_inbound(tx)));
        let responder_socket = remote.clone();
        owners.responder = Some(tokio::spawn(async move {
            let mut bytes = [0u8; 256];
            let (len, source) = responder_socket
                .recv_from(&mut bytes)
                .await
                .map_err(|e| e.to_string())?;
            let probe = decode_punch_packet(&bytes[..len]).ok_or("invalid actual idle consent")?;
            if source != source_endpoint || probe.kind != PunchPacketKind::Punch {
                return Err("actual idle consent source/kind mismatch".into());
            }
            let ack = build_punch_ack(probe.nonce);
            let accepted = responder_socket
                .send_to(&ack, source_endpoint)
                .await
                .map_err(|e| e.to_string())?;
            if accepted != ack.len() {
                return Err("actual idle consent ACK short send".into());
            }
            Ok(probe.nonce)
        }));
        // This is the original matching-consent wait. No application traffic
        // or extra idle sleep supplies a synthetic success observation.
        udp.run_keepalive_round(Duration::from_millis(500)).await;
        let _ack_transaction = udp.lock_peer_adoption_for_direct_validation("peer-b").await;
        let connection = peers
            .get_connection("peer-b")
            .await
            .ok_or("missing idle peer after original ACK adoption")?;
        let pair = connection
            .candidate_pairs
            .iter()
            .find(|pair| pair.remote_endpoint == endpoint)
            .ok_or("missing original idle consent pair")?;
        let selection = peers.select_path_for_data("peer-b", true, false).await;
        Ok::<_, String>((
            connection.state,
            connection.direct_health.success_count,
            connection.direct_health.consecutive_failures,
            pair.state,
            pair.consecutive_failures,
            selection.path,
            selection.direct_confirmed,
            successes_before,
            connection
                .direct_events
                .iter()
                .any(|event| event.stage == "consent_ack_received"),
            connection
                .direct_events
                .iter()
                .any(|event| event.stage == "consent_timeout"),
        ))
    })
    .catch_unwind();
    let body_result = timeout_at(work_end, body).await;

    let held = usize::from(owners.inbound.is_some()) + usize::from(owners.responder.is_some());
    owners.abort_workers();
    let (burst_count, bursts_joined) = bursts.abort_and_join_until(end).await;
    let (inbound_joined, inbound_result, inbound_error) =
        collect_idle_worker(&mut owners.inbound, end).await;
    let (responder_joined, responder_result, responder_error) =
        collect_idle_worker(&mut owners.responder, end).await;
    let had_udp = owners.udp.is_some();
    let had_remote = owners.remote.is_some();
    drop(owners.udp.take());
    drop(owners.remote.take());
    // run_inbound owns its original reader JoinSet. Its dropped children are
    // not exposed as independent handles; observe their actual socket release
    // within the same end without claiming extra native joins.
    let sockets_released = timeout_at(end, async {
        while primary.as_ref().is_some_and(|w| w.upgrade().is_some())
            || ipv6.as_ref().is_some_and(|w| w.upgrade().is_some())
            || remote_weak.as_ref().is_some_and(|w| w.upgrade().is_some())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let local_rebound = if let Some(address) = local_addr {
        Some(timeout_at(end, UdpSocket::bind(address)).await)
    } else {
        None
    };
    let remote_rebound = if let Some(address) = remote_addr {
        Some(timeout_at(end, UdpSocket::bind(address)).await)
    } else {
        None
    };
    let ports_reclaimed = (!had_udp || matches!(&local_rebound, Some(Ok(Ok(_)))))
        && (!had_remote || matches!(&remote_rebound, Some(Ok(Ok(_)))));
    drop(local_rebound);
    drop(remote_rebound);

    assert!(inbound_joined && responder_joined && bursts_joined);
    assert!(
        inbound_error.is_none() && responder_error.is_none(),
        "original idle worker errors after cleanup: {inbound_error:?}/{responder_error:?}"
    );
    assert!(sockets_released && ports_reclaimed);
    let observed = match body_result {
        Ok(Ok(Ok(value))) => value,
        Ok(Ok(Err(error))) => panic!("original idle consent body failed after cleanup: {error}"),
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("original idle consent body exceeded work end after cleanup"),
    };
    assert_eq!(held, 2);
    assert_eq!(burst_count, 1, "one original legacy consent producer");
    assert!(inbound_result.is_none() || matches!(inbound_result, Some(Ok(()))));
    assert!(
        matches!(responder_result, Some(Ok(_))),
        "original responder must actually receive the probe and fully send its ACK"
    );
    assert_eq!(observed.0, ConnectionState::Direct);
    assert_eq!(
        observed.1,
        observed.7 + 1,
        "one original matched health sample"
    );
    assert_eq!(observed.2, 0);
    assert_eq!(observed.3, crate::peer::CandidatePairState::Selected);
    assert_eq!(observed.4, 0);
    assert_eq!(observed.5, Some(crate::peer::NetworkPath::Direct));
    assert!(observed.6 && observed.8 && !observed.9);
}
