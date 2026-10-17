use super::*;

struct ObserverReceipts {
    requests: Vec<([u8; 12], usize)>,
    responses: u32,
}

struct CostObserver {
    endpoint: SocketAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<ObserverReceipts>,
}

fn record_request(receipts: &mut ObserverReceipts, data: &[u8]) -> StunMessage {
    let request = StunMessage::decode(data).expect("a real STUN request reaches the observer");
    assert_eq!(request.msg_type, p2pnet_nat::BINDING_REQUEST);
    assert!(receipts.requests.len() < 6, "original request bound");
    receipts.requests.push((request.transaction_id, data.len()));
    request
}

impl CostObserver {
    async fn start(respond: bool, index: u16) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = socket.local_addr().unwrap();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut receipts = ObserverReceipts {
                requests: Vec::new(),
                responses: 0,
            };
            let mut buf = [0u8; 1024];
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    packet = socket.recv_from(&mut buf) => {
                        let (len, source) = packet.unwrap();
                        let request = record_request(&mut receipts, &buf[..len]);
                        if respond {
                            let mut response = StunMessage::with_transaction_id(
                                BINDING_RESPONSE, request.transaction_id,
                            );
                            response.add_attribute(StunAttribute::XorMappedAddress(
                                SocketAddr::from(([127, 0, 0, 1], 41000 + index)),
                            ));
                            let bytes = response.encode();
                            assert_eq!(socket.send_to(&bytes, source).await.unwrap(), bytes.len());
                            receipts.responses += 1;
                        }
                    }
                }
            }
            // Include every already-queued kernel datagram before dropping the socket.
            loop {
                match socket.try_recv_from(&mut buf) {
                    Ok((len, _)) => {
                        record_request(&mut receipts, &buf[..len]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("drain owned observer: {error}"),
                }
            }
            receipts
        });
        Self {
            endpoint,
            stop,
            task,
        }
    }

    async fn finish(self) -> ObserverReceipts {
        self.stop.send(()).expect("owned observer remains alive");
        timeout(Duration::from_secs(2), self.task)
            .await
            .unwrap()
            .unwrap()
    }
}

async fn cost_fixture(
    birthday: bool,
    peer_endpoint: SocketAddr,
) -> (Arc<PeerManager>, UdpTransport) {
    let local = NodeIdentity::generate();
    let remote = NodeIdentity::generate();
    let mut config = config_for_identity(&local, "peer-a");
    config.network.birthday_probing_enabled = true;
    let peers = Arc::new(PeerManager::new(config));
    peers.set_timeline(crate::connection_timeline::ConnectionTimeline::new(
        "cost", 0,
    ));
    let mut info = peer_with_public_key(
        "peer-b",
        "10.20.0.2",
        hex::encode(remote.public_key()),
        Some(peer_endpoint),
    );
    info.nat_type =
        "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7"
            .to_string();
    peers.add_peer(&info).await;
    let endpoint = peer_endpoint.to_string();
    peers
        .add_candidates_with_sources(
            "peer-b",
            std::slice::from_ref(&endpoint),
            &HashMap::from([(endpoint.clone(), "stun_observed".to_string())]),
        )
        .await;
    assert!(
        peers
            .bind_remote_nat_profile_to_candidate_epoch("peer-b", 7)
            .await
    );
    let mut profile =
        hard_nat_candidate_report(FilteringBehavior::AddressOrPortDependent).nat_profile;
    if birthday {
        profile.port_delta = None;
        profile.prediction_candidate = false;
        profile.predicted_endpoints.clear();
        profile.confidence = 70;
    }
    peers.update_nat_profile(profile).await;
    assert_eq!(
        peers.hard_hard_plan_uses_birthday("peer-b").await,
        Some(birthday)
    );
    let (tx, _rx) = mpsc::channel(64);
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a")
        .with_inbound_channel(tx);
    (peers, udp)
}

async fn rejected_cost_case(birthday: bool, coordinated: bool) {
    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (peers, udp) = cost_fixture(birthday, peer_socket.local_addr().unwrap()).await;
    let mut observers = Vec::new();
    for index in 0..if !birthday && !coordinated { 4 } else { 3 } {
        observers.push(CostObserver::start(!birthday && !coordinated && index < 3, index).await);
    }
    let endpoints = observers
        .iter()
        .map(|observer| observer.endpoint)
        .collect::<Vec<_>>();
    let plan = crate::peer::HardHardPlanSnapshot {
        local_network_generation: peers.current_network_generation_sync(),
        remote_candidate_epoch: peers
            .current_remote_candidate_epoch("peer-b")
            .await
            .unwrap(),
        local_profile_generation: peers.current_local_profile_generation_sync(),
        remote_profile_generation: 7,
    };
    let peer_generation = peers.peer_session_generation_sync("peer-b").unwrap();
    let punch_at_ms = crate::hard_hard_now_ms() + 3_000;
    let failure = match crate::run_hard_hard_local_measurement(
        &udp,
        &peers,
        "peer-b",
        crate::HardHardMeasurementRequest {
            observers: &endpoints,
            stun_timeout: Duration::from_millis(300),
            session_token: "cost-rejection",
            cancellation: None,
            punch_at_ms,
            coordinated,
        },
    )
    .await
    {
        Err(failure) => failure,
        Ok(_) => panic!("silent observer must reject the measurement"),
    };
    let mut received = Vec::new();
    let mut responses = 0;
    for observer in observers {
        let receipts = observer.finish().await;
        received.extend(receipts.requests);
        responses += receipts.responses;
    }
    let expected = if !birthday && !coordinated {
        FreshMappingRejection::UnobservedAllocation
    } else {
        FreshMappingRejection::InsufficientSamples
    };
    assert_eq!(failure.rejection, expected);
    assert!(!received.is_empty());
    assert!(received.len() <= 6, "original collector bound");
    assert_eq!(
        received
            .iter()
            .map(|(tx, _)| tx)
            .collect::<HashSet<_>>()
            .len(),
        received.len()
    );
    assert_eq!(udp.dynamic_socket_count().await, 0);
    assert_eq!(udp.stun_waiters.len(), 0);
    assert!(!peers.is_direct("peer-b").await);
    assert!(peers.hard_hard_session_for_test("peer-b").await.is_none());
    let mut buf = [0; 1024];
    assert_eq!(
        peer_socket.try_recv_from(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let observation =
        crate::hard_hard_rejected_measurement_observation(&peers, &failure, punch_at_ms);
    let report = crate::build_hard_hard_pre_session_attempt_report(
        false,
        peer_generation,
        plan,
        "cost-rejection",
        "initiator",
        0,
        observation.as_ref(),
        crate::hard_hard_measurement_failure_class(&failure.rejection),
        failure.rejection.label(),
    );
    assert!(
        peers
            .record_hard_hard_pre_session_attempt_report("peer-b", report.clone())
            .await
    );
    // Independent kernel receipts are the oracle; absent snapshots are not zero sends.
    assert_eq!(
        report.counts.stun_send_success_datagrams as usize,
        received.len()
    );
    assert_eq!(
        report.counts.stun_send_success_bytes,
        received.iter().map(|(_, len)| *len as u64).sum::<u64>()
    );
    assert_eq!(report.counts.stun_responses, responses);
    assert_eq!(report.counts.stun_send_errors, 0);
    let started = report.timeline.measurement_started_at_ms.unwrap();
    let last = report.timeline.last_measurement_send_at_ms.unwrap();
    let completed = report.timeline.measurement_completed_at_ms.unwrap();
    assert!(started <= last && last <= completed);
    assert!(report.timeline.planned_send_at_ms.is_some());
    assert!(!report.direct_confirmed);
    assert!(report.socket_index.is_none());
    peers
        .advance_network_generation("cost report cannot authorize a replacement")
        .await;
    assert!(
        !peers
            .record_hard_hard_pre_session_attempt_report("peer-b", report)
            .await
    );
}

#[tokio::test]
async fn hard_hard_rejected_predictable_retains_real_unobserved_send_cost() {
    rejected_cost_case(false, false).await;
}

#[tokio::test]
async fn hard_hard_rejected_birthday_retains_real_silent_observer_cost() {
    rejected_cost_case(true, false).await;
}

#[tokio::test]
async fn hard_hard_rejected_prepared_retains_real_silent_observer_cost() {
    rejected_cost_case(true, true).await;
}

#[tokio::test]
async fn hard_hard_rejected_preflight_has_no_measurement_snapshot() {
    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (peers, udp) = cost_fixture(false, peer_socket.local_addr().unwrap()).await;
    let mut profile = hard_nat_candidate_report(FilteringBehavior::Unknown).nat_profile;
    profile.mapping_behavior = MappingBehavior::EndpointIndependent;
    profile.public_port_stable = Some(true);
    profile.prediction_candidate = false;
    peers.update_nat_profile(profile).await;
    let observer = CostObserver::start(false, 0).await;
    let failure = match crate::run_hard_hard_local_measurement(
        &udp,
        &peers,
        "peer-b",
        crate::HardHardMeasurementRequest {
            observers: &[observer.endpoint],
            stun_timeout: Duration::from_millis(300),
            session_token: "preflight",
            cancellation: None,
            punch_at_ms: crate::hard_hard_now_ms(),
            coordinated: true,
        },
    )
    .await
    {
        Err(failure) => failure,
        Ok(_) => panic!("stable local NAT must fail before measurement"),
    };
    assert_eq!(failure.rejection, FreshMappingRejection::StableLocalNat);
    assert!(failure.measurement.is_none());
    assert!(observer.finish().await.requests.is_empty());
    assert_eq!(udp.dynamic_socket_count().await, 0);
}
