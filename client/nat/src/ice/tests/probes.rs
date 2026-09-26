#[tokio::test]
async fn test_probe_filtering_behavior_keeps_port_only_response_unknown() {
    let (server, _handle) =
        spawn_change_request_stun_server(ChangeResponseMode::ChangedPortForIpPort).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let filtering =
        probe_filtering_behavior(&socket, server, Duration::from_secs(1), &[server]).await;

    assert_eq!(filtering, None);
}

#[tokio::test]
async fn test_probe_filtering_behavior_keeps_unsupported_change_ip_unknown() {
    let (server, _handle) =
        spawn_change_request_stun_server(ChangeResponseMode::ChangedPortForPortOnly).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // A dropped unsupported request is not evidence of restrictive filtering.
    let filtering =
        probe_filtering_behavior(&socket, server, Duration::from_millis(500), &[server]).await;

    assert_eq!(filtering, None);
}

#[test]
fn test_changed_ip_port_classifier_requires_ip_change_for_endpoint_independent() {
    let server = "192.0.2.10:3478".parse().unwrap();
    let changed_ip = "198.51.100.10:3479".parse().unwrap();
    let changed_port = "192.0.2.10:3479".parse().unwrap();
    let unchanged = server;

    assert_eq!(
        classify_filtering_probe_response(server, changed_ip, &[server]),
        Some(FilteringBehavior::EndpointIndependent)
    );
    assert_eq!(
        classify_filtering_probe_response(server, changed_port, &[server]),
        None
    );
    assert_eq!(
        classify_filtering_probe_response(server, unchanged, &[server]),
        None
    );
}

#[tokio::test]
async fn test_probe_mapping_lifetime_records_lower_bound() {
    let (server, _handle) = crate::client::test_helpers::spawn_mock_stun_server().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let expected_endpoint = socket.local_addr().unwrap();

    let lifetime =
        probe_mapping_lifetime(&socket, server, expected_endpoint, Duration::from_secs(1)).await;

    assert_eq!(
        lifetime,
        Some(MappingLifetime::LowerBoundMs(duration_millis(
            MAPPING_LIFETIME_PROBE_DELAY
        )))
    );
}

#[tokio::test]
async fn test_probe_hairpin_behavior_detects_self_hairpin() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_endpoint = socket.local_addr().unwrap();

    let hairpin = probe_hairpin_behavior(&socket, public_endpoint, Duration::from_secs(1)).await;

    assert_eq!(hairpin, Some(HairpinBehavior::Supported));
}
