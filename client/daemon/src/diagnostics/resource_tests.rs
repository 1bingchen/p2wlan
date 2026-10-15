use super::*;

fn actual_daemon_context(daemon: &crate::Daemon) -> DiagnosticsContext {
    DiagnosticsContext::new(
        daemon.config.clone(),
        daemon.peers.clone(),
        daemon.udp_transport.clone(),
        daemon.candidate_snapshot.clone(),
        daemon.nat_profile.clone(),
        daemon.gateway_mapping_diagnostics.clone(),
        daemon.relay_transport.clone(),
        daemon.relay_selection.clone(),
        daemon.health.clone(),
        daemon.task_manager.clone(),
        daemon.route_manager.clone(),
        daemon.shutdown_tx.clone(),
        daemon.timeline.clone(),
        daemon.status_events.clone(),
        None,
        daemon.config.diagnostics.auth_token.clone(),
        None,
    )
    .with_resource_capture(daemon.resource_capture.clone())
}

async fn request(addr: std::net::SocketAddr, method: &str, auth: &str) -> String {
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(
            format!("{method} /resources HTTP/1.1\r\nHost: localhost\r\n{auth}\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn runtime_resource_authenticated_http_is_bounded_and_independent_of_network_state_locks() {
    use crate::dataplane_resources::{ResidencyLease, ResidencyStage};
    for observe in [false, true] {
        let end = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut config =
            Config::generate_default("https://control.example.com", "resources").unwrap();
        config.network.manual = true;
        config.diagnostics.enabled = true;
        config.diagnostics.resource_capture = observe;
        config.diagnostics.auth_token = Some("resource-test-token".into());
        let daemon = crate::Daemon::new(config);
        let context = actual_daemon_context(&daemon);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let mut server = tokio::spawn(serve_diagnostics(listener, context, shutdown));
        let mut work = tokio::spawn(async move {
            // /status would wait for these; /resources must not read them.
            let _udp = daemon.udp_transport.write().await;
            let _relay = daemon.relay_transport.write().await;
            let mut bytes = Vec::with_capacity(128);
            bytes.extend_from_slice(b"payload-must-not-be-exported");
            let _lease = daemon.transport.resource_capture().and_then(|capture| {
                ResidencyLease::observe(capture, ResidencyStage::RawChannel, &bytes)
            });
            for auth in ["", "Authorization: Bearer wrong-token\r\n"] {
                assert!(request(addr, "GET", auth)
                    .await
                    .starts_with("HTTP/1.1 401 Unauthorized"));
            }
            let auth = "Authorization: Bearer resource-test-token\r\n";
            assert!(request(addr, "POST", auth)
                .await
                .starts_with("HTTP/1.1 403 Forbidden"));
            let response = request(addr, "GET", auth).await;
            assert!(response.starts_with("HTTP/1.1 200 OK"));
            assert!(!response.contains("Access-Control-Allow-Origin"));
            assert!(!response.contains("resource-test-token"));
            assert!(!response.contains("payload-must-not-be-exported"));
            let body = response.split_once("\r\n\r\n").unwrap().1;
            assert!(body.len() <= 16 * 1024);
            let readout: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(readout["enabled"], observe);
            assert_eq!(readout["schema_version"], 1);
            if observe {
                let owner = &readout["capture"]["observed_owner_residency"];
                assert_eq!(owner["coherent"], true);
                assert_eq!(owner["total"]["live_buffers"], 1);
                assert_eq!(owner["total"]["len_bytes"], bytes.len() as u64);
                assert_eq!(owner["total"]["capacity_bytes"], bytes.capacity() as u64);
                assert_eq!(owner["whole_pipeline_bytes_measured"], false);
                assert_eq!(
                    readout["capture"]["site_and_lexical_counters"]["coherent"],
                    false
                );
            } else {
                assert!(readout["capture"].is_null());
            }
        });
        // Retain the first outcome and reap both original task owners before
        // reporting any assertion/panic/deadline failure.
        let result = timeout(Duration::from_secs(2), &mut work).await;
        if result.is_err() {
            work.abort();
            let _ = work.await;
        }
        let _ = stop.send(true);
        let joined = tokio::time::timeout_at(end, &mut server).await;
        if joined.is_err() {
            server.abort();
            let _ = server.await;
        }
        assert!(
            matches!(joined, Ok(Ok(Ok(())))),
            "original server owner did not join: {joined:?}"
        );
        result
            .expect("original resource request work bound")
            .expect("resource request assertions");
    }
}
