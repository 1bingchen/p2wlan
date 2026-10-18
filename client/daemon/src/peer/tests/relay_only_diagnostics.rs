//! Unregistered connection DTOs only: no peer manager, socket, crypto,
//! KernelRead, Full producer, current-owner permission or business is created.
use super::super::*;

fn retained_direct_dto(on_link: bool, relay_confirmed: bool) -> PeerConnection {
    let endpoint: SocketAddr = "192.0.2.9:41000".parse().unwrap();
    let mut conn = PeerConnection::new("diagnostic-policy-peer", "10.21.1.3");
    if on_link {
        conn.set_local_interface_networks(vec![LocalNetwork::new(
            "192.0.2.1".parse().unwrap(),
            24,
        )]);
    }
    let mut pair = CandidatePair::new_with_source(
        endpoint,
        0,
        if on_link {
            CandidatePairSource::Host
        } else {
            CandidatePairSource::StunObserved
        },
    );
    pair.state = CandidatePairState::Selected;
    pair.selected_at = Some(Instant::now());
    conn.candidate_pairs = vec![pair];
    conn.endpoint = Some(endpoint);
    conn.state = ConnectionState::Direct;
    conn.direct_health
        .record_success_with_latency(Duration::from_millis(1));
    if relay_confirmed {
        conn.relay_confirmed_at = Some(Instant::now());
        conn.relay_confirmed_generation = Some(0);
        conn.relay_confirmed_endpoint = Some("tcp://192.0.2.2:18081".to_owned());
    }
    conn
}

fn render(conn: &PeerConnection, selection: &PathSelection) -> PeerDiagnostics {
    PeerDiagnostics::from_connection_with_path_selection(
        conn,
        Some(selection),
        None,
        0,
        Some("192.0.2.1:41001".parse().unwrap()),
        None,
        true,
        false,
        None,
        None,
    )
}

#[test]
fn relay_only_diagnostic_keeps_explicit_selection_over_retained_direct() {
    for on_link in [false, true] {
        let mut conn = retained_direct_dto(on_link, true);
        let selection = PathSelection::relay(REASON_PATH_DIRECT_DISABLED, "explicit policy");
        conn.last_path_selection = Some(selection.clone());
        let value = serde_json::to_value(render(&conn, &selection)).unwrap();
        assert_eq!(value["active_path"], "relay");
        for field in ["current_path_selection", "last_path_selection"] {
            assert_eq!(value[field]["path"], "relay");
            assert_eq!(value[field]["reason_code"], REASON_PATH_DIRECT_DISABLED);
            assert_eq!(value[field]["direct_confirmed"], false);
        }
        assert_eq!(conn.state, ConnectionState::Direct);
        assert!(conn.public_key.is_empty() && conn.probe_mac_key.is_none());
    }
}

#[test]
fn relay_only_diagnostic_without_peer_confirmation_cannot_revive_direct() {
    for on_link in [false, true] {
        let conn = retained_direct_dto(on_link, false);
        let selection = PathSelection::relay(REASON_PATH_DIRECT_DISABLED, "explicit policy");
        let value = serde_json::to_value(render(&conn, &selection)).unwrap();
        assert!(value["active_path"].is_null());
        assert_eq!(value["current_path_selection"]["path"], "relay");
        assert_eq!(
            value["current_path_selection"]["reason_code"],
            REASON_PATH_DIRECT_DISABLED
        );
        assert!(value.get("relay_confirmed_endpoint").is_none());
    }
}

#[test]
fn relay_only_diagnostic_preserves_confirmed_direct_over_older_selector() {
    for on_link in [false, true] {
        let conn = retained_direct_dto(on_link, false);
        let old_selection =
            PathSelection::relay(REASON_PATH_DIRECT_NOT_CONFIRMED, "older selector");
        let value = serde_json::to_value(render(&conn, &old_selection)).unwrap();
        assert_eq!(value["active_path"], "direct");
        assert_eq!(value["current_path_selection"]["path"], "direct");
        assert_eq!(
            value["current_path_selection"]["reason_code"],
            REASON_PATH_DIRECT_CONFIRMED
        );
        assert_eq!(value["current_path_selection"]["direct_confirmed"], true);
    }
}
