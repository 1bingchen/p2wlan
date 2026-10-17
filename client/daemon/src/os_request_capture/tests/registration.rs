use super::*;

fn empty_open() -> Value {
    let mut value = plan();
    value["flows"] = json!([]);
    value
}

#[tokio::test]
async fn original_descriptor_can_open_empty_then_register_exact_inputs_without_read_authority() {
    use std::io::Write;
    use tokio::io::AsyncBufReadExt;
    let (setup, mut parent) = setup(empty_open()).await;
    let before = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(before["registration_revision"], 0);
    assert_eq!(before["requests"], json!([]));
    let mut bytes = serde_json::to_vec(&json!({"op":"register", "plan":plan()})).unwrap();
    bytes.extend_from_slice(b"\n{\"op\":\"snapshot\"}\n{\"op\":\"close\"}\n");
    parent.write_all(&bytes).unwrap();
    parent.set_nonblocking(true).unwrap();
    let mut reader = tokio::io::BufReader::new(tokio::net::UnixStream::from_std(parent).unwrap());
    let task = tokio::spawn(setup.channel.run());
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let receipt: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(receipt["scope"], "registered_expected_inputs_only");
    assert_eq!(receipt["registration_revision"], 1);
    assert_eq!(receipt["added_requests"], 1);
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    let after: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(after["requests"][0]["read_events"], 0);
    assert_eq!(
        after["requests"][0]["producer_scope"],
        plan()["producer_scope"]
    );
    assert_eq!(after["requests"][0]["kernel_frame_read_complete"], false);
    assert_eq!(after["physical_send_verified"], false);
    assert_eq!(after["canonical_current_owner_verified"], false);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn duplicate_and_foreign_registration_preserve_the_original_slots_and_revision() {
    let (setup, _parent) = setup(empty_open()).await;
    setup.session.register(decode(&plan()).unwrap()).unwrap();
    let before = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    for field in ["same", "capture_id", "producer_scope"] {
        let mut value = plan();
        if field != "same" {
            value[field] = json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        }
        assert!(setup.session.register(decode(&value).unwrap()).is_err());
        let after = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
        assert_eq!(
            after["registration_revision"],
            before["registration_revision"]
        );
        assert_eq!(after["requests"], before["requests"]);
    }
}

#[tokio::test]
async fn appended_capacity_is_global_and_overflow_leaves_the_original_thousand_slots() {
    let (setup, _parent) = setup(empty_open()).await;
    let mut value = plan();
    value["flows"][0]["request_nonces"] = json!((1..=MAX_REQUESTS)
        .map(|n| format!("{n:032x}"))
        .collect::<Vec<_>>());
    setup.session.register(decode(&value).unwrap()).unwrap();
    let mut extra = plan();
    extra["producer_scope"] = json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    extra["flows"][0]["bind_port"] = json!(32124);
    assert!(matches!(
        setup.session.register(decode(&extra).unwrap()),
        Err(CaptureFailure::Capacity)
    ));
    let snapshot = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["requests"].as_array().unwrap().len(), MAX_REQUESTS);
    assert_eq!(snapshot["registration_revision"], 1);
}

#[tokio::test]
async fn actual_retired_descriptor_scope_cannot_be_rearmed_by_new_registration() {
    let (setup, _parent) = setup(empty_open()).await;
    drop(setup.channel);
    assert!(matches!(
        setup.session.register(decode(&plan()).unwrap()),
        Err(CaptureFailure::Expired)
    ));
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["requests"],
        json!([])
    );
}

#[tokio::test]
async fn duplicate_nested_plan_fields_are_rejected_by_the_actual_control_decoder() {
    use std::io::Write;
    let (setup, mut parent) = setup(empty_open()).await;
    let raw = serde_json::to_string(&plan())
        .unwrap()
        .replacen('{', "{\"schema_version\":1,", 1);
    parent
        .write_all(format!("{{\"op\":\"register\",\"plan\":{raw}}}\n").as_bytes())
        .unwrap();
    assert_eq!(
        setup.channel.run().await,
        Err(CaptureFailure::ControlProtocol)
    );
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["requests"],
        json!([])
    );
}

#[tokio::test]
async fn concurrent_registration_has_one_append_and_never_replaces_a_slot() {
    let (setup, _parent) = setup(empty_open()).await;
    let gate = Arc::new(std::sync::Barrier::new(9));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let session = setup.session.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                session.register(decode(&plan()).unwrap()).is_ok()
            })
        })
        .collect();
    gate.wait();
    assert_eq!(
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
    let snapshot = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
    assert_eq!(snapshot["registration_revision"], 1);
    assert_eq!(snapshot["requests"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn actual_new_unix_connection_opens_without_inheriting_an_arbitrary_descriptor() {
    use tokio::io::AsyncWriteExt;
    let path = std::path::PathBuf::from(format!(
        "/tmp/p2wlan-capture-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&path).unwrap();
    let socket = path.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let peers = peers();
    let server = async {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut bytes = serde_json::to_vec(&empty_open()).unwrap();
        bytes.push(b'\n');
        connection.write_all(&bytes).await.unwrap();
        connection
    };
    let (setup, connection) = tokio::join!(CaptureSetup::from_socket_path(&socket, &peers), server);
    let setup = setup.unwrap();
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["requests"],
        json!([])
    );
    drop(connection);
    setup.channel.run().await.unwrap();
    assert_eq!(
        serde_json::to_value(setup.session.snapshot().unwrap()).unwrap()["active"],
        false
    );
    drop(listener);
    std::fs::remove_dir_all(path).unwrap();
}
