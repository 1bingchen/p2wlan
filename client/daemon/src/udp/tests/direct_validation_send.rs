use super::*;
use std::future::Future as _;

async fn ordinary_fixture() -> (UdpTransport, UdpSocket, EncryptedPeerPacket) {
    let config = crate::config::Config::generate_default("https://control.test", "net").unwrap();
    let udp = UdpTransport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(PeerManager::new(config)),
    )
    .await
    .unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![4, 0, 1, 2],
        is_business: false,
    };
    (udp, receiver, packet)
}

#[tokio::test(start_paused = true)]
async fn expired_ordinary_validation_attempt_never_reaches_udp() {
    let (udp, receiver, packet) = ordinary_fixture().await;
    let result = udp
        .send_direct_validation_request_on_socket_until(
            &udp.socket,
            0,
            &packet,
            receiver.local_addr().unwrap(),
            None,
            Some(tokio::time::Instant::now()),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        receiver.try_recv_from(&mut [0; 16]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test(start_paused = true)]
async fn ordinary_validation_rechecks_deadline_after_socket_contention() {
    let (udp, receiver, packet) = ordinary_fixture().await;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
    let guard = udp.socket_state.lock().await;
    let mut send = Box::pin(udp.send_direct_validation_request_on_socket_until(
        &udp.socket,
        0,
        &packet,
        receiver.local_addr().unwrap(),
        None,
        Some(deadline),
    ));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(send.as_mut().poll(&mut context).is_pending());
    tokio::time::advance(Duration::from_millis(50)).await;
    drop(guard);
    assert!(send.await.is_err());
    assert_eq!(
        receiver.try_recv_from(&mut [0; 16]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
