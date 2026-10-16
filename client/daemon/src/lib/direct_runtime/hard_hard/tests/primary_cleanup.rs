// Hold the real ledger in AwaitingPeer without a live punch permit. A primary
// Direct commit must retire that old experiment before its original TTL; the
// cleanup watcher remains the only owner of socket and pending-probe cleanup.
async fn exercise_primary_direct_cleanup(before_watcher: bool) {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    set_hard_hard_test_now_ms(Some(4_000_000_000));
    let _clock = HardHardTestClockReset;
    let (peers, udp, identity, remote, _) = exact_birthday_runtime_fixture().await;
    let record = peers
        .hard_hard_session_snapshot_for_cleanup(
            &identity.peer_id,
            "birthday-runtime-session",
            &identity.session_token,
        )
        .await
        .unwrap();
    assert_eq!(record.state, HardHardSessionState::AwaitingPeer);
    let descriptor = HardHardCleanupDescriptor::from_record(&record);
    let primary = udp.local_addr().unwrap();
    assert_ne!(primary, identity.socket_local_endpoint);
    let commit = || {
        peers.record_direct_success_for_generation_with_local_endpoint(
            &identity.peer_id,
            Some(remote),
            identity.network_generation,
            Some(primary),
        )
    };
    let mut committed = if before_watcher {
        commit().await
    } else {
        false
    };
    let completion =
        spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
    if !before_watcher {
        wait_for_hard_hard_cleanup_owner(&peers, &descriptor).await;
        committed = commit().await;
    }

    let observed_start = tokio::time::Instant::now();
    let completed_before_expiry =
        tokio::time::timeout(Duration::from_millis(100), completion.wait())
            .await
            .is_ok();
    let observation_elapsed = observed_start.elapsed();
    let remaining_after_direct = udp.dynamic_socket_count().await;
    let session_active_after_direct = peers.hard_hard_session_is_active(&identity.peer_id).await;
    let pair_after_direct = peers.direct_commit_pair_snapshot_sync(&identity.peer_id);
    let direct_after_observation = peers.is_direct(&identity.peer_id).await;

    // Save the counterexample before explicit fixture teardown. Even on the
    // old implementation, cancel and join its original watcher before any
    // result assertion so a failed control leaves no detached test task.
    descriptor.cancellation.cancel_for_hard_hard_cleanup();
    wait_for_hard_hard_cleanup_completion(&completion).await;
    udp.detach_all_dynamic_punch_sockets("primary_direct_causal_control_cleanup")
        .await;
    eprintln!(
        "hh_primary_cleanup_control before_watcher={before_watcher} committed={committed} completed_before_expiry={completed_before_expiry} remaining_after_direct={remaining_after_direct} session_active_after_direct={session_active_after_direct} observation_ms={} original_ttl_ms=30000",
        observation_elapsed.as_millis()
    );
    assert!(committed && direct_after_observation);
    assert_eq!(
        pair_after_direct.and_then(|pair| pair.local_endpoint),
        Some(primary)
    );
    assert!(observation_elapsed < Duration::from_secs(1));
    assert_eq!(
        remaining_after_direct, 0,
        "primary Direct must retire the original AwaitingPeer socket without waiting for its TTL"
    );
    assert!(completed_before_expiry);
    assert!(!session_active_after_direct);
}

#[tokio::test(start_paused = true)]
async fn hard_hard_primary_direct_before_watcher_retires_original_awaiting_session() {
    exercise_primary_direct_cleanup(true).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_primary_direct_after_watcher_retires_original_awaiting_session() {
    exercise_primary_direct_cleanup(false).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_primary_direct_cleanup_preserves_the_selected_token_socket() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    set_hard_hard_test_now_ms(Some(4_000_000_000));
    let _clock = HardHardTestClockReset;
    let (peers, udp, identity, remote, _) = exact_birthday_runtime_fixture().await;
    let record = peers
        .hard_hard_session_snapshot_for_cleanup(
            &identity.peer_id,
            "birthday-runtime-session",
            &identity.session_token,
        )
        .await
        .unwrap();
    let descriptor = HardHardCleanupDescriptor::from_record(&record);
    let completion =
        spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
    wait_for_hard_hard_cleanup_owner(&peers, &descriptor).await;
    let committed = peers
        .record_direct_success_for_generation_with_local_endpoint(
            &identity.peer_id,
            Some(remote),
            identity.network_generation,
            Some(identity.socket_local_endpoint),
        )
        .await;
    let completed = tokio::time::timeout(Duration::from_millis(100), completion.wait())
        .await
        .is_ok();
    let remaining = udp.dynamic_socket_count().await;
    let active = peers.hard_hard_session_is_active(&identity.peer_id).await;
    descriptor.cancellation.cancel_for_hard_hard_cleanup();
    wait_for_hard_hard_cleanup_completion(&completion).await;
    udp.detach_all_dynamic_punch_sockets("selected_token_control_cleanup")
        .await;
    assert!(committed);
    assert!(
        !completed,
        "the selected HH socket is not a competing Direct path"
    );
    assert_eq!(remaining, 1);
    assert!(active);
}

#[tokio::test(start_paused = true)]
async fn hard_hard_primary_direct_cleanup_notifications_keep_the_original_expiry() {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    set_hard_hard_test_now_ms(Some(4_000_000_000));
    let _clock = HardHardTestClockReset;
    let (peers, udp, identity, _, _) = exact_birthday_runtime_fixture().await;
    let record = peers
        .hard_hard_session_snapshot_for_cleanup(
            &identity.peer_id,
            "birthday-runtime-session",
            &identity.session_token,
        )
        .await
        .unwrap();
    let descriptor = HardHardCleanupDescriptor::from_record(&record);
    let completion =
        spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
    wait_for_hard_hard_cleanup_owner(&peers, &descriptor).await;
    // Sequence changes alone are not Direct proof. Repeated candidate or
    // other-peer notifications must neither retire this owner nor renew TTL.
    for _ in 0..29 {
        tokio::time::advance(Duration::from_secs(1)).await;
        peers.bump_direct_commit_seq(&identity.peer_id);
        peers.bump_direct_commit_seq("unrelated-primary-control-peer");
        tokio::task::yield_now().await;
    }
    let before_expiry = udp.dynamic_socket_count().await;
    let active_before_expiry = peers.hard_hard_session_is_active(&identity.peer_id).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let completed = tokio::time::timeout(Duration::from_millis(100), completion.wait())
        .await
        .is_ok();
    let after_expiry = udp.dynamic_socket_count().await;
    descriptor.cancellation.cancel_for_hard_hard_cleanup();
    wait_for_hard_hard_cleanup_completion(&completion).await;
    udp.detach_all_dynamic_punch_sockets("original_expiry_control_cleanup")
        .await;
    assert_eq!(before_expiry, 1);
    assert!(active_before_expiry);
    assert!(
        completed,
        "notifications must not reset the original 30-second expiry"
    );
    assert_eq!(after_expiry, 0);
}

async fn exercise_selected_other_token_socket(same_token: bool) {
    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    set_hard_hard_test_now_ms(Some(4_000_000_000));
    let _clock = HardHardTestClockReset;
    let (peers, udp, identity, remote, _) = exact_birthday_runtime_fixture().await;
    let record = peers
        .hard_hard_session_snapshot_for_cleanup(
            &identity.peer_id,
            "birthday-runtime-session",
            &identity.session_token,
        )
        .await
        .unwrap();
    let descriptor = HardHardCleanupDescriptor::from_record(&record);
    let (selected_index, selected_socket) = udp.bind_fresh_punch_socket().await.unwrap();
    let selected_local = selected_socket.local_addr().unwrap();
    let selected_token = if same_token {
        identity.session_token.as_str()
    } else {
        "replacement-primary-control-token"
    };
    let handoff = udp
        .attach_dynamic_punch_socket(
            &identity.peer_id,
            selected_index,
            selected_socket,
            identity.network_generation,
            2,
            None,
        )
        .await
        .unwrap();
    assert!(
        handoff
            .commit_speculative_for_test(
                &udp,
                &identity.peer_id,
                selected_index,
                identity.network_generation,
                2,
            )
            .await
    );
    assert!(handoff.finalize().await);
    assert!(
        udp.tag_hard_hard_socket(&identity.peer_id, selected_index, selected_token)
            .await
    );
    assert_eq!(
        udp.dynamic_socket_count().await,
        2,
        "the birthday receiver commit must preserve the original receiver"
    );
    let committed = peers
        .record_direct_success_for_generation_with_local_endpoint(
            &identity.peer_id,
            Some(remote),
            identity.network_generation,
            Some(selected_local),
        )
        .await;
    let completion =
        spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
    let completed = tokio::time::timeout(Duration::from_millis(100), completion.wait())
        .await
        .is_ok();
    let remaining = udp.dynamic_socket_count().await;
    let selected_still_attached = udp
        .hard_hard_socket_indices_for_token(&identity.peer_id, selected_token)
        .await
        .contains(&selected_index);
    let old_session_active = peers.hard_hard_session_is_active(&identity.peer_id).await;
    descriptor.cancellation.cancel_for_hard_hard_cleanup();
    wait_for_hard_hard_cleanup_completion(&completion).await;
    udp.detach_all_dynamic_punch_sockets("selected_other_token_control_cleanup")
        .await;
    assert!(committed);
    assert_eq!(completed, !same_token);
    assert_eq!(old_session_active, same_token);
    assert_eq!(remaining, if same_token { 2 } else { 1 });
    assert!(selected_still_attached);
}

#[tokio::test(start_paused = true)]
async fn hard_hard_primary_direct_cleanup_preserves_a_later_selected_socket_of_the_same_token() {
    exercise_selected_other_token_socket(true).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_primary_direct_cleanup_cannot_detach_the_selected_replacement_token() {
    exercise_selected_other_token_socket(false).await;
}
