//! Finite original REQUEST -> remote decrypt/echo -> local decrypt/ACK controls.
//! No OriginalSome/source, crypto success, physical Full, or once is fabricated.
//! All explicitly spawned fixture workers are owned and cancel+joined; the
//! RelayClient's native reader/writer handles remain private to that client.
use super::*;
use std::result::Result;

#[path = "original_ack_tests/fixture.rs"]
mod fixture;

use fixture::{
    exercise, exercise_bootstrap_runtime_vip, EchoCase, IdentityCase, LifecycleCase, PathKind,
    RuntimeVipCase, Scenario,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_fresh_direct_original_request_echo_commits_native_once() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::Fresh).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_fresh_relay_original_request_echo_commits_native_once() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Fresh).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_real_echo_duplicate_once_and_new_canonical_are_distinct() -> Result<(), String>
{
    exercise(PathKind::Direct, Scenario::DuplicateAndNew).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_real_echo_duplicate_once_and_new_canonical_are_distinct() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::DuplicateAndNew).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_ack_without_source_cannot_consume_then_actual_source_is_fresh(
) -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::MissingSource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_ack_without_source_cannot_consume_then_actual_source_is_fresh(
) -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::MissingSource).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_native_handler_credits_only_the_actual_once_receipt() -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::NativeHandler).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_native_handler_credits_only_the_actual_once_receipt() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::NativeHandler).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_final_try_lock_conflicts_release_without_consuming_once() -> Result<(), String>
{
    exercise(PathKind::Direct, Scenario::Contention).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_final_try_lock_conflicts_release_without_consuming_once() -> Result<(), String> {
    exercise(PathKind::Relay, Scenario::Contention).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_session_replacement_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_session_replacement_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_session_counter_expiry_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::CounterExpiry),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_session_counter_expiry_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::CounterExpiry),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_generation_change_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_generation_change_rejects_old_ack_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_peer_readd_rejects_old_lifecycle_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::RemoveReadd),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_peer_readd_rejects_old_lifecycle_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::RemoveReadd),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_quarantine_rejects_ack_then_new_request_is_fresh() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::Quarantine),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_quarantine_rejects_ack_then_new_request_is_fresh() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::Quarantine),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_publication_withdrawal_rejects_ack_then_new_owner_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::UdpOwnerWithdraw),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_pending_decrypt_cannot_inherit_its_promotion_then_new_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::PendingPromotion),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_pending_decrypt_cannot_inherit_its_promotion_then_new_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::PendingPromotion),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_original_fifteen_second_window_expires_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::OriginalWindow),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_original_fifteen_second_window_expires_then_new_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::OriginalWindow),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_actual_unfenced_slow_direct_full_stays_unknown_then_fenced_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::LegacyUnknown),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_other_canonical_ack_cannot_consume_wrong_once() -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::OtherCanonicalAck),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_other_canonical_ack_cannot_consume_wrong_once() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::OtherCanonicalAck),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_foreign_wireguard_owner_cannot_borrow_original_sources(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::ForeignWireGuardOwner),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_foreign_wireguard_owner_cannot_borrow_original_sources(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::ForeignWireGuardOwner),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_enabled_room_owner_fails_closed_for_native_credit() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::RoomAuthority),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_enabled_room_owner_fails_closed_for_native_credit() -> Result<(), String>
{
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::RoomAuthority),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_ack_parser_corruption_is_rejected_without_credit() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::Identity(IdentityCase::ParserCorruption),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_ack_parser_corruption_is_rejected_without_credit() -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Identity(IdentityCase::ParserCorruption),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_queued_original_echo_rechecks_actual_session_before_send() -> Result<(), String>
{
    exercise(
        PathKind::Direct,
        Scenario::EchoTransfer(EchoCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_queued_original_echo_rechecks_actual_session_before_send() -> Result<(), String>
{
    exercise(
        PathKind::Relay,
        Scenario::EchoTransfer(EchoCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_queued_original_echo_rechecks_actual_generation_before_send(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::EchoTransfer(EchoCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_queued_original_echo_rechecks_actual_generation_before_send(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::EchoTransfer(EchoCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_queued_original_echo_rechecks_actual_publication_before_send(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::EchoTransfer(EchoCase::UdpOwnerWithdraw),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_direct_actual_previous_key_cannot_borrow_current_echo_then_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::PreviousReceive),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_relay_actual_previous_key_cannot_borrow_current_echo_then_active_request_is_fresh(
) -> Result<(), String> {
    exercise(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::PreviousReceive),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_actual_ack_before_observable_full_cannot_inherit_later_publication(
) -> Result<(), String> {
    exercise(PathKind::Direct, Scenario::PublicationOrder).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_fresh_marker_once_and_source_rejection() -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::RuntimeVip(RuntimeVipCase::FreshMarkerOnce),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_wrong_request_destination_including_bootstrap_is_rejected(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::RuntimeVip(RuntimeVipCase::WrongRequestDestination),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_stale_generation_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_direct_stale_session_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Direct,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_fresh_marker_once_and_source_rejection() -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::RuntimeVip(RuntimeVipCase::FreshMarkerOnce),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_wrong_request_destination_including_bootstrap_is_rejected(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::RuntimeVip(RuntimeVipCase::WrongRequestDestination),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_stale_generation_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::Generation),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_runtime_vip_relay_stale_session_rejects_old_ack_then_new_a_is_fresh(
) -> Result<(), String> {
    exercise_bootstrap_runtime_vip(
        PathKind::Relay,
        Scenario::Lifecycle(LifecycleCase::SessionReplace),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_managed_real_probe_request_echo_fresh_duplicate_and_new_a() -> Result<(), String> {
    fixture::exercise_publication(
        fixture::PublicationMode::ManagedPrimary,
        fixture::PublicationCase::ManagedFresh,
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_managed_actual_budget_revoke_rejects_old_ack_then_new_a() -> Result<(), String> {
    fixture::exercise_publication(
        fixture::PublicationMode::ManagedPrimary,
        fixture::PublicationCase::ManagedBudgetRevoke,
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_managed_original_budget_contention_releases_then_actual_ack_is_fresh(
) -> Result<(), String> {
    fixture::exercise_publication(
        fixture::PublicationMode::ManagedPrimary,
        fixture::PublicationCase::ManagedContention,
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_managed_queued_echo_withdrawn_owner_rejects_then_new_publication_a(
) -> Result<(), String> {
    fixture::exercise_publication(
        fixture::PublicationMode::ManagedPrimary,
        fixture::PublicationCase::ManagedQueuedEcho,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_dynamic_actual_socket_contention_releases_then_native_fresh_and_new_a(
) -> Result<(), String> {
    fixture::exercise_publication(
        fixture::PublicationMode::DynamicLan,
        fixture::PublicationCase::DynamicFresh,
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_dynamic_actual_detach_rejects_old_ack_then_new_socket_a() -> Result<(), String> {
    fixture::exercise_publication(
        fixture::PublicationMode::DynamicLan,
        fixture::PublicationCase::DynamicDetach,
    )
    .await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b28_dynamic_original_cap_eight_rejects_ninth_and_keeps_native_owner() -> Result<(), String>
{
    fixture::exercise_publication(
        fixture::PublicationMode::DynamicLan,
        fixture::PublicationCase::DynamicCapacity,
    )
    .await
}
