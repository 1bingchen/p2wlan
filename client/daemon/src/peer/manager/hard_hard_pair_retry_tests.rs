use super::*;

#[test]
fn definite_non_send_retries_are_bounded_without_refunding_unknown_delivery() {
    for ceiling in [
        HARD_HARD_PAIR_CHECK_ATTEMPTS,
        HARD_HARD_PAIR_CONFIRM_ATTEMPTS,
    ] {
        let (mut attempts, mut deferrals, mut scheduled) = (0, 0, 0);
        while attempts < ceiling {
            attempts += 1;
            scheduled += 1;
            complete_hard_hard_pair_send_attempt(
                &mut attempts,
                &mut deferrals,
                ceiling,
                HardHardPairSendOutcome::RetryableNotSent,
            );
        }
        assert_eq!(scheduled, ceiling * 2);
        assert_eq!(deferrals, ceiling);

        let (mut attempts, mut deferrals) = (1, 0);
        complete_hard_hard_pair_send_attempt(
            &mut attempts,
            &mut deferrals,
            ceiling,
            HardHardPairSendOutcome::DeliveryUnknown,
        );
        assert_eq!((attempts, deferrals), (1, 0));
        complete_hard_hard_pair_send_attempt(
            &mut attempts,
            &mut deferrals,
            ceiling,
            HardHardPairSendOutcome::Stopped,
        );
        assert_eq!(attempts, ceiling);
    }
}

#[test]
fn budget_wait_survives_one_second_without_using_physical_retry_allowance() {
    let ceiling = HARD_HARD_PAIR_CHECK_ATTEMPTS;
    let (mut attempts, mut deferrals) = (0, 0);
    // Seven 150ms scheduling turns cross the one-second sliding window.
    // The caller still enforces the unchanged discovery deadline.
    for _ in 0..7 {
        attempts += 1;
        complete_hard_hard_pair_send_attempt(
            &mut attempts,
            &mut deferrals,
            ceiling,
            HardHardPairSendOutcome::BudgetDeferred,
        );
    }
    assert_eq!((attempts, deferrals), (0, 0));
    for sent in 1..=ceiling {
        attempts += 1;
        complete_hard_hard_pair_send_attempt(
            &mut attempts,
            &mut deferrals,
            ceiling,
            HardHardPairSendOutcome::Sent,
        );
        assert_eq!(attempts, sent);
    }
}
