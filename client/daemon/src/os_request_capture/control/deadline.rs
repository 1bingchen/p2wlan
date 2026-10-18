//! The sender's existing one-second exchange/window budget, clipped by the
//! original scope. Metadata admission never starts another request clock.
use super::*;

fn from_observation(
    sampled: tokio::time::Instant,
    now_ns: u64,
    original_end_ns: u64,
    scope_end: tokio::time::Instant,
) -> Result<tokio::time::Instant, CaptureFailure> {
    let left = original_end_ns
        .checked_sub(now_ns)
        .filter(|left| now_ns != 0 && *left != 0 && *left <= 1_000_000_000)
        .ok_or(CaptureFailure::InvalidPlan)?;
    Ok(scope_end.min(sampled + std::time::Duration::from_nanos(left)))
}

impl CaptureSession {
    pub(in crate::os_request_capture) fn metadata_command_deadline(
        &self,
        original_end_ns: u64,
    ) -> Result<tokio::time::Instant, CaptureFailure> {
        // Sample Tokio first: conversion cannot add receipt/validation time
        // to the original absolute native-clock deadline.
        let sampled = tokio::time::Instant::now();
        let now = super::super::clock::monotonic_ns().ok_or(CaptureFailure::InvalidPlan)?;
        from_observation(
            sampled,
            now,
            original_end_ns,
            tokio::time::Instant::from_std(self.expires()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_deadline_keeps_the_original_half_open_budget_and_scope() {
        let start = tokio::time::Instant::now();
        let scope = start + std::time::Duration::from_millis(5);
        assert_eq!(
            from_observation(start, 10, 20, scope).unwrap(),
            start + std::time::Duration::from_nanos(10)
        );
        assert_eq!(
            from_observation(start, 10, 1_000_000_010, scope).unwrap(),
            scope
        );
        for end in [0, 9, 10, 1_000_000_011, u64::MAX] {
            assert!(from_observation(start, 10, end, scope).is_err());
        }
        assert!(from_observation(start, 0, 10, scope).is_err());
    }
}
