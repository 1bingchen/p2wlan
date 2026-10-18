//! Pure input controls; no clock, system read/write, Full or owner is forged.
use super::*;

fn labels() -> WireWriteWindow {
    serde_json::from_value(serde_json::json!({
        "producer_scope":"abcdefabcdefabcdefabcdefabcdefab", "sequence":0,
        "request_nonce":"ab".repeat(16),
        "boot_id":"11111111-2222-3333-4444-555555555555",
        "original_started_ns":1_000_000_000u64, "original_sent_ns":1_000_000_000u64,
        "original_deadline_ns":2_000_000_000u64, "complete_returned_ns":1_000_000_001u64,
        "frame_bytes":191, "frame_sha256":"a".repeat(64)
    }))
    .unwrap()
}

#[test]
fn original_write_window_keeps_original_half_open_deadline_and_frame_size() {
    let wire = labels();
    assert!(wire.validate(1_000_000_001, 191, &[0xab; 16]).is_ok());
    assert!(wire.validate(1_999_999_999, 191, &[0xab; 16]).is_ok());
    assert!(wire.validate(2_000_000_000, 191, &[0xab; 16]).is_err());
    assert!(wire.validate(1_000_000_000, 191, &[0xab; 16]).is_err());
    assert!(wire.validate(1_000_000_002, 195, &[0xab; 16]).is_err());
}

#[test]
fn original_write_window_rejects_refill_overflow_wrong_sequence_and_digest() {
    let mut wire = labels();
    wire.original_deadline_ns += 1;
    assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
    wire = labels();
    wire.sequence = 1;
    assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
    wire = labels();
    wire.original_started_ns = u64::MAX;
    assert!(wire.validate(u64::MAX, 191, &[0xab; 16]).is_err());
    wire = labels();
    wire.frame_sha256 = "A".repeat(64);
    assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
}

#[test]
fn original_write_window_labels_cannot_deserialize_native_authority() {
    let mut value = serde_json::to_value(serde_json::json!({
        "producer_scope":"abcdefabcdefabcdefabcdefabcdefab", "sequence":0,
        "request_nonce":"ab".repeat(16),
        "boot_id":"11111111-2222-3333-4444-555555555555",
        "original_started_ns":1, "original_sent_ns":1,
        "original_deadline_ns":1_000_000_001u64, "complete_returned_ns":2,
        "frame_bytes":191, "frame_sha256":"a".repeat(64)
    }))
    .unwrap();
    for field in [
        "kernel_read",
        "native_os_write_verified",
        "canonical_current_owner_verified",
    ] {
        value[field] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<WireWriteWindow>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove(field);
    }
}

#[test]
fn original_write_window_matches_all_128_nonce_bits() {
    let mut wire = labels();
    for index in [0usize, 8, 15] {
        let mut nonce = [0xab; 16];
        nonce[index] ^= 1;
        wire.request_nonce = hex::encode(nonce);
        assert!(wire.validate(1_000_000_002, 191, &[0xab; 16]).is_err());
    }
}
