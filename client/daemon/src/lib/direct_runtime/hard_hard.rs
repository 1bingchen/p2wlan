// Hard↔Hard synchronized fresh-mapping rendezvous.
//
// This is intentionally a narrow integration around the existing fresh
// mapping, `peer_offer_fresh`, Probe v2, pending-probe and Direct validation
// machinery. Negotiated hh2 adds a bounded agreement and pair nomination;
// the existing encrypted validation and PathSelector remain authoritative.

use crate::udp::{
    apply_live_birthday_counters, hard_hard_birthday_socket_count, hard_hard_birthday_wave_count,
    update_birthday_sweep_counters, BirthdaySweepFailureKind, BirthdaySweepProgress,
    BirthdaySweepReport, UdpProbeRxSnapshot,
};

include!("hard_hard/test_gates.rs");
include!("hard_hard/coordination.rs");
include!("hard_hard/diagnostics.rs");
include!("hard_hard/wire_v2.rs");
include!("hard_hard/cleanup.rs");
include!("hard_hard/probe.rs");
include!("hard_hard/prepared.rs");
include!("hard_hard/agreement.rs");
include!("hard_hard/confirmation.rs");
include!("hard_hard/initiator.rs");
include!("hard_hard/responder.rs");
include!("hard_hard/tests.rs");
include!("hard_hard/wire_v2_tests.rs");
include!("hard_hard/diagnostics_tests.rs");
