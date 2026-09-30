"""Round-scoped mapping/fault evidence; never infer application success here."""

from __future__ import annotations

import json
import argparse
import os
from pathlib import Path
import struct
from typing import Any


def summarize_mapping_evidence(round_dir: Path, expected: dict[str, str]) -> dict[str, Any]:
    errors: list[str] = []
    features: dict[str, Any] = {}
    try:
        banners = [line.partition("=")[2] for line in (round_dir / "nat-sim.out").read_text().splitlines()
                   if line.startswith("NAT_FEATURES=")]
        if len(banners) != 1:
            raise ValueError("feature_banner_count")
        features = json.loads(banners[0])
        if not isinstance(features, dict):
            raise ValueError("feature_banner_shape")
    except (OSError, ValueError):
        errors.append("nat_features_missing_or_invalid")
    expected_features = {
        "egress_capture": "shim",
        "unassigned_egress_listeners": 0,
        "direct_gate_preserves_source_allocations": True,
        "strict_filtering_a": expected.get("STRICT_FILTERING_A", "0") == "1",
        "strict_filtering_b": expected.get("STRICT_FILTERING_B", "0") == "1",
        "consume_a": int(expected.get("CONSUME_A", "0")),
        "consume_b": int(expected.get("CONSUME_B", "0")),
        "sweep_noise_every": int(expected.get("SWEEP_NOISE_EVERY", "0")),
        "sweep_noise_count": int(expected.get("SWEEP_NOISE_COUNT", "0")),
        "sweep_noise_limit": int(expected.get("SWEEP_NOISE_LIMIT", "64")),
    }
    for field, value in expected_features.items():
        if features.get(field) != value or type(features.get(field)) is not type(value):
            errors.append(f"nat_feature_mismatch:{field}")
    background_devices = int(expected.get("BACKGROUND_DEVICES", "0"))
    if background_devices:
        for field in ("background_devices", "background_flows", "background_interval_ms"):
            wanted = int(expected.get(field.upper(), {"background_flows": "32", "background_interval_ms": "250"}.get(field, "0")))
            if features.get(field) != wanted:
                errors.append(f"nat_feature_mismatch:{field}")
    background = {nat: {"started": 0, "completed": 0, "failed": 0} for nat in ("A", "B")}
    background_times = {nat: [] for nat in ("A", "B")}
    capture_window = {nat: [] for nat in ("A", "B")}
    captures = {"A": 0, "B": 0}
    capture_bytes = {"A": 0, "B": 0}
    gateways: dict[str, int] = {}
    observed: dict[tuple[str, str], int] = {}
    initial_noise: dict[tuple[str, str], int] = {}
    first_noise_sequence: dict[tuple[str, str], int] = {}
    first_peer: set[tuple[str, str]] = set()
    noise = {"A": {"post_measurement_before_first_peer": 0, "during_sweep": 0},
             "B": {"post_measurement_before_first_peer": 0, "during_sweep": 0}}
    mappings: dict[str, dict[str, str]] = {"A": {}, "B": {}}
    unbound = {"A": 0, "B": 0}
    rejected = 0
    last_sequence = 0
    try:
        with (round_dir / "nat-trace.jsonl").open() as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                    sequence = row.get("sequence")
                    if type(sequence) is not int or sequence <= last_sequence:
                        raise ValueError("trace_sequence")
                    last_sequence = sequence
                except (ValueError, AttributeError):
                    errors.append("mapping_trace_invalid_row")
                    continue
                event, nat = row.get("event"), row.get("nat")
                if not isinstance(event, str) or (nat is not None and not isinstance(nat, str)):
                    errors.append("mapping_trace_invalid_identity_type")
                    continue
                if nat not in captures:
                    continue
                key = (nat, str(row.get("client")))
                if event == "egress_gateway_ready":
                    gateways[nat] = row.get("gateway_port")
                    if type(gateways[nat]) is not int or not 1 <= gateways[nat] <= 65535:
                        errors.append("egress_gateway_port_invalid")
                elif event == "egress_captured":
                    captures[nat] += 1
                    capture_window[nat].append(sequence)
                    if type(row.get("bytes")) is not int or row["bytes"] < 0:
                        errors.append("egress_capture_bytes_missing")
                    else:
                        capture_bytes[nat] += row["bytes"]
                elif event.startswith("background_flow_"):
                    kind = event.removeprefix("background_flow_")
                    if kind in background[nat]:
                        background[nat][kind] += 1
                        if kind == "started":
                            background_times[nat].append(sequence)
                elif event in {"egress_rejected", "outbound_queue_rejected", "outbound_mapping_error"}:
                    rejected += 1
                elif event == "stun_mapping_observed":
                    observed[key] = sequence
                elif event == "mapping_consumed":
                    stage = row.get("stage")
                    if stage not in noise[nat]:
                        errors.append("mapping_noise_unknown_stage")
                        continue
                    noise[nat][stage] += 1
                    if stage == "post_measurement_before_first_peer":
                        if key not in observed or key in first_peer:
                            errors.append("mapping_noise_outside_measurement_peer_window")
                        initial_noise[key] = initial_noise.get(key, 0) + 1
                        first_noise_sequence.setdefault(key, sequence)
                    elif key not in first_peer or not row.get("prior_peer_mappings", 0):
                        errors.append("mapping_noise_not_during_sweep")
                elif event == "peer_mapping_started" and row.get("prior_peer_mappings") == 0:
                    first_peer.add(key)
                    if key in observed:
                        wanted = expected_features[f"consume_{nat.lower()}"]
                        if initial_noise.get(key, 0) != wanted:
                            errors.append(f"{nat.lower()}_initial_noise_count_mismatch")
                        if wanted and first_noise_sequence.get(key, 0) <= observed[key]:
                            errors.append("mapping_noise_precedes_last_measurement")
                elif event == "mapping_bound":
                    endpoint, destination = row.get("public_endpoint"), row.get("destination")
                    if not isinstance(endpoint, str) or not isinstance(destination, str):
                        errors.append("mapping_bound_identity_missing")
                    else:
                        if endpoint in mappings[nat] and mappings[nat][endpoint] != destination:
                            errors.append("mapping_endpoint_reassigned_without_expiry")
                        mappings[nat][endpoint] = destination
                elif event == "outbound_destination_unmapped":
                    unbound[nat] += 1
    except OSError:
        errors.append("mapping_trace_missing")
    shim_counters: dict[str, Any] = {}
    for nat in captures:
        if nat not in gateways or not captures[nat]:
            errors.append(f"{nat.lower()}_complete_egress_capture_missing")
        try:
            raw = (round_dir / f"node-{nat.lower()}.egress-stats").read_bytes()
            magic, packets, byte_count, send_errors, gateway_port = struct.unpack("=8sQQQQ", raw)
            if magic != b"P2CNT001" or gateway_port != gateways.get(nat):
                raise ValueError("shim_counter_identity")
            shim_counters[nat] = {"datagrams": packets, "bytes": byte_count, "send_errors": send_errors}
            if packets != captures[nat] or byte_count != capture_bytes[nat]:
                errors.append(f"{nat.lower()}_egress_capture_loss_or_duplicate")
        except (OSError, ValueError, struct.error):
            errors.append(f"{nat.lower()}_shim_send_counters_missing_or_invalid")
        if expected_features[f"consume_{nat.lower()}"] and not noise[nat]["post_measurement_before_first_peer"]:
            errors.append(f"{nat.lower()}_post_measurement_noise_not_exercised")
        if expected_features["sweep_noise_every"] and expected_features["sweep_noise_count"]:
            if not noise[nat]["during_sweep"]:
                errors.append(f"{nat.lower()}_sweep_noise_not_exercised")
        if noise[nat]["during_sweep"] > expected_features["sweep_noise_limit"]:
            errors.append(f"{nat.lower()}_sweep_noise_limit_exceeded")
        if background_devices:
            wanted = background_devices * int(expected.get("BACKGROUND_FLOWS", "32"))
            if background[nat] != {"started": wanted, "completed": wanted, "failed": 0}:
                errors.append(f"{nat.lower()}_background_traffic_incomplete")
            window = capture_window[nat]
            overlap = bool(window) and any(window[0] <= event <= window[-1] for event in background_times[nat])
            if not overlap:
                errors.append(f"{nat.lower()}_background_traffic_no_overlap")
    if rejected:
        errors.append("egress_or_queue_rejection")
    pairs = sum(mappings["B"].get(destination) == endpoint
                for endpoint, destination in mappings["A"].items())
    return {
        "schema_version": 1,
        "scope": "round_simulator_mappings_not_attempt_or_business_success",
        "capture": "libc_sendto_sendmsg",
        "valid": not errors,
        "errors": sorted(set(errors)),
        "egress_datagrams": captures,
        "egress_bytes": capture_bytes,
        "shim_send_counters": shim_counters,
        "unmapped_destination_datagrams": unbound,
        "bound_mapping_counts": {nat: len(values) for nat, values in mappings.items()},
        "reciprocal_mapping_pairs": pairs,
        "injected_allocations": noise,
        "background_traffic": background,
        "features": {key: features.get(key) for key in expected_features},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("round_dir", type=Path)
    args = parser.parse_args()
    evidence = summarize_mapping_evidence(args.round_dir, dict(os.environ))
    (args.round_dir / "mapping-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"mapping_evidence_valid": evidence["valid"], "errors": evidence["errors"]}))
    raise SystemExit(0 if evidence["valid"] else 1)
