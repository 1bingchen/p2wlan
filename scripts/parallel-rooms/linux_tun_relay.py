"""Separate same-host Relay fixture and serialized-data checks.

Configuration, readiness and matching dictionaries never grant native credit.
The caller must first collect the original owned kernel/Full transactions.
"""
from collections import Counter
import json
import secrets

import linux_tun_contract as original

SCOPE = "linux_same_host_kernel_tun_relay_application"
ENDPOINT = "tcp://192.0.2.2:18081"
REGION, AUDIENCE, KEY_ID = "local", "kernel-relay", "kernel-relay"


def manifest(run_nonce, round_nonce, protocol):
    if protocol not in {"udp", "tcp"}:
        raise ValueError("Relay application protocol must be udp or tcp")
    return [entry for entry in original.manifest(run_nonce, round_nonce) if entry["protocol"] == protocol]


def summarize(entries):
    if (len(entries) != 2 or entries[0]["protocol"] not in {"udp", "tcp"}
            or [(e["protocol"], e["direction"]) for e in entries]
            != [(entries[0]["protocol"], direction) for direction in ["a-to-b", "b-to-a"]]
            or any(e["count"] != original.COUNT for e in entries)):
        raise ValueError("original two-direction Relay16 manifest changed")
    counts, missing = Counter(), 0
    for entry in entries:
        records = entry["records"]
        if records is None:
            missing += 1
            counts["not_started" if entry["outcome"] == "not_started" else "unknown"] += original.COUNT
        else:
            if len(records) != original.COUNT:
                raise ValueError("original Relay eight request slots changed")
            counts.update(row["status"] for row in records)
    return dict(denominator="all_16_prescheduled_relay_requests_including_missing_entries",
                prescheduled_requests=16, success_requests=counts["success"], terminal_counts=dict(counts),
                missing_entry_count=missing, all_responses_observed=counts["success"] == 16 and missing == 0,
                canonical_current_owner_verified=None, exact_direct_request_attribution=None,
                other_platforms_verified=None, public_network_verified=None)


def parse_keypair(text):
    parts = text.split()
    if len(parts) != 2 or any(len(p) != 64 or any(c not in "0123456789abcdef" for c in p) for p in parts):
        raise ValueError("ephemeral Relay key generator output invalid")
    return parts


def readiness(snapshot, peer_id):
    """Diagnostic preflight only; final native transactions remain mandatory."""
    peers = [p for p in snapshot.get("peers", []) if p.get("node_id") == peer_id]
    peer = peers[0] if len(peers) == 1 else {}
    selection = peer.get("current_path_selection") or {}
    generation = snapshot.get("network_generation")
    ready_id, confirmed_id = (peer.get(k) for k in ["relay_ready_connection_id", "relay_confirmed_connection_id"])
    generations = [generation, peer.get("relay_ready_generation"), peer.get("relay_confirmed_generation")]
    ready = (snapshot.get("relay_connected") is True and peer.get("online") is True
             and all(type(value) is int and value >= 0 for value in generations)
             and generations[0] == generations[1] == generations[2]
             and type(ready_id) is int and type(confirmed_id) is int and ready_id > 0 and ready_id == confirmed_id
             and peer.get("relay_ready_endpoint") == peer.get("relay_confirmed_endpoint") == ENDPOINT
             and selection.get("path") == "relay" and selection.get("reason_code") == "path_direct_disabled")
    return dict(scope="diagnostic_relay_selection_readiness_only", ready=ready, native_evidence=False,
                expected_peer=peer_id, observed_peer_count=len(peers), network_generation=generation,
                relay_ready_generation=peer.get("relay_ready_generation"),
                relay_confirmed_generation=peer.get("relay_confirmed_generation"),
                relay_ready_connection_id=ready_id, relay_confirmed_connection_id=confirmed_id,
                relay_ready_endpoint=peer.get("relay_ready_endpoint"),
                relay_confirmed_endpoint=peer.get("relay_confirmed_endpoint"),
                observed_connection_active_path=peer.get("active_path"),
                current_business_selection=selection.get("path"), selection_reason_code=selection.get("reason_code"))


def wait(lab, initial, report):
    observations = report.setdefault("relay_readiness", {})
    for name, remote in [("a1", "b1"), ("b1", "a1")]:
        def observe():
            value = readiness(lab.status(name), initial[remote]["node_id"])
            observations[name] = value
            return value if value["ready"] else None
        # Reuse the original ninety-second readiness bound, before any
        # application request plan/window. Never warm up or replay business.
        lab.wait(name + " original confirmed Relay selection readiness", observe)


def preserve_service_logs(lab, redact):
    for role in ["control", "relay"]:
        source = lab.root / (role + ".console")
        with source.open("rb") as stream:
            stream.seek(0, 2)
            stream.seek(max(0, stream.tell() - 256 * 1024))
            lines = stream.read(256 * 1024).decode(errors="replace").splitlines()[-1000:]
        destination = lab.debug_dir / ("service-" + role + ".console.log")
        destination.write_text("\n".join(redact(line) for line in lines) + "\n")
        destination.chmod(0o600)


def start(lab, report):
    # The existing synchronous command slot retains its twenty-second bound.
    # Keys stay in the private child environment, never in report or saved argv.
    seed, public = parse_keypair(lab.cmd("control", [str(lab.args.relay_keygen)]).stdout)
    lab.spawn("control", "relay", [str(lab.args.relay), "-bind", "192.0.2.2:18081",
              "-require-auth", "-allow-legacy-unauthenticated=false", "-allow-insecure-plaintext", "-relay-region", REGION,
              "-relay-audience", AUDIENCE],
              env={"RELAY_TICKET_KEYRING_JSON": json.dumps({KEY_ID: public})})
    lab.spawn("control", "control", [str(lab.args.control)], env={
        "PORT": "8080", "DB_PATH": str(lab.root / "control.db"), "JWT_SECRET": secrets.token_hex(32),
        "RELAY_TICKET_SIGNER_JSON": json.dumps({"active": {"kid": KEY_ID, "private_key": seed}}),
        "RELAY_CATALOG_JSON": json.dumps([dict(region=REGION, audience=AUDIENCE, endpoint=ENDPOINT)]),
    })
    report["relay_fixture"] = dict(endpoint=ENDPOINT, region=REGION, audience=AUDIENCE,
        authenticated_registration_required=True, outer_transport="development_plaintext_tcp",
        end_to_end_encryption_configuration_is_not_native_evidence=True,
        supplementary_application_protocol=lab.args.relay_application,
        expected_process_groups=8, original_process_group_cap=11,
        original_Direct80_denominator_unchanged=True)


def path_summary(entries):
    """Compare retained node data; the caller owns all native prerequisites."""
    counts, qualified = Counter(), 0
    for entry in entries:
        result = entry.get("original_kernel_reads", {})
        rows = result.get("requests", [])
        if len(rows) != 8 or result.get("passed") is not True or result.get("full128_owner_evidence_complete") is not True:
            continue
        for row in rows:
            for name in ["source_native_transaction", "response_native_transaction"]:
                value = row.get(name, {})
                if row.get("full128_owner_qualified") is True and value.get("matched") is True:
                    counts[value.get("physical_path", "unknown")] += 1
                    qualified += 1
    complete = len(entries) == 2 and qualified == 32 and counts == {"relay": 32}
    return dict(scope="retained_final_native_path_comparison_only", expected_node_records=32,
                collected_qualified_node_records=qualified, paths=dict(counts), complete=complete,
                missing_or_nonrelay_node_records=32 - counts["relay"],
                configuration_or_readiness_grants_no_native_credit=True)
