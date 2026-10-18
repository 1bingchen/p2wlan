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
