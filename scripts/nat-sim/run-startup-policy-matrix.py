#!/usr/bin/env python3
"""Prepare or run four cold policy calibration cases without changing product defaults."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from launch_identity import (SHA256, canonical, digest_file, load_object, read_launch_evidence,
                             source_identity, validate_artifact_set, verify_snapshot)

POLICIES = {"direct-first": "--prefer-direct", "auto": "--prefer-relay"}
CASES = (("reachable-direct", "direct-first", 0), ("reachable-direct", "auto", 0),
         ("direct-blackhole", "auto", 100), ("direct-blackhole", "direct-first", 100))
HOST_KEYS = {"PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL",
             "CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
             "GOENV", "GOPATH", "GOCACHE", "CC", "SDKROOT", "DEVELOPER_DIR"}


def daemon_flag(policy: str, legacy_prefer_relay: str = "0") -> str:
    if not policy:
        # Preserve the old harness behavior, including values other than 1.
        return "--relay-only" if legacy_prefer_relay == "1" else ""
    if policy not in POLICIES:
        raise ValueError("startup_policy_must_be_direct_first_or_auto")
    if legacy_prefer_relay not in {"", "0"}:
        raise ValueError("startup_policy_conflicts_with_legacy_prefer_relay")
    return POLICIES[policy]


def record_policy_input(path: Path, role: str, policy: str, argv: list[str]) -> None:
    if policy not in POLICIES:
        raise ValueError("explicit_startup_policy_required")
    expected = daemon_flag(policy)
    flags = [arg for arg in argv if arg in {*POLICIES.values(), "--relay-only"}]
    if role not in {"node-a", "node-b"} or flags != [expected]:
        raise ValueError("actual_policy_argv_mismatch")
    # These are public projections of the same array passed to the original
    # exec recorder; keep private config values protected by its existing hash.
    record = {"schema_version": 1, "role": role, "requested_policy": policy,
              "actual_policy_flags": flags, "argument_count": len(argv),
              "argv_sha256": hashlib.sha256(canonical(argv)).hexdigest(),
              "overlay_any_path": "--overlay-any-path" in argv,
              "artificial_business_gate": "--overlay-start-gate-file" in argv}
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(canonical(record) + b"\n")


def case_environment(base: dict, directory: Path, scenario: str, policy: str, seed: int) -> dict:
    env = {key: value for key, value in base.items() if key in HOST_KEYS}
    if scenario not in {"reachable-direct", "direct-blackhole"}:
        raise ValueError("unknown_fixed_scenario")
    flag = daemon_flag(policy)
    env.update(MODE="normal" if scenario == "reachable-direct" else "relay-only",
               STARTUP_POLICY=policy, ROUNDS="1", EGRESS_CAPTURE="shim",
               STRICT_FILTERING="0", STRICT_FILTERING_A="0", STRICT_FILTERING_B="0",
               STEP_A="1", STEP_B="1", CONSUME_A="0", CONSUME_B="0",
               NORMAL_OBSERVE_S="30", DIRECT_TIMEOUT_S="60", OVERLAY_TIMEOUT_S="60",
               ROUND_TIMEOUT_S="150", OVERLAY_BURST="0" if scenario == "reachable-direct" else "256",
               NAT_SEED_BASE=str(seed), NAT_SIM_ARTIFACT_DIR=str(directory),
               EXPERIMENT_VARIANT=f"startup-{policy}", EXPERIMENT_SCENARIO=scenario)
    assert flag != "--relay-only"
    return env


def native_marker_available(root: Path) -> bool:
    owner = root / "client/daemon/src/lib/daemon/overlay_validate/native_ack.rs"
    return owner.is_file() and "native_original_ack=true" in owner.read_text()


def make_plan(root: Path, output: Path, seed: int, base: dict) -> dict:
    rows = []
    for scenario, policy, offset in CASES:
        directory = output / f"{scenario}-{policy}"
        env = case_environment(base, directory, scenario, policy, seed + offset)
        rows.append({"scenario": scenario, "policy": policy, "cold_repetitions": 1,
                     "seed_base": seed + offset, "actual_nat_seed": seed + offset + 1,
                     "daemon_flag": POLICIES[policy], "command": ["bash", "scripts/nat-sim/nat-sim-smoke.sh"],
                     "environment": env, "directory": str(directory), "status": "not_run",
                     "native_first_ack": {side: None for side in ("a", "b")}})
    return {"schema_version": 1, "source": source_identity(root),
            "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root).decode().strip(),
            "scope": "mocktun_ipv4_cold_start_policy_calibration", "requested_cases": 4,
            "retries": 0, "cold_only": True, "cases": rows,
            "native_marker_source_available": native_marker_available(root),
            "validation_baseline": "pending_source_integration_and_native_acceptance",
            "budgets": {"normal_observe_s": 30, "direct_s": 60, "overlay_s": 60,
                        "round_s": 150, "finalize_s": 15, "outer_s": 360, "term_grace_s": 10,
                        "campaign_outer_s": 1500, "campaign_execution_s": 1470,
                        "build_only_outer_s": 360},
            "product_policy_windows_ms": {"direct_first": 5000, "relay_startup": 3000},
            "connection_to_first_business_ms": None,
            "limits": ["four_denominator_includes_all_failures", "no_performance_or_policy_adoption_claim",
                       "no_real_application_or_kernel_tun", "launch_to_daemon_timeline_alignment_unknown"]}


def native_first_ack(status: dict) -> dict | None:
    peers = status.get("peers", [])
    if not isinstance(peers, list) or len(peers) != 1 or not isinstance(peers[0], dict):
        return None
    peer_id = peers[0].get("node_id")
    if not isinstance(peer_id, str):
        return None
    timeline = status.get("connection_timeline")
    if not isinstance(timeline, dict) or not isinstance(timeline.get("events"), list):
        return None
    events = timeline["events"]
    eligible = []
    for event in events:
        if not isinstance(event, dict):
            continue
        detail = event.get("detail")
        generation = event.get("connection_generation")
        if (event.get("event") != "first_usable_bidirectional_overlay_ms"
                or event.get("peer_id") != peer_id or type(generation) is not int or generation < 0
                or not isinstance(detail, str) or "native_original_ack=true" not in detail.split()
                or f"generation={generation}" not in detail.split()
                or event.get("path") not in {"direct", "relay"} or type(event.get("at_ms")) is not int
                or event["at_ms"] < 0):
            continue
        eligible.append(event)
    if not eligible:
        return None
    event = min(eligible, key=lambda item: item["at_ms"])
    return {"timeline_origin_to_native_ack_ms": event["at_ms"], "peer_id": peer_id,
            "generation_at_native_commit": event["connection_generation"],
            "final_generation": status.get("network_generation"), "path": event["path"], "event": event}


def load_json(path: Path) -> dict:
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("evidence_json_too_large")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("evidence_json_not_object")
    return value


def collect_case(row: dict, exit_code: int, source: dict) -> dict:
    directory = Path(row["directory"])
    round_dir = directory / "round-1"
    errors, snapshots, native, inputs = [], {}, {}, {}
    launch = read_launch_evidence(directory, source)
    errors.extend(f"launch_identity:{error}" for error in launch["errors"])
    launch_by_role = {item["record"]["role"]: item["record"] for item in launch["records"]}
    if exit_code:
        errors.append(f"smoke_exit:{exit_code}")
    for side in ("a", "b"):
        role = f"node-{side}"
        try:
            policy = load_json(round_dir / f"{role}.startup-policy.json")
            config = launch_by_role[role]["configuration"]
            if (policy.get("requested_policy") != row["policy"]
                    or policy.get("actual_policy_flags") != [row["daemon_flag"]]
                    or policy.get("role") != role or policy.get("overlay_any_path") is not True
                    or policy.get("artificial_business_gate") is not False
                    or type(policy.get("argument_count")) is not int
                    or policy.get("argument_count") != config["argument_count"]):
                raise ValueError("actual_policy_input_mismatch")
            digest = policy.get("argv_sha256")
            if (not isinstance(digest, str) or not SHA256.fullmatch(digest)
                    or digest != config.get("argv_sha256")
                    or config.get("startup_policy_flags") != [row["daemon_flag"]]):
                raise ValueError("actual_policy_argv_identity_mismatch")
            inputs[side] = policy
            status = load_json(round_dir / f"{role}.status.json")
            snapshots[side] = status
            if (type(status.get("process_id")) is not int
                    or status["process_id"] != launch_by_role[role]["pid"]):
                raise ValueError("native_status_launch_process_mismatch")
            native[side] = native_first_ack(status)
            if native[side] is None:
                errors.append(f"{side}:native_original_ack_missing_or_invalid")
            peer = status["peers"][0]
            if row["scenario"] == "reachable-direct":
                if peer.get("active_path") != "direct":
                    errors.append(f"{side}:final_confirmed_direct_missing")
            elif (peer.get("active_path") != "relay" or native[side] is None
                  or native[side]["path"] != "relay"):
                errors.append(f"{side}:blackhole_relay_business_missing")
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            errors.append(f"{side}:required_evidence_missing_or_invalid")
            native.setdefault(side, None)
    retained = {}
    if row["scenario"] == "reachable-direct":
        # Reuse the original normal collector for recent, bidirectional
        # Direct business rather than accepting the final selector alone.
        spec = importlib.util.spec_from_file_location(
            "startup_normal_gate", Path(__file__).with_name("run-network-matrix.py"))
        normal_gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(normal_gate)
        retained["normal_direct_gate"] = normal_gate.read_case(directory, exit_code, True, source)
        errors.extend(f"normal_direct_gate:{error}"
                      for error in retained["normal_direct_gate"]["errors"])
    for name in ("nat-evidence", "mapping-evidence", "cleanup"):
        try:
            retained[name] = load_json(round_dir / f"{name}.json")
        except (OSError, ValueError):
            errors.append(f"missing:{name}")
    if retained.get("nat-evidence", {}).get("result") != "pass":
        errors.append("original_business_gate_failed")
    if retained.get("mapping-evidence", {}).get("valid") is not True:
        errors.append("original_mapping_evidence_failed")
    cleanup = retained.get("cleanup", {})
    if cleanup.get("all_reaped") is not True or cleanup.get("forced_termination") is not False:
        errors.append("original_owned_cleanup_failed")
    return {"valid_measurement": not errors, "errors": errors, "exit_code": exit_code,
            "native_first_ack": native, "policy_input": inputs, "launch_identity": launch,
            "original_evidence": retained, "status_snapshots": snapshots,
            "connection_to_first_business_ms": None, "pipeline_cost": None}


def run_owned(command: list[str], root: Path, environment: dict, log: Path,
              timeout_s: float) -> tuple[int, bool]:
    interrupted = False
    with log.open("w") as stream:
        process = subprocess.Popen(command, cwd=root, env=environment, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout_s)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            interrupted = isinstance(error, KeyboardInterrupt)
            code = 130 if interrupted else 124
    return code, interrupted


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon-flag", metavar="POLICY")
    parser.add_argument("--legacy-prefer-relay", default="0")
    parser.add_argument("--record-policy-input", type=Path)
    parser.add_argument("--startup-policy", choices=POLICIES)
    parser.add_argument("--role", choices=("node-a", "node-b"))
    parser.add_argument("--seed", type=int, default=932300)
    parser.add_argument("--output", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("daemon_argv", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.daemon_flag is not None:
        try:
            print(daemon_flag(args.daemon_flag, args.legacy_prefer_relay))
            return 0
        except ValueError as error:
            parser.error(str(error))
    if args.record_policy_input is not None:
        values = args.daemon_argv[1:] if args.daemon_argv[:1] == ["--"] else args.daemon_argv
        try:
            record_policy_input(args.record_policy_input, args.role, args.startup_policy, values)
            return 0
        except ValueError as error:
            parser.error(str(error))
    if not (args.dry_run or args.execute) or args.output is None or not args.output.is_absolute():
        parser.error("choose --dry-run or --execute with an absolute --output")
    if not 0 <= args.seed <= 2**31 - 101:
        parser.error("seed must leave room for the fixed scenario offset")
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists() or any((parent / ".git").exists() for parent in (output, *output.parents)):
        parser.error("output must be new and outside a repository")
    plan = make_plan(root, output, args.seed, dict(os.environ))
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    if not plan["native_marker_source_available"]:
        parser.error("pre_B28_source_missing_native_marker: integrate and validate the new source first")
    os.umask(0o077)
    output.mkdir(parents=True, mode=0o700)
    source = plan["source"]
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(plan, indent=2) + "\n")
    # The original four outer guards still share the same 1500s campaign cap.
    # Build-only preparation starts no daemon round and consumes this cap.
    campaign_end = time.monotonic() + 1470  # Reserve cleanup inside the original 1500s cap.
    build_dir = output / "build"
    build_env = {**plan["cases"][0]["environment"],
                 "NAT_SIM_ARTIFACT_DIR": str(build_dir), "NAT_SIM_BUILD_ONLY": "1"}
    code, interrupted = run_owned(["bash", "scripts/nat-sim/nat-sim-smoke.sh"], root,
                                  build_env, output / "build.log", 360)
    plan["preparation"] = {"status": "completed", "exit_code": code,
                           "native_round_executed": False}
    try:
        if code or source_identity(root) != source:
            raise ValueError("build_failed_or_source_changed")
        if (build_dir / "round-1").exists():
            raise ValueError("build_preparation_launched_a_native_round")
        frozen_path = build_dir / "artifact-set.json"
        frozen = load_object(frozen_path)
        validate_artifact_set(frozen)
        if frozen["source"] != source or set(frozen["artifacts"]) != {"daemon", "control", "relay", "udp-shim"}:
            raise ValueError("frozen_build_source_or_components_mismatch")
        for name, artifact in frozen["artifacts"].items():
            verify_snapshot(build_dir, name, artifact)
        plan["preparation"].update(artifact_set_sha256=digest_file(frozen_path),
                                    source=source, artifacts=frozen["artifacts"])
    except (OSError, ValueError, KeyError, TypeError) as error:
        plan["preparation"]["error_type"] = type(error).__name__
        plan["valid_measurement"] = False
        manifest_path.write_text(json.dumps(plan, indent=2) + "\n")
        return 1
    for row in plan["cases"]:
        row["environment"]["NAT_SIM_REUSE_ARTIFACT_SET"] = str(frozen_path)
        if source_identity(root) != source:
            row.update(status="not_run_source_changed")
            continue
        remaining = min(360, campaign_end - time.monotonic())
        if remaining <= 0:
            row.update(status="not_run_campaign_deadline")
            continue
        row.update(status="running")
        manifest_path.write_text(json.dumps(plan, indent=2) + "\n")
        started = time.monotonic()
        code, interrupted = run_owned(
            row["command"], root, row["environment"],
            output / f'{row["scenario"]}-{row["policy"]}.log', remaining)
        row.update(collect_case(row, code, source), status="completed",
                   duration_s=round(time.monotonic() - started, 3))
        if source_identity(root) != source:
            row["valid_measurement"] = False
            row["errors"].append("source_changed_during_case")
        manifest_path.write_text(json.dumps(plan, indent=2) + "\n")
        if interrupted:
            break
    daemon_hashes = {
        record["record"]["artifact"]["sha256"]
        for row in plan["cases"]
        for record in row.get("launch_identity", {}).get("records", [])
        if record["record"]["component"] == "daemon"
    }
    plan["same_daemon_bytes_across_cases"] = len(daemon_hashes) == 1
    plan["daemon_sha256"] = next(iter(daemon_hashes)) if len(daemon_hashes) == 1 else None
    sets = set()
    for row in plan["cases"]:
        value = row.get("launch_identity", {}).get("artifact_set")
        sets.add(value.get("sha256") if isinstance(value, dict) else None)
    plan["same_build_artifacts_across_cases"] = sets == {plan["preparation"]["artifact_set_sha256"]}
    plan["valid_measurement"] = (
        plan["same_daemon_bytes_across_cases"]
        and plan["same_build_artifacts_across_cases"]
        and all(row.get("valid_measurement") is True for row in plan["cases"]))
    manifest_path.write_text(json.dumps(plan, indent=2) + "\n")
    return 0 if plan["valid_measurement"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
