"""Offline policy mapping, fixed denominator and evidence rejection controls."""
import copy
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from test_launch_identity import SOURCE, write_valid_launch_evidence
import launch_identity

spec = importlib.util.spec_from_file_location(
    "startup_policy_matrix", Path(__file__).with_name("run-startup-policy-matrix.py"))
MATRIX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MATRIX)


class StartupPolicyMatrixTests(unittest.TestCase):
    def policy_case(self, root, actual_policy="auto", receipt_policy="auto"):
        actual = ["--config", "/private/synthetic-config.json", MATRIX.daemon_flag(actual_policy),
                  "--validate-overlay", "--overlay-any-path"]
        claimed = ["--config", "/private/synthetic-config.json", MATRIX.daemon_flag(receipt_policy),
                   "--validate-overlay", "--overlay-any-path"]
        launch = write_valid_launch_evidence(root, daemon_argv=actual)
        records = {item["record"]["role"]: item["record"] for item in launch["records"]}
        round_dir = root / "round-1"
        for side in ("a", "b"):
            role = f"node-{side}"
            MATRIX.record_policy_input(round_dir / f"{role}.startup-policy.json", role,
                                       receipt_policy, claimed)
            status = {"process_id": records[role]["pid"],
                      "peers": [{"node_id": "peer", "active_path": "relay"}],
                      "network_generation": 0, "connection_timeline": {"events": [
                          {"event": "first_usable_bidirectional_overlay_ms", "peer_id": "peer",
                           "path": "relay", "connection_generation": 0, "at_ms": 5100,
                           "detail": "peer=peer generation=0 native_original_ack=true"}]}}
            (round_dir / f"{role}.status.json").write_text(json.dumps(status))
        for name, value in (("nat-evidence", {"result": "pass"}),
                            ("mapping-evidence", {"valid": True}),
                            ("cleanup", {"all_reaped": True, "forced_termination": False})):
            (round_dir / f"{name}.json").write_text(json.dumps(value))
        return {"scenario": "direct-blackhole", "policy": receipt_policy,
                "directory": str(root), "daemon_flag": MATRIX.daemon_flag(receipt_policy)}

    def test_real_cli_mapping_preserves_unset_legacy_and_rejects_mixed_policy(self):
        self.assertEqual(MATRIX.daemon_flag("direct-first"), "--prefer-direct")
        self.assertEqual(MATRIX.daemon_flag("auto"), "--prefer-relay")
        self.assertEqual(MATRIX.daemon_flag("", "1"), "--relay-only")
        for legacy in ("0", "", "ignored-old-input"):
            self.assertEqual(MATRIX.daemon_flag("", legacy), "")
        for policy in ("auto", "direct-first"):
            with self.assertRaisesRegex(ValueError, "conflicts"):
                MATRIX.daemon_flag(policy, "1")
        with self.assertRaises(ValueError):
            MATRIX.daemon_flag("relay-only")

    def test_fixed_four_cases_keep_matched_seeds_original_caps_and_clean_environment(self):
        rows = []
        for scenario, policy, offset in MATRIX.CASES:
            env = MATRIX.case_environment(
                {"PATH": "/bin", "PREFER_RELAY": "1", "MODE": "direct", "LOSS": "1",
                 "CONTROL_API_TOKEN": "not-to-be-inherited", "STARTUP_POLICY": "relay-only"},
                Path("/private/output") / f"{scenario}-{policy}", scenario, policy, 932300 + offset)
            rows.append((scenario, policy, env))
            self.assertNotIn("PREFER_RELAY", env)
            self.assertNotIn("LOSS", env)
            self.assertNotIn("CONTROL_API_TOKEN", env)
            self.assertEqual((env["ROUNDS"], env["NORMAL_OBSERVE_S"], env["OVERLAY_TIMEOUT_S"],
                              env["ROUND_TIMEOUT_S"]), ("1", "30", "60", "150"))
            self.assertEqual(env["STARTUP_POLICY"], policy)
            self.assertEqual(env["EGRESS_CAPTURE"], "shim")
        self.assertEqual(len(rows), 4)
        for scenario in ("reachable-direct", "direct-blackhole"):
            pair = [env for name, _, env in rows if name == scenario]
            self.assertEqual(len(pair), 2)
            self.assertEqual(pair[0]["NAT_SEED_BASE"], pair[1]["NAT_SEED_BASE"])
            expected_mode = "normal" if scenario == "reachable-direct" else "relay-only"
            self.assertTrue(all(env["MODE"] == expected_mode for env in pair))

    def test_failed_build_keeps_four_scheduled_rows_and_launches_no_case(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "campaign"
            plan = {"source": SOURCE, "requested_cases": 4, "native_marker_source_available": True,
                    "cases": [{"status": "not_run", "environment": {}} for _ in range(4)]}
            with patch.object(MATRIX, "make_plan", return_value=plan), \
                    patch.object(MATRIX, "run_owned", return_value=(1, False)) as owned:
                self.assertEqual(MATRIX.main(["--execute", "--output", str(output)]), 1)
            self.assertEqual(owned.call_count, 1)
            result = json.loads((output / "manifest.json").read_text())
            self.assertEqual(len(result["cases"]), 4)
            self.assertTrue(all(row["status"] == "not_run" for row in result["cases"]))
            self.assertFalse(result["preparation"]["native_round_executed"])
            self.assertFalse(result["valid_measurement"])

    def test_outer_timeout_reaps_the_actual_owned_process(self):
        with tempfile.TemporaryDirectory() as directory:
            children = []
            real_popen = subprocess.Popen

            def owned(*arguments, **keywords):
                child = real_popen(*arguments, **keywords)
                children.append(child)
                return child

            with patch.object(MATRIX.subprocess, "Popen", side_effect=owned):
                code, interrupted = MATRIX.run_owned(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    Path(directory), dict(MATRIX.os.environ), Path(directory) / "owned.log", 0.05)
            self.assertEqual(code, 124)
            self.assertFalse(interrupted)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].returncode)

    def test_public_policy_receipt_records_same_argument_array_without_config_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            argv = ["--config", "/private/config.json", "--token-stdin", "--prefer-relay",
                    "--validate-overlay", "--overlay-any-path"]
            MATRIX.record_policy_input(path, "node-a", "auto", argv)
            receipt = json.loads(path.read_text())
            self.assertEqual(receipt["actual_policy_flags"], ["--prefer-relay"])
            self.assertEqual(receipt["argument_count"], len(argv))
            self.assertEqual(len(receipt["argv_sha256"]), 64)
            self.assertTrue(receipt["overlay_any_path"])
            self.assertFalse(receipt["artificial_business_gate"])
            self.assertNotIn("/private/config.json", path.read_text())
            with self.assertRaises(ValueError):
                MATRIX.record_policy_input(Path(directory) / "mixed.json", "node-a", "auto",
                                           argv + ["--relay-only"])
            with self.assertRaises(ValueError):
                MATRIX.record_policy_input(Path(directory) / "implicit.json", "node-a", "", [])

    def test_native_measurement_rejects_legacy_wrong_peer_generation_path_or_substring(self):
        event = {"event": "first_usable_bidirectional_overlay_ms", "peer_id": "peer", "path": "relay",
                 "connection_generation": 2, "at_ms": 5100,
                 "detail": "peer=peer seq=1 generation=2 native_original_ack=true attempt=42"}
        status = {"peers": [{"node_id": "peer"}], "network_generation": 2,
                  "connection_timeline": {"events": [event]}}
        self.assertEqual(MATRIX.native_first_ack(status)["timeline_origin_to_native_ack_ms"], 5100)
        later_generation = copy.deepcopy(status)
        later_generation["network_generation"] = 3
        self.assertEqual(MATRIX.native_first_ack(later_generation)["generation_at_native_commit"], 2)
        for field, value in (("peer_id", "other"), ("connection_generation", 1),
                             ("path", "unknown"), ("at_ms", True),
                             ("detail", "native_original_ack=trueish"), ("detail", "legacy")):
            changed = copy.deepcopy(status)
            changed["connection_timeline"]["events"][0][field] = value
            self.assertIsNone(MATRIX.native_first_ack(changed))

    def test_dry_run_never_launches_or_creates_output_and_missing_marker_blocks_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "not-created"
            plan = {"requested_cases": 4, "cases": [{"status": "not_run"}] * 4,
                    "native_marker_source_available": False}
            with patch.object(MATRIX, "make_plan", return_value=plan), \
                    patch.object(MATRIX.subprocess, "Popen") as launch:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(MATRIX.main(["--dry-run", "--output", str(output)]), 0)
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    MATRIX.main(["--execute", "--output", str(output)])
                self.assertEqual(raised.exception.code, 2)
                launch.assert_not_called()
                self.assertFalse(output.exists())

    def test_blackhole_collection_keeps_failure_and_unknown_native_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_launch_evidence(root)
            round_dir = root / "round-1"
            for side in ("a", "b"):
                # The offline original recorder fixture launched with no argv;
                # a forged policy receipt must not upgrade that to a real pilot.
                status = {"peers": [{"node_id": "peer", "active_path": "relay"}],
                          "network_generation": 0, "connection_timeline": {"events": []}}
                (round_dir / f"node-{side}.status.json").write_text(json.dumps(status))
                (round_dir / f"node-{side}.startup-policy.json").write_text(json.dumps(
                    {"role": f"node-{side}", "requested_policy": "auto", "argument_count": 1,
                     "actual_policy_flags": ["--prefer-relay"], "overlay_any_path": True,
                     "artificial_business_gate": False}))
            for name, value in (("nat-evidence", {"result": "pass"}),
                                ("mapping-evidence", {"valid": True}),
                                ("cleanup", {"all_reaped": True, "forced_termination": False})):
                (round_dir / f"{name}.json").write_text(json.dumps(value))
            row = {"scenario": "direct-blackhole", "policy": "auto", "directory": str(root),
                   "daemon_flag": "--prefer-relay"}
            result = MATRIX.collect_case(row, 1, SOURCE)
            self.assertFalse(result["valid_measurement"])
            self.assertIn("smoke_exit:1", result["errors"])
            self.assertEqual(result["native_first_ack"], {"a": None, "b": None})
            self.assertIsNone(result["pipeline_cost"])
            self.assertIsNone(result["connection_to_first_business_ms"])

    def test_same_source_original_exec_argv_digest_accepts_matching_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            row = self.policy_case(Path(directory))
            result = MATRIX.collect_case(row, 0, SOURCE)
            self.assertTrue(result["valid_measurement"], result["errors"])
            for side in ("a", "b"):
                self.assertEqual(result["policy_input"][side]["actual_policy_flags"], ["--prefer-relay"])
                self.assertNotIn("/private/synthetic-config.json", json.dumps(result["launch_identity"]))

    def test_same_argc_wrong_policy_cannot_replace_original_exec_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            row = self.policy_case(Path(directory), actual_policy="direct-first", receipt_policy="auto")
            result = MATRIX.collect_case(row, 0, SOURCE)
            self.assertFalse(result["valid_measurement"])
            self.assertTrue(any(error.startswith("a:") for error in result["errors"]))
            self.assertTrue(any(error.startswith("b:") for error in result["errors"]))

    def test_missing_malformed_or_mismatched_receipt_digest_cannot_supply_policy_proof(self):
        for value in (None, True, 123, "a" * 63, "A" * 64, "0" * 64):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                row = self.policy_case(root)
                path = root / "round-1/node-a.startup-policy.json"
                receipt = json.loads(path.read_text())
                if value is None:
                    receipt.pop("argv_sha256")
                else:
                    receipt["argv_sha256"] = value
                path.write_text(json.dumps(receipt))
                result = MATRIX.collect_case(row, 0, SOURCE)
                self.assertFalse(result["valid_measurement"])
                self.assertIn("a:required_evidence_missing_or_invalid", result["errors"])

    def test_copied_exec_digest_cannot_upgrade_wrong_public_policy_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.policy_case(root, actual_policy="direct-first", receipt_policy="auto")
            for side in ("a", "b"):
                path = root / f"round-1/node-{side}.startup-policy.json"
                receipt = json.loads(path.read_text())
                original = json.loads((root / f"round-1/launches/node-{side}.json").read_text())
                receipt["argv_sha256"] = original["configuration"]["argv_sha256"]
                path.write_text(json.dumps(receipt))
            result = MATRIX.collect_case(row, 0, SOURCE)
            self.assertFalse(result["valid_measurement"])
            self.assertTrue(any(error.startswith("a:") for error in result["errors"]))
            self.assertTrue(any(error.startswith("b:") for error in result["errors"]))

    def test_legacy_original_launch_remains_readable_but_cannot_supply_strict_policy_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.policy_case(root)
            path = root / "round-1/launches/node-a.json"
            record = json.loads(path.read_text())
            record["configuration"].pop("argv_sha256")
            record["configuration"].pop("startup_policy_flags")
            path.write_text(json.dumps(record))
            self.assertTrue(launch_identity.read_launch_evidence(root, SOURCE)["valid"])
            result = MATRIX.collect_case(row, 0, SOURCE)
            self.assertFalse(result["valid_measurement"])
            self.assertIn("a:required_evidence_missing_or_invalid", result["errors"])


if __name__ == "__main__":
    unittest.main()
