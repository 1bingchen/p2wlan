"""Reusing a build must retain its bytes and reject stale or changed inputs."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr

import launch_identity as L


class ReusedBuildTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        source = {"commit": "1" * 40, "patch_sha256": hashlib.sha256(b"").hexdigest()}
        build = root / "build"
        build.mkdir(mode=0o700)
        files = {}
        for name in ("control", "relay", "daemon", "udp-shim"):
            original = root / name
            original.write_bytes((name + "-one-build").encode())
            files[name] = original
        retained = L.prepare_artifacts(build, files, source)
        output = root / "case"
        output.mkdir(mode=0o700)
        return source, build, output, retained

    def test_fresh_runs_copy_every_component_from_the_same_completed_build(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, output, retained = self.fixture(directory)
            reused = L.reuse_artifacts(output, build / "artifact-set.json", source,
                                      {"control", "relay", "daemon", "udp-shim"})
            self.assertEqual(reused, retained)
            for name, identity in retained["artifacts"].items():
                self.assertEqual(L.verify_snapshot(output, name, identity).read_bytes(),
                                 (build / identity["path"]).read_bytes())

    def test_wrong_source_or_missing_required_component_rejects_before_copy(self):
        for wrong_source in (True, False):
            with self.subTest(wrong_source=wrong_source), tempfile.TemporaryDirectory() as directory:
                source, build, output, _ = self.fixture(directory)
                expected = {**source, "commit": "2" * 40} if wrong_source else source
                required = {"unknown-component"} if not wrong_source else {"daemon"}
                with self.assertRaises(ValueError):
                    L.reuse_artifacts(output, build / "artifact-set.json", expected, required)
                self.assertFalse((output / "artifacts").exists())

    def test_changed_same_size_bytes_or_symlink_cannot_be_relabelled(self):
        for symlink in (True, False):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as directory:
                source, build, output, _ = self.fixture(directory)
                executable = build / "artifacts/daemon"
                executable.chmod(0o700)
                data = executable.read_bytes()
                if symlink:
                    executable.unlink()
                    executable.symlink_to(Path(directory) / "daemon")
                else:
                    executable.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                    executable.chmod(0o500)
                with self.assertRaises(ValueError):
                    L.reuse_artifacts(output, build / "artifact-set.json", source, {"daemon"})
                self.assertFalse((output / "artifact-set.json").exists())

    def test_change_between_validation_and_copy_publishes_no_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, output, _ = self.fixture(directory)
            original = L.shutil.copyfileobj

            def changed_copy(incoming, outgoing, length):
                original(incoming, outgoing, length)
                outgoing.write(b"changed-during-copy")

            with patch.object(L.shutil, "copyfileobj", side_effect=changed_copy):
                with self.assertRaisesRegex(ValueError, "changed_during_copy"):
                    L.reuse_artifacts(output, build / "artifact-set.json", source, {"daemon"})
            self.assertFalse((output / "artifact-set.json").exists())

    def test_cli_requires_current_source_and_rejects_mixed_build_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            source, build, output, _ = self.fixture(directory)
            source_file = Path(directory) / "source.json"
            source_file.write_text(json.dumps(source))
            arguments = ["prepare", "--base-dir", str(output), "--repository", directory,
                         "--source-file", str(source_file), "--reuse-artifact-set",
                         str(build / "artifact-set.json"), "--daemon", str(Path(directory) / "daemon")]
            with patch.object(L, "source_identity", return_value=source), redirect_stderr(io.StringIO()):
                self.assertEqual(L.main(arguments), 1)
            self.assertFalse((output / "artifact-set.json").exists())
            arguments = arguments[:-2]
            with patch.object(L, "source_identity", return_value={**source, "commit": "3" * 40}), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(L.main(arguments), 1)
            self.assertFalse((output / "artifact-set.json").exists())
            with patch.object(L, "source_identity", return_value=source):
                self.assertEqual(L.main(arguments), 0)
            self.assertEqual(L.load_object(output / "artifact-set.json")["source"], source)


class NormalFailureReasons(unittest.TestCase):
    def classify(self, **changes):
        source = Path(__file__).with_name("nat-sim-smoke.sh").read_text()
        matched = re.search(r"^normal_round_failure_reason\(\) \{\n.*?^\}\n", source,
                            re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(matched)
        flags = {name: "1" for name in ("ATTEMPTS_OK", "overlay_ok", "A_TASKS_OK", "B_TASKS_OK",
                 "REPLAY_POLICY_OK", "A_STATUS_ALWAYS_200", "B_STATUS_ALWAYS_200",
                 "STATUS_SCHEMA_OK", "METRICS_SCHEMA_OK", "OBSERVATION_OK")}
        flags.update(MODE="normal", EVIDENCE_REASON="none")
        flags.update(changes)
        result = subprocess.run(["/bin/bash", "-c", matched[0] + "normal_round_failure_reason"],
                                env={**os.environ, **flags}, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_actual_failed_http_guard_cannot_keep_the_none_reason(self):
        self.assertEqual(self.classify(A_STATUS_ALWAYS_200="0"), "status_http_failure")
        self.assertEqual(self.classify(B_STATUS_ALWAYS_200="0", STATUS_SCHEMA_OK="0"),
                         "status_http_failure")

    def test_original_failure_priorities_and_evidence_reason_are_retained(self):
        self.assertEqual(self.classify(ATTEMPTS_OK="0"), "hard_hard_attempt_missing")
        self.assertEqual(self.classify(overlay_ok="0"), "overlay_verification_failed")
        self.assertEqual(self.classify(A_TASKS_OK="0"), "critical_tasks_unhealthy")
        self.assertEqual(self.classify(REPLAY_POLICY_OK="0"), "replay_policy_unsatisfied")
        self.assertEqual(self.classify(EVIDENCE_REASON="first_usable_never_observed"),
                         "first_usable_never_observed")

    def test_schema_observation_and_unknown_failure_never_claim_success(self):
        self.assertEqual(self.classify(STATUS_SCHEMA_OK="0"), "status_schema_invalid")
        self.assertEqual(self.classify(METRICS_SCHEMA_OK="0"), "metrics_schema_invalid")
        self.assertEqual(self.classify(OBSERVATION_OK="0"), "observation_window_incomplete")
        self.assertEqual(self.classify(), "normal_business_gate_failed")


if __name__ == "__main__":
    unittest.main()
