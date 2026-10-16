import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_cargo_test as runner


class CargoArtifactIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.target = self.root / "target"
        self.target.mkdir()
        self.binary = self.target / "test binary.exe"
        self.binary.write_bytes(b"native\r\n\x1aexact bytes")
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.identity = runner.CargoIdentity(self.root, self.target)

    def declare(self, binary=None):
        self.identity.stdout_line(json.dumps({"reason": "compiler-artifact", "profile": {"test": True}, "target": {"kind": ["lib"], "name": "fixture"}, "executable": str(binary or self.binary)}).encode())
        self.identity.stdout_line(b'{"reason":"build-finished","success":true}')
        self.identity.stderr_line(f"     Running unittests src/lib.rs ({binary or self.binary})\n".encode())

    def test_retains_only_cargo_selected_bytes_with_spaces_and_windows_control_bytes(self):
        self.declare()
        result = self.identity.retain(self.evidence, 101)
        self.assertEqual(result["state"], "retained")
        self.assertEqual((self.evidence / result["path"]).read_bytes(), self.binary.read_bytes())
        self.assertEqual(result["sha256"], runner.sha256_file(self.binary))

    def test_never_uses_a_newer_unreported_file(self):
        self.declare()
        (self.target / "newer").write_bytes(b"stale selection")
        self.identity.stderr_line(b"Running unittests src/lib.rs (target/newer)\n")
        self.assertEqual(self.identity.retain(self.evidence, 101)["reason"], "running_not_in_cargo_artifacts")

    def test_runtime_json_cannot_replace_compiler_identity_or_build_result(self):
        self.declare()
        self.binary.write_bytes(b"runtime mutation")
        self.declare()
        self.identity.stdout_line(b'{"reason":"build-finished","success":false}')
        self.assertTrue(self.identity.build_success)
        self.assertEqual(self.identity.retain(self.evidence, 101)["state"], "unavailable")

    def test_compiler_artifact_capacity_is_explicit(self):
        with mock.patch.object(runner, "MAX_ARTIFACTS", 0):
            self.declare()
        self.assertTrue(self.identity.capacity_exceeded)
        self.assertEqual(self.identity.retain(self.evidence, 101)["state"], "unavailable")

    def test_outside_target_is_unavailable(self):
        outside = self.root / "outside"
        outside.write_bytes(b"not target")
        self.declare(outside)
        self.assertEqual(self.identity.retain(self.evidence, 101)["state"], "unavailable")

    def test_mutated_binary_is_not_copied(self):
        self.declare()
        self.binary.write_bytes(b"changed")
        self.assertEqual(self.identity.retain(self.evidence, 101)["state"], "unavailable")
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_copy_error_is_unavailable(self):
        self.declare()
        with mock.patch.object(runner.os, "chmod", side_effect=OSError("denied")):
            self.assertEqual(self.identity.retain(self.evidence, 101)["state"], "unavailable")
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_doctest_does_not_relabel_previous_successful_unit_binary(self):
        self.declare()
        self.identity.stderr_line(b"   Doc-tests fixture\n")
        self.identity.stderr_line(b"error: doctest failed, to rerun pass `--doc`\n")
        self.assertEqual(self.identity.retain(self.evidence, 101)["reason"], "doctest_executable_not_reported")

    def test_success_does_not_claim_failed_bytes(self):
        self.declare()
        self.assertEqual(self.identity.retain(self.evidence, 0)["state"], "not_needed")
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_log_and_parser_capacity_are_bounded_without_stopping_drain(self):
        received = []
        errors = []
        stream = io.BytesIO(b"123456789\n" * 100 + b"end\n")
        with mock.patch.object(runner, "MAX_LOG_BYTES", 16), mock.patch.object(runner, "MAX_LINE_BYTES", 8):
            runner.capture_stream(stream, self.evidence / "log", None, received.append, errors)
        self.assertEqual((self.evidence / "log").stat().st_size, 16)
        self.assertEqual(received, [b"end\n"])
        self.assertCountEqual(errors, ["log_capacity", "line_capacity"])
        self.assertEqual(stream.tell(), len(stream.getvalue()))


@unittest.skipUnless(shutil.which("cargo") and shutil.which("rustc"), "actual Cargo toolchain required")
class ActualCargoFailureEvidenceTests(unittest.TestCase):
    def fixture(self, source, *, all_targets):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        root = base / "repo with spaces"
        (root / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_text('[package]\nname="evidence-fixture"\nversion="0.1.0"\nedition="2021"\n[workspace]\n')
        (root / ".gitignore").write_text('/target/\n/Cargo.lock\n')
        (root / "src/lib.rs").write_text(source)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], cwd=root, check=True)
        evidence = base / "evidence"
        # Do not reuse the product target, flags, or test profile for this tiny control.
        environment = {key: value for key, value in runner.os.environ.items() if not key.startswith(("CARGO_TARGET_", "CARGO_PROFILE_")) and key not in {"CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}}
        with mock.patch.dict(runner.os.environ, environment, clear=True):
            result = runner.run_suite(root, evidence, all_targets=all_targets, echo=False)
        return result, json.loads((evidence / "manifest.json").read_text()), evidence

    def test_actual_first_native_failure_preserves_101_and_exact_executable(self):
        result, manifest, evidence = self.fixture('#[test]\nfn original_failure(){assert_eq!(1,2);}\n', all_targets=True)
        self.assertEqual(result, 101)
        self.assertEqual(manifest["cargo_returncode"], 101)
        self.assertEqual(manifest["failed_binary"]["state"], "retained")
        self.assertEqual(manifest["evidence_errors"], [])
        binary = manifest["failed_binary"]
        self.assertEqual(runner.sha256_file(evidence / binary["path"]), runner.sha256_file(Path(binary["original_path"])))
        self.assertIn("--all-targets", manifest["command"])

    def test_actual_success_has_no_failed_binary(self):
        result, manifest, evidence = self.fixture('#[test]\nfn original_success(){assert_eq!(1,1);}\n', all_targets=True)
        self.assertEqual(result, 0)
        self.assertEqual(manifest["failed_binary"]["state"], "not_needed")
        self.assertFalse((evidence / "failed-test").exists())

    def test_actual_compile_failure_cannot_reuse_a_native_artifact(self):
        result, manifest, _ = self.fixture('compile_error!("planned build failure");\n', all_targets=True)
        self.assertEqual(result, 101)
        self.assertEqual(manifest["failed_binary"]["reason"], "build_not_successful")

    def test_actual_doctest_failure_keeps_original_target_scope_and_reports_unavailable(self):
        result, manifest, _ = self.fixture('/// ```\n/// assert_eq!(1, 2);\n/// ```\npub fn documented() {}\n#[test]\nfn original_success() {}\n', all_targets=False)
        self.assertEqual(result, 101)
        self.assertNotIn("--all-targets", manifest["command"])
        self.assertEqual(manifest["failed_binary"]["reason"], "doctest_executable_not_reported")


if __name__ == "__main__":
    unittest.main()
