import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_cargo_test as runner


class CargoSuiteScopeTests(unittest.TestCase):
    def test_default_keeps_workspace_targets_features_and_original_skip(self):
        self.assertEqual(runner.cargo_test_command(all_targets=False, all_features=False, hard_hard_lib=False), ["cargo", "test", "--workspace", "--message-format=json", "--", "--test-threads=1", "--skip", "hard_hard_"])

    def test_shared_hh_scope_preserves_lib_filter_and_rejects_expansion(self):
        self.assertEqual(runner.cargo_test_command(all_targets=False, all_features=False, hard_hard_lib=True), ["cargo", "test", "-p", "p2wlan-daemon", "--lib", "hard_hard_", "--message-format=json", "--", "--test-threads=1"])
        for targets, features in [(True, False), (False, True), (True, True)]:
            with self.assertRaises(ValueError):
                runner.cargo_test_command(all_targets=targets, all_features=features, hard_hard_lib=True)

    def test_business_mtu_keeps_original_scopes_deadlines_and_failure_upload(self):
        workflow = (Path(__file__).resolve().parents[3] / ".github/workflows/business-mtu-budget-required.yml").read_text()
        linux = workflow.split("  linux_validation:\n", 1)[1].split("  production_e2e:\n", 1)[0]
        self.assertIn("timeout-minutes: 75", linux)
        self.assertIn("run_cargo_test.py --all-features --evidence-dir", linux)
        self.assertIn("run_cargo_test.py --hard-hard-lib --evidence-dir", linux)
        self.assertNotIn("--each", linux)
        self.assertNotIn("continue-on-error", linux)
        self.assertIn("! grep -qE '0 tests, [1-9][0-9]* benchmarks'", linux)
        self.assertIn("if: failure() && (steps.workspace_tests.outcome == 'failure' || steps.hard_hard_tests.outcome == 'failure')", linux)
        self.assertIn("if-no-files-found: error", linux)


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

    def test_console_raw_descriptor_preserves_bytes_across_partial_writes(self):
        read_fd, write_fd = runner.os.pipe()
        original_write = runner.os.write
        content = b"native\r\n\x1aexact bytes\n"
        try:
            with mock.patch.object(runner.os, "write", side_effect=lambda fd, data: original_write(fd, data[:2])):
                runner.capture_stream(io.BytesIO(content), self.evidence / "log", write_fd, lambda _: None, [])
            runner.os.close(write_fd)
            write_fd = None
            self.assertEqual(runner.os.read(read_fd, 1024), content)
            self.assertEqual((self.evidence / "log").read_bytes(), content)
        finally:
            if write_fd is not None:
                runner.os.close(write_fd)
            runner.os.close(read_fd)


@unittest.skipUnless(shutil.which("cargo") and shutil.which("rustc"), "actual Cargo toolchain required")
class ActualCargoFailureEvidenceTests(unittest.TestCase):
    def fixture(self, source, *, all_targets, all_features=False, hard_hard_lib=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        root = base / "repo with spaces"
        (root / "src").mkdir(parents=True)
        name = "p2wlan-daemon" if hard_hard_lib else "evidence-fixture"
        (root / "Cargo.toml").write_text(f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2021"\n[features]\nexplicit=[]\n[workspace]\n')
        (root / ".gitignore").write_text('/target/\n/Cargo.lock\n')
        (root / "src/lib.rs").write_text(source)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], cwd=root, check=True)
        evidence = base / "evidence"
        # Do not reuse the product target, flags, or test profile for this tiny control.
        environment = {key: value for key, value in runner.os.environ.items() if not key.startswith(("CARGO_TARGET_", "CARGO_PROFILE_")) and key not in {"CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"}}
        with mock.patch.dict(runner.os.environ, environment, clear=True):
            result = runner.run_suite(root, evidence, all_targets=all_targets, all_features=all_features, hard_hard_lib=hard_hard_lib, echo=False)
        return result, json.loads((evidence / "manifest.json").read_text()), evidence

    def test_actual_shared_hh_failure_retains_original_program_and_101(self):
        result, manifest, evidence = self.fixture('#[test]\nfn hard_hard_first_failure(){assert_eq!(1,2);}\n', all_targets=False, hard_hard_lib=True)
        self.assertEqual(result, 101)
        self.assertEqual(manifest["cargo_returncode"], 101)
        self.assertEqual(manifest["hard_hard_lib_summary"], dict(result="FAILED", passed=0, failed=1, ignored=0))
        binary = manifest["failed_binary"]
        self.assertEqual(binary["state"], "retained")
        self.assertEqual(runner.sha256_file(evidence / binary["path"]), runner.sha256_file(Path(binary["original_path"])))

    def test_actual_hh_filter_excludes_unrelated_failure_in_shared_process(self):
        result, manifest, _ = self.fixture('#[test]\nfn hard_hard_selected(){}\n#[test]\nfn unrelated(){panic!("outside original filter");}\n', all_targets=False, hard_hard_lib=True)
        self.assertEqual(result, 0)
        self.assertEqual(manifest["hard_hard_lib_summary"], dict(result="ok", passed=1, failed=0, ignored=0))
        self.assertEqual(manifest["evidence_errors"], [])

    def test_actual_empty_or_only_ignored_hh_selection_fails_without_rerun(self):
        for source in ['#[test]\nfn unrelated(){}\n', '#[test]\n#[ignore]\nfn hard_hard_ignored(){}\n']:
            with self.subTest(source=source):
                result, manifest, _ = self.fixture(source, all_targets=False, hard_hard_lib=True)
                self.assertEqual(result, 1)
                self.assertEqual(manifest["cargo_returncode"], 0)
                self.assertIn("hard_hard_lib_not_executed", manifest["evidence_errors"])
                self.assertFalse(manifest["source_bound"])

    def test_actual_explicit_all_features_is_available_without_changing_default(self):
        result, manifest, _ = self.fixture('#[cfg(not(feature="explicit"))]\ncompile_error!("explicit feature required");\n#[test]\nfn enabled(){}\n', all_targets=False, all_features=True)
        self.assertEqual(result, 0)
        self.assertIn("--all-features", manifest["command"])
        self.assertNotIn("--all-targets", manifest["command"])

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

    def test_actual_cargo_failure_does_not_wait_for_inherited_pipe_eof(self):
        release = threading.Event()
        closed = threading.Event()
        original_popen = subprocess.Popen
        timers = []

        class HeldEOF:
            def __init__(self, stream):
                self.stream = stream

            def read1(self, size):
                data = self.stream.read1(size)
                if not data:
                    release.wait(10)
                return data

            def close(self):
                self.stream.close()
                closed.set()

        class Process:
            def __init__(self, process):
                self.process = process
                self.stdout = HeldEOF(process.stdout)
                self.stderr = process.stderr

            def wait(self):
                code = self.process.wait()
                # A safety release also makes this regression finite on the
                # old unbounded join. The assertion uses the typed outcome.
                timer = threading.Timer(2, release.set)
                timer.start()
                timers.append(timer)
                return code

        def popen(command, *args, **kwargs):
            process = original_popen(command, *args, **kwargs)
            return Process(process) if command[:2] == ["cargo", "test"] else process

        try:
            with mock.patch.object(runner.subprocess, "Popen", side_effect=popen), mock.patch.object(runner, "DRAIN_AFTER_EXIT_SECONDS", 0.01):
                result, manifest, _ = self.fixture('#[test]\nfn original_failure(){assert_eq!(1,2);}\n', all_targets=True)
            self.assertEqual(result, 101)
            self.assertEqual(manifest["cargo_returncode"], 101)
            self.assertEqual(manifest["stream_drain"], {"complete": False, "postexit_limit_seconds": 0.01})
            self.assertIn("stream_not_closed_after_cargo_exit", manifest["evidence_errors"])
            self.assertEqual(manifest["failed_binary"]["state"], "unavailable")
            self.assertTrue(all(not log["complete"] and log["sha256"] is None for log in manifest["logs"].values()))
        finally:
            release.set()
            self.assertTrue(closed.wait(2), "owned stream pump did not close")
            for timer in timers:
                timer.cancel()
                timer.join()


if __name__ == "__main__":
    unittest.main()
