from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "release" / "prepare_cocoapods_cdn.py"
SPEC = importlib.util.spec_from_file_location("prepare_cocoapods_cdn", SCRIPT)
CDN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CDN)


@unittest.skipUnless(os.name == "posix", "CocoaPods metadata preparation uses POSIX process groups")
class CocoaPodsCDNTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls.jsonl"
        self.output = self.root / "evidence"
        self.exported = self.root / "github-env"
        self.exported.write_text("EXISTING=yes\n")
        command = self.bin / "pod"
        command.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, pathlib, signal, sys, time\n"
            "calls = pathlib.Path(os.environ['P2WLAN_CDN_FIXTURE_CALLS'])\n"
            "count = len(calls.read_text().splitlines()) if calls.exists() else 0\n"
            "with calls.open('a') as output:\n"
            " output.write(json.dumps({'argv':sys.argv[1:], 'home':os.environ['CP_HOME_DIR'], 'repos':os.environ['CP_REPOS_DIR']})+'\\n')\n"
            "mode = os.environ['P2WLAN_CDN_FIXTURE_MODE']\n"
            "if mode == 'timeout':\n"
            " signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            " time.sleep(30)\n"
            "if mode == 'failure' or (mode == 'transient' and count == 0):\n"
            " print('metadata unavailable', file=sys.stderr)\n"
            " sys.exit(7)\n"
            "print('CDN registered')\n"
        )
        command.chmod(0o700)
        self.environment = patch.dict(os.environ, {
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "CP_HOME_DIR": "foreign-home",
            "CP_REPOS_DIR": "foreign-repos",
            "P2WLAN_CDN_FIXTURE_CALLS": str(self.calls),
            "P2WLAN_CDN_FIXTURE_MODE": "success",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def run_prepare(self, mode="success"):
        with patch.dict(os.environ, {"P2WLAN_CDN_FIXTURE_MODE": mode}), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return CDN.prepare(self.output, self.exported, "a" * 40)

    def test_registers_explicit_cdn_and_exports_only_isolated_cache(self):
        result = self.run_prepare()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(result["passed"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["argv"], ["repo", "add-cdn", "trunk", CDN.CDN_URL])
        self.assertEqual(calls[0]["home"], str((self.output / "home").resolve()))
        self.assertEqual(calls[0]["repos"], str((self.output / "home" / "repos").resolve()))
        self.assertEqual(os.environ["CP_HOME_DIR"], "foreign-home")
        self.assertTrue(self.exported.read_text().startswith("EXISTING=yes\nCP_HOME_DIR="))

    def test_transient_metadata_error_retains_first_attempt_before_success(self):
        result = self.run_prepare("transient")
        self.assertTrue(result["passed"])
        self.assertEqual([r["returncode"] for r in result["attempts"]], [7, 0])
        self.assertEqual((self.output / "attempt-1.stderr").read_text(), "metadata unavailable\n")
        self.assertEqual(json.loads((self.output / "manifest.json").read_text()), result)

    def test_permanent_failure_stops_after_three_and_does_not_export(self):
        result = self.run_prepare("failure")
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["attempts"]), 3)
        self.assertTrue(all(r["wait_completed"] and r["returncode"] == 7 for r in result["attempts"]))
        self.assertEqual(self.exported.read_text(), "EXISTING=yes\n")

    def test_timeout_reaps_owned_group_and_keeps_each_failed_attempt(self):
        with patch.object(CDN, "REQUEST_TIMEOUT_SECONDS", 1), patch.object(CDN, "TERMINATE_GRACE_SECONDS", 0.1):
            result = self.run_prepare("timeout")
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["attempts"]), 3)
        self.assertTrue(all(r["timed_out"] and r["forced"] and r["wait_completed"] and r["returncode"] < 0 for r in result["attempts"]))
        self.assertEqual(self.exported.read_text(), "EXISTING=yes\n")

    def test_missing_tool_fails_before_creating_evidence(self):
        with patch.object(CDN.shutil, "which", return_value=None):
            with self.assertRaises(FileNotFoundError):
                self.run_prepare()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.calls.exists())

    def test_existing_evidence_is_never_reused_or_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / "first-failure"
        sentinel.write_text("original")
        with self.assertRaises(FileExistsError):
            self.run_prepare()
        self.assertEqual(sentinel.read_text(), "original")
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
