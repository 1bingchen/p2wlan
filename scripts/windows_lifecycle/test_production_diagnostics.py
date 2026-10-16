import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import production_diagnostics as diagnostic


class ProductionDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / ("p2wlan-windows-lifecycle-" + "a" * 32)
        self.directory = self.root / "cycle-1"
        self.directory.mkdir(parents=True)
        self.document = {"source_head_sha": "a" * 40, "workflow_sha": "b" * 40, "production_artifact_root": str(self.root), "cycles": [{"cycle": 1, "entrypoint": "diagnostics", "pid": 123, "forced_termination": True}]}
        self.sample = {"sequence": 1, "started_ms": 0, "completed_ms": 2001, "http_status": None, "auth_exists": True, "token_nonempty": None, "exception_type": "System.Net.Http.HttpRequestException"}
        self.trace = {"schema_version": 1, "source_head_sha": "a" * 40, "workflow_sha": "b" * 40, "process_id": 123, "timeout_seconds": 20, "clock": "stopwatch", "dropped_samples": 0, "samples": [self.sample]}

    def test_original_failed_cycle_is_preserved_and_missing_files_stay_unavailable(self):
        original = copy.deepcopy(self.document)
        result = diagnostic.collect(self.document, self.base / "output")
        self.assertEqual(self.document, original)
        self.assertFalse(result["changes_original_verdict"])
        self.assertTrue(result["rows"][0]["forced_termination"])
        self.assertEqual(result["rows"][0]["daemon.log"]["state"], "unavailable")
        self.assertEqual(result["rows"][0]["readiness.json"]["state"], "unavailable")
        self.assertEqual(result["rows"][0]["daemon.log"]["reason"], "missing_source")

    def test_only_bounded_allowlisted_evidence_is_copied_without_credentials(self):
        secret = "gh" + "p_" + "X" * 40
        log = f"starting daemon\nAuthorization: Bearer {secret}\n" + "A" * 80 + "\nTUN initialization\n"
        (self.directory / "daemon.log").write_text(log)
        trace = {**self.trace, "secret": secret}
        (self.directory / "readiness.json").write_text(json.dumps(trace))
        (self.directory / "config.json").write_text(secret)
        (self.directory / "p2wlan-daemon.diag-auth").write_text(secret)
        output = self.base / "output"
        result = diagnostic.collect(self.document, output)
        text = "".join(p.read_text() for p in output.rglob("*") if p.is_file())
        self.assertNotIn(secret, text)
        self.assertNotIn("A" * 80, text)
        self.assertIn("TUN initialization", text)
        self.assertEqual(result["rows"][0]["daemon.log"]["omitted_lines"], 2)
        self.assertEqual(json.loads((output / "cycle-1/readiness.json").read_text())["samples"], [self.sample])
        self.assertFalse((output / "cycle-1/config.json").exists())
        self.assertEqual((self.directory / "p2wlan-daemon.diag-auth").read_text(), secret)
        with self.assertRaises(FileExistsError):
            diagnostic.collect(self.document, output)

    def test_source_pid_timeout_clock_and_sample_boundaries_fail_closed(self):
        modifications = [("source_head_sha", "c" * 40), ("process_id", 124), ("timeout_seconds", 21), ("clock", "wall"), ("samples", [self.sample] * 129), ("dropped_samples", -1)]
        for key, value in modifications:
            with self.subTest(key=key), self.assertRaises(ValueError):
                diagnostic.readiness(json.dumps({**self.trace, key: value}).encode(), self.document, self.document["cycles"][0])
        trace = copy.deepcopy(self.trace)
        trace["samples"][0]["exception_type"] = "Authorization: example"
        with self.assertRaises(ValueError):
            diagnostic.readiness(json.dumps(trace).encode(), self.document, self.document["cycles"][0])

    def test_log_tail_capacity_drops_partial_first_line_and_does_not_grow_with_file(self):
        path = self.directory / "daemon.log"
        path.write_bytes(b"X" * (diagnostic.CAP * 2) + b"\nlast startup phase\n")
        raw, metadata = diagnostic.bounded_file(path, tail=True)
        self.assertEqual(len(raw), diagnostic.CAP)
        self.assertTrue(metadata["truncated_prefix"])
        text, _ = diagnostic.sanitized_log(raw, True)
        self.assertEqual(text, "last startup phase\n")
        with self.assertRaises(ValueError):
            diagnostic.bounded_file(path)

    def test_byte_identity_survives_crt_text_translation_defaults(self):
        path = self.directory / "daemon.log"
        raw = b"first startup\r\nTUN initialization\r\n\x1aafter control-Z\r\n"
        path.write_bytes(raw)
        real_open, real_read = os.open, os.read
        native_binary = getattr(os, "O_BINARY", 0)
        binary_flag = 1 << 28
        modes = {}

        def crt_open(filename, flags):
            descriptor = real_open(filename, (flags & ~binary_flag) | native_binary)
            modes[descriptor] = bool(flags & binary_flag)
            return descriptor

        def crt_read(descriptor, count):
            data = real_read(descriptor, count)
            if not modes[descriptor]:
                return data.replace(b"\r\n", b"\n").split(b"\x1a", 1)[0]
            return data

        # Exercise untranslated length/offset/identity semantics on every OS.
        # Native Windows also runs this alongside the original CRLF fixture.
        with patch.object(os, "O_BINARY", binary_flag, create=True), \
                patch.object(os, "open", side_effect=crt_open), \
                patch.object(os, "read", side_effect=crt_read):
            data, metadata = diagnostic.bounded_file(path, tail=True)
        self.assertEqual(data, raw)
        self.assertEqual(metadata["source_bytes"], len(raw))
        self.assertFalse(metadata["truncated_prefix"])
        self.assertEqual(path.read_bytes(), raw)

    def test_aliases_and_cycle_capacity_are_rejected(self):
        path = self.directory / "daemon.log"
        path.write_text("original startup\n")
        alias = self.directory / "alias"
        os.link(path, alias)
        with self.assertRaises(ValueError):
            diagnostic.bounded_file(path, tail=True)
        wrong = copy.deepcopy(self.document)
        wrong["cycles"] *= 51
        with self.assertRaises(ValueError):
            diagnostic.collect(wrong, self.base / "output")

    def test_unavailable_reasons_never_copy_arbitrary_errors_or_source_content(self):
        marker = "fixture-only-sensitive-value"
        (self.directory / "readiness.json").write_text("bad-json " + marker)
        output = self.base / "output"
        result = diagnostic.collect(self.document, output)
        self.assertEqual(result["rows"][0]["readiness.json"]["reason"], "invalid_evidence")
        self.assertNotIn(marker, (output / "collection.json").read_text())
        self.assertEqual(diagnostic.unavailable_reason(ValueError(marker)), "invalid_evidence")
        self.assertEqual(diagnostic.unavailable_reason(ValueError("file_changed_or_capacity")), "file_changed_or_capacity")
        self.assertEqual(diagnostic.unavailable_reason(PermissionError(marker)), "source_io_error")


@unittest.skipUnless(shutil.which("pwsh"), "requires the actual PowerShell runtime")
class ActualReadinessFunctionTests(unittest.TestCase):
    def run_fixture(self, directory, *, trace_exists=False, delayed_auth=False):
        fixture = directory / "fixture.ps1"
        fixture.write_text(r'''param($Harness, $Auth, $Trace, [switch]$DelayedAuth)
$ErrorActionPreference = 'Stop'
$expectedSourceHeadSha = 'a' * 40
$expectedWorkflowSha = 'b' * 40
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Harness, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'harness parse failure' }
$definition = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Wait-DaemonReady' }, $true))
if ($definition.Count -ne 1) { throw 'missing actual readiness function' }
. ([scriptblock]::Create($definition[0].Extent.Text))
$script:count = 0
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, [string]$Uri, [int]$TimeoutSec)
    if (-not $UseBasicParsing -or $TimeoutSec -ne 2) { throw 'original request options changed' }
    $script:count++
    if ($DelayedAuth -and $script:count -eq 2) { [System.IO.File]::WriteAllText($Auth, 'fixture-session-value') }
    [pscustomobject]@{ StatusCode = 200 }
}
$value = Wait-DaemonReady -BaseUrl 'http://127.0.0.1:1' -AuthPath $Auth -DiagnosticPath $Trace -ObservedProcessId 123 3>$null
[ordered]@{ return_preserved = ($value -ceq 'fixture-session-value'); requests = $script:count } | ConvertTo-Json -Compress
''')
        auth = directory / "auth"
        trace = directory / "readiness.json"
        if not delayed_auth:
            auth.write_text("fixture-session-value")
        if trace_exists:
            trace.write_text("original trace")
        args = [shutil.which("pwsh"), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(fixture), "-Harness", str(Path(__file__).with_name("windows_lifecycle_acceptance.ps1")), "-Auth", str(auth), "-Trace", str(trace)]
        if delayed_auth:
            args.append("-DelayedAuth")
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout.strip())
        self.assertTrue(value["return_preserved"])
        return value, trace

    def test_actual_function_waits_for_auth_without_copying_the_token(self):
        with tempfile.TemporaryDirectory() as directory:
            result, trace = self.run_fixture(Path(directory), delayed_auth=True)
            self.assertEqual(result["requests"], 2)
            value = json.loads(trace.read_text())
            self.assertEqual(value["timeout_seconds"], 20)
            self.assertEqual(value["process_id"], 123)
            self.assertEqual([r["auth_exists"] for r in value["samples"]], [False, True])
            self.assertEqual([r["token_nonempty"] for r in value["samples"]], [None, True])
            self.assertNotIn("fixture-session-value", trace.read_text())

    def test_diagnostic_file_collision_keeps_original_success_and_existing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            result, trace = self.run_fixture(Path(directory), trace_exists=True)
            self.assertEqual(result["requests"], 1)
            self.assertEqual(trace.read_text(), "original trace")


if __name__ == "__main__":
    unittest.main()
