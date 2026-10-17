from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SECURITY = Path(__file__).resolve().parents[1]
if str(SECURITY) not in sys.path:
    sys.path.insert(0, str(SECURITY))
import dependency_reports


def summary(*, warnings: int = 0, errors: int = 0) -> dict:
    fields = {
        check: {"errors": 0, "warnings": 0, "notes": 0, "helps": 0}
        for check in ["advisories", "bans", "licenses", "sources"]
    }
    fields["bans"]["warnings"] = warnings
    fields["licenses"]["errors"] = errors
    return {"type": "summary", "fields": fields}


def diagnostic(severity: str = "warning") -> dict:
    return {
        "type": "diagnostic",
        "fields": {
            "severity": severity,
            "code": "duplicate" if severity == "warning" else "rejected",
            "message": "dependency diagnostic",
        },
    }


def write_records(path: Path, *records: dict) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


class CargoDenyOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.args = argparse.Namespace(
            root_audit=root / "root-audit.json",
            fuzz_audit=root / "fuzz-audit.json",
            root_deny=root / "root-deny.jsonl",
            fuzz_deny=root / "fuzz-deny.jsonl",
            root_deny_stderr=root / "root-deny.stderr",
            fuzz_deny_stderr=root / "fuzz-deny.stderr",
            deny_config=root / "deny.toml",
            advisory_exceptions=root / "advisory-exceptions.json",
            root_audit_status=0, fuzz_audit_status=0,
            root_deny_status=0, fuzz_deny_status=0,
            head_sha="a" * 40, workflow_sha="b" * 40,
            repository="example/project",
            cargo_audit_version="cargo-audit 0.22.2",
            cargo_deny_version="cargo-deny 0.20.2",
        )
        for path in [self.args.root_audit, self.args.fuzz_audit]:
            path.write_text('{"vulnerabilities":{"count":0},"warnings":{}}', encoding="utf-8")
        for path in [self.args.root_deny, self.args.fuzz_deny]:
            path.write_text("", encoding="utf-8")
        for path in [self.args.root_deny_stderr, self.args.fuzz_deny_stderr]:
            write_records(path, summary())
        self.args.deny_config.write_text("[advisories]\nignore = []\n", encoding="utf-8")
        self.args.advisory_exceptions.write_text('{"exceptions":[]}', encoding="utf-8")

    def report(self) -> dict:
        return dependency_reports.rust_summary(self.args)

    def test_stderr_records_are_counted_when_stdout_is_empty(self) -> None:
        write_records(self.args.root_deny_stderr, diagnostic(), summary(warnings=1))
        report = self.report()
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["cargo_deny_record_counts"], {"root": 2, "fuzz": 1})

    def test_stdout_summary_and_stderr_diagnostics_are_both_retained(self) -> None:
        write_records(self.args.root_deny, summary(warnings=1))
        write_records(self.args.root_deny_stderr, diagnostic())
        report = self.report()
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["cargo_deny_record_counts"]["root"], 2)

    def test_empty_success_output_is_rejected(self) -> None:
        self.args.root_deny_stderr.write_text("", encoding="utf-8")
        self.assertEqual(self.report()["result"], "fail")

    def test_error_diagnostic_with_zero_exit_status_is_rejected(self) -> None:
        write_records(self.args.root_deny_stderr, diagnostic("error"), summary())
        self.assertEqual(self.report()["result"], "fail")

    def test_summary_error_with_zero_exit_status_is_rejected(self) -> None:
        write_records(self.args.root_deny_stderr, summary(errors=1))
        self.assertEqual(self.report()["result"], "fail")

    def test_missing_requested_check_is_rejected(self) -> None:
        record = summary()
        del record["fields"]["sources"]
        write_records(self.args.root_deny_stderr, record)
        self.assertEqual(self.report()["result"], "fail")

    def test_malformed_stderr_is_rejected(self) -> None:
        self.args.root_deny_stderr.write_text("{not-json\n", encoding="utf-8")
        self.assertEqual(self.report()["result"], "fail")

    def test_duplicate_completion_summary_is_rejected(self) -> None:
        write_records(self.args.root_deny_stderr, summary(), summary())
        self.assertEqual(self.report()["result"], "fail")

    def test_valid_stdout_only_output_remains_compatible(self) -> None:
        self.args.root_deny_stderr = self.args.fuzz_deny_stderr = None
        for path in [self.args.root_deny, self.args.fuzz_deny]:
            write_records(path, summary())
        report = self.report()
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["cargo_deny_record_counts"], {"root": 1, "fuzz": 1})

    def test_cli_accepts_both_actual_diagnostic_streams(self) -> None:
        output = Path(self.tmp.name) / "report.json"
        command = [sys.executable, "-B", str(SECURITY / "dependency_reports.py"), "rust"]
        for name, value in vars(self.args).items():
            command.extend(["--" + name.replace("_", "-"), str(value)])
        command.extend(["--output", str(output)])
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())["cargo_deny_output_channels"], {
            "root": {"stdout": 0, "stderr": 1},
            "fuzz": {"stdout": 0, "stderr": 1},
        })

    def test_invalid_completion_counter_is_rejected(self) -> None:
        for value in [-1, False]:
            with self.subTest(value=value):
                record = summary()
                record["fields"]["licenses"]["errors"] = value
                write_records(self.args.root_deny_stderr, record)
                self.assertEqual(self.report()["result"], "fail")

    def test_unknown_record_is_rejected(self) -> None:
        write_records(self.args.root_deny_stderr, {"type": "unknown", "fields": {}}, summary())
        self.assertEqual(self.report()["result"], "fail")

    def test_combined_output_byte_bound_is_enforced(self) -> None:
        from cargo_deny_report import MAX_OUTPUT_BYTES
        with self.args.root_deny_stderr.open("wb") as stream:
            stream.truncate(MAX_OUTPUT_BYTES + 1)
        report = self.report()
        self.assertEqual(report["result"], "fail")
        self.assertIn("cargo_deny_output_limit", {row["code"] for row in report["findings"]})

    def test_malformed_record_count_is_bounded(self) -> None:
        from cargo_deny_report import MAX_RECORDS
        self.args.root_deny_stderr.write_text("{\n" * (MAX_RECORDS + 1), encoding="utf-8")
        report = self.report()
        self.assertEqual(report["result"], "fail")
        self.assertIn("cargo_deny_record_limit", {row["code"] for row in report["findings"]})
        self.assertLessEqual(len(report["findings"]), MAX_RECORDS + 3)

    def test_nested_json_failure_is_structured(self) -> None:
        self.args.root_deny_stderr.write_text("[" * 2000 + "]" * 2000, encoding="utf-8")
        report = self.report()
        self.assertEqual(report["result"], "fail")
        self.assertIn("invalid_cargo_deny_jsonl", {row["code"] for row in report["findings"]})


if __name__ == "__main__":
    unittest.main()
