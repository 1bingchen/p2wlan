"""Read bounded cargo-deny JSON streams without assuming their output channel."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 65_536
CHECKS = frozenset({"advisories", "bans", "licenses", "sources"})
COUNTERS = frozenset({"errors", "warnings", "notes", "helps"})


@dataclass
class DenyOutput:
    records: list[dict[str, Any]]
    channels: dict[str, int]
    checks: dict[str, dict[str, int]] | None


def read_output(
    stdout: Path,
    stderr: Path | None,
    findings: list[dict[str, str]],
    graph: str,
) -> DenyOutput:
    """Combine records for validation, without assigning a cross-stream order."""
    records: list[dict[str, Any]] = []
    channels: dict[str, int] = {}
    remaining = MAX_OUTPUT_BYTES
    seen_lines = 0

    def reject(code: str, message: str) -> None:
        findings.append({"code": code, "message": f"{graph}: {message}"})

    for channel, path in [("stdout", stdout), ("stderr", stderr)]:
        if path is None:
            continue
        channels[channel] = 0
        try:
            with path.open("rb") as stream:
                raw = stream.read(remaining + 1)
            if len(raw) > remaining:
                reject("cargo_deny_output_limit", "combined output exceeds 16 MiB")
                break
            remaining -= len(raw)
            lines = raw.decode("utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            reject("invalid_cargo_deny_jsonl", f"{channel} {path}: {error}")
            continue
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            if seen_lines >= MAX_RECORDS:
                reject("cargo_deny_record_limit", "output exceeds 65536 JSON records")
                break
            seen_lines += 1
            try:
                record = json.loads(line)
            except (ValueError, RecursionError) as error:
                reject("invalid_cargo_deny_jsonl", f"{channel} {path}:{number}: {error}")
                continue
            if not isinstance(record, dict):
                reject("invalid_cargo_deny_record", f"{channel}:{number}: expected an object")
                continue
            records.append(record)
            channels[channel] += 1

    if not records:
        reject("empty_cargo_deny_output", "no structured diagnostics or completion summary")
    summaries: list[dict[str, Any]] = []
    for record in records:
        fields = record.get("fields")
        if not isinstance(fields, dict):
            reject("invalid_cargo_deny_record", "record fields must be an object")
            continue
        if record.get("type") == "summary":
            summaries.append(fields)
        elif record.get("type") == "diagnostic":
            severity = fields.get("severity")
            if severity not in {"error", "warning", "note", "help"}:
                reject("invalid_cargo_deny_diagnostic", "missing or unknown severity")
            elif severity == "error":
                reject("cargo_deny_error_diagnostic", "scanner emitted an error diagnostic")
        else:
            reject("invalid_cargo_deny_record", "unknown record type")

    if len(summaries) != 1:
        reject("cargo_deny_completion_summary", "expected exactly one completion summary")
        return DenyOutput(records, channels, None)
    summary = summaries[0]
    if set(summary) != CHECKS:
        reject("cargo_deny_completion_checks", "summary must cover advisories, bans, licenses and sources")
        return DenyOutput(records, channels, None)
    valid = True
    for check, totals in summary.items():
        if not isinstance(totals, dict) or set(totals) != COUNTERS:
            reject("invalid_cargo_deny_summary", f"{check}: missing completion counters")
            valid = False
            continue
        if any(type(value) is not int or value < 0 for value in totals.values()):
            reject("invalid_cargo_deny_summary", f"{check}: counters must be nonnegative integers")
            valid = False
        elif totals["errors"]:
            reject("cargo_deny_summary_errors", f"{check}: completion reports errors")
    return DenyOutput(records, channels, summary if valid else None)
