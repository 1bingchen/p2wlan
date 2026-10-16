#!/usr/bin/env python3
"""Bounded, credential-free copies of the original production cycle evidence.

Missing files and identity/race failures stay unavailable. This collector does
not decide whether the daemon started, stopped, or met its original deadlines.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat

CAP = 65536
MAX_CYCLES = 50
SENSITIVE = re.compile(r"token|secret|password|private|authorization|bearer|-----BEGIN|-----END", re.I)
OPAQUE = re.compile(r"[A-Za-z0-9_+/=-]{40,}")
UNAVAILABLE_REASONS = frozenset({
    "symlink", "not_single_regular_file", "file_capacity", "file_changed_or_capacity",
    "readiness_contract", "readiness_identity_mismatch", "readiness_process_mismatch",
    "sample_capacity", "sample_type", "sample_time", "sample_order", "http_status",
    "sample_boolean", "exception_type", "dropped_samples",
})


def unavailable_reason(error: Exception) -> str:
    if isinstance(error, FileNotFoundError):
        return "missing_source"
    if isinstance(error, OSError):
        return "source_io_error"
    # Only our fixed codes may leave the collector. Parse errors can carry
    # the source document; neither their text nor filenames are evidence.
    if len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in UNAVAILABLE_REASONS:
        return error.args[0]
    return "invalid_evidence"


def bounded_file(path: Path, *, tail: bool = False) -> tuple[bytes, dict]:
    if path.is_symlink():
        raise ValueError("symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("not_single_regular_file")
        if not tail and before.st_size > CAP:
            raise ValueError("file_capacity")
        if tail:
            os.lseek(descriptor, max(0, before.st_size - CAP), os.SEEK_SET)
        raw = os.read(descriptor, CAP + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if len(raw) != min(before.st_size, CAP) or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise ValueError("file_changed_or_capacity")
        return raw, {"source_bytes": before.st_size, "truncated_prefix": tail and before.st_size > CAP}
    finally:
        os.close(descriptor)


def sanitized_log(raw: bytes, truncated: bool) -> tuple[str, int]:
    lines = raw.decode("utf-8", errors="replace").splitlines()
    if truncated and lines:
        lines = lines[1:]  # Never expose the suffix of an unknown first line.
    output, omitted = [], 0
    for line in lines[-512:]:
        if len(line) > 1024 or SENSITIVE.search(line) or OPAQUE.search(line):
            output.append("[credential-related or oversized line omitted]")
            omitted += 1
        else:
            output.append(line)
    return "\n".join(output) + "\n", omitted


def readiness(raw: bytes, document: dict, cycle: dict) -> dict:
    value = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value.get("schema_version") != 1 or type(value.get("timeout_seconds")) is not int or value.get("timeout_seconds") != 20 or value.get("clock") != "stopwatch":
        raise ValueError("readiness_contract")
    for key in ("source_head_sha", "workflow_sha"):
        if not isinstance(value.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", value[key]) or value[key] != document.get(key):
            raise ValueError("readiness_identity_mismatch")
    if type(value.get("process_id")) is not int or value["process_id"] <= 0 or value["process_id"] != cycle.get("pid"):
        raise ValueError("readiness_process_mismatch")
    records = value.get("samples")
    if not isinstance(records, list) or len(records) > 128:
        raise ValueError("sample_capacity")
    keys = ("sequence", "started_ms", "completed_ms", "http_status", "auth_exists", "token_nonempty", "exception_type")
    copied = []
    previous_end = 0
    for row in records:
        if not isinstance(row, dict):
            raise ValueError("sample_type")
        item = {k: row.get(k) for k in keys}
        if any(type(item[k]) is not int or item[k] < 0 for k in ("sequence", "started_ms", "completed_ms")):
            raise ValueError("sample_time")
        if item["sequence"] != len(copied) + 1 or item["started_ms"] < previous_end or item["completed_ms"] < item["started_ms"]:
            raise ValueError("sample_order")
        previous_end = item["completed_ms"]
        if item["http_status"] is not None and (type(item["http_status"]) is not int or not 100 <= item["http_status"] <= 599):
            raise ValueError("http_status")
        if any(item[k] is not None and type(item[k]) is not bool for k in ("auth_exists", "token_nonempty")):
            raise ValueError("sample_boolean")
        if item["exception_type"] is not None and not re.fullmatch(r"[A-Za-z0-9_.+`]{1,128}", item["exception_type"]):
            raise ValueError("exception_type")
        copied.append(item)
    dropped = value.get("dropped_samples")
    if type(dropped) is not int or dropped < 0:
        raise ValueError("dropped_samples")
    return {"schema_version": 1, "source_head_sha": document["source_head_sha"], "workflow_sha": document["workflow_sha"], "process_id": cycle["pid"], "timeout_seconds": 20, "clock": "stopwatch", "dropped_samples": dropped, "samples": copied}


def collect(document: dict, output: Path) -> dict:
    root = Path(document["production_artifact_root"])
    if not root.is_absolute() or root.is_symlink() or not re.fullmatch(r"p2wlan-windows-lifecycle-[0-9a-f]{32}", root.name):
        raise ValueError("runtime_root")
    cycles = [c for c in document["cycles"] if c["entrypoint"] != "ui"]
    if not 1 <= len(cycles) <= MAX_CYCLES or [c["cycle"] for c in cycles] != list(range(1, len(cycles) + 1)):
        raise ValueError("cycle_capacity_or_identity")
    output.mkdir(exist_ok=False)
    rows = []
    for cycle in cycles:
        row = {"cycle": cycle["cycle"], "pid": cycle["pid"], "forced_termination": cycle["forced_termination"]}
        directory = root / f"cycle-{cycle['cycle']}"
        if directory.is_symlink():
            raise ValueError("cycle_directory_symlink")
        target = output / directory.name
        target.mkdir()
        for name in ("daemon.log", "readiness.json"):
            try:
                raw, info = bounded_file(directory / name, tail=name == "daemon.log")
                if name == "daemon.log":
                    text, omitted = sanitized_log(raw, info["truncated_prefix"])
                    (target / "daemon-sanitized.log").write_text(text)
                    info["omitted_lines"] = omitted
                else:
                    value = readiness(raw, document, cycle)
                    (target / name).write_text(json.dumps(value, indent=2) + "\n")
                row[name] = {"state": "collected", **info}
            except (OSError, ValueError, TypeError, KeyError) as error:
                row[name] = {"state": "unavailable", "reason": unavailable_reason(error)}
        rows.append(row)
    result = {"schema_version": 1, "source_head_sha": document["source_head_sha"], "workflow_sha": document["workflow_sha"], "original_cycles": len(cycles), "cycle_capacity": MAX_CYCLES, "file_read_capacity": CAP, "changes_original_verdict": False, "rows": rows}
    (output / "collection.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    collect(json.loads(args.input.read_text(encoding="utf-8-sig")), args.output)
