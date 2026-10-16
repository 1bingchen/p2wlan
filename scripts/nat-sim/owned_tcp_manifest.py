#!/usr/bin/env python3
"""Freeze one optional diagnostic image and bind its original round targets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from launch_identity import (digest_file, load_object, read_bound_process_birth,
                             validate_artifact_set, validate_source, verify_snapshot, write_new)
from monotonic_clock import monotonic_ns
from process_birth import _private_bytes

SOURCE = Path(__file__).with_name("owned_tcp_observer.c")


def freeze_curl(directory: Path, expected: dict | None = None, retained: Path | None = None) -> dict:
    """Retain the selected original caller; never substitute its executable."""
    path = Path(shutil.which("curl") or "")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024 * 1024:
        raise ValueError("tcp_curl_capacity_or_type_invalid")
    value = {"path": str(path.absolute()), "sha256": digest_file(path), "bytes": info.st_size}
    if expected is not None and value != expected:
        raise ValueError("tcp_original_curl_changed")
    target = directory / "curl-original"
    original = retained or path
    original_info = original.stat()
    if (not stat.S_ISREG(original_info.st_mode) or original_info.st_size != value["bytes"]
            or (retained is not None and retained.is_symlink())):
        raise ValueError("tcp_original_curl_snapshot_invalid")
    with original.open("rb") as incoming, target.open("xb") as outgoing:
        payload = incoming.read(value["bytes"] + 1)
        if len(payload) != value["bytes"]:
            raise ValueError("tcp_original_curl_snapshot_changed")
        os.fchmod(outgoing.fileno(), 0o400)
        outgoing.write(payload)
    if digest_file(target) != value["sha256"] or digest_file(path) != value["sha256"]:
        raise ValueError("tcp_original_curl_changed_during_snapshot")
    return value


def verify_curl(value: dict, path: str) -> None:
    actual = Path(path)
    if (value.get("path") != str(actual.absolute()) or actual.stat().st_size != value.get("bytes")
            or digest_file(actual) != value.get("sha256")):
        raise ValueError("tcp_original_curl_changed")


def private_object(path: Path) -> dict:
    value = json.loads(_private_bytes(path, 16384))
    if not isinstance(value, dict):
        raise ValueError("tcp_private_object_invalid")
    return value


def image_from_manifest(path: Path, source: dict) -> tuple[dict, Path | None]:
    value = private_object(path)
    if (value.get("schema_version") != 1 or value.get("source") != source
            or value.get("native_source_sha256") != digest_file(SOURCE)
            or value.get("state") not in {"available", "unavailable"}):
        raise ValueError("tcp_image_source_mismatch")
    validate_source(value["source"])
    if value["state"] == "unavailable":
        return value, None
    image = path.parent / "observer"
    info = image.lstat()
    if (path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700
            or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o500
            or not 0 < info.st_size <= 1024 * 1024
            or info.st_size != value.get("image_bytes") or digest_file(image) != value.get("image_sha256")):
        raise ValueError("tcp_image_changed")
    return value, image


def prepare_image(base: Path, artifact_set: Path, reuse: Path | None = None) -> dict:
    artifacts = load_object(artifact_set)
    validate_artifact_set(artifacts)
    directory = base / "tcp-observer"
    directory.mkdir(mode=0o700)
    value = {"schema_version": 1, "source": artifacts["source"],
             "native_source_sha256": digest_file(SOURCE), "state": "unavailable"}
    if reuse is not None:
        try:
            reused, image = image_from_manifest(reuse, artifacts["source"])
            if image is not None:
                with image.open("rb") as incoming, (directory / "observer").open("xb") as outgoing:
                    payload = incoming.read(1024 * 1024 + 1)
                    if len(payload) != reused["image_bytes"]:
                        raise ValueError("tcp_image_changed_during_copy")
                    os.fchmod(outgoing.fileno(), 0o500)
                    outgoing.write(payload)
                if digest_file(directory / "observer") != reused["image_sha256"]:
                    raise ValueError("tcp_image_changed_during_copy")
                freeze_curl(directory, reused["curl"], reuse.parent / "curl-original")
            value = reused
        except (OSError, ValueError, KeyError, TypeError):
            value["reason"] = "retained_diagnostic_image_or_caller_unavailable"
    elif sys.platform != "darwin":
        value["reason"] = "unsupported_platform"
    else:
        image = directory / "observer"
        try:
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(SOURCE), "-o", str(image)], check=True, timeout=20,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            image.chmod(0o500)
            if digest_file(SOURCE) != value["native_source_sha256"]:
                raise ValueError("tcp_native_source_changed_during_build")
            value.update(state="available", image_sha256=digest_file(image), image_bytes=image.stat().st_size,
                         curl=freeze_curl(directory))
        except (OSError, subprocess.SubprocessError, ValueError):
            value["reason"] = "native_build_or_caller_identity_unavailable"
    write_new(directory / "manifest.json", value)
    return value


def prepare_pair(base: Path, round_dir: Path, owner: int, targets: list[tuple[int, int]],
                 cutoff_ms: int) -> Path:
    """Only the original Bash owner may supply targets already in its PIDS."""
    started = monotonic_ns()
    if owner <= 0 or cutoff_ms * 1_000_000 <= started or len(targets) != 2:
        raise ValueError("tcp_setup_deadline_or_owner_invalid")
    artifacts = load_object(base / "artifact-set.json")
    validate_artifact_set(artifacts)
    manifest, image = image_from_manifest(base / "tcp-observer/manifest.json", artifacts["source"])
    if image is None:
        raise ValueError("tcp_native_image_unavailable")
    # Verify retained original bytes, not a late executable-name lookup.
    verify_snapshot(base, "daemon", artifacts["artifacts"]["daemon"])
    bindings = {}
    for side, (pid, port) in zip(("a", "b"), targets):
        role = f"node-{side}"
        path = round_dir / "launches" / f"{role}.json"
        record = load_object(path)
        bound = read_bound_process_birth(path, artifacts["source"], role)
        birth = bound["observation"]
        if (record["artifact_set_sha256"] != digest_file(base / "artifact-set.json")
                or record["artifact"] != artifacts["artifacts"]["daemon"] or record["pid"] != pid
                or birth.get("state") != "available" or birth["ppid"] != owner
                or birth["uid"] != os.getuid() or not 1 <= port <= 65535):
            raise ValueError("tcp_original_launch_binding_invalid")
        bindings[side] = {"pid": pid, "port": port, "birth": birth,
                          "launch_record_sha256": bound["launch_record_sha256"],
                          "artifact_sha256": record["artifact"]["sha256"]}
    directory = round_dir / "tcp-observation"
    directory.mkdir(mode=0o700)
    for side in ("a", "b"):
        for kind in ("in", "out"):
            os.mkfifo(directory / f"{side}-{kind}", 0o600)
    if monotonic_ns() >= cutoff_ms * 1_000_000:
        raise ValueError("tcp_setup_deadline_exhausted")
    write_new(directory / "context.json", {"schema_version": 1, "source": artifacts["source"],
        "owner_pid": owner, "image": str(image), "manifest": manifest, "targets": bindings,
        "fixed_work_cutoff_ms": cutoff_ms, "setup_started_monotonic_ns": started,
        "setup_completed_monotonic_ns": monotonic_ns(), "selection": "first_original_status_pair_only"})
    return image


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("prepare")
    build.add_argument("--base", type=Path, required=True)
    build.add_argument("--reuse", type=Path)
    pair = sub.add_parser("pair")
    pair.add_argument("--base", type=Path, required=True)
    pair.add_argument("--round-dir", type=Path, required=True)
    pair.add_argument("--owner", type=int, required=True)
    pair.add_argument("--cutoff-ms", type=int, required=True)
    pair.add_argument("--a-pid", type=int, required=True)
    pair.add_argument("--b-pid", type=int, required=True)
    pair.add_argument("--a-port", type=int, required=True)
    pair.add_argument("--b-port", type=int, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare_image(args.base, args.base / "artifact-set.json", args.reuse)
    else:
        print(prepare_pair(args.base, args.round_dir, args.owner,
                           [(args.a_pid, args.a_port), (args.b_pid, args.b_port)], args.cutoff_ms))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        # Paths/inputs/native error text never enter public logs.
        print("owned_tcp_unavailable:prepare_failed", file=sys.stderr)
        raise SystemExit(1)
