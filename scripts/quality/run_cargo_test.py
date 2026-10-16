#!/usr/bin/env python3
"""Run the original workspace suite once and retain its failed native artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time

from run_rust_tests import ROOT, _atomic_json, _utc_now, sha256_file, source_identity, toolchain_identity

MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_ARTIFACTS = 512
MAX_BINARY_BYTES = 1024 * 1024 * 1024
DRAIN_AFTER_EXIT_SECONDS = 5


def fingerprint(path: Path) -> tuple[int, ...]:
    value = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(value.st_mode):
        raise ValueError("not_regular_file")
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def bounded_binary_hash(path: Path, expected_bytes: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source:
        while chunk := source.read(min(1024 * 1024, expected_bytes - consumed + 1)):
            consumed += len(chunk)
            if consumed > expected_bytes:
                raise ValueError("binary_grew_during_hash")
            digest.update(chunk)
    if consumed != expected_bytes:
        raise ValueError("binary_shrank_during_hash")
    return digest.hexdigest()


class CargoIdentity:
    def __init__(self, root: Path, target: Path):
        self.root = root
        self.target = target.resolve()
        self.artifacts: dict[Path, dict] = {}
        self.build_success: bool | None = None
        self.last_running: Path | None = None
        self.unavailable: str | None = None
        self.capacity_exceeded = False
        self.lock = threading.Lock()

    def stdout_line(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except (ValueError, UnicodeError):
            return
        if not isinstance(message, dict):
            return
        with self.lock:
            # Test stdout shares this stream. After Cargo closes the build,
            # runtime JSON must not replace compiler identities or its verdict.
            if self.build_success is not None:
                return
            if message.get("reason") == "build-finished":
                self.build_success = message.get("success") is True
            if message.get("reason") != "compiler-artifact" or not message.get("profile", {}).get("test"):
                return
            executable = message.get("executable")
            if not isinstance(executable, str) or not executable:
                return
            path = (self.root / executable).absolute()
            try:
                resolved = path.resolve(strict=True)
                if self.target not in resolved.parents or resolved != path or path.is_symlink():
                    raise ValueError("outside_target_or_symlink")
                identity = fingerprint(path)
                if len(self.artifacts) >= MAX_ARTIFACTS and path not in self.artifacts:
                    self.capacity_exceeded = True
                    raise ValueError("artifact_capacity")
                self.artifacts[path] = {"fingerprint": identity, "target": message.get("target"), "package_id": message.get("package_id")}
            except (OSError, ValueError):
                self.unavailable = "artifact_identity_unavailable"

    def stderr_line(self, line: bytes) -> None:
        text = line.decode("utf-8", errors="replace").strip()
        with self.lock:
            if text.startswith("Doc-tests ") or "error: doctest failed" in text:
                self.last_running = None
                self.unavailable = "doctest_executable_not_reported"
            elif text.startswith("Running "):
                match = re.search(r"\((.+)\)$", text)
                self.last_running = (self.root / match[1]).absolute() if match else None
                if self.last_running is None:
                    self.unavailable = "running_executable_not_reported"

    def retain(self, evidence: Path, returncode: int) -> dict:
        if returncode == 0:
            return {"state": "not_needed", "reason": "cargo_succeeded"}
        if self.build_success is not True:
            return {"state": "unavailable", "reason": "build_not_successful"}
        path = self.last_running
        record = self.artifacts.get(path)
        if record is None or self.unavailable is not None:
            return {"state": "unavailable", "reason": self.unavailable or "running_not_in_cargo_artifacts"}
        destination = evidence / ("failed-test.exe" if path.suffix.lower() == ".exe" else "failed-test")
        try:
            before = fingerprint(path)
            if before != record["fingerprint"] or not 0 < before[2] <= MAX_BINARY_BYTES:
                raise ValueError("binary_changed_or_capacity")
            original_hash = bounded_binary_hash(path, before[2])
            # Binary mode preserves Windows CRLF and control-Z bytes too.
            with path.open("rb") as source, destination.open("xb") as output:
                copied = 0
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > before[2]:
                        raise ValueError("binary_changed_during_copy")
                    output.write(chunk)
            os.chmod(destination, 0o600)
            if fingerprint(path) != before or copied != before[2] or bounded_binary_hash(destination, before[2]) != original_hash or bounded_binary_hash(path, before[2]) != original_hash:
                raise ValueError("binary_changed_during_copy")
            return {"state": "retained", "path": destination.name, "original_path": str(path), "bytes": copied, "sha256": original_hash, "target": record["target"], "package_id": record["package_id"], "selection": "same Cargo invocation compiler-artifact and final Running record", "native_PID_observed": False}
        except (OSError, ValueError):
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            return {"state": "unavailable", "reason": "binary_copy_or_identity_failed"}


def capture_stream(stream, path: Path, output, consume, errors: list[str], stop=None) -> None:
    pending = bytearray()
    oversized_line = False
    stored = 0
    with path.open("xb", buffering=0) as log:
        os.chmod(path, 0o600)
        while chunk := stream.read1(65536):
            if stop is not None and stop.is_set():
                return
            remaining = max(0, MAX_LOG_BYTES - stored)
            log.write(chunk[:remaining])
            stored += min(len(chunk), remaining)
            if len(chunk) > remaining and "log_capacity" not in errors:
                errors.append("log_capacity")
            if output is not None:
                # Raw descriptors avoid a daemon pump owning Python's
                # buffered stdout lock during interpreter shutdown.
                remaining_output = memoryview(chunk)
                while remaining_output and (stop is None or not stop.is_set()):
                    written = os.write(output, remaining_output)
                    if written <= 0:
                        raise OSError("console_write_failed")
                    remaining_output = remaining_output[written:]
            for part in chunk.splitlines(keepends=True):
                if stop is not None and stop.is_set():
                    return
                if not oversized_line:
                    pending.extend(part)
                if len(pending) > MAX_LINE_BYTES:
                    if "line_capacity" not in errors:
                        errors.append("line_capacity")
                    pending.clear()
                    oversized_line = True
                if part.endswith(b"\n"):
                    if not oversized_line:
                        consume(bytes(pending))
                    pending.clear()
                    oversized_line = False
        if pending and not oversized_line and (stop is None or not stop.is_set()):
            consume(bytes(pending))


def run_suite(root: Path, evidence: Path, *, all_targets: bool, echo: bool = True) -> int:
    root = root.resolve()
    evidence = evidence.resolve()
    if evidence == root or root in evidence.parents or evidence.exists():
        raise ValueError("evidence must be a new directory outside the repository")
    evidence.mkdir(parents=True, mode=0o700)
    os.chmod(evidence, 0o700)
    command = ["cargo", "test", "--workspace"]
    if all_targets:
        command.append("--all-targets")
    command += ["--message-format=json", "--", "--test-threads=1", "--skip", "hard_hard_"]
    manifest = {"schema": 1, "started_at": _utc_now(), "command": command, "source": source_identity(root), "toolchain": toolchain_identity(), "workflow": {key: os.environ.get(key) for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "RUNNER_OS")}, "cargo_returncode": None, "failed_binary": {"state": "unavailable", "reason": "cargo_not_finished"}}
    manifest_path = evidence / "manifest.json"
    _atomic_json(manifest_path, manifest)
    returncode = None
    errors: list[str] = []
    try:
        metadata = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=root, check=True, capture_output=True)
        identity = CargoIdentity(root, Path(json.loads(metadata.stdout)["target_directory"]))
        environment = dict(os.environ, CARGO_TERM_COLOR="never")
        # The original Cargo wait has no added test timeout. After it exits,
        # an inherited pipe can remain open in a descendant. Never wait for
        # that descendant's EOF or close a BufferedReader held by its pump.
        stop = threading.Event()
        ready = threading.Event()
        process_box = []
        def pump(stream_name, name, output, consume):
            ready.wait()
            if not process_box:
                return
            stream = getattr(process_box[0], stream_name)
            try:
                capture_stream(stream, evidence / name, output, consume, errors, stop)
            except Exception:
                errors.append("stream_capture_failed")
                # Keep draining while the original Cargo is alive.
                while not stop.is_set() and stream.read1(65536):
                    pass
            finally:
                try:
                    stream.close()
                except OSError:
                    errors.append("stream_close_failed")
        threads = [threading.Thread(target=pump, args=("stdout", "cargo.stdout.log", sys.stdout.fileno() if echo else None, identity.stdout_line), daemon=True), threading.Thread(target=pump, args=("stderr", "cargo.stderr.log", sys.stderr.fileno() if echo else None, identity.stderr_line), daemon=True)]
        try:
            # A thread-capacity failure occurs before Cargo is spawned.
            for thread in threads:
                thread.start()
            process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
            process_box.append(process)
        finally:
            ready.set()
        returncode = process.wait()
        drain_end = time.monotonic() + DRAIN_AFTER_EXIT_SECONDS
        for thread in threads:
            thread.join(max(0, drain_end - time.monotonic()))
        drained = all(not thread.is_alive() for thread in threads)
        stop.set()
        if not drained:
            errors.append("stream_not_closed_after_cargo_exit")
        manifest.update(cargo_returncode=returncode, build_success=identity.build_success, compiler_artifact_count=len(identity.artifacts), stream_drain={"complete": drained, "postexit_limit_seconds": DRAIN_AFTER_EXIT_SECONDS}, failed_binary=identity.retain(evidence, returncode) if drained else {"state": "unavailable", "reason": "stream_not_closed_after_cargo_exit"})
        if identity.capacity_exceeded:
            errors.append("artifact_capacity")
        manifest["source_after"] = source_identity(root)
        manifest["toolchain_after"] = toolchain_identity()
        if manifest["source_after"] != manifest["source"]:
            errors.append("source_changed")
        if manifest["toolchain_after"] != manifest["toolchain"]:
            errors.append("toolchain_changed")
        for name in ("cargo.stdout.log", "cargo.stderr.log"):
            path = evidence / name
            manifest.setdefault("logs", {})[name] = {"complete": drained, "bytes": path.stat().st_size, "sha256": sha256_file(path) if drained else None}
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError):
        errors.append("runner_or_metadata_failed")
    finally:
        manifest.update(finished_at=_utc_now(), evidence_errors=sorted(set(errors)), source_bound=not errors)
        try:
            _atomic_json(manifest_path, manifest)
        except OSError:
            errors.append("manifest_write_failed")
    # Always preserve the original Cargo failure, including when retention fails.
    return returncode if returncode else (1 if errors else 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--all-targets", action="store_true")
    args = parser.parse_args()
    try:
        return run_suite(ROOT, args.evidence_dir, all_targets=args.all_targets)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL Cargo evidence setup: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
