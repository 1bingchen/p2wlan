#!/usr/bin/env python3
"""Register the official CocoaPods CDN before a macOS build, with bounded metadata work."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

CDN_URL = "https://cdn.cocoapods.org/"
ATTEMPTS = 3
REQUEST_TIMEOUT_SECONDS = 20
TERMINATE_GRACE_SECONDS = 2
MAX_METADATA_FILE_BYTES = 2 * 1024 * 1024


def limit_metadata_files() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_METADATA_FILE_BYTES, MAX_METADATA_FILE_BYTES))


def metadata_attempt(pod: str, environment: dict[str, str], output: Path, attempt: int) -> dict:
    stdout = output / f"attempt-{attempt}.stdout"
    stderr = output / f"attempt-{attempt}.stderr"
    command = [pod, "repo", "add-cdn", "trunk", CDN_URL]
    began = time.monotonic()
    timed_out = forced = False
    with stdout.open("xb") as out, stderr.open("xb") as err:
        child = subprocess.Popen(
            command,
            env=environment,
            stdout=out,
            stderr=err,
            start_new_session=True,
            preexec_fn=limit_metadata_files,
        )
        try:
            child.wait(timeout=REQUEST_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            # The group was created by this Popen; no existing process is targeted.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                forced = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=TERMINATE_GRACE_SECONDS)
    logs = {}
    for path, stream in [(stdout, sys.stdout), (stderr, sys.stderr)]:
        data = path.read_bytes()
        assert len(data) <= MAX_METADATA_FILE_BYTES
        logs[path.name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if data:
            print(data.decode("utf-8", errors="replace"), file=stream, end="", flush=True)
    return {
        "attempt": attempt,
        "command": command,
        "owned_pid": child.pid,
        "wait_completed": True,
        "returncode": child.returncode,
        "timed_out": timed_out,
        "forced": forced,
        "elapsed_seconds": time.monotonic() - began,
        "logs": logs,
    }


def prepare(output: Path, github_env: Path, source_sha: str) -> dict:
    if os.name != "posix" or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("CocoaPods metadata preparation requires POSIX and an exact source SHA")
    if github_env.is_symlink() or not github_env.parent.is_dir():
        raise ValueError("GitHub environment file must have an existing parent and must not be a symlink")
    pod = shutil.which("pod")
    if pod is None:
        raise FileNotFoundError("CocoaPods executable is unavailable")
    output.mkdir(mode=0o700, exist_ok=False)
    home = (output / "home").resolve()
    home.mkdir(mode=0o700)
    if any(c in str(home) for c in "\r\n"):
        raise ValueError("CocoaPods cache path cannot contain line breaks")
    environment = dict(os.environ)
    environment.update(
        CP_HOME_DIR=str(home),
        CP_REPOS_DIR=str(home / "repos"),
        COCOAPODS_DISABLE_STATS="true",
        COCOAPODS_SKIP_UPDATE_MESSAGE="true",
    )
    result = {"source_sha": source_sha, "cdn_url": CDN_URL, "cache_home": str(home), "passed": False, "attempts": []}
    for attempt in range(1, ATTEMPTS + 1):
        print(f"CocoaPods CDN metadata attempt {attempt}/{ATTEMPTS}", flush=True)
        row = metadata_attempt(pod, environment, output, attempt)
        result["attempts"].append(row)
        result["passed"] = row["returncode"] == 0 and not row["timed_out"]
        (output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
        if result["passed"]:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
            with os.fdopen(os.open(github_env, flags, 0o600), "a") as exported:
                exported.write(f"CP_HOME_DIR={home}\nCP_REPOS_DIR={home / 'repos'}\n")
            break
        if attempt < ATTEMPTS:
            time.sleep(attempt)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.evidence_dir, args.github_env, args.source_sha)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"CocoaPods CDN metadata preparation failed: {error}", file=sys.stderr)
        return 1
    print("cocoapods_cdn_metadata=" + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
