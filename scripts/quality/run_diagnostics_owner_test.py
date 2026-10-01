#!/usr/bin/env python3
"""Run the fixed root-only daemon ownership regressions in Linux CI."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "p2wlan-daemon"
TARGETS = {"bin": PACKAGE, "lib": "p2pnet_daemon"}
CASES = (
    ("bin", "tests::diagnostics_auth_privileged_owner_survives_repair"),
    (
        "bin",
        "tests::runtime_directory_prepare_regressions::"
        "runtime_directory_prepare_privileged_root_owned_paths_preserve_data_and_foreign_owners",
    ),
    ("lib", "config::persistence_tests::privileged_config_save_inherits_pinned_directory_owner"),
)


class DiagnosticsOwnerGateError(RuntimeError):
    pass


def build_test_binaries() -> dict[str, Path]:
    # Compile without elevation. Only artifacts emitted by this successful
    # invocation are eligible; never guess a filename in target/debug/deps.
    command = [
        "cargo", "test", "--locked", "-p", PACKAGE, "--lib", "--bin", PACKAGE,
        "--no-run", "--message-format=json",
    ]
    print("+ " + " ".join(command), flush=True)
    candidates: dict[str, set[Path]] = {kind: set() for kind in TARGETS}
    manifest = (ROOT / "client/daemon/Cargo.toml").resolve()
    with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, text=True) as process:
        assert process.stdout is not None
        for line in process.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                print(line, end="", flush=True)
                continue
            if not isinstance(message, dict):
                continue
            if message.get("reason") == "compiler-message":
                rendered = message.get("message", {}).get("rendered")
                if rendered:
                    print(rendered, end="", file=sys.stderr, flush=True)
            executable = message.get("executable")
            target = message.get("target", {})
            if (
                message.get("reason") == "compiler-artifact"
                and message.get("profile", {}).get("test") is True
                and message.get("manifest_path") == str(manifest)
                and isinstance(executable, str)
                and executable
            ):
                for kind, name in TARGETS.items():
                    if target.get("name") == name and target.get("kind") == [kind]:
                        candidates[kind].add(Path(executable).resolve())
        returncode = process.wait()
    if returncode:
        raise DiagnosticsOwnerGateError(
            f"Cargo test build failed ({returncode}); no existing binary will be reused"
        )
    binaries: dict[str, Path] = {}
    for kind, paths in candidates.items():
        if len(paths) != 1:
            raise DiagnosticsOwnerGateError(
                f"expected exactly one Cargo {kind} test artifact for {TARGETS[kind]}, "
                f"found {len(paths)}"
            )
        binary = paths.pop()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise DiagnosticsOwnerGateError(f"Cargo test artifact is not executable: {binary}")
        binaries[kind] = binary
    if len(set(binaries.values())) != len(TARGETS):
        raise DiagnosticsOwnerGateError("Cargo bin and lib test artifacts must be distinct")
    return binaries


def run_checked(command: list[str], timeout: int) -> str:
    print("+ " + " ".join(command), flush=True)
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False
    )
    print(result.stdout, end="", flush=True)
    print(result.stderr, end="", file=sys.stderr, flush=True)
    if result.returncode:
        raise DiagnosticsOwnerGateError(f"command failed ({result.returncode}): {command[0]}")
    return result.stdout


def main() -> int:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise DiagnosticsOwnerGateError("run this Linux CI gate as the unprivileged runner, not root")
    if len(sys.argv) != 1:
        raise DiagnosticsOwnerGateError("this gate accepts no custom binary, test selector, or runner")

    binaries = build_test_binaries()
    # Verify every fixed selector without elevation before running any root case.
    for kind, selector in CASES:
        listed = run_checked(
            [
                str(binaries[kind]), "--list", "--ignored", "--exact", selector,
                "--format=terse", "--color=never",
            ],
            timeout=30,
        )
        entries = re.findall(r"^(.+): (test|benchmark)$", listed, flags=re.MULTILINE)
        if entries != [(selector, "test")]:
            raise DiagnosticsOwnerGateError(
                f"expected exactly the one ignored owner test {selector}, found {entries!r}"
            )

    # Only one fixed allowlisted test per invocation is elevated. Cargo and
    # artifact selection always run under the runner's ordinary credentials.
    for kind, selector in CASES:
        output = run_checked(
            [
                "sudo", "--non-interactive", "--", str(binaries[kind]),
                "--ignored", "--exact", selector, "--test-threads=1",
                "--format=pretty", "--color=never",
            ],
            timeout=120,
        )
        summaries = re.findall(
            r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;",
            output,
            flags=re.MULTILINE,
        )
        completed = re.findall(r"^test (.+) \.\.\. ok$", output, flags=re.MULTILINE)
        if summaries != [("1", "0", "0", "0")] or completed != [selector]:
            raise DiagnosticsOwnerGateError(
                f"owner regression {selector} must actually execute exactly once: "
                "1 passed, 0 failed, 0 ignored"
            )
    print("daemon ownership gate PASS (3 passed, 0 failed, 0 ignored)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DiagnosticsOwnerGateError, OSError, subprocess.TimeoutExpired) as error:
        print(f"daemon ownership gate failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
