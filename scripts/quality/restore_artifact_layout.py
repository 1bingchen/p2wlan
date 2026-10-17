#!/usr/bin/env python3
"""Restore artifact-name directories after v8 pattern downloads.

Use separate, empty download destinations with merge-multiple:false. v8
flattens a single match, but nests multiple matches. The authenticated run
inventory determines which layout to expect; payload names never determine
artifact identity. Bind inventory to the workflow run head, which can differ
from a manually selected validation checkout. This only restores directories: the original consumers
still verify evidence source, workflow, attempt, digest and producer result.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

MAX_ARTIFACTS = 1000
MAX_RESPONSE = 2 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_BYTES = 2 * 1024 * 1024 * 1024
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")


class LayoutError(RuntimeError):
    """A downloaded set cannot be associated safely with the run inventory."""


def fetch_inventory(repository: str, run_id: int, token: str) -> list[dict]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository) or run_id < 1:
        raise LayoutError("artifact_query_identity_invalid")
    if not token:
        raise LayoutError("artifact_query_token_missing")
    deadline = time.monotonic() + 90
    artifacts: list[dict] = []
    expected = None
    for page in range(1, 11):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LayoutError("artifact_query_deadline")
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts"
            f"?per_page=100&page={page}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "p2wlan-artifact-layout",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=min(15, remaining)) as response:
                body = bytearray()
                while True:
                    if time.monotonic() >= deadline:
                        raise LayoutError("artifact_query_deadline")
                    chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(body)))
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE:
                        raise LayoutError("artifact_query_response_limit")
                    if not chunk:
                        break
            payload = json.loads(body)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            # Do not include the authenticated request or token in diagnostics.
            raise LayoutError("artifact_query_failed") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
            raise LayoutError("artifact_query_shape_invalid")
        total = payload.get("total_count")
        if type(total) is not int or not 0 <= total <= MAX_ARTIFACTS:
            raise LayoutError("artifact_query_count_invalid")
        if expected is not None and total != expected:
            raise LayoutError("artifact_query_inventory_changed")
        expected = total
        rows = payload["artifacts"]
        if len(rows) > 100 or len(artifacts) + len(rows) > total:
            raise LayoutError("artifact_query_count_mismatch")
        artifacts.extend(rows)
        if len(artifacts) == total:
            return artifacts
        if len(rows) != 100:
            raise LayoutError("artifact_query_incomplete")
    raise LayoutError("artifact_query_page_limit")


def matching_artifacts(inventory: list[dict], pattern: str, run_id: int, run_head_sha: str) -> list[dict]:
    if not re.fullmatch(r"[A-Za-z0-9_.*-]+", pattern) or f"-{run_id}-" not in pattern:
        raise LayoutError("artifact_pattern_invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", run_head_sha) or run_id < 1:
        raise LayoutError("artifact_run_head_invalid")
    if len(inventory) > MAX_ARTIFACTS:
        raise LayoutError("artifact_inventory_limit")
    matches = []
    names: set[str] = set()
    ids: set[int] = set()
    for row in inventory:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise LayoutError("artifact_inventory_row_invalid")
        if not fnmatch.fnmatchcase(row["name"], pattern):
            continue
        if row.get("expired") is True:
            continue
        name, artifact_id = row["name"], row.get("id")
        if not SAFE_NAME.fullmatch(name) or type(artifact_id) is not int or artifact_id < 1:
            raise LayoutError("artifact_identity_invalid")
        run = row.get("workflow_run")
        if not isinstance(run, dict) or run.get("id") != run_id or run.get("head_sha") != run_head_sha:
            raise LayoutError("artifact_run_source_mismatch")
        if row.get("expired") is not False:
            raise LayoutError("artifact_expired_or_unknown")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(row.get("digest", ""))):
            raise LayoutError("artifact_digest_missing")
        if name in names or artifact_id in ids:
            raise LayoutError("artifact_duplicate")
        names.add(name)
        ids.add(artifact_id)
        matches.append(row)
    if not matches:
        raise LayoutError("artifact_matches_missing")
    return sorted(matches, key=lambda row: row["name"])


def inspect_tree(root: Path, budget: list[int]) -> None:
    """Reject links/special entries and bound work without reading binary bodies."""
    pending = [root]
    files = 0
    while pending:
        path = pending.pop()
        mode = path.lstat().st_mode
        budget[0] += 1
        if budget[0] > MAX_ENTRIES:
            raise LayoutError("artifact_entry_limit")
        if stat.S_ISDIR(mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    pending.append(Path(entry.path))
                    if budget[0] + len(pending) > MAX_ENTRIES:
                        raise LayoutError("artifact_entry_limit")
        elif stat.S_ISREG(mode):
            budget[1] += path.stat().st_size
            files += 1
            if budget[1] > MAX_BYTES:
                raise LayoutError("artifact_byte_limit")
        else:
            raise LayoutError("artifact_link_or_special_entry")
    if not files:
        raise LayoutError("artifact_payload_empty")


def restore(inventory: list[dict], downloads: list[tuple[str, Path]], output: Path,
            *, run_id: int, run_head_sha: str) -> list[dict]:
    if not 1 <= len(downloads) <= 8:
        raise LayoutError("artifact_download_group_limit")
    if output.exists() or output.is_symlink():
        raise LayoutError("artifact_output_exists")
    output = output.parent.resolve(strict=True) / output.name
    plans: list[tuple[Path, Path]] = []
    roots: list[Path] = []
    names: set[str] = set()
    ids: set[int] = set()
    receipt = []
    budget = [0, 0]
    for pattern, root in downloads:
        if root.is_symlink() or not root.is_dir():
            raise LayoutError("artifact_download_root_invalid")
        root = root.resolve(strict=True)
        if root == output or root in output.parents or output in root.parents:
            raise LayoutError("artifact_output_overlap")
        if any(root == prior or root in prior.parents or prior in root.parents for prior in roots):
            raise LayoutError("artifact_download_roots_overlap")
        roots.append(root)
        matches = matching_artifacts(inventory, pattern, run_id, run_head_sha)
        if len(matches) > 1 and {entry.name for entry in root.iterdir()} != {row["name"] for row in matches}:
            raise LayoutError("artifact_download_names_mismatch")
        for row in matches:
            if row["name"] in names or row["id"] in ids:
                raise LayoutError("artifact_download_groups_overlap")
            names.add(row["name"])
            ids.add(row["id"])
            # Always wrap the whole root for one match, even if a payload
            # directory coincidentally has the artifact's name.
            src = root if len(matches) == 1 else root / row["name"]
            if src.is_symlink() or not src.is_dir():
                raise LayoutError("artifact_payload_root_invalid")
            inspect_tree(src, budget)
            plans.append((src, output / row["name"]))
            receipt.append({"name": row["name"], "id": row["id"], "single_match": len(matches) == 1})
    # Validate every group before mutating anything; no copies of large test
    # programs, no deletion/overwrite of a previous consumer's evidence.
    output.mkdir(mode=0o700)
    moved: list[tuple[Path, Path]] = []
    try:
        for src, dst in plans:
            src.rename(dst)
            moved.append((src, dst))
    except OSError:
        for src, dst in reversed(moved):
            dst.rename(src)
        output.rmdir()
        raise
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-head-sha", required=True)
    parser.add_argument("--download", required=True, nargs=2, action="append", metavar=("PATTERN", "ROOT"))
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        inventory = fetch_inventory(args.repository, args.run_id, os.environ.get("GH_TOKEN", ""))
        receipt = restore(inventory, [(pattern, Path(root)) for pattern, root in args.download],
                          args.output_root, run_id=args.run_id, run_head_sha=args.run_head_sha)
    except (LayoutError, OSError) as error:
        print(f"artifact layout failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"artifact_layout_restored": receipt}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
