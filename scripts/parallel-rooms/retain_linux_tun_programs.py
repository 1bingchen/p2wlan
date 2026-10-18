"""Copy existing failed-run images by their recorded digests; never rebuild/run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

MAX_IMAGE_BYTES = 1024 * 1024 * 1024


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def retain(args, manifest):
    reports = []
    for report in args.report:
        if report.exists():
            if report.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("original report exceeds capacity")
            value = json.loads(report.read_text())
            if value.get("source_commit") != args.head:
                raise ValueError("original report checkout mismatch")
            reports.append(value)
    sources = [("daemon", args.daemon), ("control", args.control)]
    if getattr(args, "relay", None) is not None:
        sources.append(("relay", args.relay))
    for role, source in sources:
        expected = {r.get("binary_sha256", {}).get(role) for r in reports} - {None}
        row = dict(role=role, available=False)
        manifest["images"].append(row)
        if not expected:
            row["reason"] = "original_measured_image_digest_unavailable"
        elif len(expected) != 1 or not source.is_file() or source.is_symlink():
            row["reason"] = "original_image_missing_or_conflicting"
        else:
            target = args.output / ("p2wlan-" + role)
            with source.open("rb") as original:
                before = os.fstat(original.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_IMAGE_BYTES:
                    raise ValueError("original image exceeds capacity or is not regular")
                copied, value = 0, hashlib.sha256()
                with target.open("xb") as saved:
                    row["unverified_file"] = target.name
                    for block in iter(lambda: original.read(1024 * 1024), b""):
                        copied += len(block)
                        if copied > before.st_size:
                            raise ValueError("original image changed during retention")
                        value.update(block)
                        saved.write(block)
                    saved.flush()
                    os.fsync(saved.fileno())
                after = os.fstat(original.fileno())
            target.chmod(0o444)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("original image changed during retention")
            actual = value.hexdigest()
            if copied != before.st_size or actual not in expected or digest(target) != actual:
                raise ValueError("retained original image digest mismatch")
            del row["unverified_file"]
            row.update(available=True, file=target.name, bytes=copied, sha256=actual,
                       matched_original_report_digest=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--relay", type=Path, help="optional original measured Relay image")
    parser.add_argument("--head", required=True)
    parser.add_argument("--report", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.head) != 40 or any(c not in "0123456789abcdef" for c in args.head):
        parser.error("head must be the original checkout commit")
    if len(args.report) > 3:
        parser.error("at most the original three reports may be inspected")
    args.output.mkdir(exist_ok=False)
    manifest = dict(schema_version=1, scope="recorded_original_program_bytes_only",
                    actual_checkout=args.head, run_id=os.environ.get("GITHUB_RUN_ID"),
                    run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"), images=[],
                    rebuilt=False, executed=False, no_native_IO_authority_granted=True)
    try:
        retain(args, manifest)
    except (OSError, ValueError, TypeError) as error:
        manifest["retention_failure"] = type(error).__name__
        raise
    finally:
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
