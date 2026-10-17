"""Prepare and read bounded OS probe input plans; no daemon authority.

Probe mode loads this module only for an explicit --request-plan. Existing staged
copies of the UDP/TCP tools keep their original default dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import secrets

MAX_PLAN_BYTES = 128 * 1024
FIELDS = frozenset({
    "schema_version", "transport", "capture_id", "producer_scope", "tool_sha256",
    "shared_config_tool_sha256", "run_nonce", "round_nonce", "configuration",
    "request_nonces", "plan_loader_sha256",
})


def unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("request plan has duplicate JSON fields")
        result[name] = value
    return result


def lower_hex(value: object, size: int) -> bool:
    return isinstance(value, str) and len(value) == size and all(c in "0123456789abcdef" for c in value)


def file_identity(value: os.stat_result) -> tuple:
    return (*cross_api_identity(value), value.st_ctime_ns)


def cross_api_identity(value: os.stat_result) -> tuple:
    # Windows path stat can expose creation time as ctime while descriptor
    # fstat exposes change time (CPython #157671). Compare birth time across
    # APIs; still check each API's full ctime before/after independently.
    stamp = getattr(value, "st_birthtime_ns", None) if os.name == "nt" else value.st_ctime_ns
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, stamp


def read_bounded_file(path: Path) -> bytes:
    if not path.is_absolute():
        raise ValueError("request plan path must be absolute")
    original = path.lstat()
    if not stat.S_ISREG(original.st_mode) or not 0 < original.st_size <= MAX_PLAN_BYTES:
        raise ValueError("request plan must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if cross_api_identity(before) != cross_api_identity(original):
            raise ValueError("request plan changed before reading")
        raw = stream.read(MAX_PLAN_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (len(raw) != original.st_size or file_identity(before) != file_identity(after)
            or file_identity(path.lstat()) != file_identity(original)):
        raise ValueError("request plan changed while reading")
    return raw


@dataclass(frozen=True)
class PreparedRequestPlan:
    nonces: tuple[str, ...]
    sha256: str
    capture_id: str
    producer_scope: str
    loader_sha256: str

    def evidence(self) -> dict:
        return {
            "schema_version": 1, "scope": "prepared_probe_input_only",
            "sha256": self.sha256, "capture_id": self.capture_id,
            "producer_scope": self.producer_scope,
            "plan_loader_sha256": self.loader_sha256,
            "daemon_registration_verified": False,
        }


def load_plan(path: Path, config, transport: str, tool_sha256: str,
              shared_config_tool_sha256: str) -> PreparedRequestPlan:
    config.validate()
    raw = read_bounded_file(path)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("request plan must be UTF-8 JSON") from error
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("request plan fields differ from schema 1")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("unsupported request plan schema")
    if transport not in ("udp", "tcp") or value["transport"] != transport:
        raise ValueError("request plan transport differs from this tool")
    if not lower_hex(value["capture_id"], 32) or not lower_hex(value["producer_scope"], 32):
        raise ValueError("request plan requires full 128-bit capture scopes")
    loader_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    for name, expected in [("tool_sha256", tool_sha256),
                           ("shared_config_tool_sha256", shared_config_tool_sha256),
                           ("plan_loader_sha256", loader_sha256)]:
        if not lower_hex(expected, 64) or value[name] != expected:
            raise ValueError("request plan tool source differs from this tool")
    if value["run_nonce"] != config.run_nonce or value["round_nonce"] != config.round_nonce:
        raise ValueError("request plan run or round differs from this invocation")
    expected = config.as_dict()
    supplied = value["configuration"]
    if (not isinstance(supplied, dict) or set(supplied) != set(expected)
            or any(type(supplied[k]) is not type(v) or supplied[k] != v for k, v in expected.items())):
        raise ValueError("request plan changes the flow, denominator, schedule or deadline")
    nonces = value["request_nonces"]
    if (not isinstance(nonces, list) or len(nonces) != config.count
            or any(not lower_hex(nonce, 32) for nonce in nonces)
            or len(set(nonces)) != config.count):
        raise ValueError("request plan requires one distinct full 128-bit nonce per request")
    return PreparedRequestPlan(tuple(nonces), hashlib.sha256(raw).hexdigest(),
                               value["capture_id"], value["producer_scope"], loader_sha256)


def make_plan(config, transport: str, capture_id: str, producer_scope: str) -> dict:
    config.validate()
    if transport not in ("udp", "tcp") or not lower_hex(capture_id, 32) or not lower_hex(producer_scope, 32):
        raise ValueError("prepare requires udp/tcp and full 128-bit capture scopes")
    nonces = [secrets.token_hex(16) for _ in range(config.count)]
    if any(not lower_hex(n, 32) for n in nonces) or len(set(nonces)) != config.count:
        raise ValueError("request nonce generation was invalid or collided; no retry performed")
    root = Path(__file__).resolve().parent
    digest = lambda name: hashlib.sha256((root / name).read_bytes()).hexdigest()
    return {
        "schema_version": 1, "transport": transport, "capture_id": capture_id,
        "producer_scope": producer_scope, "request_nonces": nonces,
        "tool_sha256": digest(transport + "_business_probe.py"),
        "shared_config_tool_sha256": digest("udp_business_probe.py"),
        "plan_loader_sha256": digest("probe_request_plan.py"),
        "run_nonce": config.run_nonce, "round_nonce": config.round_nonce,
        "configuration": config.as_dict(),
    }


def main(argv: list[str] | None = None) -> int:
    from udp_business_probe import Config, validate_output_path, write_report
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare"])
    parser.add_argument("--transport", required=True, choices=["udp", "tcp"])
    for name in ["bind-ip", "target-ip", "run-nonce", "round-nonce", "capture-id", "producer-scope"]:
        parser.add_argument("--" + name, required=True)
    for name in ["bind-port", "target-port"]:
        parser.add_argument("--" + name, type=int, required=True)
    for name, default in [("count", 8), ("interval-ms", 100), ("timeout-ms", 1000),
                          ("duration-ms", 10000), ("payload-bytes", 128)]:
        parser.add_argument("--" + name, type=int, default=default)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    config = Config((args.bind_ip, args.bind_port), (args.target_ip, args.target_port),
                    args.run_nonce, args.round_nonce, args.count, args.interval_ms,
                    args.timeout_ms, args.duration_ms, args.payload_bytes)
    try:
        config.validate()
        validate_output_path(args.output)
        value = make_plan(config, args.transport, args.capture_id, args.producer_scope)
        write_report(args.output, value)
    except (OSError, ValueError) as error:
        parser.exit(2, f"probe-request-plan: {error}\n")
    print(json.dumps({"scope": "prepared_probe_input_only", "output": str(args.output),
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      "requests": config.count, "daemon_registration_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
