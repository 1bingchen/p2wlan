"""Optional self-only native birth evidence captured before the original exec.

This is a fence for a later owned-process observation, not proof that exec
succeeded. It never looks up a supplied PID, opens sockets or reads stdin.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from monotonic_clock import monotonic_ns

MAX_BYTES = 4096
MAX_LAUNCH_BYTES = 128 * 1024
PROC_PIDTBSDINFO = 3
SCOPE = "self_birth_before_exec"
UNAVAILABLE = {"unsupported_platform", "native_query_unavailable", "self_identity_changed"}


class DarwinBSDInfo(ctypes.Structure):
    """Public proc_bsdinfo ABI; the native test checks SDK size and offsets."""
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid",
        "rgid", "svuid", "svgid", "reserved")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        "nfiles", "pgid", "pjobc", "tdev", "tpgid")]
    _fields_ += [("nice", ctypes.c_int32), ("birth_seconds", ctypes.c_uint64),
                ("birth_microseconds", ctypes.c_uint64)]


def capture_self() -> dict:
    """Two bounded read-only kernel calls, with no helper child or PID API."""
    if sys.platform != "darwin":
        return {"state": "unavailable", "reason": "unsupported_platform"}
    pid, uid = os.getpid(), os.getuid()
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        query = library.proc_pidinfo
        query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        query.restype = ctypes.c_int
        before, after = DarwinBSDInfo(), DarwinBSDInfo()
        started = monotonic_ns()
        for value in (before, after):
            if query(pid, PROC_PIDTBSDINFO, 0, ctypes.byref(value), ctypes.sizeof(value)) != ctypes.sizeof(value):
                return {"state": "unavailable", "reason": "native_query_unavailable"}
        ended = monotonic_ns()
    except (OSError, AttributeError, ValueError):
        return {"state": "unavailable", "reason": "native_query_unavailable"}
    fields = ("pid", "ppid", "uid", "birth_seconds", "birth_microseconds")
    if (any(getattr(before, f) != getattr(after, f) for f in fields)
            or before.pid != pid or before.uid != uid or before.ppid != os.getppid()
            or before.birth_seconds <= 0 or before.birth_microseconds >= 1_000_000):
        return {"state": "unavailable", "reason": "self_identity_changed"}
    return {"state": "available", "platform": "darwin", **{f:int(getattr(before, f)) for f in fields},
            "started_monotonic_ns": started, "completed_monotonic_ns": ended}


def sidecar_path(record: Path) -> Path:
    # The original strict *.json launch collector must not consume a different
    # schema. This separate suffix requires no exception in that collector.
    return record.with_name(record.name + ".birth")


def _private_bytes(path: Path, capacity: int) -> bytes:
    # Nonblocking open rejects a substituted FIFO before any read can wait
    # for a writer. O_NOFOLLOW and fstat inspect the actual opened object.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_size > capacity):
            raise ValueError("birth_file_not_private_regular_or_bounded")
        payload = stream.read(capacity + 1)
    if len(payload) > capacity:
        raise ValueError("birth_file_capacity")
    return payload


def write_pre_exec(record_path: Path, record: dict) -> None:
    """Diagnostic failure stays unavailable and cannot prevent the real exec."""
    try:
        parent = record_path.parent
        if parent.is_symlink() or stat.S_IMODE(parent.stat().st_mode) != 0o700:
            raise ValueError("private_parent_required")
        value = {"schema_version": 1, "scope": SCOPE,
                 "launch_record_sha256": hashlib.sha256(_private_bytes(record_path, MAX_LAUNCH_BYTES)).hexdigest(),
                 "source": record["source"], "role": record["role"], "component": record["component"],
                 "pid": record["pid"], "artifact_sha256": record["artifact"]["sha256"],
                 "observation": capture_self()}
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if len(payload) > MAX_BYTES:
            raise ValueError("sidecar_capacity")
        fd = os.open(sidecar_path(record_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
    except (OSError, ValueError):
        # No path, native error text or launch input is disclosed.
        print("launch_birth_unavailable:sidecar_write_failed", file=sys.stderr)


def read_bound(record_path: Path, record: dict) -> dict:
    """Validate the original private record binding; do not rebind a live PID."""
    if record["state"] != "exec_requested":
        raise ValueError("birth_original_exec_failed")
    if record_path.parent.is_symlink() or stat.S_IMODE(record_path.parent.stat().st_mode) != 0o700:
        raise ValueError("birth_sidecar_parent_not_private")
    path = sidecar_path(record_path)
    payload = _private_bytes(path, MAX_BYTES)
    value = json.loads(payload)
    expected = {"schema_version": 1, "scope": SCOPE,
                "launch_record_sha256": hashlib.sha256(_private_bytes(record_path, MAX_LAUNCH_BYTES)).hexdigest(),
                "source": record["source"], "role": record["role"], "component": record["component"],
                "pid": record["pid"], "artifact_sha256": record["artifact"]["sha256"]}
    if (not isinstance(value, dict) or set(value) != set(expected) | {"observation"}
            or type(value["schema_version"]) is not int
            or type(value["pid"]) is not int
            or any(value[k] != v for k, v in expected.items())):
        raise ValueError("birth_launch_binding_mismatch")
    observation = value["observation"]
    if not isinstance(observation, dict):
        raise ValueError("birth_observation_invalid")
    if observation.get("state") == "unavailable":
        if (set(observation) != {"state", "reason"} or not isinstance(observation["reason"], str)
                or observation["reason"] not in UNAVAILABLE):
            raise ValueError("birth_unavailable_reason_invalid")
        return value
    keys = {"state", "platform", "pid", "ppid", "uid", "birth_seconds", "birth_microseconds",
            "started_monotonic_ns", "completed_monotonic_ns"}
    numeric = keys - {"state", "platform"}
    if (set(observation) != keys or observation["state"] != "available"
            or observation["platform"] != "darwin"
            or any(type(observation[k]) is not int for k in numeric)
            or observation["pid"] != record["pid"] or observation["uid"] != os.getuid()
            or observation["ppid"] <= 0 or observation["birth_seconds"] <= 0
            or not 0 <= observation["birth_microseconds"] < 1_000_000
            or not 0 < observation["started_monotonic_ns"] <= observation["completed_monotonic_ns"]):
        raise ValueError("birth_observation_invalid")
    return value
