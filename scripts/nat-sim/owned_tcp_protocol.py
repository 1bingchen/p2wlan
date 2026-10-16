#!/usr/bin/env python3
"""Bounded private pipe protocol; unavailable rows never prove socket absence."""
from __future__ import annotations

import json
import os
import selectors
import stat

from monotonic_clock import monotonic_ns

MAX_RESPONSE = 65536
QUERY_NS = 200_000_000


class Unavailable(Exception):
    pass


class Channel:
    def __init__(self, incoming: int, outgoing: int, cutoff_ns: int, cancelled):
        self.incoming, self.outgoing = incoming, outgoing
        self.cutoff_ns, self.cancelled = cutoff_ns, cancelled
        self.buffer = b""
        self.sequence = 0
        self.disabled = None
        self.selector = selectors.DefaultSelector()
        # The native writer must have a separate open-file description.
        os.set_blocking(incoming, False)
        os.set_blocking(outgoing, False)
        self.selector.register(incoming, selectors.EVENT_READ)

    def read(self, budget_ns: int = QUERY_NS) -> dict:
        end = min(monotonic_ns() + budget_ns, self.cutoff_ns)
        while b"\n" not in self.buffer:
            if self.cancelled():
                raise Unavailable("cancelled")
            remaining = (end - monotonic_ns()) / 1e9
            if remaining <= 0:
                raise Unavailable("response_deadline")
            if not self.selector.select(min(remaining, 0.025)):
                continue
            try:
                part = os.read(self.incoming, MAX_RESPONSE + 1 - len(self.buffer))
            except BlockingIOError:
                continue
            if not part:
                raise Unavailable("observer_eof")
            self.buffer += part
            if len(self.buffer) > MAX_RESPONSE:
                raise Unavailable("response_capacity")
        line, self.buffer = self.buffer.split(b"\n", 1)
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            raise Unavailable("response_invalid") from None
        if not isinstance(value, dict) or value.get("schema") != 3:
            raise Unavailable("response_invalid")
        return value

    def ready(self, owner: int, observer: int) -> dict:
        # Original prototype preparation bound, before curl starts. TCP
        # queries still use 200ms and all waits share the original cutoff.
        value = self.read(5_000_000_000)
        if (value.get("event") != "ready" or value.get("owner_pid") != owner
                or value.get("observer_pid") != observer or value.get("max_commands") != 8
                or value.get("max_nonquit") != 7 or value.get("max_fds") != 128):
            raise Unavailable("observer_owner_or_contract_mismatch")
        return value

    def query(self, kind: str, pid: int, port: int, birth: tuple[int, int] | None = None) -> dict:
        self.sequence += 1
        began = monotonic_ns()
        entry = {"request_id": self.sequence, "kind": kind, "target_pid": pid,
                 "began_monotonic_ns": began, "usable": False}
        try:
            if self.disabled:
                raise Unavailable(self.disabled)
            if self.sequence > 7 or kind not in {"sample", "identity"}:
                raise Unavailable("command_capacity")
            if began >= self.cutoff_ns or self.cancelled():
                raise Unavailable("cancelled_or_fixed_cutoff")
            command = f"{kind} {self.sequence} {pid} {port}"
            if kind == "sample":
                if birth is None:
                    raise Unavailable("initial_identity_unavailable")
                command += f" {birth[0]} {birth[1]}"
            payload = (command + "\n").encode("ascii")
            if len(payload) >= 128 or os.write(self.outgoing, payload) != len(payload):
                raise Unavailable("command_write_unavailable")
            value = self.read()
            entry["response"] = value
            if (value.get("request_id") != self.sequence or value.get("event") != kind
                    or type(value.get("valid")) is not bool):
                raise Unavailable("response_identity_invalid")
            if value["valid"]:
                numeric = ["pid", "ppid", "uid", "birth_seconds", "birth_microseconds",
                           "started_uptime_raw_ns", "ended_uptime_raw_ns"]
                if (any(type(value.get(k)) is not int for k in numeric) or value["pid"] != pid
                        or value["uid"] != os.getuid() or value["birth_seconds"] <= 0
                        or not 0 <= value["birth_microseconds"] < 1_000_000
                        or not began <= value["started_uptime_raw_ns"] <= value["ended_uptime_raw_ns"] <= monotonic_ns()):
                    raise Unavailable("response_identity_invalid")
                if kind == "sample":
                    if ((value["birth_seconds"], value["birth_microseconds"]) != birth
                            or value.get("expected_birth_supplied") is not True
                            or value.get("ipv4_tcp_only") is not True
                            or type(value.get("complete")) is not bool
                            or not isinstance(value.get("rows"), list) or len(value["rows"]) > 128):
                        raise Unavailable("response_scope_invalid")
                    entry["usable"] = value["complete"]
                else:
                    if value.get("scope") != "owned_process_identity_only" or value.get("socket_observation") is not False:
                        raise Unavailable("response_scope_invalid")
                    entry["usable"] = True
            else:
                entry["reason"] = "native_query_unavailable"
        except (OSError, Unavailable) as exc:
            reason = str(exc) if isinstance(exc, Unavailable) else "pipe_io_unavailable"
            entry["reason"] = reason
            self.disabled = reason
        entry["ended_monotonic_ns"] = monotonic_ns()
        return entry

    def quit(self) -> None:
        try:
            os.write(self.outgoing, b"quit\n")
        except OSError:
            pass

    def close(self) -> None:
        self.selector.close()


def check_fifo(fd: int, path) -> None:
    actual, expected = os.fstat(fd), path.lstat()
    if (not stat.S_ISFIFO(actual.st_mode) or not stat.S_ISFIFO(expected.st_mode)
            or stat.S_IMODE(expected.st_mode) != 0o600
            or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)):
        raise Unavailable("fifo_identity_invalid")
