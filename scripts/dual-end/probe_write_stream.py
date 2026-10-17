"""Bounded recognition of one original child's OS-write observation stream.

Expected identity comes from the caller's original Popen before poll/wait,
never from a received PID or JSON. Recognition grants no daemon, kernel,
physical-send, connection-owner, or once authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

import probe_process_identity as process_identity
import probe_write_facts as facts
import tcp_business_probe as tcp
import udp_business_probe as udp
import udp_business_summary as udp_summary

MAX_CHUNK_BYTES = 4096


class StreamError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise StreamError(reason)


def integer(value, lower=0):
    return type(value) is int and value >= lower


@dataclass(frozen=True)
class OriginalChild:
    pid: int
    parent_pid: int
    uid: int
    spawn_requested_ns: int
    start_ticks: int | None
    boot_id: str | None
    pid_namespace: str | None
    net_namespace: str | None
    unavailable_reason: str | None

    @classmethod
    def from_spawn(cls, child: subprocess.Popen, spawn_requested_ns: int,
                   expected_net_namespace: str | None = None):
        require(os.name == "posix", "POSIX_original_child_required")
        require(isinstance(child, subprocess.Popen) and integer(child.pid, 1), "original_child_missing")
        require(integer(spawn_requested_ns, 1), "original_spawn_clock_missing")
        base = dict(pid=child.pid, parent_pid=os.getpid(), uid=os.getuid(),
                    spawn_requested_ns=spawn_requested_ns, start_ticks=None, boot_id=None,
                    pid_namespace=None, net_namespace=expected_net_namespace)
        if sys.platform != "linux":
            return cls(**base, unavailable_reason="Linux_birth_and_same_boot_clock_unavailable")
        # Do not poll/wait here: only the original, still-unreaped child may
        # be inspected. An already reaped PID must never be queried again.
        if child.returncode is not None:
            return cls(**base, unavailable_reason="original_child_already_reaped")
        try:
            raw = process_identity.bounded_text(f"/proc/{child.pid}/stat")
            delimiter = raw.rfind(")")
            tail = raw[delimiter + 2:].split()
            require(delimiter >= 0 and int(raw.split("(", 1)[0]) == child.pid and len(tail) >= 20,
                    "original_child_birth_invalid")
            base.update(start_ticks=int(tail[19]),
                        boot_id=process_identity.bounded_text("/proc/sys/kernel/random/boot_id"),
                        pid_namespace=os.readlink("/proc/self/ns/pid"))
            require(integer(base["start_ticks"]) and expected_net_namespace is not None,
                    "original_child_namespace_missing")
        except (OSError, ValueError, UnicodeError):
            return cls(**base, unavailable_reason="original_child_birth_unavailable")
        return cls(**base, unavailable_reason=None)


def unique_object(pairs):
    value = {}
    for name, field in pairs:
        require(name not in value, "duplicate_JSON_field")
        value[name] = field
    return value


def reject_constant(_value):
    raise StreamError("non_finite_JSON_constant")


class WriteStream:
    def __init__(self, config, prepared, transport: str, original_child: OriginalChild):
        config.validate()
        require((config.count, config.interval_ms, config.timeout_ms, config.duration_ms,
                 config.payload_bytes) == (8, 100, 1000, 10000, 128), "fixed_original8_configuration_required")
        require(transport in ("udp", "tcp") and len(prepared.nonces) == 8, "registered_plan_required")
        self.config, self.plan, self.transport, self.child = config, prepared, transport, original_child
        tool = udp if transport == "udp" else tcp
        root = Path(__file__).resolve().parent
        digest = lambda name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        self.headers = [
            ("source", dict(plan_sha256=prepared.sha256, capture_id=prepared.capture_id,
                            producer_scope=prepared.producer_scope, transport=transport,
                            tool_sha256=digest(transport + "_business_probe.py"))),
            ("helpers", dict(shared_tool_sha256=digest("udp_business_probe.py"),
                             plan_loader_sha256=prepared.loader_sha256,
                             observer_sha256=digest("probe_write_facts.py"),
                             identity_sha256=digest("probe_process_identity.py"))),
            ("owner", None), ("clock", None),
            ("request_set", dict(run_nonce=config.run_nonce, round_nonce=config.round_nonce,
                                 count=8, interval_ms=100, timeout_ms=1000, duration_ms=10000, payload_bytes=128)),
        ]
        frames = [tool.encode(config, i, nonce, tool.REQUEST) for i, nonce in enumerate(prepared.nonces)]
        if transport == "tcp":
            frames = [struct.pack("!I", len(frame)) + frame for frame in frames]
        self.expected_frames = [(len(frame), hashlib.sha256(frame).hexdigest()) for frame in frames]
        self.requests = [dict(sequence=i, request_nonce=nonce, attempts=0, accepted_bytes=0,
                              original_sent_ns=None, original_deadline_ns=None,
                              last_returned_ns=None, last_errno=None, terminal_error=False)
                         for i, nonce in enumerate(prepared.nonces)]
        self.pending = bytearray()
        self.records = self.bytes = self.write_calls = 0
        self.started = self.end = self.last_sequence = None
        self.owner_verified = self.clock_verified = self.socket_seen = self.finished = False
        self.finish_reason = self.gap = None

    def feed(self, raw: bytes):
        if self.gap is not None:
            return
        try:
            require(type(raw) is bytes and len(raw) <= MAX_CHUNK_BYTES, "read_chunk_bound")
            require(self.bytes + len(raw) <= facts.MAX_BYTES, "stream_byte_bound")
            self.bytes += len(raw)
            self.pending.extend(raw)
            lines = 0
            while b"\n" in self.pending:
                end = self.pending.index(10)
                require(end + 1 <= facts.MAX_RECORD_BYTES, "record_byte_bound")
                require(lines < 128 and self.records < facts.MAX_EVENTS, "stream_record_bound")
                line = bytes(self.pending[:end])
                del self.pending[:end + 1]
                value = json.loads(line.decode("ascii"), object_pairs_hook=unique_object,
                                   parse_constant=reject_constant)
                self.observe(value)
                self.records += 1
                lines += 1
            require(len(self.pending) < facts.MAX_RECORD_BYTES, "unterminated_record_bound")
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as error:
            self.gap = str(error) if isinstance(error, StreamError) else "malformed_write_record"

    def observe(self, value):
        require(isinstance(value, dict) and type(value.get("v")) is int and value["v"] == 1,
                "record_schema")
        require(integer(value.get("n")) and value["n"] == self.records and not self.finished, "record_order")
        kind = value.get("kind")
        fields = {k: v for k, v in value.items() if k not in {"v", "n", "kind"}}
        if self.records < len(self.headers):
            expected_kind, expected = self.headers[self.records]
            require(kind == expected_kind, "header_order")
            if kind == "owner":
                self.owner(fields)
            elif kind == "clock":
                self.clock(fields)
            else:
                require(fields == expected and all(type(fields[k]) is type(v) for k, v in expected.items()),
                        "registered_header_mismatch")
            return
        if kind == "start":
            require(self.started is None and self.records == 5 and set(fields) == {"original_started_ns", "original_end_ns"}, "start_order")
            self.started, self.end = fields["original_started_ns"], fields["original_end_ns"]
            require(integer(self.started, 1) and integer(self.end) and self.end == self.started + 10_000_000_000, "original_total_deadline")
        elif kind == "socket":
            require(self.started is not None and not self.socket_seen and self.write_calls == 0, "socket_order")
            require(set(fields) == {"device", "inode", "family", "socket_type", "local", "target"}, "socket_fields")
            require(all(integer(fields[n]) for n in ["device", "inode", "family", "socket_type"]), "socket_identity_types")
            require(all(isinstance(fields[n], list) and len(fields[n]) == 2 and type(fields[n][0]) is str
                        and integer(fields[n][1], 1) and fields[n][1] <= 65535 for n in ["local", "target"]), "socket_endpoint_types")
            require(fields["local"] == list(self.config.bind) and fields["target"] == list(self.config.target), "socket_flow")
            import socket
            require(fields["family"] == int(socket.AF_INET) and fields["socket_type"] == int(socket.SOCK_DGRAM if self.transport == "udp" else socket.SOCK_STREAM), "socket_transport")
            self.socket_seen = True
        elif kind == "write":
            self.write(fields)
        elif kind == "finish":
            require(set(fields) == {"termination_reason"} and isinstance(fields["termination_reason"], str), "finish_fields")
            self.finished, self.finish_reason = True, fields["termination_reason"]
        else:
            raise StreamError("unexpected_record_kind")

    def owner(self, fields):
        base = {"pid", "parent_pid", "uid", "linux_birth_available"}
        require(type(fields.get("linux_birth_available")) is bool, "owner_availability_type")
        available = fields["linux_birth_available"]
        require(set(fields) == base | ({"start_ticks", "boot_id", "pid_namespace", "net_namespace"} if available else set()), "owner_fields")
        require(all(integer(fields[k]) for k in ["pid", "parent_pid", "uid"]), "owner_numeric_types")
        require((fields["pid"], fields["parent_pid"], fields["uid"]) == (self.child.pid, self.child.parent_pid, self.child.uid), "original_child_identity")
        if self.child.unavailable_reason is None:
            require(available, "original_child_birth_missing")
        if available:
            require(integer(fields["start_ticks"]) and isinstance(fields["boot_id"], str)
                    and re.fullmatch(r"[0-9a-f-]{36}", fields["boot_id"]) is not None
                    and all(isinstance(fields[k], str) and re.fullmatch(prefix + r":\[[0-9]+\]", fields[k])
                            for k, prefix in [("pid_namespace", "pid"), ("net_namespace", "net")]), "owner_birth_field_types")
        if available and self.child.unavailable_reason is None:
            require(integer(fields["start_ticks"]) and (fields["start_ticks"], fields["boot_id"], fields["pid_namespace"], fields["net_namespace"]) ==
                    (self.child.start_ticks, self.child.boot_id, self.child.pid_namespace, self.child.net_namespace), "original_child_birth_or_namespace")
            self.owner_verified = True

    def clock(self, fields):
        required = {"implementation", "monotonic", "adjustable", "same_boot_clock_available"}
        require(type(fields.get("same_boot_clock_available")) is bool, "clock_availability_type")
        available = fields["same_boot_clock_available"]
        require(set(fields) == required | ({"boot_id"} if available else set()), "clock_fields")
        info = time.get_clock_info("monotonic")
        require(fields["implementation"] == info.implementation and fields["monotonic"] is True and fields["adjustable"] is False, "original_clock")
        if self.child.unavailable_reason is None:
            require(available, "original_same_boot_clock_missing")
        if available and self.child.boot_id is not None:
            require(fields["implementation"] == "clock_gettime(CLOCK_MONOTONIC)" and fields["boot_id"] == self.child.boot_id, "original_boot_clock")
            self.clock_verified = True

    def write(self, fields):
        required = {"sequence", "original_sent_ns", "original_deadline_ns", "before_ns", "returned_ns",
                    "frame_sha256", "frame_bytes", "offset", "requested", "accepted", "errno"}
        require(self.started is not None and self.socket_seen and set(fields) == required, "write_fields_or_order")
        require(all(integer(fields[n]) for n in required - {"frame_sha256", "accepted", "errno"}), "write_numeric_types")
        i = fields["sequence"]
        require(0 <= i < 8, "original_request_denominator")
        record = self.requests[i]
        size, fingerprint = self.expected_frames[i]
        require(fields["frame_bytes"] == size and fields["frame_sha256"] == fingerprint, "original_full_frame")
        sent, deadline = fields["original_sent_ns"], fields["original_deadline_ns"]
        require(self.started + i * 100_000_000 <= sent < self.end and deadline == min(self.end, sent + 1_000_000_000), "original_request_deadline")
        require(sent <= fields["before_ns"] <= fields["returned_ns"], "write_clock_order")
        require(fields["errno"] is None or integer(fields["errno"]), "numeric_errno_required")
        count = fields["accepted"]
        require(count is None or integer(count), "actual_write_count_type")
        require(fields["offset"] == record["accepted_bytes"] and fields["requested"] == size - fields["offset"] > 0, "original_write_range")
        require(count is None or count <= fields["requested"], "actual_write_count_bound")
        require(count is None or fields["errno"] is None, "mixed_write_error_and_count")
        require(not record["terminal_error"], "write_after_original_error")
        if self.last_sequence is None:
            require(i == 0, "request_write_order")
        else:
            require(i in (self.last_sequence, self.last_sequence + 1), "request_write_order")
        if self.transport == "udp":
            require(record["attempts"] == 0 and fields["offset"] == 0, "UDP_application_retry")
        elif self.last_sequence is not None:
            previous = self.requests[self.last_sequence]
            require(not previous["terminal_error"] and (i == self.last_sequence or previous["accepted_bytes"] == size), "TCP_advance_before_complete_write")
        if record["attempts"]:
            require((sent, deadline) == (record["original_sent_ns"], record["original_deadline_ns"]), "partial_write_deadline_changed")
            require(record["last_returned_ns"] <= fields["before_ns"], "partial_write_clock_order")
        record.update(attempts=record["attempts"] + 1, original_sent_ns=sent, original_deadline_ns=deadline,
                      last_returned_ns=fields["returned_ns"], last_errno=fields["errno"],
                      terminal_error=count is None or count == 0)
        record["accepted_bytes"] += count or 0
        self.last_sequence, self.write_calls = i, self.write_calls + 1

    def finish(self, report, observed_ns=None):
        try:
            require(self.gap is None, self.gap or "stream_gap")
            require(not self.pending and self.finished, "missing_finish_or_partial_line")
            if self.transport == "udp":
                udp_summary.validate_report(report)
            else:
                tcp.validate_probe(report)
            require(report["configuration"] == self.config.as_dict() and report["request_plan"] == self.plan.evidence(), "original_report_plan")
            require((report["run_nonce"], report["round_nonce"]) == (self.config.run_nonce, self.config.round_nonce), "original_report_round")
            summary = report["write_facts"]
            require(set(summary) == {"schema_version", "scope", "records_emitted", "bytes_emitted", "emission_gap_reason", "original_started_ns", "daemon_registration_verified", "kernel_tun_verified"}, "original_report_observer_fields")
            require(type(summary["schema_version"]) is int and summary["schema_version"] == 1 and summary["scope"] == "original_os_socket_write_observations_only", "original_report_observer_scope")
            require(summary["daemon_registration_verified"] is False and summary["kernel_tun_verified"] is False, "unexpected_authority_claim")
            require(summary["emission_gap_reason"] is None and summary["original_started_ns"] == self.started, "original_report_observation_gap")
            require(integer(summary["records_emitted"]) and integer(summary["bytes_emitted"]) and (summary["records_emitted"], summary["bytes_emitted"]) == (self.records, self.bytes), "original_report_stream_counts")
            require(report["termination_reason"] == self.finish_reason, "original_report_termination")
            if self.started is None:
                require(self.transport == "udp" and self.finish_reason == "bind_failed" and self.write_calls == 0, "original_start_missing")
            if self.finish_reason == "completed":
                require(self.socket_seen and all(r["attempts"] for r in self.requests), "completed_stream_missing_requests")
            for expected, actual in zip(self.requests, report["requests"]):
                require(actual["request_nonce"] == expected["request_nonce"], "original_report_full_nonce")
                if expected["attempts"]:
                    require(self.started + actual["sent_offset_ns"] == expected["original_sent_ns"], "original_report_sent_anchor")
                if actual["status"] == "success":
                    require(self.accepted_in_time(expected), "successful_request_missing_original_write")
                if actual["sent_offset_ns"] is None:
                    require(expected["attempts"] == 0, "unsent_request_has_write")
            if self.clock_verified and self.started is not None:
                last = max((r["last_returned_ns"] or self.started for r in self.requests), default=self.started)
                require(integer(observed_ns) and self.child.spawn_requested_ns <= self.started <= last <= observed_ns, "original_spawn_and_observation_clock")
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as error:
            self.gap = self.gap or (str(error) if isinstance(error, StreamError) else "original_report_invalid")
        return dict(schema_version=1, scope="original_child_os_write_stream_only", request_count=8,
                    stream_complete=self.gap is None, gap_reason=self.gap, records=self.records,
                    bytes=self.bytes, write_calls=self.write_calls,
                    requests=[dict(r, accepted_in_original_deadline=self.gap is None and self.accepted_in_time(r)) for r in self.requests],
                    original_child_birth_namespace_matched=self.owner_verified,
                    original_same_boot_clock_matched=self.clock_verified,
                    daemon_registration_verified=False, kernel_tun_verified=False,
                    physical_send_verified=False, canonical_current_owner_verified=False)

    def accepted_in_time(self, record):
        size = self.expected_frames[record["sequence"]][0]
        return (record["accepted_bytes"] == size and not record["terminal_error"]
                and record["last_returned_ns"] is not None
                and record["last_returned_ns"] < record["original_deadline_ns"])
