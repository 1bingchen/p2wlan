"""Owned daemon connections and original-request system-TUN read observations.

The parent binds the actual original Popen before poll/wait. Registration labels
and parsed JSON never grant physical-send, current-connection or once credit.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import time

from linux_tun_probe_capture import streams, udp
import linux_tun_native_transaction as native

MAX_BYTES = 4 * 1024 * 1024
MAX_LINE = 1024 * 1024
MAX_PLAN = 128 * 1024
MAX_ENDPOINTS = 2
MAX_ENTRIES = 4


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


class Endpoint:
    def __init__(self, connection, child, original, capture_id, producer_scope):
        self.connection, self.child, self.original = connection, child, original
        self.capture_id, self.producer_scope = capture_id, producer_scope
        self.input_bytes = self.output_bytes = self.revision = 0
        self.pending = bytearray()
        self.owner = None
        self.raw_snapshots = []
        self.receipts = []

    def send(self, value, end):
        require(self.connection is not None, "kernel_control_connection_closed")
        raw = encode(value)
        require(len(raw) <= MAX_PLAN and self.output_bytes + len(raw) <= MAX_BYTES, "kernel_control_input_capacity")
        self.connection.settimeout(max(.000001, end - time.monotonic()))
        require(time.monotonic() < end, "kernel_control_original_deadline")
        self.connection.sendall(raw)
        self.output_bytes += len(raw)

    def observe_original_write_window(self, window):
        """One nonblocking write, no response, buffering, wait or retry."""
        require(self.connection is not None, "kernel_control_connection_closed")
        raw = encode(dict(op="observe_original_write_window", window=window))
        require(len(raw) <= 512 and self.output_bytes + len(raw) <= MAX_BYTES,
                "original_window_control_capacity")
        try:
            self.connection.setblocking(False)
            n = self.connection.send(raw)
            self.output_bytes += n
            require(n == len(raw), "original_window_short_control_write")
        except (OSError, ValueError):
            self.close()  # A partial JSON record must never be refilled.
            raise

    def exchange(self, value, *, deadline=None):
        end = min(time.monotonic() + 1, deadline) if deadline is not None else time.monotonic() + 1
        self.send(value, end)
        while b"\n" not in self.pending:
            require(len(self.pending) < MAX_LINE and time.monotonic() < end, "kernel_control_reply_capacity_or_deadline")
            self.connection.settimeout(max(.000001, end - time.monotonic()))
            raw = self.connection.recv(min(4096, MAX_LINE - len(self.pending)))
            require(raw and self.input_bytes + len(raw) <= MAX_BYTES, "kernel_control_reply_EOF_or_capacity")
            self.input_bytes += len(raw)
            self.pending.extend(raw)
        end_line = self.pending.index(10)
        raw = bytes(self.pending[:end_line])
        del self.pending[:end_line + 1]
        try:
            result = json.loads(raw.decode(), object_pairs_hook=streams.unique_object, parse_constant=streams.reject_constant)
        except RecursionError as error:
            raise ValueError("kernel_control_reply_depth") from error
        require(isinstance(result, dict) and result.get("capture_id") == self.capture_id
                and integer(result.get("owner"), 1), "kernel_control_reply_scope")
        if self.owner is None:
            self.owner = result["owner"]
        require(result["owner"] == self.owner, "kernel_control_original_owner_changed")
        return result, raw

    def register(self, document, *, deadline=None):
        receipt, raw = self.exchange({"op": "register", "plan": document}, deadline=deadline)
        require(receipt.get("scope") == "registered_expected_inputs_only"
                and receipt.get("producer_scope") == document["producer_scope"]
                and integer(receipt.get("registration_revision"), 1)
                and receipt["registration_revision"] == self.revision + 1
                and receipt.get("added_requests") == 8
                and integer(receipt.get("total_requests"), 8) and receipt["total_requests"] <= 1000,
                "kernel_registration_receipt_mismatch")
        self.revision += 1
        self.receipts.append({"receipt": receipt, "sha256": hashlib.sha256(raw).hexdigest()})
        return receipt

    def snapshot(self, *, deadline=None):
        require(len(self.raw_snapshots) < MAX_ENTRIES, "original_kernel_snapshot_count_capacity")
        value, raw = self.exchange({"op": "snapshot"}, deadline=deadline)
        expected = self.original
        clock = value.get("clock_scope")
        require(isinstance(clock, dict) and clock.get("clock_name") == "CLOCK_MONOTONIC"
                and clock.get("boot_id") == expected.boot_id and clock.get("process_id") == expected.pid
                and clock.get("parent_pid") == expected.parent_pid and clock.get("uid") == expected.uid
                and clock.get("start_ticks") == expected.start_ticks and clock.get("net_namespace") == expected.net_namespace,
                "kernel_original_daemon_birth_namespace_clock_mismatch")
        require(type(value.get("schema_version")) is int and value["schema_version"] == 2
                and value.get("scope") == "registered_native_frame_capture" and value.get("active") is True
                and value.get("producer_scope") == self.producer_scope
                and value.get("registration_revision") == self.revision
                and integer(value.get("observed_monotonic_ns"), 1)
                and isinstance(value.get("requests"), list) and len(value["requests"]) <= 1000
                and all(isinstance(row, dict) for row in value["requests"])
                and all(type(value.get(k)) is bool for k in ["daemon_registration_verified", "physical_send_verified", "canonical_current_owner_verified"]),
                "kernel_read_snapshot_scope_or_capacity")
        self.raw_snapshots.append(raw + b"\n")
        return value

    def close(self):
        if self.connection is not None:
            connection, self.connection = self.connection, None
            connection.close()


def read_pair(request, response, write):
    """Historical byte/time comparison, supplied only after owned collection.

    This pure comparison cannot certify a device, process, Full or current owner.
    """
    def original_window(row):
        first, last = row.get("first_read_monotonic_ns"), row.get("last_read_monotonic_ns")
        sent, end = write.get("original_sent_ns"), write.get("original_deadline_ns")
        return (row.get("kernel_frame_read_complete") is True and row.get("flow_invalid") is False
                and integer(first, 1) and integer(last, first) and integer(sent, 1)
                and integer(end, sent + 1) and sent <= first <= last < end)
    return {"sequence": write["sequence"], "request_nonce": write["request_nonce"],
            "source_kernel_frame_read_complete": request.get("kernel_frame_read_complete") is True,
            "source_kernel_read_in_original_deadline": original_window(request),
            "response_kernel_frame_read_complete": response.get("kernel_frame_read_complete") is True,
            "response_kernel_read_in_original_deadline": original_window(response),
            "original_OS_write_accepted_in_deadline": write.get("accepted_in_original_deadline") is True}


class KernelCaptures:
    def __init__(self, private_root: Path, output: Path, capture_id: str, expected_entries: int):
        require(sys.platform == "linux" and expected_entries in (2, MAX_ENTRIES), "original_Linux_kernel_capture_required")
        self.root, self.output, self.capture_id = private_root, output, capture_id
        self.expected_entries = expected_entries
        self.endpoints, self.entries = {}, []
        self.path = private_root / "kernel-control.sock"
        require(self.path.is_absolute() and len(os.fsencode(self.path)) <= 100, "private_kernel_socket_path_bound")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.listener.bind(str(self.path))
            self.listener.listen(MAX_ENDPOINTS)
        except BaseException:
            self.listener.close()
            raise

    def environment(self):
        require(len(self.endpoints) < MAX_ENDPOINTS, "original_kernel_endpoint_capacity")
        return {"P2WLAN_OS_REQUEST_CONTROL_SOCKET": str(self.path)}

    def bind(self, groups, child, namespace):
        # Caller invokes this before the first poll/wait of this exact Popen.
        owners = [o for o in groups.owners if o["child"] is child]
        require(len(owners) == 1 and child.returncode is None and owners[0]["anchor"].returncode is None,
                "original_kernel_daemon_owner_missing")
        require(namespace in groups.owned_namespace_names, "original_kernel_namespace_not_created")
        expected_ns = "net:[" + str(os.stat("/var/run/netns/" + namespace).st_ino) + "]"
        original = streams.OriginalChild.from_spawn(child, owners[0]["child_spawn_requested_monotonic_ns"], expected_ns)
        require(original.unavailable_reason is None and original.start_ticks is not None and original.boot_id,
                "original_kernel_daemon_birth_unavailable")
        end = time.monotonic() + 1
        self.listener.settimeout(max(.000001, end - time.monotonic()))
        connection, _ = self.listener.accept()
        try:
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            require(pid == child.pid and uid == original.uid, "original_kernel_peer_credentials_mismatch")
            scope = secrets.token_hex(16)
            endpoint = Endpoint(connection, child, original, self.capture_id, scope)
            endpoint.send(dict(schema_version=1, capture_id=self.capture_id, producer_scope=scope, flows=[]), end)
            self.endpoints[child] = endpoint
        except BaseException:
            connection.close()
            raise

    def prepare(self, lab, entry, capture, source, target, snapshots, *, deadline=None):
        record = {"entry": entry, "capture": capture, "endpoints": None, "result": None}
        if len(self.entries) >= self.expected_entries:
            record["gap"] = "original_kernel_probe_capacity"
            return record
        self.entries.append(record)
        try:
            require(len(self.entries) <= self.expected_entries and capture is not None, "original_kernel_probe_plan_missing_or_capacity")
            endpoints = [self.endpoints[lab.daemons[name]["process"]] for name in (source, target)]
            config, prepared = capture.config, capture.prepared
            def document(kind, bind, destination, peer):
                flow = dict(protocol=capture.transport, kind=kind, peer_id=peer,
                            run_nonce=config.run_nonce, round_nonce=config.round_nonce,
                            bind_ip=bind[0], bind_port=bind[1], target_ip=destination[0], target_port=destination[1],
                            payload_bytes=config.payload_bytes, request_nonces=list(prepared.nonces))
                return dict(schema_version=1, capture_id=prepared.capture_id,
                            producer_scope=prepared.producer_scope, flows=[flow])
            for endpoint, value in zip(endpoints, [document("request", config.bind, config.target, snapshots[target]["node_id"]),
                                                     document("response", config.target, config.bind, snapshots[source]["node_id"])]):
                endpoint.register(value, deadline=deadline)
            capture.enable_live_window_bridge(endpoints)
            record["endpoints"] = endpoints
        except (OSError, ValueError, KeyError) as error:
            record["gap"] = "original_kernel_registration_failed:" + type(error).__name__
        return record

    def finish(self, record, *, deadline=None):
        if record["result"] is not None:
            return record["result"]
        result = dict(scope="original_owned_daemon_full128_kernel_transactions", request_count=8,
                      passed=False, physical_send_verified=False, canonical_current_owner_verified=False,
                      requests=[], gap_reason=record.get("gap"))
        try:
            require(record["endpoints"] is not None, "original_kernel_registration_unavailable")
            capture = record["capture"]
            writes = record["entry"].get("original_write_stream", {})
            require(writes.get("stream_complete") is True and writes.get("original_child_birth_namespace_matched") is True
                    and writes.get("original_same_boot_clock_matched") is True, "original_kernel_OS_write_stream_unavailable")
            bridge = capture.live_window_bridge.summary() if capture.live_window_bridge is not None else None
            require(bridge is not None and bridge["gap_reason"] is None, "original_live_write_window_bridge_unavailable")
            result["original_live_write_windows"] = bridge
            pairs, native_pairs = [], []
            app = record["entry"].get("records")
            require(isinstance(app, list) and len(app) == 8, "original_kernel_original_application_records_missing")
            for endpoint, kind in zip(record["endpoints"], ["request", "response"]):
                snapshot = endpoint.snapshot(deadline=deadline)
                rows = [r for r in snapshot["requests"] if r.get("producer_scope") == capture.prepared.producer_scope]
                require(len(rows) == 8 and {r.get("sequence") for r in rows} == set(range(8)), "original_kernel_eight_slots_missing")
                rows.sort(key=lambda r: r["sequence"])
                require(all(r.get("kind") == kind and r.get("protocol") == capture.transport
                            and r.get("run_nonce") == capture.config.run_nonce and r.get("round_nonce") == capture.config.round_nonce
                            and r.get("request_nonce") == capture.prepared.nonces[i] for i, r in enumerate(rows)),
                        "original_kernel_full128_plan_mismatch")
                for row, write, live in zip(rows, writes["requests"], bridge["requests"]):
                    window = row.get("original_write_window")
                    if write["accepted_in_original_deadline"]:
                        expected = live.get("window", {})
                        require(live["delivered"] and isinstance(window, dict)
                                and window.get("scope") == "original_controller_write_window_only"
                                and all(window.get(k) == expected[k] for k in ["request_nonce", "original_started_ns", "original_sent_ns",
                                    "original_deadline_ns", "complete_returned_ns", "frame_bytes", "frame_sha256"])
                                and integer(window.get("received_monotonic_ns"), expected["complete_returned_ns"])
                                and window["received_monotonic_ns"] < expected["original_deadline_ns"]
                                and window.get("native_os_write_verified") is False
                                and window.get("canonical_current_owner_verified") is False,
                                "original_live_write_window_missing_changed_or_late")
                    else:
                        require(window is None, "original_unsent_request_has_write_window")
                pairs.append(rows)
                comparisons = []
                for row, application in zip(rows, app):
                    if application["status"] == "success":
                        require(all(snapshot.get(k) is True for k in ["incoming_provenance_complete", "original_read_observation_complete", "original_full_retention_complete"]),
                                "original_native_capture_provenance_incomplete")
                        comparisons.append(native.frame_comparison(snapshot, row, row["original_write_window"]))
                    else:
                        # Preserve failed/unsent application samples. A local
                        # kernel receipt alone never turns them into successes.
                        comparisons.append(dict(matched=False, application_status=application["status"]))
                native_pairs.append(comparisons)
            records = [read_pair(a, b, w) for a, b, w in zip(*pairs, writes["requests"])]
            require(len(records) == 8, "original_kernel_fixed_denominator_changed")
            result.update(requests=records, capture_id=capture.prepared.capture_id, producer_scope=capture.prepared.producer_scope,
                          original_owned_connections_and_native_clock_matched=True)
            for row, source, response, application in zip(records, *native_pairs, app):
                row.update(source_native_transaction=source, response_native_transaction=response,
                           full128_owner_qualified=application["status"] == "success" and source["matched"] and response["matched"])
            # Unsent original TCP requests remain eight unsent, never synthetic
            # successes. Sent inputs require the actual complete system read.
            result["passed"] = all((r["source_kernel_read_in_original_deadline"] if w["accepted_in_original_deadline"]
                else not r["source_kernel_frame_read_complete"] and w.get("accepted_bytes") == 0 and a["status"] == "not_sent")
                and (r["response_kernel_read_in_original_deadline"] if a["status"] == "success" else True)
                for r, w, a in zip(records, writes["requests"], app))
            result["full128_owner_evidence_complete"] = all(a["status"] != "success" or r["full128_owner_qualified"] for r, a in zip(records, app))
            result["passed"] = result["passed"] and result["full128_owner_evidence_complete"]
            result["canonical_current_owner_verified"] = all(r["full128_owner_qualified"] for r in records)
            result["physical_send_verified"] = result["canonical_current_owner_verified"]
            result["gap_reason"] = None if result["passed"] else "original_kernel_read_missing_conflicted_or_outside_original_deadline"
        except (OSError, ValueError, KeyError, TypeError) as error:
            result["gap_reason"] = result["gap_reason"] or "original_kernel_collection_failed:" + getattr(error, "code", type(error).__name__)
        record["result"] = result
        record["entry"]["original_kernel_reads"] = result
        return result

    def close(self):
        errors = []
        for endpoint in self.endpoints.values():
            try:
                endpoint.close()
            except OSError as error:
                errors.append(type(error).__name__)
        if self.listener is not None:
            listener, self.listener = self.listener, None
            try:
                listener.close()
            except OSError as error:
                errors.append(type(error).__name__)
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError as error:
            errors.append(type(error).__name__)
        return dict(complete=not errors, errors=errors)

    def persist(self):
        # No PID lookup, control read, wait or signal after original cleanup.
        for index, endpoint in enumerate(self.endpoints.values()):
            udp.write_report(self.output / f"kernel-daemon-{index}-binding.json",
                dict(original_child=asdict(endpoint.original), capture_id=self.capture_id,
                     daemon_scope=endpoint.producer_scope, owner=endpoint.owner, registration_receipts=endpoint.receipts))
            raw = b"".join(endpoint.raw_snapshots)
            path = self.output / f"kernel-daemon-{index}-snapshots.jsonl"
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
        for record in self.entries:
            if record["result"] is None:
                record["entry"]["original_kernel_reads"] = dict(scope="original_owned_daemon_full128_kernel_transactions",
                    request_count=8, passed=False, gap_reason="original_kernel_collection_not_completed",
                    physical_send_verified=False, canonical_current_owner_verified=False, requests=[])

    def summary(self, entries):
        results = [entry.get("original_kernel_reads", {}) for entry in entries]
        records = [r for result in results for r in result.get("requests", [])]
        return dict(scope="original_owned_daemon_full128_kernel_transactions", prescheduled_requests=self.expected_entries * 8,
                    actual_collected_request_records=len(records), uncollected_or_unknown_requests=self.expected_entries * 8 - len(records),
                    passed=len(results) == self.expected_entries and all(r.get("passed") is True for r in results),
                    actual_source_kernel_frames=sum(r["source_kernel_frame_read_complete"] for r in records),
                    actual_source_frames_in_original_deadline=sum(r["source_kernel_read_in_original_deadline"] for r in records),
                    actual_response_kernel_frames=sum(r["response_kernel_frame_read_complete"] for r in records),
                    actual_response_frames_in_original_deadline=sum(r["response_kernel_read_in_original_deadline"] for r in records),
                    full128_owner_evidence_complete=len(results) == self.expected_entries and all(r.get("full128_owner_evidence_complete") is True for r in results),
                    actual_full128_owner_qualified_requests=sum(r.get("full128_owner_qualified") is True for r in records),
                    physical_send_verified=len(results) == self.expected_entries and all(r.get("physical_send_verified") is True for r in results),
                    canonical_current_owner_verified=len(results) == self.expected_entries and all(r.get("canonical_current_owner_verified") is True for r in results))
