"""Control-stream and pure deadline controls; no simulated kernel-read credit."""
import copy
import json
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest

import linux_tun_kernel_capture as kernel


class DeadlineControls(unittest.TestCase):
    def setUp(self):
        self.write = dict(sequence=0, request_nonce="f" * 32, original_sent_ns=100,
                          original_deadline_ns=200, accepted_in_original_deadline=True)
        self.row = dict(kernel_frame_read_complete=True, flow_invalid=False,
                        first_read_monotonic_ns=101, last_read_monotonic_ns=199)

    def test_full128_and_original_half_open_deadline_are_retained_as_data_only(self):
        value = kernel.read_pair(self.row, self.row, self.write)
        self.assertEqual(value["request_nonce"], "f" * 32)
        self.assertTrue(value["source_kernel_read_in_original_deadline"])
        self.assertFalse(any("verified" in k for k in value))
        for first, last in [(99, 199), (101, 200), (102, 101), (True, 199), (None, None)]:
            bad = dict(self.row, first_read_monotonic_ns=first, last_read_monotonic_ns=last)
            self.assertFalse(kernel.read_pair(bad, self.row, self.write)["source_kernel_read_in_original_deadline"])

    def test_conflict_partial_and_late_response_do_not_borrow_a_fresh_window(self):
        for change in [dict(flow_invalid=True), dict(kernel_frame_read_complete=False),
                       dict(first_read_monotonic_ns=201, last_read_monotonic_ns=202)]:
            bad = dict(self.row, **change)
            value = kernel.read_pair(self.row, bad, self.write)
            self.assertTrue(value["source_kernel_read_in_original_deadline"])
            self.assertFalse(value["response_kernel_read_in_original_deadline"])

    def test_missing_original_write_time_cannot_be_replaced_by_read_time(self):
        for name in ["original_sent_ns", "original_deadline_ns"]:
            write = dict(self.write, **{name: None})
            self.assertFalse(kernel.read_pair(self.row, self.row, write)["source_kernel_read_in_original_deadline"])

    def test_capacity_failure_precedes_endpoint_or_child_access(self):
        captures = kernel.KernelCaptures.__new__(kernel.KernelCaptures)
        captures.entries, captures.expected_entries = [None] * 4, 4
        record = captures.prepare(None, {}, None, None, None, None)
        self.assertEqual(record["gap"], "original_kernel_probe_capacity")
        self.assertEqual(len(captures.entries), 4)

    def test_interrupted_collection_never_queries_a_process_or_control_connection(self):
        captures = kernel.KernelCaptures.__new__(kernel.KernelCaptures)
        entry = {"records": [{"status": "not_sent"}] * 8}
        captures.expected_entries, captures.entries = 2, [{"entry": entry, "capture": None,
                                                         "endpoints": None, "result": None}]
        before = copy.deepcopy(entry["records"])
        result = captures.finish(captures.entries[0])
        self.assertFalse(result["passed"])
        self.assertFalse(result["physical_send_verified"])
        self.assertFalse(result["canonical_current_owner_verified"])
        self.assertEqual(entry["records"], before)
        self.assertEqual(result["request_count"], 8)


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "actual Unix control sockets required")
class ActualStreamControls(unittest.TestCase):
    def exchange(self, response, *, close=False):
        parent, peer = socket.socketpair()
        endpoint = kernel.Endpoint(parent, None, None, "a" * 32, "b" * 32)
        failures = []
        def serve():
            try:
                peer.settimeout(2)
                data = bytearray()
                while b"\n" not in data:
                    block = peer.recv(4096)
                    if not block:
                        return
                    data.extend(block)
                if not close:
                    peer.sendall(response)
            except BaseException as error:
                failures.append(error)
            finally:
                peer.close()
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            return endpoint.exchange({"op": "snapshot"})
        finally:
            endpoint.close()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])

    def test_actual_socket_reply_retains_labels_without_minting_kernel_authority(self):
        value, _ = self.exchange(kernel.encode(dict(capture_id="a" * 32, owner=1, scope="registered_expected_inputs_only")))
        self.assertEqual(value["scope"], "registered_expected_inputs_only")
        self.assertNotIn("kernel_frame_read_complete", value)

    def test_actual_socket_EOF_wrong_scope_and_duplicate_JSON_are_rejected(self):
        for raw, close in [(b"", True), (kernel.encode(dict(capture_id="c" * 32, owner=1)), False),
                           (b'{"capture_id":"' + b'a' * 32 + b'","owner":1,"owner":2}\n', False)]:
            with self.assertRaises(ValueError):
                self.exchange(raw, close=close)


if __name__ == "__main__":
    unittest.main()
