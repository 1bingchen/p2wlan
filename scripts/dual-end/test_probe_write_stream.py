"""Original owned CLI/pipe observations plus explicitly synthetic parser controls."""
from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import probe_request_plan as plans
import probe_write_stream as stream
import tcp_business_probe as tcp
import udp_business_probe as udp


class PlatformControls(unittest.TestCase):
    def test_non_POSIX_source_observation_rejects_before_PID_or_descriptor_access(self):
        with patch.object(stream.os, "name", "nt"), patch.object(stream.process_identity, "bounded_text") as read:
            with self.assertRaisesRegex(stream.StreamError, "POSIX_original_child_required"):
                stream.OriginalChild.from_spawn(None, 1)
            read.assert_not_called()


@unittest.skipUnless(os.name == "posix", "original child write streams require POSIX pipes")
class OwnedStreams(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cases = {name: cls.capture(name) for name in ["udp", "tcp", "refused"]}

    @classmethod
    def capture(cls, name):
        transport = "udp" if name == "udp" else "tcp"
        tool = udp if transport == "udp" else tcp
        kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        root = Path(cls.directory.name) / name
        root.mkdir()
        with socket.socket(socket.AF_INET, kind) as reserved, socket.socket(socket.AF_INET, kind) as peer:
            reserved.bind(("127.0.0.1", 0))
            peer.bind(("127.0.0.1", 0))
            config = udp.Config(reserved.getsockname(), peer.getsockname(), "1" * 32, "2" * 32)
            echo = replace(config, bind=config.target, target=config.bind)
            document = plans.make_plan(config, transport, ("a1" if transport == "udp" else "a2") * 16,
                                       ("b1" if transport == "udp" else "b2") * 16)
            plan_path, report_path = root / "plan.json", root / "report.json"
            plan_path.write_text(json.dumps(document), encoding="utf-8")
            prepared = plans.load_plan(plan_path, config, transport, document["tool_sha256"],
                                       document["shared_config_tool_sha256"])
            ready = threading.Event()
            echo_result = {}
            worker = None if name == "refused" else threading.Thread(target=lambda: echo_result.update(report=tool.run_echo(echo, peer, ready.set)))
            if worker:
                worker.start()
                if not ready.wait(1):
                    raise RuntimeError("owned echo readiness")
            reader, writer = os.pipe()
            os.set_blocking(reader, False)
            os.set_blocking(writer, False)
            child = None
            try:
                reserved.close()
                argv = [sys.executable, "-B", str(Path(tool.__file__)), "probe",
                        "--bind-ip", config.bind[0], "--bind-port", str(config.bind[1]),
                        "--target-ip", config.target[0], "--target-port", str(config.target[1]),
                        "--run-nonce", config.run_nonce, "--round-nonce", config.round_nonce,
                        "--request-plan", str(plan_path), "--write-facts-fd", str(writer),
                        "--output", str(report_path)]
                requested = time.monotonic_ns()
                child = subprocess.Popen(argv, pass_fds=(writer,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                namespace = os.readlink("/proc/self/ns/net") if sys.platform == "linux" else None
                original = stream.OriginalChild.from_spawn(child, requested, namespace)
                os.close(writer)
                writer = None
                raw = bytearray()
                end = time.monotonic() + 4
                while time.monotonic() < end:
                    if not select.select([reader], [], [], .05)[0]:
                        continue
                    chunk = os.read(reader, stream.MAX_CHUNK_BYTES)
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > stream.facts.MAX_BYTES:
                        raise RuntimeError("owned stream capture capacity")
                else:
                    raise TimeoutError("owned stream capture deadline")
                stdout, stderr = child.communicate(timeout=1)
                if child.returncode != int(name == "refused"):
                    raise AssertionError((child.returncode, stderr.decode("utf-8", "replace"), stdout))
                report = json.loads(report_path.read_text())
                return dict(config=config, prepared=prepared, transport=transport, child=original,
                            raw=bytes(raw), report=report, observed_ns=time.monotonic_ns(),
                            child_handle=child, echo=echo_result.get("report"))
            finally:
                if child is not None and child.returncode is None:
                    child.kill()
                    child.wait()
                os.close(reader)
                if writer is not None:
                    os.close(writer)
                if worker:
                    worker.join(2)
                    if worker.is_alive():
                        raise RuntimeError("owned echo did not terminate")

    def decode(self, name="udp", *, rows=None, raw=None, report=None, child=None, chunk_size=4096):
        case = self.cases[name]
        observer = stream.WriteStream(case["config"], case["prepared"], case["transport"], child or case["child"])
        if rows is not None:
            raw = b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode("ascii") for row in rows)
        raw = case["raw"] if raw is None else raw
        report = copy.deepcopy(case["report"]) if report is None else report
        if rows is not None:
            report["write_facts"].update(records_emitted=len(rows), bytes_emitted=len(raw))
        for start in range(0, len(raw), chunk_size):
            observer.feed(raw[start:start + chunk_size])
        return observer.finish(report, case["observed_ns"])

    def rows(self, name="udp"):
        return [json.loads(line) for line in self.cases[name]["raw"].splitlines()]

    def assert_no_authority(self, result):
        for field in ["daemon_registration_verified", "kernel_tun_verified", "physical_send_verified", "canonical_current_owner_verified"]:
            self.assertIs(result[field], False)
        self.assertEqual((result["request_count"], len(result["requests"])), (8, 8))
        if not result["stream_complete"]:
            self.assertTrue(all(not r["accepted_in_original_deadline"] for r in result["requests"]))

    def test_actual_UDP_child_source_full_nonces_original8_and_deadlines(self):
        result = self.decode()
        self.assertTrue(result["stream_complete"], result["gap_reason"])
        self.assertEqual(result["write_calls"], 8)
        self.assertTrue(all(r["accepted_in_original_deadline"] for r in result["requests"]))
        self.assertEqual([r["request_nonce"] for r in result["requests"]], list(self.cases["udp"]["prepared"].nonces))
        self.assertEqual(self.cases["udp"]["echo"]["responses_sent"], 8)
        self.assertEqual(result["original_child_birth_namespace_matched"], sys.platform == "linux")
        self.assertEqual(result["original_same_boot_clock_matched"], sys.platform == "linux")
        self.assert_no_authority(result)

    def test_actual_TCP_child_keeps_original8_and_exactly_one_connection(self):
        result = self.decode("tcp")
        self.assertTrue(result["stream_complete"], result["gap_reason"])
        self.assertTrue(all(r["accepted_in_original_deadline"] for r in result["requests"]))
        self.assertEqual(self.cases["tcp"]["report"]["connection_attempts"], 1)
        self.assertEqual(self.cases["tcp"]["echo"]["accepted_connections"], 1)
        self.assert_no_authority(result)

    def test_actual_connect_refusal_keeps_all8_without_invented_write_or_socket(self):
        result = self.decode("refused")
        self.assertTrue(result["stream_complete"], result["gap_reason"])
        self.assertEqual(result["write_calls"], 0)
        self.assertTrue(all(r["attempts"] == r["accepted_bytes"] == 0 for r in result["requests"]))
        self.assertEqual([r["status"] for r in self.cases["refused"]["report"]["requests"]], ["not_sent"] * 8)
        self.assert_no_authority(result)

    def test_chunk_boundaries_do_not_change_original_stream(self):
        expected = self.decode()
        for size in [1, 7, 511, 4096]:
            with self.subTest(size=size):
                self.assertEqual(self.decode(chunk_size=size), expected)

    def test_source_plan_owner_flow_and_full_frame_mismatches_are_rejected(self):
        rows = self.rows()
        changes = [
            ("source", "plan_sha256", "0" * 64), ("source", "capture_id", "a1" * 8),
            ("helpers", "observer_sha256", "0" * 64), ("helpers", "identity_sha256", "0" * 64),
            ("request_set", "run_nonce", "0" * 32), ("request_set", "count", True),
            ("owner", "pid", self.cases["udp"]["child"].pid + 1),
            ("owner", "parent_pid", self.cases["udp"]["child"].parent_pid + 1),
            ("socket", "target", ["127.0.0.1", 1]), ("write", "frame_sha256", "0" * 64),
            ("write", "frame_bytes", 1), ("write", "accepted", True),
        ]
        for kind, key, value in changes:
            changed = copy.deepcopy(rows)
            next(r for r in changed if r["kind"] == kind)[key] = value
            with self.subTest(kind=kind, key=key):
                result = self.decode(rows=changed)
                self.assertFalse(result["stream_complete"])
                self.assert_no_authority(result)

    def test_duplicate_JSON_fields_unknown_fields_order_and_truncation_fail_closed(self):
        raw = self.cases["udp"]["raw"]
        rows = self.rows()
        extra = copy.deepcopy(rows)
        extra[0]["registered"] = True
        reordered = copy.deepcopy(rows)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        for data in [raw.replace(b'"v":1', b'"v":1,"v":1', 1), raw[:-1], raw + raw[:raw.index(b"\n") + 1]]:
            with self.subTest(data=data[:30]):
                result = self.decode(raw=data)
                self.assertFalse(result["stream_complete"])
                self.assert_no_authority(result)
        for changed in [extra, reordered, rows[:-1]]:
            self.assertFalse(self.decode(rows=changed)["stream_complete"])

    def test_fixed_chunk_record_and_total_byte_capacity_have_structured_gaps(self):
        case = self.cases["udp"]
        for data, expected in [(b"x" * 4097, "read_chunk_bound"), (b"x" * 512, "unterminated_record_bound")]:
            observer = stream.WriteStream(case["config"], case["prepared"], "udp", case["child"])
            observer.feed(data)
            result = observer.finish(case["report"], case["observed_ns"])
            self.assertEqual(result["gap_reason"], expected)
            self.assert_no_authority(result)
        with patch.object(stream.facts, "MAX_BYTES", 1):
            self.assertEqual(self.decode()["gap_reason"], "stream_byte_bound")

    def test_control_partial_TCP_ranges_keep_one_original_deadline(self):
        rows = self.rows("tcp")
        index = next(i for i, r in enumerate(rows) if r["kind"] == "write")
        original = rows[index]
        first, second = copy.deepcopy(original), copy.deepcopy(original)
        part = original["frame_bytes"] // 2
        first.update(accepted=part, returned_ns=original["before_ns"])
        second.update(offset=part, requested=original["frame_bytes"] - part,
                      accepted=original["frame_bytes"] - part)
        rows[index:index + 1] = [first, second]
        for i, row in enumerate(rows):
            row["n"] = i
        result = self.decode("tcp", rows=rows)
        self.assertTrue(result["stream_complete"], result["gap_reason"])
        self.assertEqual(result["write_calls"], 9)
        self.assert_no_authority(result)
        for key, value in [("offset", part - 1), ("original_deadline_ns", second["original_deadline_ns"] + 1),
                           ("original_sent_ns", second["original_sent_ns"] + 1)]:
            changed = copy.deepcopy(rows)
            changed[index + 1][key] = value
            with self.subTest(key=key):
                self.assertFalse(self.decode("tcp", rows=changed)["stream_complete"])

    def test_original_report_nonces_denominator_and_authority_cannot_be_replaced(self):
        for change in [lambda r: r["requests"].pop(),
                       lambda r: r["requests"][0].update(request_nonce="0" * 32),
                       lambda r: r["requests"][0].update(sent_offset_ns=r["requests"][0]["sent_offset_ns"] + 1),
                       lambda r: r["write_facts"].update(daemon_registration_verified=True),
                       lambda r: r["write_facts"].update(kernel_tun_verified=True),
                       lambda r: r["write_facts"].update(emission_gap_reason="observation_pipe_full"),
                       lambda r: r["write_facts"].update(records_emitted=0)]:
            report = copy.deepcopy(self.cases["udp"]["report"])
            change(report)
            result = self.decode(report=report)
            self.assertFalse(result["stream_complete"])
            self.assert_no_authority(result)

    def test_other_original_child_and_reaped_PID_are_never_refilled(self):
        case = self.cases["udp"]
        changed = replace(case["child"], pid=case["child"].pid + 1)
        self.assertFalse(self.decode(child=changed)["stream_complete"])
        with patch.object(stream.sys, "platform", "linux"), patch.object(stream.process_identity, "bounded_text") as read:
            result = stream.OriginalChild.from_spawn(case["child_handle"], 1, "net:[1]")
            self.assertEqual(result.unavailable_reason, "original_child_already_reaped")
            read.assert_not_called()

    def test_parent_clock_bounds_cannot_restart_original_request_timeouts(self):
        case = self.cases["udp"]
        rows = self.rows()
        first_write = next(r for r in rows if r["kind"] == "write")
        first_write["original_deadline_ns"] += 1
        self.assertFalse(self.decode(rows=rows)["stream_complete"])
        if sys.platform == "linux":
            later = replace(case["child"], spawn_requested_ns=case["observed_ns"] + 1)
            self.assertFalse(self.decode(child=later)["stream_complete"])

    def test_non_original_configuration_cannot_shrink_fixed8_scope(self):
        case = self.cases["udp"]
        for field, value in [("count", 7), ("interval_ms", 99), ("timeout_ms", 999),
                             ("duration_ms", 9999), ("payload_bytes", 127)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                stream.WriteStream(replace(case["config"], **{field: value}), case["prepared"], "udp", case["child"])


if __name__ == "__main__":
    unittest.main()
