"""Prepared input controls and owned loopback checks; no TUN/owner credit."""
from dataclasses import replace
from contextlib import redirect_stderr, redirect_stdout
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import probe_request_plan as plans
import tcp_business_probe as tcp
import udp_business_probe as udp

TOOLS = Path(__file__).resolve().parent


def digest(name):
    return hashlib.sha256((TOOLS / name).read_bytes()).hexdigest()


def document(config, transport):
    return {
        "schema_version": 1, "transport": transport, "capture_id": "a1" * 16,
        "producer_scope": "b2" * 16,
        "tool_sha256": digest(transport + "_business_probe.py"),
        "shared_config_tool_sha256": digest("udp_business_probe.py"),
        "plan_loader_sha256": digest("probe_request_plan.py"),
        "run_nonce": config.run_nonce, "round_nonce": config.round_nonce,
        "configuration": config.as_dict(),
        "request_nonces": [f"{i:032x}" for i in range(config.count)],
    }


class InputControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "plan.json"
        self.config = udp.Config(("127.0.0.1", 41001), ("127.0.0.1", 41002), "1" * 32, "2" * 32)

    def load(self, value=None, config=None, transport="udp"):
        config = config or self.config
        value = document(config, transport) if value is None else value
        self.path.write_text(json.dumps(value), encoding="utf-8")
        return plans.load_plan(self.path, config, transport, digest(transport + "_business_probe.py"),
                               digest("udp_business_probe.py"))

    def test_exact_defaults_full_nonces_raw_digest_and_no_daemon_authority(self):
        for transport in ["udp", "tcp"]:
            with self.subTest(transport=transport):
                value = document(self.config, transport)
                result = self.load(value, transport=transport)
                self.assertEqual(result.nonces, tuple(value["request_nonces"]))
                self.assertEqual(result.sha256, hashlib.sha256(self.path.read_bytes()).hexdigest())
                self.assertEqual(self.config.as_dict(), value["configuration"])
                self.assertFalse(result.evidence()["daemon_registration_verified"])
                self.assertEqual(result.evidence()["scope"], "prepared_probe_input_only")
                self.assertEqual(result.evidence()["plan_loader_sha256"], digest("probe_request_plan.py"))
                with self.assertRaises(AttributeError):
                    result.nonces = ()

    def test_original_maximum_request_count_fits_fixed_input_capacity(self):
        config = replace(self.config, count=1000, interval_ms=1, duration_ms=120000)
        self.assertEqual(len(self.load(config=config).nonces), 1000)
        self.assertLess(self.path.stat().st_size, plans.MAX_PLAN_BYTES)

    def test_flow_count_payload_schedule_deadline_and_numeric_types_are_exact(self):
        for field, old in self.config.as_dict().items():
            value = document(self.config, "udp")
            value["configuration"][field] = old + 1 if type(old) is int else "127.0.0.2"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(value)
        for field, changed in [("interval_ms", 100.0), ("count", True)]:
            value = document(self.config, "udp")
            value["configuration"][field] = changed
            with self.subTest(field=field, changed=changed), self.assertRaises(ValueError):
                self.load(value)

    def test_transport_run_round_source_and_full_capture_scopes_are_exact(self):
        changes = [
            ("schema_version", True), ("schema_version", 2), ("transport", "tcp"),
            ("run_nonce", "1" * 31 + "3"), ("round_nonce", "2" * 31 + "3"),
            ("tool_sha256", "0" * 64), ("shared_config_tool_sha256", "0" * 64),
            ("plan_loader_sha256", "0" * 64), ("capture_id", "a1" * 8),
            ("producer_scope", "B2" * 16),
        ]
        for field, changed in changes:
            value = document(self.config, "udp")
            value[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(value)

    def test_nonce_count_format_uniqueness_and_schema_fields_are_strict(self):
        base = document(self.config, "udp")
        candidates = []
        for nonces in [[], base["request_nonces"][:-1], ["3" * 32] * 8,
                       ["3" * 16] * 8, ["G" * 32] * 8, [{}] * 8]:
            value = copy.deepcopy(base)
            value["request_nonces"] = nonces
            candidates.append(value)
        for field in ["capture_id", "request_nonces", "configuration"]:
            value = copy.deepcopy(base)
            del value[field]
            candidates.append(value)
        value = copy.deepcopy(base)
        value["registered"] = True
        candidates.append(value)
        for index, value in enumerate(candidates):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.load(value)

    def test_duplicate_fields_non_utf8_and_deep_json_are_rejected(self):
        raw = json.dumps(document(self.config, "udp"))
        cases = [raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1').encode(),
                 raw.encode("utf-16"), b"\xff", ("[" * 1200 + "0" + "]" * 1200).encode()]
        for index, data in enumerate(cases):
            self.path.write_bytes(data)
            with self.subTest(index=index), self.assertRaises(ValueError):
                plans.load_plan(self.path, self.config, "udp", digest("udp_business_probe.py"),
                                digest("udp_business_probe.py"))

    def test_relative_directory_and_oversize_input_are_rejected(self):
        self.path.write_text("{}")
        for path in [Path("relative.json"), self.path.parent]:
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                plans.read_bounded_file(path)
        self.path.write_bytes(b" " * (plans.MAX_PLAN_BYTES + 1))
        with self.assertRaises(ValueError):
            plans.read_bounded_file(self.path)

    def test_symlink_is_rejected_when_OS_permits_its_creation(self):
        self.path.write_text("{}")
        link = self.path.with_name("link.json")
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError) as error:
            self.skipTest("OS symlink creation unavailable: " + type(error).__name__)
        with self.assertRaises(ValueError):
            plans.read_bounded_file(link)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "OS has no FIFO constructor")
    def test_fifo_is_rejected_before_a_blocking_open(self):
        os.mkfifo(self.path)
        with self.assertRaises(ValueError):
            plans.read_bounded_file(self.path)

    def test_file_mutation_and_replacement_during_read_close_owned_descriptor(self):
        original_fstat = os.fstat
        original_lstat = Path.lstat
        for replacement in [False, True]:
            self.path.write_text(json.dumps(document(self.config, "udp")))
            before = self.path.stat()
            calls = []
            path_checks = []

            def fstat(descriptor):
                calls.append(descriptor)
                if len(calls) == 2 and not replacement:
                    os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000))
                return original_fstat(descriptor)

            def lstat(path, *args, **kwargs):
                if path == self.path:
                    path_checks.append(path)
                    if replacement and len(path_checks) == 2:
                        # Windows can forbid replacing an open descriptor.
                        # Replace at the final path check, after owned close.
                        with self.assertRaises(OSError):
                            original_fstat(calls[0])
                        other = self.path.with_name("replacement")
                        other.write_text("{}")
                        os.replace(other, self.path)
                return original_lstat(path, *args, **kwargs)

            with self.subTest(replacement=replacement), patch.object(plans.os, "fstat", side_effect=fstat), patch.object(Path, "lstat", lstat):
                with self.assertRaises(ValueError):
                    plans.read_bounded_file(self.path)
            self.assertEqual(len(calls), 2)
            with self.assertRaises(OSError):
                original_fstat(calls[0])

    def test_windows_cross_api_birth_identity_retains_both_ctime_change_fences(self):
        fields = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                      st_size=10, st_mtime_ns=20, st_birthtime_ns=30, st_ctime_ns=30)
        by_path = SimpleNamespace(**fields)
        by_fd = SimpleNamespace(**dict(fields, st_ctime_ns=40))
        with patch.object(plans.os, "name", "nt"):
            self.assertEqual(plans.cross_api_identity(by_path), plans.cross_api_identity(by_fd))
            self.assertNotEqual(plans.file_identity(by_path), plans.file_identity(by_fd))
            for field in ["st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_birthtime_ns"]:
                changed = SimpleNamespace(**dict(vars(by_fd), **{field: getattr(by_fd, field) + 1}))
                with self.subTest(field=field):
                    self.assertNotEqual(plans.cross_api_identity(by_path), plans.cross_api_identity(changed))
            changed_fd = SimpleNamespace(**dict(vars(by_fd), st_ctime_ns=41))
            changed_path = SimpleNamespace(**dict(vars(by_path), st_ctime_ns=31))
            self.assertNotEqual(plans.file_identity(by_fd), plans.file_identity(changed_fd))
            self.assertNotEqual(plans.file_identity(by_path), plans.file_identity(changed_path))

    def test_invalid_plan_never_opens_udp_or_tcp_socket(self):
        for tool, transport, boundary in [(udp, "udp", "open_socket"), (tcp, "tcp", "bound_socket")]:
            value = document(self.config, transport)
            value["request_nonces"] = []
            self.path.write_text(json.dumps(value))
            with self.subTest(transport=transport), patch.object(tool, boundary) as open_socket:
                with self.assertRaises(ValueError):
                    tool.run_probe(self.config, request_plan=self.path)
                open_socket.assert_not_called()

    def test_plan_is_loaded_before_original_measurement_clock_and_socket(self):
        original_loader = plans.load_plan
        for tool, transport, boundary in [(udp, "udp", "open_socket"), (tcp, "tcp", "bound_socket")]:
            self.path.write_text(json.dumps(document(self.config, transport)))
            events = []

            def load(*args):
                events.append("plan")
                return original_loader(*args)

            def clock():
                events.append("clock")
                return len(events) * 1000000

            def fail_socket(*_args):
                events.append("socket")
                raise OSError(errno.EADDRINUSE, "owned bind control")

            with self.subTest(transport=transport), patch.object(plans, "load_plan", side_effect=load), \
                    patch.object(tool.time, "monotonic_ns", side_effect=clock), \
                    patch.object(tool, boundary, side_effect=fail_socket):
                report = tool.run_probe(self.config, request_plan=self.path)
            self.assertEqual(events[:3], ["plan", "clock", "socket"])
            self.assertEqual(len(report["requests"]), 8)
            self.assertEqual([r["planned_offset_ns"] for r in report["requests"]], [i * 100000000 for i in range(8)])
            self.assertEqual(report["evidence"], udp.UNVERIFIED)

    def test_plan_builder_preserves_defaults_sources_and_generates_once_without_network(self):
        for transport in ["udp", "tcp"]:
            with self.subTest(transport=transport), patch.object(udp.socket, "socket", side_effect=AssertionError("prepare opens no socket")):
                value = plans.make_plan(self.config, transport, "a1" * 16, "b2" * 16)
                self.assertEqual(value["configuration"], self.config.as_dict())
                self.assertEqual(len(set(value["request_nonces"])), 8)
                self.assertEqual(self.load(value, transport=transport).nonces, tuple(value["request_nonces"]))

    def test_plan_builder_rejects_invalid_scope_transport_and_config_before_entropy(self):
        cases = [(self.config, "other", "a1" * 16, "b2" * 16),
                 (self.config, "udp", "a1" * 8, "b2" * 16),
                 (self.config, "udp", "a1" * 16, "B2" * 16),
                 (replace(self.config, count=True), "udp", "a1" * 16, "b2" * 16)]
        for args in cases:
            with self.subTest(args=args[1:]), patch.object(plans.secrets, "token_hex") as entropy:
                with self.assertRaises(ValueError):
                    plans.make_plan(*args)
                entropy.assert_not_called()

    def test_plan_builder_does_not_retry_invalid_or_colliding_entropy(self):
        for value in ["3" * 32, "invalid"]:
            with self.subTest(value=value), patch.object(plans.secrets, "token_hex", return_value=value) as entropy:
                with self.assertRaises(ValueError):
                    plans.make_plan(self.config, "udp", "a1" * 16, "b2" * 16)
                self.assertEqual(entropy.call_count, 8)

    def arguments(self, output):
        return ["prepare", "--transport", "udp", "--bind-ip", self.config.bind[0],
                "--bind-port", str(self.config.bind[1]), "--target-ip", self.config.target[0],
                "--target-port", str(self.config.target[1]), "--run-nonce", self.config.run_nonce,
                "--round-nonce", self.config.round_nonce, "--capture-id", "a1" * 16,
                "--producer-scope", "b2" * 16, "--output", str(output)]

    def test_prepare_cli_writes_one_private_plan_and_refuses_overwrite_before_entropy(self):
        out = io.StringIO()
        with redirect_stdout(out), patch.object(udp.socket, "socket", side_effect=AssertionError("prepare opens no socket")):
            self.assertEqual(plans.main(self.arguments(self.path)), 0)
        value = json.loads(self.path.read_text())
        self.assertEqual(value["configuration"], self.config.as_dict())
        receipt = json.loads(out.getvalue())
        self.assertFalse(receipt["daemon_registration_verified"])
        self.assertEqual(receipt["requests"], 8)
        self.assertEqual(receipt["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        original = self.path.read_bytes()
        with redirect_stderr(io.StringIO()), patch.object(plans.secrets, "token_hex") as entropy:
            with self.assertRaises(SystemExit) as error:
                plans.main(self.arguments(self.path))
            self.assertEqual(error.exception.code, 2)
            entropy.assert_not_called()
        self.assertEqual(self.path.read_bytes(), original)

    def test_prepare_cli_rejects_relative_and_checkout_outputs_before_entropy(self):
        checkout = self.path.parent / "repo"
        checkout.mkdir()
        (checkout / ".git").mkdir()
        for output in [Path("relative-plan.json"), checkout / "plan.json"]:
            with self.subTest(output=str(output)), redirect_stderr(io.StringIO()), patch.object(plans.secrets, "token_hex") as entropy:
                with self.assertRaises(SystemExit) as error:
                    plans.main(self.arguments(output))
                self.assertEqual(error.exception.code, 2)
                entropy.assert_not_called()
                self.assertFalse(output.exists())


class ActualOwnedLoopback(unittest.TestCase):
    def exercise(self, transport):
        kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        tool = udp if transport == "udp" else tcp
        client = socket.socket(socket.AF_INET, kind)
        server = socket.socket(socket.AF_INET, kind)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        client.bind(("127.0.0.1", 0))
        server.bind(("127.0.0.1", 0))
        config = udp.Config(client.getsockname(), server.getsockname(), "1" * 32, "2" * 32)
        echo = replace(config, bind=config.target, target=config.bind)
        result = {}
        ready = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            value = document(config, transport)
            path.write_text(json.dumps(value))
            worker = threading.Thread(target=lambda: result.update(echo=tool.run_echo(echo, server, ready.set)))
            worker.start()
            try:
                self.assertTrue(ready.wait(1))
                with patch.object(tool.secrets, "token_hex", side_effect=AssertionError("planned requests cannot regenerate nonce")):
                    report = tool.run_probe(config, client, request_plan=path)
            finally:
                worker.join(12)
            self.assertFalse(worker.is_alive())
        self.assertEqual([r["request_nonce"] for r in report["requests"]], value["request_nonces"])
        self.assertEqual([r["status"] for r in report["requests"]], ["success"] * 8)
        self.assertEqual(result["echo"]["responses_sent"], 8)
        self.assertEqual(report["configuration"], config.as_dict())
        self.assertEqual(report["evidence"], udp.UNVERIFIED)
        self.assertFalse(report["request_plan"]["daemon_registration_verified"])
        if transport == "tcp":
            self.assertEqual(report["connection_attempts"], 1)
            self.assertEqual(result["echo"]["accepted_connections"], 1)
            self.assertEqual(len(tcp.validate_probe(report)), 8)

    def test_udp_original_eight_requests_use_prepared_nonces_and_remain_unverified(self):
        self.exercise("udp")

    def test_tcp_original_eight_requests_one_connection_use_prepared_nonces(self):
        self.exercise("tcp")

    def test_original_two_file_staging_runs_default_mode_without_plan_helper(self):
        for transport, kind in [("udp", socket.SOCK_DGRAM), ("tcp", socket.SOCK_STREAM)]:
            with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_INET, kind) as occupied:
                occupied.bind(("127.0.0.1", 0))
                for name in ["udp_business_probe.py", "tcp_business_probe.py"]:
                    shutil.copyfile(TOOLS / name, Path(directory) / name)
                code = (f'import {transport}_business_probe as tool; from udp_business_probe import Config,UNVERIFIED; '
                        f'config=Config({occupied.getsockname()!r},("127.0.0.1",9),"1"*32,"2"*32); '
                        'report=tool.run_probe(config); assert "request_plan" not in report; '
                        'assert len(report["requests"])==8; assert report["evidence"]==UNVERIFIED; '
                        'assert report["termination_reason"]=="bind_failed"')
                env = dict(os.environ, PYTHONPATH="", PYTHONNOUSERSITE="1")
                child = subprocess.run([sys.executable, "-B", "-c", code], cwd=directory,
                                       env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(child.returncode, 0, child.stderr)


if __name__ == "__main__":
    unittest.main()
