#!/usr/bin/env python3
"""Observe one original HTTP pair without supplying an HTTP acceptance verdict."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from launch_identity import read_bound_process_birth
from monotonic_clock import monotonic_ns
from owned_tcp_manifest import image_from_manifest, private_object, verify_curl
from owned_tcp_protocol import Channel, Unavailable, check_fifo


class Cancelled(BaseException):
    pass


class Observation:
    def __init__(self, directory: Path, side: str, server_pid: int, port: int, observer_pid: int, curl_path: str):
        self.directory, self.side = directory, side
        self.cancelled = False
        self.client_observer = self.client = None
        self.server_channel = self.client_channel = None
        self.old_handlers = {}
        self.record = {"schema_version": 1, "side": side, "state": "unavailable", "events": [],
                       "owned_children": [], "socket_rows_are_sequential_not_atomic": True,
                       "missing_or_incomplete_rows_are_not_absence_proof": True,
                       "http_verdict_supplied": False, "setup_started_monotonic_ns": monotonic_ns()}
        try:
            for sig in (signal.SIGTERM, signal.SIGINT):
                self.old_handlers[sig] = signal.signal(sig, self._cancel)
            context = private_object(directory / "context.json")
            if side not in {"a", "b"}:
                raise Unavailable("side_invalid")
            target = context["targets"][side]
            if target["pid"] != server_pid or target["port"] != port:
                raise Unavailable("target_mismatch")
            original = read_bound_process_birth(directory.parent / "launches" / f"node-{side}.json",
                                                context["source"], f"node-{side}")
            if (original["launch_record_sha256"] != target["launch_record_sha256"]
                    or original["observation"] != target["birth"]):
                raise Unavailable("original_launch_changed")
            self.cutoff_ns = context["fixed_work_cutoff_ms"] * 1_000_000
            self.target, self.port = target, port
            self.image_meta, image = image_from_manifest(directory.parent.parent / "tcp-observer/manifest.json",
                                                        context["source"])
            if image is None or str(image) != context["image"]:
                raise Unavailable("image_unavailable")
            verify_curl(self.image_meta["curl"], curl_path)
            self.record.update(source=context["source"], image_sha256=self.image_meta["image_sha256"],
                original_server_binding=target, main_Bash_pid=context["owner_pid"],
                status_Bash_pid=os.getppid(), sampler_Python_pid=os.getpid(),
                fixed_work_cutoff_ms=context["fixed_work_cutoff_ms"], server_observer_pid=observer_pid)
            self.record["original_curl_executable"] = self.image_meta["curl"]
            self.record["caller_interposition_environment_present"] = any(os.environ.get(k) for k in
                ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES"))
            command_fd, response_fd = (8, 9) if side == "a" else (6, 7)
            check_fifo(command_fd, directory / f"{side}-in")
            check_fifo(response_fd, directory / f"{side}-out")
            self.server_channel = Channel(response_fd, command_fd, self.cutoff_ns, lambda: self.cancelled)
            self.record["server_ready"] = self.server_channel.ready(context["owner_pid"], observer_pid)
            self.client_observer = subprocess.Popen([str(image)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.client_channel = Channel(self.client_observer.stdout.fileno(), self.client_observer.stdin.fileno(),
                                          self.cutoff_ns, lambda: self.cancelled)
            self.record["client_ready"] = self.client_channel.ready(os.getpid(), self.client_observer.pid)
            self._event("server_warmup", self.server_channel.query("sample", server_pid, port, self._server_birth()))
            self._event("client_warmup", self.client_channel.query("identity", os.getpid(), port))
            self.record["state"] = "armed"
        except (OSError, ValueError, KeyError, TypeError, Unavailable) as error:
            self.record["reason"] = str(error) if isinstance(error, Unavailable) else "observer_setup_unavailable"
        self.record["setup_completed_monotonic_ns"] = monotonic_ns()

    def _cancel(self, _signal, _frame):
        # Assignment-only handler: a Popen returned during cancellation must
        # first enter its actual owner's slot before cleanup can signal it.
        self.cancelled = True

    def _server_birth(self):
        value = self.target["birth"]
        return value["birth_seconds"], value["birth_microseconds"]

    def _event(self, name, value):
        self.record["events"].append({"point": name, **value})

    def run(self, command: list[str], input_text: str, timeout: float, connect_s: float):
        if self.cancelled:
            raise Cancelled()
        # A short write into a new pipe cannot block. Other inputs use normal
        # communicate without TCP claims; this owner still joins actual curl.
        observable = self.record["state"] == "armed" and len(input_text.encode()) <= 512
        if not observable:
            self.record["state"] = "unavailable"
            self.record.setdefault("reason", "stdin_not_observable")
        began = monotonic_ns()
        self.record.update(curl_started_monotonic_ns=began, original_wrapper_timeout_s=timeout,
                           original_connect_timeout_s=connect_s)
        self.client = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
        # Send the exact original input before the native identity query. Do
        # not poll/wait/reap this actual child until its initial identity read.
        self.record["actual_curl_pid"] = self.client.pid
        pending_input = input_text
        if observable:
            try:
                self.client.stdin.write(input_text)
                self.client.stdin.close()
            except BrokenPipeError:
                pass
            self.client.stdin = None
            pending_input = None
            initial = self.client_channel.query("identity", self.client.pid, self.port)
            self._event("client_initial_identity", initial)
            value = initial.get("response", {})
            birth = None
            if initial["usable"] and value["ppid"] == os.getpid():
                birth = value["birth_seconds"], value["birth_microseconds"]
            self.record["actual_curl_initial_identity_available"] = birth is not None
            for offset in (0, 25, 75, 125, 175):
                target = began + offset * 1_000_000
                while not self.cancelled and monotonic_ns() < min(target, self.cutoff_ns):
                    time.sleep(max(0, min((target - monotonic_ns()) / 1e9, 0.005)))
                if self.cancelled:
                    raise Cancelled()
                for name, channel, pid, fence in [
                    ("server", self.server_channel, self.target["pid"], self._server_birth()),
                    ("client", self.client_channel, self.client.pid, birth)]:
                    event = channel.query("sample", pid, self.port, fence)
                    event["scheduled_offset_ms"] = offset
                    event["within_original_connect_window"] = event["ended_monotonic_ns"] <= began + int(connect_s * 1e9)
                    self._event(name, event)
        deadline = began + int(timeout * 1e9)
        while True:
            if self.cancelled:
                raise Cancelled()
            remaining = (deadline - monotonic_ns()) / 1e9
            if remaining <= 0:
                self.client.kill()
                out, _ = self.client.communicate()
                # subprocess.run TimeoutExpired normally exposes bytes even
                # in text mode; preserve the existing caller's timeout record.
                raise subprocess.TimeoutExpired(command, timeout, output=out.encode())
            try:
                out, err = self.client.communicate(input=pending_input, timeout=min(remaining, 0.025))
                break
            except subprocess.TimeoutExpired:
                pending_input = None
                continue
        self.record["curl_completed_monotonic_ns"] = monotonic_ns()
        if observable:
            self.record["state"] = "observed"
        return subprocess.CompletedProcess(command, self.client.returncode, out, err)

    def close(self):
        for name, child, channel in [("curl", self.client, None),
                                     ("client_observer", self.client_observer, self.client_channel)]:
            if child is None:
                continue
            if channel:
                channel.quit()
            forced = False
            try:
                code = child.wait(timeout=0.2 if not self.cancelled else 0)
            except subprocess.TimeoutExpired:
                forced = True
                child.kill()
                try:
                    code = child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    code = None
                    self.record.update(state="unavailable", reason="owned_child_join_unavailable")
            self.record["owned_children"].append({"role": name, "pid": child.pid,
                "exit_status": code, "wait_completed": code is not None, "forced": forced})
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        self.record.update(state="unavailable", reason="owned_pipe_close_unavailable")
        if self.server_channel:
            self.server_channel.quit()
            self.server_channel.close()
        if self.client_channel:
            self.client_channel.close()
        self.record.update(cancelled=self.cancelled, finalized_monotonic_ns=monotonic_ns())
        try:
            payload = json.dumps(self.record, sort_keys=True).encode() + b"\n"
            if len(payload) > 1024 * 1024:
                raise ValueError("observation_record_capacity")
            with (self.directory / f"{self.side}-observation.json").open("xb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(payload)
        except (OSError, ValueError):
            # A diagnostic publisher failure cannot replace the HTTP verdict.
            print("owned_tcp_unavailable:record_write_failed", file=sys.stderr)
        finally:
            for sig, handler in self.old_handlers.items():
                signal.signal(sig, handler)
