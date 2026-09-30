import asyncio
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest

from background_traffic import run_background, validate_background_limits
from background_evidence import sustained_background_coverage
from nat_sim import Nat, NatFabric, NatTrace


class BackgroundTrafficTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(sys.platform in {"darwin", "linux"}, "native NAT harness platforms")
    async def test_sigterm_drains_inflight_continuous_background_flows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            process = await asyncio.create_subprocess_exec(
                sys.executable, str(Path(__file__).with_name("nat_sim.py")),
                "--egress-capture", "shim", "--trace-file", str(path),
                "--background-devices", "2", "--background-interval-ms", "10",
                "--background-duration-ms", "1000", "--stun-delay-a-ms", "500",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                banner = {}
                while "NAT_FEATURES" not in banner:
                    line = await asyncio.wait_for(process.stdout.readline(), 3)
                    self.assertTrue(line, "simulator exited before readiness")
                    key, value = line.decode().strip().split("=", 1)
                    banner[key] = value
                observer = int(banner["STUN_A"].split(",")[0].split(":")[-1])
                payload = struct.pack("!HHI", 1, 0, 0x2112A442) + bytes(12)
                envelope = b"P2NAT001" + socket.inet_aton("127.0.0.1") + struct.pack("!HH", observer, len(payload)) + payload
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.sendto(envelope, ("127.0.0.1", int(banner["EGRESS_A_PORT"])))
                for _ in range(100):
                    rows = [json.loads(line) for line in path.read_text().splitlines()]
                    if sum(row["event"] == "background_flow_started" for row in rows) >= 2:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(sum(row["event"] == "background_flow_started" for row in rows), 2)
                process.terminate()
                _, stderr = await asyncio.wait_for(process.communicate(), 3)
                self.assertEqual(process.returncode, 0, stderr.decode())
                rows = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertEqual(sum(row["event"] == "background_flow_cancelled" for row in rows), 2)
                self.assertEqual(sum(row["event"] == "background_device_stopped" for row in rows), 2)
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()

    async def test_independent_udp_flows_share_allocator_and_receive_replies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            trace = NatTrace(str(path))
            nat = await Nat("A", "127.0.0.1", 1, 42, 18000).start(NatFabric(trace))
            try:
                await nat.add_observer()
                await nat.add_observer()
                before = nat.mapping_for(("127.0.0.1", 9998), ("127.0.0.1", 9999)).port
                await asyncio.wait_for(run_background(nat, 3, 4, 10, 101), timeout=3)
                after = nat.mapping_for(("127.0.0.1", 9998), ("127.0.0.1", 9997)).port
                self.assertGreater(after - before, 1)
                self.assertLessEqual(len(nat.mappings), 14)
            finally:
                await nat.close()
                trace.close()
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            completed = [row for row in rows if row["event"] == "background_flow_completed"]
            bound_clients = {row["client"] for row in rows if row["event"] == "mapping_bound"}
            self.assertEqual(len(completed), 12)
            self.assertEqual({row["device"] for row in completed}, {0, 1, 2})
            self.assertTrue(all(row["client"] in bound_clients for row in completed))
            self.assertFalse(any(row["event"] == "background_flow_failed" for row in rows))

    async def test_cancellation_stops_background_allocation(self):
        nat = await Nat("A", "127.0.0.1", 1, 42, 19000).start()
        try:
            await nat.add_observer()
            task = asyncio.create_task(run_background(nat, 2, 64, 10, 202, duration_ms=1000))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            count = len(nat.mappings)
            await asyncio.sleep(0.05)
            self.assertEqual(len(nat.mappings), count)
        finally:
            await nat.close()

    async def test_sustained_mode_outlives_the_finite_flow_count_and_stops_at_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            trace = NatTrace(str(path))
            nat = await Nat("A", "127.0.0.1", 1, 42, 19000).start(NatFabric(trace))
            try:
                await nat.add_observer()
                await asyncio.wait_for(run_background(nat, 2, 1, 10, 303, 150), timeout=1)
                count = len(nat.mappings)
                await asyncio.sleep(0.04)
                self.assertEqual(len(nat.mappings), count)
            finally:
                await nat.close()
                trace.close()
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            for device in range(2):
                starts = [row["monotonic_ns"] for row in rows
                          if row["event"] == "background_flow_started" and row["device"] == device]
                self.assertGreater(len(starts), 2)
                self.assertGreater(starts[-1] - starts[0], 100_000_000)
            self.assertTrue(all(row["reason"] == "duration_expired" for row in rows
                                if row["event"] == "background_device_stopped"))

    def test_sustained_mode_has_a_total_allocation_and_duration_bound(self):
        self.assertEqual(validate_background_limits(8, 16, 150, 60000), 800)
        for args in [(16, 64, 10, 60000), (8, 16, 150, 120001), (8, 16, 150, -1)]:
            with self.assertRaises(ValueError):
                validate_background_limits(*args)

    def test_coverage_requires_all_eight_devices_through_the_final_capture(self):
        start = 1_000_000_000
        rows = [{"device": device, "monotonic_ns": start + offset * 1_000_000_000}
                for offset in range(1, 31) for device in range(8)]
        clocks = [start, start + 30_000_000_000]
        self.assertTrue(sustained_background_coverage(rows, clocks, 8, 150)["valid"])
        stopped = [row for row in rows if row["device"] != 7 or row["monotonic_ns"] < start + 3_000_000_000]
        self.assertFalse(sustained_background_coverage(stopped, clocks, 8, 150)["valid"])
        self.assertFalse(sustained_background_coverage(rows[:16], clocks, 8, 150)["valid"])
        self.assertFalse(sustained_background_coverage(rows, [], 8, 150)["valid"])
