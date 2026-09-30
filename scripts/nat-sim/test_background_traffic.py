import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from background_traffic import run_background
from nat_sim import Nat, NatFabric, NatTrace


class BackgroundTrafficTests(unittest.IsolatedAsyncioTestCase):
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
            task = asyncio.create_task(run_background(nat, 2, 64, 10, 202))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            count = len(nat.mappings)
            await asyncio.sleep(0.05)
            self.assertEqual(len(nat.mappings), count)
        finally:
            await nat.close()
