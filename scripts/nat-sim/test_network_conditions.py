import asyncio
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from network_conditions import Impairments, NetworkProfile, load_profiles
from nat_sim import Nat, NatFabric


class ProfileTests(unittest.TestCase):
    def test_profile_rejects_invalid_types_nonfinite_values_and_unpaired_outage(self):
        for options in ({"jitter_ms": True}, {"loss_rate": float("nan")},
                        {"loss_rate": -1}, {"loss_rate": True}, {"queue_limit": 0},
                        {"mapping_idle_ms": 50}, {"outage_after_ms": 1},
                        {"impair_stun": 1}, {"rebind_after_ms": 120001}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                NetworkProfile(**options)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            for value in ({"schema_version": True}, {"schema_version": 1, "A": {"typo": 1}}, []):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_profiles(path)

    def test_jitter_reproduces_for_same_seed_and_stays_in_bounds(self):
        first = Impairments(NetworkProfile(jitter_ms=40), 17)
        second = Impairments(NetworkProfile(jitter_ms=40), 17)
        a = [first.delay(10, 60, 100) for _ in range(30)]
        b = [second.delay(10, 60, 100) for _ in range(30)]
        self.assertEqual(a, b)
        self.assertGreater(len(set(a)), 1)
        self.assertTrue(all(0.02 <= value <= 0.1 for value in a))

    def test_burst_drops_are_correlated_and_end_after_configured_length(self):
        model = Impairments(NetworkProfile(burst_loss_rate=0.4, burst_loss_packets=4), 21)
        decisions = [model.loss(0) for _ in range(200)]
        self.assertIn(None, decisions)
        self.assertIn("packet_dropped_burst", decisions)
        runs = []
        run = 0
        for value in decisions + [None]:
            if value:
                run += 1
            elif run:
                runs.append(run)
                run = 0
        # The last sampled run may be truncated by the finite observation.
        self.assertTrue(all(length % 4 == 0 for length in runs[:-1]))

    def test_serialization_queue_is_shared_bounded_and_rejected_packet_does_not_reserve(self):
        model = Impairments(NetworkProfile(rate_kbps=8, max_queue_delay_ms=250), 1)
        self.assertAlmostEqual(model.delay(1, 0, 100), 0.1)
        self.assertAlmostEqual(model.delay(1, 0, 100), 0.2)
        reserved = model.next_delivery_at
        self.assertIsNone(model.delay(1, 0, 100))
        self.assertEqual(model.next_delivery_at, reserved)
        self.assertAlmostEqual(model.delay(2, 0, 100), 0.1)

    def test_packet_fault_rng_does_not_perturb_port_allocator(self):
        a = Nat("A", "127.0.0.1", 1, 3, 16000, mapping_mode="random")
        b = Nat("A", "127.0.0.1", 1, 3, 16000, mapping_mode="random",
                network_profile=NetworkProfile(jitter_ms=100, loss_rate=0.5))
        for _ in range(100):
            b.impairments.loss(0)
            b.impairments.delay(0, 0, 100)
            self.assertEqual(a.alloc_port(), b.alloc_port())


class Capture(asyncio.DatagramProtocol):
    def __init__(self):
        self.packets = asyncio.Queue()

    def datagram_received(self, data, source):
        self.packets.put_nowait((data, source))


class Trace:
    def __init__(self):
        self.rows = []

    def record(self, event, **fields):
        self.rows.append({"event": event, **fields})


class NetworkLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transports, self.nats = [], []
        self.trace = Trace()
        self.fabric = NatFabric(self.trace)

    async def asyncTearDown(self):
        for nat in self.nats:
            await nat.close()
        for transport in self.transports:
            transport.close()

    async def endpoint(self):
        capture = Capture()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: capture, local_addr=("127.0.0.1", 0))
        self.transports.append(transport)
        return transport, capture, transport.get_extra_info("sockname")

    async def nat(self, name, **options):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        nat = Nat(name, "127.0.0.1", 1, len(self.nats) + 3, port, **options)
        await nat.start(self.fabric)
        self.nats.append(nat)
        return nat

    async def until(self, predicate):
        async with asyncio.timeout(1):
            while not predicate():
                await asyncio.sleep(0)

    def event_count(self, event):
        return sum(row["event"] == event for row in self.trace.rows)

    async def test_real_stun_outage_rebind_and_recovery(self):
        profile = NetworkProfile(outage_after_ms=100, outage_duration_ms=1000, rebind_after_ms=500)
        nat = await self.nat("A", network_profile=profile)
        observer = await nat.add_observer()
        transport, capture, client = await self.endpoint()
        request = struct.pack("!HHI", 1, 0, 0x2112A442) + b"a" * 12
        transport.sendto(request, observer)
        first, _ = await asyncio.wait_for(capture.packets.get(), 1)
        nat._network_task.cancel()
        await asyncio.gather(nat._network_task, return_exceptions=True)
        started = nat._network_started_at
        old = nat.mappings[(client, observer)]
        nat.advance_network(started + 0.2)
        transport.sendto(request, observer)
        await self.until(lambda: self.event_count("packet_dropped_outage") == 1)
        self.assertTrue(capture.packets.empty())
        nat.advance_network(started + 1.2)
        self.assertFalse(nat.mapping_is_current(old))
        transport.sendto(request, observer)
        second, _ = await asyncio.wait_for(capture.packets.get(), 1)
        self.assertNotEqual(first[26:28], second[26:28])
        self.assertEqual(self.event_count("network_rebound"), 1)
        self.assertEqual(self.event_count("network_outage_ended"), 1)

    async def test_idle_timer_refreshes_on_outbound_and_retires_exact_mapping(self):
        nat = await self.nat("A", network_profile=NetworkProfile(mapping_idle_ms=1000))
        _, _, client = await self.endpoint()
        mapping = nat.mapping_for(client, ("127.0.0.1", 40001))
        nat._network_started_at = mapping.last_outbound_at
        mapping.last_outbound_at -= 0.8
        self.assertIs(nat.mapping_for(client, mapping.destination), mapping)
        nat.advance_network(mapping.last_outbound_at + 0.9)
        self.assertTrue(nat.mapping_is_current(mapping))
        nat.advance_network(mapping.last_outbound_at + 1.1)
        self.assertFalse(nat.mapping_is_current(mapping))

    async def test_queued_packet_cannot_use_replaced_source_or_receiver_mapping(self):
        for retire_source in (False, True):
            a, b = await self.nat("A"), await self.nat("B")
            _, _, client_a = await self.endpoint()
            _, capture_b, client_b = await self.endpoint()
            source = a.mapping_for(client_a, (b.public_ip, b.next_port))
            receiver = b.mapping_for(client_b, (a.public_ip, source.port))
            await a.ensure_bound(source)
            await b.ensure_bound(receiver)
            task = asyncio.create_task(b._delayed_delivery(
                receiver, b"old-packet", (a.public_ip, source.port), 0.02,
                source_mapping=(a, source)))
            owner, old = (a, source) if retire_source else (b, receiver)
            owner.retire_mapping(old, "network_rebind")
            replacement = owner.mapping_for(old.client, old.destination)
            await owner.ensure_bound(replacement)
            await task
            self.assertTrue(capture_b.packets.empty())
        self.assertEqual(self.event_count("packet_dropped_stale_mapping"), 2)

    async def test_stun_pending_queue_is_bounded_and_close_cancels_deliveries(self):
        nat = await self.nat("A", stun_delay_ms=500, network_profile=NetworkProfile(queue_limit=2))
        observer = await nat.add_observer()
        transport, capture, _ = await self.endpoint()
        request = struct.pack("!HHI", 1, 0, 0x2112A442) + b"b" * 12
        for _ in range(20):
            transport.sendto(request, observer)
        await self.until(lambda: self.event_count("packet_dropped_queue") == 18)
        self.assertEqual(len(nat._packet_tasks), 2)
        await nat.close()
        self.assertFalse(nat._packet_tasks)
        self.assertTrue(capture.packets.empty())

    async def test_delayed_stun_cannot_advertise_retired_mapping(self):
        nat = await self.nat("A", stun_delay_ms=30)
        observer = await nat.add_observer()
        transport, capture, client = await self.endpoint()
        transport.sendto(struct.pack("!HHI", 1, 0, 0x2112A442) + b"c" * 12, observer)
        await self.until(lambda: any(m.bound_reported for m in nat.mappings.values()))
        nat.retire_mapping(nat.mappings[(client, observer)], "network_rebind")
        await self.until(lambda: self.event_count("packet_dropped_stale_mapping") == 1)
        self.assertTrue(capture.packets.empty())


if __name__ == "__main__":
    unittest.main()
