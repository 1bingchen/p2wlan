"""Bounded independent UDP clients competing for a simulated NAT allocator.

Each logical device opens short UDP flows on its own schedule. Real STUN
request/response traffic enters the same observer/allocator as the daemon.
This models shared port allocation, not radio contention or TCP congestion.
"""

import asyncio
import random
import struct


class Reply(asyncio.DatagramProtocol):
    def __init__(self, transaction):
        self.transaction = transaction
        self.received = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if (len(data) >= 20 and data[:2] == b"\x01\x01"
                and data[8:20] == self.transaction and not self.received.done()):
            self.received.set_result(True)


async def run_background(nat, devices, flows, interval_ms, seed):
    if not 1 <= devices <= 16 or not 1 <= flows <= 64 or not 10 <= interval_ms <= 5000:
        raise ValueError("background limits: devices 1..16, flows 1..64, interval 10..5000 ms")

    async def device_work(device):
        rng = random.Random(seed + device)
        loop = asyncio.get_running_loop()
        for flow in range(flows):
            # Independent jitter prevents noise from being phase-locked to
            # the daemon's measurement or sweep. No candidate knowledge here.
            await asyncio.sleep(interval_ms * rng.uniform(0.5, 1.5) / 1000)
            transaction = struct.pack("!III", seed & 0xffffffff, device, flow)
            protocol = Reply(transaction)
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol, local_addr=("127.0.0.1", 0))
            try:
                client = transport.get_extra_info("sockname")
                observer = nat.observers[rng.randrange(len(nat.observers))][1]
                nat.record("background_flow_started", device=device, flow=flow,
                           client=f"{client[0]}:{client[1]}")
                transport.sendto(struct.pack("!HHI", 1, 0, 0x2112A442) + transaction, observer)
                try:
                    await asyncio.wait_for(protocol.received, timeout=2)
                    nat.record("background_flow_completed", device=device, flow=flow,
                               client=f"{client[0]}:{client[1]}")
                except asyncio.TimeoutError:
                    nat.record("background_flow_failed", device=device, flow=flow,
                               reason="stun_response_timeout")
            finally:
                transport.close()

    tasks = [asyncio.create_task(device_work(device)) for device in range(devices)]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
