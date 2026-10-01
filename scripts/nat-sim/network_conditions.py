"""Bounded, seeded network faults. Profiles are experiments, not carrier traces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import math
from pathlib import Path
import random


@dataclass(frozen=True)
class NetworkProfile:
    jitter_ms: int = 0
    loss_rate: float | None = None
    burst_loss_rate: float = 0.0
    burst_loss_packets: int = 3
    impair_stun: bool = False
    rate_kbps: int = 0
    queue_limit: int = 1024
    max_queue_delay_ms: int = 5000
    outage_after_ms: int = 0
    outage_duration_ms: int = 0
    rebind_after_ms: int = 0
    mapping_idle_ms: int = 0

    def __post_init__(self):
        bounds = {
            "jitter_ms": (0, 5000), "burst_loss_packets": (2, 256),
            "rate_kbps": (0, 1_000_000), "queue_limit": (1, 4096),
            "max_queue_delay_ms": (1, 30_000), "outage_after_ms": (0, 120_000),
            "outage_duration_ms": (0, 30_000), "rebind_after_ms": (0, 120_000),
            "mapping_idle_ms": (0, 600_000),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be an integer in {minimum}..{maximum}")
        for name in ("loss_rate", "burst_loss_rate"):
            value = getattr(self, name)
            if name == "loss_rate" and value is None:
                continue
            if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be a finite probability")
        if type(self.impair_stun) is not bool:
            raise ValueError("impair_stun must be boolean")
        if bool(self.outage_after_ms) != bool(self.outage_duration_ms):
            raise ValueError("outage requires both after and duration")
        if 0 < self.mapping_idle_ms < 100:
            raise ValueError("mapping_idle_ms must be zero or at least 100")

    def to_dict(self):
        return asdict(self)


def load_profiles(path: str | Path | None) -> dict[str, NetworkProfile]:
    if path is None:
        return {name: NetworkProfile() for name in ("A", "B")}
    source = Path(path)
    if source.stat().st_size > 16_384:
        raise ValueError("network profile exceeds 16 KiB")
    value = json.loads(source.read_text())
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or set(value) - {"schema_version", "A", "B"}):
        raise ValueError("network profile must use schema_version 1 and A/B objects")
    allowed = {field.name for field in fields(NetworkProfile)}
    result = {}
    for name in ("A", "B"):
        side = value.get(name, {})
        if not isinstance(side, dict) or set(side) - allowed:
            raise ValueError(f"invalid network profile fields for {name}")
        result[name] = NetworkProfile(**side)
    return result


class Impairments:
    """One per-NAT impairment stream, independent of the port allocator RNG."""

    def __init__(self, profile: NetworkProfile, seed: int):
        self.profile = profile
        self.rng = random.Random(seed ^ 0x504E4154)
        self.burst_remaining = 0
        self.next_delivery_at = 0.0

    def loss(self, inherited_rate: float) -> str | None:
        if self.burst_remaining:
            self.burst_remaining -= 1
            return "packet_dropped_burst"
        if self.profile.burst_loss_rate and self.rng.random() < self.profile.burst_loss_rate:
            self.burst_remaining = self.profile.burst_loss_packets - 1
            return "packet_dropped_burst"
        rate = inherited_rate if self.profile.loss_rate is None else self.profile.loss_rate
        if rate and self.rng.random() < rate:
            return "packet_dropped_loss"
        return None

    def delay(self, now: float, base_ms: int, size: int) -> float | None:
        jitter = self.rng.uniform(-self.profile.jitter_ms, self.profile.jitter_ms)
        propagation = max(0, base_ms + jitter) / 1000
        serialized = now
        if self.profile.rate_kbps:
            serialized = max(now, self.next_delivery_at) + size * 8 / (self.profile.rate_kbps * 1000)
        delay = serialized - now + propagation
        if delay * 1000 > self.profile.max_queue_delay_ms:
            return None
        self.next_delivery_at = serialized
        return delay
