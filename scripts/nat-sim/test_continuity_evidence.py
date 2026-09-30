import json
from pathlib import Path
import tempfile
import unittest

from continuity_evidence import sample, summarize


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.samples = [{"monotonic_ns": (i + 1) * 1_000_000_000, "a": 2 * i, "b": 2 * i}
                        for i in range(9)]

    def verify(self, events=(), profile=None, require_direct=False):
        (self.root / "business-samples.jsonl").write_text("".join(json.dumps(x) + "\n" for x in self.samples))
        (self.root / "nat-trace.jsonl").write_text("".join(json.dumps(x) + "\n" for x in events))
        path = None
        if profile is not None:
            path = self.root / "profile.json"
            path.write_text(json.dumps({"schema_version": 1, "A": profile}))
        return summarize(self.root, path, require_direct)

    def test_sampler_distinguishes_verified_direct_business_from_promotions(self):
        for side in ("a", "b"):
            (self.root / f"node-{side}.log").write_text(
                'direct_promoted\noverlay_payload_verified ingress=direct count=1\n'
                'overlay_payload_verified ingress=relay:test count=2\n')
        sample(self.root)
        row = json.loads((self.root / "business-samples.jsonl").read_text())
        self.assertEqual(row["direct"], {"a": 1, "b": 1})
        self.assertEqual((row["a"], row["b"]), (2, 2))
        self.assertGreaterEqual(row["completed_monotonic_ns"], row["monotonic_ns"])

    def test_established_path_requires_direct_business_before_first_fault(self):
        events = [{"nat": "A", "event": name, "monotonic_ns": second * 1_000_000_000}
                  for name, second in [("network_outage_started", 4), ("packet_dropped_outage", 5),
                                       ("network_outage_ended", 6)]]
        profile = {"outage_after_ms": 4000, "outage_duration_ms": 2000}
        for row in self.samples:
            row["completed_monotonic_ns"] = row["monotonic_ns"] + 1
            row["direct"] = {side: row[side] for side in ("a", "b")}
        self.assertTrue(self.verify(events, profile, True)["direct_before_fault"])
        # Direct that starts after the fault cannot satisfy the setup proof.
        for row in self.samples[:4]:
            row["direct"] = {"a": 0, "b": 0}
        result = self.verify(events, profile, True)
        self.assertFalse(result["valid"])
        self.assertIn("direct_business_before_fault_missing", result["errors"])

    def test_direct_sample_must_have_a_valid_read_completion_clock(self):
        for row in self.samples:
            row["completed_monotonic_ns"] = row["monotonic_ns"] - 1
            row["direct"] = {side: row[side] for side in ("a", "b")}
        self.assertIn("invalid_direct_business_sample", self.verify(require_direct=True)["errors"])

    def test_sustained_both_direction_business_passes(self):
        self.assertTrue(self.verify()["valid"])

    def test_historic_success_and_one_sided_progress_do_not_pass(self):
        for row in self.samples:
            row["b"] = 100
        result = self.verify()
        self.assertFalse(result["valid"])
        self.assertIn("recent_bidirectional_business_stalled", result["errors"])

    def test_counter_reset_or_reordered_sample_invalidates_evidence(self):
        self.samples[-1]["a"] = 0
        self.assertFalse(self.verify()["valid"])
        self.samples[-1] = dict(self.samples[-2])
        self.assertFalse(self.verify()["valid"])

    def test_configured_but_unexercised_fault_fails(self):
        result = self.verify(profile={"burst_loss_rate": 0.1})
        self.assertIn("A:fault_not_exercised:packet_dropped_burst", result["errors"])

    def test_outage_requires_actual_drop_end_and_new_business_afterward(self):
        events = [{"nat": "A", "event": name, "monotonic_ns": second * 1_000_000_000}
                  for name, second in [("network_outage_started", 1), ("packet_dropped_outage", 2),
                                       ("network_outage_ended", 4)]]
        profile = {"outage_after_ms": 1000, "outage_duration_ms": 3000}
        self.assertTrue(self.verify(events, profile)["valid"])
        events[-1]["monotonic_ns"] = 8_500_000_000
        result = self.verify(events, profile)
        self.assertIn("post_fault_bidirectional_business_missing", result["errors"])

    def test_rebind_requires_nonempty_retirement_and_new_mapping(self):
        events = [{"nat": "A", "event": "network_rebound", "monotonic_ns": 2_000_000_000,
                   "retired_mappings": 3}]
        profile = {"rebind_after_ms": 1000}
        self.assertFalse(self.verify(events, profile)["valid"])
        events.append({"nat": "A", "event": "mapping_created", "monotonic_ns": 3_000_000_000})
        self.assertTrue(self.verify(events, profile)["valid"])
        events[0]["retired_mappings"] = 0
        self.assertFalse(self.verify(events, profile)["valid"])


if __name__ == "__main__":
    unittest.main()
