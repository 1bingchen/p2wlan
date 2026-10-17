"""Deterministic timing controls, independent of the eleven native TCP cases."""
import unittest

from owned_status_observation import wait_for_sample


class SampleScheduleControls(unittest.TestCase):
    def test_clock_crossing_never_requests_zero_duration_yield(self):
        times = iter([99, 101, 101])
        sleeps = []
        self.assertTrue(wait_for_sample(100, 1000, lambda: False,
                                       clock=lambda: next(times), sleeper=sleeps.append))
        self.assertTrue(sleeps)
        self.assertTrue(all(duration > 0 for duration in sleeps), sleeps)

    def test_wait_uses_the_nearer_fixed_cutoff(self):
        times = iter([2, 4, 4])
        sleeps = []
        self.assertTrue(wait_for_sample(1_000_000_000, 3, lambda: False,
                                       clock=lambda: next(times), sleeper=sleeps.append))
        self.assertTrue(sleeps)
        self.assertTrue(all(duration <= 1e-9 for duration in sleeps), sleeps)

    def test_due_point_does_not_sleep(self):
        sleeps = []
        self.assertTrue(wait_for_sample(100, 1000, lambda: False,
                                       clock=lambda: 100, sleeper=sleeps.append))
        self.assertEqual(sleeps, [])

    def test_already_cancelled_wait_does_not_read_clock_or_sleep(self):
        def forbidden(*_args):
            self.fail("a cancelled wait cannot read or sleep")
        self.assertFalse(wait_for_sample(100, 1000, lambda: True,
                                        clock=forbidden, sleeper=forbidden))

    def test_long_wait_keeps_five_ms_poll_and_original_target(self):
        now = 0
        sleeps = []
        def sleep(duration):
            nonlocal now
            self.assertGreater(duration, 0)
            self.assertLessEqual(duration, 0.005)
            sleeps.append(duration)
            now += round(duration * 1_000_000_000)
        self.assertTrue(wait_for_sample(30_000_000, 100_000_000, lambda: False,
                                       clock=lambda: now, sleeper=sleep))
        self.assertEqual(now, 30_000_000)
        self.assertEqual(len(sleeps), 6)

    def test_cancellation_after_sleep_does_not_wait_again(self):
        cancelled = False
        sleeps = []
        def sleep(duration):
            nonlocal cancelled
            sleeps.append(duration)
            cancelled = True
        self.assertFalse(wait_for_sample(30_000_000, 100_000_000, lambda: cancelled,
                                        clock=lambda: 0, sleeper=sleep))
        self.assertEqual(sleeps, [0.005])


if __name__ == "__main__":
    unittest.main()
