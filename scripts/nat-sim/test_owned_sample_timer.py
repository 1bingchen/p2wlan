"""Timer resource and fallback controls without extending sample deadlines."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from owned_sample_timer import SampleSleeper
from owned_status_observation import wait_for_sample


def native(queue):
    return SimpleNamespace(kqueue=Mock(return_value=queue),
        kevent=lambda ident, **kwargs: SimpleNamespace(ident=ident, **kwargs),
        KQ_FILTER_TIMER=-7, KQ_EV_ADD=1, KQ_EV_ONESHOT=16, KQ_EV_ERROR=16384)


class TimerControls(unittest.TestCase):
    def queue(self):
        queue = Mock()
        queue.control.return_value = [SimpleNamespace(ident=1, filter=-7, flags=0)]
        return queue

    def test_other_platform_keeps_existing_sleep_without_native_resource(self):
        api = native(self.queue())
        with patch("owned_sample_timer.sys.platform", "linux"), patch("owned_sample_timer.select", api), \
                patch("owned_sample_timer.time.sleep") as sleep:
            result = SampleSleeper()(.005)
        sleep.assert_called_once_with(.005)
        api.kqueue.assert_not_called()
        self.assertEqual(result["backend"], "time_sleep")

    def test_one_shot_timer_keeps_interval_and_closes_its_only_queue(self):
        queue = self.queue()
        with patch("owned_sample_timer.sys.platform", "darwin"), patch("owned_sample_timer.select", native(queue)):
            result = SampleSleeper()(.005)
        changes, count, timeout = queue.control.call_args.args
        self.assertEqual((count, timeout), (1, .005))
        self.assertEqual((changes[0].data, changes[0].filter, changes[0].flags, changes[0].fflags),
                         (5_000_000, -7, 17, 0x24))
        queue.close.assert_called_once_with()
        self.assertEqual(result, {"backend": "darwin_kqueue", "wake": "timer"})

    def test_timeout_also_closes_the_one_shot_queue(self):
        queue = self.queue()
        queue.control.return_value = []
        with patch("owned_sample_timer.sys.platform", "darwin"), patch("owned_sample_timer.select", native(queue)):
            result = SampleSleeper()(.005)
        self.assertEqual(result["wake"], "timeout")
        queue.close.assert_called_once_with()

    def test_creation_failure_falls_back_only_on_the_next_wait(self):
        api = native(self.queue())
        api.kqueue.side_effect = OSError("no queue")
        with patch("owned_sample_timer.sys.platform", "darwin"), patch("owned_sample_timer.select", api), \
                patch("owned_sample_timer.time.sleep") as sleep:
            sleeper = SampleSleeper()
            self.assertEqual(sleeper(.005)["backend"], "darwin_timer_unavailable")
            sleep.assert_not_called()
            self.assertEqual(sleeper(.002)["backend"], "time_sleep")
        sleep.assert_called_once_with(.002)
        api.kqueue.assert_called_once_with()

    def test_control_failure_closes_before_reporting_unavailable(self):
        queue = self.queue()
        queue.control.side_effect = OSError("timer registration failed")
        with patch("owned_sample_timer.sys.platform", "darwin"), patch("owned_sample_timer.select", native(queue)):
            result = SampleSleeper()(.005)
        self.assertEqual(result["backend"], "darwin_timer_unavailable")
        queue.close.assert_called_once_with()

    def test_error_or_wrong_timer_event_is_unavailable_and_closed(self):
        for event in [SimpleNamespace(ident=1, filter=-7, flags=16384),
                      SimpleNamespace(ident=2, filter=-7, flags=0),
                      SimpleNamespace(ident=1, filter=-1, flags=0)]:
            with self.subTest(event=event):
                queue = self.queue()
                queue.control.return_value = [event]
                with patch("owned_sample_timer.sys.platform", "darwin"), patch("owned_sample_timer.select", native(queue)):
                    self.assertEqual(SampleSleeper()(.005)["backend"], "darwin_timer_unavailable")
                queue.close.assert_called_once_with()

    def test_positive_fraction_never_registers_zero_nanoseconds(self):
        queue = self.queue()
        with patch("owned_sample_timer.sys.platform", "darwin"), patch("owned_sample_timer.select", native(queue)):
            SampleSleeper()(.5e-9)
        self.assertEqual(queue.control.call_args.args[0][0].data, 1)


class WaitTraceControls(unittest.TestCase):
    def test_backend_failure_time_is_charged_to_the_original_target(self):
        now = 0
        queue = Mock()
        def fail(*_args):
            nonlocal now
            now = 8_000_000
            raise OSError("spent time before failure")
        queue.control.side_effect = fail
        def sleep(seconds):
            nonlocal now
            now += round(seconds * 1e9)
        trace = {}
        with patch("owned_sample_timer.sys.platform", "darwin"), patch("owned_sample_timer.select", native(queue)), \
                patch("owned_sample_timer.time.sleep", side_effect=sleep) as fallback:
            self.assertTrue(wait_for_sample(10_000_000, 100_000_000, lambda: False,
                clock=lambda: now, sleeper=SampleSleeper(), trace=trace))
        fallback.assert_called_once_with(.002)
        queue.close.assert_called_once_with()
        self.assertEqual(now, 10_000_000)
        self.assertEqual([v["requested_ns"] for v in trace["sleeps"]], [5_000_000, 2_000_000])
        self.assertEqual(trace["due_observed_monotonic_ns"], 10_000_000)

    def test_trace_capacity_reports_omissions_without_adding_waits(self):
        now = 0
        def sleep(_seconds):
            nonlocal now
            now += 1
        trace = {}
        self.assertTrue(wait_for_sample(100, 1000, lambda: False,
            clock=lambda: now, sleeper=sleep, trace=trace))
        self.assertEqual((now, trace["sleep_count"], len(trace["sleeps"]), trace["omitted_sleeps"]),
                         (100, 100, 64, 36))

    def test_cancelled_trace_does_not_read_clock_or_allocate_timer(self):
        def forbidden(*_args):
            self.fail("cancelled sampler cannot wait")
        trace = {}
        self.assertFalse(wait_for_sample(100, 1000, lambda: True,
            clock=forbidden, sleeper=forbidden, trace=trace))
        self.assertTrue(trace["cancelled"])
        self.assertEqual(trace["sleeps"], [])


if __name__ == "__main__":
    unittest.main()
