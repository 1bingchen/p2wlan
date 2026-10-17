"""One bounded diagnostic timer; it never changes process scheduling priority."""
from contextlib import closing
import math
import select
import sys
import time


class SampleSleeper:
    def __init__(self):
        self.native = sys.platform == "darwin"
        self.unavailable = None

    def __call__(self, seconds):
        if not self.native or self.unavailable:
            time.sleep(seconds)
            return {"backend": "time_sleep", "native_unavailable": self.unavailable}
        try:
            with closing(select.kqueue()) as queue:
                # Darwin sys/event.h: nanoseconds=0x4, minimal timer coalescing=0x20.
                # This applies to this one timer; it does not elevate the thread.
                event = select.kevent(1, filter=select.KQ_FILTER_TIMER,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                    fflags=0x4 | 0x20, data=max(1, math.ceil(seconds * 1e9)))
                ready = queue.control([event], 1, seconds)
                if ready and (len(ready) != 1 or ready[0].ident != 1
                        or ready[0].filter != select.KQ_FILTER_TIMER
                        or ready[0].flags & select.KQ_EV_ERROR):
                    raise OSError("sample_timer_event_unavailable")
                return {"backend": "darwin_kqueue", "wake": "timer" if ready else "timeout"}
        except (OSError, ValueError) as error:
            self.unavailable = type(error).__name__
            # Return without another sleep. The caller re-reads its fixed
            # deadline before falling back, including time spent in the failure.
            return {"backend": "darwin_timer_unavailable", "reason": self.unavailable}
