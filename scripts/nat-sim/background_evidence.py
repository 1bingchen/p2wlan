"""Require every competing device to remain active through captured traffic."""


def sustained_background_coverage(rows, capture_times, devices, interval_ms):
    # Independent jitter adds up to half an interval. A failed STUN flow may
    # spend two seconds waiting; allow a further bounded scheduler margin.
    maximum_gap_ns = int(interval_ms * 1.5 + 3000) * 1_000_000
    errors = []
    per_device = {}
    if (not capture_times or any(type(t) is not int or t <= 0 for t in capture_times)
            or any(b < a for a, b in zip(capture_times, capture_times[1:]))):
        return {"valid": False, "errors": ["capture_clock_invalid"], "devices": {}}
    start, end = capture_times[0], capture_times[-1]
    if end - start < 10_000_000_000:
        errors.append("capture_window_too_short")
    for row in rows:
        if (type(row.get("device")) is not int or not 0 <= row["device"] < devices
                or type(row.get("monotonic_ns")) is not int or row["monotonic_ns"] <= 0):
            errors.append("background_identity_or_clock_invalid")
    for device in range(devices):
        times = [row["monotonic_ns"] for row in rows
                 if row.get("device") == device and type(row.get("monotonic_ns")) is int]
        in_window = [t for t in times if start <= t <= end]
        gaps = [b - a for a, b in zip([start, *in_window], [*in_window, end])]
        valid = (len(in_window) >= 2 and all(0 <= gap <= maximum_gap_ns for gap in gaps)
                 and all(a < b for a, b in zip(times, times[1:])))
        if not valid:
            errors.append(f"device_{device}_coverage_incomplete")
        per_device[str(device)] = {"flow_starts": len(times), "starts_during_capture": len(in_window),
                                   "maximum_gap_ms": max(gaps, default=0) / 1_000_000,
                                   "valid": valid}
    return {"valid": not errors, "errors": sorted(set(errors)), "devices": per_device,
            "capture_span_ms": (end - start) / 1_000_000,
            "maximum_allowed_gap_ms": maximum_gap_ns / 1_000_000}
