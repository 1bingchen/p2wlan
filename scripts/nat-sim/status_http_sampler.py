#!/usr/bin/env python3
"""Original authenticated curl sampler with optional owned TCP diagnostics."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

side, url, token_path, process_pid, timeout_s, connect_timeout_s, header_path, root_dir = sys.argv[1:9]
tcp_directory, tcp_observer_pid = sys.argv[9:]
sys.path.insert(0, str(Path(root_dir) / "scripts/nat-sim"))
from monotonic_clock import monotonic_ns
from owned_status_observation import Observation, Cancelled
parsed = urlsplit(url)
host_port = f"{parsed.hostname or 'unknown'}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
try:
    token = Path(token_path).read_text(encoding="utf-8").strip()
except OSError:
    token = ""
curl_path = shutil.which("curl")
header_file = Path(header_path)
header_file.touch(mode=0o600, exist_ok=True)
try:
    os.chmod(header_file, 0o600)
except OSError:
    pass

process_started = None
try:
    process_started = subprocess.run(
        ["ps", "-p", str(int(process_pid)), "-o", "lstart="],
        capture_output=True,
        text=True,
        timeout=1,
        check=False,
    ).stdout.strip() or None
except (OSError, ValueError, subprocess.TimeoutExpired):
    pass

observation = None
if tcp_directory and tcp_observer_pid.isdigit() and int(tcp_observer_pid) > 0:
    observation = Observation(Path(tcp_directory), side, int(process_pid), parsed.port or 80,
                              int(tcp_observer_pid), curl_path or "")
started_ns = monotonic_ns()
stderr_text = ""
stdout_text = ""
exit_code = 1
if not token:
    stderr_text = "diagnostics_token_file_missing"
elif not curl_path:
    stderr_text = "curl_executable_missing"
else:
    writeout = "%{http_code}\t%{time_connect}\t%{time_starttransfer}\t%{time_total}\t%{size_download}"
    command = [
        curl_path,
        "--config", "-",
        "--silent", "--show-error",
        "--connect-timeout", connect_timeout_s,
        "--max-time", timeout_s,
        "--output", os.devnull,
        "--dump-header", str(header_file),
        "--write-out", writeout,
        url,
    ]
    try:
        if observation is not None:
            completed = observation.run(command, f'header = "Authorization: Bearer {token}"\n',
                                        float(timeout_s) + 2, float(connect_timeout_s))
        else:
            completed = subprocess.run(
                command,
                input=f'header = "Authorization: Bearer {token}"\n',
                capture_output=True,
                text=True,
                timeout=float(timeout_s) + 2,
                check=False,
            )
        exit_code = completed.returncode
        stdout_text = completed.stdout.strip()
        stderr_text = completed.stderr.strip()
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stderr_text = "curl_wrapper_timeout"
        if isinstance(exc.stdout, str):
            stdout_text = exc.stdout.strip()
    except OSError as exc:
        exit_code = 127
        stderr_text = f"curl_launch_error:{type(exc).__name__}"
    except Cancelled:
        observation.close()
        raise SystemExit(143)
completed_ns = monotonic_ns()
if observation is not None:
    observation.close()

parts = stdout_text.split("\t")
code = parts[0] if parts and re.fullmatch(r"[0-9]{3}", parts[0]) else "000"
def float_field(index):
    try:
        value = float(parts[index])
        return value if value >= 0 else None
    except (IndexError, ValueError):
        return None
try:
    response_bytes = int(float(parts[4]))
    if response_bytes < 0:
        response_bytes = None
except (IndexError, ValueError, OverflowError):
    response_bytes = None

request_id = None
try:
    for line in header_file.read_text(encoding="iso-8859-1").splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "x-p2wlan-status-request-id":
            request_id = value.strip()
except OSError:
    pass
finally:
    try:
        header_file.unlink()
    except OSError:
        pass

stderr_text = stderr_text.replace(token, "<redacted>") if token else stderr_text
stderr_text = re.sub(r"(?i)authorization\s*:\s*bearer\s+\S+", "Authorization: Bearer <redacted>", stderr_text)
stderr_text = "".join(ch for ch in stderr_text if ch in "\t" or ord(ch) >= 32)[:500]
record = {
    "side": side,
    "target_host_port": host_port,
    "target_path": parsed.path or "/",
    "target_process_pid": int(process_pid) if process_pid.isdigit() else None,
    "target_process_start": process_started,
    "client_started_monotonic_ns": started_ns,
    "client_completed_monotonic_ns": completed_ns,
    "client_duration_ms": round((completed_ns - started_ns) / 1_000_000, 3),
    "curl_exit_code": exit_code,
    "http_status": code,
    "time_connect_s": float_field(1),
    "time_starttransfer_s": float_field(2),
    "time_total_s": float_field(3),
    "response_bytes": response_bytes,
    "server_request_id": request_id,
    "curl_stderr": stderr_text,
}
print(json.dumps(record, sort_keys=True))
