#!/usr/bin/env python3
"""Source-entry controls, distinct from the four actual product rounds."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import launch_identity as launch
from monotonic_clock import monotonic_ns
from owned_tcp_manifest import image_from_manifest, prepare_image
from owned_tcp_protocol import Channel, Unavailable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def function(name):
    source = (HERE / "nat-sim-smoke.sh").read_text()
    start = source.index(name + "() {\n")
    end = re.search(r"^\}\n", source[start:], re.M)
    return source[start:start + end.end()]


class PipeControls(unittest.TestCase):
    def test_real_forced_join_is_bounded_and_does_not_start_round_resource_grace(self):
        script = r'''
set -euo pipefail
ROOT_DIR=$1; ROUND_DIR=$2; PIDS=(); overall=0
source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"
source "$ROOT_DIR/scripts/nat-sim/owned_tcp_observer.sh"
round_init
/bin/bash -c 'trap "" TERM; echo ready; exec sleep 3' >"$ROUND_DIR/ready" &
child=$!
round_register_process tcp-server-observer-a "$child"
end=$(($(_round_now)+1000))
_tcp_join_owned "$child" "$end"
[[ ${#PIDS[@]} == 0 && $_ROUND_WAIT_COMPLETED == 1 && $_ROUND_WAIT_UNKNOWN == 0 ]]
[[ $_ROUND_RESOURCE_END_MS == 0 && $_ROUND_OWNER_FORCED == 1 && $CLEANUP_FORCED == 1 ]]
_round_owner_lines
'''
        with tempfile.TemporaryDirectory(prefix="p2wlan-join-bound-") as directory:
            env = {**os.environ, "PATH": str(Path(sys.executable).parent) + ":" + os.environ["PATH"]}
            result = subprocess.run(["/bin/bash", "-c", script, "control", str(ROOT), directory],
                                    capture_output=True, text=True, timeout=4, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip().split("\t")[2:], ["1", "137", "1"])

    def test_eof_is_unavailable_and_reader_nonblocking_does_not_change_writer(self):
        incoming, writer = os.pipe()
        command, outgoing = os.pipe()
        channel = Channel(incoming, outgoing, monotonic_ns() + 1_000_000_000, lambda: False)
        try:
            self.assertFalse(os.get_blocking(incoming))
            self.assertTrue(os.get_blocking(writer))
            os.close(writer)
            writer = None
            with self.assertRaisesRegex(Unavailable, "observer_eof"):
                channel.read()
        finally:
            channel.close()
            for fd in (incoming, writer, command, outgoing):
                if fd is not None:
                    os.close(fd)

    def test_expired_query_cannot_write_a_command(self):
        incoming, writer = os.pipe()
        command, outgoing = os.pipe()
        channel = Channel(incoming, outgoing, monotonic_ns() - 1, lambda: False)
        try:
            row = channel.query("sample", os.getpid(), 1, (1, 0))
            self.assertFalse(row["usable"])
            self.assertEqual(row["reason"], "cancelled_or_fixed_cutoff")
            os.set_blocking(command, False)
            with self.assertRaises(BlockingIOError):
                os.read(command, 128)
        finally:
            channel.close()
            for fd in (incoming, writer, command, outgoing):
                os.close(fd)

    def test_invalid_response_does_not_become_empty_socket_snapshot(self):
        incoming, writer = os.pipe()
        command, outgoing = os.pipe()
        channel = Channel(incoming, outgoing, monotonic_ns() + 1_000_000_000, lambda: False)
        try:
            os.write(writer, b'{"schema":3,"event":"sample","request_id":2,"valid":true}\n')
            row = channel.query("sample", os.getpid(), 1, (1, 0))
            self.assertFalse(row["usable"])
            self.assertEqual(row["reason"], "response_identity_invalid")
            self.assertIn("response", row)
            self.assertNotIn("rows", row)
        finally:
            channel.close()
            for fd in (incoming, writer, command, outgoing):
                os.close(fd)


SERVER = r'''
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1],"--probe")) { puts("fixture-image-ready");return 0; }
    alarm(8);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family=AF_INET, .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    if (s < 0 || bind(s,(struct sockaddr *)&a,sizeof(a)) || listen(s,8)) return 3;
    socklen_t size=sizeof(a);
    if (getsockname(s,(struct sockaddr *)&a,&size)) return 4;
    printf("ready %d\n",ntohs(a.sin_port));fflush(stdout);
    int c=accept(s,NULL,NULL);
    char request[2048];
    if (c < 0 || read(c,request,sizeof(request)) <= 0) return 5;
    puts("request");fflush(stdout);
    if (!strcmp(argv[1],"stall")) sleep(6);
    else {
        const char response[]="HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-P2WLAN-Status-Request-ID: fixture-only\r\nConnection: close\r\n\r\n";
        if (write(c,response,sizeof(response)-1) != sizeof(response)-1) return 6;
        close(c);
        if (strcmp(argv[1],"fast")) sleep(1);
    }
    close(s);return 0;
}
'''

OWNER = r'''
set -euo pipefail
ROOT_DIR=$1; BASE_DIR=$2; ROUND_DIR=$BASE_DIR/round-1; control=$3
mkdir -m 700 "$ROUND_DIR" "$ROUND_DIR/launches"
source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"
source "$ROOT_DIR/scripts/nat-sim/owned_tcp_observer.sh"
umask 077
PIDS=();overall=0;ROUND_TIMEOUT_S=150;FINALIZE_BUDGET_S=15
ROUND_DEADLINE=$((SECONDS+150));WORK_DEADLINE=$((ROUND_DEADLINE-15));MODE=normal
read -r ROUND_CLOCK_ORIGIN_MONOTONIC_MS ROUND_CLOCK_ORIGIN_UNIX_S ROUND_CLOCK_ORIGIN_UNIX_MS < <(python3 "$ROOT_DIR/scripts/nat-sim/monotonic_clock.py" origin)
ROUND_CLOCK_ORIGIN_SECONDS=$SECONDS
round_init
cleanup_control() {
  local status=$?
  trap - EXIT INT TERM
  if (( ${#PIDS[@]} > 0 )); then stop_round_processes; fi
  _round_owner_lines >"$BASE_DIR/owner-ledger.tsv"
  printf '%s\t%s\t%s\t%s\n' "$_ROUND_STARTED" "$_ROUND_WAIT_COMPLETED" "$_ROUND_WAIT_UNKNOWN" "${#PIDS[@]}" >"$BASE_DIR/owner-counts.tsv"
  exit "$status"
}
trap cleanup_control EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
NAT_SIM_TCP_OBSERVER=1
ARTIFACT_SET=$BASE_DIR/artifact-set.json
for side in a b; do
  mode=fast
  if [[ "$control" == stalled || "$control" == cancelled ]]; then mode=stall; fi
  if [[ "$control" == wrong_birth ]]; then mode=ok; fi
  python3 "$ROOT_DIR/scripts/nat-sim/launch_identity.py" exec --artifact-set "$ARTIFACT_SET" \
    --component daemon --role "node-$side" --record "$ROUND_DIR/launches/node-$side.json" \
    --process-birth -- "$mode" >"$BASE_DIR/server-$side.events" 2>"$BASE_DIR/server-$side.stderr" &
  child=$!
  round_register_process "node-$side" "$child"
  if [[ "$side" == a ]]; then NODE_A_PID=$child; else NODE_B_PID=$child; fi
done
read -r DIAG_A_PORT DIAG_B_PORT < <(python3 - "$BASE_DIR" <<'PY'
from pathlib import Path
import sys,time
root=Path(sys.argv[1]);end=time.monotonic()+2
while time.monotonic()<end:
    rows=[(root/f'server-{s}.events').read_text().splitlines() for s in 'ab']
    if all(r and r[0].startswith('ready ') for r in rows):
        print(*(r[0].split()[1] for r in rows));break
    time.sleep(.005)
else:raise SystemExit('fixture_ready_timeout')
PY
)
[[ "$DIAG_A_PORT" =~ ^[0-9]+$ && "$DIAG_B_PORT" =~ ^[0-9]+$ ]]
if [[ "$control" == missing_birth ]]; then rm "$ROUND_DIR/launches/node-a.json.birth"; fi
if [[ "$control" == wrong_birth ]]; then
  python3 - "$ROUND_DIR/launches/node-a.json.birth" <<'PY'
from pathlib import Path
import sys,json
p=Path(sys.argv[1]);v=json.loads(p.read_text());v['observation']['birth_seconds']+=1;p.write_text(json.dumps(v))
PY
fi
printf 'fixture-private-token\n' >"$BASE_DIR/token"
A_STATUS_SAMPLE_COUNT=0;B_STATUS_SAMPLE_COUNT=0;A_STATUS_200_COUNT=0;B_STATUS_200_COUNT=0
A_STATUS_SEEN_200=1;B_STATUS_SEEN_200=1;A_STATUS_ALWAYS_200=1;B_STATUS_ALWAYS_200=1
deadline_curl_timeout() { echo 2; }
source "$BASE_DIR/original-entry-functions.sh"
if [[ "$control" == cancelled ]]; then
  # Exercise forwarding while both actual servers still hold their clients;
  # otherwise stopping nodes first can finish curl via EOF before cancellation.
  trap 'stop_pid_group_bounded "$a_pid" "$b_pid"; exit 143' TERM
fi
sample_relay_status_pair "http://127.0.0.1:$DIAG_A_PORT/status" "$BASE_DIR/token" "$NODE_A_PID" \
                         "http://127.0.0.1:$DIAG_B_PORT/status" "$BASE_DIR/token" "$NODE_B_PID"
printf '%s\t%s\n' "$A_STATUS_ALWAYS_200" "$B_STATUS_ALWAYS_200" >"$BASE_DIR/http-verdict.tsv"
'''


@unittest.skipUnless(sys.platform == "darwin", "actual Darwin proc/FD ownership requires Darwin")
class NativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supplied = os.environ.get("P2WLAN_NAT_SIM_TCP_EVIDENCE_DIR")
        cls.temporary = None if supplied else tempfile.TemporaryDirectory(prefix="p2wlan-owned-tcp-")
        cls.directory = Path(supplied) if supplied else Path(cls.temporary.name)
        if supplied:
            cls.directory.mkdir(mode=0o700)
        cls.directory.chmod(0o700)
        cls.source = launch.source_identity(ROOT)
        (cls.directory / "server.c").write_text(SERVER)
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(cls.directory / "server.c"), "-o", str(cls.directory / "server")], check=True)
        cls.frozen = cls.directory / "frozen"
        cls.frozen.mkdir(mode=0o700)
        launch.prepare_artifacts(cls.frozen, {"daemon": cls.directory / "server"}, cls.source)
        # Explicit fixture preparation only, before the fixed readiness and
        # measurement controls. This is not a product cold-start measurement.
        before = monotonic_ns()
        probe = subprocess.run([str(cls.frozen / "artifacts/daemon"), "--probe"],
                               capture_output=True, timeout=8, check=True)
        if probe.stdout != b"fixture-image-ready\n":
            raise AssertionError("fixture image probe invalid")
        (cls.directory / "fixture-preparation.json").write_text(json.dumps({
            "started_monotonic_ns": before, "completed_monotonic_ns": monotonic_ns(),
            "fixture_only": True, "product_cold_start_measurement": False,
            "fixture_ready_bound_s": 2, "original_product_rounds": 0}))
        prepare_image(cls.frozen, cls.frozen / "artifact-set.json")
        cls.manifest, cls.image = image_from_manifest(cls.frozen / "tcp-observer/manifest.json", cls.source)
        if cls.image is None:
            raise AssertionError("actual native image unavailable")
        (cls.directory / "source-and-image.json").write_text(json.dumps(cls.manifest, indent=2))
        cls.env = {**os.environ, "PATH": str(Path(sys.executable).parent) + ":" + os.environ["PATH"]}

    @classmethod
    def tearDownClass(cls):
        if cls.temporary:
            cls.temporary.cleanup()

    def run_pair(self, control):
        base = self.directory / control
        base.mkdir(mode=0o700)
        launch.reuse_artifacts(base, self.frozen / "artifact-set.json", self.source, {"daemon"})
        prepare_image(base, base / "artifact-set.json", self.frozen / "tcp-observer/manifest.json")
        (base / "owner.sh").write_text(OWNER)
        (base / "original-entry-functions.sh").write_text("\n".join(function(n) for n in
            ["status_http_code", "record_relay_status_code", "sample_relay_status_pair"]))
        with (base / "owner.stdout").open("wb") as out, (base / "owner.stderr").open("wb") as err:
            process = subprocess.Popen(["/bin/bash", str(base / "owner.sh"), str(ROOT), str(base), control],
                                       stdout=out, stderr=err, env=self.env)
            try:
                if control == "cancelled":
                    end = time.monotonic() + 5
                    while time.monotonic() < end:
                        if all((base / f"server-{s}.events").exists() and "request" in
                               (base / f"server-{s}.events").read_text().splitlines() for s in "ab"):
                            break
                        if process.poll() is not None:
                            self.fail("owner exited before actual requests")
                        time.sleep(.005)
                    else:
                        self.fail("original requests not observed in control bound")
                    process.terminate()
                code = process.wait(timeout=12)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        self.assertEqual(code, 143 if control == "cancelled" else 0, (base / "owner.stderr").read_text())
        counts = (base / "owner-counts.tsv").read_text().strip().split("\t")
        expected = "2" if control == "missing_birth" else "6"
        self.assertEqual(counts, [expected, expected, "0", "0"])
        ledger = [line.split("\t") for line in (base / "owner-ledger.tsv").read_text().splitlines()]
        self.assertTrue(all(row[2] == "1" and row[4] == "0" for row in ledger), ledger)
        self.assertTrue(all((base / f"server-{s}.events").read_text().splitlines().count("request") == 1 for s in "ab"))
        if control == "missing_birth":
            self.assertTrue((base / "round-1/tcp-observer-unavailable").exists())
            self.assertEqual((base / "http-verdict.tsv").read_text().strip(), "1\t1")
            return
        roles = {row[0]: int(row[1]) for row in ledger}
        if control != "cancelled":
            self.assertTrue(all(row[3] == '0' for row in ledger
                                if row[0].startswith(('tcp-server-observer-', 'tcp-status-'))), ledger)
        for side in "ab":
            value = json.loads((base / f"round-1/tcp-observation/{side}-observation.json").read_text())
            self.assertEqual(value["main_Bash_pid"], process.pid)
            self.assertEqual(value["status_Bash_pid"], roles[f"tcp-status-{side}"])
            self.assertEqual(value["server_observer_pid"], roles[f"tcp-server-observer-{side}"])
            self.assertNotEqual(value["sampler_Python_pid"], value["status_Bash_pid"])
            self.assertEqual(len(value["owned_children"]), 2)
            self.assertTrue(all(v["wait_completed"] for v in value["owned_children"]))
            self.assertEqual(value["image_sha256"], self.manifest["image_sha256"])
            self.assertEqual(value["original_curl_executable"], self.manifest["curl"])
            if control == "cancelled":
                self.assertTrue(value["cancelled"])
                continue
            self.assertFalse(value["cancelled"])
            self.assertFalse(any(v["forced"] for v in value["owned_children"]))
            self.assertEqual(len(value["events"]), 13)
            points = [v for v in value["events"] if v["point"] == "client"]
            self.assertEqual([v["scheduled_offset_ms"] for v in points], [0, 25, 75, 125, 175])
            if control == "stalled":
                self.assertTrue(value["actual_curl_initial_identity_available"])
                self.assertTrue(all(v["usable"] and v["within_original_connect_window"] for v in points), points)
                self.assertTrue(any(r["tcp_state"] == 4 for v in points for r in v["response"]["rows"]))
                self.assertTrue(all(r["foreign_address"] == '127.0.0.1' for v in points
                                    for r in v["response"]["rows"]))
            if control == "wrong_birth" and side == "a":
                self.assertTrue(all(not v["usable"] and v["response"]["reason"] == "expected_birth_mismatch"
                                    for v in value["events"] if v["point"].startswith("server")))
        if control != "cancelled":
            records = [json.loads(s) for s in (base / "round-1/status-http-samples.log").read_text().splitlines()]
            self.assertEqual(len(records), 2)
            for row in records:
                self.assertNotIn("fixture-private-token", json.dumps(row))
                self.assertEqual(row["http_status"], "000" if control == "stalled" else "200")
                self.assertEqual(row["curl_exit_code"], 28 if control == "stalled" else 0)
            self.assertFalse(any((base / "round-1").glob(".status-*-headers")))

    def test_actual_concurrent_fast_HTTP_and_normal_join(self):
        self.run_pair("fast")

    def test_actual_concurrent_connected_no_response_and_five_points(self):
        self.run_pair("stalled")

    def test_actual_missing_original_birth_preserves_original_HTTP(self):
        self.run_pair("missing_birth")

    def test_actual_wrong_birth_is_unavailable_and_HTTP_stays_original(self):
        self.run_pair("wrong_birth")

    def test_actual_cancel_joins_both_sampler_children(self):
        self.run_pair("cancelled")

    def test_actual_native_wrong_owner_FD_capacity_and_identity_scope(self):
        with subprocess.Popen([str(self.image)], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
            channel = Channel(child.stdout.fileno(), child.stdin.fileno(), monotonic_ns() + 3_000_000_000, lambda: False)
            descriptors = []
            try:
                channel.ready(os.getpid(), child.pid)
                identity = channel.query("identity", os.getpid(), 1)
                self.assertTrue(identity["usable"])
                value = identity["response"]
                self.assertFalse(value["socket_observation"])
                birth = value["birth_seconds"], value["birth_microseconds"]
                wrong = channel.query("sample", os.getpid(), 1, (birth[0] + 1, birth[1]))
                self.assertEqual(wrong["response"]["reason"], "expected_birth_mismatch")
                foreign = channel.query("sample", os.getppid(), 1, birth)
                self.assertEqual(foreign["response"]["reason"], "not_owned_parent_or_child")
                descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(130)]
                capacity = channel.query("sample", os.getpid(), 1, birth)
                self.assertFalse(capacity["usable"])
                self.assertEqual(capacity["response"]["reason"], "fd_capacity")
                channel.quit()
                self.assertEqual(child.wait(timeout=1), 0)
            finally:
                for fd in descriptors:
                    os.close(fd)
                channel.close()

    def test_actual_native_overflow_rejected_and_EOF_exits(self):
        bad = subprocess.run([str(self.image)], input=b"sample 1 999999999999999999999999999999 1 1 0\n",
                             capture_output=True, timeout=2)
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(json.loads(bad.stdout.splitlines()[1])["reason"], "command_arguments")
        eof = subprocess.run([str(self.image)], input=b"", capture_output=True, timeout=2)
        self.assertEqual(eof.returncode, 0)
        self.assertEqual(json.loads(eof.stdout)["event"], "ready")
        capacity = subprocess.run([str(self.image)], input=b"sample " + b"9" * 128 + b"\n",
                                  capture_output=True, timeout=2)
        self.assertEqual(capacity.returncode, 1)
        self.assertEqual(json.loads(capacity.stdout.splitlines()[1])["reason"], "command_capacity")
        commands = ''.join(f'identity {i} {os.getpid()} 1\n' for i in range(1, 8))
        limit = subprocess.run([str(self.image)], input=(commands + f'identity 8 {os.getpid()} 1\n').encode(),
                               capture_output=True, timeout=2)
        self.assertEqual(limit.returncode, 1)
        values = [json.loads(line) for line in limit.stdout.splitlines()]
        self.assertEqual(len(values), 9)
        self.assertTrue(all(v['valid'] for v in values[1:8]))
        self.assertEqual(values[-1]['reason'], 'command_limit')


if __name__ == "__main__":
    unittest.main()
