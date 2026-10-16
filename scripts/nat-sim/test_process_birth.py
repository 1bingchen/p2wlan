"""Original-exec fences, fail-closed evidence and actual Darwin SDK/exec ABI."""
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import launch_identity as launch
import process_birth as birth
from test_launch_identity import ExecObserved, SOURCE, write_valid_launch_evidence

HERE = Path(__file__).resolve().parent


class ProcessBirthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.fixture = self.base/'fixture'
        self.fixture.write_text('#!/bin/sh\nexit 0\n')
        self.fixture.chmod(0o700)
        launch.prepare_artifacts(self.base, {'daemon':self.fixture}, SOURCE)
        self.directory = self.base/'round-1/launches'
        self.directory.mkdir(parents=True, mode=0o700)
        self.record = self.directory/'node-a.json'
        self.observation = {'state':'available', 'platform':'darwin', 'pid':os.getpid(),
            'ppid':os.getppid(), 'uid':os.getuid(), 'birth_seconds':123456,
            'birth_microseconds':123, 'started_monotonic_ns':1, 'completed_monotonic_ns':2}

    def emit(self, enabled=True, observation=None, error=None):
        failure = error if error is not None else ExecObserved()
        with patch.object(birth, 'capture_self', return_value=observation or self.observation) as capture, \
                patch.object(launch.os, 'execve', side_effect=failure) as execute:
            with self.assertRaises(type(failure)):
                launch.exec_launch(self.base/'artifact-set.json', 'daemon', self.record,
                                   'node-a', ['--token-stdin'], [], stdin_authorization=True,
                                   process_birth=enabled)
        return capture, execute

    def read(self):
        return launch.read_bound_process_birth(self.record, SOURCE, 'node-a')

    def test_default_does_not_capture_or_write_and_preserves_original_record_schema(self):
        capture, execute = self.emit(enabled=False)
        capture.assert_not_called()
        self.assertFalse(birth.sidecar_path(self.record).exists())
        value = json.loads(self.record.read_text())
        launch.validate_record(value, SOURCE)
        self.assertEqual(set(value), {'schema_version','source','role','component','state','pid',
            'monotonic_ns','artifact_set_sha256','artifact','configuration'})
        self.assertEqual(execute.call_args.args[1][1:], ['--token-stdin'])

    def test_sidecar_is_private_bounded_and_bound_to_original_bytes_not_collected_as_launch(self):
        self.emit()
        value = self.read()
        self.assertEqual(value['observation'], self.observation)
        self.assertEqual(value['launch_record_sha256'], launch.digest_file(self.record))
        self.assertEqual(stat.S_IMODE(birth.sidecar_path(self.record).stat().st_mode), 0o600)
        self.assertLess(birth.sidecar_path(self.record).stat().st_size, birth.MAX_BYTES)
        self.assertEqual(list(self.directory.glob('*.json')), [self.record])
        summary = launch.read_launch_evidence(self.base, SOURCE, ['node-a'])
        self.assertTrue(summary['valid'], summary)
        self.assertNotIn('token', json.dumps(value))

    def test_failed_original_exec_invalidates_pre_exec_fence(self):
        self.emit(error=OSError(8, 'synthetic exec failure'))
        self.assertEqual(json.loads(self.record.read_text())['state'], 'exec_failed')
        with self.assertRaisesRegex(ValueError, 'original_exec_failed'):
            self.read()

    def test_unknown_platform_is_typed_unavailable_without_preventing_original_exec(self):
        self.emit(observation={'state':'unavailable','reason':'unsupported_platform'})
        self.assertEqual(self.read()['observation']['reason'], 'unsupported_platform')
        with patch.object(birth.sys, 'platform', 'unsupported-test-platform'):
            self.assertEqual(birth.capture_self(), {'state':'unavailable','reason':'unsupported_platform'})

    def test_sidecar_write_failure_does_not_prevent_exec_or_rewrite_existing_evidence(self):
        sidecar = birth.sidecar_path(self.record)
        sidecar.write_bytes(b'original evidence')
        sidecar.chmod(0o600)
        with patch('sys.stderr'):
            _, execute = self.emit()
        execute.assert_called_once()
        self.assertEqual(sidecar.read_bytes(), b'original evidence')

    def test_source_role_record_and_pid_rebinding_are_rejected(self):
        self.emit()
        with self.assertRaises(ValueError):
            launch.read_bound_process_birth(self.record, {**SOURCE,'commit':'c'*40}, 'node-a')
        with self.assertRaises(ValueError):
            launch.read_bound_process_birth(self.record, SOURCE, 'node-b')
        original = self.record.read_bytes()
        record = json.loads(original)
        # A later launch cannot reuse the old birth fence, even with the same
        # numeric PID. This is not a forced kernel PID-reuse experiment.
        record['monotonic_ns'] += 1
        self.record.write_bytes(launch.canonical(record)+b'\n')
        with self.assertRaisesRegex(ValueError, 'binding_mismatch'):
            self.read()
        self.record.write_bytes(original)
        value = json.loads(birth.sidecar_path(self.record).read_text())
        value['pid'] += 1
        birth.sidecar_path(self.record).write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'binding_mismatch'):
            self.read()

    def test_missing_removed_symlink_world_readable_oversize_and_malformed_fences_rejected(self):
        self.emit()
        sidecar = birth.sidecar_path(self.record)
        original = sidecar.read_bytes()
        sidecar.unlink()
        with self.assertRaises(OSError):
            self.read()
        sidecar.symlink_to(self.record)
        with self.assertRaises(OSError):
            self.read()
        sidecar.unlink()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(sidecar, 0o600)
            with self.assertRaisesRegex(ValueError, 'regular'):
                self.read()
            sidecar.unlink()
        sidecar.write_bytes(original)
        sidecar.chmod(0o644)
        with self.assertRaises(ValueError):
            self.read()
        sidecar.chmod(0o600)
        sidecar.write_bytes(b'x'*(birth.MAX_BYTES+1))
        with self.assertRaises(ValueError):
            self.read()
        sidecar.write_bytes(original)
        original_value = json.loads(original)
        bad = [dict(original_value, unexpected=True), dict(original_value, schema_version=True)]
        for key, value in [('pid',True), ('birth_microseconds',1_000_000),
                           ('completed_monotonic_ns',0), ('platform','linux')]:
            candidate = copy.deepcopy(original_value)
            candidate['observation'][key] = value
            bad.append(candidate)
        candidate = copy.deepcopy(original_value)
        candidate['observation'] = {'state':'unavailable','reason':[]}
        bad.append(candidate)
        for candidate in bad:
            with self.subTest(candidate=candidate):
                sidecar.write_text(json.dumps(candidate))
                with self.assertRaises(ValueError):
                    self.read()

    def test_private_sidecars_do_not_relax_original_four_role_launch_collection(self):
        root = self.base/'four-roles'
        launch_summary = write_valid_launch_evidence(root)
        self.assertTrue(launch_summary['valid'])
        for item in launch_summary['records']:
            p = root/item['path']
            with patch.object(birth, 'capture_self', return_value=self.observation):
                birth.write_pre_exec(p, item['record'])
        actual = launch.read_launch_evidence(root, SOURCE)
        self.assertTrue(actual['valid'], actual)
        self.assertEqual(len(actual['records']), 4)


NATIVE_FIXTURE = r'''
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <time.h>
#include <unistd.h>
int main(void) {
    struct proc_bsdinfo b;
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &b, sizeof(b)) != (int)sizeof(b)) return 2;
    char input[64];
    if (!fgets(input, sizeof(input), stdin)) return 3;
    printf("{\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"birth_seconds\":%llu,\"birth_microseconds\":%llu,"
           "\"completed_monotonic_ns\":%llu,\"stdin_unchanged\":%s,\"size\":%zu,"
           "\"offsets\":[%zu,%zu,%zu,%zu,%zu,%zu,%zu]}\n", b.pbi_pid, b.pbi_ppid, b.pbi_uid,
           b.pbi_start_tvsec, b.pbi_start_tvusec, clock_gettime_nsec_np(CLOCK_UPTIME_RAW),
           !strcmp(input, "synthetic-original-stdin\n") ? "true" : "false", sizeof(b),
           offsetof(struct proc_bsdinfo, pbi_pid), offsetof(struct proc_bsdinfo, pbi_ppid),
           offsetof(struct proc_bsdinfo, pbi_uid), offsetof(struct proc_bsdinfo, pbi_nfiles),
           offsetof(struct proc_bsdinfo, pbi_nice), offsetof(struct proc_bsdinfo, pbi_start_tvsec),
           offsetof(struct proc_bsdinfo, pbi_start_tvusec));
    return 0;
}
'''


@unittest.skipUnless(sys.platform == 'darwin', 'Darwin SDK/exec boundary requires Darwin')
class NativeProcessBirthTests(unittest.TestCase):
    def test_system_python_original_exec_matches_native_sdk_birth_and_preserves_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            c = base/'native-birth.c'
            c.write_text(NATIVE_FIXTURE)
            program = base/'native-birth'
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',str(c),'-lproc','-o',str(program)],
                           check=True, capture_output=True, timeout=30)
            program.chmod(0o500)
            source = launch.source_identity(HERE.parents[1])
            launch.prepare_artifacts(base, {'daemon':program}, source)
            records = base/'round-1/launches'
            records.mkdir(parents=True, mode=0o700)
            record = records/'node-a.json'
            command = ['/usr/bin/python3', str(HERE/'launch_identity.py'), 'exec',
                '--artifact-set',str(base/'artifact-set.json'),'--component','daemon','--role','node-a',
                '--record',str(record),'--stdin-authorization','--process-birth','--']
            with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as process:
                try:
                    out, err = process.communicate(b'synthetic-original-stdin\n', timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    out, err = process.communicate(timeout=2)
                actual_pid = process.pid
            evidence = os.environ.get('P2WLAN_NAT_SIM_BIRTH_EVIDENCE_DIR')
            if evidence:
                output = Path(evidence)
                output.mkdir(parents=True, exist_ok=False, mode=0o700)
                members = {'native-birth.c':c, 'actual-native-birth':program,
                    'original-launch.json':record, 'original-launch.birth':birth.sidecar_path(record),
                    'artifact-set.json':base/'artifact-set.json'}
                hashes = {}
                for name, path in members.items():
                    if not path.exists():
                        continue
                    shutil.copyfile(path, output/name)
                    (output/name).chmod(0o600)
                    hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
                (output/'actual-native.stdout').write_bytes(out)
                (output/'actual-native.stderr').write_bytes(err)
                (output/'VERIFIED.json').write_text(json.dumps({'scope':'native C fixture pre/post original exec, not Rust daemon or TCP snapshot',
                    'source':source, 'actual_pid':actual_pid,
                    'native_result':None, 'qualified':False,
                    'original_launch_sha256':launch.digest_file(record) if record.exists() else None, 'artifacts_sha256':hashes}, indent=2)+'\n')
            self.assertEqual(process.returncode, 0, err)
            self.assertEqual(launch.source_identity(HERE.parents[1]), source)
            result = json.loads(out)
            sidecar = launch.read_bound_process_birth(record, source, 'node-a')
            observation = sidecar['observation']
            self.assertEqual(observation['state'], 'available', observation)
            self.assertEqual(result['pid'], actual_pid)
            for key in ('pid','ppid','uid','birth_seconds','birth_microseconds'):
                self.assertEqual(result[key], observation[key], key)
            self.assertEqual(result['ppid'], os.getpid())
            self.assertTrue(result['stdin_unchanged'])
            self.assertLessEqual(observation['completed_monotonic_ns'], result['completed_monotonic_ns'])
            self.assertEqual(result['size'], ctypes.sizeof(birth.DarwinBSDInfo))
            self.assertEqual(result['offsets'], [getattr(birth.DarwinBSDInfo, key).offset for key in
                ('pid','ppid','uid','nfiles','nice','birth_seconds','birth_microseconds')])
            if evidence:
                saved = json.loads((output/'VERIFIED.json').read_text())
                saved.update(native_result=result, qualified=True, same_pid_and_birth=True, stdin_preserved=True)
                (output/'VERIFIED.json').write_text(json.dumps(saved, indent=2)+'\n')



if __name__ == '__main__':
    unittest.main()
