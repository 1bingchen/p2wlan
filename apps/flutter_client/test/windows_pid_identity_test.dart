import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/daemon/windows_process.dart';

void main() {
  test('startup accepts only the launched live daemon identity', () {
    const daemon = WindowsProcessProbe.running(
      r'C:\Program Files\P2WLAN\p2wlan-daemon.exe',
    );
    expect(
      classifyWindowsChildIdentity(
        process: daemon,
        pid: 4242,
        launchedProcessId: 4242,
      ),
      isNull,
    );
    for (final process in [
      const WindowsProcessProbe.running(r'C:\Windows\powershell.exe'),
      const WindowsProcessProbe.unavailable('open_process', 5),
      const WindowsProcessProbe.unavailable('image_name', 31),
    ]) {
      expect(
        classifyWindowsChildIdentity(
          process: process,
          pid: 4242,
          launchedProcessId: 4242,
        )?.code,
        DaemonStartupFailureCode.pidMarkerFailed,
      );
    }
    expect(
      classifyWindowsChildIdentity(
        process: daemon,
        pid: 4242,
        launchedProcessId: 9999,
      )?.code,
      DaemonStartupFailureCode.pidMarkerFailed,
    );
  });

  test('early child exit is not reported as a PID marker failure', () {
    for (final process in [
      const WindowsProcessProbe.exited(),
      const WindowsProcessProbe.exited(1),
      const WindowsProcessProbe.exited(0xc0000135),
    ]) {
      expect(
        classifyWindowsChildIdentity(
          process: process,
          pid: 4242,
          launchedProcessId: 4242,
        )?.code,
        DaemonStartupFailureCode.daemonExitedDuringStartup,
      );
    }
  });

  test('unavailable native queries can recover within the handoff', () async {
    var calls = 0;
    final result = await waitForWindowsProcess(
      4242,
      query: (pid) {
        expect(pid, 4242);
        calls += 1;
        return calls == 1
            ? const WindowsProcessProbe.unavailable('image_name', 31)
            : const WindowsProcessProbe.running(r'C:\P2WLAN\p2wlan-daemon.exe');
      },
      pollInterval: Duration.zero,
    );
    expect(result.state, WindowsProcessState.running);
    expect(calls, 2);
  });

  test(
    'query deadline preserves access denial without a final extra probe',
    () async {
      var calls = 0;
      final result = await waitForWindowsProcess(
        4242,
        query: (_) {
          calls += 1;
          return const WindowsProcessProbe.unavailable('open_process', 5);
        },
        timeout: Duration.zero,
      );
      expect(calls, 1);
      expect(result.state, WindowsProcessState.unavailable);
      expect(result.operation, 'open_process');
      expect(result.win32Error, 5);
    },
  );

  test('confirmed exit and wrong image never wait for a reused PID', () async {
    for (final observed in [
      const WindowsProcessProbe.exited(1),
      const WindowsProcessProbe.running(r'C:\Windows\other.exe'),
    ]) {
      var calls = 0;
      final result = await waitForWindowsProcess(
        4242,
        query: (_) {
          calls += 1;
          return observed;
        },
      );
      expect(result, same(observed));
      expect(calls, 1);
    }
  });

  test('native image paths preserve Unicode and the exact executable name', () {
    const process = WindowsProcessProbe.running(
      r'C:\应用程序\P2WLAN 客户端\P2WLAN-DAEMON.EXE',
    );
    expect(process.processName, 'P2WLAN-DAEMON.EXE');
    expect(
      classifyWindowsChildIdentity(
        process: process,
        pid: 4242,
        launchedProcessId: 4242,
      ),
      isNull,
    );
  });

  test('trusted Windows daemon identity is limited to sourced PIDs', () {
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: 4242,
        authenticatedProcessId: null,
        processName: 'p2wlan-daemon.exe',
      ),
      isTrue,
    );
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: null,
        authenticatedProcessId: 4242,
        processName: 'P2WLAN-DAEMON.EXE',
      ),
      isTrue,
    );
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: 1000,
        authenticatedProcessId: 2000,
        processName: 'p2wlan-daemon.exe',
      ),
      isFalse,
    );
    expect(
      trustedWindowsDaemonIdentityMatches(
        pid: 4242,
        launchedProcessId: 4242,
        authenticatedProcessId: null,
        processName: 'powershell.exe',
      ),
      isFalse,
    );
  });

  test('Windows PowerShell helper preserves Unicode output', () async {
    final api = DiagnosticsApi(authTokenReader: () async => null);
    addTearDown(api.close);
    final controller = DaemonController(diagnosticsApi: api);
    final result = await controller.runWindowsPowerShellForTesting(
      "Write-Output 'P2WLAN-中文路径-✓'",
    );
    expect(result.exitCode, 0, reason: result.stderr.toString());
    expect(result.stdout.toString().trim(), 'P2WLAN-中文路径-✓');
  }, skip: !Platform.isWindows);

  test('trusted fresh child resolves identity through Win32', () async {
    final api = DiagnosticsApi(authTokenReader: () async => null);
    addTearDown(api.close);
    final controller = DaemonController(diagnosticsApi: api);
    final windir = Platform.environment['WINDIR']?.trim();
    final powershell = windir == null || windir.isEmpty
        ? 'powershell.exe'
        : '$windir\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    final child = await Process.start(powershell, [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      'Start-Sleep -Seconds 30',
    ], mode: ProcessStartMode.normal);
    try {
      final probe = queryWindowsProcess(child.pid);
      expect(probe.state, WindowsProcessState.running);
      expect(probe.processName?.toLowerCase(), 'powershell.exe');
      final name = await controller.windowsProcessNameForTesting(child.pid);
      expect(name?.toLowerCase(), 'powershell.exe');
    } finally {
      child.kill(ProcessSignal.sigkill);
      await child.exitCode.timeout(
        const Duration(seconds: 10),
        onTimeout: () => -1,
      );
    }
  }, skip: !Platform.isWindows);

  test('Win32 reports a terminated child as exited', () async {
    final windir = Platform.environment['WINDIR']!;
    final child = await Process.start('$windir\\System32\\cmd.exe', [
      '/d',
      '/q',
      '/c',
      'exit 7',
    ]);
    await child.stdout.drain<void>();
    await child.stderr.drain<void>();
    expect(await child.exitCode, 7);
    expect(queryWindowsProcess(child.pid).state, WindowsProcessState.exited);
  }, skip: !Platform.isWindows);

  test('Win32 identifies a daemon image in a Unicode path', () async {
    final root = await Directory.systemTemp.createTemp('p2wlan identity 中文 ');
    addTearDown(() => root.delete(recursive: true));
    final windir = Platform.environment['WINDIR']!;
    final executable = await File('$windir\\System32\\cmd.exe')
        .copy('${root.path}\\p2wlan-daemon.exe');
    // The built-in command waits on this test's stdin, without launching a
    // descendant or relying on a sleep to keep the identity fixture alive.
    final child = await Process.start(executable.path, [
      '/d',
      '/q',
      '/c',
      'set /p p2wlan_identity_fixture=',
    ]);
    final stdout = child.stdout.drain<void>();
    final stderr = child.stderr.drain<void>();
    try {
      final process = await waitForWindowsProcess(child.pid);
      expect(process.state, WindowsProcessState.running);
      expect(process.imagePath, contains('中文'));
      expect(
        classifyWindowsChildIdentity(
          process: process,
          pid: child.pid,
          launchedProcessId: child.pid,
        ),
        isNull,
      );
    } finally {
      child.stdin.writeln('done');
      await child.stdin.close();
      await child.exitCode.timeout(
        const Duration(seconds: 5),
        onTimeout: () {
          child.kill(ProcessSignal.sigkill);
          return child.exitCode;
        },
      );
      await Future.wait([stdout, stderr]);
    }
  }, skip: !Platform.isWindows);
}
