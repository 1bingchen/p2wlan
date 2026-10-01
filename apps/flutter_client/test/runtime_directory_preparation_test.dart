import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';

void main() {
  final directory = Directory('/runtime');
  const denied = PosixLaunchPathProtectionException(
    directory: true,
    exitCode: 1,
  );

  test(
    'permission recovery verifies user access after one elevation',
    () async {
      final events = <String>[];
      var protected = false;
      final preparer = RuntimeDirectoryPreparer(
        protect: (_) async {
          events.add('protect');
          if (!protected) throw denied;
        },
        repair: (_) async {
          events.add('repair');
          protected = true;
        },
      );
      await preparer.prepare(directory);
      expect(events, ['protect', 'repair', 'protect']);
    },
  );

  test('an accessible runtime never needs elevated recovery', () async {
    var repairs = 0;
    final preparer = RuntimeDirectoryPreparer(
      protect: (_) async {},
      repair: (_) async {
        repairs++;
      },
    );
    await preparer.prepare(directory);
    expect(repairs, 0);
  });

  test('failed verification stops after one recovery attempt', () async {
    var repairs = 0;
    var checks = 0;
    final preparer = RuntimeDirectoryPreparer(
      protect: (_) async {
        checks++;
        throw denied;
      },
      repair: (_) async {
        repairs++;
      },
    );
    await expectLater(preparer.prepare(directory), throwsA(same(denied)));
    expect(repairs, 1);
    expect(checks, 2);
  });

  test('a failed repair never proceeds to a second access check', () async {
    const rejected = RuntimeDirectoryRepairException();
    var checks = 0;
    final preparer = RuntimeDirectoryPreparer(
      protect: (_) async {
        checks++;
        throw denied;
      },
      repair: (_) async {
        throw rejected;
      },
    );
    await expectLater(preparer.prepare(directory), throwsA(same(rejected)));
    expect(checks, 1);
  });

  test(
    'unsafe paths and unrelated IO failures never request elevation',
    () async {
      for (final error in [
        const UnsafeLaunchPathException(),
        const FileSystemException('missing path', '', OSError('', 2)),
      ]) {
        var repairs = 0;
        final preparer = RuntimeDirectoryPreparer(
          protect: (_) async {
            throw error;
          },
          repair: (_) async {
            repairs++;
          },
        );
        await expectLater(preparer.prepare(directory), throwsA(same(error)));
        expect(repairs, 0);
      }
    },
  );

  test('file IO permission codes are distinct from other startup failures', () {
    for (final code in [1, 13]) {
      expect(
        isPosixRuntimePermissionFailure(
          FileSystemException('denied', '', OSError('', code)),
        ),
        isTrue,
      );
    }
    expect(
      isPosixRuntimePermissionFailure(
        const FileSystemException('missing', '', OSError('', 2)),
      ),
      isFalse,
    );
  });

  test(
    'without an elevation boundary permission errors remain failures',
    () async {
      final preparer = RuntimeDirectoryPreparer(
        protect: (_) async {
          throw denied;
        },
        repair: null,
      );
      await expectLater(preparer.prepare(directory), throwsA(same(denied)));
    },
  );

  test('a runtime symlink is rejected before creating any token', () async {
    if (Platform.isWindows) return;
    final temp = await Directory.systemTemp.createTemp('p2wlan-runtime-path-');
    addTearDown(() => temp.delete(recursive: true));
    final target = await Directory('${temp.path}/target').create();
    final linked = Directory('${temp.path}/runtime');
    await Link(linked.path).create(target.path);
    final api = DiagnosticsApi();
    addTearDown(api.close);
    final controller = DaemonController(diagnosticsApi: api);
    await expectLater(
      controller.createEphemeralLaunchTokenFile(linked, 'local-test-secret'),
      throwsA(isA<UnsafeLaunchPathException>()),
    );
    expect(await target.list().toList(), isEmpty);
  });

  test('short lived runtime preparation is never a daemon identity', () {
    expect(
      isP2wlanDaemonRuntimeCommandLine(
        '/opt/p2wlan/p2wlan-daemon --prepare-runtime-directory /runtime',
      ),
      isFalse,
    );
  });
}
