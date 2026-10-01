import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/session_log_bundle.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/session_log_capture.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/support_log_protocol.dart';

void main() {
  test('legacy logs never include unverified rotated files', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_session_logs_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    final client = File('${directory.path}/p2wlan-client.log');
    await daemon.writeAsString('Bearer live-token\nprobe ok\n');
    await client.writeAsString('startup ok\n');
    await File('${daemon.path}.1').writeAsString('old startup\n');

    final bundle = await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: client.path,
    );

    expect(bundle.files.map((file) => file.name), [
      'p2wlan-daemon.log',
      'p2wlan-client.log',
    ]);
    expect(bundle.files.first.content, contains('Bearer <redacted>'));
    expect(bundle.files.first.content, isNot(contains('live-token')));
    expect(bundle.files.first.content, isNot(contains('old startup')));
  });

  test(
    'retains startup head and latest tail with explicit bounded gaps',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'p2wlan_log_head_tail_',
      );
      addTearDown(() => directory.delete(recursive: true));
      final daemon = File('${directory.path}/p2wlan-daemon.log');
      await daemon.writeAsString(
        'startup first event\n${'middle event\n' * 500}latest event\n',
      );
      final bundle = await CurrentSessionLogBundle.collect(
        daemonLogPath: daemon.path,
        clientLogPath: '${directory.path}/missing-client.log',
        maxBytesPerFile: 2048,
      );
      final content = bundle.files.single.content;
      expect(content, contains('startup first event'));
      expect(content, contains('latest event'));
      expect(content, contains('[p2wlan-log-gap]'));
      expect(utf8.encode(content).length, lessThanOrEqualTo(2048));
      final coverage = _coverage(content);
      expect(coverage['scope'], 'legacy_current_file');
      expect(coverage['archive'], 'marker_missing');
      expect(coverage['omitted_bytes'], greaterThan(0));
    },
  );

  test('joins only consecutive archive segments of the same runtime', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_log_segments_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    final previous = File('${daemon.path}.1');
    final currentText = '${_marker('a', 1)}current latest\n';
    final previousText = '${_marker('a', 0)}initial handshake\n';
    await daemon.writeAsString(currentText);
    await previous.writeAsString(previousText);
    Future<String> collect() async => (await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: '${directory.path}/missing-client.log',
    )).files.single.content;

    final joined = await collect();
    expect(joined, contains('initial handshake'));
    expect(joined, contains('current latest'));
    expect(joined, isNot(contains('[p2wlan-log-gap]')));
    expect(_coverage(joined)['archive'], 'same_runtime_consecutive');
    expect(_coverage(joined)['startup_retained'], true);
    expect(_coverage(joined)['omitted_bytes'], 0);

    await previous.writeAsString(
      '${_marker('b', 0)}prior daemon private data\n',
    );
    final restarted = await collect();
    expect(restarted, isNot(contains('prior daemon private data')));
    expect(_coverage(restarted)['archive'], 'identity_mismatch');
    expect(_coverage(restarted)['startup_retained'], false);

    await previous.writeAsString('${_marker('a', 1)}duplicate segment\n');
    expect(await collect(), isNot(contains('duplicate segment')));
    await previous.writeAsString('old unmarked daemon\n');
    expect(await collect(), isNot(contains('old unmarked daemon')));
  });

  test('shared archive budget keeps whole UTF-8 records and identifies missing startup', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_log_budget_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    await daemon.writeAsString('${_marker('c', 7)}${'最近事件\n' * 400}latest\n');
    await File('${daemon.path}.1').writeAsString(
      '${_marker('c', 6)}earliest retained event\n${'很长事件\n' * 400}',
    );
    final content = (await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: '${directory.path}/missing-client.log',
      maxBytesPerFile: 2048,
    )).files.single.content;
    expect(content, contains('earliest retained event'));
    expect(content, contains('latest'));
    expect(content, isNot(contains('�')));
    expect(utf8.encode(content).length, lessThanOrEqualTo(2048));
    expect(_coverage(content)['older_segments_unavailable'], true);
    expect(_coverage(content)['startup_retained'], false);
    expect(_coverage(content)['captured_bytes'], lessThanOrEqualTo(1024));
  });

  test(
    'recovers startup through at most four verified archive segments',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'p2wlan_log_chain_',
      );
      addTearDown(() => directory.delete(recursive: true));
      final daemon = File('${directory.path}/p2wlan-daemon.log');
      await daemon.writeAsString('${_marker('d', 4)}latest\n');
      for (var number = 1; number <= 4; number++) {
        await File(
          '${daemon.path}.$number',
        ).writeAsString('${_marker('d', 4 - number)}segment ${4 - number}\n');
      }
      await File('${daemon.path}.5')
          .writeAsString('outside retention budget\n');
      Future<String> collect() async => (await CurrentSessionLogBundle.collect(
        daemonLogPath: daemon.path,
        clientLogPath: '${directory.path}/missing-client.log',
      )).files.single.content;
      final full = await collect();
      expect(full, contains('segment 0'));
      expect(full, isNot(contains('outside retention budget')));
      expect(_coverage(full)['segments_retained'], 5);
      expect(_coverage(full)['startup_retained'], true);
      await File('${daemon.path}.2')
          .writeAsString('${_marker('e', 2)}other runtime\n');
      final interrupted = await collect();
      expect(interrupted, contains('segment 3'));
      expect(interrupted, isNot(contains('segment 0')));
      expect(interrupted, isNot(contains('other runtime')));
      expect(_coverage(interrupted)['archive_stop'], 'identity_mismatch');
      expect(_coverage(interrupted)['startup_retained'], false);
    },
  );

  test('retries a runtime replaced while its old descriptor is open', () async {
    final directory = await Directory.systemTemp.createTemp('p2wlan_log_race_');
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    await daemon.writeAsString(
      '${_marker('a', 0)}previous runtime secret context\n',
    );
    final rotating = _ReplaceAfterOpenFile(daemon, () async {
      await daemon.rename('${daemon.path}.1');
      await daemon.writeAsString('${_marker('b', 0)}replacement runtime\n');
    });
    final content = await readCurrentRuntimeLog(rotating, 2048);
    expect(content, contains('replacement runtime'));
    expect(content, isNot(contains('previous runtime secret context')));
    expect(_coverage(content)['segments_retained'], 1);
    expect(_coverage(content)['startup_retained'], true);
  });

  test(
    'rotation keeps the sampled descriptor and rejects duplicate archives',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'p2wlan_log_rotate_race_',
      );
      addTearDown(() => directory.delete(recursive: true));
      final daemon = File('${directory.path}/p2wlan-daemon.log');
      await daemon.writeAsString('${_marker('a', 1)}sampled event\n');
      final rotating = _ReplaceAfterOpenFile(daemon, () async {
        await daemon.rename('${daemon.path}.1');
        await daemon.writeAsString('${_marker('a', 2)}after snapshot\n');
      });
      final content = await readCurrentRuntimeLog(rotating, 2048);
      expect('sampled event'.allMatches(content), hasLength(1));
      expect(content, isNot(contains('after snapshot')));
      expect(_coverage(content)['rotated_during_read'], true);
      expect(_coverage(content)['archive'], 'identity_mismatch');
    },
  );

  test('redacts nested credentials while preserving valid JSON', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_session_logs_nested_secrets_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    final client = File('${directory.path}/p2wlan-client.log');
    await daemon.writeAsString(
      '${jsonEncode({
        'Authorization': 'Bearer auth-secret',
        'nested': [
          {'access_token': 'access-secret', 'refresh_token': 'refresh-secret', 'password': 'password-secret', 'secret': 'secret-value', 'api-key': 'api-secret'},
        ],
      })}\n',
    );
    await client.writeAsString('startup ok\n');

    final bundle = await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: client.path,
    );

    final content = bundle.files.first.content.trim();
    final decoded =
        jsonDecode(content.split('\n').last) as Map<String, dynamic>;
    final nested =
        (decoded['nested'] as List<dynamic>).single as Map<String, dynamic>;
    expect(decoded['Authorization'], '<redacted>');
    expect(nested.values, everyElement('<redacted>'));
    for (final rawSecret in const [
      'auth-secret',
      'access-secret',
      'refresh-secret',
      'password-secret',
      'secret-value',
      'api-secret',
    ]) {
      expect(content, isNot(contains(rawSecret)));
    }
    expect(content, contains('<redacted>'));
  });

  test('collects room instance logs and redacts sensitive data', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_session_logs_room_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    final client = File('${directory.path}/p2wlan-client.log');
    await daemon.writeAsString('daemon ok\n');
    await client.writeAsString('client ok\n');

    final roomDir = Directory(
      '${directory.path}/rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    );
    await roomDir.create(recursive: true);
    final roomLog = File('${roomDir.path}/p2wlan-daemon.log');
    final roomSummary = File('${roomDir.path}/status-summary.json');
    await roomLog.writeAsString('room daemon token=super-secret-key\n');
    await roomSummary.writeAsString(
      '{"network_id":"room-1","token":"auth-secret"}\n',
    );

    final bundle = await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: client.path,
      extraFiles: [
        (
          name: 'rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/p2wlan-daemon.log',
          path: roomLog.path,
        ),
        (
          name: 'rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/status-summary.json',
          path: roomSummary.path,
        ),
      ],
    );

    expect(bundle.files.length, 4);
    expect(bundle.files.map((f) => f.name), [
      'p2wlan-daemon.log',
      'p2wlan-client.log',
      'rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/p2wlan-daemon.log',
      'rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/status-summary.json',
    ]);

    final collectedRoomLog = bundle.files.firstWhere(
      (f) => f.name.contains('rooms/') && f.name.endsWith('.log'),
    );
    expect(collectedRoomLog.content, contains('token=<redacted>'));
    expect(collectedRoomLog.content, isNot(contains('super-secret-key')));

    final collectedSummary = bundle.files.firstWhere(
      (f) => f.name.endsWith('.json'),
    );
    expect(jsonDecode(collectedSummary.content)['support_summary_version'], 1);
    expect(collectedSummary.content, isNot(contains('auth-secret')));
    expect(collectedSummary.content, isNot(contains('room-1')));
  });

  test(
    'collects logs and generated summaries for the default eight-room budget',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'p2wlan_session_logs_eight_rooms_',
      );
      addTearDown(() => directory.delete(recursive: true));
      final daemon = File('${directory.path}/p2wlan-daemon.log');
      final client = File('${directory.path}/p2wlan-client.log');
      await daemon.writeAsString('main daemon ok\n');
      await client.writeAsString('client ok\n');
      final extraFiles = <({String name, String path})>[];
      final inlineFiles = <SessionLogFile>[];
      for (var room = 1; room <= maxSupportLogRoomInstances; room++) {
        final profileId = room.toRadixString(16).padLeft(64, '0');
        final roomDir = Directory('${directory.path}/rooms/$profileId');
        await roomDir.create(recursive: true);
        final roomLog = File('${roomDir.path}/p2wlan-daemon.log');
        await roomLog.writeAsString('room $room daemon ok\n');
        extraFiles.add((
          name: 'rooms/$profileId/p2wlan-daemon.log',
          path: roomLog.path,
        ));
        inlineFiles.add(
          SessionLogFile(
            name: 'rooms/$profileId/status-summary.json',
            content: '{"phase":"failed","message":"start failed"}',
          ),
        );
      }

      final bundle = await CurrentSessionLogBundle.collect(
        daemonLogPath: daemon.path,
        clientLogPath: client.path,
        extraFiles: extraFiles,
        inlineFiles: inlineFiles,
      );

      expect(bundle.files, hasLength(maxSupportLogFilesV2));
      expect(
        bundle.files.where((file) => file.name.endsWith('status-summary.json')),
        hasLength(maxSupportLogRoomInstances),
      );
    },
  );

  test(
    'records room instances omitted by the bounded support-log selection',
    () {
      final profileIds = [
        for (var room = 1; room <= maxSupportLogRoomInstances + 1; room++)
          room.toRadixString(16).padLeft(64, '0'),
      ];

      final selection = selectSupportLogRoomProfiles(profileIds);

      expect(
        selection.retainedProfileIds,
        hasLength(maxSupportLogRoomInstances),
      );
      expect(selection.omittedProfileIds, [profileIds.last]);
    },
  );
}

String _marker(String digit, int segment) =>
    '[p2wlan-log-segment] version=1 runtime_id=${digit * 32} segment=$segment\n';

Map<String, dynamic> _coverage(String content) => jsonDecode(
  content.split('\n').first.substring('[p2wlan-log-coverage] '.length),
) as Map<String, dynamic>;

// A real descriptor is returned after a deterministic pathname replacement.
// The reader must use that descriptor for both identity and content, then
// revalidate the pathname before returning a runtime-scoped bundle.
class _ReplaceAfterOpenFile implements File {
  _ReplaceAfterOpenFile(this.file, this.replace);
  final File file;
  final Future<void> Function() replace;
  bool replaced = false;
  @override
  String get path => file.path;
  @override
  Future<RandomAccessFile> open({FileMode mode = FileMode.read}) async {
    final handle = await file.open(mode: mode);
    if (!replaced) {
      replaced = true;
      await replace();
    }
    return handle;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
