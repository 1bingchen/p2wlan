import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/session_log_bundle.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/support_log_protocol.dart';

void main() {
  test('collects current files and never reads rotated logs', () async {
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

  test('keeps only the tail when a current file exceeds the bound', () async {
    final directory = await Directory.systemTemp.createTemp(
      'p2wlan_session_logs_tail_',
    );
    addTearDown(() => directory.delete(recursive: true));
    final daemon = File('${directory.path}/p2wlan-daemon.log');
    await daemon.writeAsString('first line\nsecond line\n');

    final bundle = await CurrentSessionLogBundle.collect(
      daemonLogPath: daemon.path,
      clientLogPath: '${directory.path}/missing-client.log',
      maxBytesPerFile: 8,
    );

    expect(bundle.files.single.content, contains('showing its tail only'));
    expect(bundle.files.single.content, contains('line\n'));
    expect(bundle.files.single.content, isNot(contains('first line')));
  });

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
    final decoded = jsonDecode(content) as Map<String, dynamic>;
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
