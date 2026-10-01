import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/core/build_info.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/session_log_bundle.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/support_log_protocol.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/support_status_capture.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/support_status_summary.dart';

const _build = ClientBuildInfo(
  appVersion: '0.1.166',
  gitCommit: 'abcdef01',
  buildId: 'abcdef02',
  dirtyValue: 'false',
  diffHash: 'none',
  profile: 'release',
);

Future<Map<String, dynamic>> _upload({
  required String summary,
  List<SessionLogFile> roomFiles = const [],
}) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  addTearDown(() => server.close(force: true));
  final api = ControlApi();
  addTearDown(api.close);
  final pending = api.uploadSupportLogs(
    controlServer: 'http://127.0.0.1:${server.port}',
    authToken: 'account-auth',
    deviceName: 'Test device',
    clientBuild: _build,
    daemonBuild: null,
    mainStatusSummary: summary,
    files: [
      const SessionLogFile(
        name: 'p2wlan-daemon.log',
        content: 'token=log-secret\n',
      ),
      const SessionLogFile(name: 'p2wlan-client.log', content: 'client ok\n'),
      ...roomFiles,
    ],
  );
  final request = await server.first.timeout(const Duration(seconds: 3));
  expect(request.uri.path, '/api/v1/support/logs');
  expect(
    request.headers.value(HttpHeaders.authorizationHeader),
    'Bearer account-auth',
  );
  final compressed = await request.fold<List<int>>(
    [],
    (all, chunk) => all..addAll(chunk),
  );
  final payload =
      jsonDecode(utf8.decode(gzip.decode(compressed))) as Map<String, dynamic>;
  request.response
    ..headers.contentType = ContentType.json
    ..write(
      jsonEncode({
        'success': true,
        'upload_id': 'test-upload',
        'instances': payload['manifest']['total_instances'],
      }),
    );
  await request.response.close();
  expect((await pending).uploadId, 'test-upload');
  return payload;
}

void main() {
  test(
    'main summary uses v2 structured main without creating a legacy room',
    () async {
      final payload = await _upload(
        summary: buildSupportStatusSummary(
          source: 'live',
          snapshot: {'version': '0.1.166', 'network_generation': 8},
        ),
      );
      expect(payload['schema_version'], 2);
      expect(payload['manifest'], {
        'total_instances': 1,
        'has_room_logs': false,
        'retained_room_instances': 0,
      });
      final instances = payload['instances'] as List;
      expect(instances, hasLength(1));
      expect(instances.single['instance_type'], 'main');
      expect(
        jsonDecode(
          instances.single['status_summary'],
        )['status']['network_generation'],
        8,
      );
      expect((payload['files'] as List).map((file) => file['name']), [
        'p2wlan-daemon.log',
        'p2wlan-client.log',
      ]);
      expect(jsonEncode(payload), isNot(contains('log-secret')));
    },
  );

  test('main snapshot and eight room summaries retain exact wire instance count', () async {
    final summary = buildSupportStatusSummary(
      source: 'cached',
      snapshot: {'version': '0.1.166'},
    );
    final payload = await _upload(
      summary: summary,
      roomFiles: [
        for (var room = 1; room <= maxSupportLogRoomInstances; room++) ...[
          SessionLogFile(
            name:
                'rooms/${room.toRadixString(16).padLeft(64, '0')}/p2wlan-daemon.log',
            content: 'room ok',
          ),
          SessionLogFile(
            name:
                'rooms/${room.toRadixString(16).padLeft(64, '0')}/status-summary.json',
            content: summary,
          ),
        ],
      ],
    );
    expect(payload['manifest'], {
      'total_instances': 9,
      'has_room_logs': true,
      'retained_room_instances': 8,
    });
    expect(payload['files'], hasLength(maxSupportLogFilesV2));
    final instances = payload['instances'] as List;
    expect(instances, hasLength(maxSupportLogInstancesV2));
    expect(
      instances.where((instance) => instance['instance_type'] == 'main'),
      hasLength(1),
    );
    expect(
      instances
          .where((instance) => instance['instance_type'] == 'room')
          .map((instance) => instance['profile_id'])
          .toSet(),
      hasLength(8),
    );
    for (final file in payload['files']) {
      if ((file['name'] as String).endsWith('status-summary.json')) {
        expect(jsonDecode(file['content'])['stale'], isTrue);
        expect(
          utf8.encode(file['content']).length,
          lessThanOrEqualTo(maxSupportStatusBytes),
        );
      }
    }
  });

  test(
    'diagnostic 401 is recorded but does not block authenticated log upload',
    () async {
      final diagnostics = await HttpServer.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      addTearDown(() => diagnostics.close(force: true));
      final capture = captureMainSupportStatus(
        diagnosticsUrl: 'http://127.0.0.1:${diagnostics.port}',
        tokenReader: () async => 'old-diagnostic-auth',
        cachedSnapshot: {'version': '0.1.165', 'network_generation': 2},
      );
      final request = await diagnostics.first;
      request.response
        ..statusCode = HttpStatus.unauthorized
        ..write('private failure token=diagnostics-secret');
      await request.response.close();
      final payload = await _upload(summary: await capture);
      final summary = jsonDecode(payload['instances'][0]['status_summary']);
      expect(summary['error_code'], 'diagnostics_auth_rejected');
      expect(summary['source'], 'cached');
      expect(summary['stale'], isTrue);
      expect(payload['files'], hasLength(2));
      expect(jsonEncode(payload), isNot(contains('diagnostics-secret')));
    },
  );
}
