import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/control_api.dart';
import 'package:p2wlan_flutter_client/core/build_info.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/session_log_bundle.dart';

void main() {
  const storageMessage = '控制服务器无法保存日志，请联系管理员检查日志存储权限或剩余空间，修复后再试';
  const expiredMessage = '登录状态已过期，请重新登录后再上传日志';
  final cases = <({String name, int status, String body, String expected})>[
    (
      name: 'standard storage failure is actionable and does not request login',
      status: HttpStatus.internalServerError,
      body: jsonEncode({'error': 'support_log_storage_failed'}),
      expected: storageMessage,
    ),
    (
      name: 'legacy storage failure has the same safe explanation',
      status: HttpStatus.internalServerError,
      body: jsonEncode({'error': 'support log storage failed'}),
      expected: storageMessage,
    ),
    (
      name: 'unauthorized status takes precedence over a storage error body',
      status: HttpStatus.unauthorized,
      body: jsonEncode({'error': 'support_log_storage_failed'}),
      expected: expiredMessage,
    ),
    (
      name: 'HTML unauthorized response still explains expired authentication',
      status: HttpStatus.unauthorized,
      body: '<html>Unauthorized: token=server-secret</html>',
      expected: expiredMessage,
    ),
    (
      name: 'forbidden upload does not incorrectly require another login',
      status: HttpStatus.forbidden,
      body: jsonEncode({'error': 'forbidden'}),
      expected: '当前账号没有上传日志的权限，请联系服务器管理员',
    ),
    (
      name: 'unknown server errors do not expose credentials paths or payload',
      status: HttpStatus.internalServerError,
      body: jsonEncode({
        'error':
            'write /private/server-logs: token=server-secret '
            'Bearer upload-test-token payload=private-log-content',
      }),
      expected: '控制服务器暂时无法处理日志上传（HTTP 500），请稍后重试或联系服务器管理员',
    ),
    (
      name: 'non-JSON proxy failure retains a safe HTTP status',
      status: HttpStatus.serviceUnavailable,
      body: '<html>upstream /private/server-logs unavailable</html>',
      expected: '控制服务器暂时无法处理日志上传（HTTP 503），请稍后重试或联系服务器管理员',
    ),
    (
      name: 'unknown rejected uploads do not leak arbitrary response text',
      status: HttpStatus.badRequest,
      body: jsonEncode({'error': 'payload=private-log-content'}),
      expected: '日志上传失败（HTTP 400），请稍后重试；若持续失败，请联系服务器管理员',
    ),
    (
      name: 'upload size failures retain the existing explanation',
      status: HttpStatus.requestEntityTooLarge,
      body: '',
      expected: '日志文件过大，请缩短本次启动时间后再试',
    ),
    (
      name: 'schema compatibility failures retain the existing explanation',
      status: HttpStatus.badRequest,
      body: jsonEncode({'error': 'unsupported schema_version: 2'}),
      expected: '控制服务器不支持多房间日志格式(schema v2)，请升级服务端后再试',
    ),
    (
      name: 'manifest mismatch retains the existing explanation',
      status: HttpStatus.badRequest,
      body: jsonEncode({'error': 'manifest total_instances mismatch'}),
      expected: '日志包实例清单与实际文件不一致，请重试上传',
    ),
  ];

  for (final scenario in cases) {
    test('uploadSupportLogs ${scenario.name}', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final api = ControlApi();
      addTearDown(api.close);
      final upload = api.uploadSupportLogs(
        controlServer: 'http://127.0.0.1:${server.port}',
        authToken: 'upload-test-token',
        deviceName: 'Test device',
        clientBuild: const ClientBuildInfo(
          appVersion: '0.1.135',
          gitCommit: 'abc',
          buildId: 'build',
          dirtyValue: 'false',
          diffHash: 'none',
          profile: 'release',
        ),
        daemonBuild: null,
        files: const [
          SessionLogFile(
            name: 'p2wlan-daemon.log',
            content: 'private-log-content\n',
          ),
        ],
      );
      final assertion = expectLater(
        upload,
        throwsA(
          isA<ControlApiException>()
              .having((error) => error.message, 'message', scenario.expected)
              .having(
                (error) => error.toString(),
                'safe error string',
                isNot(
                  matches(
                    r'server-secret|upload-test-token|private-log-content|'
                    r'/private/server-logs|support_log_storage_failed',
                  ),
                ),
              ),
        ),
      );
      final request = await server.first.timeout(const Duration(seconds: 3));
      expect(request.method, 'POST');
      expect(request.uri.path, '/api/v1/support/logs');
      expect(
        request.headers.value(HttpHeaders.authorizationHeader),
        'Bearer upload-test-token',
      );
      expect(request.headers.value(HttpHeaders.contentEncodingHeader), 'gzip');
      await request.drain<void>();
      request.response
        ..statusCode = scenario.status
        ..headers.contentType = ContentType.text
        ..write(scenario.body);
      await request.response.close();
      await assertion;
    });
  }
}
