import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/support_status_capture.dart';

void main() {
  test(
    'live capture authenticates only the original loopback status path',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final capture = captureMainSupportStatus(
        diagnosticsUrl:
            'http://127.0.0.1:${server.port}/other?secret=old#fragment',
        tokenReader: () async => 'local-diagnostic-token',
      );
      final request = await server.first;
      expect(request.uri.path, '/status');
      expect(request.uri.query, isEmpty);
      expect(
        request.headers.value(HttpHeaders.authorizationHeader),
        'Bearer local-diagnostic-token',
      );
      request.response
        ..headers.contentType = ContentType.json
        ..write(
          jsonEncode({
            'version': '0.1.166',
            'network_generation': 6,
            'revision': 7,
            'captured_revision': 7,
          }),
        );
      await request.response.close();
      final safe = jsonDecode(await capture);
      expect(safe['source'], 'live');
      expect(safe['stale'], isFalse);
      expect(safe['status']['network_generation'], 6);
      expect(jsonEncode(safe), isNot(contains('local-diagnostic-token')));
    },
  );

  for (final status in [401, 403, 500]) {
    test(
      'HTTP $status retains only cached evidence and a stable failure',
      () async {
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        final capture = captureMainSupportStatus(
          diagnosticsUrl: 'http://127.0.0.1:${server.port}',
          tokenReader: () async => 'local-token',
          cachedSnapshot: {'version': '0.1.165', 'network_generation': 2},
          cachedAt: DateTime.utc(2026, 1, 1),
        );
        final request = await server.first;
        request.response
          ..statusCode = status
          ..write('Bearer secret body /private/path');
        await request.response.close();
        final safe = jsonDecode(await capture);
        expect(safe['source'], 'cached');
        expect(safe['stale'], isTrue);
        expect(safe['cached_at'], '2026-01-01T00:00:00.000Z');
        expect(safe['status']['network_generation'], 2);
        expect(
          safe['error_code'],
          status == 500
              ? 'diagnostics_http_failed'
              : 'diagnostics_auth_rejected',
        );
        expect(jsonEncode(safe), isNot(contains('secret')));
      },
    );
  }

  test(
    'blocked token lookup respects total timeout without any request',
    () async {
      final token = Completer<String?>();
      final safe = jsonDecode(
        await captureMainSupportStatus(
          diagnosticsUrl: 'http://127.0.0.1:1',
          tokenReader: () => token.future,
          timeout: const Duration(milliseconds: 30),
          cachedSnapshot: {'version': '0.1.165'},
        ),
      );
      expect(safe['error_code'], 'status_timeout');
      expect(safe['source'], 'cached');
      // The owned client is already closed; completion cannot issue a late GET.
      token.complete('late-local-token');
    },
  );

  test('a remote URL is rejected before reading local credentials', () async {
    var reads = 0;
    final safe = jsonDecode(
      await captureMainSupportStatus(
        diagnosticsUrl: 'https://example.invalid/status',
        tokenReader: () async {
          reads++;
          return 'must-not-read';
        },
      ),
    );
    expect(reads, 0);
    expect(safe['error_code'], 'invalid_local_address');
    expect(safe['source'], 'unavailable');
  });

  test(
    'an oversized advertised response cannot displace cached evidence',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final capture = captureMainSupportStatus(
        diagnosticsUrl: 'http://127.0.0.1:${server.port}',
        tokenReader: () async => 'local-token',
        cachedSnapshot: {'version': '0.1.165'},
      );
      final request = await server.first;
      request.response.contentLength = maxSupportStatusResponseBytes + 1;
      request.response.write(' ' * (maxSupportStatusResponseBytes + 1));
      // The client may close as soon as it sees the bounded size header.
      unawaited(request.response.close().catchError((_) {}));
      final safe = jsonDecode(await capture);
      expect(safe['error_code'], 'status_response_size_limit');
      expect(safe['source'], 'cached');
    },
  );
}
