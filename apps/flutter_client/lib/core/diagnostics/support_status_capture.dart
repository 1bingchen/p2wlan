import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import '../daemon/diagnostics_auth.dart';
import 'support_status_summary.dart';

const supportStatusCaptureTimeout = Duration(milliseconds: 1500);
const maxSupportStatusResponseBytes = 2 * 1024 * 1024;

class _CaptureFailure implements Exception {
  const _CaptureFailure(this.code);
  final String code;
}

/// A one-shot, separately owned client makes the total timeout cancel actual
/// sockets. This does not alter StatusStore, authentication or account state.
Future<String> captureMainSupportStatus({
  required String diagnosticsUrl,
  Map<String, dynamic>? cachedSnapshot,
  DateTime? cachedAt,
  Map<String, dynamic>? observedDaemonBuild,
  Future<String?> Function()? tokenReader,
  Duration timeout = supportStatusCaptureTimeout,
}) async {
  final client = HttpClient()
    ..findProxy = null
    ..connectionTimeout = supportStatusCaptureTimeout;
  Map<String, dynamic>? snapshot;
  String? errorCode;
  final boundedTimeout = timeout > supportStatusCaptureTimeout
      ? supportStatusCaptureTimeout
      : timeout;
  try {
    snapshot = await (() async {
      final uri = Uri.tryParse(diagnosticsUrl);
      final host = uri?.host.replaceAll('[', '').replaceAll(']', '') ?? '';
      final address = InternetAddress.tryParse(host);
      if (uri == null ||
          (uri.scheme != 'http' && uri.scheme != 'https') ||
          uri.userInfo.isNotEmpty ||
          (host != 'localhost' && address?.isLoopback != true)) {
        throw const _CaptureFailure('invalid_local_address');
      }
      final token = await (tokenReader ?? readDiagnosticsAuthToken)();
      if (token == null || token.isEmpty || token.length > 4096) {
        throw const _CaptureFailure('diagnostics_auth_unavailable');
      }
      final request = await client.getUrl(
        uri.replace(path: '/status', query: '', fragment: ''),
      );
      request.followRedirects = false;
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
      final response = await request.close();
      if (response.statusCode == 401 || response.statusCode == 403) {
        throw const _CaptureFailure('diagnostics_auth_rejected');
      }
      if (response.statusCode != 200) {
        throw const _CaptureFailure('diagnostics_http_failed');
      }
      if (response.contentLength > maxSupportStatusResponseBytes) {
        throw const _CaptureFailure('status_response_size_limit');
      }
      final bytes = <int>[];
      await for (final chunk in response) {
        if (bytes.length + chunk.length > maxSupportStatusResponseBytes) {
          throw const _CaptureFailure('status_response_size_limit');
        }
        bytes.addAll(chunk);
      }
      final decoded = await _decodeStatus(bytes);
      if (decoded is! Map<String, dynamic>) {
        throw const _CaptureFailure('status_invalid_response');
      }
      final payload = decoded['snapshot'] ?? decoded;
      if (payload is! Map<String, dynamic> || payload['version'] is! String) {
        throw const _CaptureFailure('status_invalid_response');
      }
      return payload;
    })().timeout(boundedTimeout);
  } on _CaptureFailure catch (error) {
    errorCode = error.code;
  } on TimeoutException {
    errorCode = 'status_timeout';
  } on FormatException {
    errorCode = 'status_invalid_response';
  } on SocketException {
    errorCode = 'status_connection_failed';
  } catch (_) {
    errorCode = 'status_unavailable';
  } finally {
    client.close(force: true);
  }
  final source = snapshot != null
      ? 'live'
      : cachedSnapshot != null
      ? 'cached'
      : 'unavailable';
  final effective = snapshot ?? cachedSnapshot;
  // Projection/encoding is bounded independently and runs outside the UI.
  try {
    return await _encodeStatus(
      snapshot: effective,
      source: source,
      errorCode: errorCode,
      stale: snapshot == null,
      cachedAt: snapshot == null ? cachedAt : null,
      observedDaemonBuild: observedDaemonBuild,
    );
  } catch (_) {
    return buildSupportStatusSummary(
      source: 'unavailable',
      errorCode: 'summary_unavailable',
    );
  }
}

// Separate closure scopes avoid accidentally transferring HttpClient handles
// from the live request's lexical context to a worker isolate.
Future<dynamic> _decodeStatus(List<int> bytes) =>
    Isolate.run(() => jsonDecode(utf8.decode(bytes)));

Future<String> _encodeStatus({
  Map<String, dynamic>? snapshot,
  required String source,
  String? errorCode,
  bool stale = false,
  DateTime? cachedAt,
  Map<String, dynamic>? observedDaemonBuild,
}) => Isolate.run(
  () => buildSupportStatusSummary(
    snapshot: snapshot,
    source: source,
    errorCode: errorCode,
    stale: stale,
    cachedAt: cachedAt,
    observedDaemonBuild: observedDaemonBuild,
  ),
);
