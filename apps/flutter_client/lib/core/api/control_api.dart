import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import '../build_info.dart';
import '../diagnostics/session_log_bundle.dart';
import '../diagnostics/support_log_protocol.dart';
import '../security/redactor.dart';
import '../state/settings_store.dart';

enum AuthMode { login, register }

class AuthSession {
  const AuthSession({
    required this.token,
    required this.controlServer,
    this.user,
  });

  final String token;
  final String controlServer;
  final Map<String, dynamic>? user;
}

class AccountProfile {
  const AccountProfile({required this.email, required this.username});

  final String email;
  final String username;
}

class DeviceUpdateResult {
  const DeviceUpdateResult({required this.deviceName, required this.virtualIp});

  final String deviceName;
  final String virtualIp;
}

class SupportLogUploadResult {
  const SupportLogUploadResult({
    required this.uploadId,
    this.receivedAt,
    this.instances = 1,
  });

  final String uploadId;
  final String? receivedAt;
  final int instances;
}

class ControlApi {
  ControlApi({HttpClient? client}) : _client = client ?? HttpClient() {
    _client.connectionTimeout = _requestTimeout;
  }

  static const _requestTimeout = Duration(seconds: 8);
  static const _supportLogUploadTimeout = Duration(seconds: 60);
  static const _maxSupportLogCompressedBytes = maxSupportLogCompressedBytes;

  final HttpClient _client;

  Future<AuthSession> authenticate({
    required AuthMode mode,
    required String controlServer,
    required String email,
    required String password,
  }) async {
    final normalizedControlServer = _normalizeAuthControlServer(controlServer);
    final normalizedIdentifier = email.trim();
    if (normalizedIdentifier.isEmpty) {
      throw const ControlApiException('请输入邮箱或用户名');
    }
    if (password.length < 6) {
      throw const ControlApiException('密码至少需要 6 个字符');
    }
    final endpointPath =
        '/api/v1/${mode == AuthMode.register ? 'register' : 'login'}';
    final payload = <String, dynamic>{
      'identifier': normalizedIdentifier.contains('@')
          ? normalizedIdentifier.toLowerCase()
          : normalizedIdentifier,
      'email': normalizedIdentifier.contains('@')
          ? normalizedIdentifier.toLowerCase()
          : normalizedIdentifier,
      'password': password,
    };
    Map<String, dynamic>? body;
    var usedControlServer = normalizedControlServer;
    ControlApiException? lastEndpointError;
    final candidates = _authControlServerCandidates(normalizedControlServer);
    for (var index = 0; index < candidates.length; index++) {
      final candidate = candidates[index];
      try {
        body = await _sendJson(
          method: 'POST',
          uri: Uri.parse('$candidate$endpointPath'),
          payload: payload,
        );
        usedControlServer = candidate;
        break;
      } on ControlApiException catch (error) {
        lastEndpointError = error;
        if (index == candidates.length - 1 ||
            !_isRetryableAuthEndpointError(error)) {
          rethrow;
        }
      }
    }
    final responseBody = body;
    if (responseBody == null) {
      throw lastEndpointError ?? const ControlApiException('控制服务器请求失败');
    }
    final token = responseBody['token']?.toString() ?? '';
    if (token.isEmpty || responseBody['success'] == false) {
      throw ControlApiException(
        _zhAuthError(responseBody['error']?.toString()),
      );
    }
    return AuthSession(
      token: token,
      controlServer: usedControlServer,
      user: responseBody['user'] is Map
          ? Map<String, dynamic>.from(responseBody['user'] as Map)
          : null,
    );
  }

  Future<String> profileUsername({
    required String controlServer,
    required String authToken,
    String? username,
  }) async {
    final name = username?.trim();
    if (name != null &&
        (name.isEmpty ||
            name.runes.length > 32 ||
            RegExp(r'[\x00-\x1f\x7f-\x9f]').hasMatch(name))) {
      throw const ControlApiException('用户名需为 1–32 个字符，不能包含控制字符');
    }
    final profile = await accountProfile(
      controlServer: controlServer,
      authToken: authToken,
      username: username,
    );
    return profile.username;
  }

  Future<AccountProfile> accountProfile({
    required String controlServer,
    required String authToken,
    String? username,
  }) async {
    final name = username?.trim();
    if (name != null &&
        (name.isEmpty ||
            name.runes.length > 32 ||
            RegExp(r'[\x00-\x1f\x7f-\x9f]').hasMatch(name))) {
      throw const ControlApiException('用户名需为 1–32 个字符，不能包含控制字符');
    }
    final body = await _sendJson(
      method: name == null ? 'GET' : 'PATCH',
      uri: Uri.parse(
        '${_normalizeAuthControlServer(controlServer)}/api/v1/profile',
      ),
      authToken: authToken,
      payload: name == null ? null : {'username': name},
    );
    final user = body['user'] is Map
        ? Map<String, dynamic>.from(body['user'] as Map)
        : const <String, dynamic>{};
    return AccountProfile(
      email: user['email']?.toString().trim() ?? '',
      username: user['username']?.toString() ?? '',
    );
  }

  Future<String> renameDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
    required String deviceName,
  }) async {
    final result = await updateDevice(
      controlServer: controlServer,
      authToken: authToken,
      deviceId: deviceId,
      deviceName: deviceName,
    );
    return result.deviceName;
  }

  Future<DeviceUpdateResult> updateDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
    String? deviceName,
    String? virtualIp,
  }) async {
    final name = deviceName?.trim() ?? '';
    final ip = virtualIp?.trim() ?? '';
    if (name.isEmpty && ip.isEmpty) {
      throw const ControlApiException('设备名称或虚拟 IP 至少需要填写一项');
    }
    if (ip.isNotEmpty &&
        InternetAddress.tryParse(ip)?.type != InternetAddressType.IPv4) {
      throw const ControlApiException('虚拟 IP 格式不正确，例如 10.20.0.42');
    }
    if (deviceId.trim().isEmpty) {
      throw const ControlApiException('设备标识不能为空');
    }
    if (name.isNotEmpty && name.runes.length > 128) {
      throw const ControlApiException('设备名称不能超过 128 个字符');
    }
    if (ip.length > 64) {
      throw const ControlApiException('虚拟 IP 不能超过 64 个字符');
    }
    if (authToken.trim().isEmpty) {
      throw const ControlApiException('登录状态已失效，请重新登录');
    }
    final normalizedControlServer = _normalizeAuthControlServer(controlServer);
    final endpoint = Uri.parse(
      '$normalizedControlServer/api/v1/devices/${Uri.encodeComponent(deviceId)}',
    );
    final body = await _sendJson(
      method: 'PATCH',
      uri: endpoint,
      payload: {
        if (name.isNotEmpty) 'device_name': name,
        if (ip.isNotEmpty) 'virtual_ip': ip,
      },
      authToken: authToken,
      unauthorizedMessage: '登录状态已过期或无权修改该设备，请重新登录后再试',
    );
    if (body['success'] == false) {
      throw ControlApiException(
        _zhAuthError(body['error']?.toString() ?? '设备名称保存失败'),
      );
    }
    final device = body['device'] is Map
        ? Map<String, dynamic>.from(body['device'] as Map)
        : const <String, dynamic>{};
    return DeviceUpdateResult(
      deviceName:
          body['device_name']?.toString() ??
          device['device_name']?.toString() ??
          name,
      virtualIp:
          body['virtual_ip']?.toString() ??
          device['virtual_ip']?.toString() ??
          ip,
    );
  }

  Future<void> deleteDevice({
    required String controlServer,
    required String authToken,
    required String deviceId,
  }) async {
    final id = deviceId.trim();
    if (id.isEmpty) {
      throw const ControlApiException('设备标识不能为空');
    }
    if (authToken.trim().isEmpty) {
      throw const ControlApiException('登录状态已失效，请重新登录');
    }
    final normalizedControlServer = _normalizeAuthControlServer(controlServer);
    final endpoint = Uri.parse(
      '$normalizedControlServer/api/v1/devices/${Uri.encodeComponent(id)}',
    );
    final body = await _sendJson(
      method: 'DELETE',
      uri: endpoint,
      authToken: authToken,
      unauthorizedMessage: '登录状态已过期或无权移除该设备，请重新登录后再试',
    );
    if (body['success'] == false) {
      throw ControlApiException(
        _zhAuthError(body['error']?.toString() ?? '设备删除失败'),
      );
    }
  }

  /// Upload only the current local startup log bundle to the authenticated
  /// control server. The client never sends a private key or a destination
  /// path; the server allocates the upload id and stores the bundle privately.
  Future<SupportLogUploadResult> uploadSupportLogs({
    required String controlServer,
    required String authToken,
    required String deviceName,
    required ClientBuildInfo clientBuild,
    required DaemonBuildInfo? daemonBuild,
    required Iterable<SessionLogFile> files,
    Iterable<String> omittedRoomProfileIds = const [],
  }) async {
    final token = authToken.trim();
    if (token.isEmpty) {
      throw const ControlApiException('登录状态已失效，请重新登录后再上传日志');
    }
    final normalizedControlServer = _normalizeAuthControlServer(controlServer);
    final logFiles = files
        .map((file) => {'name': file.name, 'content': file.content})
        .toList(growable: false);
    if (logFiles.isEmpty) {
      throw const ControlApiException('没有找到本次启动的日志');
    }
    final omittedProfiles = _normalizeOmittedRoomProfiles(
      omittedRoomProfileIds,
    );
    _validateSupportLogFiles(logFiles);

    // Redaction, JSON expansion, UTF-8 encoding and gzip are deliberately
    // performed off the Flutter UI isolate. `async` alone does not move CPU
    // work off the main isolate and was causing Android to freeze on large
    // daemon logs.
    late final Uint8List compressed;
    try {
      compressed = await _prepareSupportLogPayload(
        uploadedAt: DateTime.now().toUtc().toIso8601String(),
        deviceName: deviceName.trim(),
        platform: Platform.operatingSystem,
        clientBuild: {
          'app_version': clientBuild.appVersion,
          'git_commit': clientBuild.gitCommit,
          'build_id': clientBuild.buildId,
          'dirty': clientBuild.dirtyLabel,
          'diff_hash': clientBuild.diffHash,
          'profile': clientBuild.profile,
        },
        daemonBuild: daemonBuild == null
            ? null
            : {
                'app_version': daemonBuild.appVersion,
                'daemon_version': daemonBuild.daemonVersion,
                'git_commit': daemonBuild.gitCommit,
                'build_id': daemonBuild.buildId,
                'dirty': daemonBuild.dirtyLabel,
                'diff_hash': daemonBuild.diffHash,
                'profile': daemonBuild.profile,
              },
        files: logFiles,
        omittedRoomProfileIds: omittedProfiles,
      );
    } on _SupportLogPayloadTooLarge {
      throw const ControlApiException('日志展开后过大，请缩短本次启动时间后再试');
    }
    if (compressed.length > _maxSupportLogCompressedBytes) {
      throw const ControlApiException('日志压缩后仍然过大，请缩短本次启动时间后再试');
    }

    final endpoint = Uri.parse('$normalizedControlServer/api/v1/support/logs');
    try {
      final request = await _client
          .postUrl(endpoint)
          .timeout(_supportLogUploadTimeout);
      request.followRedirects = false;
      request.persistentConnection = false;
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      request.headers.contentType = ContentType.json;
      request.headers.set(HttpHeaders.contentEncodingHeader, 'gzip');
      request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
      request.contentLength = compressed.length;
      request.add(compressed);
      final response = await request.close().timeout(_supportLogUploadTimeout);
      final text = await utf8
          .decodeStream(response)
          .timeout(_supportLogUploadTimeout);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        String? serverError;
        try {
          final decoded = jsonDecode(text);
          if (decoded is Map && decoded['error'] is String) {
            serverError = decoded['error'] as String;
          }
        } on FormatException {
          // Proxies may return HTML or an empty body. The HTTP status still
          // identifies authentication failures without exposing that body.
        }
        throw ControlApiException(
          _zhSupportLogUploadError(serverError, response.statusCode),
        );
      }
      final decoded = text.trim().isEmpty
          ? <String, dynamic>{}
          : jsonDecode(text);
      final body = decoded is Map
          ? Map<String, dynamic>.from(decoded)
          : <String, dynamic>{};
      final uploadId = body['upload_id']?.toString().trim() ?? '';
      if (uploadId.isEmpty || body['success'] == false) {
        throw const ControlApiException('控制服务器没有返回日志上传编号');
      }
      final instances = body['instances'] is num
          ? (body['instances'] as num).toInt()
          : (body['instances'] is String
                ? int.tryParse(body['instances'] as String) ?? 1
                : 1);
      return SupportLogUploadResult(
        uploadId: uploadId,
        receivedAt: body['received_at']?.toString(),
        instances: instances,
      );
    } on ControlApiException {
      rethrow;
    } on TimeoutException {
      throw ControlApiException('日志上传超时：${endpoint.origin}');
    } on SocketException catch (error) {
      throw ControlApiException(_zhNetworkError(error, endpoint));
    } on HandshakeException {
      throw ControlApiException('控制服务器 TLS 握手失败：${endpoint.origin}');
    } on FormatException {
      throw const ControlApiException('控制服务器返回了无法解析的日志上传结果');
    } on HttpException {
      throw ControlApiException('无法连接控制服务器：${endpoint.origin}。请确认服务端已更新并正在运行。');
    }
  }

  Future<Map<String, dynamic>> _sendJson({
    required String method,
    required Uri uri,
    Map<String, dynamic>? payload,
    String? authToken,
    String? unauthorizedMessage,
  }) async {
    try {
      final request = await _client
          .openUrl(method, uri)
          .timeout(_requestTimeout);
      request.followRedirects = false;
      request.persistentConnection = false;
      request.headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (authToken != null && authToken.trim().isNotEmpty) {
        request.headers.set(
          HttpHeaders.authorizationHeader,
          'Bearer ${authToken.trim()}',
        );
      }
      if (payload != null) {
        request.headers.contentType = ContentType.json;
        request.write(jsonEncode(payload));
      }
      final response = await request.close().timeout(_requestTimeout);
      final text = await utf8.decodeStream(response).timeout(_requestTimeout);
      final decoded = text.trim().isEmpty
          ? <String, dynamic>{}
          : jsonDecode(text);
      final Map<String, dynamic> body = decoded is Map
          ? Map<String, dynamic>.from(decoded)
          : <String, dynamic>{};
      if (response.statusCode < 200 || response.statusCode >= 300) {
        if (body['error'] == null && response.statusCode >= 500) {
          throw ControlApiException(
            '无法连接控制服务器：${uri.origin}。请确认服务端已启动且地址/端口正确。',
          );
        }
        throw ControlApiException(
          _zhAuthError(
            body['error']?.toString(),
            response.statusCode,
            unauthorizedMessage,
          ),
        );
      }
      return body;
    } on ControlApiException {
      rethrow;
    } on TimeoutException {
      throw ControlApiException('连接控制服务器超时：${uri.origin}');
    } on SocketException catch (error) {
      throw ControlApiException(_zhNetworkError(error, uri));
    } on HandshakeException {
      throw ControlApiException('控制服务器 TLS 握手失败：${uri.origin}');
    } on FormatException {
      throw const ControlApiException('控制服务器返回了无法解析的数据');
    } on HttpException {
      // `HttpClient` reports a refused/closed socket as HttpException on
      // some platforms and SocketException on others.  At this point no HTTP
      // response exists, so exposing a generic request failure is not useful
      // to the user; classify every transport-level HttpException as an
      // unreachable control endpoint.
      throw ControlApiException('无法连接控制服务器：${uri.origin}。请确认服务端已启动且地址/端口正确。');
    }
  }

  void close() {
    _client.close(force: true);
  }
}

Future<Uint8List> _prepareSupportLogPayload({
  required String uploadedAt,
  required String deviceName,
  required String platform,
  required Map<String, String> clientBuild,
  required Map<String, String>? daemonBuild,
  required List<Map<String, String>> files,
  required List<String> omittedRoomProfileIds,
}) async {
  final encoded = await Isolate.run<Map<String, Object?>>(() {
    final logFiles = files
        .map(
          (file) => <String, String>{
            'name': file['name'] ?? '',
            // This is the only redaction pass. It runs in the worker isolate,
            // so even a busy log cannot monopolize Flutter's UI isolate.
            'content': redactSensitive(file['content'] ?? ''),
          },
        )
        .toList(growable: false);
    final roomProfiles = <String>{};
    for (final f in logFiles) {
      final name = f['name'] ?? '';
      if (name.startsWith('rooms/')) {
        final parts = name.split('/');
        if (parts.length >= 2 && parts[1].isNotEmpty) {
          roomProfiles.add(parts[1]);
        }
      } else if (name == 'p2wlan-room.log') {
        roomProfiles.add('legacy');
      }
    }
    final omittedProfiles = omittedRoomProfileIds
        .where((profileId) => !roomProfiles.contains(profileId))
        .toSet();
    final hasRoomLogs = roomProfiles.isNotEmpty;
    final schemaVersion = hasRoomLogs || omittedProfiles.isNotEmpty ? 2 : 1;
    final payload = <String, dynamic>{
      'schema_version': schemaVersion,
      'uploaded_at': uploadedAt,
      'device_name': deviceName,
      'platform': platform,
      'client_build': clientBuild,
      ...?daemonBuild == null
          ? null
          : <String, dynamic>{'daemon_build': daemonBuild},
      if (schemaVersion == 2)
        'manifest': <String, dynamic>{
          'total_instances': 1 + roomProfiles.length,
          'has_room_logs': hasRoomLogs,
          'retained_room_instances': roomProfiles.length,
          if (omittedProfiles.isNotEmpty) ...<String, dynamic>{
            'omitted_room_instances': omittedProfiles.length,
            'omitted_reason': 'room_instance_budget',
          },
        },
      'files': logFiles,
    };
    final jsonBytes = utf8.encode(jsonEncode(payload));
    if (jsonBytes.length > maxSupportLogExpandedBytes) {
      return <String, Object?>{'expanded_too_large': true};
    }
    final compressed = GZipCodec().encode(jsonBytes);
    return <String, Object?>{
      'compressed': TransferableTypedData.fromList([
        Uint8List.fromList(compressed),
      ]),
    };
  });
  if (encoded['expanded_too_large'] == true) {
    throw const _SupportLogPayloadTooLarge();
  }
  final transferable = encoded['compressed'];
  if (transferable is! TransferableTypedData) {
    throw StateError('support log encoder did not return compressed data');
  }
  return transferable.materialize().asUint8List();
}

class _SupportLogPayloadTooLarge implements Exception {
  const _SupportLogPayloadTooLarge();
}

void _validateSupportLogFiles(List<Map<String, String>> files) {
  final names = <String>{};
  final roomProfiles = <String>{};
  final roomLogProfiles = <String>{};
  for (final file in files) {
    final name = (file['name'] ?? '').trim();
    if (name.isEmpty || !names.add(name)) {
      throw const ControlApiException('日志文件名为空或重复，请重试上传');
    }
    if (name.startsWith('rooms/')) {
      final parts = name.split('/');
      final validRoomFile =
          parts.length == 3 &&
          RegExp(r'^[a-f0-9]{64}$').hasMatch(parts[1]) &&
          (parts[2] == 'p2wlan-daemon.log' ||
              parts[2] == 'p2wlan-room.log' ||
              parts[2] == 'status-summary.json');
      if (!validRoomFile) {
        throw const ControlApiException('房间日志文件名无效，请重试上传');
      }
      roomProfiles.add(parts[1]);
      if (parts[2] != 'status-summary.json' && !roomLogProfiles.add(parts[1])) {
        throw const ControlApiException('同一房间只能上传一个守护进程日志');
      }
    }
  }
  if (roomProfiles.length > maxSupportLogRoomInstances) {
    throw ControlApiException('本次最多可上传 $maxSupportLogRoomInstances 个房间实例的日志');
  }
  final maxFiles = roomProfiles.isEmpty ? 3 : maxSupportLogFilesV2;
  if (files.length > maxFiles) {
    throw ControlApiException('本次日志文件超过协议上限 $maxFiles 个');
  }
}

List<String> _normalizeOmittedRoomProfiles(Iterable<String> profileIds) {
  final normalized = <String>[];
  final seen = <String>{};
  final profileIdPattern = RegExp(r'^[a-f0-9]{64}$');
  for (final rawProfileId in profileIds) {
    final profileId = rawProfileId.trim();
    if (!profileIdPattern.hasMatch(profileId)) {
      throw const ControlApiException('被省略房间的日志身份无效，请重试上传');
    }
    if (seen.add(profileId)) normalized.add(profileId);
  }
  if (normalized.length > maxTrackedSupportLogRoomInstances) {
    throw const ControlApiException('本次省略的房间实例超过支持日志的记录上限');
  }
  return List.unmodifiable(normalized);
}

String _normalizeAuthControlServer(String value) {
  try {
    final normalized = normalizeControlServer(value);
    if (normalized.isEmpty) {
      throw const FormatException('控制服务器地址不能为空');
    }
    return normalized;
  } on FormatException catch (error) {
    throw ControlApiException(error.message);
  }
}

/// A self-hosted control plane listens on 18080 by default. Older client
/// builds allowed users to enter only the host, which silently targeted port
/// 80 and often returned a web page instead of the JSON API. For a bare HTTP
/// IPv4/IPv6 address, try the control port first while retaining the original
/// address as a reverse-proxy fallback. Explicit ports and HTTPS URLs are
/// always respected.
List<String> _authControlServerCandidates(String normalized) {
  final uri = Uri.tryParse(normalized);
  if (uri == null ||
      uri.scheme != 'http' ||
      uri.hasPort ||
      InternetAddress.tryParse(uri.host) == null) {
    return [normalized];
  }
  final controlPort = uri.replace(port: 18080).toString();
  return controlPort == normalized ? [normalized] : [controlPort, normalized];
}

bool _isRetryableAuthEndpointError(ControlApiException error) {
  final message = error.message;
  return message.startsWith('无法连接控制服务器') ||
      message.startsWith('无法解析控制服务器域名') ||
      message.startsWith('Windows 无法建立到控制服务器的连接') ||
      message.startsWith('控制服务器网络请求失败') ||
      message.startsWith('控制服务器 TLS 握手失败') ||
      message.startsWith('连接控制服务器超时') ||
      message.startsWith('控制服务器返回了无法解析的数据');
}

class ControlApiException implements Exception {
  const ControlApiException(this.message);

  final String message;

  @override
  String toString() => message;
}

String _zhSupportLogUploadError(String? message, int statusCode) {
  if (statusCode == 401) return '登录状态已过期，请重新登录后再上传日志';
  if (statusCode == 403) return '当前账号没有上传日志的权限，请联系服务器管理员';
  if (statusCode == 404) return '控制服务器暂不支持日志上传，请先更新服务端';
  if (statusCode == 413) return '日志文件过大，请缩短本次启动时间后再试';
  if (statusCode == 429) return '日志上传过于频繁，请稍后再试';
  final normalized = (message?.trim().toLowerCase() ?? '').replaceAll('_', ' ');
  if (normalized == 'support log storage failed') {
    return '控制服务器无法保存日志，请联系管理员检查日志存储权限或剩余空间，修复后再试';
  }
  if (normalized.contains('schema version')) {
    return '控制服务器不支持多房间日志格式(schema v2)，请升级服务端后再试';
  }
  if (normalized.contains('manifest') &&
      normalized.contains('total instances')) {
    return '日志包实例清单与实际文件不一致，请重试上传';
  }
  // Error bodies can contain internal paths, credentials or echoed logs.
  // Only recognized errors above are translated; unknown text stays private.
  if (statusCode >= 500) {
    return '控制服务器暂时无法处理日志上传（HTTP $statusCode），请稍后重试或联系服务器管理员';
  }
  return '日志上传失败（HTTP $statusCode），请稍后重试；若持续失败，请联系服务器管理员';
}

String _zhAuthError(
  String? message, [
  int? statusCode,
  String? unauthorizedMessage,
]) {
  final raw = message?.trim() ?? '';
  final normalized = raw.toLowerCase();
  if (statusCode == 401) return unauthorizedMessage ?? '认证失败，请检查邮箱和密码';
  if (statusCode == 403) return '当前账号没有权限执行该操作';
  if (statusCode == 404) return '控制服务器暂不支持该接口，请先更新服务端';
  if (statusCode == 409) return '账号已存在';
  if (statusCode == 413) return '日志文件过大，请缩短本次启动时间后再试';
  if (normalized.contains('invalid credentials')) return '邮箱或密码错误';
  if (normalized.contains('invalid email or username')) {
    return '邮箱或用户名格式不正确';
  }
  if (normalized.contains('invalid email')) return '邮箱格式不正确';
  if (normalized.contains('invalid password')) return '密码不符合要求，至少需要 6 个字符';
  if (normalized.contains('registration failed')) return '注册失败，邮箱可能已存在';
  if (normalized.contains('rate limit')) return '请求过于频繁，请稍后再试';
  if (normalized.contains('schema_version') ||
      normalized.contains('schema version')) {
    return '控制服务器不支持多房间日志格式(schema v2)，请升级服务端后再试';
  }
  if (normalized.contains('manifest') &&
      normalized.contains('total_instances')) {
    return '日志包实例清单与实际文件不一致，请重试上传';
  }
  return raw.isEmpty ? '控制服务器请求失败' : raw;
}

String _zhNetworkError(SocketException error, Uri uri) {
  final osMessage = error.osError?.message.toLowerCase() ?? '';
  final message = error.message.toLowerCase();
  if (osMessage.contains('nodename nor servname') ||
      osMessage.contains('name or service not known') ||
      osMessage.contains('no address associated') ||
      message.contains('failed host lookup')) {
    return '无法解析控制服务器域名：${uri.host}。请检查网络，或把控制面服务器改为可访问地址。';
  }
  if (osMessage.contains('connection refused') ||
      message.contains('connection refused')) {
    return '无法连接控制服务器：${uri.origin}。请确认服务端已启动且地址/端口正确。';
  }
  if (osMessage.contains('socket is not connected') ||
      osMessage.contains('no address') ||
      osMessage.contains('sendto') ||
      osMessage.contains('套接字没有连接') ||
      osMessage.contains('没有提供地址') ||
      message.contains('socket is not connected') ||
      message.contains('no address') ||
      message.contains('sendto') ||
      message.contains('套接字没有连接') ||
      message.contains('没有提供地址')) {
    return 'Windows 无法建立到控制服务器的连接：${uri.origin}。请检查代理/VPN/防火墙，或在浏览器打开 ${uri.origin}/health 验证是否返回 ok。';
  }
  return '控制服务器网络请求失败：${error.message}';
}
