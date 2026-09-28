import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import '../daemon/diagnostics_auth.dart';
import '../security/redactor.dart';
import 'support_log_protocol.dart';
import 'support_status_summary.dart';

// Mobile log uploads must not make the Flutter UI hold several copies of a
// multi-megabyte, high-volume daemon log while it is being redacted and
// compressed. The tail is still large enough to include the recent failure
// timeline, while keeping Android memory pressure predictable.
const maxCurrentSessionLogBytesPerFile = 1 * 1024 * 1024;

class SessionLogFile {
  const SessionLogFile({required this.name, required this.content});

  final String name;
  final String content;
}

class CurrentSessionLogBundle {
  const CurrentSessionLogBundle({
    required this.files,
    this.omittedRoomProfileIds = const [],
  });

  final List<SessionLogFile> files;
  final List<String> omittedRoomProfileIds;

  /// Collect the files from the platform-specific directory used by the
  /// running daemon. Android resolves this through the native Context because
  /// its private files directory is not exposed as a stable HOME path.
  static Future<CurrentSessionLogBundle> collectCurrentStartup({
    int maxBytesPerFile = maxCurrentSessionLogBytesPerFile,
    List<String> activeRoomProfileIds = const [],
    Map<String, String> dynamicSummaries = const {},
  }) async {
    final directory = await resolveP2WlanLogDir();
    final separator = Platform.pathSeparator;
    final roomSelection = selectSupportLogRoomProfiles(activeRoomProfileIds);
    final roomProfileIds = roomSelection.retainedProfileIds;
    final summaries = <String, String>{
      for (final profileId in roomProfileIds)
        if ((dynamicSummaries[profileId] ?? '').trim().isNotEmpty)
          profileId: dynamicSummaries[profileId]!,
    };
    // File reads and redaction are CPU/memory work from the UI's point of
    // view. Keep the platform channel lookup above on the main isolate, then
    // do the actual collection in a worker isolate.
    final serializedFiles = await Isolate.run(
      () => _collectCurrentStartupFiles(
        daemonLogPath: '${directory.path}${separator}p2wlan-daemon.log',
        clientLogPath: '${directory.path}${separator}p2wlan-client.log',
        logDirPath: directory.path,
        activeRoomProfileIds: roomProfileIds,
        dynamicSummaries: summaries,
        maxBytesPerFile: maxBytesPerFile.clamp(
          1,
          maxCurrentSessionLogBytesPerFile,
        ),
      ),
    );
    return CurrentSessionLogBundle(
      files: List.unmodifiable(
        serializedFiles.map(
          (file) =>
              SessionLogFile(name: file['name']!, content: file['content']!),
        ),
      ),
      omittedRoomProfileIds: roomSelection.omittedProfileIds,
    );
  }

  /// Read only the files that represent the current daemon startup.
  /// Rotated `.1` files are deliberately never consulted.
  static Future<CurrentSessionLogBundle> collect({
    required String daemonLogPath,
    required String clientLogPath,
    List<({String name, String path})> extraFiles = const [],
    List<SessionLogFile> inlineFiles = const [],
    int maxBytesPerFile = maxCurrentSessionLogBytesPerFile,
    bool redactFiles = true,
  }) async {
    final candidates = <({String name, String path})>[
      (name: 'p2wlan-daemon.log', path: daemonLogPath),
      (name: 'p2wlan-client.log', path: clientLogPath),
      ...extraFiles,
    ];
    final files = <SessionLogFile>[];
    final seenPaths = <String>{};
    final seenNames = <String>{};
    for (final candidate in candidates) {
      final normalizedPath = candidate.path.trim();
      if (normalizedPath.isEmpty || !seenPaths.add(normalizedPath)) continue;
      final file = File(normalizedPath);
      if (!await file.exists()) continue;
      final rawContent = await _readCurrentFile(file, maxBytesPerFile);
      final content = candidate.name.endsWith('status-summary.json')
          ? sanitizeSupportStatusSummary(rawContent)
          : redactFiles
          ? redactSensitive(rawContent)
          : rawContent;
      if (content.trim().isEmpty || !seenNames.add(candidate.name)) continue;
      files.add(SessionLogFile(name: candidate.name, content: content));
    }
    for (final file in inlineFiles) {
      final name = file.name.trim();
      if (name.isEmpty || !seenNames.add(name)) continue;
      final rawContent = name.endsWith('status-summary.json')
          ? sanitizeSupportStatusSummary(file.content)
          : _truncateInlineContent(file.content, maxBytesPerFile);
      final content = redactFiles ? redactSensitive(rawContent) : rawContent;
      if (content.trim().isEmpty) continue;
      files.add(SessionLogFile(name: name, content: content));
    }
    if (files.isEmpty) {
      throw const FileSystemException(
        'No current startup log files were found.',
      );
    }
    return CurrentSessionLogBundle(files: List.unmodifiable(files));
  }
}

Future<List<Map<String, String>>> _collectCurrentStartupFiles({
  required String daemonLogPath,
  required String clientLogPath,
  required String logDirPath,
  required List<String> activeRoomProfileIds,
  required Map<String, String> dynamicSummaries,
  required int maxBytesPerFile,
}) async {
  final separator = Platform.pathSeparator;
  final extraFiles = <({String name, String path})>[];
  final inlineFiles = <SessionLogFile>[];
  for (final profileId in activeRoomProfileIds) {
    final daemonPath =
        '$logDirPath$separator'
        'rooms$separator'
        '$profileId$separator'
        'p2wlan-daemon.log';
    if (await File(daemonPath).exists()) {
      extraFiles.add((
        name: 'rooms/$profileId/p2wlan-daemon.log',
        path: daemonPath,
      ));
    }
    final dynamicSummary = dynamicSummaries[profileId];
    if (dynamicSummary != null && dynamicSummary.trim().isNotEmpty) {
      // The summary is assembled from the current in-memory room lifecycle,
      // including failures before the daemon ever exposes /status.  Keeping it
      // inline avoids synchronously writing a support artifact on the UI
      // isolate and avoids relying on a file that a failed process never made.
      inlineFiles.add(
        SessionLogFile(
          name: 'rooms/$profileId/status-summary.json',
          content: dynamicSummary,
        ),
      );
    } else {
      final summaryPath =
          '$logDirPath$separator'
          'rooms$separator'
          '$profileId$separator'
          'status-summary.json';
      if (await File(summaryPath).exists()) {
        extraFiles.add((
          name: 'rooms/$profileId/status-summary.json',
          path: summaryPath,
        ));
      }
    }
  }
  final bundle = await CurrentSessionLogBundle.collect(
    daemonLogPath: daemonLogPath,
    clientLogPath: clientLogPath,
    extraFiles: extraFiles,
    inlineFiles: inlineFiles,
    maxBytesPerFile: maxBytesPerFile,
    // The upload encoder is the final redaction boundary. Keeping the file
    // raw here avoids doing the same expensive pass twice in worker isolates.
    redactFiles: false,
  );
  return bundle.files
      .map(
        (file) => <String, String>{'name': file.name, 'content': file.content},
      )
      .toList(growable: false);
}

String _truncateInlineContent(String content, int maxBytes) {
  if (maxBytes <= 0) {
    throw ArgumentError('maxBytes must be positive');
  }
  final bytes = utf8.encode(content);
  if (bytes.length <= maxBytes) return content;
  final tail = utf8.decode(
    bytes.sublist(bytes.length - maxBytes),
    allowMalformed: true,
  );
  return '[p2wlan] generated status summary exceeded $maxBytes bytes; '
      'showing its tail only.\n$tail';
}

Future<String> _readCurrentFile(File file, int maxBytes) async {
  if (maxBytes <= 0) {
    throw ArgumentError('maxBytes must be positive');
  }
  final length = await file.length();
  final truncated = length > maxBytes;
  final start = truncated ? length - maxBytes : 0;
  final bytes = <int>[];
  await for (final chunk in file.openRead(start, length)) {
    bytes.addAll(chunk);
  }
  final decoded = utf8.decode(bytes, allowMalformed: true);
  if (!truncated) return decoded;
  return '[p2wlan] current startup log exceeded $maxBytes bytes; '
      'showing its tail only.\n$decoded';
}
