part of '../daemon_controller.dart';

/// Best-effort desktop launcher diagnostics. Windows retains its established
/// prefix. This file contains stage names and redacted identity
/// facts only; it never receives the daemon argument list or auth token.
class WindowsStartupTrace {
  WindowsStartupTrace(
    this.logDir, {
    this.clientBuild = ClientBuildInfo.current,
    this.platform = 'windows',
  });

  static const fileName = 'p2wlan-client.log';

  final Directory logDir;
  final ClientBuildInfo clientBuild;
  final String platform;
  final List<String> _entries = [];

  /// Retain a bounded receipt even when the failing runtime directory also
  /// prevents writing the client log. Each new start owns a fresh trace.
  List<String> get entries => List.unmodifiable(_entries);

  String get _prefix => '[$platform-startup]';

  File get file => File('${logDir.path}${Platform.pathSeparator}$fileName');

  String get path => file.path;

  Future<void> open() async {
    try {
      await logDir.create(recursive: true);
      final previous = File('${file.path}.1');
      if (await previous.exists()) await previous.delete();
      if (await file.exists()) await file.rename(previous.path);
      await file.writeAsString('', flush: true);
    } catch (_) {
      // Client logging must never prevent a UAC attempt.  Every subsequent
      // write also remains best effort for the same reason.
    }
  }

  Future<void> startRequested() async {
    await _write('start requested');
    await _write(
      'client build identity app_version=${clientBuild.appVersion} '
      'git_commit=${clientBuild.gitCommit} build_id=${clientBuild.buildId} '
      'dirty=${clientBuild.dirtyLabel} diff_hash=${clientBuild.diffHash} '
      'profile=${clientBuild.profile}',
    );
  }

  Future<void> detail(String message) => _write(message);

  Future<void> stageStart(int number, String name) =>
      _write('${_stage(number)} $name START');

  Future<void> stageOk(int number, String name) =>
      _write('${_stage(number)} $name OK');

  Future<void> stageAccepted(int number, String name) =>
      _write('${_stage(number)} $name ACCEPTED');

  Future<void> stageSkipped(int number, String name) =>
      _write('${_stage(number)} $name SKIPPED');

  Future<void> childPid(int pid) => _write('${_stage(9)} child_pid PID=$pid');

  Future<void> daemonAlive() => _write('${_stage(10)} daemon_alive OK');

  Future<void> failure(int stage, String code) =>
      _write('FAIL stage=${stage.toString().padLeft(2, '0')} code=$code');

  String _stage(int number) => '$_prefix ${number.toString().padLeft(2, '0')}';

  Future<void> _write(String message) async {
    var sanitized = message.replaceAll(RegExp(r'[\r\n]+'), ' ').trim();
    if (sanitized.isEmpty) return;
    if (sanitized.length > 1024) sanitized = sanitized.substring(0, 1024);
    final prefix = sanitized.startsWith(_prefix) ? '' : '$_prefix ';
    final entry = '${DateTime.now().toIso8601String()} $prefix$sanitized';
    if (_entries.length == 64) _entries.removeAt(0);
    _entries.add(entry);
    try {
      await logDir.create(recursive: true);
      await file.writeAsString('$entry\n', mode: FileMode.append, flush: true);
    } catch (_) {}
  }
}
