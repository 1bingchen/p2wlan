part of '../daemon_controller.dart';

/// A chmod failure is kept typed; helper output can contain local paths and
/// is not needed to decide whether the one bounded ownership repair applies.
class PosixLaunchPathProtectionException implements Exception {
  const PosixLaunchPathProtectionException({
    required this.directory,
    required this.exitCode,
  });

  final bool directory;
  final int exitCode;

  @override
  String toString() =>
      'POSIX permissions failed: target=${directory ? 'directory' : 'file'} '
      'exit_code=$exitCode';
}

class UnsafeLaunchPathException implements Exception {
  const UnsafeLaunchPathException();

  @override
  String toString() =>
      'The runtime path is not a safe regular file or directory.';
}

class RuntimeDirectoryRepairException implements Exception {
  const RuntimeDirectoryRepairException();

  @override
  String toString() => 'The daemon runtime directory ownership repair failed.';
}

bool isPosixRuntimePermissionFailure(Object error) =>
    error is PosixLaunchPathProtectionException ||
    error is FileSystemException &&
        const {1, 13}.contains(error.osError?.errorCode);

/// A failed user-level protection gets at most one elevated repair, followed
/// by a mandatory user-level verification. Cancellation, unsafe paths and
/// non-permission failures never start a daemon or create a launch token.
class RuntimeDirectoryPreparer {
  const RuntimeDirectoryPreparer({required this.protect, required this.repair});

  final Future<void> Function(Directory directory) protect;
  final Future<void> Function(Directory directory)? repair;

  Future<void> prepare(Directory directory) async {
    try {
      await protect(directory);
    } catch (error) {
      final recover = repair;
      if (recover == null || !isPosixRuntimePermissionFailure(error)) rethrow;
      await recover(directory);
      await protect(directory);
    }
  }
}

extension DaemonControllerRuntimePermissions on DaemonController {
  Future<String?> _preparePosixRuntimeDirectories({
    required File binary,
    required File config,
    required Directory runtime,
    required bool allowElevation,
    String? password,
  }) async {
    var activePassword = password;
    final preparer = RuntimeDirectoryPreparer(
      protect: (directory) async {
        await protectRuntimeDirectory(directory);
        if (directory.path == config.parent.path && await config.exists()) {
          await _restrictLaunchPath(config.path);
        }
      },
      repair: !allowElevation
          ? null
          : (directory) async {
              final args = ['--prepare-runtime-directory', directory.path];
              if (Platform.isMacOS) {
                final repaired = await _startMacosElevated(
                  '${_shellQuote(binary.path)} ${args.map(_shellQuote).join(' ')}',
                  password: activePassword,
                );
                // Retain only for this start, so a newly prompted password is
                // reused even when no persistence callback was supplied.
                activePassword = repaired.password;
              } else if (Platform.isLinux) {
                await _repairLinuxRuntimeDirectory(binary, args);
              } else {
                throw const RuntimeDirectoryRepairException();
              }
            },
    );
    await preparer.prepare(config.parent);
    if (runtime.path != config.parent.path) await preparer.prepare(runtime);
    return activePassword;
  }

  Future<void> _repairLinuxRuntimeDirectory(
    File binary,
    List<String> args,
  ) async {
    final pkexec = await _which('pkexec');
    if (pkexec == null) throw const RuntimeDirectoryRepairException();
    final process = await Process.start(pkexec.path, [binary.path, ...args]);
    await process.stdin.close();
    final stdoutDrain = process.stdout.listen((_) {}, onError: (Object _) {});
    final stderrDrain = process.stderr.listen((_) {}, onError: (Object _) {});
    try {
      final exitCode = await process.exitCode.timeout(
        const Duration(seconds: 45),
      );
      if (exitCode != 0) throw const RuntimeDirectoryRepairException();
    } on TimeoutException {
      process.kill();
      throw const RuntimeDirectoryRepairException();
    } finally {
      // No helper diagnostics are copied into logs or user-facing messages.
      // Cancel the owned listeners even if a privileged child retained a
      // pipe; timing out a drain Future alone would leave it subscribed.
      await Future.wait([stdoutDrain.cancel(), stderrDrain.cancel()])
          .timeout(const Duration(seconds: 1), onTimeout: () => <void>[]);
    }
  }
}
