import 'dart:async';
import 'dart:ffi';
import 'dart:io';

enum WindowsProcessState { running, exited, unavailable }

/// A failed OS query is not evidence that the child has exited. Keep the
/// native error separate so startup can report the actual failed boundary.
class WindowsProcessProbe {
  const WindowsProcessProbe.running(this.imagePath)
    : state = WindowsProcessState.running,
      exitCode = null,
      operation = null,
      win32Error = null;

  const WindowsProcessProbe.exited([this.exitCode])
    : state = WindowsProcessState.exited,
      imagePath = null,
      operation = null,
      win32Error = null;

  const WindowsProcessProbe.unavailable(this.operation, [this.win32Error])
    : state = WindowsProcessState.unavailable,
      imagePath = null,
      exitCode = null;

  final WindowsProcessState state;
  final String? imagePath;
  final int? exitCode;
  final String? operation;
  final int? win32Error;

  String? get processName => imagePath?.split(RegExp(r'[/\\]')).last;
}

/// Query the exact OS-returned PID without starting PowerShell or using WMI.
/// Limited-information access works across the normal/elevated boundary;
/// access denial stays an explicit failure, never a successful identity.
WindowsProcessProbe queryWindowsProcess(int processId) {
  if (!Platform.isWindows) {
    return const WindowsProcessProbe.unavailable('unsupported_platform');
  }
  if (processId <= 0 || processId > 0xffffffff) {
    return const WindowsProcessProbe.unavailable('invalid_pid');
  }
  try {
    return _WindowsProcessApi.instance.query(processId);
  } on ArgumentError {
    return const WindowsProcessProbe.unavailable('api_unavailable');
  }
}

/// Only unavailable queries are retried. A live process with a different
/// image or a confirmed exit must not be replaced by a later reused PID.
Future<WindowsProcessProbe> waitForWindowsProcess(
  int processId, {
  WindowsProcessProbe Function(int) query = queryWindowsProcess,
  Duration timeout = const Duration(seconds: 3),
  Duration pollInterval = const Duration(milliseconds: 100),
}) async {
  final clock = Stopwatch()..start();
  var result = query(processId);
  while (result.state == WindowsProcessState.unavailable) {
    final remaining = timeout - clock.elapsed;
    if (remaining <= Duration.zero) break;
    await Future<void>.delayed(
      pollInterval < remaining ? pollInterval : remaining,
    );
    if (clock.elapsed >= timeout) break;
    result = query(processId);
  }
  return result;
}

class _WindowsProcessApi {
  static final instance = _WindowsProcessApi();

  // QueryFullProcessImageNameW and GetExitCodeProcess require only this
  // right, not PROCESS_ALL_ACCESS or access to the target's virtual memory.
  static const _queryLimitedInformation = 0x1000;
  static const _stillActive = 259;
  static const _invalidParameter = 87;
  static const _pathCapacity = 32768;

  final _kernel = DynamicLibrary.open('kernel32.dll');
  late final _openProcess = _kernel
      .lookupFunction<
        Pointer<Void> Function(Uint32, Int32, Uint32),
        Pointer<Void> Function(int, int, int)
      >('OpenProcess');
  late final _closeHandle = _kernel
      .lookupFunction<
        Int32 Function(Pointer<Void>),
        int Function(Pointer<Void>)
      >('CloseHandle');
  late final _getLastError = _kernel
      .lookupFunction<Uint32 Function(), int Function()>('GetLastError');
  late final _getProcessHeap = _kernel
      .lookupFunction<Pointer<Void> Function(), Pointer<Void> Function()>(
        'GetProcessHeap',
      );
  late final _heapAlloc = _kernel
      .lookupFunction<
        Pointer<Void> Function(Pointer<Void>, Uint32, UintPtr),
        Pointer<Void> Function(Pointer<Void>, int, int)
      >('HeapAlloc');
  late final _heapFree = _kernel
      .lookupFunction<
        Int32 Function(Pointer<Void>, Uint32, Pointer<Void>),
        int Function(Pointer<Void>, int, Pointer<Void>)
      >('HeapFree');
  late final _getExitCode = _kernel
      .lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<Uint32>),
        int Function(Pointer<Void>, Pointer<Uint32>)
      >('GetExitCodeProcess');
  late final _queryImageName = _kernel
      .lookupFunction<
        Int32 Function(Pointer<Void>, Uint32, Pointer<Uint16>, Pointer<Uint32>),
        int Function(Pointer<Void>, int, Pointer<Uint16>, Pointer<Uint32>)
      >('QueryFullProcessImageNameW');

  WindowsProcessProbe query(int processId) {
    final process = _openProcess(_queryLimitedInformation, 0, processId);
    if (process == nullptr) {
      final error = _getLastError();
      // A positive PID that no longer exists is rejected by OpenProcess.
      return error == _invalidParameter
          ? const WindowsProcessProbe.exited()
          : WindowsProcessProbe.unavailable('open_process', error);
    }
    try {
      final heap = _getProcessHeap();
      if (heap == nullptr) {
        return WindowsProcessProbe.unavailable('process_heap', _getLastError());
      }
      // One bounded allocation holds a DWORD result and the UTF-16 image
      // path. All buffers and the process handle are released on every path.
      final buffer = _heapAlloc(heap, 0, 4 + _pathCapacity * 2);
      if (buffer == nullptr) {
        return const WindowsProcessProbe.unavailable('allocate_buffer', 8);
      }
      try {
        final value = buffer.cast<Uint32>();
        if (_getExitCode(process, value) == 0) {
          return WindowsProcessProbe.unavailable('exit_code', _getLastError());
        }
        if (value.value != _stillActive) {
          return WindowsProcessProbe.exited(value.value);
        }
        final path = (buffer.cast<Uint8>() + 4).cast<Uint16>();
        value.value = _pathCapacity;
        if (_queryImageName(process, 0, path, value) == 0) {
          return WindowsProcessProbe.unavailable('image_name', _getLastError());
        }
        final length = value.value;
        if (length == 0 || length >= _pathCapacity) {
          return const WindowsProcessProbe.unavailable('invalid_image_name');
        }
        final imagePath = String.fromCharCodes(path.asTypedList(length));
        if (_getExitCode(process, value) == 0) {
          return WindowsProcessProbe.unavailable('exit_code', _getLastError());
        }
        return value.value == _stillActive
            ? WindowsProcessProbe.running(imagePath)
            : WindowsProcessProbe.exited(value.value);
      } finally {
        _heapFree(heap, 0, buffer);
      }
    } finally {
      _closeHandle(process);
    }
  }
}
