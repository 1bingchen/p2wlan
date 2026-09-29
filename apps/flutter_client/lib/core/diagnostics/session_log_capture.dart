import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

const _coverageReserveBytes = 1024;
const _segmentHeaderBytes = 192;
const _maxArchiveSegments = 4;
const _gap = '\n[p2wlan-log-gap]\n';
final _segmentPattern = RegExp(
  r'^\[p2wlan-log-segment\] version=1 runtime_id=([0-9a-f]{32}) segment=(\d+)\n',
);

typedef _Segment = ({String runtimeId, int number});

/// Capture startup context and recent events under one byte budget. An archive
/// is eligible only when its immutable segment header proves a consecutive
/// chain to the current file in the same daemon runtime (at most four archives). File descriptors stay
/// open while inspecting headers and reading ranges, so a rename cannot switch
/// the file underneath a verified identity.
Future<String> readCurrentRuntimeLog(File current, int maxBytes) async {
  if (maxBytes <= 0) throw ArgumentError('maxBytes must be positive');
  if (maxBytes <= _coverageReserveBytes) {
    const notice = '[p2wlan-log-coverage] budget_too_small\n';
    return notice.substring(0, math.min(notice.length, maxBytes));
  }
  for (var attempt = 0; attempt < 2; attempt++) {
    final sources = <_LogSource>[];
    try {
      final latest = await _LogSource.open(current, 'current');
      sources.add(latest);
      var archiveStatus = 'marker_missing';
      var archiveStop = 'marker_missing';
      if (latest.segment != null) {
        archiveStatus = 'absent';
        archiveStop = 'retention_limit';
        for (var number = 1; number <= _maxArchiveSegments; number++) {
          final earliest = sources.first.segment!;
          if (earliest.number == 0) {
            archiveStop = 'runtime_start';
            break;
          }
          try {
            final previous = await _LogSource.open(
              File('${current.path}.$number'),
              'previous_$number',
            );
            sources.insert(0, previous);
            final previousSegment = previous.segment;
            if (previousSegment != null &&
                previousSegment.runtimeId == earliest.runtimeId &&
                previousSegment.number + 1 == earliest.number) {
              archiveStatus = 'same_runtime_consecutive';
            } else {
              sources.removeAt(0);
              await previous.handle.close();
              archiveStop = 'identity_mismatch';
              if (sources.length == 1) archiveStatus = archiveStop;
              break;
            }
          } on FileSystemException catch (error) {
            archiveStop = error.osError?.errorCode == 2
                ? 'absent'
                : 'unreadable';
            if (sources.length == 1) archiveStatus = archiveStop;
            break;
          }
        }
        if (sources.first.segment!.number == 0) archiveStop = 'runtime_start';
      }
      final sourceBytes = sources.fold(0, (sum, source) => sum + source.length);
      final budget = maxBytes - _coverageReserveBytes;
      final ranges = <({int start, int end})>[];
      if (sourceBytes <= budget) {
        ranges.add((start: 0, end: sourceBytes));
      } else {
        // Startup gets one quarter of the budget; recent events keep three
        // quarters. The same bound covers both current and previous segments.
        final headBytes = budget ~/ 4;
        ranges.add((start: 0, end: headBytes));
        ranges.add((
          start: sourceBytes - (budget - headBytes),
          end: sourceBytes,
        ));
      }
      final fragments = <String>[];
      final coverage = <Map<String, Object>>[];
      var capturedBytes = 0;
      int? previousEnd;
      for (final range in ranges) {
        var offset = 0;
        for (final source in sources) {
          final start = math.max(0, range.start - offset);
          final end = math.min(source.length, range.end - offset);
          offset += source.length;
          if (start >= end) continue;
          final fragment = await source.readLines(start, end);
          if (fragment.bytes == 0) continue;
          capturedBytes += fragment.bytes;
          final absoluteStart = offset - source.length + fragment.start;
          if (previousEnd != null && absoluteStart > previousEnd) {
            fragments.add(_gap);
          }
          fragments.add(fragment.text);
          previousEnd = absoluteStart + fragment.bytes;
          coverage.add({
            'source': source.name,
            if (source.segment != null) 'segment': source.segment!.number,
            'start': fragment.start,
            'end': fragment.start + fragment.bytes,
          });
        }
      }
      // A new daemon can replace the pathname while the old descriptor is
      // still readable. Retry once, then return an explicit gap without stale
      // content. Capacity rotation within the same runtime remains a valid
      // point-in-time snapshot and is reported separately.
      final sampled = latest.segment;
      var rotatedDuringRead = false;
      if (sampled != null) {
        _LogSource? observed;
        try {
          observed = await _LogSource.open(current, 'current');
          if (observed.segment?.runtimeId != sampled.runtimeId) continue;
          rotatedDuringRead = observed.segment!.number != sampled.number;
        } on FileSystemException {
          continue;
        } finally {
          await observed?.handle.close();
        }
      }
      final metadata = <String, Object>{
        'version': 1,
        'scope': sampled == null ? 'legacy_current_file' : 'verified_runtime',
        'archive': archiveStatus,
        'archive_stop': archiveStop,
        'segments_retained': sources.length,
        'source_bytes': sourceBytes,
        'captured_bytes': capturedBytes,
        'omitted_bytes': sourceBytes - capturedBytes,
        'startup_retained':
            sources.first.segment?.number == 0 &&
            coverage.isNotEmpty &&
            coverage.first['start'] == 0,
        'older_segments_unavailable':
            sources.first.segment?.number != 0 && sampled != null,
        'rotated_during_read': rotatedDuringRead,
        'ranges': coverage,
      };
      return '[p2wlan-log-coverage] ${jsonEncode(metadata)}\n'
          '${fragments.join()}';
    } on FileSystemException {
      if (attempt == 1) {
        return '[p2wlan-log-coverage] {"version":1,"scope":"unreadable",'
            '"content_omitted":true}\n';
      }
    } finally {
      for (final source in sources) {
        await source.handle.close();
      }
    }
  }
  return '[p2wlan-log-coverage] {"version":1,"scope":"runtime_changed",'
      '"content_omitted":true}\n';
}

class _LogSource {
  _LogSource(this.handle, this.name, this.length, this.segment);
  final RandomAccessFile handle;
  final String name;
  final int length;
  final _Segment? segment;

  static Future<_LogSource> open(File file, String name) async {
    final handle = await file.open();
    try {
      final length = await handle.length();
      final header = utf8.decode(
        await handle.read(math.min(length, _segmentHeaderBytes)),
        allowMalformed: true,
      );
      final match = _segmentPattern.firstMatch(header);
      final number = match == null ? null : int.tryParse(match.group(2)!);
      return _LogSource(
        handle,
        name,
        length,
        match == null || number == null
            ? null
            : (runtimeId: match.group(1)!, number: number),
      );
    } catch (_) {
      await handle.close();
      rethrow;
    }
  }

  Future<({String text, int start, int bytes})> readLines(
    int start,
    int end,
  ) async {
    // Inspect one preceding byte to avoid dropping a whole line when the
    // selected range already starts at a boundary. Never emit a sliced token.
    final readStart = start > 0 ? start - 1 : 0;
    await handle.setPosition(readStart);
    final bytes = await handle.read(end - readStart);
    var begin = start - readStart;
    if (start > 0 && bytes.isNotEmpty && bytes[0] != 10) {
      final newline = bytes.indexOf(10, begin);
      begin = newline < 0 ? bytes.length : newline + 1;
    }
    var finish = bytes.length;
    if (end < length && finish > begin && bytes[finish - 1] != 10) {
      finish = bytes.lastIndexOf(10) + 1;
    }
    if (finish <= begin) return (text: '', start: start, bytes: 0);
    return (
      text: utf8
          .decode(bytes.sublist(begin, finish), allowMalformed: true)
          .replaceAll('\uFFFD', '?'),
      start: readStart + begin,
      bytes: finish - begin,
    );
  }
}
