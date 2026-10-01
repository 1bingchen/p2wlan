import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

// This is an export projection, never a second source of connection state.
const maxSupportStatusBytes = 64 * 1024;
const maxSupportStatusPeerBytes = 16 * 1024;
const maxSupportStatusPeers = 8;
const maxSupportStatusEvents = 24;
const maxSupportStatusAttempts = 4;

/// Explicit fields only: free-form detail/error/message, secrets, packet data,
/// paths, URLs, names and raw session identifiers are intentionally absent.
const _scalars = {
  'schema_version',
  'contract_version',
  'contractVersion',
  'kind',
  'model',
  'strategy',
  'capability',
  'fallback',
  'background_reclaim',
  'relay_available',
  'remote_profile_fresh',
  'network_hint',
  'process_id',
  'runtime_incarnation',
  'revision',
  'captured_revision',
  'captured_at_ms',
  'peer_snapshot_stale',
  'peer_snapshot_age_ms',
  'peer_snapshot_shape',
  'network_generation',
  'connection_generation',
  'uptime_ms',
  'ready_phase',
  'udp_socket_count',
  'udp_socket_pool_active',
  'relay_connected',
  'candidate_snapshot_version',
  'candidate_snapshot_hash',
  'mapping_behavior',
  'filtering_behavior',
  'hairpin_behavior',
  'mapping_lifetime',
  'udp_blocked',
  'public_ip_stable',
  'public_port_stable',
  'port_preserved',
  'port_delta',
  'likely_symmetric',
  'confidence',
  'prediction_candidate',
  'birthday_candidate',
  'prediction_confidence',
  'prediction_window',
  'profile_generation',
  'step',
  'direction',
  'rtt_ms',
  'online',
  'last_seen',
  'state',
  'active_path',
  'direct_type',
  'direct_generation',
  'remote_candidate_generation',
  'remote_candidate_epoch',
  'remote_nat_profile_generation',
  'remote_nat_profile_received_at_ms',
  'remote_nat_profile_fresh',
  'peer_session_generation',
  'direct_retry_after_ms',
  'direct_retry_remaining_ms',
  'stage',
  'age_ms',
  'at_ms',
  'event',
  'candidate_count',
  'sent_probes',
  'probe_tx_socket0_count',
  'probe_tx_alt_socket_count',
  'probe_tx_unique_target_ports',
  'probe_tx_repeated_target_ports',
  'validation_session_id',
  'remote_validation_owner',
  'request_id',
  'socket_index',
  'ack_endpoint_authenticated',
  'validation_rtt_ms',
  'role',
  'mode',
  'attempt',
  'local_profile_generation',
  'remote_profile_generation',
  'punch_generation',
  'candidate_cap',
  'truncation_reason',
  'confirmed_target_rank',
  'probe_packets_received',
  'matched_probe_acks',
  'authenticated_probe_packets_received',
  'authenticated_probe_acks_unmatched',
  'direct_confirmed',
  'failure_class',
  'terminal_reason',
  'requested',
  'generated',
  'unique',
  'advertised',
  'parsed_targets_for_plan',
  'planned_targets',
  'planned_sockets',
  'planned_socket_target_combinations',
  'planned_logical_probes',
  'planned_physical_datagram_cap',
  'attempted_targets',
  'logical_probes_attempted',
  'logical_probes_sent',
  'send_success_datagrams',
  'send_success_bytes',
  'send_errors',
  'send_error_bytes',
  'budget_skipped',
  'planned_logical_probes_not_attempted',
  'stun_send_success_datagrams',
  'stun_send_success_bytes',
  'stun_send_errors',
  'stun_send_error_bytes',
  'stun_responses',
  'candidate_signal_payload_logic_bytes',
  'measurement_started_at_ms',
  'last_measurement_send_at_ms',
  'measurement_completed_at_ms',
  'candidate_signal_accepted_at_ms',
  'planned_send_at_ms',
  'send_dispatch_at_ms',
  'actual_first_send_at_ms',
  'probe_last_hit_at_ms',
  'probe_last_hit_source',
  'encrypted_validation_completed_at_ms',
  'business_ready_at_ms',
  'first_business_success_at_ms',
  'measurement_age_at_send_ms',
  'measurement_to_first_send_ms',
  'schedule_deviation_ms',
  'last_probe_hit_to_validation_ms',
  'connection_to_first_business_ms',
  'validation_to_first_business_ms',
  'business_evidence_attribution',
  'datagrams',
  'bytes',
  'retryable_not_sent',
  'budget_deferred',
  'delivery_unknown',
  'stopped',
  'requested_level',
  'generated_candidate_count',
  'signaled_candidate_count',
  'effective_target_count',
  'requested_socket_count',
  'attached_socket_count',
  'usable_socket_count',
  'unavailable_socket_count',
  'socket_count',
  'degraded_reason',
  'waves_planned',
  'waves_started',
  'waves_fully_completed',
  'waves_completed',
  'packets_planned',
  'targets_assigned',
  'targets_examined',
  'targets_attempted',
  'logical_probe_send_failures',
  'physical_datagrams_sent',
  'physical_send_errors',
  'partial_physical_send_errors',
  'targets_budget_skipped',
  'targets_cancelled',
  'stop_reason',
  'packets_sent',
  'unique_target_endpoints',
  'physical_bytes_sent',
  'physical_send_error_bytes',
  'probe_path_errors',
  'failure_kind',
  'first_send_at_ms',
  'last_send_at_ms',
  'epoch_budget_exhausted',
  'candidate_iteration_capped',
  'pacing_deadline_reached',
  'worker_failed',
  'target_processing_completed',
  'sweep_budget_stop',
  'control_connected',
  'control_api_reachable',
  'device_lease_healthy',
  'reauth_required',
  'status',
  'last_control_success_secs_ago',
  'last_device_lease_success_secs_ago',
  'total_peers',
  'direct_connections',
  'relay_connections',
  'total_bytes_sent',
  'total_bytes_received',
  'stage_age_ms',
  'epoch_age_ms',
  'probe_credit_remaining',
  'fresh_generation_quota_remaining',
  'http_quota_remaining',
  'scatter_windows_sent',
  'ack_feedback_seen',
  'predicted_top',
  'actual_port',
  'hit_window',
  'hit_rank',
  'hit_top1',
  'hit_top6',
  'hit_top24',
  'hit_top96',
  'hard_hard_generation_quota_remaining',
  'probes_remaining',
  'candidate_iterations_remaining',
  'evidence_reopens',
  'epoch',
  'path',
  'current_path',
  'previous_path',
  'lifecycle',
  'transition_reason',
  'last_path_change_reason',
  'first_direct_commit_age_ms',
  'reason_code',
  'direct_state',
  'relay_state',
  'recovery_state',
  'path_age_ms',
  'direct_commit_sequence',
  'transport_instance_id',
  'reachable',
  'local_candidates_total',
  'candidates_total',
  'predicted_endpoints_total',
  'observations_total',
  'target_order_tags_total',
  'query_failed',
  'first_usable_at_ms',
  'transition_revision',
  'relay_ready_at_ms',
  'first_usable_delta_ms',
  'direct_first_remaining_ms_at_relay_ready',
  'business_sent',
  'business_received',
  'business_exchange',
  'source',
  'last_success_age_ms',
  'last_failure_age_ms',
  'consecutive_failures',
  'last_error_code',
  'last_liveness',
  'latest_stage',
  'latest_age_ms',
  'latest_candidate_count',
  'latest_sent_probes',
  'latest_unique_target_ports',
  'latest_repeated_target_ports',
  'candidate_pair_count',
  'selected_path_mtu',
  'selected_udp_datagram_size',
  'latency_ms',
  'rtt_ewma_ms',
  'jitter_ms',
  'success_count',
  'failure_count',
  'success_rate_per_mille',
  'cooldown_remaining_ms',
  'accepted_transitions',
  'accepted_observations',
  'duplicate_events',
  'rejected_transitions',
  'path_changes',
  'direct_attempts',
  'direct_retries',
  'direct_validations',
  'direct_successes',
  'direct_failures',
  'validation_failures',
  'relay_confirmations',
  'relay_fallbacks',
  'relay_failures',
  'candidate_refreshes',
  'control_reconnects',
  'network_generation_changes',
  'lifecycle_resets',
  'dplpmtud_changes',
  'active_tasks',
  'active_sockets',
  'dropped_transition_events',
  'count',
  'sum_ms',
  'max_ms',
  'path_state_revision',
  'event_kind',
  'decision',
  'responder_binding_contended',
  'responder_binding_stale',
  'direct_ingress_contended',
  'direct_ingress_stale',
  'business_ingress_deferred',
  'business_ingress_stale',
  'outbound_flush_batches',
  'matched_ack_validation_queued',
  'matched_ack_validation_coalesced',
  'matched_ack_validation_backpressured',
  'matched_ack_validation_inactive',
  'transitions_truncated',
  'current_connection_committed',
  'archive_reason',
};
const _objects = {
  'nat_profile',
  'traversal_plan',
  'nat_capabilities',
  'remote_nat_capabilities',
  'allocation_model',
  'FixedStep',
  'Linear',
  'NoisyLinear',
  'MonotonicWindow',
  'Unpredictable',
  'Periodic',
  'counts',
  'timeline',
  'birthday_sweep',
  'confirmation',
  'triggered_check',
  'nomination',
  'probe_ack',
  'validation_request',
  'validation_ack',
  'business_attribution_identity',
  'health',
  'stats',
  'direct',
  'relay',
  'recovery',
  'path_observability',
  'current_path_selection',
  'selected_pair',
  'current_direct_pair',
  'connection_timeline',
  'hot_path_observations',
  'traversal_history',
  'direct_health',
  'relay_health',
  'metrics',
  'direct_time_to_connect_ms',
  'network_epoch',
  'epoch',
  'latest_handshake',
  'latest_validation',
  'candidate_punch',
};
const _endpoints = {
  'udp_local_addr',
  'local_addr',
  'public_endpoint',
  'stable_public_endpoint',
  'server',
  'mapped_address',
  'endpoint',
  'local_endpoint',
  'remote_endpoint',
  'expected_endpoint',
  'observed_ack_endpoint',
  'selected_endpoint',
};
const _hashes = {
  'baseline_git_commit',
  'source_git_commit',
  'git_commit',
  'build_id',
  'session_tag',
  'plan_tag',
  'binary_sha256',
  'node_id_tag',
  'peer_id_tag',
  'network_id_tag',
};

Map<String, Object?> _map(dynamic value) =>
    value is Map<String, dynamic> ? value : const {};
List<dynamic> _list(dynamic value) => value is List ? value : const [];
num _age(dynamic value) {
  final age = _map(value)['age_ms'];
  return age is num && age.isFinite ? age : 1e18;
}

String? _code(dynamic value) =>
    value is String &&
        value.length <= 96 &&
        RegExp(r'^[A-Za-z][A-Za-z0-9_-]*$').hasMatch(value)
    ? value
    : null;
String? _tag(dynamic value) =>
    value is String && value.isNotEmpty && value.length <= 256
    ? sha256.convert(utf8.encode(value)).toString().substring(0, 16)
    : null;

Map<String, Object?>? _endpoint(dynamic value, Map<String, String> aliases) {
  if (value is Map) {
    final tag = value['ip_tag'];
    final port = value['port'];
    final family = value['family'];
    if (tag is String &&
        RegExp(r'^ip[1-9][0-9]{0,2}$').hasMatch(tag) &&
        port is int &&
        port > 0 &&
        port <= 65535 &&
        (family == 'ipv4' || family == 'ipv6')) {
      return {'ip_tag': tag, 'family': family, 'port': port};
    }
    return null;
  }
  if (value is! String || value.length > 128) return null;
  final match = RegExp(r'^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$')
      .firstMatch(value);
  if (match == null) return null;
  final ip = InternetAddress.tryParse(match[1] ?? match[2]!);
  final port = int.tryParse(match[3]!);
  if (ip == null || port == null || port < 1 || port > 65535) return null;
  if (!aliases.containsKey(ip.address) && aliases.length >= 512) return null;
  return {
    'ip_tag': aliases.putIfAbsent(ip.address, () => 'ip${aliases.length + 1}'),
    'family': ip.type == InternetAddressType.IPv4 ? 'ipv4' : 'ipv6',
    'port': port,
  };
}

class _Projection {
  var remainingNodes = 8192;
  bool truncated = false;
  final Map<String, String> addressAliases = {};

  Map<String, Object?> project(dynamic raw, [int depth = 0]) {
    if (depth > 7 || remainingNodes-- <= 0) {
      truncated = true;
      return {};
    }
    final input = _map(raw);
    final result = <String, Object?>{};
    for (final key in _scalars) {
      if (!input.containsKey(key)) continue;
      final value = input[key];
      if (value == null ||
          value is bool ||
          value is int ||
          value is double && value.isFinite) {
        result[key] = value;
      } else if (_code(value) case final String code) {
        result[key] = code;
      }
    }
    for (final key in _hashes) {
      final value = input[key];
      if (value is String && RegExp(r'^[a-fA-F0-9]{8,64}$').hasMatch(value)) {
        result[key] = value;
      }
    }
    for (final key in ['version', 'app_version', 'daemon_version']) {
      final value = input[key];
      if (value is String &&
          value.length <= 48 &&
          RegExp(r'^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$').hasMatch(value)) {
        result[key] = value;
      }
    }
    for (final key in ['node_id', 'peer_id', 'network_id']) {
      if (_tag(input[key]) case final String tag) result['${key}_tag'] = tag;
    }
    for (final key in _endpoints) {
      if (_endpoint(input[key], addressAliases)
          case final Map<String, Object?> endpoint) {
        result[key] = endpoint;
      }
    }
    for (final key in _objects) {
      if (input[key] is Map) {
        result[key] = project(input[key], depth + 1);
      } else if (_code(input[key]) case final String code) {
        result[key] = code;
      }
    }
    for (final key in [
      'local_candidates',
      'candidates',
      'predicted_endpoints',
    ]) {
      if (input[key] is! List) continue;
      final values = _list(input[key]);
      result['${key}_total'] = input['${key}_total'] is int
          ? input['${key}_total']
          : values.length;
      result[key] = [
        for (final value in values.take(16))
          if (_endpoint(value, addressAliases)
              case final Map<String, Object?> endpoint)
            endpoint,
      ];
      if (values.length > 16) truncated = true;
    }
    if (input['observations'] is List) {
      final observations = _list(input['observations']);
      result['observations_total'] = input['observations_total'] is int
          ? input['observations_total']
          : observations.length;
      result['observations'] = [
        for (final value in observations.take(16))
          {
            ...project(value, depth + 1),
            'query_failed':
                _map(value)['query_failed'] == true ||
                _map(value)['error'] != null,
          },
      ];
      if (observations.length > 16) truncated = true;
    }
    for (final key in ['steps', 'sequence', 'deltas', 'target_order_tags']) {
      if (input[key] is! List) continue;
      final values = _list(input[key]);
      result['${key}_total'] = input['${key}_total'] is int
          ? input['${key}_total']
          : values.length;
      result[key] = [
        for (final value in values.take(32))
          if (value is int)
            value
          else if (key == 'target_order_tags' &&
              value is String &&
              RegExp(r'^[a-f0-9]{8,64}$').hasMatch(value))
            value,
      ];
      if (values.length > 32) truncated = true;
    }
    if (input['fresh_mapping'] is List) {
      final entries = _list(input['fresh_mapping']);
      result['fresh_mapping_total'] = input['fresh_mapping_total'] is int
          ? input['fresh_mapping_total']
          : entries.length;
      result['fresh_mapping'] = [
        for (final entry in entries.take(8))
          {
            ...project(entry, depth + 1),
            if (_map(entry)['error'] is int) 'error': _map(entry)['error'],
          },
      ];
      if (entries.length > 8) truncated = true;
    }
    if (input['per_socket_sent'] is List) {
      result['per_socket_sent'] = [
        for (final value in _list(input['per_socket_sent']).take(8))
          if (value is List &&
              value.length == 2 &&
              value[0] is int &&
              value[1] is int)
            [value[0], value[1]],
      ];
    }
    for (final (key, limit) in [
      ('events', 16),
      ('first_usable_summaries', 8),
      ('hard_hard_terminal_summaries', 8),
      ('sources', 8),
      ('transitions', 8),
    ]) {
      if (input[key] is! List) continue;
      final values = _list(input[key]);
      result['${key}_total'] = input['${key}_total'] is int
          ? input['${key}_total']
          : values.length;
      result[key] = [
        for (final value in values.skip(
          values.length > limit ? values.length - limit : 0,
        ))
          project(value, depth + 1),
      ];
      if (values.length > limit) truncated = true;
    }
    for (final key in ['bounds_ms', 'buckets']) {
      if (input[key] is! List) continue;
      final values = _list(input[key]);
      result[key] = [
        for (final value in values.take(16))
          if (value is int) value,
      ];
      if (values.length > 16) truncated = true;
    }
    return result;
  }
}

/// Produces valid JSON within fixed budgets. Missing fields stay missing; a
/// cached snapshot is never relabeled fresh because an upload was requested.
String buildSupportStatusSummary({
  Map<String, dynamic>? snapshot,
  required String source,
  String? errorCode,
  bool stale = false,
  DateTime? cachedAt,
  Map<String, dynamic>? observedDaemonBuild,
  String? roomPhase,
  DateTime? collectedAt,
}) {
  final projection = _Projection();
  final peers = _list(snapshot?['peers']);
  final result = <String, Object?>{
    'support_summary_version': 1,
    'address_tag_scope': 'summary',
    'collected_at': (collectedAt ?? DateTime.now()).toUtc().toIso8601String(),
    'source': _code(source) ?? 'unavailable',
    'stale':
        stale || source != 'live' || snapshot?['peer_snapshot_stale'] == true,
    if (_code(errorCode) case final String code) 'error_code': code,
    if (cachedAt != null) 'cached_at': cachedAt.toUtc().toIso8601String(),
    if (_code(roomPhase) case final String phase) 'room_phase': phase,
    if (observedDaemonBuild != null)
      'last_observed_daemon_build': projection.project(observedDaemonBuild),
    if (snapshot != null) 'status': projection.project(snapshot),
    'peers_total': peers.length,
  };
  final projectedPeers = <Map<String, Object?>>[];
  for (final rawPeer in peers.take(maxSupportStatusPeers)) {
    final peer = projection.project(rawPeer);
    final allEvents = _list(_map(rawPeer)['direct_events']);
    // The native ring is bounded; bound our inspection even for malformed input.
    final recent = allEvents.take(256).toList()
      ..sort((a, b) => _age(a).compareTo(_age(b)));
    final events = [
      for (final event in recent.take(maxSupportStatusEvents))
        projection.project(event),
    ];
    final reports = [
      for (final event in recent)
        if (_map(event)['hard_hard_attempt'] is Map)
          _map(event)['hard_hard_attempt'],
    ];
    final attempts = [
      for (final report in reports.take(maxSupportStatusAttempts))
        projection.project(report),
    ];
    peer.addAll({
      'direct_events_total': allEvents.length,
      'direct_events': events,
      'hard_hard_attempts_seen': reports.length,
      'hard_hard_attempts': attempts,
      'events_truncated': allEvents.length > events.length,
      'attempts_truncated':
          allEvents.length > 256 || reports.length > attempts.length,
    });
    final transitions = _list(_map(peer['path_observability'])['transitions']);
    while (utf8.encode(jsonEncode(peer)).length > maxSupportStatusPeerBytes &&
        (events.isNotEmpty || transitions.isNotEmpty || attempts.isNotEmpty)) {
      if (events.isNotEmpty) {
        events.removeLast();
      } else if (transitions.isNotEmpty) {
        transitions.removeAt(0);
      } else {
        attempts.removeLast();
      }
      projection.truncated = true;
    }
    if (utf8.encode(jsonEncode(peer)).length > maxSupportStatusPeerBytes) {
      peer.clear();
      peer.addAll({
        'node_id_tag': _tag(_map(rawPeer)['node_id']),
        'error_code': 'peer_summary_size_limit',
      });
      projection.truncated = true;
    }
    peer['events_truncated'] = allEvents.length > events.length;
    peer['attempts_truncated'] =
        allEvents.length > 256 || reports.length > attempts.length;
    if (peer['path_observability'] case final Map<String, Object?> path) {
      path['transitions_truncated'] =
          (path['transitions_total'] as int? ?? 0) > transitions.length;
    }
    if (peer['events_truncated'] == true ||
        peer['attempts_truncated'] == true) {
      projection.truncated = true;
    }
    projectedPeers.add(peer);
  }
  result['peers'] = projectedPeers;
  result['truncated'] =
      projection.truncated || peers.length > projectedPeers.length;
  while (utf8.encode(jsonEncode(result)).length > maxSupportStatusBytes &&
      projectedPeers.isNotEmpty) {
    projectedPeers.removeLast();
    result['truncated'] = true;
  }
  final encoded = jsonEncode(result);
  // Fixed maps/lists bound the normal shape; retain valid metadata on a future
  // schema expansion rather than byte-cutting JSON into an unusable tail.
  if (utf8.encode(encoded).length > maxSupportStatusBytes) {
    return jsonEncode({
      'support_summary_version': 1,
      'source': 'unavailable',
      'error_code': 'summary_size_limit',
      'truncated': true,
    });
  }
  return encoded;
}

/// Reapply the export boundary at encoding time, including legacy room summary
/// files. Invalid/oversized JSON becomes a small reason, never a raw text tail.
String sanitizeSupportStatusSummary(String encoded) {
  if (encoded.length > maxSupportStatusBytes ||
      utf8.encode(encoded).length > maxSupportStatusBytes) {
    return buildSupportStatusSummary(
      source: 'unavailable',
      errorCode: 'summary_size_limit',
    );
  }
  try {
    final value = jsonDecode(encoded);
    if (value is! Map<String, dynamic>) throw const FormatException();
    if (value['support_summary_version'] != 1) {
      return buildSupportStatusSummary(
        snapshot: value['last_status'] is Map<String, dynamic>
            ? value['last_status'] as Map<String, dynamic>
            : value,
        source: 'cached',
        stale: true,
        roomPhase: _code(value['phase']),
      );
    }
    final projection = _Projection();
    final result = <String, Object?>{
      'support_summary_version': 1,
      'address_tag_scope': 'summary',
    };
    for (final key in ['source', 'error_code', 'room_phase']) {
      if (_code(value[key]) case final String code) result[key] = code;
    }
    for (final key in ['stale', 'truncated']) {
      if (value[key] is bool) result[key] = value[key];
    }
    for (final key in ['collected_at', 'cached_at']) {
      final date = value[key];
      if (date is String && date.length <= 40) {
        final parsed = DateTime.tryParse(date);
        if (parsed != null) result[key] = parsed.toUtc().toIso8601String();
      }
    }
    for (final key in ['status', 'last_observed_daemon_build']) {
      if (value[key] is Map) result[key] = projection.project(value[key]);
    }
    if (value['peers_total'] is int) {
      result['peers_total'] = value['peers_total'];
    }
    result['peers'] = [
      for (final rawPeer in _list(value['peers']).take(maxSupportStatusPeers))
        {
          ...projection.project(rawPeer),
          'direct_events': [
            for (final event in _list(
              _map(rawPeer)['direct_events'],
            ).take(maxSupportStatusEvents))
              projection.project(event),
          ],
          'hard_hard_attempts': [
            for (final report in _list(
              _map(rawPeer)['hard_hard_attempts'],
            ).take(maxSupportStatusAttempts))
              projection.project(report),
          ],
          for (final key in [
            'direct_events_total',
            'hard_hard_attempts_seen',
            'events_truncated',
            'attempts_truncated',
          ])
            if (_map(rawPeer)[key] is int || _map(rawPeer)[key] is bool)
              key: _map(rawPeer)[key],
        },
    ];
    for (final peer in result['peers']! as List<Map<String, Object?>>) {
      if (utf8.encode(jsonEncode(peer)).length > maxSupportStatusPeerBytes) {
        final id = peer['node_id_tag'];
        peer.clear();
        peer.addAll({
          'node_id_tag': ?id,
          'error_code': 'peer_summary_size_limit',
        });
        projection.truncated = true;
      }
    }
    if (_list(value['peers']).length > maxSupportStatusPeers) {
      projection.truncated = true;
    }
    if (projection.truncated) result['truncated'] = true;
    final safe = jsonEncode(result);
    if (utf8.encode(safe).length <= maxSupportStatusBytes) return safe;
  } catch (_) {
    return buildSupportStatusSummary(
      source: 'unavailable',
      errorCode: 'summary_invalid',
    );
  }
  return buildSupportStatusSummary(
    source: 'unavailable',
    errorCode: 'summary_size_limit',
  );
}
