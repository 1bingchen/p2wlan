import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/diagnostics/support_status_summary.dart';

void main() {
  test(
    'whitelist retains typed NAT and attempt evidence without identities',
    () {
      final encoded = buildSupportStatusSummary(
        source: 'live',
        snapshot: {
          'version': '0.1.166',
          'contractVersion': 1,
          'network_generation': 4,
          'node_id': 'private-local-node',
          'token': 'sensitive-token',
          'nat_profile': {
            'public_endpoint': '192.0.2.10:43123',
            'filtering_behavior': 'unknown',
            'port_delta': null,
            'observations': [
              {'mapped_address': '192.0.2.10:43124', 'error': '/secret/path'},
            ],
          },
          'nat_capabilities': {
            'allocation_model': {'kind': 'monotonic_window', 'direction': -1},
          },
          'peers': [
            {
              'node_id': 'private-remote-node',
              'device_name': 'private device',
              'probe_session_id': 'sensitive-session',
              'private_key': 'sensitive-key',
              'packet': 'sensitive-packet',
              'endpoint': '198.51.100.7:50123',
              'recovery': {'probe_credit_remaining': 0, 'epoch_age_ms': 123},
              'direct_events': [
                {
                  'age_ms': 2,
                  'stage': 'hard_hard_attempt_complete',
                  'detail': 'Bearer sensitive-auth /secret/path',
                  'hard_hard_attempt': {
                    'schema_version': 2,
                    'source_git_commit':
                        'f16d70613b08b5e1bae421f71b8a6303d6c80cd5',
                    'mode': 'birthday',
                    'remote_profile_generation': 3,
                    'counts': {'send_success_datagrams': 16, 'generated': 64},
                    'timeline': {'actual_first_send_at_ms': 600},
                    'birthday_sweep': {
                      'waves_started': 2,
                      'physical_datagrams_sent': 16,
                      'per_socket_sent': [
                        [2, 8],
                        [3, 8],
                      ],
                      'failure_kind': 'cancelled',
                    },
                  },
                },
              ],
            },
          ],
        },
      );
      final safe = jsonDecode(sanitizeSupportStatusSummary(encoded));
      expect(safe['source'], 'live');
      expect(safe['stale'], isFalse);
      expect(safe['address_tag_scope'], 'summary');
      expect(safe['status']['contractVersion'], 1);
      final nat = safe['status']['nat_profile'];
      expect(nat['port_delta'], isNull);
      expect(nat['public_endpoint'], {
        'ip_tag': 'ip1',
        'family': 'ipv4',
        'port': 43123,
      });
      expect(nat['observations'][0]['mapped_address']['ip_tag'], 'ip1');
      expect(nat['observations'][0]['query_failed'], isTrue);
      expect(
        safe['status']['nat_capabilities']['allocation_model']['kind'],
        'monotonic_window',
      );
      final peer = safe['peers'][0];
      expect(peer['endpoint']['ip_tag'], 'ip2');
      expect(peer['recovery']['probe_credit_remaining'], 0);
      final attempt = peer['hard_hard_attempts'][0];
      expect(attempt['counts']['send_success_datagrams'], 16);
      expect(attempt['remote_profile_generation'], 3);
      expect(attempt['timeline']['actual_first_send_at_ms'], 600);
      expect(attempt['birthday_sweep']['per_socket_sent'], [
        [2, 8],
        [3, 8],
      ]);
      for (final forbidden in [
        'sensitive-',
        'private-',
        'private device',
        '/secret/path',
        '192.0.2.10',
        '198.51.100.7',
        'Bearer',
      ]) {
        expect(jsonEncode(safe), isNot(contains(forbidden)));
      }
    },
  );

  test(
    'summary peer event and report limits retain valid JSON and omission facts',
    () {
      final encoded = buildSupportStatusSummary(
        source: 'live',
        snapshot: {
          'version': '0.1.166',
          'peers': List.generate(
            12,
            (peer) => {
              'node_id': 'peer-$peer',
              'direct_events': List.generate(
                200,
                (event) => {
                  'age_ms': event,
                  'stage': 'probe',
                  'candidate_count': event,
                  'hard_hard_attempt': {
                    'attempt': event,
                    'counts': {'generated': 64},
                  },
                },
              ),
            },
          ),
        },
      );
      expect(
        utf8.encode(encoded).length,
        lessThanOrEqualTo(maxSupportStatusBytes),
      );
      final safe = jsonDecode(encoded);
      expect(safe['peers_total'], 12);
      expect(safe['truncated'], isTrue);
      final peers = safe['peers'] as List;
      expect(peers.length, lessThanOrEqualTo(maxSupportStatusPeers));
      for (final peer in peers) {
        expect(
          utf8.encode(jsonEncode(peer)).length,
          lessThanOrEqualTo(maxSupportStatusPeerBytes),
        );
        expect(
          (peer['direct_events'] as List).length,
          lessThanOrEqualTo(maxSupportStatusEvents),
        );
        expect(
          (peer['hard_hard_attempts'] as List).length,
          lessThanOrEqualTo(maxSupportStatusAttempts),
        );
        expect(peer['direct_events_total'], 200);
        expect(peer['events_truncated'], isTrue);
        expect(peer['attempts_truncated'], isTrue);
      }
    },
  );

  test(
    'a typed attempt outside the recent event tail is retained separately',
    () {
      final safe = jsonDecode(
        buildSupportStatusSummary(
          source: 'live',
          snapshot: {
            'peers': [
              {
                'direct_events': [
                  for (var age = 0; age < 40; age++)
                    {'age_ms': age, 'stage': 'probe'},
                  {
                    'age_ms': 50,
                    'hard_hard_attempt': {
                      'mode': 'predictable',
                      'direct_confirmed': false,
                    },
                  },
                ],
              },
            ],
          },
        ),
      );
      expect(safe['peers'][0]['hard_hard_attempts'][0]['mode'], 'predictable');
      expect(safe['peers'][0]['direct_events'].length, maxSupportStatusEvents);
    },
  );

  test(
    'legacy room input is cached and invalid or large input is bounded JSON',
    () {
      final safe = jsonDecode(
        sanitizeSupportStatusSummary(
          jsonEncode({
            'phase': 'failed',
            'message': 'token=secret /private/location',
            'last_status': {'version': '0.1.165', 'network_generation': 9},
          }),
        ),
      );
      expect(safe['room_phase'], 'failed');
      expect(safe['stale'], isTrue);
      expect(safe['source'], 'cached');
      expect(safe['status']['network_generation'], 9);
      expect(jsonEncode(safe), isNot(contains('secret')));
      for (final raw in [
        'not JSON token=secret',
        'x' * (maxSupportStatusBytes + 1),
      ]) {
        final summary = jsonDecode(sanitizeSupportStatusSummary(raw));
        expect(summary['source'], 'unavailable');
        expect(summary['error_code'], startsWith('summary_'));
        expect(jsonEncode(summary), isNot(contains('secret')));
      }
    },
  );

  test(
    'daemon-stale live captures are marked stale and build observations labeled',
    () {
      final safe = jsonDecode(
        buildSupportStatusSummary(
          source: 'live',
          snapshot: {'version': '0.1.166', 'peer_snapshot_stale': true},
          observedDaemonBuild: {
            'daemon_version': '0.1.165',
            'git_commit': 'abcdef01',
          },
        ),
      );
      expect(safe['stale'], isTrue);
      expect(safe['status']['version'], '0.1.166');
      expect(safe['last_observed_daemon_build']['daemon_version'], '0.1.165');
    },
  );
}
