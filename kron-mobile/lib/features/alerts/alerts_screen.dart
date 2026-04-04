/// Alert feed screen — real-time list of KRON alerts.
///
/// Pulls the initial alert list from the REST API and refreshes on pull-to-refresh.
/// P1 alerts appear at the top with a red left border.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../models/alert.dart';
import '../../services/api_service.dart';

/// Provider that fetches the alert list.
final alertsProvider = FutureProvider.autoDispose<List<Alert>>((ref) async {
  final api = ref.read(apiServiceProvider);
  return api.listAlerts(status: 'open', limit: 100);
});

class AlertsScreen extends ConsumerWidget {
  const AlertsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final alertsAsync = ref.watch(alertsProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Alerts', style: TextStyle(fontWeight: FontWeight.w700)),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.invalidate(alertsProvider),
          ),
        ],
      ),
      body: alertsAsync.when(
        data: (alerts) => alerts.isEmpty
            ? const _EmptyState()
            : RefreshIndicator(
                onRefresh: () async => ref.invalidate(alertsProvider),
                child: ListView.builder(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  itemCount: alerts.length,
                  itemBuilder: (ctx, i) => _AlertCard(alert: alerts[i]),
                ),
              ),
        loading: () => const _LoadingSkeleton(),
        error: (e, _) => _ErrorState(message: e.toString()),
      ),
    );
  }
}

class _AlertCard extends StatelessWidget {
  const _AlertCard({required this.alert});
  final Alert alert;

  @override
  Widget build(BuildContext context) {
    final color = _severityColor(alert.severity);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: InkWell(
        borderRadius: BorderRadius.circular(8),
        onTap: () => context.go('/alerts/${alert.alertId}'),
        child: IntrinsicHeight(
          child: Row(
            children: [
              // Severity bar
              Container(
                width: 4,
                decoration: BoxDecoration(
                  color: color,
                  borderRadius: const BorderRadius.only(
                    topLeft: Radius.circular(8),
                    bottomLeft: Radius.circular(8),
                  ),
                ),
              ),
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          _SeverityBadge(severity: alert.severity),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              alert.ruleName,
                              style: const TextStyle(
                                fontWeight: FontWeight.w600,
                                fontSize: 14,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 6),
                      Row(
                        children: [
                          if (alert.hostname != null) ...[
                            const Icon(Icons.computer, size: 12,
                                color: Color(0xFF64748B)),
                            const SizedBox(width: 4),
                            Text(alert.hostname!,
                                style: const TextStyle(
                                    fontSize: 12, color: Color(0xFF64748B))),
                            const SizedBox(width: 12),
                          ],
                          const Icon(Icons.access_time, size: 12,
                              color: Color(0xFF64748B)),
                          const SizedBox(width: 4),
                          Text(
                            _formatTime(alert.createdAt),
                            style: const TextStyle(
                                fontSize: 12, color: Color(0xFF64748B)),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
              const Icon(Icons.chevron_right, color: Color(0xFF64748B)),
              const SizedBox(width: 8),
            ],
          ),
        ),
      ),
    );
  }

  static Color _severityColor(AlertSeverity s) => switch (s) {
    AlertSeverity.p1 => const Color(0xFFC81E1E),
    AlertSeverity.p2 => const Color(0xFFB45309),
    AlertSeverity.p3 => const Color(0xFF1A56DB),
    AlertSeverity.p4 => const Color(0xFF057A55),
    AlertSeverity.p5 => const Color(0xFF4B5563),
    AlertSeverity.unknown => const Color(0xFF6B7280),
  };

  static String _formatTime(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return DateFormat('dd MMM HH:mm').format(dt);
  }
}

class _SeverityBadge extends StatelessWidget {
  const _SeverityBadge({required this.severity});
  final AlertSeverity severity;

  @override
  Widget build(BuildContext context) {
    final (label, bg, fg) = switch (severity) {
      AlertSeverity.p1 => ('P1', const Color(0xFFFEE2E2), const Color(0xFFC81E1E)),
      AlertSeverity.p2 => ('P2', const Color(0xFFFEF3C7), const Color(0xFFB45309)),
      AlertSeverity.p3 => ('P3', const Color(0xFFDBEAFE), const Color(0xFF1A56DB)),
      AlertSeverity.p4 => ('P4', const Color(0xFFD1FAE5), const Color(0xFF057A55)),
      AlertSeverity.p5 => ('P5', const Color(0xFFF3F4F6), const Color(0xFF4B5563)),
      AlertSeverity.unknown => ('??', const Color(0xFFF3F4F6), const Color(0xFF6B7280)),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(4)),
      child: Text(label,
          style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: fg)),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.check_circle_outline, size: 56, color: Color(0xFF057A55)),
          SizedBox(height: 16),
          Text('No open alerts', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
          SizedBox(height: 8),
          Text('All clear — no active incidents.',
              style: TextStyle(color: Color(0xFF64748B))),
        ],
      ),
    );
  }
}

class _LoadingSkeleton extends StatelessWidget {
  const _LoadingSkeleton();

  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: 6,
      itemBuilder: (_, __) => Card(
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
        child: Container(height: 72),
      ),
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.message});
  final String message;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Color(0xFFC81E1E)),
            const SizedBox(height: 16),
            const Text('Failed to load alerts',
                style: TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
            const SizedBox(height: 8),
            Text(message,
                style: const TextStyle(fontSize: 13, color: Color(0xFF64748B)),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }
}
