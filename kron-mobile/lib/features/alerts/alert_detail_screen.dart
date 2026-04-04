/// Alert detail screen — full context for a single KRON alert.
///
/// Shows severity, rule info, MITRE ATT&CK mapping, host/IP context,
/// event count, narrative, and action buttons (acknowledge / resolve /
/// mark false positive).
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../models/alert.dart';
import '../../services/api_service.dart';

/// Provider that fetches a single alert by ID.
final alertDetailProvider =
    FutureProvider.autoDispose.family<Alert, String>((ref, alertId) async {
  final api = ref.read(apiServiceProvider);
  return api.getAlert(alertId);
});

class AlertDetailScreen extends ConsumerWidget {
  const AlertDetailScreen({super.key, required this.alertId});
  final String alertId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final alertAsync = ref.watch(alertDetailProvider(alertId));

    return Scaffold(
      appBar: AppBar(
        title: const Text('Alert Detail',
            style: TextStyle(fontWeight: FontWeight.w700)),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.go('/alerts'),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => ref.invalidate(alertDetailProvider(alertId)),
          ),
        ],
      ),
      body: alertAsync.when(
        data: (alert) => _AlertDetailBody(alert: alert),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => _ErrorState(message: e.toString()),
      ),
    );
  }
}

class _AlertDetailBody extends ConsumerStatefulWidget {
  const _AlertDetailBody({required this.alert});
  final Alert alert;

  @override
  ConsumerState<_AlertDetailBody> createState() => _AlertDetailBodyState();
}

class _AlertDetailBodyState extends ConsumerState<_AlertDetailBody> {
  bool _actioning = false;

  Future<void> _acknowledge() async {
    setState(() => _actioning = true);
    try {
      await ref.read(apiServiceProvider).acknowledgeAlert(widget.alert.alertId);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Alert acknowledged')),
        );
        ref.invalidate(alertDetailProvider(widget.alert.alertId));
      }
    } on Exception catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed: $e'),
            backgroundColor: const Color(0xFFC81E1E),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _actioning = false);
    }
  }

  Future<void> _updateStatus(String status) async {
    setState(() => _actioning = true);
    try {
      await ref
          .read(apiServiceProvider)
          .updateAlertStatus(widget.alert.alertId, status);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Alert marked as $status')),
        );
        ref.invalidate(alertDetailProvider(widget.alert.alertId));
      }
    } on Exception catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed: $e'),
            backgroundColor: const Color(0xFFC81E1E),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _actioning = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final alert = widget.alert;
    final isOpen = alert.status == AlertStatus.open;
    final isAcked = alert.status == AlertStatus.acknowledged;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header card ─────────────────────────────────────────────────────
          _SectionCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    _SeverityBadgeLarge(severity: alert.severity),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        alert.ruleName,
                        style: const TextStyle(
                          fontSize: 17,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                _StatusChip(status: alert.status),
                const SizedBox(height: 12),
                _LabelValue(
                    label: 'Alert ID', value: alert.alertId, mono: true),
                _LabelValue(label: 'Rule ID', value: alert.ruleId, mono: true),
                _LabelValue(
                  label: 'Created',
                  value: DateFormat('dd MMM yyyy HH:mm:ss').format(alert.createdAt),
                ),
                if (alert.acknowledgedAt != null)
                  _LabelValue(
                    label: 'Acknowledged',
                    value: DateFormat('dd MMM yyyy HH:mm:ss')
                        .format(alert.acknowledgedAt!),
                  ),
                if (alert.resolvedAt != null)
                  _LabelValue(
                    label: 'Resolved',
                    value: DateFormat('dd MMM yyyy HH:mm:ss')
                        .format(alert.resolvedAt!),
                  ),
                _LabelValue(
                    label: 'Event count', value: alert.eventCount.toString()),
              ],
            ),
          ),

          // ── Context card (host / IP) ─────────────────────────────────────
          if (alert.hostname != null || alert.srcIp != null) ...[
            const SizedBox(height: 12),
            _SectionCard(
              title: 'Context',
              child: Column(
                children: [
                  if (alert.hostname != null)
                    _LabelValue(
                        label: 'Hostname', value: alert.hostname!, mono: true),
                  if (alert.srcIp != null)
                    _LabelValue(
                        label: 'Source IP', value: alert.srcIp!, mono: true),
                  if (alert.assignee != null)
                    _LabelValue(label: 'Assignee', value: alert.assignee!),
                ],
              ),
            ),
          ],

          // ── MITRE ATT&CK ────────────────────────────────────────────────
          if (alert.mitreAttackId != null || alert.mitreTactic != null) ...[
            const SizedBox(height: 12),
            _SectionCard(
              title: 'MITRE ATT&CK',
              child: Column(
                children: [
                  if (alert.mitreAttackId != null)
                    _LabelValue(
                      label: 'Technique',
                      value: alert.mitreAttackId!,
                      mono: true,
                    ),
                  if (alert.mitreTactic != null)
                    _LabelValue(
                        label: 'Tactic', value: alert.mitreTactic!),
                ],
              ),
            ),
          ],

          // ── Narrative ───────────────────────────────────────────────────
          if (alert.narrative != null && alert.narrative!.isNotEmpty) ...[
            const SizedBox(height: 12),
            _SectionCard(
              title: 'Narrative',
              child: Text(
                alert.narrative!,
                style: const TextStyle(
                    fontSize: 13.5, color: Color(0xFFCBD5E1), height: 1.6),
              ),
            ),
          ],

          // ── Action buttons ───────────────────────────────────────────────
          const SizedBox(height: 20),
          if (isOpen || isAcked) ...[
            if (isOpen)
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _actioning ? null : _acknowledge,
                  icon: const Icon(Icons.check_circle_outline, size: 18),
                  label: _actioning
                      ? const SizedBox(
                          height: 18,
                          width: 18,
                          child: CircularProgressIndicator(
                              color: Colors.white, strokeWidth: 2),
                        )
                      : const Text('Acknowledge'),
                ),
              ),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: _actioning
                        ? null
                        : () => _updateStatus('resolved'),
                    icon: const Icon(Icons.done_all, size: 18),
                    label: const Text('Resolve'),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: const Color(0xFFB45309),
                      side: const BorderSide(color: Color(0xFFB45309)),
                    ),
                    onPressed: _actioning
                        ? null
                        : () => _updateStatus('false_positive'),
                    icon: const Icon(Icons.block, size: 18),
                    label: const Text('False Positive'),
                  ),
                ),
              ],
            ),
          ],
          const SizedBox(height: 32),
        ],
      ),
    );
  }
}

// ── Internal widgets ─────────────────────────────────────────────────────────

class _SectionCard extends StatelessWidget {
  const _SectionCard({required this.child, this.title});
  final Widget child;
  final String? title;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (title != null) ...[
              Text(title!,
                  style: const TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: Color(0xFF64748B),
                    letterSpacing: 0.8,
                  )),
              const SizedBox(height: 10),
              const Divider(color: Color(0xFF1E2D45), height: 1),
              const SizedBox(height: 10),
            ],
            child,
          ],
        ),
      ),
    );
  }
}

class _LabelValue extends StatelessWidget {
  const _LabelValue(
      {required this.label, required this.value, this.mono = false});
  final String label;
  final String value;
  final bool mono;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 110,
            child: Text(label,
                style: const TextStyle(
                    fontSize: 12, color: Color(0xFF64748B))),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                fontSize: 13,
                fontFamily: mono ? 'monospace' : null,
                color: const Color(0xFFE2E8F0),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _SeverityBadgeLarge extends StatelessWidget {
  const _SeverityBadgeLarge({required this.severity});
  final AlertSeverity severity;

  @override
  Widget build(BuildContext context) {
    final (label, bg, fg) = switch (severity) {
      AlertSeverity.p1 =>
        ('P1 CRITICAL', const Color(0xFFFEE2E2), const Color(0xFFC81E1E)),
      AlertSeverity.p2 =>
        ('P2 HIGH', const Color(0xFFFEF3C7), const Color(0xFFB45309)),
      AlertSeverity.p3 =>
        ('P3 MEDIUM', const Color(0xFFDBEAFE), const Color(0xFF1A56DB)),
      AlertSeverity.p4 =>
        ('P4 LOW', const Color(0xFFD1FAE5), const Color(0xFF057A55)),
      AlertSeverity.p5 =>
        ('P5 INFO', const Color(0xFFF3F4F6), const Color(0xFF4B5563)),
      AlertSeverity.unknown =>
        ('UNKNOWN', const Color(0xFFF3F4F6), const Color(0xFF6B7280)),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration:
          BoxDecoration(color: bg, borderRadius: BorderRadius.circular(6)),
      child: Text(label,
          style:
              TextStyle(fontSize: 12, fontWeight: FontWeight.w700, color: fg)),
    );
  }
}

class _StatusChip extends StatelessWidget {
  const _StatusChip({required this.status});
  final AlertStatus status;

  @override
  Widget build(BuildContext context) {
    final (label, color) = switch (status) {
      AlertStatus.open => ('Open', const Color(0xFFC81E1E)),
      AlertStatus.acknowledged => ('Acknowledged', const Color(0xFFB45309)),
      AlertStatus.resolved => ('Resolved', const Color(0xFF057A55)),
      AlertStatus.falsePositive => ('False Positive', const Color(0xFF64748B)),
      AlertStatus.unknown => ('Unknown', const Color(0xFF64748B)),
    };

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 6),
        Text(label,
            style: TextStyle(
                fontSize: 13, fontWeight: FontWeight.w600, color: color)),
      ],
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
            const Icon(Icons.error_outline,
                size: 48, color: Color(0xFFC81E1E)),
            const SizedBox(height: 16),
            const Text('Failed to load alert',
                style:
                    TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
            const SizedBox(height: 8),
            Text(message,
                style: const TextStyle(
                    fontSize: 13, color: Color(0xFF64748B)),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }
}
