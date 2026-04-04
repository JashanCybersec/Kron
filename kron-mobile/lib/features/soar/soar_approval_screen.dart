/// SOAR playbook approval screen — analyst approves or rejects a pending
/// automated response action, with biometric confirmation for approvals.
///
/// Biometric gate is mandatory for approvals: a SOAR action executed without
/// analyst sign-off creates an audit gap. The biometric challenge happens
/// **after** the analyst reads the full action detail, not before.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:local_auth/local_auth.dart';

import '../../services/api_service.dart';

// ── Models ───────────────────────────────────────────────────────────────────

/// Severity of the playbook being approved.
enum PlaybookRisk { low, medium, high, critical }

/// A pending SOAR approval request.
class PlaybookApproval {
  const PlaybookApproval({
    required this.playbookId,
    required this.name,
    required this.description,
    required this.actions,
    required this.risk,
    required this.alertId,
    required this.requestedBy,
    required this.requestedAt,
    this.targetAssets = const [],
  });

  final String playbookId;
  final String name;
  final String description;
  final List<String> actions;
  final PlaybookRisk risk;
  final String alertId;
  final String requestedBy;
  final DateTime requestedAt;
  final List<String> targetAssets;

  factory PlaybookApproval.fromJson(Map<String, dynamic> json) {
    return PlaybookApproval(
      playbookId: json['playbook_id'] as String? ?? '',
      name: json['name'] as String? ?? 'Unknown Playbook',
      description: json['description'] as String? ?? '',
      actions: List<String>.from(
          (json['actions'] as List<dynamic>? ?? []).map((e) => e.toString())),
      risk: _parseRisk(json['risk'] as String? ?? ''),
      alertId: json['alert_id'] as String? ?? '',
      requestedBy: json['requested_by'] as String? ?? 'System',
      requestedAt:
          DateTime.tryParse(json['requested_at'] as String? ?? '') ??
              DateTime.now(),
      targetAssets: List<String>.from(
          (json['target_assets'] as List<dynamic>? ?? [])
              .map((e) => e.toString())),
    );
  }

  static PlaybookRisk _parseRisk(String s) => switch (s.toLowerCase()) {
        'low' => PlaybookRisk.low,
        'medium' => PlaybookRisk.medium,
        'high' => PlaybookRisk.high,
        'critical' => PlaybookRisk.critical,
        _ => PlaybookRisk.medium,
      };
}

// ── Provider ─────────────────────────────────────────────────────────────────

/// Fetches pending approval details for a playbook.
final playbookApprovalProvider =
    FutureProvider.autoDispose.family<PlaybookApproval, String>(
  (ref, playbookId) async {
    final api = ref.read(apiServiceProvider);
    final response = await api.getPlaybookApproval(playbookId);
    return response;
  },
);

// ── Screen ────────────────────────────────────────────────────────────────────

class SoarApprovalScreen extends ConsumerWidget {
  const SoarApprovalScreen({super.key, required this.playbookId});
  final String playbookId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final approvalAsync = ref.watch(playbookApprovalProvider(playbookId));

    return Scaffold(
      appBar: AppBar(
        title: const Text('SOAR Approval',
            style: TextStyle(fontWeight: FontWeight.w700)),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.go('/alerts'),
        ),
      ),
      body: approvalAsync.when(
        data: (approval) => _ApprovalBody(approval: approval),
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (e, _) => _ErrorState(message: e.toString()),
      ),
    );
  }
}

// ── Body ─────────────────────────────────────────────────────────────────────

class _ApprovalBody extends ConsumerStatefulWidget {
  const _ApprovalBody({required this.approval});
  final PlaybookApproval approval;

  @override
  ConsumerState<_ApprovalBody> createState() => _ApprovalBodyState();
}

class _ApprovalBodyState extends ConsumerState<_ApprovalBody> {
  bool _actioning = false;
  String? _outcome; // 'approved' | 'rejected'

  /// Reject does NOT require biometric — only approval does.
  Future<void> _reject() async {
    final confirmed = await _showConfirmDialog(
      title: 'Reject Playbook?',
      message:
          'The automated response will be cancelled. You can manually run the playbook later.',
      confirmLabel: 'Reject',
      confirmColor: const Color(0xFFC81E1E),
    );
    if (!confirmed || !mounted) return;

    setState(() => _actioning = true);
    try {
      await ref
          .read(apiServiceProvider)
          .rejectPlaybook(widget.approval.playbookId);
      if (mounted) {
        setState(() => _outcome = 'rejected');
      }
    } on Exception catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('Rejection failed: $e'),
          backgroundColor: const Color(0xFFC81E1E),
        ));
      }
    } finally {
      if (mounted) setState(() => _actioning = false);
    }
  }

  /// Approve REQUIRES biometric confirmation.
  Future<void> _approve() async {
    // Step 1: confirm the user read the actions
    final confirmed = await _showConfirmDialog(
      title: 'Approve and Execute?',
      message:
          'This will execute the playbook on the listed assets. Biometric confirmation is required.',
      confirmLabel: 'Continue to Biometric',
      confirmColor: const Color(0xFF3B82F6),
    );
    if (!confirmed || !mounted) return;

    // Step 2: biometric gate
    final auth = LocalAuthentication();
    final canUseBiometric = await auth.canCheckBiometrics ||
        await auth.isDeviceSupported();

    if (!canUseBiometric) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
                'Biometric authentication is required but not available on this device.'),
            backgroundColor: Color(0xFFC81E1E),
          ),
        );
      }
      return;
    }

    final biometricPassed = await auth.authenticate(
      localizedReason:
          'Confirm approval of SOAR playbook: ${widget.approval.name}',
      options: const AuthenticationOptions(
        biometricOnly: false, // allow PIN fallback for devices without biometric
        stickyAuth: true,
      ),
    );

    if (!biometricPassed || !mounted) return;

    // Step 3: call API
    setState(() => _actioning = true);
    try {
      await ref
          .read(apiServiceProvider)
          .approvePlaybook(widget.approval.playbookId);
      if (mounted) {
        setState(() => _outcome = 'approved');
      }
    } on Exception catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text('Approval failed: $e'),
          backgroundColor: const Color(0xFFC81E1E),
        ));
      }
    } finally {
      if (mounted) setState(() => _actioning = false);
    }
  }

  Future<bool> _showConfirmDialog({
    required String title,
    required String message,
    required String confirmLabel,
    required Color confirmColor,
  }) async {
    return await showDialog<bool>(
          context: context,
          builder: (ctx) => AlertDialog(
            backgroundColor: const Color(0xFF131929),
            title: Text(title),
            content: Text(message,
                style: const TextStyle(color: Color(0xFF94A3B8))),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: const Text('Cancel',
                    style: TextStyle(color: Color(0xFF64748B))),
              ),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                    backgroundColor: confirmColor),
                onPressed: () => Navigator.pop(ctx, true),
                child: Text(confirmLabel),
              ),
            ],
          ),
        ) ??
        false;
  }

  @override
  Widget build(BuildContext context) {
    if (_outcome != null) {
      return _OutcomeState(
        outcome: _outcome!,
        playbookName: widget.approval.name,
      );
    }

    final approval = widget.approval;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Risk banner ────────────────────────────────────────────────
          _RiskBanner(risk: approval.risk),
          const SizedBox(height: 14),

          // ── Playbook info ──────────────────────────────────────────────
          _SectionCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  approval.name,
                  style: const TextStyle(
                      fontSize: 17, fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 6),
                Text(
                  approval.description,
                  style: const TextStyle(
                      fontSize: 13.5,
                      color: Color(0xFF94A3B8),
                      height: 1.5),
                ),
                const SizedBox(height: 12),
                _LabelValue(
                    label: 'Triggered by alert', value: approval.alertId),
                _LabelValue(
                    label: 'Requested by', value: approval.requestedBy),
              ],
            ),
          ),

          // ── Actions list ───────────────────────────────────────────────
          const SizedBox(height: 12),
          _SectionCard(
            title: 'ACTIONS TO EXECUTE',
            child: Column(
              children: approval.actions
                  .asMap()
                  .entries
                  .map(
                    (e) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 5),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            width: 22,
                            height: 22,
                            decoration: const BoxDecoration(
                              color: Color(0xFF1E2D45),
                              shape: BoxShape.circle,
                            ),
                            alignment: Alignment.center,
                            child: Text(
                              '${e.key + 1}',
                              style: const TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.w700,
                                  color: Color(0xFF94A3B8)),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              e.value,
                              style: const TextStyle(
                                  fontSize: 13.5,
                                  fontFamily: 'monospace',
                                  color: Color(0xFFE2E8F0)),
                            ),
                          ),
                        ],
                      ),
                    ),
                  )
                  .toList(),
            ),
          ),

          // ── Target assets ──────────────────────────────────────────────
          if (approval.targetAssets.isNotEmpty) ...[
            const SizedBox(height: 12),
            _SectionCard(
              title: 'TARGET ASSETS',
              child: Wrap(
                spacing: 8,
                runSpacing: 6,
                children: approval.targetAssets
                    .map((asset) => Chip(
                          label: Text(asset,
                              style: const TextStyle(
                                  fontSize: 12, fontFamily: 'monospace')),
                          backgroundColor: const Color(0xFF1E2D45),
                          side: BorderSide.none,
                        ))
                    .toList(),
              ),
            ),
          ],

          // ── Biometric notice ───────────────────────────────────────────
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF1A2030),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: const Color(0xFF3B82F6), width: 1),
            ),
            child: Row(
              children: const [
                Icon(Icons.fingerprint, color: Color(0xFF3B82F6), size: 20),
                SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Approval requires biometric authentication to create an audit trail.',
                    style:
                        TextStyle(fontSize: 12.5, color: Color(0xFF94A3B8)),
                  ),
                ),
              ],
            ),
          ),

          // ── Action buttons ─────────────────────────────────────────────
          const SizedBox(height: 24),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: const Color(0xFFC81E1E),
                    side: const BorderSide(color: Color(0xFFC81E1E)),
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                  onPressed: _actioning ? null : _reject,
                  icon: const Icon(Icons.close, size: 18),
                  label: const Text('Reject'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 14),
                  ),
                  onPressed: _actioning ? null : _approve,
                  icon: _actioning
                      ? const SizedBox(
                          height: 18,
                          width: 18,
                          child: CircularProgressIndicator(
                              color: Colors.white, strokeWidth: 2),
                        )
                      : const Icon(Icons.fingerprint, size: 18),
                  label: const Text('Approve'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 32),
        ],
      ),
    );
  }
}

// ── Risk banner ───────────────────────────────────────────────────────────────

class _RiskBanner extends StatelessWidget {
  const _RiskBanner({required this.risk});
  final PlaybookRisk risk;

  @override
  Widget build(BuildContext context) {
    final (label, bg, fg, icon) = switch (risk) {
      PlaybookRisk.low => (
          'LOW RISK',
          const Color(0xFFD1FAE5),
          const Color(0xFF057A55),
          Icons.shield_outlined
        ),
      PlaybookRisk.medium => (
          'MEDIUM RISK',
          const Color(0xFFFEF3C7),
          const Color(0xFFB45309),
          Icons.warning_amber_outlined
        ),
      PlaybookRisk.high => (
          'HIGH RISK',
          const Color(0xFFFEE2E2),
          const Color(0xFFC81E1E),
          Icons.warning_outlined
        ),
      PlaybookRisk.critical => (
          'CRITICAL RISK',
          const Color(0xFFFEE2E2),
          const Color(0xFF9B1C1C),
          Icons.dangerous_outlined
        ),
    };

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: bg.withAlpha(30),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: fg.withAlpha(80)),
      ),
      child: Row(
        children: [
          Icon(icon, color: fg, size: 20),
          const SizedBox(width: 10),
          Text(label,
              style: TextStyle(
                  fontSize: 13, fontWeight: FontWeight.w700, color: fg)),
          const Spacer(),
          Text('Review all actions before approving',
              style: TextStyle(fontSize: 11, color: fg.withAlpha(180))),
        ],
      ),
    );
  }
}

// ── Outcome state ─────────────────────────────────────────────────────────────

class _OutcomeState extends StatelessWidget {
  const _OutcomeState({required this.outcome, required this.playbookName});
  final String outcome;
  final String playbookName;

  @override
  Widget build(BuildContext context) {
    final isApproved = outcome == 'approved';
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              isApproved ? Icons.check_circle_outline : Icons.cancel_outlined,
              size: 64,
              color: isApproved
                  ? const Color(0xFF057A55)
                  : const Color(0xFFC81E1E),
            ),
            const SizedBox(height: 16),
            Text(
              isApproved ? 'Playbook Approved' : 'Playbook Rejected',
              style: const TextStyle(
                  fontSize: 20, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            Text(
              isApproved
                  ? '"$playbookName" will execute momentarily.\nAn audit record has been created.'
                  : '"$playbookName" has been cancelled.\nNo automated actions will be taken.',
              style:
                  const TextStyle(color: Color(0xFF94A3B8), height: 1.6),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 32),
            ElevatedButton.icon(
              onPressed: () => context.go('/alerts'),
              icon: const Icon(Icons.arrow_back, size: 18),
              label: const Text('Back to Alerts'),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

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
                    fontSize: 11,
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
  const _LabelValue({required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 130,
            child: Text(label,
                style: const TextStyle(
                    fontSize: 12, color: Color(0xFF64748B))),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(
                    fontSize: 13, color: Color(0xFFE2E8F0))),
          ),
        ],
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
            const Icon(Icons.error_outline,
                size: 48, color: Color(0xFFC81E1E)),
            const SizedBox(height: 16),
            const Text('Failed to load playbook approval',
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
