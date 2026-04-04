/// Alert model — mirrors the kron-query-api alert response shape.
library;

/// Severity levels matching the KRON platform.
enum AlertSeverity { p1, p2, p3, p4, p5, unknown }

/// Alert lifecycle status.
enum AlertStatus { open, acknowledged, resolved, falsePositive, unknown }

/// A single KRON alert record.
class Alert {
  const Alert({
    required this.alertId,
    required this.tenantId,
    required this.ruleId,
    required this.ruleName,
    required this.severity,
    required this.status,
    required this.createdAt,
    this.acknowledgedAt,
    this.resolvedAt,
    this.assignee,
    this.narrative,
    this.mitreAttackId,
    this.mitreTactic,
    this.hostname,
    this.srcIp,
    this.eventCount = 0,
  });

  final String alertId;
  final String tenantId;
  final String ruleId;
  final String ruleName;
  final AlertSeverity severity;
  final AlertStatus status;
  final DateTime createdAt;
  final DateTime? acknowledgedAt;
  final DateTime? resolvedAt;
  final String? assignee;
  final String? narrative;
  final String? mitreAttackId;
  final String? mitreTactic;
  final String? hostname;
  final String? srcIp;
  final int eventCount;

  /// Deserialises from the API JSON response.
  factory Alert.fromJson(Map<String, dynamic> json) {
    return Alert(
      alertId: json['alert_id'] as String? ?? '',
      tenantId: json['tenant_id'] as String? ?? '',
      ruleId: json['rule_id'] as String? ?? '',
      ruleName: json['rule_name'] as String? ?? 'Unknown Rule',
      severity: _parseSeverity(json['severity'] as String? ?? ''),
      status: _parseStatus(json['status'] as String? ?? ''),
      createdAt: DateTime.tryParse(json['created_at'] as String? ?? '') ?? DateTime.now(),
      acknowledgedAt: json['acknowledged_at'] != null
          ? DateTime.tryParse(json['acknowledged_at'] as String)
          : null,
      resolvedAt: json['resolved_at'] != null
          ? DateTime.tryParse(json['resolved_at'] as String)
          : null,
      assignee: json['assignee'] as String?,
      narrative: json['narrative'] as String?,
      mitreAttackId: json['mitre_attack_id'] as String?,
      mitreTactic: json['mitre_tactic'] as String?,
      hostname: json['hostname'] as String?,
      srcIp: json['src_ip'] as String?,
      eventCount: (json['event_count'] as int?) ?? 0,
    );
  }

  static AlertSeverity _parseSeverity(String s) => switch (s.toLowerCase()) {
    'p1' || 'critical' => AlertSeverity.p1,
    'p2' || 'high' => AlertSeverity.p2,
    'p3' || 'medium' => AlertSeverity.p3,
    'p4' || 'low' => AlertSeverity.p4,
    'p5' || 'info' => AlertSeverity.p5,
    _ => AlertSeverity.unknown,
  };

  static AlertStatus _parseStatus(String s) => switch (s.toLowerCase()) {
    'open' => AlertStatus.open,
    'acknowledged' => AlertStatus.acknowledged,
    'resolved' => AlertStatus.resolved,
    'false_positive' => AlertStatus.falsePositive,
    _ => AlertStatus.unknown,
  };
}
