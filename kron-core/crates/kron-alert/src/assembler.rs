//! Assembles a full [`KronAlert`] from a dedup window and the triggering
//! [`AlertCandidate`].

use chrono::Utc;
use kron_types::enums::{AlertStatus, DetectionSource, Severity};
use kron_types::KronAlert;

use crate::dedup::{DedupKey, WindowState};
use crate::narrative;
use crate::types::AlertCandidate;

/// Builds complete [`KronAlert`] records from dedup window state.
pub struct AlertAssembler;

impl AlertAssembler {
    /// Assembles a [`KronAlert`] from a dedup window and the alert candidate
    /// that first opened the window.
    ///
    /// The assembled alert captures all evidence accumulated across the full
    /// 15-minute window before the flush.
    #[must_use]
    pub fn assemble(
        candidate: &AlertCandidate,
        window: &WindowState,
        dedup_key: &DedupKey,
    ) -> KronAlert {
        let detection_source = detection_source_for(candidate);
        let severity = Severity::from_score(window.risk_score);

        let rule_name = candidate
            .rule_matches
            .first()
            .map_or_else(|| "Unknown".to_string(), |r| r.rule_title.clone());

        let rule_version = candidate.rule_matches.first().map(|_| "1".to_string());

        let mitre_tactic = candidate.mitre_tags.first().map(|t| t.tactic.clone());

        let mitre_technique = candidate.mitre_tags.first().map(|t| t.technique_id.clone());

        let mitre_sub_tech = candidate
            .mitre_tags
            .first()
            .and_then(|t| t.sub_technique_id.clone());

        // Affected assets: hostname from the triggering event.
        let affected_assets = candidate.event.hostname.iter().cloned().collect::<Vec<_>>();

        // Affected users: username from the triggering event.
        let affected_users = candidate
            .event
            .user_name
            .iter()
            .cloned()
            .collect::<Vec<_>>();

        // Affected IPs: deduplicated src + dst IPs.
        let affected_ips = build_affected_ips(candidate);

        let narrative_en = Some(narrative::build_en_summary(candidate, window));
        let narrative_hi = Some(narrative::build_hi_summary(candidate, window));

        let (cert_in_category, rbi_control, dpdp_applicable) =
            compliance_fields_from_tags(candidate);

        KronAlert {
            alert_id: window.alert_id,
            tenant_id: dedup_key.tenant_id,
            rule_id: dedup_key.rule_id,
            rule_name,
            rule_version,
            detection_source,
            created_at: Utc::now(),
            first_seen: window.first_seen,
            last_seen: window.last_seen,
            event_count: window.event_count,
            risk_score: window.risk_score,
            severity,
            confidence: candidate.anomaly_score,
            mitre_tactic,
            mitre_technique,
            mitre_sub_tech,
            kill_chain_stage: None,
            affected_assets,
            affected_users,
            affected_ips,
            evidence_event_ids: window.evidence_event_ids.clone(),
            raw_matches: None,
            narrative_en,
            narrative_hi,
            narrative_ta: None,
            narrative_te: None,
            root_cause_chain: None,
            fp_probability: None,
            suggested_playbook: None,
            status: AlertStatus::Open,
            assigned_to: None,
            resolved_at: None,
            resolved_by: None,
            resolution_notes: None,
            case_id: None,
            cert_in_category,
            rbi_control,
            dpdp_applicable,
            whatsapp_sent: false,
            sms_sent: false,
            email_sent: false,
            notification_ts: None,
            schema_version: 1,
        }
    }
}

/// Determines the primary detection source for the alert.
///
/// Prefers SIGMA if any rule matched; falls back to IOC or ONNX.
fn detection_source_for(candidate: &AlertCandidate) -> DetectionSource {
    if !candidate.rule_matches.is_empty() {
        DetectionSource::Sigma
    } else if candidate.ioc_hit {
        DetectionSource::Ioc
    } else {
        DetectionSource::Onnx
    }
}

/// Collects unique IPv4 addresses from the triggering event's src and dst
/// fields, returning them as strings.
fn build_affected_ips(candidate: &AlertCandidate) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    if let Some(ip) = candidate.event.src_ip {
        let s = ip.to_string();
        if !ips.contains(&s) {
            ips.push(s);
        }
    }
    if let Some(ip) = candidate.event.dst_ip {
        let s = ip.to_string();
        if !ips.contains(&s) {
            ips.push(s);
        }
    }
    ips
}

/// Derives compliance flag fields from rule tags (heuristic).
///
/// Returns `(cert_in_category, rbi_control, dpdp_applicable)`.
fn compliance_fields_from_tags(
    candidate: &AlertCandidate,
) -> (Option<String>, Option<String>, bool) {
    // If any rule tag tactic relates to data exfiltration, mark DPDP.
    let dpdp = candidate
        .mitre_tags
        .iter()
        .any(|t| t.tactic.to_lowercase().contains("exfil"));

    // CERT-In category: map Critical/High severity network-related alerts.
    let cert_in = if candidate.severity >= kron_types::Severity::High {
        Some("Malicious Code / Attack".to_string())
    } else {
        None
    };

    (cert_in, None, dpdp)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dedup::{DedupKey, WindowState};
    use crate::types::{AlertCandidate, MitreTagRaw, RuleMatch};
    use chrono::Utc;
    use kron_types::{AlertId, EventSource, KronEvent, RuleId, Severity, TenantId};

    fn make_assembly_inputs() -> (AlertCandidate, WindowState, DedupKey) {
        let tenant_id = TenantId::new();
        let rule_id = RuleId::new();

        let event = KronEvent::builder()
            .tenant_id(tenant_id)
            .source_type(EventSource::LinuxEbpf)
            .event_type("brute_force")
            .ts(Utc::now())
            .hostname("web-srv-01")
            .user_name("jdoe")
            .src_ip("192.168.1.50".parse().expect("valid ip"))
            .build()
            .expect("valid event");

        let candidate = AlertCandidate {
            event,
            risk_score: 82,
            severity: Severity::Critical,
            rule_matches: vec![RuleMatch {
                rule_id: rule_id.to_string(),
                rule_title: "Brute Force Login".to_string(),
                severity: Severity::Critical,
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1110".to_string()],
            }],
            ioc_hit: false,
            ioc_type_str: None,
            anomaly_score: Some(0.87),
            mitre_tags: vec![MitreTagRaw {
                tactic: "Credential Access".to_string(),
                technique_id: "T1110".to_string(),
                sub_technique_id: None,
            }],
        };

        let window = WindowState {
            alert_id: AlertId::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            event_count: 47,
            evidence_event_ids: vec![],
            risk_score: 82,
            is_flushed: true,
        };

        let key = DedupKey {
            tenant_id,
            rule_id,
            primary_asset: "web-srv-01".to_string(),
        };

        (candidate, window, key)
    }

    #[test]
    fn test_assemble_when_sigma_match_then_detection_source_is_sigma() {
        let (candidate, window, key) = make_assembly_inputs();
        let alert = AlertAssembler::assemble(&candidate, &window, &key);
        assert_eq!(alert.detection_source, DetectionSource::Sigma);
    }

    #[test]
    fn test_assemble_when_critical_score_then_severity_is_critical() {
        let (candidate, window, key) = make_assembly_inputs();
        let alert = AlertAssembler::assemble(&candidate, &window, &key);
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn test_assemble_when_hostname_set_then_in_affected_assets() {
        let (candidate, window, key) = make_assembly_inputs();
        let alert = AlertAssembler::assemble(&candidate, &window, &key);
        assert!(alert.affected_assets.contains(&"web-srv-01".to_string()));
    }

    #[test]
    fn test_assemble_when_user_set_then_in_affected_users() {
        let (candidate, window, key) = make_assembly_inputs();
        let alert = AlertAssembler::assemble(&candidate, &window, &key);
        assert!(alert.affected_users.contains(&"jdoe".to_string()));
    }

    #[test]
    fn test_assemble_when_src_ip_set_then_in_affected_ips() {
        let (candidate, window, key) = make_assembly_inputs();
        let alert = AlertAssembler::assemble(&candidate, &window, &key);
        assert!(alert.affected_ips.contains(&"192.168.1.50".to_string()));
    }

    #[test]
    fn test_assemble_when_narrative_requested_then_both_languages_present() {
        let (candidate, window, key) = make_assembly_inputs();
        let alert = AlertAssembler::assemble(&candidate, &window, &key);
        assert!(alert.narrative_en.is_some());
        assert!(alert.narrative_hi.is_some());
    }
}
