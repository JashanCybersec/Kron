//! Template-based alert narrative generation in English and Hindi.
//!
//! Narratives are plain-language summaries of an alert for analyst triage.
//! They are built from template strings using `format!` with IST timestamps
//! (UTC + 5:30).  No external dependency or LLM is used.

use chrono::Duration;

use crate::dedup::WindowState;
use crate::types::AlertCandidate;

/// IST offset from UTC: +5 hours 30 minutes.
const IST_OFFSET_HOURS: i64 = 5;
const IST_OFFSET_MINUTES: i64 = 30;

/// Formats a UTC timestamp as `HH:MM IST`.
fn to_ist_time(ts: &chrono::DateTime<chrono::Utc>) -> String {
    let ist = *ts + Duration::hours(IST_OFFSET_HOURS) + Duration::minutes(IST_OFFSET_MINUTES);
    ist.format("%H:%M IST").to_string()
}

/// Returns the rule title from the first rule match, or `"Unknown"`.
fn rule_title(candidate: &AlertCandidate) -> &str {
    candidate
        .rule_matches
        .first()
        .map_or("Unknown", |r| r.rule_title.as_str())
}

/// Returns the first MITRE technique ID, or an empty string.
fn first_technique(candidate: &AlertCandidate) -> String {
    candidate
        .mitre_tags
        .first()
        .map(|t| t.technique_id.clone())
        .unwrap_or_default()
}

/// Returns the first MITRE tactic name, or an empty string.
fn first_tactic(candidate: &AlertCandidate) -> String {
    candidate
        .mitre_tags
        .first()
        .map(|t| t.tactic.clone())
        .unwrap_or_default()
}

/// Builds a plain-English summary of the alert.
///
/// # Example output
///
/// ```text
/// Critical security alert: Brute Force Login detected on host web-srv-01
/// at 14:32 IST. 47 events in the last 15 minutes. Severity: Critical.
/// MITRE ATT&CK: T1110 (Credential Access).
/// ```
#[must_use]
pub fn build_en_summary(candidate: &AlertCandidate, window: &WindowState) -> String {
    let severity = candidate.severity.to_string();
    let severity_cap = {
        let mut s = severity.clone();
        if let Some(c) = s.get_mut(0..1) {
            c.make_ascii_uppercase();
        }
        s
    };
    let rule = rule_title(candidate);
    let asset = candidate
        .event
        .hostname
        .as_deref()
        .or_else(|| candidate.event.src_ip.as_ref().map(|_| "unknown"))
        .unwrap_or("unknown");
    let time = to_ist_time(&window.first_seen);
    let count = window.event_count;
    let tech = first_technique(candidate);
    let tactic = first_tactic(candidate);

    let mitre_part = if tech.is_empty() {
        String::new()
    } else if tactic.is_empty() {
        format!(" MITRE ATT&CK: {tech}.")
    } else {
        format!(" MITRE ATT&CK: {tech} ({tactic}).")
    };

    format!(
        "{severity_cap} security alert: {rule} detected on host {asset} at {time}. \
        {count} event(s) in the last 15 minutes. Severity: {severity_cap}.{mitre_part}"
    )
}

/// Builds a Hindi-language summary of the alert.
///
/// # Example output
///
/// ```text
/// गंभीर सुरक्षा अलर्ट: web-srv-01 पर 14:32 IST पर Brute Force Login
/// का पता चला। पिछले 15 मिनटों में 47 घटनाएँ।
/// ```
#[must_use]
pub fn build_hi_summary(candidate: &AlertCandidate, window: &WindowState) -> String {
    let severity_hi = match candidate.severity {
        kron_types::Severity::Critical => "गंभीर",
        kron_types::Severity::High => "उच्च",
        kron_types::Severity::Medium => "मध्यम",
        kron_types::Severity::Low => "निम्न",
        kron_types::Severity::Info => "सूचनात्मक",
    };
    let rule = rule_title(candidate);
    let asset = candidate.event.hostname.as_deref().unwrap_or("अज्ञात होस्ट");
    let time = to_ist_time(&window.first_seen);
    let count = window.event_count;

    format!(
        "{severity_hi} सुरक्षा अलर्ट: {asset} पर {time} पर {rule} \
        का पता चला। पिछले 15 मिनटों में {count} घटनाएँ।"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dedup::WindowState;
    use crate::types::{AlertCandidate, MitreTagRaw, RuleMatch};
    use chrono::Utc;
    use kron_types::{AlertId, EventSource, KronEvent, RuleId, Severity, TenantId};

    fn make_window() -> WindowState {
        WindowState {
            alert_id: AlertId::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            event_count: 47,
            evidence_event_ids: vec![],
            risk_score: 80,
            is_flushed: false,
        }
    }

    fn make_candidate() -> AlertCandidate {
        let event = KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("brute_force")
            .ts(Utc::now())
            .hostname("web-srv-01")
            .build()
            .expect("valid event");

        AlertCandidate {
            event,
            risk_score: 80,
            severity: Severity::Critical,
            rule_matches: vec![RuleMatch {
                rule_id: RuleId::new().to_string(),
                rule_title: "Brute Force Login".to_string(),
                severity: Severity::Critical,
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1110".to_string()],
            }],
            ioc_hit: false,
            ioc_type_str: None,
            anomaly_score: None,
            mitre_tags: vec![MitreTagRaw {
                tactic: "Credential Access".to_string(),
                technique_id: "T1110".to_string(),
                sub_technique_id: None,
            }],
        }
    }

    #[test]
    fn test_en_summary_when_critical_then_contains_severity_and_host() {
        let candidate = make_candidate();
        let window = make_window();
        let summary = build_en_summary(&candidate, &window);
        assert!(summary.contains("Critical"));
        assert!(summary.contains("web-srv-01"));
        assert!(summary.contains("Brute Force Login"));
        assert!(summary.contains("T1110"));
    }

    #[test]
    fn test_hi_summary_when_critical_then_contains_hindi_severity() {
        let candidate = make_candidate();
        let window = make_window();
        let summary = build_hi_summary(&candidate, &window);
        assert!(summary.contains("गंभीर"));
        assert!(summary.contains("web-srv-01"));
    }
}
