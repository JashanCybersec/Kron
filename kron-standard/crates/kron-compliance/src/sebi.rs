//! SEBI CSCRF (Cyber Security and Cyber Resilience Framework) — compliance module.
//!
//! SEBI's CSCRF applies to Market Infrastructure Institutions (MIIs), Qualified
//! Stock Brokers (QSBs), and other regulated entities. It mandates:
//!
//! - Maintaining a Security Operations Centre (SOC).
//! - Implementing and testing an Incident Response Plan (IRP).
//! - Continuous monitoring with defined MTTD and MTTR targets.
//! - Quarterly vulnerability assessments and penetration testing.
//! - Cyber audit by CERT-In empanelled organisations annually.
//!
//! KRON maps these requirements to:
//! - SOC monitoring → alert pipeline metrics (MTTD, MTTA, MTTR).
//! - IRP testing → SOAR playbook execution records.
//! - VA/PT → integration with external scanner results (future phase).

use serde::{Deserialize, Serialize};

/// SEBI CSCRF compliance metrics for a reporting period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SebiMetrics {
    /// Mean Time to Detect (MTTD) in seconds. SEBI target: ≤ 15 minutes.
    pub mttd_secs: Option<u64>,
    /// Mean Time to Acknowledge (MTTA) in seconds. SEBI target: ≤ 30 minutes.
    pub mtta_secs: Option<u64>,
    /// Mean Time to Respond/Resolve (MTTR) in seconds. SEBI target: ≤ 4 hours for critical.
    pub mttr_secs: Option<u64>,
    /// Total P1 (critical) incidents in the period.
    pub critical_incidents: u64,
    /// Total incidents where MTTD > 15 min (SLA breach).
    pub mttd_sla_breaches: u64,
    /// Total incidents where MTTR > 4 hours (SLA breach for critical).
    pub mttr_sla_breaches: u64,
    /// Number of SOAR playbook executions (IRP test evidence).
    pub playbook_executions: u64,
    /// Whether a SOC is continuously operational (24×7).
    pub soc_24x7: bool,
}

/// SEBI CSCRF thresholds (in seconds).
pub const MTTD_TARGET_SECS: u64 = 15 * 60; // 15 minutes
pub const MTTA_TARGET_SECS: u64 = 30 * 60; // 30 minutes
pub const MTTR_TARGET_SECS: u64 = 4 * 60 * 60; // 4 hours

/// Renders the SEBI CSCRF compliance section as an HTML fragment.
///
/// # Arguments
/// * `metrics` — The SEBI compliance metrics for the period.
#[must_use]
pub fn render_html_section(metrics: &SebiMetrics) -> String {
    let mut html = String::with_capacity(2048);

    html.push_str("<section id=\"sebi\">\n");
    html.push_str("<h2>SEBI CSCRF — Compliance Report</h2>\n");

    html.push_str("<h3>SOC Metrics</h3>\n");
    html.push_str("<table>\n<thead><tr>\
        <th>Metric</th><th>Value</th><th>SEBI Target</th><th>Status</th>\
        </tr></thead>\n<tbody>\n");

    let mttd_ok = metrics
        .mttd_secs
        .map_or(true, |v| v <= MTTD_TARGET_SECS);
    let mtta_ok = metrics
        .mtta_secs
        .map_or(true, |v| v <= MTTA_TARGET_SECS);
    let mttr_ok = metrics
        .mttr_secs
        .map_or(true, |v| v <= MTTR_TARGET_SECS);

    html.push_str(&metric_row(
        "MTTD (Mean Time to Detect)",
        &metrics.mttd_secs.map_or("N/A".to_owned(), fmt_duration),
        "≤ 15 min",
        mttd_ok,
    ));
    html.push_str(&metric_row(
        "MTTA (Mean Time to Acknowledge)",
        &metrics.mtta_secs.map_or("N/A".to_owned(), fmt_duration),
        "≤ 30 min",
        mtta_ok,
    ));
    html.push_str(&metric_row(
        "MTTR (Mean Time to Resolve)",
        &metrics.mttr_secs.map_or("N/A".to_owned(), fmt_duration),
        "≤ 4 hr",
        mttr_ok,
    ));
    html.push_str(&metric_row(
        "SOC 24×7 Operational",
        if metrics.soc_24x7 { "Yes" } else { "No" },
        "Required",
        metrics.soc_24x7,
    ));

    html.push_str("</tbody></table>\n");

    html.push_str("<h3>Incident Response Plan (IRP) Evidence</h3>\n");
    html.push_str(&format!(
        "<p>SOAR playbook executions (IRP tests/responses): <strong>{}</strong></p>\n",
        metrics.playbook_executions
    ));

    html.push_str("<h3>SLA Breach Summary</h3>\n");
    html.push_str(&format!(
        "<p>MTTD SLA breaches (>15 min): <strong class=\"{}\">{}</strong></p>\n",
        if metrics.mttd_sla_breaches > 0 { "warn" } else { "ok" },
        metrics.mttd_sla_breaches,
    ));
    html.push_str(&format!(
        "<p>MTTR SLA breaches (>4 hr for critical): <strong class=\"{}\">{}</strong></p>\n",
        if metrics.mttr_sla_breaches > 0 { "warn" } else { "ok" },
        metrics.mttr_sla_breaches,
    ));

    html.push_str("</section>\n");
    html
}

/// Formats a duration in seconds as a human-readable string.
fn fmt_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Renders a single metric table row.
fn metric_row(label: &str, value: &str, target: &str, ok: bool) -> String {
    let status_class = if ok { "ok" } else { "warn" };
    let status_text = if ok { "✓ Met" } else { "✗ Breach" };
    format!(
        "<tr><td>{label}</td><td>{value}</td><td>{target}</td>\
         <td class=\"{status_class}\">{status_text}</td></tr>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_html_section_when_all_met_then_all_ok() {
        let metrics = SebiMetrics {
            mttd_secs: Some(300),  // 5 min — within target
            mtta_secs: Some(600),  // 10 min — within target
            mttr_secs: Some(3600), // 1 hr — within target
            critical_incidents: 2,
            mttd_sla_breaches: 0,
            mttr_sla_breaches: 0,
            playbook_executions: 5,
            soc_24x7: true,
        };
        let html = render_html_section(&metrics);
        assert!(html.contains("SEBI CSCRF"));
        assert!(html.contains("✓ Met"));
        assert!(!html.contains("✗ Breach"));
    }

    #[test]
    fn test_render_html_section_when_mttd_breach_then_breach_shown() {
        let metrics = SebiMetrics {
            mttd_secs: Some(2000), // > 15 min
            mtta_secs: None,
            mttr_secs: None,
            critical_incidents: 1,
            mttd_sla_breaches: 1,
            mttr_sla_breaches: 0,
            playbook_executions: 0,
            soc_24x7: false,
        };
        let html = render_html_section(&metrics);
        assert!(html.contains("✗ Breach"));
    }
}
