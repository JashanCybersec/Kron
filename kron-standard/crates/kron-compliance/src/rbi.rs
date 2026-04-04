//! RBI IS (Information Security) framework — compliance module.
//!
//! The RBI Cybersecurity Framework for Banks and the Master Direction on IT
//! Governance require regulated entities to:
//!
//! - Maintain an IS audit trail of all privileged access and config changes.
//! - Report cybersecurity incidents to CERT-In and RBI within **2–6 hours**.
//! - Demonstrate data localisation (customer data stored within India).
//! - Implement continuous monitoring and immediate alerting on anomalies.
//!
//! KRON maps these requirements to:
//! - Privileged access trail → `audit_log` where `actor_type = 'admin'`.
//! - Incident reporting → alerts tagged with MITRE T1486 / T1489 / T1498.
//! - Data localisation → deployment metadata (always on-premise in India).

use serde::{Deserialize, Serialize};

/// A privileged access record for the RBI IS audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedAccessRecord {
    /// The admin/privileged user who performed the action.
    pub actor_id: String,
    /// The action performed: `"config_change"`, `"admin_login"`, `"data_export"`, etc.
    pub action: String,
    /// The resource affected.
    pub resource: String,
    /// ISO-8601 UTC timestamp.
    pub timestamp: String,
    /// Result: `"success"` | `"failure"` | `"denied"`.
    pub result: String,
    /// Source IP of the admin session.
    pub source_ip: Option<String>,
}

/// Data localisation verification record.
///
/// RBI requires all customer data to be stored within India.
/// KRON is on-premise — this record captures the evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLocalisationRecord {
    /// Storage backend in use: `"DuckDB (on-premise)"` / `"ClickHouse (on-premise)"`.
    pub storage_backend: String,
    /// Server hostname or IP.
    pub server_hostname: String,
    /// Whether data residency is confirmed within India.
    pub india_resident: bool,
    /// Any cloud egress points (must be empty for compliance).
    pub cloud_egress: Vec<String>,
    /// Verification timestamp.
    pub verified_at: String,
}

/// Renders the RBI IS compliance section as an HTML fragment.
///
/// # Arguments
/// * `privileged_records` — Privileged access audit trail for the period.
/// * `localisation`       — Data localisation verification snapshot.
/// * `incident_count`     — Total reportable incidents in the period.
#[must_use]
pub fn render_html_section(
    privileged_records: &[PrivilegedAccessRecord],
    localisation: &DataLocalisationRecord,
    incident_count: u64,
) -> String {
    let mut html = String::with_capacity(4096);

    html.push_str("<section id=\"rbi\">\n");
    html.push_str("<h2>RBI IS Framework — Compliance Report</h2>\n");

    // ── Data localisation ─────────────────────────────────────────────────────
    html.push_str("<h3>Data Localisation Verification</h3>\n");
    let loc_class = if localisation.india_resident && localisation.cloud_egress.is_empty() {
        "ok"
    } else {
        "critical"
    };
    html.push_str(&format!(
        "<p class=\"{loc_class}\">Storage: {} | Server: {} | India Resident: {} | Cloud Egress: {}</p>\n",
        html_escape(&localisation.storage_backend),
        html_escape(&localisation.server_hostname),
        if localisation.india_resident { "Yes ✓" } else { "No ✗" },
        if localisation.cloud_egress.is_empty() {
            "None ✓".to_owned()
        } else {
            localisation.cloud_egress.join(", ")
        },
    ));

    // ── Incident summary ──────────────────────────────────────────────────────
    html.push_str("<h3>Reportable Incidents</h3>\n");
    html.push_str(&format!(
        "<p>Total reportable cyber incidents in period: <strong>{incident_count}</strong></p>\n"
    ));

    // ── Privileged access trail ───────────────────────────────────────────────
    html.push_str("<h3>Privileged Access Audit Trail</h3>\n");
    if privileged_records.is_empty() {
        html.push_str("<p class=\"ok\">No privileged access events in this period.</p>\n");
    } else {
        html.push_str("<table>\n<thead><tr>\
            <th>Actor</th><th>Action</th><th>Resource</th>\
            <th>Timestamp</th><th>Result</th><th>Source IP</th>\
            </tr></thead>\n<tbody>\n");

        for r in privileged_records {
            let result_class = match r.result.as_str() {
                "success" => "ok",
                "failure" | "denied" => "warn",
                _ => "",
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td class=\"{result_class}\">{}</td><td>{}</td></tr>\n",
                html_escape(&r.actor_id),
                html_escape(&r.action),
                html_escape(&r.resource),
                html_escape(&r.timestamp),
                html_escape(&r.result),
                r.source_ip
                    .as_deref()
                    .map(html_escape)
                    .unwrap_or_default(),
            ));
        }
        html.push_str("</tbody></table>\n");
    }

    html.push_str("</section>\n");
    html
}

/// Escapes HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_html_section_when_no_records_then_contains_no_events() {
        let loc = DataLocalisationRecord {
            storage_backend: "ClickHouse (on-premise)".to_owned(),
            server_hostname: "kron-prod-01".to_owned(),
            india_resident: true,
            cloud_egress: vec![],
            verified_at: "2026-03-25T00:00:00Z".to_owned(),
        };
        let html = render_html_section(&[], &loc, 0);
        assert!(html.contains("RBI IS Framework"));
        assert!(html.contains("India Resident: Yes"));
        assert!(html.contains("None ✓"));
    }
}
