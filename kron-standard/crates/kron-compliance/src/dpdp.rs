//! Digital Personal Data Protection (DPDP) Act 2023 — compliance module.
//!
//! The DPDP Act requires organisations to:
//! - Maintain an audit trail of all access to personal data.
//! - Report data breaches to the Data Protection Board of India (DPBI)
//!   and to affected data principals within **72 hours** of becoming aware.
//! - Demonstrate purpose limitation and data minimisation.
//!
//! KRON maps these requirements to its audit log and alert tables:
//! - Personal data access trail → `audit_log` rows where `resource_type = 'personal_data'`.
//! - Breach detection → alerts tagged with CERT-In Category 11 (data breach).

use serde::{Deserialize, Serialize};

/// A single personal data access record from the KRON audit log.
///
/// Used to populate the DPDP access trail section of compliance reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalDataAccessRecord {
    /// The user or service that accessed personal data.
    pub actor_id: String,
    /// Human-readable actor type: `"analyst"`, `"api_key"`, `"service"`.
    pub actor_type: String,
    /// What they did: `"view"`, `"export"`, `"query"`, `"delete"`.
    pub action: String,
    /// The category of personal data accessed (e.g. `"pii"`, `"financial"`, `"health"`).
    pub data_category: String,
    /// Number of records accessed in this operation.
    pub records_count: Option<u64>,
    /// ISO-8601 UTC timestamp of the access.
    pub accessed_at: String,
    /// Stated purpose for the access (populated from audit log `detail` field).
    pub purpose: Option<String>,
    /// Whether explicit consent was recorded (true/false/unknown).
    pub consent_recorded: bool,
}

/// A data breach notification record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBreachRecord {
    /// KRON alert ID.
    pub alert_id: String,
    /// ISO-8601 UTC timestamp when KRON first detected the breach.
    pub detected_at: String,
    /// Nature of the breach (source from CERT-In category description).
    pub nature: String,
    /// Estimated number of data principals affected.
    pub estimated_affected: Option<u64>,
    /// Whether the 72-hour notification deadline has passed.
    pub notification_overdue: bool,
    /// Hours remaining until the DPBI notification deadline (negative if overdue).
    pub hours_until_deadline: i64,
}

/// Computes the DPDP breach notification deadline status.
///
/// The DPDP Act requires notification within 72 hours of becoming aware
/// of the breach. Returns the number of hours remaining (negative if overdue).
///
/// # Arguments
/// * `detected_at_iso` — ISO-8601 UTC string when the breach was detected.
#[must_use]
pub fn deadline_status(detected_at_iso: &str) -> (bool, i64) {
    let Ok(detected) = chrono::DateTime::parse_from_rfc3339(detected_at_iso) else {
        return (false, 72);
    };

    let now = chrono::Utc::now();
    let elapsed_hours = (now.signed_duration_since(detected.with_timezone(&chrono::Utc)))
        .num_hours();
    let hours_remaining = 72 - elapsed_hours;
    let overdue = hours_remaining < 0;
    (overdue, hours_remaining)
}

/// Renders the DPDP compliance section as an HTML fragment.
///
/// The returned string is embedded inside the full report HTML by
/// [`crate::report::ReportEngine`].
///
/// # Arguments
/// * `access_records` — All personal data access events in the report period.
/// * `breaches`       — All data breach alerts in the report period.
#[must_use]
pub fn render_html_section(
    access_records: &[PersonalDataAccessRecord],
    breaches: &[DataBreachRecord],
) -> String {
    let mut html = String::with_capacity(4096);

    html.push_str("<section id=\"dpdp\">\n");
    html.push_str("<h2>DPDP Act 2023 — Compliance Report</h2>\n");

    // ── Personal data access trail ────────────────────────────────────────────
    html.push_str("<h3>Personal Data Access Trail</h3>\n");
    if access_records.is_empty() {
        html.push_str("<p class=\"ok\">No personal data access events in this period.</p>\n");
    } else {
        html.push_str("<table>\n<thead><tr>\
            <th>Actor</th><th>Type</th><th>Action</th>\
            <th>Data Category</th><th>Records</th>\
            <th>Accessed At</th><th>Purpose</th><th>Consent</th>\
            </tr></thead>\n<tbody>\n");

        for r in access_records {
            let consent_class = if r.consent_recorded { "ok" } else { "warn" };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td>\
                 <td class=\"{consent_class}\">{}</td></tr>\n",
                html_escape(&r.actor_id),
                html_escape(&r.actor_type),
                html_escape(&r.action),
                html_escape(&r.data_category),
                r.records_count.map_or("-".to_owned(), |n| n.to_string()),
                html_escape(&r.accessed_at),
                r.purpose
                    .as_deref()
                    .map(html_escape)
                    .unwrap_or_else(|| "<em>not recorded</em>".to_owned()),
                if r.consent_recorded { "Yes" } else { "No" },
            ));
        }
        html.push_str("</tbody></table>\n");
    }

    // ── Data breach notifications ─────────────────────────────────────────────
    html.push_str("<h3>Data Breach Notifications</h3>\n");
    if breaches.is_empty() {
        html.push_str("<p class=\"ok\">No data breach incidents in this period.</p>\n");
    } else {
        html.push_str("<table>\n<thead><tr>\
            <th>Alert ID</th><th>Detected At</th><th>Nature</th>\
            <th>Affected</th><th>Deadline Status</th>\
            </tr></thead>\n<tbody>\n");

        for b in breaches {
            let status_class = if b.notification_overdue { "critical" } else { "ok" };
            let deadline_text = if b.notification_overdue {
                format!("OVERDUE by {} hours", b.hours_until_deadline.unsigned_abs())
            } else {
                format!("{} hours remaining", b.hours_until_deadline)
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td class=\"{status_class}\">{deadline_text}</td></tr>\n",
                html_escape(&b.alert_id),
                html_escape(&b.detected_at),
                html_escape(&b.nature),
                b.estimated_affected
                    .map_or("Unknown".to_owned(), |n| n.to_string()),
            ));
        }
        html.push_str("</tbody></table>\n");
    }

    html.push_str("</section>\n");
    html
}

/// Escapes HTML special characters in a string.
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
    fn test_deadline_status_when_recent_then_not_overdue() {
        // A breach detected 10 minutes ago should have ~71h50m remaining.
        let recent = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::minutes(10))
            .unwrap()
            .to_rfc3339();
        let (overdue, remaining) = deadline_status(&recent);
        assert!(!overdue);
        assert!(remaining >= 71);
    }

    #[test]
    fn test_deadline_status_when_old_then_overdue() {
        let old = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::hours(80))
            .unwrap()
            .to_rfc3339();
        let (overdue, remaining) = deadline_status(&old);
        assert!(overdue);
        assert!(remaining < 0);
    }

    #[test]
    fn test_render_html_section_when_empty_then_contains_no_events_message() {
        let html = render_html_section(&[], &[]);
        assert!(html.contains("No personal data access events"));
        assert!(html.contains("No data breach incidents"));
    }
}
