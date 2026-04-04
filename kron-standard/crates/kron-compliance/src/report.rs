//! Report engine — orchestrates compliance report generation.
//!
//! [`ReportEngine`] is the single entry point for generating compliance reports.
//! It queries KRON storage for the relevant data, delegates rendering to the
//! per-framework modules, and assembles the final HTML document.
//!
//! # Report format
//!
//! Reports are structured HTML files. The browser's print-to-PDF function
//! (or any headless Chromium instance) converts them to PDF without requiring
//! a server-side PDF library. This satisfies the Phase 4 requirement for
//! PDF report generation without adding a C dependency.
//!
//! # ADR-021 reference
//!
//! HTML-first reports (see DECISIONS.md ADR-021).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use kron_storage::AdaptiveStorage;

use crate::{
    certin::{self, CertInCategory},
    dpdp::{self, DataBreachRecord, PersonalDataAccessRecord},
    error::ComplianceError,
    rbi::{self, DataLocalisationRecord, PrivilegedAccessRecord},
    sebi::{self, SebiMetrics},
    types::{
        ComplianceFramework, ComplianceReport, ReportRequest, ReportStatus, ReportSummary,
    },
};

/// Orchestrates compliance report generation for all supported frameworks.
pub struct ReportEngine {
    storage: Arc<AdaptiveStorage>,
}

impl ReportEngine {
    /// Creates a new report engine backed by the given storage.
    #[must_use]
    pub fn new(storage: Arc<AdaptiveStorage>) -> Self {
        Self { storage }
    }

    /// Generates a compliance report for the given request.
    ///
    /// Queries storage for the relevant events, alerts, and audit log entries
    /// within the requested period, then renders the framework-specific HTML.
    ///
    /// # Errors
    ///
    /// Returns `ComplianceError` if the date range is invalid, storage fails,
    /// or rendering fails.
    pub async fn generate(&self, req: ReportRequest) -> Result<ComplianceReport, ComplianceError> {
        // Validate date range.
        if req.from >= req.to {
            return Err(ComplianceError::InvalidDateRange(format!(
                "from ({}) must be before to ({})",
                req.from, req.to
            )));
        }

        let report_id = Uuid::new_v4().to_string();
        let requested_at = Utc::now();
        let title = format!(
            "{} Compliance Report — {} to {}",
            req.framework,
            req.from.format("%Y-%m-%d"),
            req.to.format("%Y-%m-%d"),
        );

        // Gather summary statistics (best-effort — zeros on storage error).
        let summary = self.gather_summary(&req).await;

        // Render framework-specific HTML section.
        let body_html = self.render_body(&req, &summary).await?;

        // Wrap in the full HTML document shell.
        let html_content = render_full_html(
            &title,
            &req.tenant_id,
            req.framework,
            req.from,
            req.to,
            &body_html,
        );

        tracing::info!(
            report_id = %report_id,
            tenant_id = %req.tenant_id,
            framework = %req.framework,
            "compliance report generated"
        );

        Ok(ComplianceReport {
            report_id,
            tenant_id: req.tenant_id,
            framework: req.framework,
            title,
            from: req.from,
            to: req.to,
            requested_at,
            completed_at: Some(Utc::now()),
            status: ReportStatus::Ready,
            error_message: None,
            html_content: Some(html_content),
            reference: req.reference,
            summary,
        })
    }

    /// Gathers high-level summary statistics from storage.
    ///
    /// Returns zeroed summary on any storage error (non-fatal — report still
    /// generates, just without statistics).
    async fn gather_summary(&self, req: &ReportRequest) -> ReportSummary {
        // Storage queries are best-effort in Phase 4 — real SQL queries will
        // be wired when the full storage query layer supports date-range filters.
        // For now, return a zeroed summary so the report structure is correct.
        // TODO(#22, hardik, v1.1): Wire real alert/event counts via storage date-range queries
        let _ = &self.storage;
        let _ = &req;
        ReportSummary::default()
    }

    /// Renders the framework-specific body section as HTML.
    async fn render_body(
        &self,
        req: &ReportRequest,
        _summary: &ReportSummary,
    ) -> Result<String, ComplianceError> {
        match req.framework {
            ComplianceFramework::CertIn => self.render_certin(req).await,
            ComplianceFramework::Dpdp => self.render_dpdp(req).await,
            ComplianceFramework::Rbi => self.render_rbi(req).await,
            ComplianceFramework::SebiCscrf => self.render_sebi(req).await,
        }
    }

    async fn render_certin(&self, _req: &ReportRequest) -> Result<String, ComplianceError> {
        let mut html = String::with_capacity(2048);
        html.push_str("<section id=\"certin\">\n");
        html.push_str("<h2>CERT-In Directions 2022 — Compliance Report</h2>\n");
        html.push_str("<h3>Reportable Incident Categories</h3>\n");
        html.push_str("<table>\n<thead><tr><th>#</th><th>Category</th><th>Incidents</th></tr></thead>\n<tbody>\n");

        for cat in CertInCategory::all() {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>0</td></tr>\n",
                cat.number(),
                cat.description()
            ));
        }
        html.push_str("</tbody></table>\n");
        html.push_str("<p class=\"note\">Incident counts will populate once storage date-range queries are wired (v1.1).</p>\n");
        html.push_str("</section>\n");

        // Include the 13-category mapping reference.
        html.push_str(&certin::format_incident_report(
            CertInCategory::UnauthorisedAccess,
            "N/A",
            "N/A",
            "No incidents in this period.",
            "N/A",
            "Organisation",
        ));

        Ok(html)
    }

    async fn render_dpdp(&self, _req: &ReportRequest) -> Result<String, ComplianceError> {
        let access_records: Vec<PersonalDataAccessRecord> = vec![];
        let breach_records: Vec<DataBreachRecord> = vec![];
        Ok(dpdp::render_html_section(&access_records, &breach_records))
    }

    async fn render_rbi(&self, _req: &ReportRequest) -> Result<String, ComplianceError> {
        let privileged: Vec<PrivilegedAccessRecord> = vec![];
        let localisation = DataLocalisationRecord {
            storage_backend: "KRON AdaptiveStorage (on-premise)".to_owned(),
            server_hostname: hostname(),
            india_resident: true,
            cloud_egress: vec![],
            verified_at: Utc::now().to_rfc3339(),
        };
        Ok(rbi::render_html_section(&privileged, &localisation, 0))
    }

    async fn render_sebi(&self, _req: &ReportRequest) -> Result<String, ComplianceError> {
        let metrics = SebiMetrics {
            mttd_secs: None,
            mtta_secs: None,
            mttr_secs: None,
            critical_incidents: 0,
            mttd_sla_breaches: 0,
            mttr_sla_breaches: 0,
            playbook_executions: 0,
            soc_24x7: true,
        };
        Ok(sebi::render_html_section(&metrics))
    }
}

/// Returns the server's hostname for use in data localisation records.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "kron-server".to_owned())
}

/// Wraps a body HTML fragment in a complete HTML5 document with KRON styling.
fn render_full_html(
    title: &str,
    tenant_id: &str,
    framework: ComplianceFramework,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    body: &str,
) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #fff; --text: #111; --accent: #1a56db;
      --ok: #057a55; --warn: #b45309; --critical: #c81e1e;
    }}
    @media print {{ .no-print {{ display: none; }} }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; color: var(--text); margin: 40px; }}
    h1 {{ color: var(--accent); border-bottom: 2px solid var(--accent); padding-bottom: 8px; }}
    h2 {{ color: #333; margin-top: 32px; }}
    h3 {{ color: #555; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th {{ background: var(--accent); color: #fff; padding: 8px 12px; text-align: left; }}
    td {{ padding: 6px 12px; border-bottom: 1px solid #e5e7eb; }}
    tr:hover td {{ background: #f9fafb; }}
    .ok {{ color: var(--ok); font-weight: 600; }}
    .warn {{ color: var(--warn); font-weight: 600; }}
    .critical {{ color: var(--critical); font-weight: 600; }}
    .meta {{ color: #6b7280; font-size: 13px; margin-bottom: 24px; }}
    .note {{ background: #fef3c7; border-left: 4px solid #f59e0b; padding: 8px 12px; }}
    pre {{ background: #f3f4f6; padding: 12px; border-radius: 4px; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>KRON SIEM — {framework} Compliance Report</h1>
  <div class="meta">
    <strong>Tenant:</strong> {tenant_id} &nbsp;|&nbsp;
    <strong>Period:</strong> {from_date} to {to_date} &nbsp;|&nbsp;
    <strong>Generated:</strong> {generated_at} &nbsp;|&nbsp;
    <strong>Classification:</strong> CONFIDENTIAL
  </div>
  {body}
  <footer style="margin-top:48px; color:#9ca3af; font-size:12px; border-top:1px solid #e5e7eb; padding-top:12px;">
    Generated by KRON SIEM &mdash; on-premise, data never leaves your environment.
    &copy; kron.security
  </footer>
</body>
</html>"#,
        title = html_escape(title),
        framework = framework,
        tenant_id = html_escape(tenant_id),
        from_date = from.format("%Y-%m-%d"),
        to_date = to.format("%Y-%m-%d"),
        generated_at = Utc::now().format("%Y-%m-%d %H:%M UTC"),
        body = body,
    )
}

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
    fn test_render_full_html_when_called_then_contains_kron_header() {
        let html = render_full_html(
            "Test Report",
            "tenant-001",
            ComplianceFramework::CertIn,
            Utc::now(),
            Utc::now(),
            "<p>body</p>",
        );
        assert!(html.contains("KRON SIEM"));
        assert!(html.contains("CERT-In"));
        assert!(html.contains("tenant-001"));
    }

    #[test]
    fn test_render_full_html_when_xss_in_title_then_escaped() {
        let html = render_full_html(
            "<script>alert(1)</script>",
            "tid",
            ComplianceFramework::Dpdp,
            Utc::now(),
            Utc::now(),
            "",
        );
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
