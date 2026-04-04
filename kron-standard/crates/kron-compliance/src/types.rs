//! Shared types for the compliance engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The regulatory framework a report covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    /// CERT-In Directions 2022 — 13 reportable incident categories.
    CertIn,
    /// Digital Personal Data Protection Act 2023.
    Dpdp,
    /// RBI Information Security / Cyber Security framework.
    Rbi,
    /// SEBI Cyber Security and Cyber Resilience Framework.
    SebiCscrf,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertIn => write!(f, "CERT-In"),
            Self::Dpdp => write!(f, "DPDP Act"),
            Self::Rbi => write!(f, "RBI IS"),
            Self::SebiCscrf => write!(f, "SEBI CSCRF"),
        }
    }
}

/// Status of a compliance report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Generation is queued or in progress.
    Pending,
    /// Report generated successfully.
    Ready,
    /// Generation failed — see `error_message`.
    Failed,
}

/// A request to generate a compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    /// Tenant UUID (from JWT — never from request body).
    pub tenant_id: String,
    /// Framework the report covers.
    pub framework: ComplianceFramework,
    /// Report period start (ISO-8601 UTC).
    pub from: DateTime<Utc>,
    /// Report period end (ISO-8601 UTC).
    pub to: DateTime<Utc>,
    /// Optional free-text reference (e.g. audit reference number).
    pub reference: Option<String>,
}

/// A completed (or pending) compliance report record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Unique report UUID.
    pub report_id: String,
    /// Tenant this report belongs to.
    pub tenant_id: String,
    /// Framework covered.
    pub framework: ComplianceFramework,
    /// Human-readable title.
    pub title: String,
    /// Report period start.
    pub from: DateTime<Utc>,
    /// Report period end.
    pub to: DateTime<Utc>,
    /// When the report was requested.
    pub requested_at: DateTime<Utc>,
    /// When generation completed (if status is Ready).
    pub completed_at: Option<DateTime<Utc>>,
    /// Current status.
    pub status: ReportStatus,
    /// Error message if status is Failed.
    pub error_message: Option<String>,
    /// HTML report content (present when status is Ready).
    pub html_content: Option<String>,
    /// Optional audit reference.
    pub reference: Option<String>,
    /// Summary statistics embedded in the report.
    pub summary: ReportSummary,
}

/// High-level statistics included in every report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total events in the period.
    pub total_events: u64,
    /// Total alerts raised in the period.
    pub total_alerts: u64,
    /// P1 alerts (Critical).
    pub p1_alerts: u64,
    /// P2 alerts (High).
    pub p2_alerts: u64,
    /// Mean time to acknowledge (seconds).
    pub mean_tta_secs: Option<u64>,
    /// Mean time to resolve (seconds).
    pub mean_ttr_secs: Option<u64>,
    /// Number of open (unresolved) incidents at period end.
    pub open_incidents: u64,
}

/// An evidence package bundling events, alerts, and audit log for a date range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    /// Unique package UUID.
    pub package_id: String,
    /// The report this package was generated for.
    pub report_id: String,
    /// Tenant UUID.
    pub tenant_id: String,
    /// Framework.
    pub framework: ComplianceFramework,
    /// Period covered.
    pub from: DateTime<Utc>,
    /// Period end.
    pub to: DateTime<Utc>,
    /// When the package was generated.
    pub generated_at: DateTime<Utc>,
    /// Total bytes in the ZIP archive.
    pub archive_bytes: u64,
    /// SHA-256 hex digest of the archive for integrity verification.
    pub sha256: String,
}
