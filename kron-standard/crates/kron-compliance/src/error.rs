//! Compliance engine error types.

use thiserror::Error;

/// All error variants that the compliance engine can produce.
#[derive(Debug, Error)]
pub enum ComplianceError {
    /// The requested compliance framework is not enabled for this tenant.
    #[error("framework '{0}' is not enabled for tenant '{1}'")]
    FrameworkNotEnabled(String, String),

    /// The date range given is invalid (e.g. `from` is after `to`).
    #[error("invalid date range: {0}")]
    InvalidDateRange(String),

    /// Storage query failed while gathering evidence.
    #[error("storage error while gathering evidence: {0}")]
    StorageError(String),

    /// The report ID does not exist or belongs to a different tenant.
    #[error("report '{0}' not found")]
    ReportNotFound(String),

    /// Evidence package generation failed.
    #[error("evidence package error: {0}")]
    EvidenceError(String),

    /// HTML/report template rendering failed.
    #[error("report rendering error: {0}")]
    RenderError(String),

    /// The incident category does not map to a known CERT-In category.
    #[error("unknown CERT-In category: {0}")]
    UnknownCertInCategory(String),
}
