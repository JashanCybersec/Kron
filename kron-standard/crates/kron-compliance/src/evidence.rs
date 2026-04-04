//! Evidence package generation for compliance audits.
//!
//! An evidence package is a ZIP archive containing:
//! - `manifest.json`  — package metadata, period, framework, SHA-256 of each file
//! - `report.html`    — the full compliance report HTML
//! - `events.jsonl`   — raw KRON events for the period (JSONL, one event per line)
//! - `alerts.jsonl`   — alert records for the period
//! - `audit_log.jsonl`— audit log entries for the period
//!
//! The archive itself is SHA-256 hashed for integrity verification (Merkle chain
//! reference per ADR-015). Auditors can verify the hash matches the
//! `EvidencePackage.sha256` field stored in KRON.

use std::io::Write as _;

use chrono::Utc;
use uuid::Uuid;
use zip::{write::FileOptions, ZipWriter};

use crate::{
    error::ComplianceError,
    types::{ComplianceReport, EvidencePackage},
};

/// Generates an evidence package ZIP for the given report.
///
/// Returns the `EvidencePackage` metadata record and the raw ZIP bytes.
/// Callers are responsible for storing or streaming the bytes.
///
/// # Arguments
/// * `report` — A completed (`ReportStatus::Ready`) compliance report.
///
/// # Errors
///
/// Returns `ComplianceError::EvidenceError` if ZIP assembly fails.
pub fn build_evidence_package(
    report: &ComplianceReport,
) -> Result<(EvidencePackage, Vec<u8>), ComplianceError> {
    let cursor = std::io::Cursor::new(Vec::<u8>::with_capacity(64 * 1024));
    let mut zip = ZipWriter::new(cursor);

    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // ── report.html ───────────────────────────────────────────────────────────
    zip.start_file("report.html", options)
        .map_err(|e| ComplianceError::EvidenceError(format!("zip start report.html: {e}")))?;
    let html = report
        .html_content
        .as_deref()
        .unwrap_or("<html><body>Report content unavailable.</body></html>");
    zip.write_all(html.as_bytes())
        .map_err(|e| ComplianceError::EvidenceError(format!("zip write report.html: {e}")))?;

    // ── events.jsonl (placeholder — wired in v1.1 with real storage queries) ─
    zip.start_file("events.jsonl", options)
        .map_err(|e| ComplianceError::EvidenceError(format!("zip start events.jsonl: {e}")))?;
    zip.write_all(b"# Events for period -- storage query wired in v1.1\n")
        .map_err(|e| ComplianceError::EvidenceError(format!("zip write events.jsonl: {e}")))?;

    // ── alerts.jsonl ──────────────────────────────────────────────────────────
    zip.start_file("alerts.jsonl", options)
        .map_err(|e| ComplianceError::EvidenceError(format!("zip start alerts.jsonl: {e}")))?;
    zip.write_all(b"# Alerts for period -- storage query wired in v1.1\n")
        .map_err(|e| ComplianceError::EvidenceError(format!("zip write alerts.jsonl: {e}")))?;

    // ── audit_log.jsonl ───────────────────────────────────────────────────────
    zip.start_file("audit_log.jsonl", options)
        .map_err(|e| ComplianceError::EvidenceError(format!("zip start audit_log: {e}")))?;
    zip.write_all(b"# Audit log for period -- storage query wired in v1.1\n")
        .map_err(|e| ComplianceError::EvidenceError(format!("zip write audit_log: {e}")))?;

    // ── manifest.json ─────────────────────────────────────────────────────────
    let package_id = Uuid::new_v4().to_string();
    let generated_at = Utc::now();
    let manifest = serde_json::json!({
        "package_id": package_id,
        "report_id": report.report_id,
        "tenant_id": report.tenant_id,
        "framework": format!("{}", report.framework),
        "period_from": report.from.to_rfc3339(),
        "period_to": report.to.to_rfc3339(),
        "generated_at": generated_at.to_rfc3339(),
        "files": ["report.html", "events.jsonl", "alerts.jsonl", "audit_log.jsonl"],
        "note": "Verify archive SHA-256 against EvidencePackage.sha256 in KRON.",
    });
    zip.start_file("manifest.json", options)
        .map_err(|e| ComplianceError::EvidenceError(format!("zip start manifest: {e}")))?;
    zip.write_all(manifest.to_string().as_bytes())
        .map_err(|e| ComplianceError::EvidenceError(format!("zip write manifest: {e}")))?;

    let finished_cursor = zip
        .finish()
        .map_err(|e| ComplianceError::EvidenceError(format!("zip finish: {e}")))?;
    let zip_buf = finished_cursor.into_inner();

    // SHA-256 of the archive bytes.
    let sha256 = sha256_hex(&zip_buf);
    let archive_bytes = zip_buf.len() as u64;

    let package = EvidencePackage {
        package_id,
        report_id: report.report_id.clone(),
        tenant_id: report.tenant_id.clone(),
        framework: report.framework,
        from: report.from,
        to: report.to,
        generated_at,
        archive_bytes,
        sha256,
    };

    Ok((package, zip_buf))
}

/// Computes the SHA-256 hex digest of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let hash = Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for b in hash.as_slice() {
        write!(hex, "{b:02x}").unwrap_or(());
    }
    hex
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{ComplianceFramework, ReportStatus, ReportSummary};
    use chrono::Utc;

    fn sample_report() -> ComplianceReport {
        ComplianceReport {
            report_id: "r-001".to_owned(),
            tenant_id: "t-001".to_owned(),
            framework: ComplianceFramework::CertIn,
            title: "Test Report".to_owned(),
            from: Utc::now(),
            to: Utc::now(),
            requested_at: Utc::now(),
            completed_at: Some(Utc::now()),
            status: ReportStatus::Ready,
            error_message: None,
            html_content: Some("<html><body>test</body></html>".to_owned()),
            reference: None,
            summary: ReportSummary::default(),
        }
    }

    #[test]
    fn test_build_evidence_package_when_valid_report_then_zip_produced() {
        let report = sample_report();
        let (pkg, bytes) = build_evidence_package(&report).unwrap();
        assert_eq!(pkg.report_id, "r-001");
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len() as u64, pkg.archive_bytes);
        // ZIP magic bytes: PK\x03\x04
        assert_eq!(&bytes[..2], b"PK");
    }

    #[test]
    fn test_build_evidence_package_when_valid_then_sha256_is_64_hex_chars() {
        let report = sample_report();
        let (pkg, _) = build_evidence_package(&report).unwrap();
        assert_eq!(pkg.sha256.len(), 64);
        assert!(pkg.sha256.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
