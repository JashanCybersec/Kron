//! Compliance report handlers.
//!
//! Exposes the KRON compliance engine via REST endpoints so analysts and
//! admins can generate and download reports without CLI access.
//!
//! # Endpoints
//!
//! - `GET  /api/v1/compliance/reports`                      — list reports for tenant
//! - `POST /api/v1/compliance/reports`                      — generate a new report
//! - `GET  /api/v1/compliance/reports/{id}/evidence`        — download evidence ZIP
//!
//! # Feature gate
//!
//! All handlers in this file require the `standard` Cargo feature. Without it
//! the handlers are not compiled and the compliance routes are not registered.

#![cfg(feature = "standard")]

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use chrono::Utc;
use kron_auth::rbac::{Action, Resource};
use kron_compliance::{
    evidence::build_evidence_package, types::ComplianceFramework, ReportEngine, ReportRequest,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{error::ApiError, middleware::AuthUser, state::AppState};

// ── In-memory report store (Phase 4 — persisted in v1.1) ─────────────────────

/// Global in-process report cache (keyed by `tenant_id:report_id`).
///
/// Phase 4 stores reports in-memory. A persistent store (ClickHouse table or
/// file system) will be wired in v1.1 when the storage schema is extended.
/// TODO(#24, hardik, v1.1): Persist compliance reports to storage layer
static REPORT_STORE: once_cell::sync::Lazy<
    Arc<RwLock<std::collections::HashMap<String, kron_compliance::ComplianceReport>>>,
> = once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(std::collections::HashMap::new())));

// ── Request / Response types ──────────────────────────────────────────────────

/// Request body for `POST /api/v1/compliance/reports`.
#[derive(Debug, Deserialize)]
pub struct GenerateReportRequest {
    /// Framework to generate: `cert_in` | `dpdp` | `rbi` | `sebi_cscrf`.
    pub framework: String,
    /// Period start (ISO-8601 UTC).
    pub from: String,
    /// Period end (ISO-8601 UTC).
    pub to: String,
    /// Optional audit reference number.
    pub reference: Option<String>,
}

/// Summary row returned in the reports list.
#[derive(Debug, Serialize)]
pub struct ReportSummaryRow {
    /// Report UUID.
    pub report_id: String,
    /// Framework.
    pub framework: String,
    /// Human-readable title.
    pub title: String,
    /// Period start.
    pub from: String,
    /// Period end.
    pub to: String,
    /// When requested.
    pub requested_at: String,
    /// Status: `pending` | `ready` | `failed`.
    pub status: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Lists compliance reports for the authenticated tenant.
///
/// Returns reports sorted by `requested_at` descending (newest first).
///
/// # Errors
///
/// - `403` — caller lacks `Compliance.Read`.
#[tracing::instrument(skip(state, user), fields(tenant_id = %user.tenant_id))]
pub async fn list_reports(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<ReportSummaryRow>>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Compliance) {
        return Err(ApiError::Forbidden(
            "Compliance.Read permission required".to_owned(),
        ));
    }

    let _ = &state; // storage will be used in v1.1
    let store = REPORT_STORE.read().await;
    let tenant_prefix = format!("{}:", user.tenant_id);

    let mut rows: Vec<ReportSummaryRow> = store
        .iter()
        .filter(|(k, _)| k.starts_with(&tenant_prefix))
        .map(|(_, r)| ReportSummaryRow {
            report_id: r.report_id.clone(),
            framework: r.framework.to_string(),
            title: r.title.clone(),
            from: r.from.to_rfc3339(),
            to: r.to.to_rfc3339(),
            requested_at: r.requested_at.to_rfc3339(),
            status: format!("{:?}", r.status).to_lowercase(),
        })
        .collect();

    rows.sort_by(|a, b| b.requested_at.cmp(&a.requested_at));
    Ok(Json(rows))
}

/// Generates a new compliance report for the authenticated tenant.
///
/// Report generation is synchronous in Phase 4 (completes within the request).
/// Async job queue will be wired in v1.1 for large date ranges.
///
/// # Errors
///
/// - `403` — caller lacks `Compliance.Read`.
/// - `400` — invalid framework string, invalid date format, or invalid date range.
#[tracing::instrument(skip(state, user, req), fields(tenant_id = %user.tenant_id))]
pub async fn generate_report(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<GenerateReportRequest>,
) -> Result<(StatusCode, Json<ReportSummaryRow>), ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Compliance) {
        return Err(ApiError::Forbidden(
            "Compliance.Read permission required".to_owned(),
        ));
    }

    let framework = parse_framework(&req.framework)?;

    let from = chrono::DateTime::parse_from_rfc3339(&req.from)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ApiError::BadRequest(format!("invalid 'from' date: {}", req.from)))?;

    let to = chrono::DateTime::parse_from_rfc3339(&req.to)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ApiError::BadRequest(format!("invalid 'to' date: {}", req.to)))?;

    let report_req = ReportRequest {
        tenant_id: user.tenant_id.to_string(),
        framework,
        from,
        to,
        reference: req.reference,
    };

    let engine = ReportEngine::new(Arc::clone(&state.storage));
    let report = engine.generate(report_req).await.map_err(|e| {
        tracing::error!(
            tenant_id = %user.tenant_id,
            error = %e,
            "compliance report generation failed"
        );
        ApiError::Internal(format!("report generation failed: {e}"))
    })?;

    let row = ReportSummaryRow {
        report_id: report.report_id.clone(),
        framework: report.framework.to_string(),
        title: report.title.clone(),
        from: report.from.to_rfc3339(),
        to: report.to.to_rfc3339(),
        requested_at: report.requested_at.to_rfc3339(),
        status: "ready".to_owned(),
    };

    // Store in-memory for subsequent evidence download.
    let store_key = format!("{}:{}", user.tenant_id, report.report_id);
    REPORT_STORE.write().await.insert(store_key, report);

    Ok((StatusCode::CREATED, Json(row)))
}

/// Downloads the evidence package ZIP for a report.
///
/// Returns the archive as `application/zip` with a `Content-Disposition`
/// header so browsers save it as `kron-evidence-{report_id}.zip`.
///
/// # Errors
///
/// - `403` — caller lacks `Compliance.Read` or the report belongs to another tenant.
/// - `404` — report not found.
#[tracing::instrument(skip(state, user), fields(tenant_id = %user.tenant_id, report_id = %report_id))]
pub async fn export_evidence(
    State(state): State<AppState>,
    user: AuthUser,
    Path(report_id): Path<String>,
) -> Result<Response, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Compliance) {
        return Err(ApiError::Forbidden(
            "Compliance.Read permission required".to_owned(),
        ));
    }

    let _ = &state;
    let store_key = format!("{}:{}", user.tenant_id, report_id);
    let store = REPORT_STORE.read().await;

    let report = store
        .get(&store_key)
        .ok_or_else(|| ApiError::NotFound(format!("report '{report_id}' not found")))?;

    let (pkg, zip_bytes) = build_evidence_package(report).map_err(|e| {
        tracing::error!(report_id = %report_id, error = %e, "evidence package generation failed");
        ApiError::Internal(format!("evidence package failed: {e}"))
    })?;

    tracing::info!(
        tenant_id = %user.tenant_id,
        report_id = %report_id,
        package_id = %pkg.package_id,
        archive_bytes = pkg.archive_bytes,
        sha256 = %pkg.sha256,
        "evidence package generated"
    );

    let filename = format!("kron-evidence-{report_id}.zip");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CONTENT_LENGTH, zip_bytes.len())
        .header("X-Evidence-SHA256", pkg.sha256)
        .body(Body::from(zip_bytes))
        .map_err(|e| ApiError::Internal(format!("response build failed: {e}")))?;

    Ok(response)
}

/// Parses a framework string from the request body into `ComplianceFramework`.
fn parse_framework(s: &str) -> Result<ComplianceFramework, ApiError> {
    match s {
        "cert_in" => Ok(ComplianceFramework::CertIn),
        "dpdp" => Ok(ComplianceFramework::Dpdp),
        "rbi" => Ok(ComplianceFramework::Rbi),
        "sebi_cscrf" => Ok(ComplianceFramework::SebiCscrf),
        other => Err(ApiError::BadRequest(format!(
            "unknown framework '{other}'. Valid values: cert_in, dpdp, rbi, sebi_cscrf"
        ))),
    }
}
