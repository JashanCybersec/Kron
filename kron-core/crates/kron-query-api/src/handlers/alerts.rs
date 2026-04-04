//! Alert management handlers.
//!
//! All handlers require a valid JWT and enforce tenant isolation.
//!
//! # Endpoints
//!
//! - `GET   /api/v1/alerts`                       — paginated alert list
//! - `GET   /api/v1/alerts/{id}`                  — single alert by ID
//! - `PATCH /api/v1/alerts/{id}`                  — update status/assignment
//! - `POST  /api/v1/alerts/{id}/acknowledge`      — one-click acknowledge

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use kron_auth::rbac::{Action, Resource};
use kron_types::{AlertStatus, TenantContext};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use kron_storage::{traits::AuditLogEntry, StorageEngine};

use crate::{error::ApiError, middleware::AuthUser, state::AppState};

/// Writes an audit log entry after a state-changing alert operation.
/// Failures are logged but never propagate — audit must not block the response.
async fn audit(
    state: &AppState,
    ctx: &kron_types::TenantContext,
    actor_id: &str,
    action: &str,
    alert_id: &str,
    detail: Option<String>,
) {
    let entry = AuditLogEntry {
        actor_id: actor_id.to_owned(),
        actor_type: "human".to_owned(),
        action: action.to_owned(),
        resource_type: Some("alert".to_owned()),
        resource_id: Some(alert_id.to_owned()),
        result: "success".to_owned(),
        detail,
    };
    if let Err(e) = state.storage.insert_audit_log(ctx, entry).await {
        tracing::warn!(action, alert_id, error = %e, "Failed to write audit log entry");
    }
}

// ── Query / Request / Response types ─────────────────────────────────────────

/// Query parameters for `GET /api/v1/alerts`.
#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    /// Filter by alert status (e.g. `open`, `acknowledged`, `resolved`).
    pub status: Option<String>,
    /// Filter by minimum severity name.
    pub severity: Option<String>,
    /// Filter alerts created after this ISO-8601 timestamp.
    pub from: Option<String>,
    /// Maximum rows to return (1–1 000, default 50).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// Request body for `PATCH /api/v1/alerts/{id}`.
#[derive(Debug, Deserialize)]
pub struct AlertUpdateRequest {
    /// New status value (e.g. `"acknowledged"`, `"resolved"`, `"false_positive"`).
    pub status: Option<String>,
    /// Analyst resolution notes.
    pub resolution_notes: Option<String>,
    /// User ID to assign this alert to.
    pub assigned_to: Option<String>,
}

/// Response for alert list queries.
#[derive(Debug, Serialize)]
pub struct AlertListResponse {
    /// Total matching alerts in this page.
    pub total: u64,
    /// Alert objects.
    pub alerts: Vec<serde_json::Value>,
    /// Query execution time in milliseconds.
    pub query_ms: u64,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Returns a paginated list of alerts for the authenticated tenant.
///
/// # Errors
///
/// - `400` — invalid query parameters.
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Alerts.
/// - `500` — storage query failure.
#[tracing::instrument(
    skip(state),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id)
)]
pub async fn list_alerts(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<AlertQuery>,
) -> Result<Json<AlertListResponse>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Alerts) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to read alerts".to_owned(),
        ));
    }

    let limit = params.limit.unwrap_or(50).min(1_000);
    let offset = params.offset.unwrap_or(0);

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    let t0 = Instant::now();

    let alerts = state
        .storage
        .query_alerts(&ctx, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %user.tenant_id,
                error = %e,
                "storage query_alerts failed"
            );
            ApiError::Internal("alert query failed".to_owned())
        })?;

    let query_ms = t0.elapsed().as_millis() as u64;

    // Apply in-memory filtering on status and severity (storage layer does not
    // yet support these predicates — they will be pushed down in Phase 3).
    let alerts: Vec<kron_types::KronAlert> = alerts
        .into_iter()
        .filter(|a| {
            if let Some(ref s) = params.status {
                let status_str = format!("{:?}", a.status).to_lowercase();
                if &status_str != s {
                    return false;
                }
            }
            if let Some(ref sev) = params.severity {
                let sev_str = format!("{:?}", a.severity).to_lowercase();
                if &sev_str != sev {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = alerts.len() as u64;
    let alerts_json: Vec<serde_json::Value> = alerts
        .into_iter()
        .filter_map(|a| serde_json::to_value(a).ok())
        .collect();

    Ok(Json(AlertListResponse {
        total,
        alerts: alerts_json,
        query_ms,
    }))
}

/// Returns a single alert by ID for the authenticated tenant.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Alerts.
/// - `404` — alert not found or belongs to another tenant.
/// - `500` — storage query failure.
#[tracing::instrument(
    skip(state),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id, alert_id = %alert_id)
)]
pub async fn get_alert(
    State(state): State<AppState>,
    user: AuthUser,
    Path(alert_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Alerts) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to read alerts".to_owned(),
        ));
    }

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());

    let alert = state
        .storage
        .get_alert(&ctx, &alert_id)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %user.tenant_id,
                alert_id = %alert_id,
                error = %e,
                "storage get_alert failed"
            );
            ApiError::Internal("alert lookup failed".to_owned())
        })?;

    let alert = alert.ok_or_else(|| ApiError::NotFound(format!("alert '{alert_id}' not found")))?;

    serde_json::to_value(alert).map(Json).map_err(|e| {
        tracing::error!(alert_id = %alert_id, error = %e, "alert serialization failed");
        ApiError::Internal("alert serialization failed".to_owned())
    })
}

/// Updates alert metadata (status, assignment, resolution notes).
///
/// # Errors
///
/// - `400` — request body is malformed.
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Write permission on Alerts.
/// - `404` — alert not found or belongs to another tenant.
/// - `500` — storage update failure.
#[tracing::instrument(
    skip(state, body),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id, alert_id = %alert_id)
)]
pub async fn update_alert(
    State(state): State<AppState>,
    user: AuthUser,
    Path(alert_id): Path<String>,
    Json(body): Json<AlertUpdateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Write, Resource::Alerts) {
        tracing::warn!(
            user_id = %user.user_id,
            role = %user.role,
            "insufficient permissions to update alert"
        );
        return Err(ApiError::Forbidden(
            "insufficient permissions to update alerts".to_owned(),
        ));
    }

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());

    let mut alert = state
        .storage
        .get_alert(&ctx, &alert_id)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %user.tenant_id,
                alert_id = %alert_id,
                error = %e,
                "storage get_alert (pre-update) failed"
            );
            ApiError::Internal("alert lookup failed".to_owned())
        })?
        .ok_or_else(|| ApiError::NotFound(format!("alert '{alert_id}' not found")))?;

    // Apply partial updates.
    if let Some(ref status_str) = body.status {
        alert.status = parse_alert_status(status_str)?;
        if alert.status == AlertStatus::Resolved {
            alert.resolved_at = Some(Utc::now());
            alert.resolved_by = Some(user.user_id.clone());
        }
    }
    if let Some(notes) = body.resolution_notes {
        alert.resolution_notes = Some(notes);
    }
    if let Some(assigned) = body.assigned_to {
        alert.assigned_to = Some(assigned);
    }

    state
        .storage
        .update_alert(&ctx, &alert)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %user.tenant_id,
                alert_id = %alert_id,
                error = %e,
                "storage update_alert failed"
            );
            ApiError::Internal("alert update failed".to_owned())
        })?;

    tracing::info!(
        user_id = %user.user_id,
        alert_id = %alert_id,
        "alert updated successfully"
    );

    audit(
        &state,
        &ctx,
        &user.user_id,
        "alert.update",
        &alert_id,
        body.status
            .as_deref()
            .map(|s| format!("status set to '{s}'")),
    )
    .await;

    serde_json::to_value(alert).map(Json).map_err(|e| {
        tracing::error!(alert_id = %alert_id, error = %e, "updated alert serialization failed");
        ApiError::Internal("alert serialization failed".to_owned())
    })
}

/// Acknowledges an alert, transitioning it from `Open` to `Acknowledged`.
///
/// Idempotent: acknowledging an already-acknowledged alert is a no-op.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Write permission on Alerts.
/// - `404` — alert not found or belongs to another tenant.
/// - `500` — storage update failure.
#[tracing::instrument(
    skip(state),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id, alert_id = %alert_id)
)]
pub async fn acknowledge_alert(
    State(state): State<AppState>,
    user: AuthUser,
    Path(alert_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Write, Resource::Alerts) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to acknowledge alerts".to_owned(),
        ));
    }

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());

    let mut alert = state
        .storage
        .get_alert(&ctx, &alert_id)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %user.tenant_id,
                alert_id = %alert_id,
                error = %e,
                "storage get_alert (pre-acknowledge) failed"
            );
            ApiError::Internal("alert lookup failed".to_owned())
        })?
        .ok_or_else(|| ApiError::NotFound(format!("alert '{alert_id}' not found")))?;

    if alert.status == AlertStatus::Open {
        alert.status = AlertStatus::Acknowledged;
        alert.assigned_to = Some(user.user_id.clone());

        state
            .storage
            .update_alert(&ctx, &alert)
            .await
            .map_err(|e| {
                tracing::error!(
                    tenant_id = %user.tenant_id,
                    alert_id = %alert_id,
                    error = %e,
                    "storage update_alert (acknowledge) failed"
                );
                ApiError::Internal("alert acknowledge failed".to_owned())
            })?;

        tracing::info!(user_id = %user.user_id, alert_id = %alert_id, "alert acknowledged");

        audit(
            &state,
            &ctx,
            &user.user_id,
            "alert.acknowledge",
            &alert_id,
            None,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Parses an alert status string into the typed [`AlertStatus`] enum.
///
/// # Errors
///
/// Returns [`ApiError::BadRequest`] if the string is not a recognised status.
fn parse_alert_status(s: &str) -> Result<AlertStatus, ApiError> {
    match s.to_lowercase().as_str() {
        "open" => Ok(AlertStatus::Open),
        "acknowledged" => Ok(AlertStatus::Acknowledged),
        "in_progress" | "in-progress" | "in_investigation" => Ok(AlertStatus::InProgress),
        "resolved" => Ok(AlertStatus::Resolved),
        "false_positive" | "false-positive" => Ok(AlertStatus::FalsePositive),
        "suppressed" => Ok(AlertStatus::Suppressed),
        other => Err(ApiError::BadRequest(format!(
            "unknown alert status: '{other}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alert_status_when_valid_then_correct_variant() {
        assert_eq!(parse_alert_status("open").unwrap(), AlertStatus::Open);
        assert_eq!(
            parse_alert_status("acknowledged").unwrap(),
            AlertStatus::Acknowledged
        );
        assert_eq!(
            parse_alert_status("resolved").unwrap(),
            AlertStatus::Resolved
        );
        assert_eq!(
            parse_alert_status("false_positive").unwrap(),
            AlertStatus::FalsePositive
        );
    }

    #[test]
    fn test_parse_alert_status_when_invalid_then_bad_request() {
        let result = parse_alert_status("not-a-status");
        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }
}
