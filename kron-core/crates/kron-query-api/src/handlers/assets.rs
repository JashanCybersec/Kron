//! Asset management handlers.
//!
//! Assets are monitored endpoints (servers, workstations, containers) tracked
//! by the KRON agent or discovered via agentless scanning.
//!
//! # Endpoints
//!
//! - `GET /api/v1/assets`         — paginated asset list with filters
//! - `GET /api/v1/assets/{id}`    — single asset by ID

use axum::{
    extract::{Path, Query, State},
    Json,
};
use kron_auth::rbac::{Action, Resource};
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, middleware::AuthUser, state::AppState};

/// Query parameters for `GET /api/v1/assets`.
#[derive(Debug, Deserialize)]
pub struct AssetQuery {
    /// Filter by operating system family (e.g. `"linux"`, `"windows"`).
    pub os_type: Option<String>,
    /// Filter by asset criticality level (e.g. `"critical"`, `"high"`).
    pub criticality: Option<String>,
    /// When `true`, return only assets with the KRON agent currently active.
    pub agent_active: Option<bool>,
    /// Maximum rows to return (1–1 000, default 100).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// Summary entry for an asset in list responses.
#[derive(Debug, Serialize)]
pub struct AssetSummary {
    /// Asset UUID.
    pub asset_id: String,
    /// Hostname or FQDN.
    pub hostname: String,
    /// Primary IP address.
    pub ip_address: String,
    /// OS family.
    pub os_type: String,
    /// Criticality level.
    pub criticality: String,
    /// Whether the KRON agent is installed and reporting.
    pub agent_active: bool,
}

/// Response for asset list queries.
#[derive(Debug, Serialize)]
pub struct AssetListResponse {
    /// Total matching assets (before limit/offset).
    pub total: u64,
    /// Assets in this page.
    pub assets: Vec<AssetSummary>,
}

/// Returns a paginated list of monitored assets for the authenticated tenant.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Assets.
/// - `500` — storage query failure.
#[tracing::instrument(
    skip(state),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id)
)]
pub async fn list_assets(
    State(state): State<AppState>,
    user: AuthUser,
    Query(_params): Query<AssetQuery>,
) -> Result<Json<AssetListResponse>, ApiError> {
    let _ = &state;

    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Assets) {
        tracing::warn!(
            user_id = %user.user_id,
            role = %user.role,
            "insufficient permissions to read assets"
        );
        return Err(ApiError::Forbidden(
            "insufficient permissions to read assets".to_owned(),
        ));
    }

    // TODO(#14, hardik, v1.1): Implement asset query in kron-storage when asset table migration lands
    tracing::debug!(
        tenant_id = %user.tenant_id,
        "asset query pending storage implementation"
    );

    Ok(Json(AssetListResponse {
        total: 0,
        assets: vec![],
    }))
}

/// Returns a single asset by ID for the authenticated tenant.
///
/// # Errors
///
/// - `400` — `asset_id` is not a valid UUID.
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Assets.
/// - `404` — asset not found or belongs to another tenant.
#[tracing::instrument(
    skip(state),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id, asset_id = %asset_id)
)]
pub async fn get_asset(
    State(state): State<AppState>,
    user: AuthUser,
    Path(asset_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = &state;

    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Assets) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to read assets".to_owned(),
        ));
    }

    let _ = uuid::Uuid::parse_str(&asset_id)
        .map_err(|_| ApiError::BadRequest(format!("invalid asset_id: '{asset_id}'")))?;

    // TODO(#14, hardik, v1.1): Implement single-asset fetch in kron-storage
    Err(ApiError::NotFound(format!("asset '{asset_id}' not found")))
}
