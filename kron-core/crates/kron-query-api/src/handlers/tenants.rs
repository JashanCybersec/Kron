//! Tenant management handlers (MSSP portal).
//!
//! All write operations require `Role::SuperAdmin`.
//! Tenant admins may read or update config for their own tenant only.
//!
//! # Endpoints
//!
//! - `POST   /api/v1/tenants`              — create tenant (super_admin)
//! - `GET    /api/v1/tenants`              — list all tenants (super_admin)
//! - `GET    /api/v1/tenants/{id}`         — get tenant (super_admin or own tenant)
//! - `PUT    /api/v1/tenants/{id}/config`  — update per-tenant config (super_admin or own admin)
//! - `DELETE /api/v1/tenants/{id}`         — offboard tenant + data purge (super_admin)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use kron_auth::rbac::{Action, Resource, Role};
use kron_storage::{traits::AuditLogEntry, StorageEngine, TenantRecord};
use kron_types::TenantContext;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::ApiError, middleware::AuthUser, state::AppState};

/// Writes an audit log entry after a state-changing tenant operation.
/// Failures are logged but never propagate — audit must not block the response.
async fn audit(
    state: &AppState,
    ctx: &TenantContext,
    actor_id: &str,
    action: &str,
    target_tenant_id: &str,
    detail: Option<String>,
) {
    let entry = AuditLogEntry {
        actor_id: actor_id.to_owned(),
        actor_type: "human".to_owned(),
        action: action.to_owned(),
        resource_type: Some("tenant".to_owned()),
        resource_id: Some(target_tenant_id.to_owned()),
        result: "success".to_owned(),
        detail,
    };
    if let Err(e) = state.storage.insert_audit_log(ctx, entry).await {
        tracing::warn!(action, target_tenant_id, error = %e, "Failed to write audit log entry");
    }
}

// ── Request / Response types ──────────────────────────────────────────────────

/// Request body for `POST /api/v1/tenants`.
#[derive(Debug, Deserialize)]
pub struct CreateTenantRequest {
    /// Human-readable organisation name.
    pub name: String,
    /// Optional WhatsApp number for P1/P2 alerts (E.164 format).
    pub whatsapp_number: Option<String>,
    /// Primary contact email for compliance reports.
    pub contact_email: String,
    /// Compliance frameworks enabled for this tenant.
    pub compliance_frameworks: Vec<String>,
    /// Preferred language for reports and alerts (default: `"en"`).
    pub language: Option<String>,
}

/// Tenant record returned by the API.
#[derive(Debug, Serialize)]
pub struct TenantResponse {
    /// Unique tenant UUID.
    pub tenant_id: String,
    /// Organisation name.
    pub name: String,
    /// Contact email.
    pub contact_email: String,
    /// WhatsApp number if configured.
    pub whatsapp_number: Option<String>,
    /// Active compliance frameworks.
    pub compliance_frameworks: Vec<String>,
    /// Alert/report language code.
    pub language: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Tenant status: `active` | `suspended` | `offboarded`.
    pub status: String,
}

impl From<TenantRecord> for TenantResponse {
    fn from(r: TenantRecord) -> Self {
        Self {
            tenant_id: r.tenant_id,
            name: r.name,
            contact_email: r.contact_email,
            whatsapp_number: r.whatsapp_number,
            compliance_frameworks: r.compliance_frameworks,
            language: r.language,
            created_at: r.created_at,
            status: r.status,
        }
    }
}

/// Request body for `PUT /api/v1/tenants/{id}/config`.
#[derive(Debug, Deserialize)]
pub struct UpdateTenantConfigRequest {
    /// Replace WhatsApp number (omit to leave unchanged).
    pub whatsapp_number: Option<String>,
    /// Replace contact email (omit to leave unchanged).
    pub contact_email: Option<String>,
    /// Replace compliance frameworks (omit to leave unchanged).
    pub compliance_frameworks: Option<Vec<String>>,
    /// Replace language code (omit to leave unchanged).
    pub language: Option<String>,
}

/// Response for `DELETE /api/v1/tenants/{id}`.
#[derive(Debug, Serialize)]
pub struct OffboardResponse {
    /// The tenant ID that was offboarded.
    pub tenant_id: String,
    /// Human-readable confirmation.
    pub message: String,
    /// ISO-8601 timestamp of the purge operation.
    pub purged_at: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Creates a new tenant (MSSP onboarding).
///
/// Only `super_admin` may create tenants. Generates a fresh UUID, persists
/// the tenant record, and returns the created entry.
///
/// # Errors
///
/// - `403` — caller is not `super_admin`.
/// - `400` — name is empty or email is invalid.
/// - `409` — generated UUID collided (astronomically rare; retry).
#[tracing::instrument(skip(state, user, req), fields(caller = %user.user_id))]
pub async fn create_tenant(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Write, Resource::Tenants) {
        tracing::warn!(caller = %user.user_id, role = ?user.role, "create_tenant: insufficient role");
        return Err(ApiError::Forbidden(
            "only super_admin may create tenants".to_owned(),
        ));
    }

    let name = req.name.trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::BadRequest("tenant name must not be empty".to_owned()));
    }
    if !req.contact_email.contains('@') {
        return Err(ApiError::BadRequest(
            "contact_email is not a valid email address".to_owned(),
        ));
    }

    let tenant_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let language = req.language.unwrap_or_else(|| "en".to_owned());

    let record = TenantRecord {
        tenant_id: tenant_id.clone(),
        name: name.clone(),
        contact_email: req.contact_email.clone(),
        whatsapp_number: req.whatsapp_number.clone(),
        compliance_frameworks: req.compliance_frameworks.clone(),
        language: language.clone(),
        created_at: now,
        status: "active".to_owned(),
    };

    state
        .storage
        .tenants
        .insert(record.clone())
        .await
        .map_err(|e| {
            tracing::error!(tenant_id = %tenant_id, error = %e, "failed to persist new tenant");
            ApiError::Conflict(format!("failed to create tenant: {e}"))
        })?;

    tracing::info!(tenant_id = %tenant_id, name = %name, caller = %user.user_id, "tenant created");

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    audit(
        &state,
        &ctx,
        &user.user_id,
        "tenant.create",
        &tenant_id,
        Some(format!("name='{name}'")),
    )
    .await;

    Ok((StatusCode::CREATED, Json(TenantResponse::from(record))))
}

/// Lists all tenants (MSSP portal overview).
///
/// Only `super_admin` may enumerate tenants. Returns all tenants sorted by
/// creation date ascending.
///
/// # Errors
///
/// - `403` — caller is not `super_admin`.
#[tracing::instrument(skip(state, user), fields(caller = %user.user_id))]
pub async fn list_tenants(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<TenantResponse>>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Tenants) {
        return Err(ApiError::Forbidden(
            "only super_admin may list tenants".to_owned(),
        ));
    }

    let records = state.storage.tenants.list().await;
    Ok(Json(records.into_iter().map(TenantResponse::from).collect()))
}

/// Returns a single tenant record.
///
/// `super_admin` may read any tenant. `admin` / other roles may only read
/// their own tenant (as identified by the JWT `tid` claim).
///
/// # Errors
///
/// - `403` — non-super_admin attempting cross-tenant read.
/// - `404` — tenant does not exist.
#[tracing::instrument(skip(state, user), fields(caller = %user.user_id, target = %tenant_id))]
pub async fn get_tenant(
    State(state): State<AppState>,
    user: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantResponse>, ApiError> {
    let is_super = user.role == Role::SuperAdmin;
    let is_own = user.tenant_id.to_string() == tenant_id;

    if !is_super && !is_own {
        return Err(ApiError::Forbidden(
            "you may only read your own tenant record".to_owned(),
        ));
    }

    state
        .storage
        .tenants
        .get(&tenant_id)
        .await
        .map(TenantResponse::from)
        .ok_or_else(|| ApiError::NotFound(format!("tenant '{tenant_id}' not found")))
        .map(Json)
}

/// Updates per-tenant configuration fields.
///
/// `super_admin` may update any tenant. `admin` may update their own tenant's
/// WhatsApp number, language, and compliance frameworks.
///
/// # Errors
///
/// - `403` — insufficient role for the target tenant.
/// - `404` — tenant does not exist.
#[tracing::instrument(skip(state, user, req), fields(caller = %user.user_id, target = %tenant_id))]
pub async fn update_tenant_config(
    State(state): State<AppState>,
    user: AuthUser,
    Path(tenant_id): Path<String>,
    Json(req): Json<UpdateTenantConfigRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    let is_super = user.role == Role::SuperAdmin;
    let is_own_admin = user.role == Role::Admin && user.tenant_id.to_string() == tenant_id;

    if !is_super && !is_own_admin {
        return Err(ApiError::Forbidden(
            "only super_admin or the tenant's own admin may update config".to_owned(),
        ));
    }

    let updated = state
        .storage
        .tenants
        .update_config(
            &tenant_id,
            req.whatsapp_number.as_deref(),
            req.contact_email.as_deref(),
            req.compliance_frameworks.as_deref(),
            req.language.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::error!(tenant_id = %tenant_id, error = %e, "update_tenant_config failed");
            ApiError::Internal(format!("storage error: {e}"))
        })?
        .ok_or_else(|| ApiError::NotFound(format!("tenant '{tenant_id}' not found")))?;

    tracing::info!(tenant_id = %tenant_id, caller = %user.user_id, "tenant config updated");

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    audit(
        &state,
        &ctx,
        &user.user_id,
        "tenant.update_config",
        &tenant_id,
        None,
    )
    .await;

    Ok(Json(TenantResponse::from(updated)))
}

/// Offboards a tenant: marks as offboarded and records the purge timestamp.
///
/// Data purge of event/alert partitions is asynchronous. The audit log is
/// retained for 7 years per CERT-In and RBI requirements.
/// Only `super_admin` may offboard tenants. A super_admin cannot offboard
/// their own tenant as a safety guard.
///
/// # Errors
///
/// - `403` — caller is not `super_admin`.
/// - `400` — caller is attempting to offboard their own tenant.
/// - `404` — tenant does not exist.
/// - `409` — tenant is already offboarded.
#[tracing::instrument(skip(state, user), fields(caller = %user.user_id, target = %tenant_id))]
pub async fn offboard_tenant(
    State(state): State<AppState>,
    user: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Json<OffboardResponse>, ApiError> {
    if user.role != Role::SuperAdmin {
        return Err(ApiError::Forbidden(
            "only super_admin may offboard tenants".to_owned(),
        ));
    }

    if user.tenant_id.to_string() == tenant_id {
        return Err(ApiError::BadRequest(
            "cannot offboard your own tenant — use a different super_admin account".to_owned(),
        ));
    }

    state
        .storage
        .tenants
        .offboard(&tenant_id)
        .await
        .map_err(|e| {
            tracing::error!(tenant_id = %tenant_id, error = %e, "offboard_tenant failed");
            // Differentiate "not found" vs "already offboarded" vs other storage error.
            if e.to_string().contains("not found") {
                ApiError::NotFound(format!("tenant '{tenant_id}' not found"))
            } else if e.to_string().contains("already offboarded") {
                ApiError::Conflict(format!("tenant '{tenant_id}' is already offboarded"))
            } else {
                ApiError::Internal(format!("offboard failed: {e}"))
            }
        })?;

    let purged_at = chrono::Utc::now().to_rfc3339();

    tracing::warn!(
        tenant_id = %tenant_id,
        caller = %user.user_id,
        purged_at = %purged_at,
        "tenant offboarded and data purge initiated"
    );

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    audit(
        &state,
        &ctx,
        &user.user_id,
        "tenant.offboard",
        &tenant_id,
        Some(format!("purged_at='{purged_at}'")),
    )
    .await;

    Ok(Json(OffboardResponse {
        tenant_id,
        message: "tenant offboarded; event and alert data purge initiated. \
                  Audit log retained per compliance requirements."
            .to_owned(),
        purged_at,
    }))
}
