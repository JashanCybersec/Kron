//! Detection rule management handlers.
//!
//! Rules are SIGMA-compatible detection definitions stored per-tenant.
//! All write operations require Admin or Analyst role.
//!
//! # Endpoints
//!
//! - `GET    /api/v1/rules`          — list all rules for the tenant
//! - `POST   /api/v1/rules`          — create a new rule
//! - `PUT    /api/v1/rules/{id}`     — update an existing rule
//! - `DELETE /api/v1/rules/{id}`     — soft-delete a rule
//! - `POST   /api/v1/rules/import`   — import from SIGMA YAML

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use kron_auth::rbac::{Action, Resource};
use kron_storage::{traits::AuditLogEntry, StorageEngine};
use kron_types::TenantContext;
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, middleware::AuthUser, state::AppState};

/// Writes an audit log entry after a state-changing rule operation.
/// Failures are logged but never propagate — audit must not block the response.
async fn audit(
    state: &AppState,
    ctx: &TenantContext,
    actor_id: &str,
    action: &str,
    rule_id: &str,
    detail: Option<String>,
) {
    let entry = AuditLogEntry {
        actor_id: actor_id.to_owned(),
        actor_type: "human".to_owned(),
        action: action.to_owned(),
        resource_type: Some("rule".to_owned()),
        resource_id: Some(rule_id.to_owned()),
        result: "success".to_owned(),
        detail,
    };
    if let Err(e) = state.storage.insert_audit_log(ctx, entry).await {
        tracing::warn!(action, rule_id, error = %e, "Failed to write audit log entry");
    }
}

// ── Request / Response types ──────────────────────────────────────────────────

/// Request body for creating or updating a detection rule.
#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    /// Human-readable rule name.
    pub name: String,
    /// Rule type: `"sigma"`, `"threshold"`, `"ml"`, etc.
    pub rule_type: String,
    /// Severity: `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"`.
    pub severity: String,
    /// MITRE ATT&CK tactic name (e.g. `"Lateral Movement"`).
    pub mitre_tactic: Option<String>,
    /// MITRE technique ID (e.g. `"T1021"`).
    pub mitre_technique: Option<String>,
    /// Rule-type–specific configuration payload.
    pub config: serde_json::Value,
}

/// Rule summary returned in list and create/update responses.
#[derive(Debug, Serialize)]
pub struct RuleResponse {
    /// UUID of the rule.
    pub rule_id: String,
    /// Human-readable rule name.
    pub name: String,
    /// Severity level.
    pub severity: String,
    /// Lifecycle status (`"active"`, `"disabled"`, `"deleted"`).
    pub status: String,
    /// Rule type identifier.
    pub rule_type: String,
}

/// Request body for SIGMA YAML bulk import.
#[derive(Debug, Deserialize)]
pub struct ImportSigmaRequest {
    /// Raw SIGMA YAML text (single document or multi-document `---` separated).
    pub yaml: String,
}

/// Response for a SIGMA import operation.
#[derive(Debug, Serialize)]
pub struct ImportSigmaResponse {
    /// Number of rules successfully imported.
    pub imported: usize,
    /// Names of rules that failed to parse.
    pub failed: Vec<String>,
}

// ── In-memory rule store (placeholder until kron-storage adds rule queries) ──
//
// The storage trait does not yet expose rule CRUD (it is a Phase 3 task).
// Until then we use a DashMap keyed by (tenant_id, rule_id) to keep rules
// in memory within the process lifetime.
//
// TODO(#13, hardik, v1.1): Replace in-memory rule store with kron-storage rule CRUD
use once_cell::sync::Lazy;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredRule {
    rule_id: String,
    tenant_id: String,
    name: String,
    rule_type: String,
    severity: String,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
    config: serde_json::Value,
    status: String,
}

static RULES_STORE: Lazy<dashmap::DashMap<String, HashMap<String, StoredRule>>> =
    Lazy::new(dashmap::DashMap::new);

fn tenant_rules_mut(
    tenant_id: &str,
) -> dashmap::mapref::one::RefMut<'_, String, HashMap<String, StoredRule>> {
    RULES_STORE
        .entry(tenant_id.to_owned())
        .or_insert_with(HashMap::new)
}

/// Valid severity values for detection rules.
const VALID_SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];
/// Maximum allowed rule name length.
const MAX_RULE_NAME_LEN: usize = 200;

/// Validates the fields of a [`CreateRuleRequest`] that are common to create and update.
///
/// # Errors
///
/// Returns [`ApiError::BadRequest`] if any field fails validation.
fn validate_rule_request(body: &CreateRuleRequest) -> Result<(), ApiError> {
    if body.name.is_empty() || body.name.len() > MAX_RULE_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "rule name must be between 1 and {MAX_RULE_NAME_LEN} characters"
        )));
    }
    let sev_lower = body.severity.to_lowercase();
    if !VALID_SEVERITIES.contains(&sev_lower.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "invalid severity '{}'; must be one of: {}",
            body.severity,
            VALID_SEVERITIES.join(", ")
        )));
    }
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Returns all active rules for the authenticated tenant.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Rules.
#[tracing::instrument(skip_all, fields(user_id = %user.user_id, tenant_id = %user.tenant_id))]
pub async fn list_rules(
    State(_state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Vec<RuleResponse>>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Rules) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to read rules".to_owned(),
        ));
    }

    let tenant_id = user.tenant_id.to_string();
    let rules: Vec<RuleResponse> = RULES_STORE
        .get(&tenant_id)
        .map(|m| {
            m.values()
                .filter(|r| r.status != "deleted")
                .map(|r| RuleResponse {
                    rule_id: r.rule_id.clone(),
                    name: r.name.clone(),
                    severity: r.severity.clone(),
                    status: r.status.clone(),
                    rule_type: r.rule_type.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(rules))
}

/// Creates a new detection rule for the tenant.
///
/// # Errors
///
/// - `400` — request body is malformed.
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Write permission on Rules.
#[tracing::instrument(
    skip(state, body),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id)
)]
pub async fn create_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<RuleResponse>), ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Write, Resource::Rules) {
        tracing::warn!(user_id = %user.user_id, role = %user.role, "insufficient permissions to create rule");
        return Err(ApiError::Forbidden(
            "insufficient permissions to create rules".to_owned(),
        ));
    }

    validate_rule_request(&body)?;

    let rule_id = uuid::Uuid::new_v4().to_string();
    let tenant_id = user.tenant_id.to_string();

    let stored = StoredRule {
        rule_id: rule_id.clone(),
        tenant_id: tenant_id.clone(),
        name: body.name.clone(),
        rule_type: body.rule_type.clone(),
        severity: body.severity.clone(),
        mitre_tactic: body.mitre_tactic,
        mitre_technique: body.mitre_technique,
        config: body.config,
        status: "active".to_owned(),
    };

    tenant_rules_mut(&tenant_id).insert(rule_id.clone(), stored);

    tracing::info!(
        user_id = %user.user_id,
        tenant_id = %tenant_id,
        rule_id = %rule_id,
        "rule created"
    );

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    audit(
        &state,
        &ctx,
        &user.user_id,
        "rule.create",
        &rule_id,
        Some(format!("name='{}' severity='{}'", body.name, body.severity)),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(RuleResponse {
            rule_id,
            name: body.name,
            severity: body.severity,
            status: "active".to_owned(),
            rule_type: body.rule_type,
        }),
    ))
}

/// Updates an existing rule.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Write permission on Rules.
/// - `404` — rule not found or belongs to another tenant.
#[tracing::instrument(
    skip(state, body),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id, rule_id = %rule_id)
)]
pub async fn update_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(rule_id): Path<String>,
    Json(body): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Write, Resource::Rules) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to update rules".to_owned(),
        ));
    }

    validate_rule_request(&body)?;

    let tenant_id = user.tenant_id.to_string();
    let mut rules = tenant_rules_mut(&tenant_id);

    let rule = rules
        .get_mut(&rule_id)
        .ok_or_else(|| ApiError::NotFound(format!("rule '{rule_id}' not found")))?;

    rule.name = body.name.clone();
    rule.rule_type = body.rule_type.clone();
    rule.severity = body.severity.clone();
    rule.mitre_tactic = body.mitre_tactic;
    rule.mitre_technique = body.mitre_technique;
    rule.config = body.config;

    tracing::info!(user_id = %user.user_id, rule_id = %rule_id, "rule updated");

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    audit(
        &state,
        &ctx,
        &user.user_id,
        "rule.update",
        &rule_id,
        Some(format!("name='{}' severity='{}'", body.name, body.severity)),
    )
    .await;

    Ok(Json(RuleResponse {
        rule_id,
        name: body.name,
        severity: body.severity,
        status: rule.status.clone(),
        rule_type: body.rule_type,
    }))
}

/// Soft-deletes a rule (sets status to `"deleted"`).
///
/// Deleted rules are excluded from detection processing on the next stream
/// processor reload. They are retained for audit purposes.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Delete permission on Rules.
/// - `404` — rule not found or belongs to another tenant.
#[tracing::instrument(
    skip(state),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id, rule_id = %rule_id)
)]
pub async fn delete_rule(
    State(state): State<AppState>,
    user: AuthUser,
    Path(rule_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Delete, Resource::Rules) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to delete rules".to_owned(),
        ));
    }

    let tenant_id = user.tenant_id.to_string();
    let mut rules = tenant_rules_mut(&tenant_id);

    let rule = rules
        .get_mut(&rule_id)
        .ok_or_else(|| ApiError::NotFound(format!("rule '{rule_id}' not found")))?;

    rule.status = "deleted".to_owned();

    tracing::info!(user_id = %user.user_id, rule_id = %rule_id, "rule soft-deleted");

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    audit(&state, &ctx, &user.user_id, "rule.delete", &rule_id, None).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Imports SIGMA rules from a YAML payload.
///
/// Parses each SIGMA document and stores valid rules. Invalid documents are
/// collected and reported in the response rather than aborting the import.
///
/// # Errors
///
/// - `400` — YAML body is completely unparseable (not SIGMA format).
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Write permission on Rules.
#[tracing::instrument(
    skip(state, body),
    fields(user_id = %user.user_id, tenant_id = %user.tenant_id)
)]
pub async fn import_sigma(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<ImportSigmaRequest>,
) -> Result<Json<ImportSigmaResponse>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Write, Resource::Rules) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to import rules".to_owned(),
        ));
    }

    if body.yaml.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "yaml body must not be empty".to_owned(),
        ));
    }

    let tenant_id = user.tenant_id.to_string();
    let mut imported = 0usize;
    let mut failed: Vec<String> = Vec::new();

    // Split on YAML document separators.
    for (idx, document) in body.yaml.split("\n---\n").enumerate() {
        let trimmed = document.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(trimmed);
        match parsed {
            Ok(yaml_val) => {
                // Extract required fields from the SIGMA structure.
                let title = yaml_val
                    .get("title")
                    .and_then(serde_yaml::Value::as_str)
                    .unwrap_or("Unnamed Rule")
                    .to_owned();

                let severity = yaml_val
                    .get("level")
                    .and_then(serde_yaml::Value::as_str)
                    .unwrap_or("medium")
                    .to_owned();

                let rule_id = uuid::Uuid::new_v4().to_string();
                let config = match serde_json::to_value(&yaml_val) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            document = idx,
                            error = %e,
                            "sigma import: failed to convert YAML document to JSON"
                        );
                        failed.push(format!("document {idx}: JSON conversion failed: {e}"));
                        continue;
                    }
                };

                let stored = StoredRule {
                    rule_id: rule_id.clone(),
                    tenant_id: tenant_id.clone(),
                    name: title,
                    rule_type: "sigma".to_owned(),
                    severity,
                    mitre_tactic: None,
                    mitre_technique: None,
                    config,
                    status: "active".to_owned(),
                };

                tenant_rules_mut(&tenant_id).insert(rule_id, stored);
                imported += 1;
            }
            Err(e) => {
                failed.push(format!("document {idx}: {e}"));
            }
        }
    }

    tracing::info!(
        user_id = %user.user_id,
        tenant_id = %tenant_id,
        imported = imported,
        failed = failed.len(),
        "sigma import complete"
    );

    if imported > 0 {
        let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
        audit(
            &state,
            &ctx,
            &user.user_id,
            "rule.import_sigma",
            "batch",
            Some(format!("imported={imported} failed={}", failed.len())),
        )
        .await;
    }

    Ok(Json(ImportSigmaResponse { imported, failed }))
}
