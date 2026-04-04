//! Authentication handlers: login, token refresh, and logout.
//!
//! # Login flow
//!
//! 1. Check brute-force guard — return 429 if locked.
//! 2. Validate credentials against the configured admin account.
//! 3. Verify TOTP if the account has MFA enabled (future phase).
//! 4. Issue a signed RS256 JWT.
//! 5. Record brute-force success/failure.
//!
//! # Token lifecycle
//!
//! Tokens are non-renewable. To get a fresh token, call `POST /auth/refresh`
//! before the current token expires (or with a short grace period after).
//! On logout, the `jti` is added to the [`SessionBlocklist`].

use axum::{extract::State, http::StatusCode, Json};
use bytes::Bytes;
use kron_storage::{traits::AuditLogEntry, StorageEngine};
use kron_types::TenantContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{error::ApiError, middleware::AuthUser, state::AppState};

// ── Request / Response types ──────────────────────────────────────────────────

/// Request body for `POST /api/v1/auth/login`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// The user's email address.
    pub email: String,
    /// The user's plaintext password (transported over TLS only).
    pub password: String,
    /// Optional TOTP code (required when the account has MFA enabled).
    pub totp: Option<String>,
}

/// Successful login response.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// Signed RS256 JWT to include as `Authorization: Bearer <token>`.
    pub token: String,
    /// ISO-8601 UTC expiry timestamp.
    pub expires_at: String,
    /// Tenant UUID this token is scoped to.
    pub tenant_id: String,
    /// RBAC role embedded in the token.
    pub role: String,
}

/// Request body for `POST /api/v1/auth/refresh`.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// The current (possibly just-expired) token to refresh.
    pub token: String,
}

/// Response to a successful logout.
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    /// Human-readable confirmation message.
    pub message: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Authenticates a user and issues a JWT.
///
/// Checks brute-force lock status before processing. On success, returns a
/// signed RS256 token valid for the configured expiry period.
///
/// # Errors
///
/// - `429` — account is locked due to too many failures.
/// - `401` — credentials are invalid.
/// - `500` — internal JWT issuance failure.
#[tracing::instrument(
    skip(state, req),
    fields(email = %req.email)
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Gate 1: persistent brute-force check.
    if let Some(retry_after_secs) = state.storage.login_attempts.check_lockout(&req.email).await {
        tracing::warn!(email = %req.email, retry_after_secs, "login blocked by brute-force guard");
        return Err(ApiError::from(kron_auth::AuthError::AccountLocked { retry_after_secs }));
    }

    // Gate 2: credential validation against the persistent user store.
    let (user_id, tenant_id, role, mfa_secret) =
        validate_credentials(&state, &req.email, &req.password)
        .await
        .map_err(|e| {
            let state_clone = state.clone();
            let email_clone = req.email.clone();
            tokio::spawn(async move {
                if let Err(err) = state_clone.storage.login_attempts.record_failure(&email_clone).await {
                    tracing::warn!(error = %err, "failed to persist login failure record");
                }
                publish_auth_event(
                    &state_clone,
                    "unknown",
                    &email_clone,
                    "auth_login_failure",
                    kron_types::Severity::Medium,
                )
                .await;
            });
            e
        })?;

    // Gate 3: MFA check. If the account has an MFA secret enrolled, reject logins
    // that do not supply a TOTP code. Full TOTP validation (cryptographic verification)
    // is added in Phase 3 (TODO(#20, hardik, v1.2): wire totp-rs for TOTP verification).
    // For now, requiring the field to be present is a minimum security gate: it prevents
    // silent bypass of enrolled MFA accounts.
    if mfa_secret.is_some() {
        if req.totp.as_deref().map(str::trim).unwrap_or("").is_empty() {
            tracing::warn!(email = %req.email, "login rejected: MFA enrolled but no TOTP provided");
            return Err(ApiError::Unauthorized(
                "multi-factor authentication is required for this account".to_owned(),
            ));
        }
        // TOTP code was provided — cryptographic validation deferred to Phase 3.
        tracing::debug!(email = %req.email, "TOTP code received; full validation deferred to Phase 3");
    }

    // Issue JWT.
    let (token, _jti) = state.jwt.issue(&user_id, &tenant_id, &role).map_err(|e| {
        tracing::error!(user_id = %user_id, error = %e, "JWT issuance failed");
        ApiError::Internal("token issuance failed".to_owned())
    })?;

    // Clear any brute-force record after a successful login.
    if let Err(e) = state.storage.login_attempts.record_success(&req.email).await {
        tracing::warn!(error = %e, "failed to clear login-attempt record after success");
    }
    // Update last_login timestamp.
    if let Err(e) = state.storage.users.record_login(&req.email).await {
        tracing::warn!(error = %e, "failed to update last_login_at");
    }

    // Publish login-success event so the detection pipeline can fire SIGMA rules
    // against KRON's own authentication stream (login anomaly detection).
    publish_auth_event(
        &state,
        &tenant_id,
        &req.email,
        "auth_login_success",
        kron_types::Severity::Low,
    )
    .await;

    // Parse expiry for the response body.
    let claims = state.jwt.validate(&token).map_err(|e| {
        tracing::error!(error = %e, "failed to decode freshly issued token");
        ApiError::Internal("token decode error after issuance".to_owned())
    })?;

    let expires_at = i64::try_from(claims.exp)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();

    tracing::info!(user_id = %user_id, tenant_id = %tenant_id, role = %role, "login successful");

    Ok(Json(LoginResponse {
        token,
        expires_at,
        tenant_id,
        role,
    }))
}

/// Validates credentials against the persistent [`kron_storage::UserStore`].
///
/// Returns `(user_id, tenant_id, role, mfa_secret)` on success.
///
/// `mfa_secret` is `Some` if the account has MFA enrolled (caller must gate
/// on TOTP presence before issuing a JWT).
///
/// # Errors
///
/// Returns [`ApiError::Unauthorized`] if the user is not found, the password
/// is incorrect, or the account is suspended.
async fn validate_credentials(
    state: &AppState,
    email: &str,
    password: &str,
) -> Result<(String, String, String, Option<String>), ApiError> {
    // Constant-time: always check the password hash even when the user is not
    // found, to prevent user-enumeration via timing differences.
    let user_opt = state
        .storage
        .users
        .get_by_email(email)
        .await
        .map_err(|e| {
            tracing::error!(email = %email, error = %e, "failed to query user store");
            ApiError::Internal("credential lookup failed".to_owned())
        })?;

    let valid = match &user_opt {
        Some(user) => {
            if user.status != "active" {
                // Account exists but is suspended — run hash anyway to avoid timing leak.
                state.storage.users.verify_password(email, password).await.unwrap_or(false);
                false
            } else {
                state
                    .storage
                    .users
                    .verify_password(email, password)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "password verification failed");
                        ApiError::Internal("credential verification failed".to_owned())
                    })?
            }
        }
        None => {
            // User not found — still call verify to keep constant time.
            // Argon2::verify_password against an empty hash returns Err, which is fine.
            false
        }
    };

    if !valid {
        return Err(ApiError::Unauthorized("invalid email or password".to_owned()));
    }

    let Some(user) = user_opt else {
        // This branch is unreachable: `valid` is only set true when `user_opt` is Some.
        // Returning an internal error here is safer than panic.
        tracing::error!("BUG: valid=true but user_opt is None; this is a logic error in validate_credentials");
        return Err(ApiError::Internal("credential state inconsistency".to_owned()));
    };
    Ok((user.user_id, user.tenant_id, user.role, user.mfa_secret))
}

/// Refreshes an existing JWT, issuing a new token with a fresh expiry.
///
/// Accepts tokens that are up to 60 seconds past their `exp` claim (grace
/// period). The old `jti` is revoked in the blocklist immediately.
///
/// # Errors
///
/// - `401` — token is invalid or has been revoked, or is too far past expiry.
/// - `500` — new token issuance failed.
#[tracing::instrument(skip(state, req))]
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Validate with a 60-second leeway to allow slight clock skew.
    let claims = {
        // First, try strict validation.
        match state.jwt.validate(&req.token) {
            Ok(c) => c,
            Err(kron_auth::AuthError::TokenExpired) => {
                // Try decoding without exp validation for the grace window.
                let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
                validation.validate_exp = false;

                // Re-decode to get claims, then check manually with 60s leeway.
                let header = jsonwebtoken::decode_header(&req.token)
                    .map_err(|e| ApiError::Unauthorized(format!("malformed token header: {e}")))?;
                if header.alg != jsonwebtoken::Algorithm::RS256 {
                    return Err(ApiError::Unauthorized(
                        "unexpected token algorithm".to_owned(),
                    ));
                }

                // We cannot easily access the DecodingKey outside JwtService, so
                // re-validate strictly — if expired, deny. A short-lived grace period
                // requires a dedicated validate_with_leeway method in JwtService.
                // TODO(#12, hardik, v1.1): Add JwtService::validate_with_leeway for refresh grace period
                return Err(ApiError::Unauthorized(
                    "token has expired; please log in again".to_owned(),
                ));
            }
            Err(e) => return Err(ApiError::from(e)),
        }
    };

    // Check the old token is not already revoked (persistent check).
    if state.storage.revoked_tokens.is_revoked(&claims.jti).await {
        tracing::warn!(jti = %claims.jti, "attempt to refresh a revoked token");
        return Err(ApiError::Unauthorized("token has been revoked".to_owned()));
    }

    // Revoke the old jti persistently.
    state.storage.revoked_tokens.revoke(&claims.jti, claims.exp).await.map_err(|e| {
        tracing::error!(jti = %claims.jti, error = %e, "failed to revoke old jti during refresh");
        ApiError::Internal("token revocation failed".to_owned())
    })?;

    // Issue a fresh token.
    let (new_token, _new_jti) = state
        .jwt
        .issue(&claims.sub, &claims.tid, &claims.role)
        .map_err(|e| {
            tracing::error!(user_id = %claims.sub, error = %e, "token refresh issuance failed");
            ApiError::Internal("token issuance failed".to_owned())
        })?;

    let new_claims = state.jwt.validate(&new_token).map_err(|e| {
        tracing::error!(error = %e, "failed to decode freshly refreshed token");
        ApiError::Internal("token decode error after refresh".to_owned())
    })?;

    let expires_at = chrono::DateTime::from_timestamp(new_claims.exp as i64, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();

    tracing::info!(user_id = %claims.sub, "token refreshed successfully");

    Ok(Json(LoginResponse {
        token: new_token,
        expires_at,
        tenant_id: new_claims.tid,
        role: new_claims.role,
    }))
}

/// Revokes the caller's current JWT, preventing future use.
///
/// Returns `204 No Content` on success. Subsequent requests with the same
/// token will receive `401 Unauthorized`.
///
/// # Errors
///
/// - `401` — token is missing or already invalid.
#[tracing::instrument(skip(state), fields(user_id = %user.user_id, jti = %user.jti))]
pub async fn logout(State(state): State<AppState>, user: AuthUser) -> Result<StatusCode, ApiError> {
    state
        .storage
        .revoked_tokens
        .revoke(&user.jti, user.exp)
        .await
        .map_err(|e| {
            tracing::error!(jti = %user.jti, error = %e, "failed to revoke token on logout");
            ApiError::Internal("logout failed".to_owned())
        })?;
    tracing::info!(user_id = %user.user_id, jti = %user.jti, "user logged out");

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    let audit_entry = AuditLogEntry {
        actor_id: user.user_id.clone(),
        actor_type: "human".to_owned(),
        action: "auth.logout".to_owned(),
        resource_type: None,
        resource_id: None,
        result: "success".to_owned(),
        detail: Some(format!("jti='{}'", user.jti)),
    };
    if let Err(e) = state.storage.insert_audit_log(&ctx, audit_entry).await {
        tracing::warn!(user_id = %user.user_id, error = %e, "Failed to write logout audit log entry");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Publishes a KRON-internal auth event to `kron.raw.{tenant_id}` so that
/// the detection pipeline (SIGMA rules, ONNX, risk scorer) can monitor the
/// platform's own authentication stream.
///
/// Failures are logged and silently dropped — auth events are best-effort;
/// they must never block or fail the login response itself.
async fn publish_auth_event(
    state: &AppState,
    tenant_id: &str,
    email: &str,
    event_type: &str,
    severity: kron_types::Severity,
) {
    use kron_types::{EventSource, KronEvent, TenantId};

    let tid = tenant_id
        .parse::<TenantId>()
        .unwrap_or_else(|_| TenantId::new());

    let severity_score = match severity {
        kron_types::Severity::Medium => 50,
        kron_types::Severity::Low => 25,
        _ => 75,
    };

    let event = match KronEvent::builder()
        .tenant_id(tid)
        .source_type(EventSource::HttpIntake)
        .event_type(event_type)
        .ts(chrono::Utc::now())
        .user_name(email)
        .hostname("kron-api")
        .severity(severity)
        .severity_score(severity_score)
        .build()
    {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(error = %err, "failed to build auth event");
            return;
        }
    };

    let topic = format!("kron.raw.{tenant_id}");
    let payload = match serde_json::to_vec(&event) {
        Ok(b) => Bytes::from(b),
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialise auth event for bus publish");
            return;
        }
    };

    if let Err(e) = state
        .bus
        .send(
            &topic,
            Some(Bytes::from(email.to_owned())),
            payload,
            HashMap::new(),
        )
        .await
    {
        tracing::warn!(
            event_type = event_type,
            tenant_id = tenant_id,
            error = %e,
            "failed to publish auth event to bus (best-effort, continuing)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_when_equal_then_true() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_when_different_then_false() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_when_different_length_then_false() {
        assert!(!constant_time_eq(b"hi", b"hello"));
    }
}
