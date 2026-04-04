//! Axum request extractors for JWT authentication.
//!
//! [`AuthUser`] is an Axum [`FromRequestParts`] extractor that:
//! 1. Reads the `Authorization: Bearer <token>` header.
//! 2. Validates the token via [`JwtService::validate`].
//! 3. Checks the `jti` against the [`SessionBlocklist`].
//! 4. Returns a populated [`AuthUser`] on success, or [`ApiError::Unauthorized`].
//!
//! [`TenantId`] is a thin wrapper extractor that provides the tenant UUID
//! from the validated [`AuthUser`] in a single-field struct for ergonomic use.

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap},
};
use kron_types::TenantId;

use crate::{
    error::ApiError,
    state::{AppState, KronClaims},
};

/// The authenticated caller extracted from the JWT on every protected request.
///
/// Provides `user_id`, `tenant_id`, `role`, and `jti` for use by handlers.
/// This is the **only** valid source of `tenant_id` in any handler — never
/// read `tenant_id` from query params, headers, or request bodies.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// User ID from the JWT `sub` claim.
    pub user_id: String,
    /// Tenant ID from the JWT `tid` claim.
    pub tenant_id: TenantId,
    /// RBAC role from the JWT `role` claim.
    pub role: kron_auth::rbac::Role,
    /// JWT ID from the `jti` claim — needed for logout revocation.
    pub jti: String,
    /// Raw expiry Unix timestamp (for blocklist eviction on logout).
    pub exp: u64,
}

impl AuthUser {
    /// Builds an [`AuthUser`] from validated JWT claims.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Unauthorized`] if the `tid` or `role` claims
    /// cannot be parsed into their typed equivalents.
    fn from_claims(claims: KronClaims) -> Result<Self, ApiError> {
        let tenant_id = claims.tid.parse::<TenantId>().map_err(|e| {
            ApiError::Unauthorized(format!("token contains invalid tenant_id: {e}"))
        })?;

        let role = parse_role(&claims.role)?;

        Ok(Self {
            user_id: claims.sub,
            tenant_id,
            role,
            jti: claims.jti,
            exp: claims.exp,
        })
    }
}

/// Parses a role string from a JWT claim into the typed [`Role`] enum.
///
/// # Errors
///
/// Returns [`ApiError::Unauthorized`] if the role string is unrecognised.
fn parse_role(role_str: &str) -> Result<kron_auth::rbac::Role, ApiError> {
    match role_str {
        "super_admin" => Ok(kron_auth::rbac::Role::SuperAdmin),
        "admin" => Ok(kron_auth::rbac::Role::Admin),
        "analyst" => Ok(kron_auth::rbac::Role::Analyst),
        "viewer" => Ok(kron_auth::rbac::Role::Viewer),
        "api_key" => Ok(kron_auth::rbac::Role::ApiKey),
        other => Err(ApiError::Unauthorized(format!(
            "token contains unknown role: '{other}'"
        ))),
    }
}

/// Extracts `Bearer <token>` from the `Authorization` header.
///
/// Returns `None` if the header is absent or not in Bearer format.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value.strip_prefix("Bearer ")
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(&parts.headers).ok_or_else(|| {
            ApiError::Unauthorized("Authorization header with Bearer token is required".to_owned())
        })?;

        let claims = state.jwt.validate(token).map_err(|e| {
            tracing::warn!(error = %e, "JWT validation failed");
            ApiError::from(e)
        })?;

        // Check the persistent revocation list (survives restarts).
        if state.storage.revoked_tokens.is_revoked(&claims.jti).await {
            tracing::warn!(jti = %claims.jti, "attempt to use revoked token");
            return Err(ApiError::Unauthorized("token has been revoked".to_owned()));
        }

        AuthUser::from_claims(claims)
    }
}

/// Convenience extractor that yields only the [`TenantId`] from the JWT.
///
/// Use when a handler only needs the tenant context and not the full [`AuthUser`].
#[derive(Debug, Clone, Copy)]
pub struct ExtractedTenantId(pub TenantId);

#[async_trait]
impl FromRequestParts<AppState> for ExtractedTenantId {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_user = AuthUser::from_request_parts(parts, state).await?;
        Ok(ExtractedTenantId(auth_user.tenant_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_role_when_valid_then_correct_variant() {
        assert_eq!(parse_role("admin").unwrap(), kron_auth::rbac::Role::Admin);
        assert_eq!(
            parse_role("analyst").unwrap(),
            kron_auth::rbac::Role::Analyst
        );
        assert_eq!(parse_role("viewer").unwrap(), kron_auth::rbac::Role::Viewer);
    }

    #[test]
    fn test_parse_role_when_unknown_then_error() {
        let result = parse_role("hacker");
        assert!(matches!(result, Err(ApiError::Unauthorized(_))));
    }

    #[test]
    fn test_extract_bearer_token_when_valid_then_returns_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer my.test.token".parse().unwrap(),
        );
        assert_eq!(extract_bearer_token(&headers), Some("my.test.token"));
    }

    #[test]
    fn test_extract_bearer_token_when_missing_then_none() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_when_not_bearer_then_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );
        assert_eq!(extract_bearer_token(&headers), None);
    }
}
