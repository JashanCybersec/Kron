//! JWT issuance, validation, and Axum extraction for the KRON SIEM platform.
//!
//! Uses RS256 (RSA + SHA-256) so that the private key is held only by the
//! auth service while all other services verify with the public key.
//!
//! # Usage
//!
//! ```no_run
//! use kron_auth::jwt::JwtService;
//! use kron_auth::rbac::Role;
//!
//! let svc = JwtService::new(
//!     include_bytes!("/var/lib/kron/keys/jwt.key"),
//!     include_bytes!("/var/lib/kron/keys/jwt.pub"),
//!     28800,
//! ).unwrap();
//!
//! let token = svc.issue("user-uuid", "tenant-uuid", &Role::Analyst).unwrap();
//! let claims = svc.validate(&token).unwrap();
//! assert_eq!(claims.role, "analyst");
//! ```

use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{error::AuthError, rbac::Role, session::SessionBlocklist};

/// Claims encoded inside every KRON JWT.
///
/// All fields are standard JWT (`sub`, `exp`, `iat`) or KRON-specific
/// (`tenant_id`, `role`, `jti`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject — the user's UUID string.
    pub sub: String,
    /// Tenant UUID string. Must match the row-level security filter on every
    /// database query. Never trust a tenant ID from the request body — always
    /// use this claim.
    pub tenant_id: String,
    /// Role as a lowercase `snake_case` string (matches [`Role`] serde output).
    pub role: String,
    /// Expiry as a Unix timestamp (seconds since epoch).
    pub exp: u64,
    /// Issued-at as a Unix timestamp.
    pub iat: u64,
    /// JWT ID — unique per token; used for revocation via [`SessionBlocklist`].
    pub jti: String,
}

/// RSA key material for JWT signing and verification.
///
/// Hold both keys in a single struct so they are always loaded together and
/// the service can fail fast at startup if either key file is corrupt.
pub struct JwtKeys {
    /// RSA private key for signing (RS256). Never leave the auth service.
    pub(crate) encoding: EncodingKey,
    /// RSA public key for verification. Distributed to all KRON services.
    pub(crate) decoding: DecodingKey,
}

/// JWT issuance and validation service.
///
/// Constructed once at startup and shared via `Arc` / Axum `Extension`.
pub struct JwtService {
    keys: Arc<JwtKeys>,
    expiry_secs: u64,
}

impl JwtService {
    /// Constructs a new [`JwtService`] from RSA PEM key files.
    ///
    /// # Arguments
    /// * `private_key_pem` — raw bytes of the RSA private key in PEM format
    /// * `public_key_pem`  — raw bytes of the RSA public key in PEM format
    /// * `expiry_secs`     — token lifetime in seconds (from `AuthConfig`)
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::JwtEncode`] if either PEM cannot be parsed.
    pub fn new(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
        expiry_secs: u64,
    ) -> Result<Self, AuthError> {
        let encoding = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|e| AuthError::JwtEncode(format!("invalid private key PEM: {e}")))?;
        let decoding = DecodingKey::from_rsa_pem(public_key_pem)
            .map_err(|e| AuthError::JwtEncode(format!("invalid public key PEM: {e}")))?;

        Ok(Self {
            keys: Arc::new(JwtKeys { encoding, decoding }),
            expiry_secs,
        })
    }

    /// Issues a signed RS256 JWT for the given principal.
    ///
    /// # Arguments
    /// * `user_id`   — UUID of the authenticated user
    /// * `tenant_id` — UUID of the user's tenant
    /// * `role`      — the user's RBAC role
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::JwtEncode`] if the RS256 signing operation fails.
    #[tracing::instrument(skip(self), fields(user_id, tenant_id, role = %role))]
    pub fn issue(&self, user_id: &str, tenant_id: &str, role: &Role) -> Result<String, AuthError> {
        // Timestamps are Unix seconds since epoch; always non-negative.
        #[allow(clippy::cast_sign_loss)]
        let now = Utc::now().timestamp() as u64;
        let exp = now + self.expiry_secs;

        let claims = JwtClaims {
            sub: user_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            role: role.to_string(),
            exp,
            iat: now,
            jti: Uuid::new_v4().to_string(),
        };

        let header = Header::new(Algorithm::RS256);
        encode(&header, &claims, &self.keys.encoding)
            .map_err(|e| AuthError::JwtEncode(format!("signing failed: {e}")))
    }

    /// Validates a JWT string, returning the decoded claims on success.
    ///
    /// Validates both the RS256 signature and the `exp` claim. Does **not**
    /// check the session blocklist — that is done by [`JwtExtractor`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenExpired`] if the token's `exp` is in the past.
    /// Returns [`AuthError::TokenInvalid`] for any other validation failure.
    #[tracing::instrument(skip(self, token))]
    pub fn validate(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        decode::<JwtClaims>(token, &self.keys.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                    AuthError::TokenExpired
                } else {
                    AuthError::TokenInvalid(e.to_string())
                }
            })
    }

    /// Decodes JWT claims while ignoring expiry, for use in the refresh flow.
    ///
    /// Validates the RS256 signature but allows tokens that expired within the
    /// last hour (3600-second grace). Tokens older than that are still rejected
    /// to prevent indefinite replay.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenExpired`] if the token expired more than 1 hour ago.
    /// Returns [`AuthError::TokenInvalid`] if the signature or structure is wrong.
    #[tracing::instrument(skip(self, token))]
    pub fn claims_unchecked_expiry(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;

        let claims = decode::<JwtClaims>(token, &self.keys.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| AuthError::TokenInvalid(e.to_string()))?;

        // Enforce a 1-hour grace window even in the refresh path.
        // Timestamps are Unix seconds since epoch; always non-negative.
        #[allow(clippy::cast_sign_loss)]
        let now = Utc::now().timestamp() as u64;
        const GRACE_SECS: u64 = 3600;
        if claims.exp + GRACE_SECS < now {
            return Err(AuthError::TokenExpired);
        }

        Ok(claims)
    }
}

/// Axum request-parts extractor that validates a Bearer JWT.
///
/// Reads the `Authorization: Bearer <token>` header, validates the token via
/// [`JwtService`], and checks the `jti` against [`SessionBlocklist`]. On
/// success, injects [`JwtClaims`] into the request extensions.
///
/// # Requires in Axum Extension state
/// * `Arc<JwtService>`
/// * `Arc<SessionBlocklist>`
///
/// # Errors
///
/// Responds with HTTP 401 and a JSON `{"error": "..."}` body on failure.
#[axum::async_trait]
impl<S> FromRequestParts<S> for JwtClaims
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract Authorization header.
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "missing Authorization header"})),
                )
                    .into_response()
            })?;

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Authorization header must use Bearer scheme"})),
            )
                .into_response()
        })?;

        // Resolve JwtService from extensions.
        let jwt_svc = parts
            .extensions
            .get::<Arc<JwtService>>()
            .ok_or_else(|| {
                tracing::error!("JwtService not registered as Axum Extension");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
                )
                    .into_response()
            })?
            .clone();

        // Validate signature and expiry.
        let claims = jwt_svc.validate(token).map_err(|e| {
            let msg = e.to_string();
            (StatusCode::UNAUTHORIZED, Json(json!({"error": msg}))).into_response()
        })?;

        // Check blocklist.
        let blocklist = parts
            .extensions
            .get::<Arc<SessionBlocklist>>()
            .ok_or_else(|| {
                tracing::error!("SessionBlocklist not registered as Axum Extension");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal server error"})),
                )
                    .into_response()
            })?;

        if blocklist.is_revoked(&claims.jti) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "token revoked"})),
            )
                .into_response());
        }

        Ok(claims)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Generates a throwaway 2048-bit RSA key pair for tests.
    /// In CI this runs once; the cost is acceptable.
    fn test_key_pair() -> (Vec<u8>, Vec<u8>) {
        // Use the openssl crate is not available; generate with RSA test vectors
        // that are checked in as test fixtures for determinism.
        // For unit tests we use a pre-generated 2048-bit RSA pair (test-only).
        let private_pem = include_bytes!("../tests/fixtures/test_jwt.key");
        let public_pem = include_bytes!("../tests/fixtures/test_jwt.pub");
        (private_pem.to_vec(), public_pem.to_vec())
    }

    #[test]
    fn test_jwt_service_when_valid_token_then_claims_round_trip() {
        let (priv_pem, pub_pem) = test_key_pair();
        let svc = JwtService::new(&priv_pem, &pub_pem, 3600).unwrap();

        let token = svc.issue("user-123", "tenant-456", &Role::Analyst).unwrap();
        let claims = svc.validate(&token).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.tenant_id, "tenant-456");
        assert_eq!(claims.role, "analyst");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_jwt_service_when_tampered_token_then_invalid_error() {
        let (priv_pem, pub_pem) = test_key_pair();
        let svc = JwtService::new(&priv_pem, &pub_pem, 3600).unwrap();

        let token = svc.issue("user-123", "tenant-456", &Role::Viewer).unwrap();
        // Corrupt the signature part (last segment).
        let mut parts: Vec<&str> = token.splitn(3, '.').collect();
        parts[2] = "invalidsignature";
        let tampered = parts.join(".");

        let result = svc.validate(&tampered);
        assert!(matches!(result, Err(AuthError::TokenInvalid(_))));
    }

    #[test]
    fn test_jwt_service_when_expired_token_then_expired_error() {
        let (priv_pem, pub_pem) = test_key_pair();
        // expiry_secs = 0 → token expires immediately
        let svc = JwtService::new(&priv_pem, &pub_pem, 0).unwrap();

        let token = svc.issue("user-999", "tenant-001", &Role::Viewer).unwrap();

        // Give clock a moment to advance past expiry.
        std::thread::sleep(std::time::Duration::from_secs(1));

        let result = svc.validate(&token);
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }
}
