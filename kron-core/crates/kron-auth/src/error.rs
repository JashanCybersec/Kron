//! Error types for the `kron-auth` crate.
//!
//! All authentication and authorization failures are expressed through
//! [`AuthError`], which implements [`std::error::Error`] via [`thiserror`].

use thiserror::Error;

/// Authentication and authorization error variants.
///
/// Every variant carries enough context for structured logging.
/// Variants are mapped to HTTP 401/403 responses by the Axum extractor.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Credentials (username/password) did not match any known account.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// The account is temporarily locked after repeated failed attempts.
    #[error("account locked: too many failed attempts, retry after {retry_after_secs}s")]
    AccountLocked {
        /// Seconds until the lockout expires and the account may be retried.
        retry_after_secs: u64,
    },

    /// The presented JWT has passed its `exp` claim.
    #[error("token expired")]
    TokenExpired,

    /// The JWT signature is invalid, the header is malformed, or required
    /// claims are absent.
    #[error("token invalid: {0}")]
    TokenInvalid(String),

    /// The JWT `jti` claim appears in the session blocklist (logged-out token).
    #[error("token revoked")]
    TokenRevoked,

    /// The account requires a TOTP code but none was supplied.
    #[error("TOTP required")]
    TotpRequired,

    /// The supplied TOTP code did not match the current or previous window.
    #[error("TOTP invalid")]
    TotpInvalid,

    /// The caller's role does not permit the requested action on the resource.
    #[error("permission denied: role {role} cannot {action} on {resource}")]
    PermissionDenied {
        /// Role of the caller.
        role: String,
        /// Action that was attempted.
        action: String,
        /// Resource that was targeted.
        resource: String,
    },

    /// Argon2id hashing or verification failed due to an internal error.
    #[error("password hashing error: {0}")]
    PasswordHash(String),

    /// JWT encoding (signing) failed.
    #[error("JWT encoding error: {0}")]
    JwtEncode(String),

    /// The request did not include an `Authorization` header.
    #[error("missing Authorization header")]
    MissingAuthHeader,
}
