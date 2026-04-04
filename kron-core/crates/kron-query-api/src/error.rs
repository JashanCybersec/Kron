//! API-level error types and HTTP response mapping.
//!
//! [`ApiError`] covers every failure mode a handler can return. Each variant
//! carries a human-readable message and maps to a specific HTTP status code.
//! The JSON body always has the shape `{"error": "…", "code": "VARIANT"}`.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use kron_auth::AuthError;
use serde::Serialize;
use thiserror::Error;

/// All error variants that an API handler may produce.
///
/// Implement [`IntoResponse`] so handlers can use `?` with `Result<_, ApiError>`.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The request did not supply valid credentials or a valid token.
    #[error("{0}")]
    Unauthorized(String),

    /// The caller's role does not permit the action they attempted.
    #[error("{0}")]
    Forbidden(String),

    /// The requested resource does not exist or belongs to another tenant.
    #[error("{0}")]
    NotFound(String),

    /// The request body or query parameters are malformed or invalid.
    #[error("{0}")]
    BadRequest(String),

    /// The operation cannot proceed because of a conflicting resource state.
    #[error("{0}")]
    Conflict(String),

    /// The caller is sending requests too rapidly.
    #[error("{0}")]
    TooManyRequests(String),

    /// An unrecoverable server-side failure.
    #[error("{0}")]
    Internal(String),
}

/// Wire representation of every error response body.
#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    code: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            ApiError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            ApiError::TooManyRequests(_) => (StatusCode::TOO_MANY_REQUESTS, "TOO_MANY_REQUESTS"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR"),
        };

        let _body = ErrorBody {
            error: self.to_string().as_str(),
            // SAFETY: `to_string()` borrows `self` which is dropped at the end of this fn.
            // We need an owned String in the body. Use a small helper below.
            code,
        };

        // Re-encode with owned message to avoid lifetime issues.
        (
            status,
            Json(OwnedErrorBody {
                error: self.to_string(),
                code,
            }),
        )
            .into_response()
    }
}

/// Owned version of the wire error body used by `IntoResponse`.
#[derive(Serialize)]
struct OwnedErrorBody {
    error: String,
    code: &'static str,
}

/// Converts `AuthError` into the closest matching `ApiError`.
impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials => {
                // Return a generic message to prevent user enumeration.
                ApiError::Unauthorized("invalid email or password".to_owned())
            }
            AuthError::AccountLocked { retry_after_secs } => ApiError::TooManyRequests(format!(
                "account locked due to too many failed attempts, retry after {retry_after_secs}s"
            )),
            AuthError::TokenExpired => ApiError::Unauthorized("token has expired".to_owned()),
            AuthError::TokenInvalid(msg) => {
                ApiError::Unauthorized(format!("token is invalid: {msg}"))
            }
            AuthError::TokenRevoked => ApiError::Unauthorized("token has been revoked".to_owned()),
            AuthError::TotpRequired => {
                ApiError::Unauthorized("TOTP code required for this account".to_owned())
            }
            AuthError::TotpInvalid => ApiError::Unauthorized("TOTP code is invalid".to_owned()),
            AuthError::PermissionDenied {
                role,
                action,
                resource,
            } => ApiError::Forbidden(format!("role '{role}' cannot '{action}' on '{resource}'")),
            AuthError::PasswordHash(msg) => {
                tracing::error!(error = %msg, "internal password hashing error");
                ApiError::Internal("internal authentication error".to_owned())
            }
            AuthError::JwtEncode(msg) => {
                tracing::error!(error = %msg, "JWT encoding failure");
                ApiError::Internal("internal token issuance error".to_owned())
            }
            AuthError::MissingAuthHeader => {
                ApiError::Unauthorized("Authorization header is required".to_owned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_unauthorized_when_converted_then_status_401() {
        let err = ApiError::Unauthorized("bad token".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_forbidden_when_converted_then_status_403() {
        let err = ApiError::Forbidden("no access".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_not_found_when_converted_then_status_404() {
        let err = ApiError::NotFound("alert not found".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_too_many_requests_when_converted_then_status_429() {
        let err = ApiError::TooManyRequests("slow down".to_owned());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_auth_error_account_locked_when_converted_then_429() {
        let err = ApiError::from(AuthError::AccountLocked {
            retry_after_secs: 60,
        });
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_auth_error_token_expired_when_converted_then_401() {
        let err = ApiError::from(AuthError::TokenExpired);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
