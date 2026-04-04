//! Top-level error type for the KRON platform.
//!
//! All `kron-*` crates define their own internal error types and convert them
//! to `KronError` at API and inter-crate boundaries. This ensures error
//! handling is type-safe and carries enough context for structured logging.

use thiserror::Error;

/// The top-level KRON error type.
///
/// Each variant carries enough context to log a meaningful structured message
/// and determine whether the error is transient (retriable) or permanent.
#[derive(Debug, Error)]
pub enum KronError {
    /// A required configuration value is missing or invalid.
    #[error("configuration error: {0}")]
    Config(String),

    /// A database or storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// A message bus operation failed.
    #[error("bus error: {0}")]
    Bus(String),

    /// An authentication or authorisation check failed.
    #[error("auth error: {0}")]
    Auth(String),

    /// A required field was not present in the input.
    #[error("missing field: {field}")]
    MissingField {
        /// Name of the missing field.
        field: String,
    },

    /// An input value failed validation.
    #[error("validation error on field `{field}`: {reason}")]
    Validation {
        /// Name of the field that failed validation.
        field: String,
        /// Human-readable reason for the validation failure.
        reason: String,
    },

    /// The requested resource was not found.
    #[error("not found: {resource_type} with id `{id}`")]
    NotFound {
        /// The type of resource that was not found (e.g. "event", "alert").
        resource_type: String,
        /// The ID that was looked up.
        id: String,
    },

    /// A cross-tenant data access attempt was detected and blocked.
    ///
    /// This error must always be logged at `error` level and trigger an
    /// internal security alert.
    #[error(
        "tenant isolation violation: attempted access to tenant `{target}` from tenant `{caller}`"
    )]
    TenantIsolationViolation {
        /// The tenant ID of the authenticated caller.
        caller: String,
        /// The tenant ID of the data that was illegally requested.
        target: String,
    },

    /// An event, log line, or message could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An internal invariant was violated. This is always a bug.
    #[error("internal error: {0}")]
    Internal(String),
}

impl KronError {
    /// Returns `true` if the error is transient and the operation may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Storage(_) | Self::Bus(_))
    }

    /// Returns the HTTP status code that best represents this error.
    ///
    /// Used by the query API to set response status codes.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Auth(_) => 401,
            Self::TenantIsolationViolation { .. } => 403,
            Self::NotFound { .. } => 404,
            Self::Validation { .. } | Self::MissingField { .. } | Self::Parse(_) => 400,
            _ => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_field_error_when_displayed_then_contains_field_name() {
        let err = KronError::MissingField {
            field: "tenant_id".to_string(),
        };
        assert!(err.to_string().contains("tenant_id"));
    }

    #[test]
    fn test_tenant_isolation_violation_when_displayed_then_contains_both_tenants() {
        let err = KronError::TenantIsolationViolation {
            caller: "tenant-a".to_string(),
            target: "tenant-b".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("tenant-a"));
        assert!(msg.contains("tenant-b"));
    }

    #[test]
    fn test_storage_error_when_checked_then_is_transient() {
        let err = KronError::Storage("connection refused".to_string());
        assert!(err.is_transient());
    }

    #[test]
    fn test_bus_error_when_checked_then_is_transient() {
        let err = KronError::Bus("broker unavailable".to_string());
        assert!(err.is_transient());
    }

    #[test]
    fn test_validation_error_when_checked_then_is_not_transient() {
        let err = KronError::Validation {
            field: "severity_score".to_string(),
            reason: "must be 0-100".to_string(),
        };
        assert!(!err.is_transient());
    }

    #[test]
    fn test_auth_error_when_mapped_then_returns_401() {
        let err = KronError::Auth("invalid token".to_string());
        assert_eq!(err.http_status(), 401);
    }

    #[test]
    fn test_tenant_isolation_when_mapped_then_returns_403() {
        let err = KronError::TenantIsolationViolation {
            caller: "a".to_string(),
            target: "b".to_string(),
        };
        assert_eq!(err.http_status(), 403);
    }

    #[test]
    fn test_not_found_when_mapped_then_returns_404() {
        let err = KronError::NotFound {
            resource_type: "alert".to_string(),
            id: "abc".to_string(),
        };
        assert_eq!(err.http_status(), 404);
    }

    #[test]
    fn test_internal_error_when_mapped_then_returns_500() {
        let err = KronError::Internal("invariant broken".to_string());
        assert_eq!(err.http_status(), 500);
    }
}
