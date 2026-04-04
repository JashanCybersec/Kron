//! Error types for `kron-ctl`.

use thiserror::Error;

/// Top-level error type for all `kron-ctl` operations.
#[derive(Debug, Error)]
pub enum CtlError {
    /// Configuration file could not be loaded or is invalid.
    #[error("config error: {0}")]
    Config(String),

    /// Storage backend returned an error.
    #[error("storage error: {0}")]
    Storage(String),

    /// HTTP request to the collector failed.
    #[error("HTTP error: {0}")]
    Http(String),

    /// JSON serialisation or deserialisation failed.
    #[error("serialise error: {0}")]
    Serialise(String),

    /// A CLI argument was invalid or out of range.
    #[error("invalid argument: {0}")]
    InvalidArg(String),

    /// Migration runner failed.
    #[error("migration error: {0}")]
    Migration(String),
}

impl From<kron_types::KronError> for CtlError {
    fn from(e: kron_types::KronError) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for CtlError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialise(e.to_string())
    }
}
