//! Collector-specific error type.
//!
//! All fallible operations in `kron-collector` return [`CollectorError`].
//! Every variant carries enough context for structured logging.

use thiserror::Error;

/// Errors produced by the kron-collector process.
#[derive(Debug, Error)]
pub enum CollectorError {
    /// Configuration file could not be read or parsed.
    #[error("config error: {0}")]
    Config(String),

    /// The gRPC server failed to start or crashed.
    #[error("gRPC server error: {0}")]
    #[allow(dead_code)]
    Grpc(String),

    /// The HTTP intake server (Axum) failed to start or crashed.
    #[error("HTTP server error: {0}")]
    Http(String),

    /// A syslog receiver (UDP or TCP) failed.
    #[error("syslog error: {0}")]
    Syslog(String),

    /// Message bus operation failed.
    #[error("bus error: {0}")]
    Bus(#[from] kron_bus::error::BusError),

    /// TLS certificate or key could not be loaded.
    #[error("TLS error: {0}")]
    #[allow(dead_code)]
    Tls(String),

    /// Agent registry operation failed (e.g. unknown agent ID).
    #[error("registry error: {0}")]
    #[allow(dead_code)]
    Registry(String),

    /// A Tokio task panicked or was cancelled.
    #[error("task error: {0}")]
    #[allow(dead_code)]
    Task(String),

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
