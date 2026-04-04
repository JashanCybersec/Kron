//! Error types for `kron-normalizer`.

use thiserror::Error;

/// All errors that can occur in the normalizer pipeline.
#[derive(Debug, Error)]
pub enum NormalizerError {
    /// Bus consumer or producer error.
    #[error("bus error: {0}")]
    Bus(#[from] kron_bus::error::BusError),

    /// Storage write failure.
    #[error("storage error: {0}")]
    Storage(String),

    /// Configuration is invalid or incomplete.
    #[error("config error: {0}")]
    Config(String),

    /// GeoIP database could not be opened or queried.
    #[error("geoip error: {0}")]
    GeoIp(String),

    /// I/O error (reading config, MMDB file, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
