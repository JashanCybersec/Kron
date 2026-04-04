//! Configuration loading for `kron-ctl`.
//!
//! Loads a [`KronConfig`] from a TOML file and derives the service URLs
//! that the CLI uses to reach the collector and storage backends.

use std::path::Path;

use kron_types::KronConfig;

use crate::error::CtlError;

/// Resolved addresses derived from [`KronConfig`], used by kron-ctl commands.
pub struct CtlConfig {
    /// Full KRON platform configuration.
    pub inner: KronConfig,
    /// Base URL for the collector HTTP API (e.g. `http://localhost:9002`).
    pub collector_base_url: String,
}

impl CtlConfig {
    /// Load configuration from a TOML file.
    ///
    /// # Arguments
    /// * `path` - Path to `kron.toml`
    /// * `collector_url_override` - If provided, overrides the URL derived from config.
    ///
    /// # Errors
    /// Returns [`CtlError::Config`] if the file cannot be read or is malformed.
    pub fn load(path: &Path, collector_url_override: Option<&str>) -> Result<Self, CtlError> {
        let inner = KronConfig::from_file(path)
            .map_err(|e| CtlError::Config(format!("failed to load {}: {e}", path.display())))?;

        let collector_base_url = if let Some(url) = collector_url_override {
            url.to_owned()
        } else {
            // collector.http_addr is "0.0.0.0:9002" by default — rewrite to localhost.
            derive_base_url(&inner.collector.http_addr)
        };

        Ok(Self {
            inner,
            collector_base_url,
        })
    }
}

/// Converts a bind address like `0.0.0.0:9002` to `http://localhost:9002`.
fn derive_base_url(bind_addr: &str) -> String {
    // Strip any scheme prefix that might already be present.
    let addr = bind_addr
        .strip_prefix("http://")
        .or_else(|| bind_addr.strip_prefix("https://"))
        .unwrap_or(bind_addr);

    // Replace 0.0.0.0 (wildcard) with localhost for outbound connections.
    let addr = addr.replace("0.0.0.0", "127.0.0.1");
    format!("http://{addr}")
}
