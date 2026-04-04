//! `kron-ctl health` — check all KRON services.
//!
//! Checks the collector HTTP endpoint and the storage backend in parallel,
//! printing a status line for each.

use kron_storage::AdaptiveStorage;

use crate::{client::CollectorClient, config::CtlConfig, error::CtlError, output};

/// Run the health check command.
///
/// Checks:
/// 1. Collector HTTP `/health`
/// 2. Storage backend `health_check()`
///
/// Prints a status line for each service.  Returns `Ok(())` even when a
/// service is down so that the CLI exits 0 — callers read the output.
/// Returns `Err` only for configuration problems.
///
/// # Errors
/// Returns [`CtlError::Config`] if the configuration cannot be loaded.
pub async fn run(config: &CtlConfig) -> Result<(), CtlError> {
    output::header("KRON Health Check");

    let collector_result = check_collector(config).await;
    let storage_result = check_storage(config).await;

    match collector_result {
        Ok(status) => output::ok("collector", &status),
        Err(e) => output::fail("collector", &e.to_string()),
    }

    match storage_result {
        Ok(backend) => output::ok("storage", &backend),
        Err(e) => output::fail("storage", &e.to_string()),
    }

    println!();
    Ok(())
}

/// Ping the collector's `/health` endpoint.
async fn check_collector(config: &CtlConfig) -> Result<String, CtlError> {
    let client = CollectorClient::new(config.collector_base_url.clone())?;
    let resp = client.health().await?;
    Ok(format!("{} ({})", resp.status, config.collector_base_url))
}

/// Run a storage health check and return the backend name.
async fn check_storage(config: &CtlConfig) -> Result<String, CtlError> {
    let storage = AdaptiveStorage::new(&config.inner)
        .await
        .map_err(|e| CtlError::Storage(e.to_string()))?;

    use kron_storage::StorageEngine as _;
    storage
        .health_check()
        .await
        .map_err(|e| CtlError::Storage(e.to_string()))?;

    Ok(format!("{} — healthy", storage.backend_name()))
}
