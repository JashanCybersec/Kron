//! `kron-ctl storage stats` — show storage backend statistics.
//!
//! Connects to the configured storage backend and prints:
//! - Backend type (DuckDB or ClickHouse)
//! - Health status
//! - Latency statistics (p50/p99 for recent queries)
//! - Deployment mode

use kron_storage::{AdaptiveStorage, StorageEngine as _};

use crate::{config::CtlConfig, error::CtlError, output};

/// Run `kron-ctl storage stats`.
///
/// # Errors
/// Returns [`CtlError::Storage`] if the backend cannot be reached.
pub async fn run_stats(config: &CtlConfig) -> Result<(), CtlError> {
    output::header("Storage Statistics");

    let storage = AdaptiveStorage::new(&config.inner)
        .await
        .map_err(|e| CtlError::Storage(e.to_string()))?;

    // Health check.
    match storage.health_check().await {
        Ok(()) => output::ok("health", "ok"),
        Err(e) => {
            output::fail("health", &e.to_string());
            return Ok(());
        }
    }

    let backend = storage.backend_name();
    let mode = format!("{:?}", config.inner.mode);
    let stats = storage.latency_stats();

    output::ok("backend", backend);
    output::ok("deployment_mode", &mode);

    println!();
    println!("  Latency statistics (recent operations):");
    println!(
        "    p50 = {:.1}ms  p99 = {:.1}ms",
        stats.p50_ms, stats.p99_ms
    );
    println!("    total queries  : {}", stats.total_queries);
    println!("    total inserted : {}", stats.total_events_inserted);
    println!();

    match backend {
        "clickhouse" => {
            println!("  ClickHouse URL : {}", config.inner.clickhouse.url);
            println!("  Database       : {}", config.inner.clickhouse.database);
        }
        "duckdb" => {
            println!("  DuckDB path    : {}", config.inner.duckdb.path.display());
        }
        _ => {}
    }

    println!();
    Ok(())
}
