//! `kron-query-api` library root.
//!
//! Exposes the full Axum REST and WebSocket API surface for the KRON SIEM
//! platform. The binary (`main.rs`) bootstraps infrastructure and calls
//! [`routes::build_router`] to obtain the router, then serves it.
//!
//! # Module structure
//!
//! - [`error`]      — `ApiError` enum with `IntoResponse` impl
//! - [`state`]      — `AppState` shared across all handlers
//! - [`middleware`] — JWT `AuthUser` extractor and auth layer
//! - [`routes`]     — Router construction
//! - [`handlers`]   — One sub-module per resource group
//! - [`ws`]         — WebSocket upgrade handlers
//!
//! # Entry point
//!
//! Call [`run`] with a loaded [`KronConfig`] and a shutdown receiver to embed
//! this service in `kron-nano` without spawning a child process.

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod routes;
pub mod state;
pub mod ws;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use kron_storage::{AdaptiveStorage, StorageEngine};
use kron_types::KronConfig;
use tokio::sync::broadcast;

/// Runs the query-API server until `shutdown_rx` fires or a fatal error occurs.
///
/// Builds all subsystems (storage, JWT service, bus producer) and serves the
/// Axum router with graceful shutdown. Identical to the startup sequence in
/// `main.rs` but accepts an external shutdown signal so it can be embedded in
/// `kron-nano`.
///
/// # Errors
///
/// Returns an error if any subsystem fails to initialise or if the Axum server
/// exits with an error.
pub async fn run(
    config: Arc<KronConfig>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    // ── Storage ───────────────────────────────────────────────────────────────
    let storage = AdaptiveStorage::new(&config)
        .await
        .context("Failed to initialise storage backend")?;
    let storage = Arc::new(storage);

    tracing::info!(backend = %storage.backend_name(), "Storage backend initialised");

    // ── JWT service ───────────────────────────────────────────────────────────
    let private_pem = std::fs::read(&config.auth.jwt_private_key_path).with_context(|| {
        format!(
            "Cannot read JWT private key from '{}'",
            config.auth.jwt_private_key_path.display()
        )
    })?;

    let public_pem = std::fs::read(&config.auth.jwt_public_key_path).with_context(|| {
        format!(
            "Cannot read JWT public key from '{}'",
            config.auth.jwt_public_key_path.display()
        )
    })?;

    let jwt_service =
        state::JwtService::from_pem(&private_pem, &public_pem, config.auth.jwt_expiry_secs)
            .map_err(|e| anyhow::anyhow!("Failed to initialise JwtService: {e}"))?;
    let jwt_service = Arc::new(jwt_service);

    // ── Auth guard eviction task ──────────────────────────────────────────────
    {
        let rt = Arc::clone(&storage.revoked_tokens);
        let la = Arc::clone(&storage.login_attempts);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(300));
            loop {
                tick.tick().await;
                if let Err(e) = rt.evict_expired().await {
                    tracing::warn!(error = %e, "Failed to evict expired revoked tokens");
                }
                if let Err(e) = la.evict_expired().await {
                    tracing::warn!(error = %e, "Failed to evict expired login-attempt records");
                }
                tracing::debug!("Evicted expired auth guard entries");
            }
        });
    }

    // ── Parquet cold-tier archival (Nano / DuckDB only) ───────────────────────
    if config.mode == kron_types::DeploymentMode::Nano
        && config.duckdb.cold_archive_dir != std::path::PathBuf::default()
    {
        let storage_arc = Arc::clone(&storage);
        let archive_dir = config.duckdb.cold_archive_dir.clone();
        let retention_days = config.duckdb.cold_storage_retention_days;
        let interval_hours = config.duckdb.cold_archive_interval_hours;

        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval(Duration::from_secs(interval_hours * 3600));
            loop {
                tick.tick().await;
                match storage_arc
                    .archive_to_parquet(archive_dir.clone(), retention_days)
                    .await
                {
                    Ok(()) => tracing::info!("Parquet cold-tier archival completed"),
                    Err(e) => tracing::error!(error = %e, "Parquet cold-tier archival failed"),
                }
            }
        });
    }

    // ── Bus producer ──────────────────────────────────────────────────────────
    let bus_producer: Arc<dyn kron_bus::BusProducer> = {
        let adaptive =
            kron_bus::AdaptiveBus::new((*config).clone()).context("Failed to initialise bus")?;
        let producer = adaptive
            .new_producer()
            .context("Failed to create bus producer")?;
        Arc::from(producer)
    };

    // ── App state + router ────────────────────────────────────────────────────
    let state_obj = state::AppState {
        storage,
        bus: bus_producer,
        jwt: jwt_service,
        config: Arc::clone(&config),
        ws_conn_counts: state::WsConnCounts::default(),
    };

    let app = routes::build_router(state_obj);

    // ── Bind and serve ────────────────────────────────────────────────────────
    let addr: SocketAddr = config
        .api
        .listen_addr
        .parse()
        .with_context(|| format!("Invalid api.listen_addr: '{}'", config.api.listen_addr))?;

    tracing::info!(address = %addr, "kron-query-api listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Cannot bind to {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            tracing::info!("Shutdown signal received, draining connections");
        })
        .await
        .context("Server error")?;

    tracing::info!("kron-query-api shutdown complete");
    Ok(())
}
