//! `kron-query-api` binary entrypoint.
//!
//! Loads configuration, initialises tracing, sets up graceful shutdown, and
//! delegates to [`kron_query_api::run`].
//!
//! # Usage
//!
//! ```text
//! KRON_CONFIG=/etc/kron/kron.toml kron-query-api
//! ```

use std::sync::Arc;

use anyhow::Context;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::info;

use kron_types::KronConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Tracing ───────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    // ── Configuration ─────────────────────────────────────────────────────────
    let config_path =
        std::env::var("KRON_CONFIG").unwrap_or_else(|_| "/etc/kron/kron.toml".to_owned());

    let config = KronConfig::from_file(std::path::Path::new(&config_path))
        .with_context(|| format!("Failed to load config from '{config_path}'"))?;
    let config = Arc::new(config);

    info!(config_path = %config_path, mode = ?config.mode, "Configuration loaded");

    // ── Shutdown channel ──────────────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });

    kron_query_api::run(config, shutdown_rx).await
}

/// Waits for SIGINT (Ctrl-C) or SIGTERM and returns.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .unwrap_or_else(|e| tracing::error!(error = %e, "failed to listen for Ctrl-C"));
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
