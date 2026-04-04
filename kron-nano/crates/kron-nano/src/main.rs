//! `kron-nano` — Single-binary KRON SIEM for small on-premise deployments.
//!
//! Runs all KRON services (collector, normalizer, stream, alert, query-api)
//! as tokio tasks within a single process. Designed for nodes with 8 GB RAM,
//! up to 50 monitored endpoints, and up to 1 K events per second.
//!
//! Storage: DuckDB (embedded, no ClickHouse required).
//! Message bus: embedded disk-backed WAL (no Redpanda required).
//!
//! # Usage
//!
//! ```text
//! KRON_CONFIG=/etc/kron/kron.toml kron-nano
//! ```
//!
//! Stream-specific directories are configured via environment variables:
//!
//! ```text
//! KRON_STREAM_RULES_DIR=/var/lib/kron/rules
//! KRON_STREAM_MODELS_DIR=/var/lib/kron/models
//! KRON_STREAM_TENANT_IDS=<uuid1>,<uuid2>
//! ```

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;

use kron_types::KronConfig;

/// Default config file path for Nano deployments.
const DEFAULT_CONFIG_PATH: &str = "/etc/kron/kron.toml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Tracing ───────────────────────────────────────────────────────────────
    let log_level = std::env::var("KRON_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level)),
        )
        .json()
        .init();

    tracing::info!("kron-nano starting — single-binary mode");

    // ── Configuration ─────────────────────────────────────────────────────────
    let config_path =
        std::env::var("KRON_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());

    let config = KronConfig::from_file(std::path::Path::new(&config_path))
        .with_context(|| format!("failed to load config from '{config_path}'"))?;

    if config.mode != kron_types::DeploymentMode::Nano {
        anyhow::bail!(
            "kron-nano requires mode = \"nano\" in config; found {:?}. \
             Use kron-collector / kron-normalizer / kron-stream / kron-alert / \
             kron-query-api for Standard/Enterprise deployments.",
            config.mode
        );
    }

    let config = Arc::new(config);
    tracing::info!(config_path = %config_path, "configuration loaded");

    // ── Master shutdown channel ───────────────────────────────────────────────
    // kron-collector and kron-normalizer install their own OS signal handlers
    // internally. kron-stream needs its ShutdownHandle triggered from outside.
    // kron-alert and kron-query-api receive a broadcast::Receiver<()> from here.
    let (master_tx, _) = broadcast::channel::<()>(8);

    // ── kron-collector ────────────────────────────────────────────────────────
    // ShutdownHandle::new() spawns an OS signal listener task internally.
    let (col_shutdown, _col_signal) = kron_collector::ShutdownHandle::new();
    let col_config = (*config).clone();
    let col_sd = col_shutdown.clone();
    let collector_task = tokio::spawn(async move {
        let collector = kron_collector::Collector::new(col_config, col_sd);
        if let Err(e) = collector.run().await {
            tracing::error!(error = %e, "kron-collector exited with error");
        }
    });

    // ── kron-normalizer ───────────────────────────────────────────────────────
    // ShutdownHandle::new() spawns an OS signal listener task internally.
    let (norm_shutdown, _norm_signal) = kron_normalizer::ShutdownHandle::new();
    let norm_config = (*config).clone();
    let norm_sd = norm_shutdown.clone();
    let normalizer_task = tokio::spawn(async move {
        if let Err(e) = kron_normalizer::run(norm_config, norm_sd).await {
            tracing::error!(error = %e, "kron-normalizer exited with error");
        }
    });

    // ── kron-stream ───────────────────────────────────────────────────────────
    // ShutdownHandle must have listen_for_signals() called explicitly.
    let stream_shutdown = Arc::new(kron_stream::shutdown::ShutdownHandle::new());
    let stream_shutdown_for_signals = Arc::clone(&stream_shutdown);
    tokio::spawn(async move {
        stream_shutdown_for_signals.listen_for_signals().await;
    });
    let stream_config = (*config).clone();
    let stream_sd = Arc::clone(&stream_shutdown);
    let stream_task = tokio::spawn(async move {
        if let Err(e) = kron_stream::run(stream_config, stream_sd).await {
            tracing::error!(error = %e, "kron-stream exited with error");
        }
    });

    // ── kron-alert ────────────────────────────────────────────────────────────
    let alert_config = (*config).clone();
    let alert_rx = master_tx.subscribe();
    let alert_task = tokio::spawn(async move {
        if let Err(e) = kron_alert::run(alert_config, alert_rx).await {
            tracing::error!(error = %e, "kron-alert exited with error");
        }
    });

    // ── kron-query-api ────────────────────────────────────────────────────────
    let api_config = Arc::clone(&config);
    let api_rx = master_tx.subscribe();
    let api_task = tokio::spawn(async move {
        if let Err(e) = kron_query_api::run(api_config, api_rx).await {
            tracing::error!(error = %e, "kron-query-api exited with error");
        }
    });

    tracing::info!(
        services = "collector, normalizer, stream, alert, query-api",
        "all services started"
    );

    // ── Await OS shutdown signal ──────────────────────────────────────────────
    // Sends shutdown to kron-alert and kron-query-api via the master channel.
    // kron-collector and kron-normalizer catch OS signals independently.
    // kron-stream's signal task handles its own shutdown.
    await_termination_signal().await;
    tracing::info!("shutdown signal received — stopping alert and query-api");
    let _ = master_tx.send(());

    // Wait for all service tasks.
    let _ = tokio::join!(
        collector_task,
        normalizer_task,
        stream_task,
        alert_task,
        api_task,
    );

    tracing::info!("kron-nano shutdown complete");
    Ok(())
}

/// Waits for SIGTERM (Unix) or Ctrl-C, whichever arrives first.
///
/// Used by kron-nano to coordinate shutdown of services that do not install
/// their own signal handlers (kron-alert, kron-query-api).
async fn await_termination_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to register SIGTERM handler");
                tokio::signal::ctrl_c()
                    .await
                    .unwrap_or_else(|e| tracing::error!(error = %e, "ctrl_c error"));
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received"),
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    tracing::error!(error = %e, "ctrl_c error");
                } else {
                    tracing::info!("SIGINT received");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .unwrap_or_else(|e| tracing::error!(error = %e, "ctrl_c error"));
        tracing::info!("Ctrl-C received");
    }
}
