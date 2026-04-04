//! `kron-alert` — Alert engine for the KRON SIEM platform.
//!
//! Assembles, deduplicates, and delivers alerts to analysts via WhatsApp
//! (primary), SMS (fallback), and email (secondary fallback).
//!
//! # Alert pipeline
//!
//! 1. Consume alert candidates from stream processor
//! 2. Deduplicate: group by `(rule_id + affected_asset + 15-min window)`
//! 3. Assemble `KronAlert` with evidence event IDs
//! 4. Generate plain-language EN/HI narrative
//! 5. Deliver via WhatsApp Business API with fallback to SMS, then email
//!
//! # Notification rate limits
//!
//! P1/P2: always immediate. P3+: max 10/hour (excess rate-limited).
//!
//! # Usage
//!
//! ```text
//! KRON_CONFIG=/etc/kron/kron.toml kron-alert
//! ```

use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;

fn main() -> std::process::ExitCode {
    // Bootstrap tracing early so config load errors are visible.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config_path =
        std::env::var("KRON_CONFIG").unwrap_or_else(|_| "/etc/kron/kron.toml".to_string());

    tracing::info!(config = %config_path, "kron-alert starting");

    let config = match kron_types::KronConfig::from_file(std::path::Path::new(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: failed to load config: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kron-alert")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: cannot create Tokio runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move {
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Received SIGINT — initiating shutdown");
                let _ = shutdown_tx.send(());
            }
        });

        match kron_alert::run(config, shutdown_rx).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "Alert engine exited with error");
                std::process::ExitCode::FAILURE
            }
        }
    })
}
