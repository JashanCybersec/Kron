//! `kron-stream` — Stream detection engine for the KRON SIEM platform.
//!
//! Consumes enriched events from `kron.enriched.{tenant_id}`, runs the full
//! detection pipeline (IOC bloom filter → SIGMA rule evaluation → ONNX anomaly
//! scoring → risk score → MITRE tagging → entity graph), and publishes
//! serialised [`AlertCandidatePayload`] messages to `kron.alerts.{tenant_id}`
//! for `kron-alert`.
//!
//! # Usage
//!
//! ```text
//! KRON_CONFIG=/etc/kron/kron.toml \
//! KRON_STREAM_RULES_DIR=/var/lib/kron/rules \
//! KRON_STREAM_MODELS_DIR=/var/lib/kron/models \
//! KRON_STREAM_TENANT_IDS=<uuid1>,<uuid2> \
//! kron-stream
//! ```

use std::sync::Arc;

use kron_stream::shutdown::ShutdownHandle;
use kron_types::KronConfig;

/// Environment variable pointing to the KRON config file.
const ENV_CONFIG_PATH: &str = "KRON_CONFIG";

/// Default config file path when the environment variable is not set.
const DEFAULT_CONFIG_PATH: &str = "/etc/kron/kron.toml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("KRON_LOG_LEVEL").unwrap_or_else(|_| "info".to_string()))
        .json()
        .init();

    tracing::info!("kron-stream starting");

    let config_path =
        std::env::var(ENV_CONFIG_PATH).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());

    let config = KronConfig::from_file(std::path::Path::new(&config_path))
        .map_err(|e| anyhow::anyhow!("loading config from {config_path}: {e}"))?;

    // Create shutdown handle. Signal listening runs concurrently with the
    // service so that `run()` can coordinate multiple consumer tasks.
    let shutdown = Arc::new(ShutdownHandle::new());
    let shutdown_for_signals = Arc::clone(&shutdown);

    tokio::spawn(async move {
        shutdown_for_signals.listen_for_signals().await;
    });

    kron_stream::run(config, shutdown).await
}
