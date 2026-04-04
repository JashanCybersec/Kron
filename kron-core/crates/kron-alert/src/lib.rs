//! `kron-alert` library — alert engine for the KRON SIEM platform.
//!
//! Exposes the alert engine as a library so that `kron-nano` can embed it
//! in a single-binary deployment. The `kron-alert` binary remains the
//! standalone Standard/Enterprise entrypoint.
//!
//! # Entry point
//!
//! Call [`run`] with a loaded [`KronConfig`] and a shutdown receiver obtained
//! from a `tokio::sync::broadcast` channel. The function returns when
//! the receiver fires or a fatal error occurs.

pub mod assembler;
pub mod dedup;
pub mod engine;
pub mod error;
pub mod metrics;
pub mod narrative;
pub mod notify;
pub mod types;

pub use engine::AlertEngine;
pub use error::AlertError;

use std::sync::Arc;

use anyhow::Context;
use kron_bus::topics;
use kron_bus::AdaptiveBus;
use kron_storage::AdaptiveStorage;
use kron_types::KronConfig;
use tokio::sync::broadcast;

/// Runs the alert engine until `shutdown_rx` fires or a fatal error occurs.
///
/// Builds storage, the bus consumer, subscribes to all tenant alert topics,
/// initialises the [`AlertEngine`], and drives the consume/deliver loop.
///
/// # Errors
///
/// Returns an error if any subsystem fails to initialise or if the engine
/// loop exits with a fatal error.
pub async fn run(config: KronConfig, shutdown_rx: broadcast::Receiver<()>) -> anyhow::Result<()> {
    tracing::info!("kron-alert starting");

    // Storage backend.
    let storage = AdaptiveStorage::new(&config)
        .await
        .context("failed to initialise storage")?;
    let storage = Arc::new(storage);

    // Bus + consumer.
    let bus = AdaptiveBus::new(config.clone()).context("failed to initialise message bus")?;

    let mut consumer = bus
        .new_consumer("kron-alert")
        .context("failed to create bus consumer")?;

    // Subscribe to alert-candidate topics for all configured tenants.
    let alert_topics: Vec<String> = config
        .normalizer
        .raw_tenant_ids
        .iter()
        .filter_map(|s| s.parse::<kron_types::TenantId>().ok())
        .map(|tid| topics::alerts(&tid))
        .collect();

    if alert_topics.is_empty() {
        tracing::warn!(
            "No tenant IDs configured in normalizer.raw_tenant_ids — \
             alert engine will not consume any topics"
        );
    } else {
        consumer
            .subscribe(&alert_topics, "kron-alert-group")
            .await
            .context("failed to subscribe to alert topics")?;
        tracing::info!(topics = ?alert_topics, "Subscribed to alert-candidate topics");
    }

    // Build and run engine.
    let engine = engine::AlertEngine::new(&config, Arc::clone(&storage), &bus)
        .context("failed to create alert engine")?;
    let engine = Arc::new(engine);

    engine
        .run(consumer, shutdown_rx)
        .await
        .context("alert engine exited with error")?;

    tracing::info!("kron-alert shutdown complete");
    Ok(())
}
