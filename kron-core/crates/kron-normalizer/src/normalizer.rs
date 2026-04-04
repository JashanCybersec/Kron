//! Main normalizer service — bus consumer loop.
//!
//! [`Normalizer`] subscribes to one `kron.raw.{tenant_id}` topic per
//! configured tenant, polls for messages, and drives each through the
//! [`Pipeline`]. Unparseable messages are `nack`-ed (routed to the dead
//! letter topic after retries).

use std::sync::Arc;
use std::time::Duration;

use kron_bus::traits::BusConsumer;
use kron_types::KronConfig;
use tokio::sync::broadcast;

use crate::error::NormalizerError;
use crate::pipeline::Pipeline;

/// Bus poll timeout — keeps the consumer responsive to shutdown signals.
const POLL_TIMEOUT: Duration = Duration::from_millis(500);

/// The normalizer service.
pub struct Normalizer {
    config: KronConfig,
    pipeline: Arc<Pipeline>,
}

impl Normalizer {
    /// Creates a new [`Normalizer`] with the given config and pipeline.
    #[must_use]
    pub fn new(config: KronConfig, pipeline: Arc<Pipeline>) -> Self {
        Self { config, pipeline }
    }

    /// Runs the normalizer until a shutdown signal is received.
    ///
    /// Subscribes to all configured `kron.raw.{tenant_id}` topics, then
    /// polls in a loop, processing each message through the pipeline.
    ///
    /// # Errors
    ///
    /// Returns [`NormalizerError::Config`] if the bus cannot be connected or
    /// no tenant IDs are configured. Non-fatal per-message errors are logged.
    pub async fn run(self, mut shutdown: broadcast::Receiver<()>) -> Result<(), NormalizerError> {
        let cfg = &self.config.normalizer;

        if cfg.raw_tenant_ids.is_empty() {
            tracing::warn!(
                "normalizer.raw_tenant_ids is empty; no topics to consume. \
                 Add tenant UUIDs to kron.toml [normalizer] raw_tenant_ids."
            );
            return Ok(());
        }

        let bus = kron_bus::adaptive::AdaptiveBus::new(self.config.clone())
            .map_err(NormalizerError::Bus)?;

        let mut consumer = bus
            .new_consumer(&cfg.consumer_group_id)
            .map_err(NormalizerError::Bus)?;

        let topics: Vec<String> = cfg
            .raw_tenant_ids
            .iter()
            .filter_map(|id| {
                id.parse::<uuid::Uuid>()
                    .ok()
                    .map(|u| kron_bus::topics::raw_events(&kron_types::TenantId::from_uuid(u)))
            })
            .collect();

        if topics.is_empty() {
            return Err(NormalizerError::Config(
                "no valid tenant UUIDs in normalizer.raw_tenant_ids".to_owned(),
            ));
        }

        consumer
            .subscribe(&topics, &cfg.consumer_group_id)
            .await
            .map_err(NormalizerError::Bus)?;

        tracing::info!(
            topics = ?topics,
            group_id = %cfg.consumer_group_id,
            "Normalizer subscribed; starting consumer loop"
        );

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    tracing::info!("Normalizer shutting down");
                    break;
                }
                result = consumer.poll(POLL_TIMEOUT) => {
                    match result {
                        Ok(Some(msg)) => {
                            process_message(&self.pipeline, &mut *consumer, msg).await;
                        }
                        Ok(None) => {
                            // Timeout with no message — loop again.
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Bus poll error");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Processes a single bus message through the pipeline.
///
/// Commits on success; nacks on pipeline failure so the bus can route the
/// message to the dead letter topic after max retries.
async fn process_message(
    pipeline: &Arc<Pipeline>,
    consumer: &mut dyn BusConsumer,
    msg: kron_bus::traits::BusMessage,
) {
    let payload = msg.payload.clone();

    match pipeline.process(payload).await {
        Ok(()) => {
            if let Err(e) = consumer.commit(&msg).await {
                tracing::error!(error = %e, "Failed to commit message offset");
            }
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                topic = %msg.topic,
                offset = msg.offset,
                retry_count = msg.retry_count,
                "Pipeline failed; nacking message"
            );
            if let Err(ne) = consumer.nack(&msg, &e.to_string()).await {
                tracing::error!(error = %ne, "Failed to nack message");
            }
        }
    }
}
