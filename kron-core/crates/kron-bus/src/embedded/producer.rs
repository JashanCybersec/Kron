//! Embedded bus producer for Nano-tier deployments.
//!
//! Writes messages directly to the per-topic WAL under `data_dir`.
//! A [`tokio::sync::Notify`] shared with consumers is signalled after each
//! successful write so consumers wake up without polling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::instrument;
use uuid::Uuid;

use super::state::EmbeddedBusState;
use crate::error::BusError;
use crate::metrics;
use crate::traits::{BusProducer, OutboundMessage};

/// Embedded bus producer backed by a WAL file per topic.
///
/// Cheaply cloneable — all clones share the same [`EmbeddedBusState`].
#[derive(Clone)]
pub struct EmbeddedBusProducer {
    state: Arc<EmbeddedBusState>,
}

impl EmbeddedBusProducer {
    /// Creates a new producer backed by `state`.
    #[must_use]
    pub fn new(state: Arc<EmbeddedBusState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl BusProducer for EmbeddedBusProducer {
    #[instrument(skip(self, payload, headers), fields(topic, payload_bytes = payload.len()))]
    async fn send(
        &self,
        topic: &str,
        key: Option<Bytes>,
        payload: Bytes,
        headers: HashMap<String, String>,
    ) -> Result<u64, BusError> {
        let start = std::time::Instant::now();
        let state = self.state.clone();
        let topic_owned = topic.to_owned();
        let msg_id = Uuid::new_v4().to_string();
        let sync = state.config.sync_writes;

        let offset = tokio::task::spawn_blocking(move || {
            let mut topics = state
                .topics
                .lock()
                .map_err(|e| BusError::Internal(format!("topics lock poisoned: {e}")))?;

            let entry = topics.get_or_create(&topic_owned, &state.config.data_dir)?;

            // Backpressure check.
            let lag = entry
                .wal
                .next_offset()
                .saturating_sub(entry.min_committed_offset());
            if lag > state.config.backpressure_lag_threshold {
                return Err(BusError::Backpressure {
                    topic: topic_owned.clone(),
                    lag,
                });
            }

            let offset = entry
                .wal
                .append(&msg_id, key.as_deref(), &headers, &payload, sync)?;

            Ok::<u64, BusError>(offset)
        })
        .await
        .map_err(|e| BusError::Internal(format!("spawn_blocking panicked: {e}")))??;

        // Wake consumers waiting for this topic.
        self.state.notify_all();

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let metrics_label = self.state.topic_name_for_metrics(topic);
        metrics::record_message_sent(metrics_label);
        metrics::record_send_latency_ms(metrics_label, elapsed_ms);

        tracing::debug!(topic = %topic, offset, elapsed_ms, "Message sent to embedded bus");
        Ok(offset)
    }

    #[instrument(skip(self, messages), fields(count = messages.len()))]
    async fn send_batch(&self, messages: Vec<OutboundMessage>) -> Result<u64, BusError> {
        let state = self.state.clone();
        let sync = state.config.sync_writes;
        let count = messages.len() as u64;

        // Collect per-topic counts before moving `messages` into the blocking task.
        let mut per_topic: HashMap<String, u64> = HashMap::new();
        for msg in &messages {
            *per_topic.entry(msg.topic.clone()).or_default() += 1;
        }

        tokio::task::spawn_blocking(move || {
            let mut topics = state
                .topics
                .lock()
                .map_err(|e| BusError::Internal(format!("topics lock poisoned: {e}")))?;

            for msg in &messages {
                let msg_id = Uuid::new_v4().to_string();
                let entry = topics.get_or_create(&msg.topic, &state.config.data_dir)?;

                entry.wal.append(
                    &msg_id,
                    msg.key.as_deref(),
                    &msg.headers,
                    &msg.payload,
                    sync,
                )?;
            }

            Ok::<(), BusError>(())
        })
        .await
        .map_err(|e| BusError::Internal(format!("spawn_blocking panicked: {e}")))??;

        self.state.notify_all();

        for (topic, n) in &per_topic {
            metrics::record_batch_sent(topic, *n);
        }

        tracing::debug!(count, "Batch sent to embedded bus");
        Ok(count)
    }

    #[instrument(skip(self))]
    async fn flush(&self, _timeout: Duration) -> Result<(), BusError> {
        // WAL is flushed synchronously on each write (BufWriter::flush).
        // If sync_writes=true, fdatasync is also called. Nothing to flush here.
        tracing::trace!("Embedded bus flush: no-op (writes are synchronous)");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), BusError> {
        // Verify data_dir is writable.
        let data_dir = self.state.config.data_dir.clone();
        tokio::task::spawn_blocking(move || {
            let test_path = data_dir.join(".health");
            std::fs::write(&test_path, b"ok").map_err(|e| {
                BusError::Connection(format!("embedded bus data_dir not writable: {e}"))
            })?;
            std::fs::remove_file(&test_path)
                .map_err(|e| BusError::Connection(format!("embedded bus cleanup failed: {e}")))?;
            Ok::<(), BusError>(())
        })
        .await
        .map_err(|e| BusError::Internal(format!("spawn_blocking panicked: {e}")))?
    }
}
