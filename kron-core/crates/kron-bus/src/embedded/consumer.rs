//! Embedded bus consumer for Nano-tier deployments.
//!
//! Reads from per-topic WAL files, commits offsets atomically to disk,
//! and implements at-most-3-retry semantics with dead-letter routing.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::instrument;

use super::state::EmbeddedBusState;
use crate::error::BusError;
use crate::metrics;
use crate::topics;
use crate::traits::{BusConsumer, BusMessage};

/// Maximum delivery attempts before routing to the dead letter topic.
const MAX_RETRIES: u8 = 3;

/// Tracks a message that has been delivered but not yet committed or nacked.
struct InFlightMessage {
    topic: String,
    offset: u64,
    retry_count: u8,
}

/// Embedded bus consumer backed by WAL files.
pub struct EmbeddedBusConsumer {
    state: Arc<EmbeddedBusState>,
    group_id: String,
    /// Topics this consumer is subscribed to.
    subscribed: Vec<String>,
    /// Current read offset per topic (next offset to poll from).
    read_offsets: HashMap<String, u64>,
    /// Messages ready for immediate redelivery (after nack, before DLQ).
    retry_queue: VecDeque<BusMessage>,
    /// Messages currently in-flight (polled but not committed/nacked).
    in_flight: HashMap<String, InFlightMessage>,
    /// Retry count per message ID.
    retry_counts: HashMap<String, u8>,
}

impl EmbeddedBusConsumer {
    /// Creates a new consumer backed by `state`.
    #[must_use]
    pub fn new(state: Arc<EmbeddedBusState>) -> Self {
        Self {
            state,
            group_id: String::new(),
            subscribed: Vec::new(),
            read_offsets: HashMap::new(),
            retry_queue: VecDeque::new(),
            in_flight: HashMap::new(),
            retry_counts: HashMap::new(),
        }
    }

    /// Attempts to read the next message from any subscribed topic.
    ///
    /// Iterates topics in order and returns the first available message.
    /// Updates the in-memory read position for the topic that had a message.
    async fn try_read_next(&mut self) -> Result<Option<BusMessage>, BusError> {
        let topics = self.subscribed.clone();

        for topic in &topics {
            let next_offset = self.read_offsets.get(topic).copied().unwrap_or(0);

            let state = self.state.clone();
            let topic_clone = topic.clone();

            let result = tokio::task::spawn_blocking(move || {
                let mut registry = state
                    .topics
                    .lock()
                    .map_err(|e| BusError::Internal(format!("topics lock poisoned: {e}")))?;
                let entry = registry.get_or_create(&topic_clone, &state.config.data_dir)?;
                let msg = entry.wal.read_at_offset(&topic_clone, next_offset)?;
                Ok::<Option<BusMessage>, BusError>(msg)
            })
            .await
            .map_err(|e| BusError::Internal(format!("spawn_blocking panicked: {e}")))??;

            if let Some(mut msg) = result {
                msg.retry_count = 0;
                let offset = msg.offset;

                self.read_offsets.insert(topic.clone(), offset + 1);
                self.in_flight.insert(
                    msg.id.clone(),
                    InFlightMessage {
                        topic: topic.clone(),
                        offset,
                        retry_count: 0,
                    },
                );

                metrics::record_message_received(topic, &self.group_id);

                return Ok(Some(msg));
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl BusConsumer for EmbeddedBusConsumer {
    #[instrument(skip(self), fields(group_id = %group_id, topic_count = topics.len()))]
    async fn subscribe(&mut self, topics: &[String], group_id: &str) -> Result<(), BusError> {
        group_id.clone_into(&mut self.group_id);
        self.subscribed = topics.to_vec();

        // Restore committed read offsets from WAL state.
        let state = self.state.clone();
        let group = group_id.to_owned();
        let topic_list = topics.to_vec();

        let offsets = tokio::task::spawn_blocking(move || {
            let mut registry = state
                .topics
                .lock()
                .map_err(|e| BusError::Internal(format!("topics lock poisoned: {e}")))?;
            let mut offsets = HashMap::new();
            for topic in &topic_list {
                let entry = registry.get_or_create(topic, &state.config.data_dir)?;
                offsets.insert(topic.clone(), entry.committed_offset(&group));
            }
            Ok::<HashMap<String, u64>, BusError>(offsets)
        })
        .await
        .map_err(|e| BusError::Internal(format!("spawn_blocking panicked: {e}")))??;

        self.read_offsets = offsets;
        tracing::info!(
            group_id = %self.group_id,
            topics = ?self.subscribed,
            "Consumer subscribed"
        );
        Ok(())
    }

    #[instrument(skip(self), fields(group_id = %self.group_id))]
    async fn poll(&mut self, timeout: Duration) -> Result<Option<BusMessage>, BusError> {
        if self.subscribed.is_empty() {
            return Err(BusError::NotSubscribed);
        }

        // Drain retry queue first.
        if let Some(msg) = self.retry_queue.pop_front() {
            let retry_count = self.retry_counts.get(&msg.id).copied().unwrap_or(0);
            let mut msg = msg;
            msg.retry_count = retry_count;
            self.in_flight.insert(
                msg.id.clone(),
                InFlightMessage {
                    topic: msg.topic.clone(),
                    offset: msg.offset,
                    retry_count,
                },
            );
            metrics::record_message_received(&msg.topic, &self.group_id);
            return Ok(Some(msg));
        }

        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Try to read the next message from any subscribed topic.
            if let Some(msg) = self.try_read_next().await? {
                return Ok(Some(msg));
            }

            // No message available — wait for a notification or timeout.
            let notify = self.state.notify.clone();
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }

            tokio::select! {
                () = notify.notified() => {
                    // New messages may be available — loop and retry.
                }
                () = tokio::time::sleep(remaining) => {
                    return Ok(None);
                }
            }
        }
    }

    #[instrument(skip(self, msg), fields(group_id = %self.group_id, topic = %msg.topic, offset = msg.offset))]
    async fn commit(&mut self, msg: &BusMessage) -> Result<(), BusError> {
        if let Some(tracked) = self.in_flight.remove(&msg.id) {
            tracing::trace!(
                group_id = %self.group_id,
                topic = %tracked.topic,
                offset = tracked.offset,
                retries = tracked.retry_count,
                "Removing message from in-flight tracking"
            );
        }
        self.retry_counts.remove(&msg.id);

        let state = self.state.clone();
        let group = self.group_id.clone();
        let topic = msg.topic.clone();
        let offset = msg.offset;

        tokio::task::spawn_blocking(move || {
            let mut registry = state
                .topics
                .lock()
                .map_err(|e| BusError::Internal(format!("topics lock poisoned: {e}")))?;
            let entry = registry.get_mut(&topic)?;
            entry.commit(&group, offset);

            let lag = entry
                .wal
                .next_offset()
                .saturating_sub(entry.committed_offset(&group));
            metrics::set_consumer_lag(&topic, &group, lag);
            metrics::record_commit(&topic, &group);

            Ok::<(), BusError>(())
        })
        .await
        .map_err(|e| BusError::Internal(format!("spawn_blocking panicked: {e}")))??;

        tracing::debug!(
            group_id = %self.group_id,
            topic = %msg.topic,
            offset = msg.offset,
            "Offset committed"
        );
        Ok(())
    }

    #[instrument(skip(self, msg), fields(group_id = %self.group_id, topic = %msg.topic, offset = msg.offset))]
    async fn nack(&mut self, msg: &BusMessage, reason: &str) -> Result<(), BusError> {
        self.in_flight.remove(&msg.id);

        let retry_count = self.retry_counts.entry(msg.id.clone()).or_insert(0);
        *retry_count += 1;
        let retries = *retry_count;

        metrics::record_nack(&msg.topic, &self.group_id);

        tracing::warn!(
            group_id = %self.group_id,
            topic = %msg.topic,
            offset = msg.offset,
            retries,
            reason,
            "Message nacked"
        );

        if retries >= MAX_RETRIES {
            // Move to dead letter.
            let dlq_topic = topics::dead_letter_for(&msg.topic);
            let mut dlq_headers = msg.headers.clone();
            dlq_headers.insert("kron.dlq.source_topic".to_owned(), msg.topic.clone());
            dlq_headers.insert("kron.dlq.reason".to_owned(), reason.to_owned());
            dlq_headers.insert("kron.dlq.retries".to_owned(), retries.to_string());
            dlq_headers.insert("kron.dlq.original_id".to_owned(), msg.id.clone());

            let state = self.state.clone();
            let dlq_payload = msg.payload.clone();
            let dlq_key = msg.key.clone();
            let sync = state.config.sync_writes;
            let msg_id = uuid::Uuid::new_v4().to_string();

            tokio::task::spawn_blocking(move || {
                let mut registry = state
                    .topics
                    .lock()
                    .map_err(|e| BusError::Internal(format!("topics lock poisoned: {e}")))?;
                let entry = registry.get_or_create(&dlq_topic, &state.config.data_dir)?;
                entry.wal.append(
                    &msg_id,
                    dlq_key.as_deref(),
                    &dlq_headers,
                    &dlq_payload,
                    sync,
                )?;
                Ok::<(), BusError>(())
            })
            .await
            .map_err(|e| BusError::Internal(format!("spawn_blocking panicked: {e}")))??;

            // Commit the original message so it isn't redelivered.
            self.commit(msg).await?;
            self.retry_counts.remove(&msg.id);
            metrics::record_dead_letter(&msg.topic);

            tracing::error!(
                group_id = %self.group_id,
                topic = %msg.topic,
                offset = msg.offset,
                retries,
                "Message moved to dead letter queue"
            );
        } else {
            // Put back in retry queue for redelivery.
            let mut retry_msg = msg.clone();
            retry_msg.retry_count = retries;
            self.retry_queue.push_back(retry_msg);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), BusError> {
        if !self.state.config.data_dir.exists() {
            return Err(BusError::Connection(format!(
                "embedded bus data_dir does not exist: {}",
                self.state.config.data_dir.display()
            )));
        }
        Ok(())
    }
}
