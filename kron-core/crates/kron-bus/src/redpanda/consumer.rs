//! Redpanda/Kafka consumer for Standard and Enterprise-tier KRON deployments.
//!
//! Wraps `rdkafka::consumer::StreamConsumer` for async, at-least-once delivery.
//! Offsets are committed only after the caller calls [`BusConsumer::commit`].
//! Nacked messages go through an in-process retry queue before the DLQ.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::{Headers, Message};
use tracing::instrument;
use uuid::Uuid;

use crate::error::BusError;
use crate::metrics;
use crate::topics;
use crate::traits::{BusConsumer, BusMessage, BusProducer};

/// Redpanda consumer for Standard and Enterprise tiers.
///
/// Wraps [`StreamConsumer`] with explicit at-least-once offset commit semantics.
pub struct RedpandaConsumer {
    inner: Option<StreamConsumer>,
    /// Broker addresses (needed to construct the consumer on subscribe).
    brokers: String,
    /// Configured consumer group prefix.
    group_id_prefix: String,
    /// Fully-qualified group ID (set after subscribe).
    group_id: String,
    /// Maximum delivery retries before DLQ.
    max_retry_count: u8,
    /// Producer used to write to DLQ topics.
    dlq_producer: Arc<dyn BusProducer>,
    /// Retry queue for messages that failed but have retries remaining.
    retry_queue: VecDeque<BusMessage>,
    /// Per message ID retry counts.
    retry_counts: HashMap<String, u8>,
}

impl RedpandaConsumer {
    /// Creates a new Redpanda consumer.
    ///
    /// # Arguments
    /// * `config` — Redpanda connection configuration.
    /// * `dlq_producer` — Producer used to route dead-lettered messages.
    ///
    /// # Errors
    /// Returns [`BusError::Connection`] if the client configuration is invalid.
    pub fn new(
        config: &kron_types::RedpandaConfig,
        dlq_producer: Arc<dyn BusProducer>,
    ) -> Result<Self, BusError> {
        Ok(Self {
            inner: None,
            brokers: config.brokers.join(","),
            group_id_prefix: config.group_id_prefix.clone(),
            group_id: String::new(),
            max_retry_count: 3,
            dlq_producer,
            retry_queue: VecDeque::new(),
            retry_counts: HashMap::new(),
        })
    }
}

#[async_trait]
impl BusConsumer for RedpandaConsumer {
    #[instrument(skip(self), fields(group_id = %group_id, topic_count = topics.len()))]
    async fn subscribe(&mut self, topics: &[String], group_id: &str) -> Result<(), BusError> {
        let full_group_id = format!("{}.{}", self.group_id_prefix, group_id);

        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &self.brokers)
            .set("group.id", &full_group_id)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("session.timeout.ms", "30000")
            .set("max.poll.interval.ms", "300000")
            .create()
            .map_err(|e| {
                BusError::Connection(format!("failed to create Redpanda consumer: {e}"))
            })?;

        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        consumer
            .subscribe(&topic_refs)
            .map_err(|e| BusError::Connection(format!("Redpanda subscribe failed: {e}")))?;

        self.inner = Some(consumer);
        self.group_id = full_group_id;

        tracing::info!(group_id = %self.group_id, topics = ?topics, "Redpanda consumer subscribed");
        Ok(())
    }

    #[instrument(skip(self), fields(group_id = %self.group_id))]
    async fn poll(&mut self, timeout: Duration) -> Result<Option<BusMessage>, BusError> {
        let consumer = self.inner.as_ref().ok_or(BusError::NotSubscribed)?;

        // Drain retry queue first.
        if let Some(msg) = self.retry_queue.pop_front() {
            return Ok(Some(msg));
        }

        let msg = tokio::time::timeout(timeout, async { consumer.recv().await }).await;

        match msg {
            Err(_elapsed) => Ok(None),
            Ok(Err(e)) => Err(BusError::Connection(format!("Redpanda recv error: {e}"))),
            Ok(Ok(rdk_msg)) => {
                let topic = rdk_msg.topic().to_owned();
                let partition = rdk_msg.partition();
                let offset = rdk_msg.offset().max(0) as u64;

                let payload = Bytes::copy_from_slice(rdk_msg.payload().unwrap_or(&[]));
                let key = rdk_msg.key().map(Bytes::copy_from_slice);

                let mut headers = HashMap::new();
                if let Some(h) = rdk_msg.headers() {
                    for header in h.iter() {
                        if let Some(val) = header.value {
                            if let Ok(v) = std::str::from_utf8(val) {
                                headers.insert(header.key.to_owned(), v.to_owned());
                            }
                        }
                    }
                }

                let timestamp = rdk_msg
                    .timestamp()
                    .to_millis()
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .unwrap_or_else(chrono::Utc::now);

                let msg = BusMessage {
                    id: Uuid::new_v4().to_string(),
                    topic: topic.clone(),
                    partition,
                    offset,
                    key,
                    payload,
                    headers,
                    timestamp,
                    retry_count: 0,
                };

                metrics::record_message_received(&topic, &self.group_id);
                Ok(Some(msg))
            }
        }
    }

    #[instrument(skip(self, msg), fields(group_id = %self.group_id, topic = %msg.topic, offset = msg.offset))]
    async fn commit(&mut self, msg: &BusMessage) -> Result<(), BusError> {
        let consumer = self.inner.as_ref().ok_or(BusError::NotSubscribed)?;

        let mut tpl = rdkafka::TopicPartitionList::new();
        tpl.add_partition_offset(
            &msg.topic,
            msg.partition,
            rdkafka::Offset::Offset(msg.offset as i64 + 1),
        )
        .map_err(|e| BusError::Internal(format!("failed to build topic partition list: {e}")))?;

        consumer
            .commit(&tpl, CommitMode::Sync)
            .map_err(|e| BusError::Connection(format!("Redpanda commit failed: {e}")))?;

        self.retry_counts.remove(&msg.id);
        metrics::record_commit(&msg.topic, &self.group_id);

        tracing::debug!(
            group_id = %self.group_id,
            topic = %msg.topic,
            offset = msg.offset,
            "Redpanda offset committed"
        );
        Ok(())
    }

    #[instrument(skip(self, msg), fields(group_id = %self.group_id, topic = %msg.topic, offset = msg.offset))]
    async fn nack(&mut self, msg: &BusMessage, reason: &str) -> Result<(), BusError> {
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
            "Redpanda message nacked"
        );

        if retries >= self.max_retry_count {
            let dlq_topic = topics::dead_letter_for(&msg.topic);
            let mut dlq_headers = msg.headers.clone();
            dlq_headers.insert("kron.dlq.source_topic".to_owned(), msg.topic.clone());
            dlq_headers.insert("kron.dlq.reason".to_owned(), reason.to_owned());
            dlq_headers.insert("kron.dlq.retries".to_owned(), retries.to_string());
            dlq_headers.insert("kron.dlq.original_id".to_owned(), msg.id.clone());

            self.dlq_producer
                .send(
                    &dlq_topic,
                    msg.key.clone(),
                    msg.payload.clone(),
                    dlq_headers,
                )
                .await
                .map_err(|e| {
                    BusError::Internal(format!("failed to write to DLQ '{dlq_topic}': {e}"))
                })?;

            self.commit(msg).await?;
            self.retry_counts.remove(&msg.id);
            metrics::record_dead_letter(&msg.topic);

            tracing::error!(
                group_id = %self.group_id,
                topic = %msg.topic,
                offset = msg.offset,
                retries,
                "Redpanda message moved to dead letter queue"
            );
        } else {
            let mut retry_msg = msg.clone();
            retry_msg.retry_count = retries;
            self.retry_queue.push_back(retry_msg);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), BusError> {
        let consumer = self.inner.as_ref().ok_or(BusError::NotSubscribed)?;

        consumer
            .client()
            .fetch_metadata(None, Duration::from_secs(5))
            .map_err(|e| BusError::Connection(format!("Redpanda health check failed: {e}")))?;
        Ok(())
    }
}
