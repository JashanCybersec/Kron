//! Redpanda/Kafka producer for Standard and Enterprise-tier KRON deployments.
//!
//! Wraps `rdkafka::producer::FutureProducer` for async, at-least-once delivery.
//! Delivery is confirmed by waiting on the delivery report future before returning.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use tracing::instrument;

use crate::error::BusError;
use crate::metrics;
use crate::traits::{BusProducer, OutboundMessage};

/// Redpanda producer for Standard and Enterprise tiers.
///
/// Internally uses `FutureProducer` for async delivery confirmation.
/// Each `send` waits for the broker acknowledgement before returning,
/// giving at-least-once delivery guarantees.
///
/// Cheaply cloneable — `FutureProducer` is internally `Arc`-backed.
#[derive(Clone)]
pub struct RedpandaProducer {
    inner: FutureProducer,
    /// Queue full timeout: how long to wait when the producer queue is full.
    enqueue_timeout: Duration,
}

impl RedpandaProducer {
    /// Creates a new Redpanda producer connecting to `brokers`.
    ///
    /// # Arguments
    /// * `brokers` — Comma-separated list of `host:port` broker addresses.
    /// * `enqueue_timeout` — How long to wait when the internal queue is full.
    ///
    /// # Errors
    /// Returns [`BusError::Connection`] if the producer cannot be created.
    pub fn new(brokers: &str, enqueue_timeout: Duration) -> Result<Self, BusError> {
        let inner: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("message.timeout.ms", "10000")
            .set("queue.buffering.max.messages", "1000000")
            .set("queue.buffering.max.ms", "5")
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .create()
            .map_err(|e| {
                BusError::Connection(format!("failed to create Redpanda producer: {e}"))
            })?;

        tracing::info!(brokers, "Redpanda producer created");

        Ok(Self {
            inner,
            enqueue_timeout,
        })
    }

    /// Creates a producer from a [`kron_types::RedpandaConfig`].
    ///
    /// # Errors
    /// Returns [`BusError::Connection`] if the producer cannot be created.
    pub fn from_config(config: &kron_types::RedpandaConfig) -> Result<Self, BusError> {
        let brokers = config.brokers.join(",");
        let enqueue_timeout = config.batch_timeout();
        Self::new(&brokers, enqueue_timeout)
    }
}

#[async_trait]
impl BusProducer for RedpandaProducer {
    #[instrument(skip(self, payload, headers), fields(topic, payload_bytes = payload.len()))]
    async fn send(
        &self,
        topic: &str,
        key: Option<Bytes>,
        payload: Bytes,
        headers: HashMap<String, String>,
    ) -> Result<u64, BusError> {
        let start = std::time::Instant::now();

        // Build rdkafka headers.
        let mut rdk_headers = rdkafka::message::OwnedHeaders::new();
        for (k, v) in &headers {
            rdk_headers = rdk_headers.insert(rdkafka::message::Header {
                key: k.as_str(),
                value: Some(v.as_bytes()),
            });
        }

        let record = FutureRecord::to(topic)
            .payload(payload.as_ref())
            .headers(rdk_headers);

        let record = if let Some(ref key) = key {
            record.key(key.as_ref())
        } else {
            record
        };

        let (partition, offset) = self
            .inner
            .send(record, Timeout::After(self.enqueue_timeout))
            .await
            .map_err(|(e, _msg)| {
                BusError::Connection(format!("Redpanda send failed on topic '{topic}': {e}"))
            })?;

        let offset = offset as u64;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        metrics::record_message_sent(topic);
        metrics::record_send_latency_ms(topic, elapsed_ms);

        tracing::debug!(
            topic,
            partition,
            offset,
            elapsed_ms,
            "Message sent to Redpanda"
        );
        Ok(offset)
    }

    #[instrument(skip(self, messages), fields(count = messages.len()))]
    async fn send_batch(&self, messages: Vec<OutboundMessage>) -> Result<u64, BusError> {
        let mut sent: u64 = 0;

        for msg in &messages {
            self.send(
                &msg.topic,
                msg.key.clone(),
                msg.payload.clone(),
                msg.headers.clone(),
            )
            .await?;
            sent += 1;
        }

        tracing::debug!(sent, "Batch sent to Redpanda");
        Ok(sent)
    }

    #[instrument(skip(self))]
    async fn flush(&self, timeout: Duration) -> Result<(), BusError> {
        self.inner
            .flush(Timeout::After(timeout))
            .map_err(|e| BusError::Connection(format!("Redpanda flush failed: {e}")))?;
        tracing::debug!("Redpanda producer flushed");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> Result<(), BusError> {
        // Fetch metadata from the broker. A successful response means the broker is reachable.
        self.inner
            .client()
            .fetch_metadata(None, Duration::from_secs(5))
            .map_err(|e| BusError::Connection(format!("Redpanda health check failed: {e}")))?;
        Ok(())
    }
}
