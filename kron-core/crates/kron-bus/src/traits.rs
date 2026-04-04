//! Core traits and message types for the KRON message bus.
//!
//! All bus implementations ([`crate::embedded`], [`crate::redpanda`]) implement
//! [`BusProducer`] and [`BusConsumer`]. Callers depend only on these traits.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::Duration;

use crate::error::BusError;

/// A message delivered to a consumer from the bus.
///
/// The `offset` field uniquely identifies the position of this message within
/// its topic partition. Consumers must pass this struct back to
/// [`BusConsumer::commit`] or [`BusConsumer::nack`].
#[derive(Debug, Clone)]
pub struct BusMessage {
    /// Unique message identifier (UUID v4).
    pub id: String,
    /// Topic this message was received from.
    pub topic: String,
    /// Partition index. `-1` for the embedded bus (no partitions).
    pub partition: i32,
    /// Monotonic offset of this message within the topic (and partition).
    pub offset: u64,
    /// Optional routing key used for partition assignment.
    pub key: Option<Bytes>,
    /// Serialized message payload.
    pub payload: Bytes,
    /// Arbitrary key-value headers attached by the producer.
    pub headers: HashMap<String, String>,
    /// UTC timestamp at which the message was produced.
    pub timestamp: DateTime<Utc>,
    /// Number of previous delivery attempts (0 = first delivery).
    pub retry_count: u8,
}

/// A message to be sent to the bus by a producer.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// Target topic name.
    pub topic: String,
    /// Optional routing key (used for partitioning in Redpanda).
    pub key: Option<Bytes>,
    /// Serialized message payload.
    pub payload: Bytes,
    /// Arbitrary key-value metadata attached to the message.
    pub headers: HashMap<String, String>,
}

impl OutboundMessage {
    /// Creates a new outbound message with no key and no headers.
    #[must_use]
    pub fn new(topic: impl Into<String>, payload: Bytes) -> Self {
        Self {
            topic: topic.into(),
            key: None,
            payload,
            headers: HashMap::new(),
        }
    }

    /// Creates a new outbound message with a partition routing key.
    #[must_use]
    pub fn with_key(topic: impl Into<String>, key: Bytes, payload: Bytes) -> Self {
        Self {
            topic: topic.into(),
            key: Some(key),
            payload,
            headers: HashMap::new(),
        }
    }

    /// Attaches a key-value header to the message.
    #[must_use]
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

/// A bus producer that sends messages to topics.
///
/// Implementations guarantee at-least-once delivery: a successful return from
/// [`BusProducer::send`] means the message is durably written to the bus.
///
/// Implementations must be cheaply cloneable (backed by `Arc` internally) so
/// that producers can be shared across Tokio tasks.
#[async_trait]
pub trait BusProducer: Send + Sync + 'static {
    /// Sends a single message to a topic.
    ///
    /// # Returns
    /// The monotonic offset at which the message was written.
    ///
    /// # Errors
    /// - [`BusError::Backpressure`] if the consumer lag exceeds the configured threshold.
    /// - [`BusError::Connection`] if the underlying transport is unavailable.
    /// - [`BusError::Serialization`] if the payload cannot be framed.
    async fn send(
        &self,
        topic: &str,
        key: Option<Bytes>,
        payload: Bytes,
        headers: HashMap<String, String>,
    ) -> Result<u64, BusError>;

    /// Sends multiple messages in a single optimized batch.
    ///
    /// Messages sent before an error are committed (at-least-once semantics).
    ///
    /// # Returns
    /// The number of messages successfully sent.
    ///
    /// # Errors
    /// Returns the first error encountered; earlier messages are not rolled back.
    async fn send_batch(&self, messages: Vec<OutboundMessage>) -> Result<u64, BusError>;

    /// Flushes all in-flight messages and waits for delivery confirmations.
    ///
    /// # Errors
    /// Returns [`BusError::Connection`] if the bus is unreachable before `timeout`.
    async fn flush(&self, timeout: Duration) -> Result<(), BusError>;

    /// Returns `Ok(())` if the producer can reach the bus.
    ///
    /// # Errors
    /// Returns [`BusError::Connection`] if the bus is unreachable.
    async fn health_check(&self) -> Result<(), BusError>;
}

/// Blanket impl so `Arc::new(box_producer)` can coerce to `Arc<dyn BusProducer>`.
#[async_trait]
impl BusProducer for Box<dyn BusProducer> {
    async fn send(
        &self,
        topic: &str,
        key: Option<Bytes>,
        payload: Bytes,
        headers: HashMap<String, String>,
    ) -> Result<u64, BusError> {
        (**self).send(topic, key, payload, headers).await
    }

    async fn send_batch(&self, messages: Vec<OutboundMessage>) -> Result<u64, BusError> {
        (**self).send_batch(messages).await
    }

    async fn flush(&self, timeout: Duration) -> Result<(), BusError> {
        (**self).flush(timeout).await
    }

    async fn health_check(&self) -> Result<(), BusError> {
        (**self).health_check().await
    }
}

/// A bus consumer that reads messages from subscribed topics.
///
/// Consumers provide at-least-once delivery: calling [`BusConsumer::commit`]
/// persists the message offset. If the process crashes before commit, the
/// message is redelivered on next startup. Callers must call either `commit`
/// or `nack` for every message returned by [`BusConsumer::poll`].
#[async_trait]
pub trait BusConsumer: Send {
    /// Subscribes this consumer to one or more topics under a shared group ID.
    ///
    /// Messages are delivered to exactly one consumer in the group.
    ///
    /// # Errors
    /// Returns [`BusError::TopicNotFound`] if a topic does not exist.
    async fn subscribe(&mut self, topics: &[String], group_id: &str) -> Result<(), BusError>;

    /// Polls for the next available message, waiting up to `timeout`.
    ///
    /// Returns `Ok(None)` if no message arrives within `timeout`.
    ///
    /// # Errors
    /// Returns [`BusError::NotSubscribed`] if called before [`BusConsumer::subscribe`].
    async fn poll(&mut self, timeout: Duration) -> Result<Option<BusMessage>, BusError>;

    /// Commits the offset of a successfully processed message.
    ///
    /// After restart, the next [`BusConsumer::poll`] returns the message
    /// immediately following this one.
    ///
    /// # Errors
    /// Returns [`BusError::Io`] if the offset cannot be persisted to disk.
    async fn commit(&mut self, msg: &BusMessage) -> Result<(), BusError>;

    /// Signals that processing failed for a message.
    ///
    /// The message is redelivered up to `max_retry_count` times. After that,
    /// it is written to the dead letter topic and its offset is committed.
    ///
    /// # Arguments
    /// * `msg` — The message that failed processing.
    /// * `reason` — Human-readable failure description (logged and stored in the DLQ header).
    ///
    /// # Errors
    /// Returns [`BusError::Io`] if the dead letter write or offset commit fails.
    async fn nack(&mut self, msg: &BusMessage, reason: &str) -> Result<(), BusError>;

    /// Returns `Ok(())` if the consumer can reach the bus.
    ///
    /// # Errors
    /// Returns [`BusError::Connection`] if the bus is unreachable.
    async fn health_check(&self) -> Result<(), BusError>;
}
