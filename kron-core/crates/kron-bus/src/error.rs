//! Error types for the kron-bus message bus layer.

use thiserror::Error;

/// All errors that can occur in the bus layer.
#[derive(Error, Debug)]
pub enum BusError {
    /// The bus transport (Redpanda or embedded WAL) is not reachable.
    #[error("bus connection error: {0}")]
    Connection(String),

    /// A message could not be serialized before sending.
    #[error("message serialization failed: {0}")]
    Serialization(String),

    /// A received message could not be deserialized.
    #[error("message deserialization failed: {0}")]
    Deserialization(String),

    /// The requested topic does not exist or is not configured.
    #[error("topic '{0}' not found or not configured")]
    TopicNotFound(String),

    /// The producer is blocked because the consumer lag on this topic
    /// exceeds the configured backpressure threshold.
    #[error("backpressure on topic '{topic}': consumer lag {lag} exceeds threshold")]
    Backpressure {
        /// The topic that is over the lag threshold.
        topic: String,
        /// Current consumer lag in number of messages.
        lag: u64,
    },

    /// A message was moved to the dead letter topic after exhausting all retries.
    #[error(
        "message '{message_id}' on topic '{topic}' sent to dead letter after {retries} retries"
    )]
    DeadLetter {
        /// The source topic.
        topic: String,
        /// The message identifier.
        message_id: String,
        /// Number of delivery attempts made.
        retries: u8,
    },

    /// An I/O error occurred when reading or writing the WAL.
    #[error("bus I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The WAL file is corrupt or has an unexpected format.
    #[error("WAL error on topic '{topic}': {reason}")]
    Wal {
        /// Topic whose WAL is corrupt.
        topic: String,
        /// Description of the corruption.
        reason: String,
    },

    /// The consumer called `poll` or `commit` before calling `subscribe`.
    #[error("consumer is not subscribed to any topics")]
    NotSubscribed,

    /// An internal bus error not covered by the above variants.
    #[error("internal bus error: {0}")]
    Internal(String),
}
