//! `kron-bus` — Message bus abstraction for the KRON SIEM platform.
//!
//! Abstracts Redpanda (Standard/Enterprise tiers) and an embedded disk-backed
//! WAL channel (Nano tier) behind the [`BusProducer`] and [`BusConsumer`] traits.
//!
//! # Feature flags
//!
//! | Feature | Description |
//! |---|---|
//! | `redpanda` | Enables the Redpanda/Kafka backend (requires cmake + libssl) |
//!
//! The `redpanda` feature is disabled by default to allow building on Windows
//! developer machines. CI and production Linux builds enable it explicitly.
//!
//! # Delivery guarantee
//!
//! At-least-once delivery. Consumers commit offsets only after successful
//! processing. Failed messages retry up to `max_retry_count` times, then
//! go to a `kron.deadletter.{source_topic}` dead letter topic.
//!
//! # Topics
//!
//! | Topic pattern | Producer | Consumer |
//! |---|---|---|
//! | `kron.raw.{tenant_id}` | kron-collector | kron-normalizer |
//! | `kron.enriched.{tenant_id}` | kron-normalizer | kron-stream |
//! | `kron.alerts.{tenant_id}` | kron-stream | kron-alert |
//! | `kron.audit` | all services | kron-compliance |
//! | `kron.deadletter.*` | kron-bus (internal) | kron-ctl / monitoring |

pub mod adaptive;
pub mod embedded;
pub mod error;
pub mod metrics;
pub mod topics;
pub mod traits;

/// Redpanda/Kafka bus implementation (Standard/Enterprise tiers).
///
/// Requires the `redpanda` feature flag. Not compiled on Windows dev machines.
#[cfg(feature = "redpanda")]
pub mod redpanda;

pub use adaptive::AdaptiveBus;
pub use error::BusError;
pub use traits::{BusConsumer, BusMessage, BusProducer, OutboundMessage};
