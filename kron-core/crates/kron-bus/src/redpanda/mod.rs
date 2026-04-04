//! Redpanda/Kafka bus implementation for Standard and Enterprise tiers.
//!
//! Uses `rdkafka` with the `cmake-build` feature for cross-platform compilation.

pub mod consumer;
pub mod producer;

pub use consumer::RedpandaConsumer;
pub use producer::RedpandaProducer;
