//! Embedded disk-backed message bus for Nano-tier KRON deployments.
//!
//! Uses one write-ahead log (WAL) file per topic for durable message storage.
//! All reads and writes go through `tokio::task::spawn_blocking` so the Tokio
//! runtime is never blocked.
//!
//! # Usage
//!
//! ```no_run
//! use std::sync::Arc;
//! use kron_types::EmbeddedBusConfig;
//! use kron_bus::embedded::{EmbeddedBusProducer, EmbeddedBusConsumer};
//! use kron_bus::embedded::state::EmbeddedBusState;
//!
//! let config = EmbeddedBusConfig::default();
//! let state = EmbeddedBusState::new(config).expect("state");
//! let producer = EmbeddedBusProducer::new(Arc::clone(&state));
//! let consumer = EmbeddedBusConsumer::new(Arc::clone(&state));
//! ```

pub mod consumer;
pub mod producer;
pub mod state;
pub mod wal;

pub use consumer::EmbeddedBusConsumer;
pub use producer::EmbeddedBusProducer;
pub use state::EmbeddedBusState;
