//! `AdaptiveBus` — selects the embedded or Redpanda bus based on deployment mode.
//!
//! Call [`AdaptiveBus::new_producer`] and [`AdaptiveBus::new_consumer`] at service
//! startup to get the correct implementation for the configured deployment tier.
//!
//! - [`DeploymentMode::Nano`] → embedded WAL bus (always available)
//! - [`DeploymentMode::Standard`] / [`DeploymentMode::Enterprise`] → Redpanda
//!   (requires the `redpanda` feature flag at compile time)

use std::sync::Arc;

use kron_types::{DeploymentMode, KronConfig};
use tracing::instrument;

use crate::embedded::{EmbeddedBusConsumer, EmbeddedBusProducer, EmbeddedBusState};
use crate::error::BusError;
use crate::traits::{BusConsumer, BusProducer};

#[cfg(feature = "redpanda")]
use crate::redpanda::{RedpandaConsumer, RedpandaProducer};

/// Factory that creates bus producers and consumers from [`KronConfig`].
///
/// In Nano mode, all calls share the same [`EmbeddedBusState`] so all producers
/// and consumers see the same WAL files.
///
/// In Standard/Enterprise mode, Redpanda is used if the `redpanda` feature is
/// compiled in; otherwise [`BusError::Internal`] is returned with a clear message.
pub struct AdaptiveBus {
    /// Shared embedded bus state. Only populated in Nano mode.
    embedded_state: Option<Arc<EmbeddedBusState>>,
    /// A copy of the config for creating Redpanda clients.
    config: KronConfig,
}

impl AdaptiveBus {
    /// Creates a new `AdaptiveBus` from `config`.
    ///
    /// In Nano mode, initialises the [`EmbeddedBusState`] (creates `data_dir` if needed).
    ///
    /// # Errors
    /// Returns [`BusError::Io`] if the embedded bus `data_dir` cannot be created.
    #[instrument(skip(config))]
    pub fn new(config: KronConfig) -> Result<Self, BusError> {
        let embedded_state = match config.mode {
            DeploymentMode::Nano => {
                tracing::info!("Bus: Nano mode — using embedded WAL bus");
                Some(EmbeddedBusState::new(config.embedded_bus.clone())?)
            }
            DeploymentMode::Standard | DeploymentMode::Enterprise => {
                tracing::info!(
                    brokers = ?config.redpanda.brokers,
                    "Bus: Standard/Enterprise mode — using Redpanda"
                );
                None
            }
        };

        Ok(Self {
            embedded_state,
            config,
        })
    }

    /// Creates a new producer for the configured deployment tier.
    ///
    /// Producers are cheaply cloneable — call this once and clone the result.
    ///
    /// # Errors
    /// - [`BusError::Connection`] if a Redpanda producer cannot be created.
    /// - [`BusError::Internal`] if Redpanda mode is configured but the
    ///   `redpanda` feature was not compiled in.
    pub fn new_producer(&self) -> Result<Box<dyn BusProducer>, BusError> {
        match self.config.mode {
            DeploymentMode::Nano => {
                let state = self.embedded_state.as_ref().ok_or_else(|| {
                    BusError::Internal("embedded state missing in Nano mode".to_owned())
                })?;
                Ok(Box::new(EmbeddedBusProducer::new(Arc::clone(state))))
            }
            DeploymentMode::Standard | DeploymentMode::Enterprise => self.new_redpanda_producer(),
        }
    }

    /// Creates a new consumer for the configured deployment tier.
    ///
    /// # Arguments
    /// * `service_name` — Appended to the consumer group ID for identification.
    ///
    /// # Errors
    /// - [`BusError::Connection`] if a Redpanda consumer cannot be created.
    /// - [`BusError::Internal`] if Redpanda mode is configured but the
    ///   `redpanda` feature was not compiled in.
    pub fn new_consumer(&self, service_name: &str) -> Result<Box<dyn BusConsumer>, BusError> {
        match self.config.mode {
            DeploymentMode::Nano => {
                let state = self.embedded_state.as_ref().ok_or_else(|| {
                    BusError::Internal("embedded state missing in Nano mode".to_owned())
                })?;
                Ok(Box::new(EmbeddedBusConsumer::new(Arc::clone(state))))
            }
            DeploymentMode::Standard | DeploymentMode::Enterprise => {
                self.new_redpanda_consumer(service_name)
            }
        }
    }

    /// Creates a Redpanda producer when the `redpanda` feature is enabled.
    #[cfg(feature = "redpanda")]
    fn new_redpanda_producer(&self) -> Result<Box<dyn BusProducer>, BusError> {
        let producer = RedpandaProducer::from_config(&self.config.redpanda)?;
        Ok(Box::new(producer))
    }

    /// Returns an error when Redpanda support was not compiled in.
    #[cfg(not(feature = "redpanda"))]
    #[allow(clippy::unused_self)]
    fn new_redpanda_producer(&self) -> Result<Box<dyn BusProducer>, BusError> {
        Err(BusError::Internal(
            "Redpanda support is not compiled in. \
             Rebuild kron-bus with `--features redpanda` or switch to Nano mode."
                .to_owned(),
        ))
    }

    /// Creates a Redpanda consumer when the `redpanda` feature is enabled.
    #[cfg(feature = "redpanda")]
    fn new_redpanda_consumer(&self, service_name: &str) -> Result<Box<dyn BusConsumer>, BusError> {
        let dlq_producer =
            Arc::new(RedpandaProducer::from_config(&self.config.redpanda)?) as Arc<dyn BusProducer>;
        let consumer = RedpandaConsumer::new(&self.config.redpanda, dlq_producer).map_err(|e| {
            BusError::Connection(format!(
                "failed to create Redpanda consumer for '{service_name}': {e}"
            ))
        })?;
        Ok(Box::new(consumer))
    }

    /// Returns an error when Redpanda support was not compiled in.
    #[cfg(not(feature = "redpanda"))]
    #[allow(clippy::unused_self)]
    fn new_redpanda_consumer(&self, _service_name: &str) -> Result<Box<dyn BusConsumer>, BusError> {
        Err(BusError::Internal(
            "Redpanda support is not compiled in. \
             Rebuild kron-bus with `--features redpanda` or switch to Nano mode."
                .to_owned(),
        ))
    }
}
