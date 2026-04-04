//! `kron-normalizer` library — event normalization for the KRON SIEM platform.
//!
//! Exposes the normalizer service as a library so that `kron-nano` can
//! embed it in a single-binary deployment.  The `kron-normalizer` binary
//! remains the standalone Standard/Enterprise entrypoint.
//!
//! # Entry point
//!
//! Call [`run`] with a loaded [`KronConfig`] and a [`ShutdownHandle`] obtained
//! from [`ShutdownHandle::new`]. The function returns when shutdown is signalled
//! or a fatal error occurs.

pub mod dedup;
pub mod enrich;
pub mod error;
pub mod metrics;
pub mod normalizer;
pub mod parser;
pub mod pipeline;
pub mod shutdown;
pub mod timestamp;

pub use error::NormalizerError;
pub use shutdown::ShutdownHandle;

use std::sync::Arc;

use kron_bus::adaptive::AdaptiveBus;
use kron_storage::AdaptiveStorage;
use kron_types::KronConfig;

use crate::enrich::asset::AssetCache;
use crate::enrich::geoip::GeoIpLookup;
use crate::enrich::Enricher;
use crate::normalizer::Normalizer;
use crate::pipeline::Pipeline;

/// Runs the normalizer service until the given shutdown handle fires.
///
/// Builds all subsystems (GeoIP, asset cache, storage, bus, pipeline) and
/// runs the consumer loop.
///
/// # Errors
///
/// Returns [`NormalizerError`] if any subsystem fails to initialise or if
/// the consumer loop exits with a fatal error.
pub async fn run(config: KronConfig, shutdown: ShutdownHandle) -> Result<(), NormalizerError> {
    let cfg = &config.normalizer;

    // Optional Prometheus metrics exporter.
    start_metrics_exporter(&cfg.metrics_addr)?;

    // GeoIP enrichment (graceful if MMDB absent).
    let geoip = GeoIpLookup::open(&cfg.geoip_db_path).map_err(NormalizerError::GeoIp)?;

    // Asset cache (always empty at startup in Phase 1.6).
    let assets = AssetCache::new(cfg.asset_cache_ttl(), cfg.asset_cache_size);

    let enricher = Arc::new(Enricher::new(geoip, assets));

    // Storage backend.
    let storage = AdaptiveStorage::new(&config)
        .await
        .map_err(|e| NormalizerError::Storage(e.to_string()))?;
    let storage: Arc<dyn kron_storage::StorageEngine> = Arc::new(storage);

    // Bus producer for publishing enriched events.
    let bus = AdaptiveBus::new(config.clone()).map_err(NormalizerError::Bus)?;
    let producer = Arc::new(bus.new_producer().map_err(NormalizerError::Bus)?)
        as Arc<dyn kron_bus::traits::BusProducer>;

    let pipeline = Arc::new(Pipeline::new(enricher, storage, producer));
    let norm = Normalizer::new(config, pipeline);

    norm.run(shutdown.subscribe()).await
}

/// Starts the Prometheus metrics HTTP exporter if `addr` is non-empty.
fn start_metrics_exporter(addr: &str) -> Result<(), NormalizerError> {
    if addr.is_empty() {
        return Ok(());
    }
    let addr_parsed: std::net::SocketAddr = addr.parse().map_err(|e| {
        NormalizerError::Config(format!("invalid metrics_addr '{addr}': {e}"))
    })?;
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(addr_parsed)
        .install()
        .map_err(|e| {
            NormalizerError::Config(format!("cannot start Prometheus exporter: {e}"))
        })?;
    tracing::info!(bind_addr = %addr, "Prometheus metrics exporter started");
    Ok(())
}
