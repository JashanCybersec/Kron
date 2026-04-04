//! End-to-end event normalization pipeline.
//!
//! [`Pipeline`] is the core processing unit:
//!
//! ```text
//! parse → enrich → dedup → write storage → publish enriched
//! ```
//!
//! Each step is independent; failures in non-critical steps (enrichment,
//! storage) are logged and do not prevent the enriched event from being
//! published to the bus.

use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use kron_storage::StorageEngine;
use kron_types::{KronEvent, TenantContext, TenantId};

use crate::enrich::Enricher;
use crate::error::NormalizerError;
use crate::metrics;
use crate::parser;

/// The end-to-end normalization pipeline.
pub struct Pipeline {
    enricher: Arc<Enricher>,
    storage: Arc<dyn StorageEngine>,
    producer: Arc<dyn kron_bus::traits::BusProducer>,
}

impl Pipeline {
    /// Creates a new [`Pipeline`] with the given backends.
    #[must_use]
    pub fn new(
        enricher: Arc<Enricher>,
        storage: Arc<dyn StorageEngine>,
        producer: Arc<dyn kron_bus::traits::BusProducer>,
    ) -> Self {
        Self {
            enricher,
            storage,
            producer,
        }
    }

    /// Processes a single raw event through the full pipeline.
    ///
    /// Steps performed:
    /// 1. Deserialize JSON payload → `KronEvent`
    /// 2. Detect format and parse additional fields from `raw`
    /// 3. Enrich (GeoIP, asset)
    /// 4. Compute dedup fingerprint
    /// 5. Write to storage (best-effort; failure logged, not propagated)
    /// 6. Publish to `kron.enriched.{tenant_id}`
    ///
    /// # Errors
    ///
    /// Returns `Err` only for unrecoverable failures (deserialization, bus
    /// publish). Storage errors are logged and treated as non-fatal.
    pub async fn process(&self, payload: Bytes) -> Result<(), NormalizerError> {
        let start = std::time::Instant::now();
        metrics::record_raw_received();

        // Step 1: Deserialize
        let mut event: KronEvent = serde_json::from_slice(&payload)?;

        // Stamp receipt time lag
        let now = Utc::now();
        let lag_ms = (now - event.ts)
            .num_milliseconds()
            .clamp(0, u32::MAX as i64) as u32;
        event.ts_received = now;
        event.ingest_lag_ms = lag_ms;

        // Step 2: Format detection + parsing
        let format = parser::detect_and_parse(&mut event);

        // Step 3: Enrichment
        self.enricher.enrich(&mut event);

        // Step 4: Dedup fingerprint
        crate::dedup::compute_and_assign(&mut event);

        let tenant_id = event.tenant_id;
        let event_id = event.event_id;

        metrics::record_event_normalized(format.label());

        // Step 5: Write to storage (best-effort)
        self.write_to_storage(tenant_id, event.clone()).await;

        // Step 6: Publish enriched event
        self.publish_enriched(tenant_id, event).await?;

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        metrics::record_pipeline_latency_ms(elapsed_ms);

        tracing::debug!(
            event_id = %event_id,
            tenant_id = %tenant_id,
            format = format.label(),
            elapsed_ms,
            "Event normalized and published"
        );

        Ok(())
    }

    /// Writes `event` to storage; logs and continues on failure.
    async fn write_to_storage(&self, tenant_id: TenantId, event: KronEvent) {
        let ctx = TenantContext::new(tenant_id, "normalizer", "service");
        match self.storage.insert_event(&ctx, event).await {
            Ok(()) => {
                metrics::record_storage_write();
            }
            Err(e) => {
                metrics::record_storage_error();
                tracing::error!(
                    error = %e,
                    tenant_id = %tenant_id,
                    "Storage write failed; event still published to bus"
                );
            }
        }
    }

    /// Serializes `event` and publishes to `kron.enriched.{tenant_id}`.
    async fn publish_enriched(
        &self,
        tenant_id: TenantId,
        event: KronEvent,
    ) -> Result<(), NormalizerError> {
        let payload = serde_json::to_vec(&event).map(Bytes::from)?;
        let topic = kron_bus::topics::enriched_events(&tenant_id);
        let key = Bytes::from(tenant_id.to_string());

        self.producer
            .send(&topic, Some(key), payload, std::collections::HashMap::new())
            .await
            .map_err(NormalizerError::Bus)?;

        metrics::record_enriched_published();
        Ok(())
    }
}
