//! Main alert engine loop.
//!
//! [`AlertEngine`] wires together the bus consumer, deduplicator, assembler,
//! storage writer, bus producer, and notification dispatcher.  It runs until
//! a shutdown signal is received.

use std::sync::Arc;
use std::time::Instant;

use kron_bus::traits::{BusConsumer, BusProducer};
use kron_bus::AdaptiveBus;
use kron_storage::traits::StorageEngine;
use kron_storage::AdaptiveStorage;
use kron_types::config::KronConfig;
use kron_types::ids::TenantId;
use kron_types::TenantContext;
use tokio::sync::broadcast;
use tracing::instrument;

use crate::assembler::AlertAssembler;
use crate::dedup::AlertDeduplicator;
use crate::error::AlertError;
use crate::metrics;
use crate::notify::dispatcher::NotificationDispatcher;
use crate::types::AlertCandidate;

/// How often the engine flushes expired dedup windows in seconds.
const FLUSH_INTERVAL_SECS: u64 = 30;

/// How long to wait for a bus message before looping to check for shutdown.
const POLL_TIMEOUT_MS: u64 = 500;

/// The alert engine: consumes candidates, deduplicates, assembles, stores,
/// publishes, and dispatches notifications.
pub struct AlertEngine {
    deduplicator: Arc<AlertDeduplicator>,
    storage: Arc<AdaptiveStorage>,
    dispatcher: Arc<NotificationDispatcher>,
    bus_producer: Arc<dyn BusProducer>,
}

impl AlertEngine {
    /// Creates a new `AlertEngine` from the given configuration.
    ///
    /// Builds an `AdaptiveBus` producer and `NotificationDispatcher` using
    /// the provided config and storage handle.
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::Bus`] if the bus producer cannot be initialised.
    pub fn new(
        config: &KronConfig,
        storage: Arc<AdaptiveStorage>,
        bus: &AdaptiveBus,
    ) -> Result<Self, AlertError> {
        let producer = bus
            .new_producer()
            .map_err(|e| AlertError::Bus(e.to_string()))?;

        let deduplicator = Arc::new(AlertDeduplicator::new(
            chrono::Duration::from_std(config.alert.dedup_window())
                .unwrap_or(chrono::Duration::minutes(15)),
        ));

        let dispatcher = Arc::new(NotificationDispatcher::new(config.alert.clone()));

        Ok(Self {
            deduplicator,
            storage,
            dispatcher,
            bus_producer: Arc::from(producer),
        })
    }

    /// Runs the alert engine loop until a shutdown signal is received.
    ///
    /// Polls the bus consumer for alert candidates, deduplicates them, and
    /// on each new window emits an alert to storage, the bus, and notification
    /// channels.  Expired windows are flushed every 30 seconds.
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::Bus`] on unrecoverable consumer errors.
    #[instrument(skip_all)]
    pub async fn run(
        self: Arc<Self>,
        mut consumer: Box<dyn BusConsumer>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<(), AlertError> {
        let mut flush_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(FLUSH_INTERVAL_SECS));

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    tracing::info!("Alert engine received shutdown signal");
                    break;
                }
                _ = flush_ticker.tick() => {
                    self.flush_expired_windows().await;
                }
                poll_result = consumer.poll(std::time::Duration::from_millis(POLL_TIMEOUT_MS)) => {
                    match poll_result {
                        Err(e) => {
                            tracing::error!(error = %e, "Bus consumer poll failed");
                            // Non-fatal: log and continue polling.
                        }
                        Ok(None) => {
                            // Timeout — no message within POLL_TIMEOUT.
                        }
                        Ok(Some(msg)) => {
                            let commit = self.process_message(&msg.payload);

                            if let Err(e) = commit {
                                tracing::warn!(
                                    error = %e,
                                    "Alert candidate processing failed; nacking message"
                                );
                                if let Err(nack_err) = consumer.nack(&msg, &e.to_string()).await {
                                    tracing::error!(
                                        error = %nack_err,
                                        "Failed to nack message after processing error"
                                    );
                                }
                            } else if let Err(commit_err) = consumer.commit(&msg).await {
                                tracing::error!(
                                    error = %commit_err,
                                    "Failed to commit message offset"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Deserializes a raw payload and runs it through the detection pipeline.
    fn process_message(&self, payload: &[u8]) -> Result<(), AlertError> {
        let start = Instant::now();

        let candidate: AlertCandidate = serde_json::from_slice(payload)
            .map_err(|e| AlertError::Deserialize(format!("invalid AlertCandidate payload: {e}")))?;

        let tenant_id = candidate.event.tenant_id;
        let tenant_id_str = tenant_id.to_string();

        match self.deduplicator.ingest(&candidate) {
            None => {
                // Merged into an existing window — count as dedup.
                metrics::record_alert_deduped(&tenant_id_str);
                tracing::debug!(
                    tenant_id = %tenant_id,
                    "Alert candidate deduplicated into existing window"
                );
            }
            Some(_new_id) => {
                // New window opened — we do not emit the alert yet.
                // Alerts are emitted when the window expires in flush_expired_windows.
                tracing::debug!(
                    tenant_id = %tenant_id,
                    "New dedup window opened for alert candidate"
                );
            }
        }

        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        metrics::record_engine_latency_ms(elapsed_ms);
        Ok(())
    }

    /// Flushes all expired dedup windows, writing each to storage and
    /// dispatching notifications.
    async fn flush_expired_windows(&self) {
        let expired = self.deduplicator.flush_expired();
        self.deduplicator.evict_old();

        for (key, window) in &expired {
            let tenant_ctx = TenantContext::new(key.tenant_id, "kron-alert", "service");
            let tenant_id_str = key.tenant_id.to_string();

            // We need an AlertCandidate to assemble with.  Since we only have
            // the window state here (not the original candidate), we do a best-
            // effort assembly with placeholder data.  The window stores all
            // accumulated evidence event IDs which is the critical information.
            //
            // A richer design would store the first candidate per window; that
            // is deferred here since the current dedup structure stores window
            // aggregates only.
            //
            // For now, build a minimal AlertCandidate stub from the window key.
            let stub = build_candidate_stub(key);

            let alert = AlertAssembler::assemble(&stub, window, key);

            // Write to storage.
            match self
                .storage
                .insert_alerts(&tenant_ctx, vec![alert.clone()])
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        alert_id = %alert.alert_id,
                        tenant_id = %alert.tenant_id,
                        severity = %alert.severity,
                        "Alert written to storage"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        alert_id = %alert.alert_id,
                        error = %e,
                        "Failed to write alert to storage"
                    );
                    metrics::record_notification_failed("storage");
                    continue;
                }
            }

            // Publish to bus.
            if let Err(e) = self.publish_alert(&alert).await {
                tracing::error!(
                    alert_id = %alert.alert_id,
                    error = %e,
                    "Failed to publish alert to bus"
                );
            }

            // Dispatch notifications.
            let dispatch = self.dispatcher.dispatch(&alert).await;
            let mut updated_alert = alert.clone();
            updated_alert.whatsapp_sent = dispatch.whatsapp_sent;
            updated_alert.sms_sent = dispatch.sms_sent;
            updated_alert.email_sent = dispatch.email_sent;

            if dispatch.whatsapp_sent || dispatch.sms_sent || dispatch.email_sent {
                updated_alert.notification_ts = Some(chrono::Utc::now());
                if let Err(e) = self.storage.update_alert(&tenant_ctx, &updated_alert).await {
                    tracing::warn!(
                        alert_id = %updated_alert.alert_id,
                        error = %e,
                        "Failed to update alert notification flags"
                    );
                }
            }

            metrics::record_alert_created(&tenant_id_str, &alert.severity.to_string());
        }
    }

    /// Serializes an alert and publishes it to `kron.alerts.{tenant_id}`.
    async fn publish_alert(&self, alert: &kron_types::KronAlert) -> Result<(), AlertError> {
        use bytes::Bytes;
        use kron_bus::topics;

        let topic = topics::alerts(&alert.tenant_id);
        let payload = serde_json::to_vec(alert)
            .map_err(|e| AlertError::Bus(format!("serialize alert: {e}")))?;

        self.bus_producer
            .send(
                &topic,
                None,
                Bytes::from(payload),
                std::collections::HashMap::default(),
            )
            .await
            .map_err(|e| AlertError::Bus(e.to_string()))?;

        Ok(())
    }
}

/// Builds a minimal placeholder `AlertCandidate` from a `DedupKey`.
///
/// Used when flushing expired windows where only aggregated state (not the
/// original first candidate) is available.
fn build_candidate_stub(key: &crate::dedup::DedupKey) -> AlertCandidate {
    use kron_types::{EventSource, KronEvent, Severity};

    let event = KronEvent::builder()
        .tenant_id(key.tenant_id)
        .source_type(EventSource::Unknown)
        .event_type("alert_flush")
        .ts(chrono::Utc::now())
        .hostname(&key.primary_asset)
        .build()
        .unwrap_or_else(|_| {
            // This path should never be hit since all required fields are set.
            // The builder only fails if tenant_id, source_type, event_type, or
            // ts is missing — all of which we provide above.
            // Use a fully-specified fallback to satisfy the borrow checker.
            kron_types::KronEvent::builder()
                .tenant_id(key.tenant_id)
                .source_type(EventSource::Unknown)
                .event_type("alert_flush")
                .ts(chrono::Utc::now())
                .build()
                .unwrap_or_else(|_| build_emergency_event(key.tenant_id))
        });

    AlertCandidate {
        event,
        risk_score: 0,
        severity: Severity::Info,
        rule_matches: vec![],
        ioc_hit: false,
        ioc_type_str: None,
        anomaly_score: None,
        mitre_tags: vec![],
    }
}

/// Absolute last-resort event construction used only in `build_candidate_stub`.
///
/// Panicking is not permitted by project policy, so this provides a safe
/// fallback with all required fields hard-coded.
fn build_emergency_event(tenant_id: TenantId) -> kron_types::KronEvent {
    use kron_types::{EventSource, KronEvent};
    KronEvent {
        event_id: kron_types::ids::EventId::new(),
        tenant_id,
        dedup_hash: 0,
        ts: chrono::Utc::now(),
        ts_received: chrono::Utc::now(),
        ingest_lag_ms: 0,
        source_type: EventSource::Unknown,
        collector_id: "kron-alert".to_string(),
        raw: String::new(),
        host_id: None,
        hostname: None,
        host_ip: None,
        host_fqdn: None,
        asset_criticality: kron_types::AssetCriticality::Unknown,
        asset_tags: vec![],
        user_name: None,
        user_id: None,
        user_domain: None,
        user_type: None,
        event_type: "alert_flush".to_string(),
        event_category: None,
        event_action: None,
        src_ip: None,
        src_ip6: None,
        src_port: None,
        dst_ip: None,
        dst_ip6: None,
        dst_port: None,
        protocol: None,
        bytes_in: None,
        bytes_out: None,
        packets_in: None,
        packets_out: None,
        direction: None,
        process_name: None,
        process_pid: None,
        process_ppid: None,
        process_path: None,
        process_cmdline: None,
        process_hash: None,
        parent_process: None,
        file_path: None,
        file_name: None,
        file_hash: None,
        file_size: None,
        file_action: None,
        auth_result: None,
        auth_method: None,
        auth_protocol: None,
        src_country: None,
        src_city: None,
        src_asn: None,
        src_asn_name: None,
        dst_country: None,
        ioc_hit: false,
        ioc_type: None,
        ioc_value: None,
        ioc_feed: None,
        mitre_tactic: None,
        mitre_technique: None,
        mitre_sub_tech: None,
        severity: kron_types::Severity::Info,
        severity_score: 0,
        anomaly_score: 0.0,
        ueba_score: 0.0,
        beacon_score: 0.0,
        exfil_score: 0.0,
        fields: std::collections::HashMap::new(),
        schema_version: 1,
    }
}
