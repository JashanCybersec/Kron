//! `kron-stream` — Detection engine library for KRON SIEM.
//!
//! Provides the complete Phase 2 detection pipeline: SIGMA rule engine,
//! IOC bloom filter, ONNX inference, and the wiring that connects them.
//!
//! # Module structure
//!
//! - [`error`]    — `StreamError` enum covering all failure modes
//! - [`sigma`]    — Rule parsing, compilation, matching, registry, and evaluation
//! - [`ioc`]      — IOC counting bloom filter with background feed refresh
//! - [`pipeline`] — Composite detection pipeline (risk scoring, MITRE tagging,
//!   entity graph, and the main `DetectionPipeline`)
//! - [`shutdown`] — Graceful shutdown signal coordination
//! - [`metrics`]  — Prometheus metric helpers
//!
//! # Entry point
//!
//! Call [`run`] with a loaded [`KronConfig`] and an [`Arc`]-wrapped
//! [`shutdown::ShutdownHandle`]. The caller is responsible for triggering
//! the handle (e.g. via [`shutdown::ShutdownHandle::listen_for_signals`]).

pub mod error;
pub mod ioc;
pub mod metrics;
pub mod pipeline;
pub mod shutdown;
pub mod sigma;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use chrono::Utc;
use kron_ai::{InferenceService, ModelRegistry};
use kron_bus::{AdaptiveBus, BusConsumer, BusProducer};
use kron_types::ids::TenantId;
use kron_types::KronConfig;
use tracing::instrument;

use crate::ioc::{FeedLoader, IocFilter, IocRefreshTask};
use crate::metrics as stream_metrics;
use crate::pipeline::entity_graph::EntityGraph;
use crate::pipeline::processor::{AlertCandidatePayload, DetectionPipeline, PipelineConfig};
use crate::shutdown::ShutdownHandle;
use crate::sigma::fp_classifier::FpClassifier;
use crate::sigma::registry::{CompiledRule, RuleRegistry};
use crate::sigma::{RuleEvaluator, RuleLoader};

/// Consumer poll timeout — how long to block waiting for a bus message.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

/// IOC feed refresh interval.
const IOC_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Runs the stream detection engine until the `shutdown` handle fires.
///
/// Reads stream-specific directories and thresholds from environment variables:
///
/// | Variable                     | Default                    | Purpose              |
/// |------------------------------|----------------------------|----------------------|
/// | `KRON_STREAM_RULES_DIR`      | `/var/lib/kron/rules`      | SIGMA rule directory |
/// | `KRON_STREAM_MODELS_DIR`     | `/var/lib/kron/models`     | ONNX model directory |
/// | `KRON_STREAM_ALERT_THRESHOLD`| `40`                       | Minimum risk score   |
/// | `KRON_STREAM_TENANT_IDS`     | *(empty)*                  | Comma-sep UUID list  |
///
/// The caller must keep the `shutdown` handle alive and eventually call
/// [`ShutdownHandle::shutdown`] (or use [`ShutdownHandle::listen_for_signals`]
/// in a background task) to stop the engine.
///
/// # Errors
///
/// Returns an error if any subsystem fails to initialise.
pub async fn run(config: KronConfig, shutdown: Arc<ShutdownHandle>) -> anyhow::Result<()> {
    tracing::info!("kron-stream starting");

    // ── Environment configuration ─────────────────────────────────────────────
    let rules_dir = std::env::var("KRON_STREAM_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/kron/rules"));

    let models_dir = std::env::var("KRON_STREAM_MODELS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/kron/models"));

    let alert_threshold: u8 = std::env::var("KRON_STREAM_ALERT_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);

    let tenant_ids: Vec<TenantId> = std::env::var("KRON_STREAM_TENANT_IDS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            s.parse::<uuid::Uuid>()
                .map(TenantId::from_uuid)
                .map_err(|e| {
                    tracing::warn!(tenant_id = s, error = %e, "invalid tenant ID — skipping");
                })
                .ok()
        })
        .collect();

    if tenant_ids.is_empty() {
        tracing::warn!("KRON_STREAM_TENANT_IDS is empty — no topics will be consumed");
    }

    // ── IOC filter + background refresh ──────────────────────────────────────
    let feeds = FeedLoader::default_feeds();
    let feed_loader = Arc::new(FeedLoader::new(feeds).context("building IOC feed loader")?);
    let ioc_filter = Arc::new(IocFilter::new());

    let (ioc_shutdown_tx, ioc_shutdown_rx) = tokio::sync::watch::channel(false);
    let refresh_task = IocRefreshTask::new(
        Arc::clone(&ioc_filter),
        Arc::clone(&feed_loader),
        IOC_REFRESH_INTERVAL,
    );
    let _refresh_handle = refresh_task.spawn(ioc_shutdown_rx);

    tracing::info!("IOC filter initialised");

    // ── SIGMA rules ───────────────────────────────────────────────────────────
    let rule_registry = Arc::new(RuleRegistry::new());
    if rules_dir.exists() {
        let mut loader = RuleLoader::new(rules_dir.clone());
        match loader.load_all() {
            Ok(rules) => {
                let count = rules.len();
                for (source_file, rule) in rules {
                    let classification = FpClassifier::classify(&rule);
                    let compiled = CompiledRule {
                        rule,
                        clickhouse_sql: None,
                        duckdb_sql: None,
                        classification,
                        source_file,
                        loaded_at: Utc::now(),
                    };
                    rule_registry.upsert(compiled);
                }
                tracing::info!(count, rules_dir = %rules_dir.display(), "SIGMA rules loaded");
            }
            Err(e) => tracing::warn!(
                error = %e,
                "failed to load SIGMA rules — continuing without rules"
            ),
        }
    } else {
        tracing::warn!(
            rules_dir = %rules_dir.display(),
            "SIGMA rules directory does not exist — continuing without rules"
        );
    }
    let rule_evaluator = Arc::new(RuleEvaluator::new(Arc::clone(&rule_registry)));

    // ── ONNX models ───────────────────────────────────────────────────────────
    let model_registry = Arc::new(ModelRegistry::new(models_dir.clone()));
    let inference = Arc::new(InferenceService::new(Arc::clone(&model_registry)));
    tracing::info!(models_dir = %models_dir.display(), "ONNX inference service ready");

    // ── Detection pipeline ────────────────────────────────────────────────────
    let entity_graph = Arc::new(EntityGraph::new());
    let pipeline_config = PipelineConfig {
        alert_threshold,
        rules_dir,
        models_dir,
    };
    let pipeline = Arc::new(DetectionPipeline::new(
        Arc::clone(&ioc_filter),
        rule_evaluator,
        inference,
        Arc::clone(&entity_graph),
        pipeline_config,
    ));
    tracing::info!(alert_threshold, "detection pipeline ready");

    // ── Per-tenant consumer tasks ─────────────────────────────────────────────
    let bus = AdaptiveBus::new(config.clone()).context("creating bus")?;
    let producer: Arc<dyn BusProducer> =
        Arc::from(bus.new_producer().context("creating bus producer")?);

    let mut task_handles = Vec::with_capacity(tenant_ids.len());
    for tenant_id in &tenant_ids {
        let mut consumer = bus
            .new_consumer("kron-stream")
            .context("creating bus consumer")?;

        let enriched_topic = kron_bus::topics::enriched_events(tenant_id);
        consumer
            .subscribe(&[enriched_topic.clone()], "kron-stream")
            .await
            .with_context(|| format!("subscribing to {enriched_topic}"))?;

        tracing::info!(
            tenant_id = %tenant_id,
            topic = %enriched_topic,
            "consumer subscribed"
        );

        let pipeline = Arc::clone(&pipeline);
        let producer = Arc::clone(&producer);
        let tenant_id = *tenant_id;
        let mut shutdown_rx = shutdown.subscribe();

        let handle = tokio::spawn(async move {
            run_consumer_loop(consumer, pipeline, producer, tenant_id, &mut shutdown_rx).await;
        });
        task_handles.push(handle);
    }

    // ── Wait for shutdown ─────────────────────────────────────────────────────
    // The caller is responsible for triggering shutdown (e.g. via
    // `shutdown.listen_for_signals()` or `shutdown.shutdown()`).
    let mut shutdown_rx = shutdown.subscribe();
    let _ = shutdown_rx.recv().await;

    // Stop the IOC refresh task.
    let _ = ioc_shutdown_tx.send(true);

    // Wait for all consumer tasks.
    for handle in task_handles {
        if let Err(e) = handle.await {
            tracing::error!(error = ?e, "consumer task panicked");
        }
    }

    tracing::info!("kron-stream shutdown complete");
    Ok(())
}

/// Event-processing loop for a single tenant consumer.
///
/// Polls the bus, deserialises events, runs the detection pipeline, and
/// publishes alert candidates to the alerts topic. Exits when the shutdown
/// signal fires.
async fn run_consumer_loop(
    mut consumer: Box<dyn BusConsumer>,
    pipeline: Arc<DetectionPipeline>,
    producer: Arc<dyn BusProducer>,
    tenant_id: TenantId,
    shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
) {
    let tenant_str = tenant_id.to_string();
    let alert_topic = kron_bus::topics::alerts(&tenant_id);

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!(tenant_id = %tenant_id, "consumer loop shutting down");
                break;
            }
            poll_result = consumer.poll(POLL_TIMEOUT) => {
                match poll_result {
                    Err(e) => {
                        tracing::error!(
                            tenant_id = %tenant_id,
                            error = %e,
                            "bus poll error"
                        );
                    }
                    Ok(None) => {
                        // No message within timeout — loop and poll again.
                    }
                    Ok(Some(msg)) => {
                        let start = Instant::now();

                        let event: kron_types::KronEvent =
                            match serde_json::from_slice(&msg.payload) {
                                Ok(e) => e,
                                Err(e) => {
                                    tracing::error!(
                                        tenant_id = %tenant_id,
                                        error = %e,
                                        "failed to deserialise KronEvent — nacking"
                                    );
                                    if let Err(ne) = consumer.nack(&msg, &e.to_string()).await {
                                        tracing::error!(error = %ne, "nack failed");
                                    }
                                    continue;
                                }
                            };

                        stream_metrics::record_events_processed(&tenant_str);

                        if let Some(candidate) = pipeline.process(&event).await {
                            stream_metrics::record_alerts_generated(
                                &tenant_str,
                                &candidate.severity.to_string(),
                            );

                            if candidate.ioc_hit {
                                stream_metrics::record_ioc_hits(&tenant_str);
                            }

                            for rule_match in &candidate.rule_matches {
                                stream_metrics::record_sigma_matches(
                                    &tenant_str,
                                    &rule_match.rule_id.to_string(),
                                );
                            }

                            publish_candidate(producer.as_ref(), &alert_topic, &candidate).await;
                        }

                        let elapsed_ms = u64::try_from(start.elapsed().as_millis())
                            .unwrap_or(u64::MAX);
                        stream_metrics::record_pipeline_latency_ms(elapsed_ms);

                        if let Err(e) = consumer.commit(&msg).await {
                            tracing::error!(
                                tenant_id = %tenant_id,
                                error = %e,
                                "failed to commit offset"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Serialise and publish an [`AlertCandidate`] to the alert topic.
///
/// Converts to [`AlertCandidatePayload`] before serialising. Failures are
/// logged at `error` level — a failed publish must not crash the consumer loop.
#[instrument(skip_all, fields(
    risk_score = candidate.risk_score,
    severity = %candidate.severity,
))]
async fn publish_candidate(
    producer: &dyn BusProducer,
    alert_topic: &str,
    candidate: &crate::pipeline::processor::AlertCandidate,
) {
    let wire = AlertCandidatePayload::from(candidate);
    let payload = match serde_json::to_vec(&wire) {
        Ok(p) => Bytes::from(p),
        Err(e) => {
            tracing::error!(
                error = %e,
                "failed to serialise AlertCandidatePayload — alert dropped"
            );
            return;
        }
    };

    let tenant_key =
        Bytes::copy_from_slice(candidate.event.tenant_id.to_string().as_bytes());

    if let Err(e) = producer
        .send(alert_topic, Some(tenant_key), payload, HashMap::new())
        .await
    {
        tracing::error!(
            topic = alert_topic,
            error = %e,
            "failed to publish alert candidate"
        );
    }
}
