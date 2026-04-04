//! High-level inference service.
//!
//! [`InferenceService`] coordinates all available ONNX models against a
//! single [`KronEvent`], returning an [`InferenceResult`] that captures each
//! available score and a composite `is_flagged` signal.

use std::sync::Arc;
use std::time::Instant;

use kron_types::event::KronEvent;
use tracing::instrument;

use crate::metrics;
use crate::onnx::anomaly::{AnomalyScorer, ANOMALY_THRESHOLD};
use crate::onnx::exfil::{ExfilFeatures, ExfilScorer, EXFIL_THRESHOLD};
use crate::registry::ModelRegistry;

/// Inference result for a single [`KronEvent`].
///
/// Scores are `None` when the corresponding model has not been loaded or
/// when feature extraction cannot produce meaningful input. A `None` score
/// never causes `is_flagged` to be set.
#[derive(Debug, Clone)]
pub struct InferenceResult {
    /// Isolation Forest anomaly score `0.0–1.0`.
    /// `None` when the anomaly model is not loaded.
    pub anomaly_score: Option<f32>,
    /// UEBA behavioral anomaly probability `0.0–1.0`.
    /// Always `None` in Phase 2 — requires per-user 30-day baseline data.
    pub ueba_score: Option<f32>,
    /// Exfiltration probability `0.0–1.0`.
    /// `None` when the exfil model is not loaded.
    pub exfil_score: Option<f32>,
    /// `true` if any score exceeds its configured detection threshold.
    pub is_flagged: bool,
}

/// High-level inference service.
///
/// Holds a reference to the [`ModelRegistry`] and coordinates model execution
/// for each incoming event. All scoring failures are logged at `warn` level
/// and reflected as `None` scores — this method never propagates errors.
pub struct InferenceService {
    registry: Arc<ModelRegistry>,
}

impl InferenceService {
    /// Construct a new [`InferenceService`] backed by the given registry.
    #[must_use]
    pub fn new(registry: Arc<ModelRegistry>) -> Self {
        Self { registry }
    }

    /// Run all available models against the given event.
    ///
    /// Steps performed:
    /// 1. Anomaly features are extracted from the event.
    /// 2. Anomaly scoring is offloaded to `spawn_blocking` (CPU-bound).
    /// 3. Exfil scoring is offloaded to `spawn_blocking` (CPU-bound).
    /// 4. UEBA scoring returns `None` in Phase 2 (requires baseline window).
    /// 5. `is_flagged` is set if any threshold is exceeded.
    /// 6. Latency and error metrics are recorded.
    ///
    /// This method never panics and never returns an `Err` — all model errors
    /// are logged internally.
    #[instrument(skip_all, fields(
        event_id  = %event.event_id,
        tenant_id = %event.tenant_id,
    ))]
    pub async fn score_event(&self, event: &KronEvent) -> InferenceResult {
        let anomaly_score = self.run_anomaly(event).await;
        let exfil_score = self.run_exfil(event).await;

        // UEBA requires 30-day per-user baseline — not available per-event in Phase 2.
        let ueba_score: Option<f32> = None;

        let is_flagged = anomaly_score.is_some_and(|s| s > ANOMALY_THRESHOLD)
            || exfil_score.is_some_and(|s| s > EXFIL_THRESHOLD);

        if is_flagged {
            metrics::record_flagged_event();
        }

        InferenceResult {
            anomaly_score,
            ueba_score,
            exfil_score,
            is_flagged,
        }
    }

    /// Run anomaly scoring in a blocking thread.
    async fn run_anomaly(&self, event: &KronEvent) -> Option<f32> {
        let scorer: Arc<AnomalyScorer> = self.registry.anomaly().await?;
        let features = AnomalyScorer::extract_features(event);

        let start = Instant::now();
        let result = tokio::task::spawn_blocking(move || scorer.score(&features)).await;
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        metrics::record_inference_latency_ms("anomaly", elapsed_ms);

        match result {
            Ok(Ok(score)) => Some(score),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "anomaly inference failed");
                metrics::record_inference_error("anomaly");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawn_blocking panicked in anomaly scorer");
                metrics::record_inference_error("anomaly");
                None
            }
        }
    }

    /// Run exfil scoring in a blocking thread.
    ///
    /// Derives `bytes_out` from the event. When no byte count is available,
    /// returns `None` immediately without invoking the model.
    async fn run_exfil(&self, event: &KronEvent) -> Option<f32> {
        let scorer: Arc<ExfilScorer> = self.registry.exfil().await?;

        // Saturating conversion: byte volumes beyond 2^24 lose precision but
        // the exfil model uses log-scale features so this is acceptable.
        #[allow(clippy::cast_precision_loss)]
        let bytes_out = event.bytes_out? as f32;

        // Baseline and reputation data require aggregation — default to
        // conservative values that minimize false positives.
        let features = ExfilFeatures {
            bytes_out,
            baseline_bytes: bytes_out.max(1.0), // ratio = 1.0 → neutral deviation
            time_deviation: 0.0,
            dst_reputation: 0.0,
        };

        let start = Instant::now();
        let result = tokio::task::spawn_blocking(move || scorer.score(&features)).await;
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        metrics::record_inference_latency_ms("exfil", elapsed_ms);

        match result {
            Ok(Ok(score)) => Some(score),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "exfil inference failed");
                metrics::record_inference_error("exfil");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawn_blocking panicked in exfil scorer");
                metrics::record_inference_error("exfil");
                None
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use chrono::Utc;
    use kron_types::enums::EventSource;
    use kron_types::ids::TenantId;

    use super::*;

    fn minimal_event() -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .ts(Utc::now())
            .build()
            .expect("valid event")
    }

    #[tokio::test]
    async fn test_score_event_when_no_models_loaded_then_all_none() {
        let registry = Arc::new(ModelRegistry::new(std::env::temp_dir()));
        let service = InferenceService::new(registry);
        let event = minimal_event();

        let result = service.score_event(&event).await;

        assert!(result.anomaly_score.is_none());
        assert!(result.ueba_score.is_none());
        assert!(result.exfil_score.is_none());
        assert!(!result.is_flagged);
    }

    #[test]
    fn test_is_flagged_when_high_anomaly_score_then_true() {
        // Unit test: verify threshold logic directly without ONNX.
        let score: f32 = 0.9;
        let is_flagged = score > ANOMALY_THRESHOLD;
        assert!(is_flagged);
    }

    #[test]
    fn test_is_flagged_when_low_anomaly_score_then_false() {
        let score: f32 = 0.5;
        let is_flagged = score > ANOMALY_THRESHOLD;
        assert!(!is_flagged);
    }

    #[test]
    fn test_is_flagged_when_high_exfil_score_then_true() {
        let score: f32 = 0.9;
        let is_flagged = score > EXFIL_THRESHOLD;
        assert!(is_flagged);
    }

    #[tokio::test]
    async fn test_score_event_when_no_bytes_out_then_exfil_none() {
        // Event with no bytes_out → exfil scorer returns None.
        let registry = Arc::new(ModelRegistry::new(std::env::temp_dir()));
        let service = InferenceService::new(registry);
        let event = minimal_event();

        let result = service.score_event(&event).await;
        assert!(result.exfil_score.is_none());
    }
}
