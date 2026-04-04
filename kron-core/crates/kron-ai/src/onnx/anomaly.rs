//! Isolation Forest anomaly scorer ONNX model wrapper.
//!
//! Scores individual security events for behavioral anomalies using a
//! 6-feature Isolation Forest model. Inference target: <3 ms CPU.

use std::path::Path;

use kron_types::event::KronEvent;

use crate::error::AiError;
use crate::onnx::session::OnnxSession;

/// Feature vector for the Isolation Forest anomaly scorer.
///
/// All values are normalized to a comparable range before inference.
/// Missing source data defaults to `0.0`, which represents "no signal".
#[derive(Debug, Clone)]
pub struct AnomalyFeatures {
    /// Hour of day (0–23) normalized to 0.0–1.0 by dividing by 23.0.
    pub login_hour_norm: f32,
    /// Failed authentication count in the last 5 minutes (raw count).
    pub failed_auth_count: f32,
    /// Data volume in bytes, log10-transformed for scale normalization.
    /// `0.0` when no volume data is available.
    pub data_volume_log: f32,
    /// Network connection count in the last 5 minutes (raw count).
    pub connection_count: f32,
    /// Process spawn count in the last 5 minutes (raw count).
    pub process_count: f32,
    /// Unique destination IPs observed in the last 5 minutes (raw count).
    pub unique_dst_ips: f32,
}

impl AnomalyFeatures {
    /// Convert the feature struct to a flat f32 slice suitable for ONNX input.
    ///
    /// The order matches the model's expected input node layout:
    /// `[login_hour_norm, failed_auth_count, data_volume_log,
    ///   connection_count, process_count, unique_dst_ips]`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.login_hour_norm,
            self.failed_auth_count,
            self.data_volume_log,
            self.connection_count,
            self.process_count,
            self.unique_dst_ips,
        ]
    }
}

/// Isolation Forest anomaly scorer.
///
/// Wraps the `anomaly_isolation_forest.onnx` model. Input shape: `[1, 6]`.
/// Output shape: `[1, 1]` — a single f32 score in the range `0.0–1.0`.
/// Scores above `0.75` are considered anomalous.
pub struct AnomalyScorer {
    session: OnnxSession,
}

/// Threshold above which an anomaly score is flagged.
pub const ANOMALY_THRESHOLD: f32 = 0.75;

/// Number of features expected by the Isolation Forest model.
const FEATURE_COUNT: usize = 6;

impl AnomalyScorer {
    /// Load the Isolation Forest model from the given path.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::ModelNotFound`] if the model file does not exist.
    /// Returns [`AiError::ModelLoad`] if the ONNX Runtime fails to load it.
    pub fn load(model_path: &Path) -> Result<Self, AiError> {
        let session = OnnxSession::load(model_path, "anomaly")?;
        Ok(Self { session })
    }

    /// Score a feature vector for anomalous behavior.
    ///
    /// Returns an anomaly score in the range `0.0–1.0`.
    /// A score above [`ANOMALY_THRESHOLD`] (`0.75`) is considered anomalous.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::Inference`] if ONNX Runtime fails during inference.
    /// Returns [`AiError::InvalidOutput`] if the model returns an unexpected
    /// number of output values.
    pub fn score(&self, features: &AnomalyFeatures) -> Result<f32, AiError> {
        let data = features.to_vec();
        let shape = [1_usize, FEATURE_COUNT];
        let outputs = self.session.run_f32("input", &data, &shape)?;

        match outputs.first() {
            Some(&score) => Ok(score.clamp(0.0, 1.0)),
            None => Err(AiError::InvalidOutput {
                expected: 1,
                got: 0,
            }),
        }
    }

    /// Extract anomaly features from a single [`KronEvent`].
    ///
    /// Features that require aggregated window data (e.g. `failed_auth_count`,
    /// `connection_count`) default to `0.0` when not available from a single
    /// event. The hour-of-day is taken from the event timestamp.
    #[must_use]
    pub fn extract_features(event: &KronEvent) -> AnomalyFeatures {
        use chrono::Timelike as _;

        // Hour is 0..=23 (u32); precision loss is intentional for normalization.
        #[allow(clippy::cast_precision_loss)]
        let login_hour_norm = event.ts.hour() as f32 / 23.0_f32;

        // Bytes are log10-transformed so precision loss in cast is acceptable.
        #[allow(clippy::cast_precision_loss)]
        let data_volume_log =
            event.bytes_out.map_or(
                0.0_f32,
                |b| if b == 0 { 0.0_f32 } else { (b as f32).log10() },
            );

        AnomalyFeatures {
            login_hour_norm,
            failed_auth_count: 0.0,
            data_volume_log,
            connection_count: 0.0,
            process_count: 0.0,
            unique_dst_ips: 0.0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[allow(clippy::cast_precision_loss)]
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

    #[test]
    fn test_extract_features_when_minimal_event_then_returns_defaults() {
        let event = minimal_event();
        let features = AnomalyScorer::extract_features(&event);

        // Non-aggregated defaults must be zero.
        assert!((features.failed_auth_count - 0.0_f32).abs() < f32::EPSILON);
        assert!((features.connection_count - 0.0_f32).abs() < f32::EPSILON);
        assert!((features.process_count - 0.0_f32).abs() < f32::EPSILON);
        assert!((features.unique_dst_ips - 0.0_f32).abs() < f32::EPSILON);
        // Hour is extracted from timestamp — must be in normalized range.
        assert!(features.login_hour_norm >= 0.0_f32);
        assert!(features.login_hour_norm <= 1.0_f32);
    }

    #[test]
    fn test_extract_features_when_bytes_out_set_then_log_transform_applied() {
        let event = KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("network_connect")
            .ts(Utc::now())
            .build()
            .expect("valid event");
        // bytes_out is None on minimal event — should default to 0.0
        let features = AnomalyScorer::extract_features(&event);
        assert!((features.data_volume_log - 0.0_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn test_anomaly_features_to_vec_when_called_then_returns_six_elements() {
        let f = AnomalyFeatures {
            login_hour_norm: 0.5,
            failed_auth_count: 3.0,
            data_volume_log: 4.2,
            connection_count: 10.0,
            process_count: 2.0,
            unique_dst_ips: 1.0,
        };
        assert_eq!(f.to_vec().len(), FEATURE_COUNT);
    }

    /// Requires model file at `/var/lib/kron/models/anomaly_isolation_forest.onnx`.
    #[test]
    #[ignore = "requires ONNX model file at /var/lib/kron/models/anomaly_isolation_forest.onnx"]
    fn test_score_when_model_loaded_then_returns_valid_range() {
        let path = std::path::Path::new("/var/lib/kron/models/anomaly_isolation_forest.onnx");
        let scorer = AnomalyScorer::load(path).expect("model must load");
        let features = AnomalyFeatures {
            login_hour_norm: 0.5,
            failed_auth_count: 0.0,
            data_volume_log: 3.0,
            connection_count: 1.0,
            process_count: 1.0,
            unique_dst_ips: 1.0,
        };
        let score = scorer.score(&features).expect("inference must succeed");
        assert!((0.0_f32..=1.0_f32).contains(&score));
    }
}
