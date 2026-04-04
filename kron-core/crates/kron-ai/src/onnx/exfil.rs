//! Data exfiltration volume scorer ONNX model wrapper.
//!
//! Scores the probability that an observed outbound data transfer represents
//! a data exfiltration event based on volume deviation from a 30-day baseline.
//! Inference target: <3 ms CPU.

use std::path::Path;

use crate::error::AiError;
use crate::onnx::session::OnnxSession;

/// Feature vector for the exfiltration volume scorer.
///
/// Combines raw volume, baseline deviation, time-of-day context, and
/// destination reputation into a 4-dimensional feature vector.
#[derive(Debug, Clone)]
pub struct ExfilFeatures {
    /// Bytes sent by the asset during the current observation window.
    pub bytes_out: f32,
    /// 30-day average bytes per equivalent time window (baseline).
    /// Used as denominator for volume normalization. Must be `> 0.0`;
    /// callers should clamp to at least `1.0` before constructing.
    pub baseline_bytes: f32,
    /// Time-of-day deviation score.
    /// `0.0` = normal business hours, `1.0` = highly unusual transfer time.
    pub time_deviation: f32,
    /// Destination IP/domain reputation score.
    /// `0.0` = known-good destination, `1.0` = suspicious or unknown.
    pub dst_reputation: f32,
}

impl ExfilFeatures {
    /// Convert the feature struct to a flat f32 slice suitable for ONNX input.
    ///
    /// Order: `[bytes_out, baseline_bytes, time_deviation, dst_reputation]`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.bytes_out,
            self.baseline_bytes,
            self.time_deviation,
            self.dst_reputation,
        ]
    }
}

/// Data exfiltration volume scorer.
///
/// Wraps the `exfil_scorer.onnx` model. Input shape: `[1, 4]`.
/// Output shape: `[1, 1]` — a single f32 probability in `0.0–1.0`.
/// Probabilities above `0.85` indicate potential exfiltration.
pub struct ExfilScorer {
    session: OnnxSession,
}

/// Threshold above which an exfil probability triggers a flag.
pub const EXFIL_THRESHOLD: f32 = 0.85;

/// Number of features expected by the exfil scorer model.
const FEATURE_COUNT: usize = 4;

impl ExfilScorer {
    /// Load the exfiltration scorer model from the given path.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::ModelNotFound`] if the model file does not exist.
    /// Returns [`AiError::ModelLoad`] if the ONNX Runtime fails to load it.
    pub fn load(model_path: &Path) -> Result<Self, AiError> {
        let session = OnnxSession::load(model_path, "exfil")?;
        Ok(Self { session })
    }

    /// Score the exfiltration probability for the given features.
    ///
    /// Returns a probability in the range `0.0–1.0`. Values above
    /// [`EXFIL_THRESHOLD`] (`0.85`) indicate potential data exfiltration.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::Inference`] if ONNX Runtime fails during inference.
    /// Returns [`AiError::InvalidOutput`] if the model returns no output values.
    pub fn score(&self, features: &ExfilFeatures) -> Result<f32, AiError> {
        let data = features.to_vec();
        let shape = [1_usize, FEATURE_COUNT];
        let outputs = self.session.run_f32("input", &data, &shape)?;

        match outputs.first() {
            Some(&prob) => Ok(prob.clamp(0.0, 1.0)),
            None => Err(AiError::InvalidOutput {
                expected: 1,
                got: 0,
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_exfil_features_to_vec_when_called_then_returns_four_elements() {
        let f = ExfilFeatures {
            bytes_out: 1_000_000.0,
            baseline_bytes: 100_000.0,
            time_deviation: 0.1,
            dst_reputation: 0.5,
        };
        assert_eq!(f.to_vec().len(), FEATURE_COUNT);
    }

    /// Requires model file at `/var/lib/kron/models/exfil_scorer.onnx`.
    #[test]
    #[ignore = "requires ONNX model file at /var/lib/kron/models/exfil_scorer.onnx"]
    fn test_score_when_model_loaded_then_returns_valid_range() {
        let path = std::path::Path::new("/var/lib/kron/models/exfil_scorer.onnx");
        let scorer = ExfilScorer::load(path).expect("model must load");
        let features = ExfilFeatures {
            bytes_out: 500_000.0,
            baseline_bytes: 100_000.0,
            time_deviation: 0.0,
            dst_reputation: 0.0,
        };
        let prob = scorer.score(&features).expect("inference must succeed");
        assert!((0.0_f32..=1.0_f32).contains(&prob));
    }
}
