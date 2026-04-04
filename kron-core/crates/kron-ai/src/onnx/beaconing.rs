//! FFT-based C2 beaconing detector ONNX model wrapper.
//!
//! Detects periodic command-and-control beaconing by analyzing the
//! inter-arrival times between connections for a source→destination pair
//! over a 1-hour observation window. Inference target: <10 ms CPU.

use std::path::Path;

use crate::error::AiError;
use crate::onnx::session::OnnxSession;

/// Minimum number of inter-arrival samples required for meaningful detection.
const MIN_SAMPLES: usize = 3;

/// Fixed input width expected by the beaconing model.
/// Shorter sequences are zero-padded; longer sequences are truncated.
pub const BEACON_INPUT_LEN: usize = 128;

/// Input features for the beaconing detector.
///
/// Provide the sorted inter-arrival times (seconds) between consecutive
/// connections from a single source IP to a single destination IP over the
/// observation window. At least [`MIN_SAMPLES`] (`3`) values are required;
/// fewer than that produces an immediate `Ok(0.0)` without calling ONNX.
#[derive(Debug, Clone)]
pub struct BeaconingFeatures {
    /// Inter-arrival times in seconds between consecutive connections.
    /// Minimum 3 values; values beyond the first 128 are ignored.
    pub inter_arrival_secs: Vec<f32>,
}

/// FFT-based beaconing detector.
///
/// Wraps the `beaconing_detector.onnx` model. Input shape: `[1, 128]`.
/// Output shape: `[1, 1]` — a single f32 beaconing score in `0.0–1.0`.
/// Scores above `0.7` indicate a probable C2 beacon candidate.
pub struct BeaconingDetector {
    session: OnnxSession,
}

/// Threshold above which a beaconing score is flagged as C2.
pub const BEACONING_THRESHOLD: f32 = 0.7;

impl BeaconingDetector {
    /// Load the beaconing detector model from the given path.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::ModelNotFound`] if the model file does not exist.
    /// Returns [`AiError::ModelLoad`] if the ONNX Runtime fails to load it.
    pub fn load(model_path: &Path) -> Result<Self, AiError> {
        let session = OnnxSession::load(model_path, "beaconing")?;
        Ok(Self { session })
    }

    /// Detect beaconing behavior and return a score in `0.0–1.0`.
    ///
    /// If fewer than 3 inter-arrival samples are provided, returns `Ok(0.0)`
    /// immediately without invoking ONNX (insufficient data).
    ///
    /// The input vector is zero-padded or truncated to exactly 128 elements
    /// before being passed to the model.
    ///
    /// A returned score above [`BEACONING_THRESHOLD`] (`0.7`) indicates a
    /// probable C2 beacon candidate.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::Inference`] if ONNX Runtime fails during inference.
    /// Returns [`AiError::InvalidOutput`] if the model returns no output values.
    pub fn detect(&self, features: &BeaconingFeatures) -> Result<f32, AiError> {
        if features.inter_arrival_secs.len() < MIN_SAMPLES {
            return Ok(0.0);
        }

        let padded = pad_or_truncate(&features.inter_arrival_secs, BEACON_INPUT_LEN);
        let shape = [1_usize, BEACON_INPUT_LEN];
        let outputs = self.session.run_f32("input", &padded, &shape)?;

        match outputs.first() {
            Some(&score) => Ok(score.clamp(0.0, 1.0)),
            None => Err(AiError::InvalidOutput {
                expected: 1,
                got: 0,
            }),
        }
    }
}

/// Pad a slice with zeros or truncate it to exactly `target_len` elements.
fn pad_or_truncate(src: &[f32], target_len: usize) -> Vec<f32> {
    let mut out = Vec::with_capacity(target_len);
    out.extend(src.iter().take(target_len).copied());
    out.resize(target_len, 0.0_f32);
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_or_truncate_when_shorter_than_target_then_zero_padded() {
        let src = vec![1.0_f32, 2.0, 3.0];
        let out = pad_or_truncate(&src, 5);
        assert_eq!(out.len(), 5);
        assert_eq!(out, vec![1.0, 2.0, 3.0, 0.0, 0.0]);
    }

    #[test]
    fn test_pad_or_truncate_when_longer_than_target_then_truncated() {
        let src: Vec<f32> = (0..200).map(|i| i as f32).collect();
        let out = pad_or_truncate(&src, BEACON_INPUT_LEN);
        assert_eq!(out.len(), BEACON_INPUT_LEN);
        assert!((out[0] - 0.0_f32).abs() < f32::EPSILON);
        assert!((out[127] - 127.0_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn test_pad_or_truncate_when_exact_length_then_unchanged() {
        let src: Vec<f32> = (0..BEACON_INPUT_LEN as i32).map(|i| i as f32).collect();
        let out = pad_or_truncate(&src, BEACON_INPUT_LEN);
        assert_eq!(out, src);
    }

    /// Requires model file at `/var/lib/kron/models/beaconing_detector.onnx`.
    #[test]
    #[ignore = "requires ONNX model file at /var/lib/kron/models/beaconing_detector.onnx"]
    fn test_score_when_model_loaded_then_returns_valid_range() {
        let path = std::path::Path::new("/var/lib/kron/models/beaconing_detector.onnx");
        let detector = BeaconingDetector::load(path).expect("model must load");
        let features = BeaconingFeatures {
            inter_arrival_secs: vec![60.0, 60.1, 59.9, 60.2, 60.0],
        };
        let score = detector.detect(&features).expect("inference must succeed");
        assert!((0.0_f32..=1.0_f32).contains(&score));
    }
}
