//! `XGBoost` UEBA (User and Entity Behavior Analytics) classifier ONNX wrapper.
//!
//! Classifies events against 30-day behavioral baselines to detect
//! credential-based insider threats. Inference target: <5 ms CPU.

use std::path::Path;

use crate::error::AiError;
use crate::onnx::session::OnnxSession;

/// Feature vector for UEBA baseline deviation scoring.
///
/// Each field represents the degree of deviation from the user's historical
/// 30-day behavioral baseline. Values closer to `0.0` indicate normal
/// behavior; values closer to `1.0` indicate extreme deviation.
#[derive(Debug, Clone)]
pub struct UebaFeatures {
    /// Deviation from 30-day baseline login hour.
    /// `0.0` = same time as usual, `1.0` = extreme hour deviation.
    pub login_hour_deviation: f32,
    /// Geographic deviation of the login origin.
    /// `0.0` = same country as usual, `1.0` = first-seen country.
    pub geo_deviation: f32,
    /// Device/host deviation.
    /// `0.0` = known enrolled device, `1.0` = never-seen device.
    pub device_deviation: f32,
    /// Data volume deviation: `log10(actual / baseline_avg)`.
    /// `0.0` = matches 30-day average, positive = volume spike.
    pub data_volume_deviation: f32,
}

impl UebaFeatures {
    /// Convert the feature struct to a flat f32 slice suitable for ONNX input.
    ///
    /// Order: `[login_hour_deviation, geo_deviation, device_deviation,
    ///          data_volume_deviation]`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.login_hour_deviation,
            self.geo_deviation,
            self.device_deviation,
            self.data_volume_deviation,
        ]
    }
}

/// `XGBoost` UEBA classifier.
///
/// Wraps the `ueba_xgboost.onnx` model. Input shape: `[1, 4]`.
/// Output shape: `[1, 1]` — a single f32 probability in `0.0–1.0`.
/// Probabilities above `0.8` are flagged as UEBA anomalies.
pub struct UebaClassifier {
    session: OnnxSession,
}

/// Threshold above which a UEBA probability triggers a flag.
pub const UEBA_THRESHOLD: f32 = 0.8;

/// Number of features expected by the UEBA model.
const FEATURE_COUNT: usize = 4;

impl UebaClassifier {
    /// Load the UEBA `XGBoost` model from the given path.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::ModelNotFound`] if the model file does not exist.
    /// Returns [`AiError::ModelLoad`] if the ONNX Runtime fails to load it.
    pub fn load(model_path: &Path) -> Result<Self, AiError> {
        let session = OnnxSession::load(model_path, "ueba")?;
        Ok(Self { session })
    }

    /// Run UEBA classification and return a behavioral anomaly probability.
    ///
    /// Returns a probability in the range `0.0–1.0`. Values above
    /// [`UEBA_THRESHOLD`] (`0.8`) indicate a UEBA flag.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::Inference`] if ONNX Runtime fails during inference.
    /// Returns [`AiError::InvalidOutput`] if the model returns no output values.
    pub fn classify(&self, features: &UebaFeatures) -> Result<f32, AiError> {
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
    fn test_ueba_features_to_vec_when_called_then_returns_four_elements() {
        let f = UebaFeatures {
            login_hour_deviation: 0.1,
            geo_deviation: 0.0,
            device_deviation: 0.0,
            data_volume_deviation: 0.2,
        };
        assert_eq!(f.to_vec().len(), FEATURE_COUNT);
    }

    /// Requires model file at `/var/lib/kron/models/ueba_xgboost.onnx`.
    #[test]
    #[ignore = "requires ONNX model file at /var/lib/kron/models/ueba_xgboost.onnx"]
    fn test_score_when_model_loaded_then_returns_valid_range() {
        let path = std::path::Path::new("/var/lib/kron/models/ueba_xgboost.onnx");
        let classifier = UebaClassifier::load(path).expect("model must load");
        let features = UebaFeatures {
            login_hour_deviation: 0.0,
            geo_deviation: 0.0,
            device_deviation: 0.0,
            data_volume_deviation: 0.0,
        };
        let prob = classifier
            .classify(&features)
            .expect("inference must succeed");
        assert!((0.0_f32..=1.0_f32).contains(&prob));
    }
}
