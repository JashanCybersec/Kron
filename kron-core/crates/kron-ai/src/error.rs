//! Error types for the `kron-ai` crate.

use thiserror::Error;

/// Errors that can occur in the KRON AI/ML inference subsystem.
#[derive(Debug, Error)]
pub enum AiError {
    /// An ONNX model could not be loaded from disk.
    #[error("ONNX model load failed: {path}: {reason}")]
    ModelLoad {
        /// Filesystem path where the model was expected.
        path: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// ONNX Runtime returned an error during inference.
    #[error("ONNX inference failed for model {model}: {reason}")]
    Inference {
        /// Name of the model that failed.
        model: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// Feature extraction could not be completed for a given event.
    #[error("feature extraction failed for event {event_id}: {reason}")]
    FeatureExtraction {
        /// ID of the event for which feature extraction failed.
        event_id: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// The model file does not exist at the expected path.
    #[error("model file not found at {path}")]
    ModelNotFound {
        /// Filesystem path where the model was expected.
        path: String,
    },

    /// The model produced an unexpected number of output values.
    #[error("invalid model output: expected {expected} values, got {got}")]
    InvalidOutput {
        /// Number of output values expected.
        expected: usize,
        /// Number of output values actually received.
        got: usize,
    },
}
