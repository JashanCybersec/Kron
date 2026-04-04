//! ONNX Runtime session management.
//!
//! Provides [`OnnxSession`], a thin wrapper around an `ort` [`Session`] that
//! abstracts model loading and f32 tensor inference behind a simple API used
//! by all model wrappers in this crate.
//!
//! The inner [`Session`] is wrapped in a [`std::sync::Mutex`] because
//! `Session::run` requires `&mut self` but model wrappers are shared via
//! `Arc<Model>` across `spawn_blocking` calls.

use std::ops::Index;
use std::path::Path;
use std::sync::Mutex;

use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::TensorRef;

use crate::error::AiError;

/// A loaded ONNX model session.
///
/// Wraps an `ort` [`Session`] behind a [`Mutex`] to allow concurrent access
/// from `Arc`-shared model wrappers. Model loading is performed via
/// [`OnnxSession::load`].
pub struct OnnxSession {
    session: Mutex<Session>,
    model_name: String,
}

impl OnnxSession {
    /// Load an ONNX model from the given filesystem path.
    ///
    /// Uses `GraphOptimizationLevel::Level3` (maximum optimization).
    /// This is CPU-intensive; callers should wrap in
    /// `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::ModelNotFound`] if the file does not exist.
    /// Returns [`AiError::ModelLoad`] if the ONNX Runtime fails to parse
    /// or compile the model.
    pub fn load(path: &Path, model_name: &str) -> Result<Self, AiError> {
        if !path.exists() {
            return Err(AiError::ModelNotFound {
                path: path.to_string_lossy().into_owned(),
            });
        }

        let session = Session::builder()
            .map_err(|e| AiError::ModelLoad {
                path: path.to_string_lossy().into_owned(),
                reason: e.to_string(),
            })?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| AiError::ModelLoad {
                path: path.to_string_lossy().into_owned(),
                reason: e.to_string(),
            })?
            .commit_from_file(path)
            .map_err(|e| AiError::ModelLoad {
                path: path.to_string_lossy().into_owned(),
                reason: e.to_string(),
            })?;

        Ok(Self {
            session: Mutex::new(session),
            model_name: model_name.to_owned(),
        })
    }

    /// Run inference with a flat f32 input slice and return the output values.
    ///
    /// Creates a tensor with the provided `shape`, runs the model, and
    /// extracts the first output as a `Vec<f32>`.
    ///
    /// # Arguments
    ///
    /// * `input_name` — Name of the model's input node (e.g. `"input"`).
    /// * `data`       — Flat row-major f32 slice of input features.
    /// * `shape`      — Tensor shape as a slice of `usize` (e.g. `&[1, 6]`).
    ///
    /// # Errors
    ///
    /// Returns [`AiError::Inference`] if the ONNX Runtime returns an error
    /// during tensor creation or the inference call itself.
    pub fn run_f32(
        &self,
        input_name: &str,
        data: &[f32],
        shape: &[usize],
    ) -> Result<Vec<f32>, AiError> {
        let tensor =
            TensorRef::<f32>::from_array_view((shape, data)).map_err(|e| AiError::Inference {
                model: self.model_name.clone(),
                reason: format!("tensor creation failed: {e}"),
            })?;

        let inputs = ort::inputs![input_name => tensor];

        let mut guard = self.session.lock().map_err(|e| AiError::Inference {
            model: self.model_name.clone(),
            reason: format!("session mutex poisoned: {e}"),
        })?;

        let outputs = guard.run(inputs).map_err(|e| AiError::Inference {
            model: self.model_name.clone(),
            reason: e.to_string(),
        })?;

        let first = outputs.index(0);
        let (_out_shape, values) =
            first
                .try_extract_tensor::<f32>()
                .map_err(|e| AiError::Inference {
                    model: self.model_name.clone(),
                    reason: format!("output extraction failed: {e}"),
                })?;

        let result: Vec<f32> = values.to_vec();
        Ok(result)
    }

    /// Returns the name registered for this session (used in error messages and metrics).
    #[must_use]
    pub fn model_name(&self) -> &str {
        &self.model_name
    }
}
