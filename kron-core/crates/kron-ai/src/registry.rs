//! Model registry with atomic hot-reload support.
//!
//! [`ModelRegistry`] holds loaded ONNX model instances behind `Arc<RwLock<_>>`
//! so that new model files can be promoted atomically in the background while
//! ongoing inference continues with the previous version.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::instrument;

use crate::error::AiError;
use crate::metrics;
use crate::onnx::anomaly::AnomalyScorer;
use crate::onnx::beaconing::BeaconingDetector;
use crate::onnx::exfil::ExfilScorer;
use crate::onnx::ueba::UebaClassifier;

/// Registry that holds all loaded ONNX models.
///
/// Each model slot is individually addressable and independently reloadable.
/// Missing model files are silently skipped — the system operates with any
/// combination of 0–4 models loaded. Consumers receive `None` for unloaded
/// models and simply skip inference for those scores.
pub struct ModelRegistry {
    anomaly: Arc<RwLock<Option<Arc<AnomalyScorer>>>>,
    ueba: Arc<RwLock<Option<Arc<UebaClassifier>>>>,
    beaconing: Arc<RwLock<Option<Arc<BeaconingDetector>>>>,
    exfil: Arc<RwLock<Option<Arc<ExfilScorer>>>>,
    models_dir: PathBuf,
}

impl ModelRegistry {
    /// Expected filename for the Isolation Forest anomaly model.
    pub const ANOMALY_FILE: &'static str = "anomaly_isolation_forest.onnx";
    /// Expected filename for the UEBA `XGBoost` model.
    pub const UEBA_FILE: &'static str = "ueba_xgboost.onnx";
    /// Expected filename for the beaconing detector model.
    pub const BEACONING_FILE: &'static str = "beaconing_detector.onnx";
    /// Expected filename for the exfiltration scorer model.
    pub const EXFIL_FILE: &'static str = "exfil_scorer.onnx";

    /// Create a new registry pointing at the given models directory.
    ///
    /// No models are loaded at construction time; call [`Self::load_all`]
    /// to load all present model files.
    #[must_use]
    pub fn new(models_dir: PathBuf) -> Self {
        Self {
            anomaly: Arc::new(RwLock::new(None)),
            ueba: Arc::new(RwLock::new(None)),
            beaconing: Arc::new(RwLock::new(None)),
            exfil: Arc::new(RwLock::new(None)),
            models_dir,
        }
    }

    /// Load all models found in the models directory.
    ///
    /// Each model is attempted in a separate `spawn_blocking` task because
    /// ONNX model compilation is CPU-intensive. Models whose files are absent
    /// are silently skipped. On a load error (corrupt file, ABI mismatch, etc.)
    /// the error is logged at `warn` level and the slot remains `None`.
    ///
    /// Returns the list of model names that were successfully loaded.
    #[instrument(skip(self), fields(models_dir = %self.models_dir.display()))]
    pub async fn load_all(&self) -> Vec<String> {
        let mut loaded = Vec::new();

        if let Some(name) = self.load_anomaly().await {
            loaded.push(name);
        }
        if let Some(name) = self.load_ueba().await {
            loaded.push(name);
        }
        if let Some(name) = self.load_beaconing().await {
            loaded.push(name);
        }
        if let Some(name) = self.load_exfil().await {
            loaded.push(name);
        }

        tracing::info!(
            loaded_count = loaded.len(),
            models = ?loaded,
            "model registry load_all complete"
        );
        loaded
    }

    /// Hot-reload a specific model by name.
    ///
    /// Supported names: `"anomaly"`, `"ueba"`, `"beaconing"`, `"exfil"`.
    /// The new model is loaded in a blocking thread and promoted atomically;
    /// in-flight inference using the old model completes unaffected.
    ///
    /// # Errors
    ///
    /// Returns [`AiError::ModelNotFound`] if the file is absent.
    /// Returns [`AiError::ModelLoad`] if the ONNX Runtime rejects the file.
    /// Returns [`AiError::Inference`] with `reason = "unknown model name"` if
    /// the supplied name is not one of the four supported values.
    #[instrument(skip(self), fields(model = %model_name))]
    pub async fn reload(&self, model_name: &str) -> Result<(), AiError> {
        match model_name {
            "anomaly" => self
                .load_anomaly()
                .await
                .map(|_| ())
                .ok_or_else(|| AiError::ModelLoad {
                    path: self
                        .models_dir
                        .join(Self::ANOMALY_FILE)
                        .to_string_lossy()
                        .into_owned(),
                    reason: "reload failed — see logs for details".to_owned(),
                }),
            "ueba" => self
                .load_ueba()
                .await
                .map(|_| ())
                .ok_or_else(|| AiError::ModelLoad {
                    path: self
                        .models_dir
                        .join(Self::UEBA_FILE)
                        .to_string_lossy()
                        .into_owned(),
                    reason: "reload failed — see logs for details".to_owned(),
                }),
            "beaconing" => {
                self.load_beaconing()
                    .await
                    .map(|_| ())
                    .ok_or_else(|| AiError::ModelLoad {
                        path: self
                            .models_dir
                            .join(Self::BEACONING_FILE)
                            .to_string_lossy()
                            .into_owned(),
                        reason: "reload failed — see logs for details".to_owned(),
                    })
            }
            "exfil" => self
                .load_exfil()
                .await
                .map(|_| ())
                .ok_or_else(|| AiError::ModelLoad {
                    path: self
                        .models_dir
                        .join(Self::EXFIL_FILE)
                        .to_string_lossy()
                        .into_owned(),
                    reason: "reload failed — see logs for details".to_owned(),
                }),
            other => Err(AiError::Inference {
                model: other.to_owned(),
                reason: "unknown model name".to_owned(),
            }),
        }
    }

    /// Get the anomaly scorer if it has been loaded.
    pub async fn anomaly(&self) -> Option<Arc<AnomalyScorer>> {
        self.anomaly.read().await.clone()
    }

    /// Get the UEBA classifier if it has been loaded.
    pub async fn ueba(&self) -> Option<Arc<UebaClassifier>> {
        self.ueba.read().await.clone()
    }

    /// Get the beaconing detector if it has been loaded.
    pub async fn beaconing(&self) -> Option<Arc<BeaconingDetector>> {
        self.beaconing.read().await.clone()
    }

    /// Get the exfiltration scorer if it has been loaded.
    pub async fn exfil(&self) -> Option<Arc<ExfilScorer>> {
        self.exfil.read().await.clone()
    }

    // --- Private loading helpers ---

    /// Attempt to load the anomaly model, returning its name on success.
    async fn load_anomaly(&self) -> Option<String> {
        let path = self.models_dir.join(Self::ANOMALY_FILE);
        let slot = Arc::clone(&self.anomaly);
        match tokio::task::spawn_blocking(move || AnomalyScorer::load(&path)).await {
            Ok(Ok(model)) => {
                *slot.write().await = Some(Arc::new(model));
                metrics::record_model_loaded("anomaly");
                tracing::info!("anomaly model loaded");
                Some("anomaly".to_owned())
            }
            Ok(Err(AiError::ModelNotFound { path: p })) => {
                tracing::debug!(path = %p, "anomaly model file not present — skipping");
                None
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "anomaly model load failed");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawn_blocking panicked loading anomaly model");
                None
            }
        }
    }

    /// Attempt to load the UEBA model, returning its name on success.
    async fn load_ueba(&self) -> Option<String> {
        let path = self.models_dir.join(Self::UEBA_FILE);
        let slot = Arc::clone(&self.ueba);
        match tokio::task::spawn_blocking(move || UebaClassifier::load(&path)).await {
            Ok(Ok(model)) => {
                *slot.write().await = Some(Arc::new(model));
                metrics::record_model_loaded("ueba");
                tracing::info!("ueba model loaded");
                Some("ueba".to_owned())
            }
            Ok(Err(AiError::ModelNotFound { path: p })) => {
                tracing::debug!(path = %p, "ueba model file not present — skipping");
                None
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "ueba model load failed");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawn_blocking panicked loading ueba model");
                None
            }
        }
    }

    /// Attempt to load the beaconing model, returning its name on success.
    async fn load_beaconing(&self) -> Option<String> {
        let path = self.models_dir.join(Self::BEACONING_FILE);
        let slot = Arc::clone(&self.beaconing);
        match tokio::task::spawn_blocking(move || BeaconingDetector::load(&path)).await {
            Ok(Ok(model)) => {
                *slot.write().await = Some(Arc::new(model));
                metrics::record_model_loaded("beaconing");
                tracing::info!("beaconing model loaded");
                Some("beaconing".to_owned())
            }
            Ok(Err(AiError::ModelNotFound { path: p })) => {
                tracing::debug!(path = %p, "beaconing model file not present — skipping");
                None
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "beaconing model load failed");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawn_blocking panicked loading beaconing model");
                None
            }
        }
    }

    /// Attempt to load the exfiltration scorer model, returning its name on success.
    async fn load_exfil(&self) -> Option<String> {
        let path = self.models_dir.join(Self::EXFIL_FILE);
        let slot = Arc::clone(&self.exfil);
        match tokio::task::spawn_blocking(move || ExfilScorer::load(&path)).await {
            Ok(Ok(model)) => {
                *slot.write().await = Some(Arc::new(model));
                metrics::record_model_loaded("exfil");
                tracing::info!("exfil model loaded");
                Some("exfil".to_owned())
            }
            Ok(Err(AiError::ModelNotFound { path: p })) => {
                tracing::debug!(path = %p, "exfil model file not present — skipping");
                None
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "exfil model load failed");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawn_blocking panicked loading exfil model");
                None
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_all_when_no_models_present_then_returns_empty_list() {
        let dir = std::env::temp_dir().join("kron_ai_test_empty");
        let registry = ModelRegistry::new(dir);
        let loaded = registry.load_all().await;
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn test_anomaly_when_not_loaded_then_returns_none() {
        let registry = ModelRegistry::new(std::env::temp_dir());
        assert!(registry.anomaly().await.is_none());
    }

    #[tokio::test]
    async fn test_reload_when_unknown_model_name_then_returns_error() {
        let registry = ModelRegistry::new(std::env::temp_dir());
        let result = registry.reload("nonexistent_model").await;
        assert!(result.is_err());
    }
}
