//! Prometheus metrics helpers for the `kron-ai` inference subsystem.
//!
//! All metrics are registered using the [`metrics`] crate and exported via
//! the workspace-wide Prometheus exporter configured in `kron-query-api`.

use metrics::{counter, histogram};

/// Record the latency of a single inference call in milliseconds.
///
/// # Arguments
/// * `model`  — short name of the model (e.g. `"anomaly"`, `"exfil"`).
/// * `ms`     — elapsed wall-clock time for the inference call.
pub fn record_inference_latency_ms(model: &str, ms: u64) {
    // Precision loss is acceptable: latency histograms do not require
    // sub-millisecond accuracy and u64 values fit within f64 up to 2^53.
    #[allow(clippy::cast_precision_loss)]
    let ms_f64 = ms as f64;
    histogram!("kron_ai_inference_latency_ms", "model" => model.to_owned()).record(ms_f64);
}

/// Increment the inference error counter for the given model.
///
/// # Arguments
/// * `model` — short name of the model that produced the error.
pub fn record_inference_error(model: &str) {
    counter!("kron_ai_inference_errors_total", "model" => model.to_owned()).increment(1);
}

/// Record that a model was successfully loaded (or hot-reloaded).
///
/// # Arguments
/// * `model` — short name of the model that was loaded.
pub fn record_model_loaded(model: &str) {
    counter!("kron_ai_models_loaded_total", "model" => model.to_owned()).increment(1);
}

/// Increment the counter of events that exceeded a detection threshold.
pub fn record_flagged_event() {
    counter!("kron_ai_flagged_events_total").increment(1);
}
