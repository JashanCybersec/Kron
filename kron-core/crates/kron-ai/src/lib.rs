//! `kron-ai` — AI/ML inference for the KRON SIEM platform.
//!
//! All inference runs locally — no external AI API calls permitted (ADR-014).
//! Data sovereignty is a hard product requirement.
//!
//! # Models
//!
//! - Anomaly scorer: Isolation Forest ONNX — `KronEvent` → score 0–1
//! - UEBA classifier: `XGBoost` ONNX — deviation features → probability 0–1
//! - Beaconing detector: FFT ONNX — inter-arrival times → score 0–1
//! - Exfil scorer: `XGBoost` ONNX — volume features → probability 0–1
//!
//! # Zero-call guarantee (ADR-014)
//!
//! This crate has a test that verifies zero outbound HTTP calls during
//! inference. It must always pass — see `tests/integration/ai_no_outbound.rs`.
//!
//! # Module structure
//!
//! - [`onnx`]      — ONNX Runtime session management and model wrappers
//! - [`registry`]  — [`ModelRegistry`]: hot-reloadable model store
//! - [`inference`] — [`InferenceService`]: high-level per-event scoring
//! - [`metrics`]   — Prometheus metric helpers
//! - [`error`]     — [`AiError`] error enum

pub mod error;
pub mod inference;
pub mod metrics;
pub mod onnx;
pub mod registry;

pub use error::AiError;
pub use inference::{InferenceResult, InferenceService};
pub use onnx::anomaly::{AnomalyFeatures, AnomalyScorer};
pub use onnx::beaconing::{BeaconingDetector, BeaconingFeatures};
pub use onnx::exfil::{ExfilFeatures, ExfilScorer};
pub use onnx::ueba::{UebaClassifier, UebaFeatures};
pub use registry::ModelRegistry;
