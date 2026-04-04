//! ONNX model wrappers for the KRON AI inference subsystem.
//!
//! Each submodule wraps one ONNX model with typed feature structs and
//! strongly-typed inference methods. All models run locally via the
//! `ort` ONNX Runtime crate — no external API calls are made.
//!
//! # Submodules
//!
//! - [`session`] — shared ONNX Runtime session management
//! - [`anomaly`] — Isolation Forest anomaly scorer (6-feature)
//! - [`ueba`]    — `XGBoost` UEBA behavioral classifier (4-feature)
//! - [`beaconing`] — FFT beaconing detector (128-element IAT input)
//! - [`exfil`]   — exfiltration volume scorer (4-feature)

pub mod anomaly;
pub mod beaconing;
pub mod exfil;
pub mod session;
pub mod ueba;
