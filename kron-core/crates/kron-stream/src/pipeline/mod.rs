//! Detection pipeline — wires together IOC bloom filter, SIGMA rule engine,
//! and ONNX inference into a full per-event processing chain.
//!
//! # Module layout
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`risk_score`] | Composite risk-score formula (F-007) |
//! | [`mitre`]      | MITRE ATT&CK tag extraction from SIGMA rule tags |
//! | [`entity_graph`] | In-memory entity relationship graph |
//! | [`processor`]  | [`DetectionPipeline`] — the main pipeline entry-point |

pub mod entity_graph;
pub mod mitre;
pub mod processor;
pub mod risk_score;
