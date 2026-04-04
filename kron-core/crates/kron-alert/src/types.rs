//! Local mirror of `AlertCandidate` as serialized by `kron-stream`.
//!
//! Rather than depending on `kron-stream` from `kron-alert`, this module
//! defines a standalone struct that matches the JSON shape emitted by the
//! stream processor. Changes to `kron-stream`'s output format must be
//! reflected here.

use kron_types::{KronEvent, Severity};
use serde::{Deserialize, Serialize};

/// An alert candidate emitted by the stream processor over the bus.
///
/// Serialized as JSON to `kron.alerts.{tenant_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCandidate {
    /// The normalized event that triggered detection.
    pub event: KronEvent,
    /// Composite risk score (0–100) computed by the pipeline.
    pub risk_score: u8,
    /// Qualitative severity derived from `risk_score`.
    pub severity: Severity,
    /// SIGMA rules that matched this event.
    pub rule_matches: Vec<RuleMatch>,
    /// Whether the event matched an IOC in the bloom filter.
    pub ioc_hit: bool,
    /// The IOC type string (e.g. `"ip"`, `"domain"`), if an IOC hit occurred.
    pub ioc_type_str: Option<String>,
    /// ONNX isolation forest anomaly score (0.0–1.0), if scored.
    pub anomaly_score: Option<f32>,
    /// Raw MITRE ATT&CK tags extracted from matched rules.
    pub mitre_tags: Vec<MitreTagRaw>,
}

/// A single SIGMA rule match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// UUID string of the matched rule.
    pub rule_id: String,
    /// Human-readable title from the SIGMA rule.
    pub rule_title: String,
    /// Severity declared by the matched rule.
    pub severity: Severity,
    /// MITRE tactic names referenced in the rule tags.
    pub mitre_tactics: Vec<String>,
    /// MITRE technique IDs referenced in the rule tags.
    pub mitre_techniques: Vec<String>,
}

/// A raw MITRE ATT&CK tag as extracted from a SIGMA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTagRaw {
    /// MITRE tactic name (e.g. `"Lateral Movement"`).
    pub tactic: String,
    /// MITRE technique ID (e.g. `"T1021"`).
    pub technique_id: String,
    /// Optional sub-technique ID (e.g. `"T1021.001"`).
    pub sub_technique_id: Option<String>,
}
