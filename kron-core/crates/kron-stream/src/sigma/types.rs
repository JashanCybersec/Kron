//! Raw YAML-deserializable SIGMA rule types.
//!
//! These types are used only for deserialization from YAML. After parsing,
//! [`super::ast::SigmaRule::from_raw`] converts them to the validated AST.

use std::collections::HashMap;

use serde::Deserialize;

/// Raw SIGMA rule as deserialized directly from a YAML file.
///
/// All fields are `Option` where the SIGMA spec allows omission.
/// Validation and normalization happen in [`super::ast::SigmaRule::from_raw`].
#[derive(Debug, Deserialize)]
pub struct SigmaRuleRaw {
    /// Human-readable title of the rule.
    pub title: String,
    /// UUID string identifying the rule. Generated if absent.
    pub id: Option<String>,
    /// Lifecycle status: experimental, test, stable, deprecated, unsupported.
    pub status: Option<String>,
    /// Human-readable description of what the rule detects.
    pub description: Option<String>,
    /// External references (URLs, CVEs, etc.).
    pub references: Option<Vec<String>>,
    /// MITRE ATT&CK and other tags (e.g. `attack.t1059.001`).
    pub tags: Option<Vec<String>>,
    /// Rule author name or email.
    pub author: Option<String>,
    /// Creation date (ISO 8601 string).
    pub date: Option<String>,
    /// Last modified date (ISO 8601 string).
    pub modified: Option<String>,
    /// Log source selector that determines which events this rule applies to.
    pub logsource: LogSourceRaw,
    /// Detection logic: named selections plus a condition string.
    pub detection: DetectionRaw,
    /// Field names relevant for investigation context.
    pub fields: Option<Vec<String>>,
    /// Known benign scenarios that may trigger this rule.
    pub falsepositives: Option<Vec<String>>,
    /// Severity level: informational, low, medium, high, critical.
    pub level: Option<String>,
}

/// Raw log source selector from a SIGMA rule.
#[derive(Debug, Deserialize)]
pub struct LogSourceRaw {
    /// Event category (e.g. `process_creation`, `network_connection`).
    pub category: Option<String>,
    /// Target product (e.g. `windows`, `linux`, `aws`).
    pub product: Option<String>,
    /// Target service (e.g. `security`, `sysmon`, `auditd`).
    pub service: Option<String>,
}

/// Raw detection block from a SIGMA rule.
///
/// The `condition` field is the mandatory boolean expression over selection
/// names. All other keys (except `timeframe`) are named selections whose
/// values can be field-filter maps or keyword lists.
#[derive(Debug, Deserialize)]
pub struct DetectionRaw {
    /// Boolean expression combining selection names (e.g. `sel1 and not sel2`).
    pub condition: String,
    /// Optional time window for aggregation conditions (e.g. `5m`).
    pub timeframe: Option<String>,
    /// Named selections — key is selection name, value is a field map or list.
    #[serde(flatten)]
    pub selections: HashMap<String, serde_yaml::Value>,
}
