//! Typed AST for validated SIGMA rules.
//!
//! [`SigmaRule`] is the canonical in-memory representation of a SIGMA rule
//! after parsing and validation. Use [`SigmaRule::from_raw`] to convert a
//! deserialized [`super::types::SigmaRuleRaw`] into this form.

use std::collections::HashMap;

use uuid::Uuid;

use kron_types::enums::Severity;

use crate::error::StreamError;
use crate::sigma::condition::parse_condition;
use crate::sigma::types::{DetectionRaw, SigmaRuleRaw};

/// A validated SIGMA detection rule.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    /// Unique rule identifier (UUID v4).
    pub id: Uuid,
    /// Human-readable title.
    pub title: String,
    /// Lifecycle status of the rule.
    pub status: RuleStatus,
    /// Description of what the rule detects.
    pub description: String,
    /// All tags from the rule (ATT&CK, custom, etc.).
    pub tags: Vec<String>,
    /// Extracted MITRE tactic names (e.g. `persistence`).
    pub mitre_tactics: Vec<String>,
    /// Extracted MITRE technique IDs (e.g. `t1059`, `t1059.001`).
    pub mitre_techniques: Vec<String>,
    /// Log source selector.
    pub logsource: LogSource,
    /// Parsed and validated detection logic.
    pub detection: Detection,
    /// Severity level derived from the `level` field.
    pub severity: Severity,
    /// Known benign scenarios that may cause false positives.
    pub falsepositives: Vec<String>,
}

/// Lifecycle status of a SIGMA rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleStatus {
    /// Rule is production-ready and well-tested.
    Stable,
    /// Rule is in testing — may have higher FP rate.
    Test,
    /// Rule is experimental — not yet validated.
    Experimental,
    /// Rule is deprecated and should not be used.
    Deprecated,
    /// Rule is not supported by this engine version.
    Unsupported,
}

/// Log source selector that scopes which events a rule applies to.
#[derive(Debug, Clone)]
pub struct LogSource {
    /// Event category (e.g. `process_creation`).
    pub category: Option<String>,
    /// Target product (e.g. `windows`).
    pub product: Option<String>,
    /// Target service (e.g. `sysmon`).
    pub service: Option<String>,
}

/// Parsed detection block.
#[derive(Debug, Clone)]
pub struct Detection {
    /// Named selections mapping selection name → `Selection`.
    pub selections: HashMap<String, Selection>,
    /// The parsed condition expression tree.
    pub condition: ConditionExpr,
    /// Optional time window in seconds (for aggregation conditions).
    pub timeframe_secs: Option<u64>,
}

/// A named selection within a detection block.
#[derive(Debug, Clone)]
pub enum Selection {
    /// List of keywords — match if ANY keyword appears in the raw event.
    Keywords(Vec<String>),
    /// One or more field filter groups — match if ANY group matches (OR).
    /// Within a group ALL filters must match (AND).
    FieldGroups(Vec<FieldFilterGroup>),
}

/// A group of field filters where all must match (implicit AND).
#[derive(Debug, Clone)]
pub struct FieldFilterGroup {
    /// All filters in this group — ALL must match.
    pub filters: Vec<FieldFilter>,
}

/// A single field filter: field name, modifier, and values to compare.
#[derive(Debug, Clone)]
pub struct FieldFilter {
    /// SIGMA field name (e.g. `CommandLine`, `Image`).
    pub field: String,
    /// How the value should be compared.
    pub modifier: FieldModifier,
    /// Values to compare against (OR semantics unless `ContainsAll` or `All`).
    pub values: Vec<FilterValue>,
}

/// How a field value is compared in a filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldModifier {
    /// Case-insensitive exact equality.
    Exact,
    /// Case-insensitive substring match (OR across values).
    Contains,
    /// All values must be present as substrings.
    ContainsAll,
    /// Case-insensitive prefix match.
    StartsWith,
    /// Case-insensitive suffix match.
    EndsWith,
    /// Regular expression match.
    Re,
    /// CIDR subnet membership.
    Cidr,
    /// Numeric greater-than.
    Gt,
    /// Numeric greater-than-or-equal.
    Gte,
    /// Numeric less-than.
    Lt,
    /// Numeric less-than-or-equal.
    Lte,
    /// All values in the list must match.
    All,
}

/// A concrete value used in a filter comparison.
#[derive(Debug, Clone)]
pub enum FilterValue {
    /// Explicit null — matches absent or null fields.
    Null,
    /// Integer value.
    Int(i64),
    /// Floating-point value.
    Float(f64),
    /// String value (may contain SIGMA wildcards `*` and `?`).
    Text(String),
}

/// Parsed condition expression tree.
#[derive(Debug, Clone)]
pub enum ConditionExpr {
    /// Reference to a named selection.
    Selection(String),
    /// Logical negation.
    Not(Box<ConditionExpr>),
    /// Logical conjunction.
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    /// Logical disjunction.
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    /// `1 of <pattern>` — any selection whose name matches the glob must match.
    OneOf(String),
    /// `all of <pattern>` — all selections whose names match the glob must match.
    AllOf(String),
    /// `<expr> | count() > N` — aggregation condition (always false in real-time mode).
    Count {
        /// The base expression to aggregate over.
        expr: Box<ConditionExpr>,
        /// Comparison operator.
        op: CmpOp,
        /// Count threshold.
        threshold: u64,
    },
    /// `near <expr>` — temporal proximity (simplified; always false in real-time mode).
    Near(Box<ConditionExpr>),
}

/// Comparison operator used in aggregation conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmpOp {
    /// Greater-than.
    Gt,
    /// Greater-than-or-equal.
    Gte,
    /// Less-than.
    Lt,
    /// Less-than-or-equal.
    Lte,
    /// Equal.
    Eq,
}

impl SigmaRule {
    /// Converts a raw deserialized SIGMA rule into a validated [`SigmaRule`].
    ///
    /// Generates a UUID if the rule has no `id` field. Extracts MITRE
    /// tactic and technique tags. Parses the condition string into a
    /// [`ConditionExpr`] tree.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::SigmaParse`] if the rule ID is present but
    /// not a valid UUID, or [`StreamError::InvalidCondition`] if the
    /// condition string cannot be parsed.
    pub fn from_raw(raw: SigmaRuleRaw) -> Result<Self, StreamError> {
        let id = parse_rule_id(raw.id.as_deref(), &raw.title)?;
        let id_str = id.to_string();

        let status = parse_status(raw.status.as_deref());
        let severity = parse_severity(raw.level.as_deref());

        let tags = raw.tags.unwrap_or_default();
        let (mitre_tactics, mitre_techniques) = extract_mitre_tags(&tags);

        let detection = parse_detection(raw.detection, &id_str)?;

        Ok(Self {
            id,
            title: raw.title,
            status,
            description: raw.description.unwrap_or_default(),
            tags,
            mitre_tactics,
            mitre_techniques,
            logsource: LogSource {
                category: raw.logsource.category,
                product: raw.logsource.product,
                service: raw.logsource.service,
            },
            detection,
            severity,
            falsepositives: raw.falsepositives.unwrap_or_default(),
        })
    }
}

/// Parses the optional rule ID string into a [`Uuid`].
///
/// If `id` is `None`, generates a new UUID v4.
/// If `id` is `Some` but not a valid UUID, returns an error with the rule title.
fn parse_rule_id(id: Option<&str>, title: &str) -> Result<Uuid, StreamError> {
    match id {
        None => Ok(Uuid::new_v4()),
        Some(s) => Uuid::parse_str(s).map_err(|e| StreamError::SigmaParse {
            file: std::path::PathBuf::from(title),
            reason: format!("invalid UUID '{s}': {e}"),
        }),
    }
}

/// Converts a raw status string to [`RuleStatus`].
///
/// Defaults to `Experimental` for unknown values.
fn parse_status(status: Option<&str>) -> RuleStatus {
    match status {
        Some("stable") => RuleStatus::Stable,
        Some("test") => RuleStatus::Test,
        Some("deprecated") => RuleStatus::Deprecated,
        Some("unsupported") => RuleStatus::Unsupported,
        _ => RuleStatus::Experimental,
    }
}

/// Converts a raw level string to [`Severity`].
///
/// Defaults to `Info` for unknown or absent values.
fn parse_severity(level: Option<&str>) -> Severity {
    match level {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        _ => Severity::Info,
    }
}

/// Extracts MITRE tactic and technique tags from the raw tag list.
///
/// Tactics look like `attack.persistence`, `attack.lateral_movement`.
/// Techniques look like `attack.t1059`, `attack.t1059.001`.
fn extract_mitre_tags(tags: &[String]) -> (Vec<String>, Vec<String>) {
    let mut tactics = Vec::new();
    let mut techniques = Vec::new();

    for tag in tags {
        let lower = tag.to_lowercase();
        if let Some(rest) = lower.strip_prefix("attack.") {
            // Technique IDs start with 't' followed by digits.
            if rest.starts_with('t') && rest.chars().nth(1).is_some_and(char::is_numeric) {
                techniques.push(rest.to_string());
            } else {
                tactics.push(rest.to_string());
            }
        }
    }

    (tactics, techniques)
}

/// Parses the raw detection block into a typed [`Detection`].
fn parse_detection(raw: DetectionRaw, rule_id: &str) -> Result<Detection, StreamError> {
    let timeframe_secs = raw.timeframe.as_deref().and_then(parse_timeframe);
    let condition = parse_condition(&raw.condition, rule_id)?;

    let mut selections = HashMap::new();

    for (name, value) in raw.selections {
        // Skip meta-fields that SIGMA puts in the flattened map.
        if name == "condition" || name == "timeframe" {
            continue;
        }
        let selection = parse_selection_value(&value);
        selections.insert(name, selection);
    }

    Ok(Detection {
        selections,
        condition,
        timeframe_secs,
    })
}

/// Parses a SIGMA timeframe string (e.g. `5m`, `1h`, `30s`) into seconds.
///
/// Returns `None` if the string cannot be parsed.
fn parse_timeframe(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (digits, unit) = s.split_at(s.len() - 1);
    let n: u64 = digits.parse().ok()?;

    match unit {
        "s" => Some(n),
        "m" => Some(n * 60),
        "h" => Some(n * 3600),
        "d" => Some(n * 86400),
        _ => None,
    }
}

/// Converts a raw YAML selection value into a typed [`Selection`].
fn parse_selection_value(value: &serde_yaml::Value) -> Selection {
    match value {
        // A YAML sequence of strings is a keyword list.
        serde_yaml::Value::Sequence(seq) => {
            let keywords: Vec<String> = seq
                .iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect();
            Selection::Keywords(keywords)
        }
        // A YAML mapping is one field-filter group.
        serde_yaml::Value::Mapping(map) => {
            let group = parse_field_filter_group(map);
            Selection::FieldGroups(vec![group])
        }
        // Anything else — treat as empty keywords.
        _ => Selection::Keywords(Vec::new()),
    }
}

/// Converts a YAML mapping into a [`FieldFilterGroup`].
fn parse_field_filter_group(map: &serde_yaml::Mapping) -> FieldFilterGroup {
    let mut filters = Vec::new();

    for (k, v) in map {
        let Some(key_str) = k.as_str() else { continue };
        let (field, modifier) = parse_field_key(key_str);
        let values = parse_filter_values(v);
        filters.push(FieldFilter {
            field,
            modifier,
            values,
        });
    }

    FieldFilterGroup { filters }
}

/// Splits a SIGMA field key like `CommandLine|contains|all` into `(field, modifier)`.
fn parse_field_key(key: &str) -> (String, FieldModifier) {
    let parts: Vec<&str> = key.split('|').collect();
    let field = parts[0].to_string();

    let modifier = if parts.len() == 1 {
        FieldModifier::Exact
    } else {
        // Handle compound modifiers like `contains|all`.
        let mod_parts = &parts[1..];
        parse_modifier(mod_parts)
    };

    (field, modifier)
}

/// Converts modifier string parts to a [`FieldModifier`].
fn parse_modifier(parts: &[&str]) -> FieldModifier {
    match parts {
        ["contains", "all"] | ["all", "contains"] => FieldModifier::ContainsAll,
        ["contains"] => FieldModifier::Contains,
        ["startswith"] => FieldModifier::StartsWith,
        ["endswith"] => FieldModifier::EndsWith,
        ["re"] => FieldModifier::Re,
        ["cidr"] => FieldModifier::Cidr,
        ["gt"] => FieldModifier::Gt,
        ["gte"] => FieldModifier::Gte,
        ["lt"] => FieldModifier::Lt,
        ["lte"] => FieldModifier::Lte,
        ["all"] => FieldModifier::All,
        _ => FieldModifier::Exact,
    }
}

/// Converts a YAML value into a list of [`FilterValue`]s.
///
/// A scalar becomes a single-element list. A sequence becomes multiple values.
fn parse_filter_values(v: &serde_yaml::Value) -> Vec<FilterValue> {
    match v {
        serde_yaml::Value::Sequence(seq) => seq.iter().map(yaml_to_filter_value).collect(),
        other => vec![yaml_to_filter_value(other)],
    }
}

/// Converts a single YAML scalar to a [`FilterValue`].
fn yaml_to_filter_value(v: &serde_yaml::Value) -> FilterValue {
    match v {
        serde_yaml::Value::Null => FilterValue::Null,
        serde_yaml::Value::Bool(b) => FilterValue::Text(b.to_string()),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                FilterValue::Int(i)
            } else if let Some(f) = n.as_f64() {
                FilterValue::Float(f)
            } else {
                FilterValue::Text(n.to_string())
            }
        }
        serde_yaml::Value::String(s) => FilterValue::Text(s.clone()),
        _ => FilterValue::Text(String::new()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sigma::types::{DetectionRaw, LogSourceRaw, SigmaRuleRaw};

    fn make_minimal_raw(condition: &str) -> SigmaRuleRaw {
        let mut selections = std::collections::HashMap::new();
        selections.insert(
            "sel".to_string(),
            serde_yaml::Value::Mapping({
                let mut m = serde_yaml::Mapping::new();
                m.insert(
                    serde_yaml::Value::String("CommandLine".to_string()),
                    serde_yaml::Value::String("powershell".to_string()),
                );
                m
            }),
        );

        SigmaRuleRaw {
            title: "Test Rule".to_string(),
            id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            status: Some("stable".to_string()),
            description: Some("Test description".to_string()),
            references: None,
            tags: Some(vec![
                "attack.execution".to_string(),
                "attack.t1059.001".to_string(),
            ]),
            author: None,
            date: None,
            modified: None,
            logsource: LogSourceRaw {
                category: Some("process_creation".to_string()),
                product: Some("windows".to_string()),
                service: None,
            },
            detection: DetectionRaw {
                condition: condition.to_string(),
                timeframe: None,
                selections,
            },
            fields: None,
            falsepositives: Some(vec!["Legitimate scripts".to_string()]),
            level: Some("high".to_string()),
        }
    }

    #[test]
    fn test_from_raw_when_valid_rule_then_parses_correctly() {
        let raw = make_minimal_raw("sel");
        let rule = SigmaRule::from_raw(raw).expect("should parse");

        assert_eq!(rule.title, "Test Rule");
        assert_eq!(rule.status, RuleStatus::Stable);
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.description, "Test description");
        assert_eq!(rule.falsepositives.len(), 1);
        assert_eq!(rule.logsource.category.as_deref(), Some("process_creation"));
    }

    #[test]
    fn test_from_raw_when_mitre_tags_present_then_extracted() {
        let raw = make_minimal_raw("sel");
        let rule = SigmaRule::from_raw(raw).expect("should parse");

        assert!(
            rule.mitre_tactics.contains(&"execution".to_string()),
            "tactics: {:?}",
            rule.mitre_tactics
        );
        assert!(
            rule.mitre_techniques.contains(&"t1059.001".to_string()),
            "techniques: {:?}",
            rule.mitre_techniques
        );
    }

    #[test]
    fn test_from_raw_when_missing_id_then_generates_uuid() {
        let mut raw = make_minimal_raw("sel");
        raw.id = None;
        let rule = SigmaRule::from_raw(raw).expect("should parse");

        // UUID should be non-nil (newly generated).
        assert_ne!(rule.id, Uuid::nil());
    }
}
