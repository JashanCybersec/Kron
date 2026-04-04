//! In-memory SIGMA rule matcher.
//!
//! [`EventMatcher`] evaluates a [`SigmaRule`] against a single [`KronEvent`]
//! without touching any database. This is used for real-time stream detection.
//!
//! Aggregation conditions (`count()`, `near`) always return `false` here — they
//! require historical data and are handled by the SQL compiler path.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

use regex::Regex;

use kron_types::event::KronEvent;

use crate::sigma::ast::{
    CmpOp, ConditionExpr, FieldFilter, FieldFilterGroup, FieldModifier, FilterValue, Selection,
    SigmaRule,
};
use crate::sigma::field_map::{resolve_field, FieldValue};

/// Maximum number of compiled regex patterns to cache per thread.
const REGEX_CACHE_MAX: usize = 256;

thread_local! {
    /// Per-thread LRU regex cache keyed by pattern string.
    /// Avoids recompiling the same regex on every event evaluation.
    static REGEX_CACHE: RefCell<HashMap<String, Option<Regex>>> = RefCell::new(HashMap::new());
}

/// Compiles (or retrieves from cache) a regex by pattern string.
///
/// Returns `None` if the pattern is invalid.
fn cached_regex(pattern: &str) -> Option<Regex> {
    REGEX_CACHE.with(|cache| {
        let mut map = cache.borrow_mut();
        if let Some(entry) = map.get(pattern) {
            return entry.clone();
        }
        let compiled = Regex::new(pattern).ok();
        // Evict all entries if cache is full (simple strategy sufficient for
        // bounded rule sets).
        if map.len() >= REGEX_CACHE_MAX {
            map.clear();
        }
        map.insert(pattern.to_string(), compiled.clone());
        compiled
    })
}

/// Evaluates SIGMA rules against in-memory events.
pub struct EventMatcher;

impl EventMatcher {
    /// Returns `true` if the event matches the rule's detection logic.
    ///
    /// Evaluates all named selections, then resolves the condition expression
    /// tree using those results.
    #[must_use]
    pub fn matches(rule: &SigmaRule, event: &KronEvent) -> bool {
        // Evaluate all selections up-front into a boolean map.
        let selection_results: HashMap<&str, bool> = rule
            .detection
            .selections
            .iter()
            .map(|(name, sel)| (name.as_str(), evaluate_selection(sel, event)))
            .collect();

        evaluate_condition(&rule.detection.condition, &selection_results)
    }
}

/// Evaluates a named [`Selection`] against a [`KronEvent`].
///
/// - [`Selection::Keywords`]: matches if ANY keyword appears in `event.raw`.
/// - [`Selection::FieldGroups`]: matches if ANY group matches (OR). A group
///   matches if ALL its filters match (AND).
fn evaluate_selection(sel: &Selection, event: &KronEvent) -> bool {
    match sel {
        Selection::Keywords(kws) => {
            let raw_lower = event.raw.to_lowercase();
            kws.iter().any(|kw| raw_lower.contains(&kw.to_lowercase()))
        }
        Selection::FieldGroups(groups) => groups.iter().any(|g| evaluate_group(g, event)),
    }
}

/// Evaluates a [`FieldFilterGroup`] — all filters must match (AND).
fn evaluate_group(group: &FieldFilterGroup, event: &KronEvent) -> bool {
    group.filters.iter().all(|f| evaluate_filter(f, event))
}

/// Evaluates a single [`FieldFilter`] against a [`KronEvent`].
fn evaluate_filter(filter: &FieldFilter, event: &KronEvent) -> bool {
    let field_val = resolve_field(event, &filter.field);

    match &filter.modifier {
        FieldModifier::Exact => filter.values.iter().any(|v| exact_match(&field_val, v)),
        FieldModifier::Contains => filter.values.iter().any(|v| contains_match(&field_val, v)),
        FieldModifier::ContainsAll => filter.values.iter().all(|v| contains_match(&field_val, v)),
        FieldModifier::All => filter.values.iter().all(|v| exact_match(&field_val, v)),
        FieldModifier::StartsWith => filter
            .values
            .iter()
            .any(|v| startswith_match(&field_val, v)),
        FieldModifier::EndsWith => filter.values.iter().any(|v| endswith_match(&field_val, v)),
        FieldModifier::Re => filter.values.iter().any(|v| regex_match(&field_val, v)),
        FieldModifier::Cidr => filter.values.iter().any(|v| cidr_match(&field_val, v)),
        FieldModifier::Gt => filter
            .values
            .iter()
            .any(|v| numeric_cmp(&field_val, v, &CmpOp::Gt)),
        FieldModifier::Gte => filter
            .values
            .iter()
            .any(|v| numeric_cmp(&field_val, v, &CmpOp::Gte)),
        FieldModifier::Lt => filter
            .values
            .iter()
            .any(|v| numeric_cmp(&field_val, v, &CmpOp::Lt)),
        FieldModifier::Lte => filter
            .values
            .iter()
            .any(|v| numeric_cmp(&field_val, v, &CmpOp::Lte)),
    }
}

/// Case-insensitive exact match, also handles null comparison.
fn exact_match(field: &Option<FieldValue>, value: &FilterValue) -> bool {
    match (field, value) {
        (None, FilterValue::Null) => true,
        (Some(FieldValue::Str(s)), FilterValue::Text(t)) => sigma_pattern_match(s, t),
        (Some(FieldValue::Int(i)), FilterValue::Int(v)) => i == v,
        (Some(FieldValue::Int(i)), FilterValue::Text(t)) => t.parse::<i64>().is_ok_and(|v| *i == v),
        (Some(FieldValue::Bool(b)), FilterValue::Text(t)) => b.to_string().eq_ignore_ascii_case(t),
        _ => false,
    }
}

/// Case-insensitive substring match.
fn contains_match(field: &Option<FieldValue>, value: &FilterValue) -> bool {
    match (field, value) {
        (Some(FieldValue::Str(s)), FilterValue::Text(t)) => {
            s.to_lowercase().contains(&t.to_lowercase())
        }
        _ => false,
    }
}

/// Case-insensitive prefix match.
fn startswith_match(field: &Option<FieldValue>, value: &FilterValue) -> bool {
    match (field, value) {
        (Some(FieldValue::Str(s)), FilterValue::Text(t)) => {
            s.to_lowercase().starts_with(&t.to_lowercase())
        }
        _ => false,
    }
}

/// Case-insensitive suffix match.
fn endswith_match(field: &Option<FieldValue>, value: &FilterValue) -> bool {
    match (field, value) {
        (Some(FieldValue::Str(s)), FilterValue::Text(t)) => {
            s.to_lowercase().ends_with(&t.to_lowercase())
        }
        _ => false,
    }
}

/// Regex match — uses thread-local cache to avoid recompiling per event.
fn regex_match(field: &Option<FieldValue>, value: &FilterValue) -> bool {
    match (field, value) {
        (Some(FieldValue::Str(s)), FilterValue::Text(pattern)) => {
            cached_regex(pattern).is_some_and(|re| re.is_match(s))
        }
        _ => false,
    }
}

/// CIDR subnet membership check for IPv4 addresses.
///
/// Parses the field value as an IPv4 address and checks whether it falls
/// within the CIDR range specified in the filter value.
fn cidr_match(field: &Option<FieldValue>, value: &FilterValue) -> bool {
    let (ip_str, cidr_str) = match (field, value) {
        (Some(FieldValue::Str(s)), FilterValue::Text(c)) => (s.as_str(), c.as_str()),
        _ => return false,
    };

    let Ok(ip) = Ipv4Addr::from_str(ip_str) else {
        return false;
    };

    parse_cidr_contains(cidr_str, ip)
}

/// Checks whether `ip` is contained in the CIDR `cidr_str` (e.g. `192.168.1.0/24`).
fn parse_cidr_contains(cidr_str: &str, ip: Ipv4Addr) -> bool {
    let Some((net_str, prefix_str)) = cidr_str.split_once('/') else {
        // No prefix — treat as host address.
        return Ipv4Addr::from_str(cidr_str).is_ok_and(|n| n == ip);
    };

    let Ok(network) = Ipv4Addr::from_str(net_str) else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.parse::<u8>() else {
        return false;
    };
    if prefix_len > 32 {
        return false;
    }

    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };

    let network_u32 = u32::from(network);
    let ip_u32 = u32::from(ip);

    (ip_u32 & mask) == (network_u32 & mask)
}

/// Numeric comparison between a field value and a filter value.
fn numeric_cmp(field: &Option<FieldValue>, value: &FilterValue, op: &CmpOp) -> bool {
    let (field_int, value_int) = match (field, value) {
        (Some(FieldValue::Int(f)), FilterValue::Int(v)) => (*f, *v),
        (Some(FieldValue::Str(s)), FilterValue::Int(v)) => {
            let Ok(f) = s.parse::<i64>() else {
                return false;
            };
            (f, *v)
        }
        _ => return false,
    };

    match op {
        CmpOp::Gt => field_int > value_int,
        CmpOp::Gte => field_int >= value_int,
        CmpOp::Lt => field_int < value_int,
        CmpOp::Lte => field_int <= value_int,
        CmpOp::Eq => field_int == value_int,
    }
}

/// Matches a string against a SIGMA pattern that may contain `*` (any) or `?` (one char).
///
/// Converts the SIGMA wildcard pattern to a regex and tests case-insensitively.
/// Uses thread-local cache to avoid recompiling per event.
fn sigma_pattern_match(s: &str, pattern: &str) -> bool {
    if !pattern.contains('*') && !pattern.contains('?') {
        return s.eq_ignore_ascii_case(pattern);
    }

    let mut regex_str = String::from("(?i)^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            c => {
                regex_str.push_str(&regex::escape(&c.to_string()));
            }
        }
    }
    regex_str.push('$');

    cached_regex(&regex_str).is_some_and(|re| re.is_match(s))
}

/// Evaluates a [`ConditionExpr`] tree using pre-computed selection results.
fn evaluate_condition(expr: &ConditionExpr, results: &HashMap<&str, bool>) -> bool {
    match expr {
        ConditionExpr::Selection(name) => *results.get(name.as_str()).unwrap_or(&false),
        ConditionExpr::Not(inner) => !evaluate_condition(inner, results),
        ConditionExpr::And(a, b) => {
            evaluate_condition(a, results) && evaluate_condition(b, results)
        }
        ConditionExpr::Or(a, b) => evaluate_condition(a, results) || evaluate_condition(b, results),
        ConditionExpr::OneOf(pattern) => {
            let re = glob_to_regex(pattern);
            results
                .iter()
                .any(|(name, &matched)| matched && re.is_match(name))
        }
        ConditionExpr::AllOf(pattern) => {
            let re = glob_to_regex(pattern);
            let matching: Vec<bool> = results
                .iter()
                .filter(|(name, _)| re.is_match(name))
                .map(|(_, &v)| v)
                .collect();
            !matching.is_empty() && matching.iter().all(|&v| v)
        }
        // Aggregation and temporal conditions require historical data — always false in real-time.
        ConditionExpr::Count { .. } | ConditionExpr::Near(_) => false,
    }
}

/// Converts a SIGMA glob pattern (`*` = any chars) to a compiled `Regex`.
///
/// Falls back to a pattern that never matches if the glob cannot be compiled.
fn glob_to_regex(pattern: &str) -> Regex {
    let mut re_str = String::from("(?i)^");
    for ch in pattern.chars() {
        match ch {
            '*' => re_str.push_str(".+"),
            '?' => re_str.push('.'),
            c => re_str.push_str(&regex::escape(&c.to_string())),
        }
    }
    re_str.push('$');

    Regex::new(&re_str).unwrap_or_else(|_| {
        // Compile a never-matching regex as a safe fallback.
        Regex::new("(?!x)x").unwrap_or_else(|_| {
            // This is unreachable — "(?!x)x" is always valid.
            unreachable!("fallback regex must always compile")
        })
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sigma::ast::{Detection, FieldFilterGroup, FieldModifier, FilterValue, LogSource};
    use chrono::Utc;
    use kron_types::enums::{EventSource, Severity};
    use kron_types::event::KronEvent;
    use kron_types::ids::TenantId;
    use uuid::Uuid;

    fn make_rule(selections: HashMap<String, Selection>, condition: ConditionExpr) -> SigmaRule {
        SigmaRule {
            id: Uuid::new_v4(),
            title: "Test Rule".to_string(),
            status: crate::sigma::ast::RuleStatus::Stable,
            description: String::new(),
            tags: vec![],
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            logsource: LogSource {
                category: None,
                product: None,
                service: None,
            },
            detection: Detection {
                selections,
                condition,
                timeframe_secs: None,
            },
            severity: Severity::High,
            falsepositives: vec![],
        }
    }

    fn make_event() -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::WindowsEtw)
            .event_type("process_create")
            .ts(Utc::now())
            .process_cmdline("powershell.exe -EncodedCommand abc123")
            .hostname("WIN-DC01")
            .user_name("SYSTEM")
            .raw("powershell.exe -EncodedCommand abc123")
            .build()
            .expect("valid event")
    }

    fn single_filter_rule(field: &str, modifier: FieldModifier, value: FilterValue) -> SigmaRule {
        let mut selections = HashMap::new();
        selections.insert(
            "sel".to_string(),
            Selection::FieldGroups(vec![FieldFilterGroup {
                filters: vec![FieldFilter {
                    field: field.to_string(),
                    modifier,
                    values: vec![value],
                }],
            }]),
        );
        make_rule(selections, ConditionExpr::Selection("sel".to_string()))
    }

    #[test]
    fn test_exact_match_when_value_equals_then_true() {
        let rule = single_filter_rule(
            "CommandLine",
            FieldModifier::Exact,
            FilterValue::Text("powershell.exe -EncodedCommand abc123".to_string()),
        );
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }

    #[test]
    fn test_contains_match_when_substring_present_then_true() {
        let rule = single_filter_rule(
            "CommandLine",
            FieldModifier::Contains,
            FilterValue::Text("EncodedCommand".to_string()),
        );
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }

    #[test]
    fn test_startswith_match_when_prefix_matches_then_true() {
        let rule = single_filter_rule(
            "CommandLine",
            FieldModifier::StartsWith,
            FilterValue::Text("powershell".to_string()),
        );
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }

    #[test]
    fn test_endswith_match_when_suffix_matches_then_true() {
        let rule = single_filter_rule(
            "CommandLine",
            FieldModifier::EndsWith,
            FilterValue::Text("abc123".to_string()),
        );
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }

    #[test]
    fn test_not_condition_when_no_match_inverted_then_true() {
        let rule = {
            let mut selections = HashMap::new();
            selections.insert(
                "sel".to_string(),
                Selection::FieldGroups(vec![FieldFilterGroup {
                    filters: vec![FieldFilter {
                        field: "CommandLine".to_string(),
                        modifier: FieldModifier::Contains,
                        values: vec![FilterValue::Text("mimikatz".to_string())],
                    }],
                }]),
            );
            make_rule(
                selections,
                ConditionExpr::Not(Box::new(ConditionExpr::Selection("sel".to_string()))),
            )
        };
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }

    #[test]
    fn test_and_condition_when_both_match_then_true() {
        let rule = {
            let mut selections = HashMap::new();
            selections.insert(
                "sel1".to_string(),
                Selection::FieldGroups(vec![FieldFilterGroup {
                    filters: vec![FieldFilter {
                        field: "CommandLine".to_string(),
                        modifier: FieldModifier::Contains,
                        values: vec![FilterValue::Text("powershell".to_string())],
                    }],
                }]),
            );
            selections.insert(
                "sel2".to_string(),
                Selection::FieldGroups(vec![FieldFilterGroup {
                    filters: vec![FieldFilter {
                        field: "Hostname".to_string(),
                        modifier: FieldModifier::Contains,
                        values: vec![FilterValue::Text("WIN".to_string())],
                    }],
                }]),
            );
            make_rule(
                selections,
                ConditionExpr::And(
                    Box::new(ConditionExpr::Selection("sel1".to_string())),
                    Box::new(ConditionExpr::Selection("sel2".to_string())),
                ),
            )
        };
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }

    #[test]
    fn test_or_condition_when_one_matches_then_true() {
        let rule = {
            let mut selections = HashMap::new();
            selections.insert(
                "sel1".to_string(),
                Selection::FieldGroups(vec![FieldFilterGroup {
                    filters: vec![FieldFilter {
                        field: "CommandLine".to_string(),
                        modifier: FieldModifier::Contains,
                        values: vec![FilterValue::Text("mimikatz".to_string())],
                    }],
                }]),
            );
            selections.insert(
                "sel2".to_string(),
                Selection::FieldGroups(vec![FieldFilterGroup {
                    filters: vec![FieldFilter {
                        field: "CommandLine".to_string(),
                        modifier: FieldModifier::Contains,
                        values: vec![FilterValue::Text("EncodedCommand".to_string())],
                    }],
                }]),
            );
            make_rule(
                selections,
                ConditionExpr::Or(
                    Box::new(ConditionExpr::Selection("sel1".to_string())),
                    Box::new(ConditionExpr::Selection("sel2".to_string())),
                ),
            )
        };
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }

    #[test]
    fn test_regex_match_when_pattern_matches_then_true() {
        let rule = single_filter_rule(
            "CommandLine",
            FieldModifier::Re,
            FilterValue::Text(r"powershell.*-EncodedCommand".to_string()),
        );
        let event = make_event();
        assert!(EventMatcher::matches(&rule, &event));
    }
}
