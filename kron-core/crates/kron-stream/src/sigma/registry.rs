//! Rule registry — concurrent in-memory store of compiled SIGMA rules.
//!
//! [`RuleRegistry`] uses a [`DashMap`] so rules can be read and updated
//! concurrently without a global write lock. The registry is the single
//! source of truth for which rules are active at any moment.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use uuid::Uuid;

use crate::sigma::ast::RuleStatus;
use crate::sigma::ast::SigmaRule;
use crate::sigma::fp_classifier::FpClassification;

/// A compiled SIGMA rule with pre-generated SQL and FP classification.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// The validated SIGMA rule AST.
    pub rule: SigmaRule,
    /// Pre-compiled ClickHouse `SELECT count()` query, if compilation succeeded.
    pub clickhouse_sql: Option<String>,
    /// Pre-compiled DuckDB `SELECT count(*)` query, if compilation succeeded.
    pub duckdb_sql: Option<String>,
    /// False-positive classification derived from rule metadata.
    pub classification: FpClassification,
    /// Path of the YAML file this rule was loaded from.
    pub source_file: PathBuf,
    /// UTC timestamp when this rule was loaded into the registry.
    pub loaded_at: DateTime<Utc>,
}

/// Concurrent registry of compiled SIGMA rules.
///
/// All operations are lock-free reads (via `DashMap`). Writes acquire a
/// per-shard lock internally.
#[derive(Default)]
pub struct RuleRegistry {
    rules: DashMap<Uuid, Arc<CompiledRule>>,
}

impl RuleRegistry {
    /// Creates a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: DashMap::new(),
        }
    }

    /// Inserts or replaces a rule. If a rule with the same ID already exists,
    /// it is silently replaced.
    pub fn upsert(&self, compiled: CompiledRule) {
        let id = compiled.rule.id;
        self.rules.insert(id, Arc::new(compiled));
    }

    /// Removes a rule by its UUID. Does nothing if the rule is not present.
    pub fn remove(&self, id: &Uuid) {
        self.rules.remove(id);
    }

    /// Returns all rules with [`RuleStatus::Stable`] status for real-time evaluation.
    ///
    /// This is the hot path — called for every event processed by the stream engine.
    #[must_use]
    pub fn production_rules(&self) -> Vec<Arc<CompiledRule>> {
        self.rules
            .iter()
            .filter(|entry| entry.value().rule.status == RuleStatus::Stable)
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Returns a single rule by its UUID, or `None` if not found.
    #[must_use]
    pub fn get(&self, id: &Uuid) -> Option<Arc<CompiledRule>> {
        self.rules.get(id).map(|r| Arc::clone(&*r))
    }

    /// Returns the total number of rules in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` if the registry contains no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sigma::ast::{ConditionExpr, Detection, LogSource, RuleStatus};
    use crate::sigma::fp_classifier::FpClassification;
    use kron_types::enums::Severity;
    use std::collections::HashMap;

    fn make_compiled_rule(id: Uuid, status: RuleStatus) -> CompiledRule {
        let rule = SigmaRule {
            id,
            title: "Test".to_string(),
            status,
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
                selections: HashMap::new(),
                condition: ConditionExpr::Selection("sel".to_string()),
                timeframe_secs: None,
            },
            severity: Severity::High,
            falsepositives: vec![],
        };

        CompiledRule {
            rule,
            clickhouse_sql: None,
            duckdb_sql: None,
            classification: FpClassification::Production,
            source_file: PathBuf::from("test.yml"),
            loaded_at: Utc::now(),
        }
    }

    #[test]
    fn test_upsert_when_new_rule_then_len_increases() {
        let registry = RuleRegistry::new();
        assert_eq!(registry.len(), 0);

        registry.upsert(make_compiled_rule(Uuid::new_v4(), RuleStatus::Stable));
        assert_eq!(registry.len(), 1);

        registry.upsert(make_compiled_rule(Uuid::new_v4(), RuleStatus::Stable));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_upsert_when_duplicate_id_then_replaced() {
        let registry = RuleRegistry::new();
        let id = Uuid::new_v4();

        registry.upsert(make_compiled_rule(id, RuleStatus::Stable));
        registry.upsert(make_compiled_rule(id, RuleStatus::Experimental));

        // Still only one rule.
        assert_eq!(registry.len(), 1);

        // The replacement has Experimental status.
        let rule = registry.get(&id).expect("should exist");
        assert_eq!(rule.rule.status, RuleStatus::Experimental);
    }

    #[test]
    fn test_production_rules_when_mixed_statuses_then_only_stable_returned() {
        let registry = RuleRegistry::new();

        registry.upsert(make_compiled_rule(Uuid::new_v4(), RuleStatus::Stable));
        registry.upsert(make_compiled_rule(Uuid::new_v4(), RuleStatus::Stable));
        registry.upsert(make_compiled_rule(Uuid::new_v4(), RuleStatus::Experimental));
        registry.upsert(make_compiled_rule(Uuid::new_v4(), RuleStatus::Test));

        let prod = registry.production_rules();
        assert_eq!(prod.len(), 2);
    }

    #[test]
    fn test_remove_when_rule_exists_then_len_decreases() {
        let registry = RuleRegistry::new();
        let id = Uuid::new_v4();

        registry.upsert(make_compiled_rule(id, RuleStatus::Stable));
        assert_eq!(registry.len(), 1);

        registry.remove(&id);
        assert_eq!(registry.len(), 0);
    }
}
