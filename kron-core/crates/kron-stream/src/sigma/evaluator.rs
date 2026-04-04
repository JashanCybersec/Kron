//! Rule evaluator — applies all production SIGMA rules to a single event.
//!
//! [`RuleEvaluator`] iterates all [`RuleStatus::Stable`] rules from the
//! [`RuleRegistry`] and evaluates each against the incoming [`KronEvent`].
//! Matched rules are returned as [`EvaluationResult`]s for the alert engine.

use std::sync::Arc;

use kron_types::enums::Severity;
use kron_types::event::KronEvent;
use uuid::Uuid;

use crate::sigma::ast::SigmaRule;
use crate::sigma::matcher::EventMatcher;
use crate::sigma::registry::RuleRegistry;

/// Result of evaluating a single SIGMA rule against a single event.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// UUID of the evaluated rule.
    pub rule_id: Uuid,
    /// Human-readable title of the rule.
    pub rule_title: String,
    /// Whether the event matched the rule's detection logic.
    pub matched: bool,
    /// Severity level of the rule.
    pub severity: Severity,
    /// MITRE ATT&CK tactic names extracted from the rule's tags.
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK technique IDs extracted from the rule's tags.
    pub mitre_techniques: Vec<String>,
}

/// Evaluates all production SIGMA rules against incoming events.
pub struct RuleEvaluator {
    registry: Arc<RuleRegistry>,
}

impl RuleEvaluator {
    /// Creates a new evaluator backed by the given registry.
    #[must_use]
    pub fn new(registry: Arc<RuleRegistry>) -> Self {
        Self { registry }
    }

    /// Evaluates all production (Stable) rules against the given event.
    ///
    /// Returns only matching rules. An empty vector means no rules matched.
    #[must_use]
    pub fn evaluate(&self, event: &KronEvent) -> Vec<EvaluationResult> {
        self.registry
            .production_rules()
            .into_iter()
            .map(|compiled| Self::evaluate_rule(&compiled.rule, event))
            .filter(|r| r.matched)
            .collect()
    }

    /// Evaluates a single rule against a single event.
    ///
    /// Always returns an [`EvaluationResult`] — `matched` indicates whether
    /// the rule fired.
    #[must_use]
    pub fn evaluate_rule(rule: &SigmaRule, event: &KronEvent) -> EvaluationResult {
        let matched = EventMatcher::matches(rule, event);

        EvaluationResult {
            rule_id: rule.id,
            rule_title: rule.title.clone(),
            matched,
            severity: rule.severity,
            mitre_tactics: rule.mitre_tactics.clone(),
            mitre_techniques: rule.mitre_techniques.clone(),
        }
    }
}
