//! False-positive classification for SIGMA rules.
//!
//! Rules are classified into three tiers based on their metadata:
//! - [`FpClassification::Production`] — auto-enabled in production
//! - [`FpClassification::Review`] — requires analyst to enable
//! - [`FpClassification::Experimental`] — disabled by default

use kron_types::enums::Severity;

use crate::sigma::ast::{RuleStatus, SigmaRule};

/// False-positive rate classification for a SIGMA rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FpClassification {
    /// FP rate < 2% — auto-enabled in production environments.
    Production,
    /// FP rate 2–10% — requires analyst review before enabling.
    Review,
    /// FP rate > 10% or untested — disabled by default.
    Experimental,
}

/// Classifies SIGMA rules by their expected false-positive rate.
pub struct FpClassifier;

impl FpClassifier {
    /// Classifies a rule based on its status, severity level, and known false-positive patterns.
    ///
    /// Classification logic:
    /// - `Deprecated` or `Unsupported` → `Experimental`
    /// - `Experimental` or `Test` status → `Experimental`
    /// - `Stable` + `Critical` or `High` → `Production`
    /// - `Stable` + `Medium` + has false positives → `Review`
    /// - `Stable` + `Medium` + no false positives → `Production`
    /// - `Stable` + `Low` or `Informational` → `Review`
    #[must_use]
    pub fn classify(rule: &SigmaRule) -> FpClassification {
        match rule.status {
            RuleStatus::Deprecated | RuleStatus::Unsupported => FpClassification::Experimental,
            RuleStatus::Experimental | RuleStatus::Test => FpClassification::Experimental,
            RuleStatus::Stable => classify_stable(rule),
        }
    }
}

/// Classifies a `Stable` rule by severity and false-positive list.
fn classify_stable(rule: &SigmaRule) -> FpClassification {
    match rule.severity {
        Severity::Critical | Severity::High => FpClassification::Production,
        Severity::Medium => {
            if rule.falsepositives.is_empty() {
                FpClassification::Production
            } else {
                FpClassification::Review
            }
        }
        Severity::Low | Severity::Info => FpClassification::Review,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sigma::ast::{
        CmpOp, ConditionExpr, Detection, FieldFilterGroup, LogSource, RuleStatus, Selection,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    fn make_rule(status: RuleStatus, severity: Severity, falsepositives: Vec<String>) -> SigmaRule {
        SigmaRule {
            id: Uuid::new_v4(),
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
            severity,
            falsepositives,
        }
    }

    #[test]
    fn test_stable_critical_when_classified_then_production() {
        let rule = make_rule(RuleStatus::Stable, Severity::Critical, vec![]);
        assert_eq!(FpClassifier::classify(&rule), FpClassification::Production);
    }

    #[test]
    fn test_stable_high_when_classified_then_production() {
        let rule = make_rule(RuleStatus::Stable, Severity::High, vec![]);
        assert_eq!(FpClassifier::classify(&rule), FpClassification::Production);
    }

    #[test]
    fn test_stable_medium_with_fp_when_classified_then_review() {
        let rule = make_rule(
            RuleStatus::Stable,
            Severity::Medium,
            vec!["Legitimate admin scripts".to_string()],
        );
        assert_eq!(FpClassifier::classify(&rule), FpClassification::Review);
    }

    #[test]
    fn test_stable_medium_no_fp_when_classified_then_production() {
        let rule = make_rule(RuleStatus::Stable, Severity::Medium, vec![]);
        assert_eq!(FpClassifier::classify(&rule), FpClassification::Production);
    }

    #[test]
    fn test_experimental_when_classified_then_experimental() {
        let rule = make_rule(RuleStatus::Experimental, Severity::High, vec![]);
        assert_eq!(
            FpClassifier::classify(&rule),
            FpClassification::Experimental
        );
    }

    #[test]
    fn test_deprecated_when_classified_then_experimental() {
        let rule = make_rule(RuleStatus::Deprecated, Severity::Critical, vec![]);
        assert_eq!(
            FpClassifier::classify(&rule),
            FpClassification::Experimental
        );
    }

    #[test]
    fn test_stable_low_when_classified_then_review() {
        let rule = make_rule(RuleStatus::Stable, Severity::Low, vec![]);
        assert_eq!(FpClassifier::classify(&rule), FpClassification::Review);
    }
}
