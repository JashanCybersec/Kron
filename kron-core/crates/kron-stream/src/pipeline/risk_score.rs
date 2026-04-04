//! Composite risk-score computation (F-007).
//!
//! [`RiskScorer::compute`] combines SIGMA rule severity, IOC hit flag, ONNX
//! anomaly score, UEBA deviation score, and asset criticality into a single
//! 0–100 score used for alert prioritisation.

use kron_types::enums::Severity;

/// Inputs to the composite risk scorer.
#[derive(Debug, Clone)]
pub struct RiskScoreInputs {
    /// SIGMA rule severity (0–100, derived from rule level).
    pub rule_severity: u8,
    /// ONNX anomaly score (0.0–1.0). `None` if model not loaded.
    pub anomaly_score: Option<f32>,
    /// Whether the event matched an IOC.
    pub ioc_hit: bool,
    /// Asset criticality multiplier (0.5–2.0).
    pub asset_criticality_mult: f32,
    /// UEBA deviation score (0.0–1.0). `None` if not available.
    pub ueba_score: Option<f32>,
}

/// Computes a composite risk score from multiple detection signals.
pub struct RiskScorer;

impl RiskScorer {
    /// Compute a composite risk score in the range 0–100.
    ///
    /// Formula (F-007):
    /// 1. `base = rule_severity` (0–100)
    /// 2. If `ioc_hit`:               `base += 20` (capped at 100)
    /// 3. If `anomaly_score > 0.75`:  `base += 15`
    /// 4. If `ueba_score > 0.80`:     `base += 10`
    /// 5. `final = (base as f32 * asset_criticality_mult).clamp(0.0, 100.0) as u8`
    #[must_use]
    pub fn compute(inputs: &RiskScoreInputs) -> u8 {
        let mut base = u32::from(inputs.rule_severity);

        if inputs.ioc_hit {
            base = base.saturating_add(20).min(100);
        }

        if inputs.anomaly_score.is_some_and(|s| s > 0.75) {
            base = base.saturating_add(15).min(100);
        }

        if inputs.ueba_score.is_some_and(|s| s > 0.80) {
            base = base.saturating_add(10).min(100);
        }

        #[allow(clippy::cast_precision_loss)]
        let scaled = (base as f32 * inputs.asset_criticality_mult).clamp(0.0, 100.0);
        // Safe: value is clamped to 0.0–100.0 before cast.
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let result = scaled as u8;
        result
    }
}

/// Derive a [`Severity`] level from a 0–100 risk score.
///
/// Mapping:
/// - ≥ 80 → [`Severity::Critical`]
/// - ≥ 60 → [`Severity::High`]
/// - ≥ 40 → [`Severity::Medium`]
/// - ≥ 20 → [`Severity::Low`]
/// - \<  20 → [`Severity::Info`]
#[must_use]
pub fn severity_from_score(score: u8) -> Severity {
    Severity::from_score(score)
}

/// Map a [`Severity`] level (from a SIGMA rule) to a numeric base score.
///
/// Returns:
/// - [`Severity::Critical`] → 90
/// - [`Severity::High`]     → 70
/// - [`Severity::Medium`]   → 50
/// - [`Severity::Low`]      → 30
/// - [`Severity::Info`]     → 10
#[must_use]
pub fn rule_severity_from_level(level: &Severity) -> u8 {
    match level {
        Severity::Critical => 90,
        Severity::High => 70,
        Severity::Medium => 50,
        Severity::Low => 30,
        Severity::Info => 10,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_when_critical_rule_then_high_score() {
        let inputs = RiskScoreInputs {
            rule_severity: 90,
            anomaly_score: None,
            ioc_hit: false,
            asset_criticality_mult: 1.0,
            ueba_score: None,
        };
        let score = RiskScorer::compute(&inputs);
        assert_eq!(score, 90);
    }

    #[test]
    fn test_compute_when_ioc_hit_then_score_increases() {
        let without = RiskScorer::compute(&RiskScoreInputs {
            rule_severity: 50,
            anomaly_score: None,
            ioc_hit: false,
            asset_criticality_mult: 1.0,
            ueba_score: None,
        });
        let with_ioc = RiskScorer::compute(&RiskScoreInputs {
            rule_severity: 50,
            anomaly_score: None,
            ioc_hit: true,
            asset_criticality_mult: 1.0,
            ueba_score: None,
        });
        assert!(with_ioc > without);
        assert_eq!(with_ioc, 70);
    }

    #[test]
    fn test_compute_when_high_asset_criticality_then_score_multiplied() {
        let low = RiskScorer::compute(&RiskScoreInputs {
            rule_severity: 50,
            anomaly_score: None,
            ioc_hit: false,
            asset_criticality_mult: 1.0,
            ueba_score: None,
        });
        let high = RiskScorer::compute(&RiskScoreInputs {
            rule_severity: 50,
            anomaly_score: None,
            ioc_hit: false,
            asset_criticality_mult: 2.0,
            ueba_score: None,
        });
        assert_eq!(low, 50);
        assert_eq!(high, 100);
    }

    #[test]
    fn test_compute_when_all_factors_then_capped_at_100() {
        let inputs = RiskScoreInputs {
            rule_severity: 90,
            anomaly_score: Some(0.9),
            ioc_hit: true,
            asset_criticality_mult: 2.0,
            ueba_score: Some(0.9),
        };
        let score = RiskScorer::compute(&inputs);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_severity_from_score_when_80_then_critical() {
        assert_eq!(severity_from_score(80), Severity::Critical);
        assert_eq!(severity_from_score(100), Severity::Critical);
        assert_eq!(severity_from_score(79), Severity::High);
        assert_eq!(severity_from_score(60), Severity::High);
        assert_eq!(severity_from_score(59), Severity::Medium);
        assert_eq!(severity_from_score(40), Severity::Medium);
        assert_eq!(severity_from_score(39), Severity::Low);
        assert_eq!(severity_from_score(20), Severity::Low);
        assert_eq!(severity_from_score(19), Severity::Info);
        assert_eq!(severity_from_score(0), Severity::Info);
    }

    #[test]
    fn test_rule_severity_from_level_when_all_levels_then_correct_values() {
        assert_eq!(rule_severity_from_level(&Severity::Critical), 90);
        assert_eq!(rule_severity_from_level(&Severity::High), 70);
        assert_eq!(rule_severity_from_level(&Severity::Medium), 50);
        assert_eq!(rule_severity_from_level(&Severity::Low), 30);
        assert_eq!(rule_severity_from_level(&Severity::Info), 10);
    }
}
