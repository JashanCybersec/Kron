//! Detection pipeline — the main event-processing entry-point for Phase 2.4.
//!
//! [`DetectionPipeline::process`] runs a single [`KronEvent`] through the
//! complete detection chain:
//!
//! 1. IOC bloom-filter check
//! 2. SIGMA rule evaluation
//! 3. ONNX anomaly scoring
//! 4. Composite risk scoring
//! 5. MITRE ATT&CK tag extraction
//! 6. Entity graph update
//! 7. Threshold check → optional [`AlertCandidate`]

use std::path::PathBuf;
use std::sync::Arc;

use kron_ai::InferenceService;
use kron_types::enums::Severity;
use kron_types::event::KronEvent;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::ioc::{IocFilter, IocType};
use crate::pipeline::entity_graph::EntityGraph;
use crate::pipeline::mitre::MitreTag;
use crate::pipeline::risk_score::{
    rule_severity_from_level, severity_from_score, RiskScoreInputs, RiskScorer,
};
use crate::sigma::{EvaluationResult, RuleEvaluator};

/// Serialisable summary of a single SIGMA rule match.
///
/// [`EvaluationResult`] does not derive `Serialize`; this struct carries the
/// fields needed downstream without coupling the sigma module to serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchSummary {
    /// UUID of the matched rule.
    pub rule_id: Uuid,
    /// Human-readable title of the rule.
    pub rule_title: String,
    /// Severity level of the rule.
    pub severity: Severity,
}

impl From<&EvaluationResult> for RuleMatchSummary {
    fn from(r: &EvaluationResult) -> Self {
        Self {
            rule_id: r.rule_id,
            rule_title: r.rule_title.clone(),
            severity: r.severity,
        }
    }
}

/// A MITRE ATT&CK tag in serialisable form (mirrors [`MitreTag`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTagSummary {
    /// ATT&CK tactic display name, if the tag encodes a tactic.
    pub tactic: Option<String>,
    /// ATT&CK technique ID (e.g. "T1055"), if the tag encodes a technique.
    pub technique_id: Option<String>,
    /// Sub-technique identifier (e.g. "001"), if present.
    pub sub_technique_id: Option<String>,
}

impl From<&MitreTag> for MitreTagSummary {
    fn from(t: &MitreTag) -> Self {
        Self {
            tactic: t.tactic.clone(),
            technique_id: t.technique_id.clone(),
            sub_technique_id: t.sub_technique_id.clone(),
        }
    }
}

/// An event that exceeded the alert threshold after full pipeline processing.
#[derive(Debug, Clone)]
pub struct AlertCandidate {
    /// The event that triggered the alert.
    pub event: KronEvent,
    /// Composite risk score (0–100).
    pub risk_score: u8,
    /// Severity derived from the risk score.
    pub severity: Severity,
    /// All SIGMA rules that matched this event.
    pub rule_matches: Vec<EvaluationResult>,
    /// Whether any IOC matched a field in this event.
    pub ioc_hit: bool,
    /// The type of IOC that matched, if any.
    pub ioc_type: Option<IocType>,
    /// ONNX anomaly score (0.0–1.0), or `None` if no model was loaded.
    pub anomaly_score: Option<f32>,
    /// MITRE ATT&CK tags extracted from matched SIGMA rule tags.
    pub mitre_tags: Vec<MitreTag>,
}

/// Serialisable form of [`AlertCandidate`] — suitable for publishing to the bus.
///
/// Converts non-serialisable fields (e.g. [`EvaluationResult`], [`MitreTag`])
/// into their serialisable summary counterparts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCandidatePayload {
    /// The event that triggered the alert.
    pub event: KronEvent,
    /// Composite risk score (0–100).
    pub risk_score: u8,
    /// Severity derived from the risk score.
    pub severity: Severity,
    /// Summarised SIGMA rule matches.
    pub rule_matches: Vec<RuleMatchSummary>,
    /// Whether any IOC matched a field in this event.
    pub ioc_hit: bool,
    /// The type of IOC that matched, if any.
    pub ioc_type: Option<IocType>,
    /// ONNX anomaly score (0.0–1.0), or `None` if no model was loaded.
    pub anomaly_score: Option<f32>,
    /// MITRE ATT&CK tags.
    pub mitre_tags: Vec<MitreTagSummary>,
}

impl From<&AlertCandidate> for AlertCandidatePayload {
    fn from(c: &AlertCandidate) -> Self {
        Self {
            event: c.event.clone(),
            risk_score: c.risk_score,
            severity: c.severity,
            rule_matches: c.rule_matches.iter().map(RuleMatchSummary::from).collect(),
            ioc_hit: c.ioc_hit,
            ioc_type: c.ioc_type,
            anomaly_score: c.anomaly_score,
            mitre_tags: c.mitre_tags.iter().map(MitreTagSummary::from).collect(),
        }
    }
}

/// Configuration for the detection pipeline.
pub struct PipelineConfig {
    /// Minimum risk score required to emit an [`AlertCandidate`]. Default: 40.
    pub alert_threshold: u8,
    /// Path to the SIGMA rules directory (passed to [`RuleEvaluator`]).
    pub rules_dir: PathBuf,
    /// Path to the ONNX models directory (passed to [`InferenceService`]).
    pub models_dir: PathBuf,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            alert_threshold: 40,
            rules_dir: PathBuf::from("/var/lib/kron/rules"),
            models_dir: PathBuf::from("/var/lib/kron/models"),
        }
    }
}

/// The full event-detection pipeline.
///
/// Holds `Arc`-wrapped references to each sub-component so the pipeline
/// can be cheaply cloned across Tokio tasks.
pub struct DetectionPipeline {
    ioc_filter: Arc<IocFilter>,
    rule_evaluator: Arc<RuleEvaluator>,
    inference: Arc<InferenceService>,
    entity_graph: Arc<EntityGraph>,
    config: PipelineConfig,
}

impl DetectionPipeline {
    /// Create a new pipeline from pre-built components and configuration.
    #[must_use]
    pub fn new(
        ioc_filter: Arc<IocFilter>,
        rule_evaluator: Arc<RuleEvaluator>,
        inference: Arc<InferenceService>,
        entity_graph: Arc<EntityGraph>,
        config: PipelineConfig,
    ) -> Self {
        Self {
            ioc_filter,
            rule_evaluator,
            inference,
            entity_graph,
            config,
        }
    }

    /// Process a single event through the full detection pipeline.
    ///
    /// Returns `Some(AlertCandidate)` when the composite risk score meets or
    /// exceeds `config.alert_threshold`.  Returns `None` when the event is
    /// clean (no detections fire above threshold).
    ///
    /// The pipeline always completes all stages regardless of intermediate
    /// results — partial detections still feed into the risk score and
    /// entity graph.
    #[instrument(skip_all, fields(
        event_id  = %event.event_id,
        tenant_id = %event.tenant_id,
        event_type = %event.event_type,
    ))]
    pub async fn process(&self, event: &KronEvent) -> Option<AlertCandidate> {
        // Stage 1: IOC check.
        let (ioc_hit, ioc_type) = self.check_ioc(event);

        // Stage 2: SIGMA rule evaluation.
        let rule_matches = self.rule_evaluator.evaluate(event);

        // Stage 3: ONNX anomaly scoring.
        let inference_result = self.inference.score_event(event).await;
        let anomaly_score = inference_result.anomaly_score;

        // Stage 4: Composite risk score.
        let rule_severity = Self::highest_rule_severity(&rule_matches);
        let inputs = RiskScoreInputs {
            rule_severity,
            anomaly_score,
            ioc_hit,
            asset_criticality_mult: event.asset_criticality.score_multiplier(),
            ueba_score: inference_result.ueba_score,
        };
        let risk_score = RiskScorer::compute(&inputs);

        // Stage 5: MITRE tagging from matched rules.
        let mitre_tags = Self::extract_mitre_tags(&rule_matches);

        // Stage 6: Entity graph update.
        self.entity_graph.update(event, risk_score);

        // Stage 7: Threshold check.
        if risk_score < self.config.alert_threshold {
            tracing::debug!(
                risk_score,
                threshold = self.config.alert_threshold,
                "event below alert threshold — no candidate emitted"
            );
            return None;
        }

        let severity = severity_from_score(risk_score);

        tracing::info!(
            risk_score,
            %severity,
            ioc_hit,
            rule_match_count = rule_matches.len(),
            "alert candidate generated"
        );

        Some(AlertCandidate {
            event: event.clone(),
            risk_score,
            severity,
            rule_matches,
            ioc_hit,
            ioc_type,
            anomaly_score,
            mitre_tags,
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Check relevant event fields against the IOC bloom filter.
    ///
    /// Returns `(true, Some(type))` on the first hit found, checking in order:
    /// `src_ip`, `dst_ip`, `file_hash` (sha256), then any URL values in
    /// the flexible `fields` map.
    fn check_ioc(&self, event: &KronEvent) -> (bool, Option<IocType>) {
        if let Some(ip) = event.src_ip {
            if self.ioc_filter.check(&ip.to_string(), &IocType::Ip) {
                return (true, Some(IocType::Ip));
            }
        }

        if let Some(ip) = event.dst_ip {
            if self.ioc_filter.check(&ip.to_string(), &IocType::Ip) {
                return (true, Some(IocType::Ip));
            }
        }

        if let Some(ref hash) = event.file_hash {
            if self.ioc_filter.check(hash, &IocType::Sha256) {
                return (true, Some(IocType::Sha256));
            }
        }

        // Check flexible fields for URL values.
        for value in event.fields.values() {
            if (value.starts_with("http://") || value.starts_with("https://"))
                && self.ioc_filter.check(value, &IocType::Url)
            {
                return (true, Some(IocType::Url));
            }
        }

        (false, None)
    }

    /// Return the highest numeric rule severity from a list of matches.
    ///
    /// Returns 0 when no rules matched (will not inflate the base score).
    fn highest_rule_severity(matches: &[EvaluationResult]) -> u8 {
        matches
            .iter()
            .map(|r| rule_severity_from_level(&r.severity))
            .max()
            .unwrap_or(0)
    }

    /// Extract MITRE tags from all matched SIGMA rules.
    fn extract_mitre_tags(matches: &[EvaluationResult]) -> Vec<MitreTag> {
        use crate::pipeline::mitre::MitreTagger;

        let all_tags: Vec<String> = matches
            .iter()
            .flat_map(|r| {
                r.mitre_tactics
                    .iter()
                    .map(|t| format!("attack.{t}"))
                    .chain(r.mitre_techniques.iter().map(|t| format!("attack.{t}")))
            })
            .collect();

        MitreTagger::extract(&all_tags)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use chrono::Utc;
    use kron_ai::ModelRegistry;
    use kron_types::enums::EventSource;
    use kron_types::ids::TenantId;

    use super::*;
    use crate::sigma::registry::RuleRegistry;

    fn build_pipeline() -> DetectionPipeline {
        let ioc_filter = Arc::new(IocFilter::with_capacity(8_192, 7));
        let registry = Arc::new(RuleRegistry::new());
        let rule_evaluator = Arc::new(RuleEvaluator::new(registry));
        let model_registry = Arc::new(ModelRegistry::new(std::env::temp_dir()));
        let inference = Arc::new(InferenceService::new(model_registry));
        let entity_graph = Arc::new(EntityGraph::new());
        let config = PipelineConfig {
            alert_threshold: 40,
            ..PipelineConfig::default()
        };
        DetectionPipeline::new(ioc_filter, rule_evaluator, inference, entity_graph, config)
    }

    fn minimal_event() -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .ts(Utc::now())
            .build()
            .expect("valid event")
    }

    #[tokio::test]
    async fn test_process_when_clean_event_then_no_candidate() {
        let pipeline = build_pipeline();
        let event = minimal_event();
        let result = pipeline.process(&event).await;
        // No rules loaded, no IOC, no model → risk score 0 → no candidate.
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_process_when_ioc_hit_then_candidate_emitted() {
        let ioc_filter = Arc::new(IocFilter::with_capacity(8_192, 7));
        ioc_filter.insert("1.2.3.4", &IocType::Ip);

        let registry = Arc::new(RuleRegistry::new());
        let rule_evaluator = Arc::new(RuleEvaluator::new(registry));
        let model_registry = Arc::new(ModelRegistry::new(std::env::temp_dir()));
        let inference = Arc::new(InferenceService::new(model_registry));
        let entity_graph = Arc::new(EntityGraph::new());
        let config = PipelineConfig {
            alert_threshold: 1, // low threshold so IOC hit triggers alert
            ..PipelineConfig::default()
        };
        let pipeline =
            DetectionPipeline::new(ioc_filter, rule_evaluator, inference, entity_graph, config);

        let event = KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("network_connect")
            .ts(Utc::now())
            .src_ip("1.2.3.4".parse().expect("valid ip"))
            .build()
            .expect("valid event");

        let result = pipeline.process(&event).await;
        assert!(result.is_some());
        let candidate = result.expect("candidate present");
        assert!(candidate.ioc_hit);
        assert_eq!(candidate.ioc_type, Some(IocType::Ip));
    }
}
