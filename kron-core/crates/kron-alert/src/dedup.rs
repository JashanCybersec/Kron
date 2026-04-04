//! Deduplication and grouping of alert candidates into 15-minute windows.
//!
//! The dedup key is `(tenant_id, rule_id, primary_asset)` where `primary_asset`
//! is the first hostname or source IP found in the event.  Multiple events
//! matching the same rule on the same asset within the window are merged into
//! one [`WindowState`] rather than producing separate alerts.

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use kron_types::ids::{AlertId, RuleId, TenantId};
use uuid::Uuid;

use crate::types::AlertCandidate;

/// Compound key that identifies a unique dedup window.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DedupKey {
    /// The tenant that owns this window.
    pub tenant_id: TenantId,
    /// The SIGMA rule (or IOC rule) that fired.
    pub rule_id: RuleId,
    /// First hostname or source IP from the triggering event.
    pub primary_asset: String,
}

/// In-memory state for an active dedup window.
#[derive(Debug, Clone)]
pub struct WindowState {
    /// The alert ID that will be assigned when this window is flushed.
    pub alert_id: AlertId,
    /// Timestamp of the first event in the window.
    pub first_seen: DateTime<Utc>,
    /// Timestamp of the most recent event merged into the window.
    pub last_seen: DateTime<Utc>,
    /// Number of events merged into this window.
    pub event_count: u32,
    /// UUIDs of raw events that contributed to this window.
    pub evidence_event_ids: Vec<Uuid>,
    /// Maximum risk score seen across all events in the window.
    pub risk_score: u8,
    /// True once the window has been flushed to an alert record.
    pub is_flushed: bool,
}

/// Manages per-tenant, per-rule 15-minute dedup windows.
///
/// Thread-safe: backed by [`DashMap`] so concurrent writers from separate
/// Tokio tasks are safe.
pub struct AlertDeduplicator {
    windows: DashMap<DedupKey, WindowState>,
    window_duration: Duration,
}

impl AlertDeduplicator {
    /// Creates a new `AlertDeduplicator` with the given window duration.
    #[must_use]
    pub fn new(window_duration: Duration) -> Self {
        Self {
            windows: DashMap::new(),
            window_duration,
        }
    }

    /// Creates a new `AlertDeduplicator` with the default 15-minute window.
    ///
    /// Primarily used in tests.
    #[must_use]
    #[cfg(test)]
    pub fn default_window() -> Self {
        Self::new(Duration::minutes(15))
    }

    /// Ingests an alert candidate.
    ///
    /// Returns `Some(AlertId)` if a **new** window was opened (first event
    /// that matches this key in the current window period), or `None` if the
    /// event was merged into an existing open window.
    #[must_use]
    pub fn ingest(&self, candidate: &AlertCandidate) -> Option<AlertId> {
        let key = build_key(candidate);
        let event_uuid = *candidate.event.event_id.as_uuid();
        let now = Utc::now();

        let mut found_existing = false;

        self.windows.alter(&key, |_, mut state| {
            if !state.is_flushed {
                state.last_seen = now;
                state.event_count += 1;
                state.evidence_event_ids.push(event_uuid);
                if candidate.risk_score > state.risk_score {
                    state.risk_score = candidate.risk_score;
                }
                found_existing = true;
            }
            state
        });

        if found_existing {
            return None;
        }

        // No open window found — open a new one.
        let new_id = AlertId::new();
        let state = WindowState {
            alert_id: new_id,
            first_seen: now,
            last_seen: now,
            event_count: 1,
            evidence_event_ids: vec![event_uuid],
            risk_score: candidate.risk_score,
            is_flushed: false,
        };
        self.windows.insert(key, state);
        Some(new_id)
    }

    /// Flushes all windows whose `first_seen` is older than `window_duration`
    /// and that have not already been flushed.
    ///
    /// Returns the list of `(DedupKey, WindowState)` pairs to be turned into
    /// persisted [`kron_types::KronAlert`] records.
    #[must_use]
    pub fn flush_expired(&self) -> Vec<(DedupKey, WindowState)> {
        let cutoff = Utc::now() - self.window_duration;
        let mut expired = Vec::new();

        // Collect windows that are newly expired in a single pass.
        // We cannot alter and collect simultaneously with DashMap, so we first
        // identify candidates, then mark+collect them.
        let keys_to_flush: Vec<DedupKey> = self
            .windows
            .iter()
            .filter(|entry| !entry.is_flushed && entry.first_seen <= cutoff)
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_flush {
            self.windows.alter(&key, |_, mut state| {
                state.is_flushed = true;
                expired.push((key.clone(), state.clone()));
                state
            });
        }

        expired
    }

    /// Evicts all windows older than `2 × window_duration` to prevent
    /// unbounded memory growth.
    pub fn evict_old(&self) {
        let evict_before = Utc::now() - self.window_duration * 2;
        self.windows
            .retain(|_, state| state.first_seen > evict_before);
    }
}

/// Derives the dedup key from an alert candidate.
fn build_key(candidate: &AlertCandidate) -> DedupKey {
    let rule_id = candidate
        .rule_matches
        .first()
        .and_then(|rm| rm.rule_id.parse::<RuleId>().ok())
        .unwrap_or_default();

    let primary_asset = candidate
        .event
        .hostname
        .clone()
        .or_else(|| candidate.event.src_ip.map(|ip| ip.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    DedupKey {
        tenant_id: candidate.event.tenant_id,
        rule_id,
        primary_asset,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use kron_types::{EventSource, KronEvent, Severity, TenantId};

    fn make_candidate(tenant_id: TenantId, hostname: &str, risk_score: u8) -> AlertCandidate {
        use crate::types::{MitreTagRaw, RuleMatch};

        let event = KronEvent::builder()
            .tenant_id(tenant_id)
            .source_type(EventSource::LinuxEbpf)
            .event_type("brute_force")
            .ts(Utc::now())
            .hostname(hostname)
            .build()
            .expect("valid event");

        AlertCandidate {
            event,
            risk_score,
            severity: Severity::from_score(risk_score),
            rule_matches: vec![RuleMatch {
                rule_id: RuleId::new().to_string(),
                rule_title: "Brute Force Login".to_string(),
                severity: Severity::High,
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1110".to_string()],
            }],
            ioc_hit: false,
            ioc_type_str: None,
            anomaly_score: None,
            mitre_tags: vec![MitreTagRaw {
                tactic: "Credential Access".to_string(),
                technique_id: "T1110".to_string(),
                sub_technique_id: None,
            }],
        }
    }

    #[test]
    fn test_dedup_when_first_event_then_opens_new_window() {
        let dedup = AlertDeduplicator::default_window();
        let tenant = TenantId::new();
        let candidate = make_candidate(tenant, "web-srv-01", 65);

        let result = dedup.ingest(&candidate);
        assert!(result.is_some(), "first event should open a new window");
    }

    #[test]
    fn test_dedup_when_duplicate_event_then_merges_into_window() {
        let dedup = AlertDeduplicator::default_window();
        let tenant = TenantId::new();
        let candidate = make_candidate(tenant, "web-srv-01", 65);

        let first = dedup.ingest(&candidate);
        let second = dedup.ingest(&candidate);

        assert!(first.is_some());
        assert!(second.is_none(), "duplicate event should return None");
    }

    #[test]
    fn test_dedup_when_different_assets_then_opens_separate_windows() {
        let dedup = AlertDeduplicator::default_window();
        let tenant = TenantId::new();

        let c1 = make_candidate(tenant, "web-srv-01", 65);
        let c2 = make_candidate(tenant, "db-srv-01", 65);

        let r1 = dedup.ingest(&c1);
        let r2 = dedup.ingest(&c2);

        assert!(r1.is_some());
        assert!(r2.is_some(), "different asset should open a new window");
    }
}
