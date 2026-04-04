//! Agent registry and per-agent rate limiter.
//!
//! [`AgentRegistry`] is the single source of truth for all registered agents.
//! It tracks liveness via heartbeat timestamps and marks agents "dark" when
//! they exceed the configured timeout.
//!
//! [`AgentRateLimiter`] implements a 1-second sliding window token bucket
//! per agent, capping event ingestion at `max_eps_per_agent`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use kron_types::{AgentId, RegisterRequest, TenantId};
use uuid::Uuid;

// ─── AgentRecord ─────────────────────────────────────────────────────────────

/// Metadata for a registered agent, persisted in [`AgentRegistry`].
#[derive(Debug, Clone)]
pub struct AgentRecord {
    /// Stable agent identifier assigned at registration.
    pub agent_id: AgentId,
    /// Tenant this agent belongs to.
    pub tenant_id: TenantId,
    /// FQDN or short hostname of the agent host.
    pub hostname: String,
    /// Primary IPv4 address of the agent host.
    pub host_ip: String,
    /// Semantic version of the kron-agent binary.
    pub agent_version: String,
    /// OS distribution string.
    pub os_name: String,
    /// Arbitrary key=value labels configured in agent.toml.
    pub labels: HashMap<String, String>,
    /// UTC timestamp when this agent first registered.
    #[allow(dead_code)]
    pub registered_at: DateTime<Utc>,
    /// UTC timestamp of the most recent heartbeat (or registration).
    pub last_heartbeat_at: DateTime<Utc>,
    /// True when the agent has exceeded the heartbeat timeout.
    pub is_dark: bool,
    /// Highest sequence number seen from this agent. `None` before first batch.
    pub last_sequence: Option<u64>,
}

// ─── AgentRateLimiter ────────────────────────────────────────────────────────

/// Per-agent 1-second sliding window token bucket.
///
/// Allows up to `max_eps` events per second. When the window rolls over,
/// the counter resets. This is a simple approximation — not a true sliding
/// window — but is accurate to within ±1 second.
#[derive(Debug)]
pub struct AgentRateLimiter {
    /// Monotonic start of the current 1-second window.
    window_start: Instant,
    /// Events counted in the current window.
    count_in_window: u32,
    /// Maximum events per second for this agent.
    max_eps: u32,
}

impl AgentRateLimiter {
    /// Creates a new rate limiter with the given EPS ceiling.
    #[must_use]
    pub fn new(max_eps: u32) -> Self {
        Self {
            window_start: Instant::now(),
            count_in_window: 0,
            max_eps,
        }
    }

    /// Checks whether `event_count` more events are allowed in the current window.
    ///
    /// If allowed, the count is recorded and `true` is returned.
    /// If denied (would exceed the limit), `false` is returned and the count is
    /// **not** incremented so callers can report exact over-limit counts.
    pub fn check_and_record(&mut self, event_count: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.count_in_window = 0;
        }
        if self.count_in_window.saturating_add(event_count) > self.max_eps {
            false
        } else {
            self.count_in_window = self.count_in_window.saturating_add(event_count);
            true
        }
    }
}

// ─── AgentRegistry ───────────────────────────────────────────────────────────

/// In-memory registry of all registered agents.
///
/// Held behind `Arc<RwLock<AgentRegistry>>` and shared across gRPC handlers,
/// the dark-agent monitor, and the metrics reporter.
pub struct AgentRegistry {
    /// Primary map: `agent_id` → record.
    agents: HashMap<AgentId, AgentRecord>,
    /// Per-agent rate limiters. Separate from the record so the read lock
    /// on `agents` doesn't block rate-limit checks.
    rate_limiters: HashMap<AgentId, AgentRateLimiter>,
    /// EPS ceiling to assign to newly registered agents.
    max_eps_per_agent: u32,
}

impl AgentRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new(max_eps_per_agent: u32) -> Self {
        Self {
            agents: HashMap::new(),
            rate_limiters: HashMap::new(),
            max_eps_per_agent,
        }
    }

    /// Registers an agent, assigning it an [`AgentId`] and the given [`TenantId`].
    ///
    /// If an agent with the same hostname already exists, the existing record is
    /// updated and the existing [`AgentId`] is returned (idempotent re-registration).
    ///
    /// Returns `(agent_id, is_new)`.
    pub fn register(&mut self, req: &RegisterRequest, tenant_id: TenantId) -> (AgentId, bool) {
        // Check if this hostname is already registered.
        let existing = self.agents.values().find(|r| r.hostname == req.hostname);
        if let Some(record) = existing {
            let agent_id = record.agent_id;
            // Update the record in-place with fresh metadata.
            if let Some(r) = self.agents.get_mut(&agent_id) {
                r.last_heartbeat_at = Utc::now();
                r.is_dark = false;
                req.agent_version.clone_into(&mut r.agent_version);
                req.host_ip.clone_into(&mut r.host_ip);
                req.os_name.clone_into(&mut r.os_name);
                req.labels.clone_into(&mut r.labels);
            }
            return (agent_id, false);
        }

        let agent_id = AgentId::from_uuid(Uuid::new_v4());
        let now = Utc::now();
        let record = AgentRecord {
            agent_id,
            tenant_id,
            hostname: req.hostname.clone(),
            host_ip: req.host_ip.clone(),
            agent_version: req.agent_version.clone(),
            os_name: req.os_name.clone(),
            labels: req.labels.clone(),
            registered_at: now,
            last_heartbeat_at: now,
            is_dark: false,
            last_sequence: None,
        };
        self.agents.insert(agent_id, record);
        self.rate_limiters
            .insert(agent_id, AgentRateLimiter::new(self.max_eps_per_agent));
        (agent_id, true)
    }

    /// Records a heartbeat from an agent, updating `last_heartbeat_at` and clearing `is_dark`.
    ///
    /// Returns `true` if the agent was found, `false` if the `agent_id` is unknown.
    pub fn record_heartbeat(&mut self, agent_id: AgentId) -> bool {
        if let Some(record) = self.agents.get_mut(&agent_id) {
            record.last_heartbeat_at = Utc::now();
            record.is_dark = false;
            true
        } else {
            false
        }
    }

    /// Marks an agent as "dark" (heartbeat timeout exceeded).
    pub fn mark_dark(&mut self, agent_id: AgentId) {
        if let Some(record) = self.agents.get_mut(&agent_id) {
            record.is_dark = true;
        }
    }

    /// Returns the IDs of all agents whose last heartbeat is older than `timeout`.
    ///
    /// Only non-dark agents are returned (avoids repeated marking).
    #[must_use]
    pub fn find_timed_out_agents(&self, timeout: Duration) -> Vec<AgentId> {
        let threshold = Utc::now()
            - chrono::Duration::from_std(timeout).unwrap_or(chrono::Duration::seconds(90));
        self.agents
            .values()
            .filter(|r| !r.is_dark && r.last_heartbeat_at < threshold)
            .map(|r| r.agent_id)
            .collect()
    }

    /// Returns the tenant ID for an agent, or `None` if the agent is unknown.
    #[must_use]
    pub fn tenant_id(&self, agent_id: &AgentId) -> Option<TenantId> {
        self.agents.get(agent_id).map(|r| r.tenant_id)
    }

    /// Returns a reference to the agent record, or `None` if not found.
    #[must_use]
    #[allow(dead_code)]
    pub fn get(&self, agent_id: &AgentId) -> Option<&AgentRecord> {
        self.agents.get(agent_id)
    }

    /// Checks the per-agent rate limit for `event_count` events.
    ///
    /// Returns `true` if the events are within the rate limit and were recorded.
    /// Returns `false` if the agent would exceed its EPS ceiling.
    /// Returns `false` if the `agent_id` is unknown.
    pub fn check_rate_limit(&mut self, agent_id: &AgentId, event_count: u32) -> bool {
        if let Some(limiter) = self.rate_limiters.get_mut(agent_id) {
            limiter.check_and_record(event_count)
        } else {
            false
        }
    }

    /// Updates the last-seen sequence number for an agent.
    ///
    /// Returns `true` if the sequence is new (≥ last seen), `false` if it looks
    /// like a duplicate or out-of-order replay.
    pub fn update_sequence(&mut self, agent_id: &AgentId, sequence: u64) -> bool {
        if let Some(record) = self.agents.get_mut(agent_id) {
            match record.last_sequence {
                None => {
                    record.last_sequence = Some(sequence);
                    true
                }
                Some(last) if sequence > last => {
                    record.last_sequence = Some(sequence);
                    true
                }
                Some(last) if sequence == last => {
                    // Exact duplicate — agent retried the same batch.
                    tracing::warn!(
                        agent_id = %agent_id,
                        sequence,
                        "Duplicate batch sequence received; accepting to preserve at-least-once"
                    );
                    true
                }
                Some(last) => {
                    tracing::warn!(
                        agent_id = %agent_id,
                        sequence,
                        last_seen = last,
                        "Out-of-order batch sequence received"
                    );
                    false
                }
            }
        } else {
            false
        }
    }

    /// Returns the count of currently active (non-dark) agents.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.agents.values().filter(|r| !r.is_dark).count()
    }

    /// Returns an iterator over all agent records.
    pub fn all_agents(&self) -> impl Iterator<Item = &AgentRecord> {
        self.agents.values()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_request(hostname: &str) -> RegisterRequest {
        RegisterRequest {
            hostname: hostname.to_owned(),
            agent_version: "0.1.0".to_owned(),
            kernel_version: "5.15.0".to_owned(),
            os_name: "Ubuntu 22.04".to_owned(),
            host_ip: "10.0.0.1".to_owned(),
            labels: HashMap::new(),
        }
    }

    fn dummy_tenant() -> TenantId {
        TenantId::from_uuid(Uuid::new_v4())
    }

    #[test]
    fn test_register_when_new_host_then_assigned_agent_id() {
        let mut registry = AgentRegistry::new(1_000);
        let req = make_request("web-01");
        let tenant = dummy_tenant();

        let (agent_id, is_new) = registry.register(&req, tenant);

        assert!(is_new);
        assert!(registry.get(&agent_id).is_some());
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_register_when_same_host_twice_then_idempotent() {
        let mut registry = AgentRegistry::new(1_000);
        let req = make_request("web-01");
        let tenant = dummy_tenant();

        let (id1, _) = registry.register(&req, tenant);
        let (id2, is_new) = registry.register(&req, tenant);

        assert_eq!(id1, id2, "Same hostname must return same AgentId");
        assert!(!is_new);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_rate_limiter_when_within_limit_then_allowed() {
        let mut registry = AgentRegistry::new(1_000);
        let (agent_id, _) = registry.register(&make_request("h1"), dummy_tenant());

        assert!(registry.check_rate_limit(&agent_id, 500));
        assert!(registry.check_rate_limit(&agent_id, 499));
    }

    #[test]
    fn test_rate_limiter_when_exceeds_limit_then_denied() {
        let mut registry = AgentRegistry::new(100);
        let (agent_id, _) = registry.register(&make_request("h1"), dummy_tenant());

        registry.check_rate_limit(&agent_id, 100);
        assert!(!registry.check_rate_limit(&agent_id, 1));
    }

    #[test]
    fn test_sequence_when_increasing_then_accepted() {
        let mut registry = AgentRegistry::new(1_000);
        let (agent_id, _) = registry.register(&make_request("h1"), dummy_tenant());

        assert!(registry.update_sequence(&agent_id, 0));
        assert!(registry.update_sequence(&agent_id, 1));
        assert!(registry.update_sequence(&agent_id, 2));
    }

    #[test]
    fn test_sequence_when_out_of_order_then_rejected() {
        let mut registry = AgentRegistry::new(1_000);
        let (agent_id, _) = registry.register(&make_request("h1"), dummy_tenant());

        registry.update_sequence(&agent_id, 5);
        assert!(!registry.update_sequence(&agent_id, 3));
    }
}
