//! In-memory entity relationship graph.
//!
//! [`EntityGraph`] tracks users, hosts, and IP addresses observed across
//! events, accumulating per-entity risk scores and mapping edges between
//! related entities. It is used by the detection pipeline to escalate risk
//! for entities that appear in multiple high-score alerts.
//!
//! All operations are thread-safe via [`DashMap`].

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use kron_types::event::KronEvent;

/// The kind of entity represented in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityKind {
    /// A user account (identified by username).
    User,
    /// A host machine (identified by hostname).
    Host,
    /// An IP address (source or destination).
    Ip,
}

impl EntityKind {
    /// Returns the short string prefix used in entity graph keys.
    fn prefix(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Host => "host",
            Self::Ip => "ip",
        }
    }
}

/// A single node in the entity graph.
#[derive(Debug, Clone)]
pub struct Entity {
    /// What kind of entity this is.
    pub kind: EntityKind,
    /// Unique identifier for this entity (username, hostname, or IP string).
    pub id: String,
    /// Timestamp of the most recent event that referenced this entity.
    pub last_seen: DateTime<Utc>,
    /// Accumulated maximum risk score seen for this entity across all events.
    pub risk_score: u8,
}

/// A directed edge between two entities in the graph.
#[derive(Debug, Clone)]
pub struct EntityEdge {
    /// Graph key of the source entity.
    pub from_id: String,
    /// Graph key of the destination entity.
    pub to_id: String,
    /// Timestamp of the most recent event that produced this edge.
    pub last_seen: DateTime<Utc>,
    /// Total number of events that produced this edge.
    pub event_count: u64,
}

/// Thread-safe in-memory entity relationship graph.
///
/// Entities are keyed as `"<kind>:<id>"` (e.g. `"host:srv-web-01"`).
/// Edges are keyed as `"<from_key>-><to_key>"`.
///
/// Risk scores are updated by taking `max(current, new)` — they only ever
/// increase, reflecting the worst event seen for each entity.
pub struct EntityGraph {
    entities: DashMap<String, Entity>,
    edges: DashMap<String, EntityEdge>,
}

impl EntityGraph {
    /// Create a new, empty entity graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entities: DashMap::new(),
            edges: DashMap::new(),
        }
    }

    /// Update the graph with a new event.
    ///
    /// - Adds or refreshes Host/User/Ip entities present in the event.
    /// - Adds User→Host and Host→Ip edges where both endpoints are present.
    /// - Entity risk scores are updated to `max(current, risk_score)`.
    pub fn update(&self, event: &KronEvent, risk_score: u8) {
        let now = Utc::now();

        let host_key = event
            .hostname
            .as_deref()
            .map(|h| self.upsert_entity(EntityKind::Host, h, now, risk_score));

        let user_key = event
            .user_name
            .as_deref()
            .map(|u| self.upsert_entity(EntityKind::User, u, now, risk_score));

        let ip_key = event
            .src_ip
            .map(|ip| self.upsert_entity(EntityKind::Ip, &ip.to_string(), now, risk_score));

        // User → Host edge
        if let (Some(ref u), Some(ref h)) = (&user_key, &host_key) {
            self.upsert_edge(u, h, now);
        }

        // Host → Ip edge
        if let (Some(ref h), Some(ref ip)) = (&host_key, &ip_key) {
            self.upsert_edge(h, ip, now);
        }
    }

    /// Return the current accumulated risk score for an entity.
    ///
    /// Returns `0` when the entity is not present in the graph.
    #[must_use]
    pub fn entity_risk(&self, kind: EntityKind, id: &str) -> u8 {
        let key = Self::entity_key(kind, id);
        self.entities.get(&key).map_or(0, |e| e.risk_score)
    }

    /// Return the total number of unique entities currently tracked.
    #[must_use]
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Insert or update an entity, returning its graph key.
    fn upsert_entity(
        &self,
        kind: EntityKind,
        id: &str,
        now: DateTime<Utc>,
        risk_score: u8,
    ) -> String {
        let key = Self::entity_key(kind, id);
        self.entities
            .entry(key.clone())
            .and_modify(|e| {
                e.last_seen = now;
                if risk_score > e.risk_score {
                    e.risk_score = risk_score;
                }
            })
            .or_insert_with(|| Entity {
                kind,
                id: id.to_string(),
                last_seen: now,
                risk_score,
            });
        key
    }

    /// Insert or update an edge, returning its graph key.
    fn upsert_edge(&self, from_key: &str, to_key: &str, now: DateTime<Utc>) {
        let edge_key = format!("{from_key}->{to_key}");
        self.edges
            .entry(edge_key.clone())
            .and_modify(|e| {
                e.last_seen = now;
                e.event_count = e.event_count.saturating_add(1);
            })
            .or_insert_with(|| EntityEdge {
                from_id: from_key.to_string(),
                to_id: to_key.to_string(),
                last_seen: now,
                event_count: 1,
            });
    }

    /// Build the canonical graph key for an entity.
    fn entity_key(kind: EntityKind, id: &str) -> String {
        format!("{}:{}", kind.prefix(), id)
    }
}

impl Default for EntityGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use chrono::Utc;
    use kron_types::enums::EventSource;
    use kron_types::ids::TenantId;

    use super::*;

    fn event_with_hostname(hostname: &str) -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .ts(Utc::now())
            .hostname(hostname)
            .build()
            .expect("valid event")
    }

    fn event_with_user(user: &str) -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("login")
            .ts(Utc::now())
            .user_name(user)
            .build()
            .expect("valid event")
    }

    #[test]
    fn test_update_when_event_with_host_then_entity_added() {
        let graph = EntityGraph::new();
        let event = event_with_hostname("srv-web-01");
        graph.update(&event, 50);

        assert_eq!(graph.entity_count(), 1);
        assert_eq!(graph.entity_risk(EntityKind::Host, "srv-web-01"), 50);
    }

    #[test]
    fn test_entity_risk_when_no_entity_then_zero() {
        let graph = EntityGraph::new();
        assert_eq!(graph.entity_risk(EntityKind::Host, "unknown-host"), 0);
    }

    #[test]
    fn test_update_when_higher_risk_then_risk_updated() {
        let graph = EntityGraph::new();
        let event = event_with_hostname("srv-db-01");

        graph.update(&event, 30);
        assert_eq!(graph.entity_risk(EntityKind::Host, "srv-db-01"), 30);

        graph.update(&event, 80);
        assert_eq!(graph.entity_risk(EntityKind::Host, "srv-db-01"), 80);

        // Lower score must not reduce the accumulated maximum.
        graph.update(&event, 20);
        assert_eq!(graph.entity_risk(EntityKind::Host, "srv-db-01"), 80);
    }

    #[test]
    fn test_update_when_user_event_then_user_entity_added() {
        let graph = EntityGraph::new();
        let event = event_with_user("alice");
        graph.update(&event, 40);

        assert_eq!(graph.entity_risk(EntityKind::User, "alice"), 40);
    }

    #[test]
    fn test_entity_count_when_multiple_entities_then_correct_count() {
        let graph = EntityGraph::new();
        graph.update(&event_with_hostname("host-a"), 10);
        graph.update(&event_with_hostname("host-b"), 20);
        graph.update(&event_with_user("bob"), 30);

        assert_eq!(graph.entity_count(), 3);
    }
}
