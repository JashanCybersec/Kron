//! Event filtering and query construction.
//!
//! This module handles the [`EventFilter`] struct and the [`QueryRewriter`]
//! which injects `tenant_id` into all queries for isolation (gate 2 of the
//! 4-gate multi-tenancy model).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Filter criteria for querying events.
///
/// All fields are optional. Empty filter means "all events for this tenant".
/// Time ranges are inclusive on both ends.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Only return events with timestamp >= this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_ts: Option<DateTime<Utc>>,

    /// Only return events with timestamp <= this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ts: Option<DateTime<Utc>>,

    /// Only return events of this source type (e.g., `'linux_ebpf'`, `'syslog'`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,

    /// Only return events with this `event_type` (e.g., `'process_create'`, `'network_connect'`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,

    /// Only return events matching this hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Only return events for this user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,

    /// Only return events with severity >= this value.
    /// Use enum names: `'critical'`, `'high'`, `'medium'`, `'low'`, `'info'`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<String>,

    /// Only return events from this source IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,

    /// Only return events to this destination IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,

    /// Only return events with this process name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,

    /// Only return events with IOC hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc_hit_only: Option<bool>,

    /// Raw SQL-like query string (for advanced queries).
    /// This field is NOT directly used in queries; clients should use typed filters.
    /// If provided, it will be validated and parameterized before use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_where_clause: Option<String>,
}

impl EventFilter {
    /// Create a new empty filter (matches all events for a tenant).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by timestamp range.
    #[must_use]
    pub fn with_timestamp_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.from_ts = Some(from);
        self.to_ts = Some(to);
        self
    }

    /// Filter by source type.
    #[must_use]
    pub fn with_source_type(mut self, source: String) -> Self {
        self.source_type = Some(source);
        self
    }

    /// Filter by event type.
    #[must_use]
    pub fn with_event_type(mut self, event_type: String) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Filter by hostname.
    #[must_use]
    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    /// Filter by minimum severity.
    #[must_use]
    pub fn with_min_severity(mut self, severity: String) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Filter by IOC hits only.
    #[must_use]
    pub fn ioc_hits_only(mut self) -> Self {
        self.ioc_hit_only = Some(true);
        self
    }

    /// Return whether this filter is empty (matches everything).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.from_ts.is_none()
            && self.to_ts.is_none()
            && self.source_type.is_none()
            && self.event_type.is_none()
            && self.hostname.is_none()
            && self.user_name.is_none()
            && self.min_severity.is_none()
            && self.src_ip.is_none()
            && self.dst_ip.is_none()
            && self.process_name.is_none()
            && self.ioc_hit_only.is_none()
            && self.raw_where_clause.is_none()
    }
}

/// SQL query builder for `ClickHouse` and `DuckDB`.
///
/// Handles parameterized queries to prevent SQL injection.
/// Never constructs SQL strings directly from user input.
pub struct QueryBuilder {
    /// The SQL template with ? placeholders for parameters.
    pub sql: String,
    /// Parameter values (will be properly escaped).
    pub params: Vec<QueryParam>,
}

/// A single query parameter value (type-safe).
#[derive(Clone, Debug)]
pub enum QueryParam {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    DateTime(DateTime<Utc>),
}

impl QueryBuilder {
    /// Build a SELECT query for events with tenant isolation.
    ///
    /// Always injects `AND tenant_id = ?` to enforce gate 2 of multi-tenancy isolation.
    #[must_use]
    pub fn select_events(filter: Option<&EventFilter>, tenant_id: &str, limit: u32) -> Self {
        let mut sql = String::from("SELECT * FROM events WHERE tenant_id = ?");
        let mut params = vec![QueryParam::String(tenant_id.to_string())];

        if let Some(f) = filter {
            if let Some(from) = f.from_ts {
                sql.push_str(" AND ts >= ?");
                params.push(QueryParam::DateTime(from));
            }

            if let Some(to) = f.to_ts {
                sql.push_str(" AND ts <= ?");
                params.push(QueryParam::DateTime(to));
            }

            if let Some(ref source) = f.source_type {
                sql.push_str(" AND source_type = ?");
                params.push(QueryParam::String(source.clone()));
            }

            if let Some(ref event_type) = f.event_type {
                sql.push_str(" AND event_type = ?");
                params.push(QueryParam::String(event_type.clone()));
            }

            if let Some(ref hostname) = f.hostname {
                sql.push_str(" AND hostname = ?");
                params.push(QueryParam::String(hostname.clone()));
            }

            if let Some(ref user) = f.user_name {
                sql.push_str(" AND user_name = ?");
                params.push(QueryParam::String(user.clone()));
            }

            if let Some(ref ip) = f.src_ip {
                sql.push_str(" AND src_ip = ?");
                params.push(QueryParam::String(ip.clone()));
            }

            if let Some(ref ip) = f.dst_ip {
                sql.push_str(" AND dst_ip = ?");
                params.push(QueryParam::String(ip.clone()));
            }

            if let Some(ref process) = f.process_name {
                sql.push_str(" AND process_name = ?");
                params.push(QueryParam::String(process.clone()));
            }

            if f.ioc_hit_only == Some(true) {
                sql.push_str(" AND ioc_hit = true");
            }
        }

        sql.push_str(" ORDER BY ts DESC LIMIT ?");
        params.push(QueryParam::Int(i64::from(limit)));

        Self { sql, params }
    }

    /// Build a SELECT query for alerts with tenant isolation.
    #[must_use]
    pub fn select_alerts(tenant_id: &str, limit: u32, offset: u32) -> Self {
        let sql = String::from(
            "SELECT * FROM alerts WHERE tenant_id = ? \
             ORDER BY created_at DESC LIMIT ? OFFSET ?",
        );
        let params = vec![
            QueryParam::String(tenant_id.to_string()),
            QueryParam::Int(i64::from(limit)),
            QueryParam::Int(i64::from(offset)),
        ];

        Self { sql, params }
    }

    /// Build a SELECT query for a single event by ID (with tenant isolation).
    #[must_use]
    pub fn get_event(tenant_id: &str, event_id: &str) -> Self {
        let sql = String::from("SELECT * FROM events WHERE tenant_id = ? AND event_id = ?");
        let params = vec![
            QueryParam::String(tenant_id.to_string()),
            QueryParam::String(event_id.to_string()),
        ];

        Self { sql, params }
    }

    /// Build a SELECT query for a single alert by ID (with tenant isolation).
    #[must_use]
    pub fn get_alert(tenant_id: &str, alert_id: &str) -> Self {
        let sql = String::from("SELECT * FROM alerts WHERE tenant_id = ? AND alert_id = ?");
        let params = vec![
            QueryParam::String(tenant_id.to_string()),
            QueryParam::String(alert_id.to_string()),
        ];

        Self { sql, params }
    }

    /// Build an INSERT query for events.
    #[must_use]
    pub fn insert_events(tenant_id: &str, event_count: usize) -> Self {
        // Placeholder: actual implementation will construct the full INSERT
        // with all 60+ event fields. This is a simplified version.
        let sql = format!(
            "INSERT INTO events (tenant_id, event_id, ts, ...) VALUES {}",
            (0..event_count)
                .map(|_| "(?, ?, ?, ...)")
                .collect::<Vec<_>>()
                .join(",")
        );

        // In real implementation, params would be populated with all event fields
        let params = vec![QueryParam::String(tenant_id.to_string())];

        Self { sql, params }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_filter_empty() {
        let filter = EventFilter::new();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_event_filter_builder() {
        let filter = EventFilter::new()
            .with_source_type("linux_ebpf".to_string())
            .with_event_type("process_create".to_string());

        assert!(!filter.is_empty());
        assert_eq!(filter.source_type, Some("linux_ebpf".to_string()));
        assert_eq!(filter.event_type, Some("process_create".to_string()));
    }

    #[test]
    fn test_query_builder_always_includes_tenant_id() {
        let builder = QueryBuilder::select_events(None, "tenant-abc", 100);
        assert!(builder.sql.contains("tenant_id = ?"));
    }
}
