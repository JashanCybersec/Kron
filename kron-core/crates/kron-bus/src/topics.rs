//! Topic name constants and per-tenant topic name helpers.
//!
//! All topic names in KRON follow a consistent naming scheme.
//! Use the functions in this module rather than constructing topic strings manually.

use kron_types::TenantId;

/// Prefix for raw event topics (`kron.raw.{tenant_id}`).
pub const PREFIX_RAW: &str = "kron.raw";

/// Prefix for normalized/enriched event topics (`kron.enriched.{tenant_id}`).
pub const PREFIX_ENRICHED: &str = "kron.enriched";

/// Prefix for alert candidate topics (`kron.alerts.{tenant_id}`).
pub const PREFIX_ALERTS: &str = "kron.alerts";

/// Shared audit log topic (not tenant-scoped — all audit entries go here).
pub const AUDIT: &str = "kron.audit";

/// Prefix for dead letter topics (`kron.deadletter.{source_topic}`).
pub const PREFIX_DEADLETTER: &str = "kron.deadletter";

/// Returns the raw events topic for `tenant_id`.
///
/// Format: `kron.raw.{tenant_id}`
///
/// Published to by: `kron-collector`
/// Consumed by: `kron-normalizer`
#[must_use]
pub fn raw_events(tenant_id: &TenantId) -> String {
    format!("{PREFIX_RAW}.{tenant_id}")
}

/// Returns the enriched events topic for `tenant_id`.
///
/// Format: `kron.enriched.{tenant_id}`
///
/// Published to by: `kron-normalizer`
/// Consumed by: `kron-stream`
#[must_use]
pub fn enriched_events(tenant_id: &TenantId) -> String {
    format!("{PREFIX_ENRICHED}.{tenant_id}")
}

/// Returns the alert candidates topic for `tenant_id`.
///
/// Format: `kron.alerts.{tenant_id}`
///
/// Published to by: `kron-stream`
/// Consumed by: `kron-alert`
#[must_use]
pub fn alerts(tenant_id: &TenantId) -> String {
    format!("{PREFIX_ALERTS}.{tenant_id}")
}

/// Returns the dead letter topic for a given source topic.
///
/// Format: `kron.deadletter.{source_topic}`
///
/// Messages are routed here after exceeding `max_retry_count` delivery attempts.
#[must_use]
pub fn dead_letter_for(source_topic: &str) -> String {
    format!("{PREFIX_DEADLETTER}.{source_topic}")
}

/// Returns true if `topic_name` matches the raw events prefix for any tenant.
#[must_use]
pub fn is_raw_events_topic(topic_name: &str) -> bool {
    topic_name.starts_with(PREFIX_RAW) && topic_name.len() > PREFIX_RAW.len() + 1
}

/// Returns true if `topic_name` matches the enriched events prefix for any tenant.
#[must_use]
pub fn is_enriched_events_topic(topic_name: &str) -> bool {
    topic_name.starts_with(PREFIX_ENRICHED) && topic_name.len() > PREFIX_ENRICHED.len() + 1
}

/// Returns true if `topic_name` is a dead letter topic.
#[must_use]
pub fn is_dead_letter_topic(topic_name: &str) -> bool {
    topic_name.starts_with(PREFIX_DEADLETTER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_events_topic_format() {
        let tenant = TenantId::new();
        let topic = raw_events(&tenant);
        assert!(topic.starts_with("kron.raw."));
        assert!(is_raw_events_topic(&topic));
    }

    #[test]
    fn test_dead_letter_topic_format() {
        let source = "kron.raw.some-tenant-id";
        let dlq = dead_letter_for(source);
        assert_eq!(dlq, "kron.deadletter.kron.raw.some-tenant-id");
        assert!(is_dead_letter_topic(&dlq));
    }

    #[test]
    fn test_audit_topic_is_not_dead_letter() {
        assert!(!is_dead_letter_topic(AUDIT));
    }
}
