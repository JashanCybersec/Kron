//! The canonical KRON event type.
//!
//! [`KronEvent`] represents a single security-relevant event after normalization.
//! It maps 1:1 to a row in the ClickHouse/DuckDB `events` table (see `docs/Database.md`).
//! All 60+ fields from the database schema are represented here.
//!
//! # Building events
//!
//! Use [`KronEventBuilder`] via [`KronEvent::builder()`] to construct events.
//! Required fields: `tenant_id`, `source_type`, `event_type`, `ts`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::enums::{
    AssetCriticality, AuthResult, EventCategory, EventSource, FileAction, NetworkDirection,
    Severity, UserType,
};
use crate::error::KronError;
use crate::ids::{EventId, TenantId};

/// A normalized security event in the KRON platform.
///
/// Represents a single row in the `events` ClickHouse/DuckDB table.
/// Events are append-only after creation. Fields are organized by functional
/// group matching the database schema defined in `docs/Database.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KronEvent {
    // --- Identity ---
    /// Unique event identifier. Auto-generated if not provided via builder.
    pub event_id: EventId,
    /// The tenant this event belongs to. Mandatory on every event.
    pub tenant_id: TenantId,
    /// xxHash3 deduplication fingerprint of canonical fields.
    /// Set to 0 at ingestion; computed by the normalizer.
    pub dedup_hash: u64,

    // --- Timing ---
    /// Timestamp of the original event, nanosecond precision UTC.
    pub ts: DateTime<Utc>,
    /// Timestamp when KRON received this event.
    pub ts_received: DateTime<Utc>,
    /// Milliseconds between the event timestamp and receipt time.
    pub ingest_lag_ms: u32,

    // --- Source ---
    /// The collection method or source system that produced this event.
    pub source_type: EventSource,
    /// The collector instance ID that ingested this event.
    pub collector_id: String,
    /// The raw original log line, stored verbatim for forensic replay.
    pub raw: String,

    // --- Asset context ---
    /// Opaque asset identifier from the asset inventory.
    pub host_id: Option<String>,
    /// Short hostname of the asset.
    pub hostname: Option<String>,
    /// Primary IPv4 address of the asset.
    pub host_ip: Option<Ipv4Addr>,
    /// Fully qualified domain name of the asset.
    pub host_fqdn: Option<String>,
    /// Criticality rating of the asset from the asset inventory.
    pub asset_criticality: AssetCriticality,
    /// Free-form tags from the asset inventory (e.g. `["prod", "payment"]`).
    pub asset_tags: Vec<String>,

    // --- User context ---
    /// Username of the actor (human or service) in the event.
    pub user_name: Option<String>,
    /// Directory or system identifier for the user.
    pub user_id: Option<String>,
    /// Active Directory domain or authentication realm.
    pub user_domain: Option<String>,
    /// Type of user account: human, service, or system.
    pub user_type: Option<UserType>,

    // --- Event classification ---
    /// Normalized event type name (e.g. `process_create`, `network_connect`).
    pub event_type: String,
    /// High-level OCSF category of this event.
    pub event_category: Option<EventCategory>,
    /// Specific action within the category (e.g. `login_failed`).
    pub event_action: Option<String>,

    // --- Network fields ---
    /// Source IPv4 address.
    pub src_ip: Option<Ipv4Addr>,
    /// Source IPv6 address.
    pub src_ip6: Option<Ipv6Addr>,
    /// Source TCP/UDP port.
    pub src_port: Option<u16>,
    /// Destination IPv4 address.
    pub dst_ip: Option<Ipv4Addr>,
    /// Destination IPv6 address.
    pub dst_ip6: Option<Ipv6Addr>,
    /// Destination TCP/UDP port.
    pub dst_port: Option<u16>,
    /// Network protocol (e.g. "tcp", "udp", "icmp").
    pub protocol: Option<String>,
    /// Bytes received by the monitored asset.
    pub bytes_in: Option<u64>,
    /// Bytes sent by the monitored asset.
    pub bytes_out: Option<u64>,
    /// Packets received by the monitored asset.
    pub packets_in: Option<u32>,
    /// Packets sent by the monitored asset.
    pub packets_out: Option<u32>,
    /// Traffic direction relative to the monitored asset.
    pub direction: Option<NetworkDirection>,

    // --- Process fields ---
    /// Name of the process (basename of the executable).
    pub process_name: Option<String>,
    /// Process ID.
    pub process_pid: Option<u32>,
    /// Parent process ID.
    pub process_ppid: Option<u32>,
    /// Full path to the process executable.
    pub process_path: Option<String>,
    /// Full command line including arguments.
    pub process_cmdline: Option<String>,
    /// SHA256 hash of the process binary.
    pub process_hash: Option<String>,
    /// Name of the parent process.
    pub parent_process: Option<String>,

    // --- File fields ---
    /// Full path to the file.
    pub file_path: Option<String>,
    /// Filename without directory component.
    pub file_name: Option<String>,
    /// SHA256 hash of the file contents.
    pub file_hash: Option<String>,
    /// File size in bytes.
    pub file_size: Option<u64>,
    /// File system operation that was performed.
    pub file_action: Option<FileAction>,

    // --- Authentication fields ---
    /// Whether authentication succeeded or failed.
    pub auth_result: Option<AuthResult>,
    /// Authentication mechanism (e.g. "kerberos", "password", "certificate").
    pub auth_method: Option<String>,
    /// Authentication protocol (e.g. "LDAP", "RADIUS", "SSH").
    pub auth_protocol: Option<String>,

    // --- Geo enrichment (added by normalizer) ---
    /// ISO 3166-1 alpha-2 country code for source IP (e.g. "IN", "US").
    pub src_country: Option<String>,
    /// City name for source IP.
    pub src_city: Option<String>,
    /// Autonomous System Number for source IP.
    pub src_asn: Option<u32>,
    /// AS organization name for source IP.
    pub src_asn_name: Option<String>,
    /// ISO 3166-1 alpha-2 country code for destination IP.
    pub dst_country: Option<String>,

    // --- Threat intel (added by stream processor) ---
    /// Whether this event matched any IOC.
    pub ioc_hit: bool,
    /// Type of IOC that matched (e.g. "ip", "domain", "sha256").
    pub ioc_type: Option<String>,
    /// The actual IOC value that matched.
    pub ioc_value: Option<String>,
    /// Name of the threat intel feed that provided the IOC.
    pub ioc_feed: Option<String>,

    // --- MITRE ATT&CK (added by stream processor) ---
    /// MITRE tactic name (e.g. "Lateral Movement").
    pub mitre_tactic: Option<String>,
    /// MITRE technique ID (e.g. "T1021").
    pub mitre_technique: Option<String>,
    /// MITRE sub-technique ID (e.g. "T1021.001").
    pub mitre_sub_tech: Option<String>,

    // --- Severity ---
    /// Qualitative severity level.
    pub severity: Severity,
    /// Numeric risk score 0–100.
    pub severity_score: u8,

    // --- AI scores (added by stream processor in Phase 2+) ---
    /// ONNX isolation forest anomaly score (0.0 = normal, 1.0 = anomalous).
    pub anomaly_score: f32,
    /// UEBA behavioral deviation score.
    pub ueba_score: f32,
    /// Periodic beaconing detection score.
    pub beacon_score: f32,
    /// Data exfiltration risk score.
    pub exfil_score: f32,

    // --- Flexible fields ---
    /// Source-specific key-value fields that did not map to a canonical field.
    pub fields: HashMap<String, String>,

    // --- Audit ---
    /// Schema version for forward compatibility. Increment when adding mandatory fields.
    pub schema_version: u8,
}

impl KronEvent {
    /// Creates a new [`KronEventBuilder`].
    #[must_use]
    pub fn builder() -> KronEventBuilder {
        KronEventBuilder::new()
    }
}

/// Builder for [`KronEvent`].
///
/// Required fields: `tenant_id`, `source_type`, `event_type`, `ts`.
/// All other fields default to `None`, `false`, `0.0`, or empty collections.
#[derive(Debug, Default)]
pub struct KronEventBuilder {
    tenant_id: Option<TenantId>,
    source_type: Option<EventSource>,
    event_type: Option<String>,
    ts: Option<DateTime<Utc>>,
    // Optional overrides
    event_id: Option<EventId>,
    dedup_hash: Option<u64>,
    collector_id: Option<String>,
    raw: Option<String>,
    host_id: Option<String>,
    hostname: Option<String>,
    host_ip: Option<Ipv4Addr>,
    host_fqdn: Option<String>,
    asset_criticality: Option<AssetCriticality>,
    asset_tags: Vec<String>,
    user_name: Option<String>,
    user_id: Option<String>,
    user_domain: Option<String>,
    user_type: Option<UserType>,
    event_category: Option<EventCategory>,
    event_action: Option<String>,
    src_ip: Option<Ipv4Addr>,
    src_ip6: Option<Ipv6Addr>,
    src_port: Option<u16>,
    dst_ip: Option<Ipv4Addr>,
    dst_ip6: Option<Ipv6Addr>,
    dst_port: Option<u16>,
    protocol: Option<String>,
    bytes_in: Option<u64>,
    bytes_out: Option<u64>,
    packets_in: Option<u32>,
    packets_out: Option<u32>,
    direction: Option<NetworkDirection>,
    process_name: Option<String>,
    process_pid: Option<u32>,
    process_ppid: Option<u32>,
    process_path: Option<String>,
    process_cmdline: Option<String>,
    process_hash: Option<String>,
    parent_process: Option<String>,
    file_path: Option<String>,
    file_name: Option<String>,
    file_hash: Option<String>,
    file_size: Option<u64>,
    file_action: Option<FileAction>,
    auth_result: Option<AuthResult>,
    auth_method: Option<String>,
    auth_protocol: Option<String>,
    src_country: Option<String>,
    src_city: Option<String>,
    src_asn: Option<u32>,
    src_asn_name: Option<String>,
    dst_country: Option<String>,
    severity: Option<Severity>,
    severity_score: Option<u8>,
    fields: HashMap<String, String>,
}

impl KronEventBuilder {
    /// Creates a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the tenant ID. **Required.**
    #[must_use]
    pub fn tenant_id(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Sets the event source type. **Required.**
    #[must_use]
    pub fn source_type(mut self, source_type: EventSource) -> Self {
        self.source_type = Some(source_type);
        self
    }

    /// Sets the normalized event type name. **Required.**
    #[must_use]
    pub fn event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// Sets the event timestamp. **Required.**
    #[must_use]
    pub fn ts(mut self, ts: DateTime<Utc>) -> Self {
        self.ts = Some(ts);
        self
    }

    /// Overrides the auto-generated event ID.
    #[must_use]
    pub fn event_id(mut self, event_id: EventId) -> Self {
        self.event_id = Some(event_id);
        self
    }

    /// Sets the raw original log line.
    #[must_use]
    pub fn raw(mut self, raw: impl Into<String>) -> Self {
        self.raw = Some(raw.into());
        self
    }

    /// Sets the collector instance ID.
    #[must_use]
    pub fn collector_id(mut self, collector_id: impl Into<String>) -> Self {
        self.collector_id = Some(collector_id.into());
        self
    }

    /// Sets the hostname.
    #[must_use]
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Sets the host IPv4 address.
    #[must_use]
    pub fn host_ip(mut self, ip: Ipv4Addr) -> Self {
        self.host_ip = Some(ip);
        self
    }

    /// Sets the asset criticality.
    #[must_use]
    pub fn asset_criticality(mut self, criticality: AssetCriticality) -> Self {
        self.asset_criticality = Some(criticality);
        self
    }

    /// Sets the username.
    #[must_use]
    pub fn user_name(mut self, user_name: impl Into<String>) -> Self {
        self.user_name = Some(user_name.into());
        self
    }

    /// Sets the event category.
    #[must_use]
    pub fn event_category(mut self, category: EventCategory) -> Self {
        self.event_category = Some(category);
        self
    }

    /// Sets the source IPv4 address.
    #[must_use]
    pub fn src_ip(mut self, ip: Ipv4Addr) -> Self {
        self.src_ip = Some(ip);
        self
    }

    /// Sets the destination IPv4 address.
    #[must_use]
    pub fn dst_ip(mut self, ip: Ipv4Addr) -> Self {
        self.dst_ip = Some(ip);
        self
    }

    /// Sets the source port.
    #[must_use]
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    /// Sets the destination port.
    #[must_use]
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// Sets the network protocol.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Sets the process name.
    #[must_use]
    pub fn process_name(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    /// Sets the process ID.
    #[must_use]
    pub fn process_pid(mut self, pid: u32) -> Self {
        self.process_pid = Some(pid);
        self
    }

    /// Sets the process command line.
    #[must_use]
    pub fn process_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.process_cmdline = Some(cmdline.into());
        self
    }

    /// Sets the severity level.
    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Sets the numeric severity score (0–100).
    #[must_use]
    pub fn severity_score(mut self, score: u8) -> Self {
        self.severity_score = Some(score);
        self
    }

    /// Adds a custom field to the flexible `fields` map.
    #[must_use]
    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// Builds the [`KronEvent`].
    ///
    /// # Errors
    ///
    /// Returns [`KronError::MissingField`] if any required field is not set.
    pub fn build(self) -> Result<KronEvent, KronError> {
        let tenant_id = self.tenant_id.ok_or_else(|| KronError::MissingField {
            field: "tenant_id".to_string(),
        })?;
        let source_type = self.source_type.ok_or_else(|| KronError::MissingField {
            field: "source_type".to_string(),
        })?;
        let event_type = self.event_type.ok_or_else(|| KronError::MissingField {
            field: "event_type".to_string(),
        })?;
        let ts = self.ts.ok_or_else(|| KronError::MissingField {
            field: "ts".to_string(),
        })?;

        let now = Utc::now();
        let lag_ms = (now - ts).num_milliseconds().clamp(0, i64::from(u32::MAX));
        // Safe: lag_ms is clamped to 0..=u32::MAX above.
        let ingest_lag_ms = u32::try_from(lag_ms).unwrap_or(0);

        Ok(KronEvent {
            event_id: self.event_id.unwrap_or_default(),
            tenant_id,
            dedup_hash: self.dedup_hash.unwrap_or(0),
            ts,
            ts_received: now,
            ingest_lag_ms,
            source_type,
            collector_id: self.collector_id.unwrap_or_else(|| "unknown".to_string()),
            raw: self.raw.unwrap_or_default(),
            host_id: self.host_id,
            hostname: self.hostname,
            host_ip: self.host_ip,
            host_fqdn: self.host_fqdn,
            asset_criticality: self.asset_criticality.unwrap_or_default(),
            asset_tags: self.asset_tags,
            user_name: self.user_name,
            user_id: self.user_id,
            user_domain: self.user_domain,
            user_type: self.user_type,
            event_type,
            event_category: self.event_category,
            event_action: self.event_action,
            src_ip: self.src_ip,
            src_ip6: self.src_ip6,
            src_port: self.src_port,
            dst_ip: self.dst_ip,
            dst_ip6: self.dst_ip6,
            dst_port: self.dst_port,
            protocol: self.protocol,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            packets_in: self.packets_in,
            packets_out: self.packets_out,
            direction: self.direction,
            process_name: self.process_name,
            process_pid: self.process_pid,
            process_ppid: self.process_ppid,
            process_path: self.process_path,
            process_cmdline: self.process_cmdline,
            process_hash: self.process_hash,
            parent_process: self.parent_process,
            file_path: self.file_path,
            file_name: self.file_name,
            file_hash: self.file_hash,
            file_size: self.file_size,
            file_action: self.file_action,
            auth_result: self.auth_result,
            auth_method: self.auth_method,
            auth_protocol: self.auth_protocol,
            src_country: self.src_country,
            src_city: self.src_city,
            src_asn: self.src_asn,
            src_asn_name: self.src_asn_name,
            dst_country: self.dst_country,
            ioc_hit: false,
            ioc_type: None,
            ioc_value: None,
            ioc_feed: None,
            mitre_tactic: None,
            mitre_technique: None,
            mitre_sub_tech: None,
            severity: self.severity.unwrap_or_default(),
            severity_score: self.severity_score.unwrap_or(0),
            anomaly_score: 0.0,
            ueba_score: 0.0,
            beacon_score: 0.0,
            exfil_score: 0.0,
            fields: self.fields,
            schema_version: 1,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn minimal_event() -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .ts(Utc::now())
            .build()
            .expect("valid event")
    }

    #[test]
    fn test_event_builder_when_all_required_fields_then_builds_successfully() {
        let event = minimal_event();
        assert_eq!(event.event_type, "process_create");
        assert_eq!(event.schema_version, 1);
        assert!(!event.ioc_hit);
        assert!((event.anomaly_score - 0.0_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn test_event_builder_when_missing_tenant_id_then_returns_missing_field_error() {
        let result = KronEvent::builder()
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .ts(Utc::now())
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tenant_id"));
    }

    #[test]
    fn test_event_builder_when_missing_ts_then_returns_missing_field_error() {
        let result = KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ts"));
    }

    #[test]
    fn test_event_when_serialized_then_round_trips_through_json() {
        let event = minimal_event();
        let json = serde_json::to_string(&event).expect("must serialize");
        let back: KronEvent = serde_json::from_str(&json).expect("must deserialize");
        assert_eq!(event.event_id, back.event_id);
        assert_eq!(event.tenant_id, back.tenant_id);
        assert_eq!(event.event_type, back.event_type);
    }

    #[test]
    fn test_event_builder_when_network_fields_set_then_preserves_them() {
        let event = KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("network_connect")
            .ts(Utc::now())
            .src_ip("192.168.1.1".parse().expect("valid ip"))
            .dst_ip("8.8.8.8".parse().expect("valid ip"))
            .dst_port(443)
            .protocol("tcp")
            .event_category(EventCategory::Network)
            .build()
            .expect("valid event");

        assert_eq!(event.dst_port, Some(443));
        assert_eq!(event.protocol.as_deref(), Some("tcp"));
        assert_eq!(event.event_category, Some(EventCategory::Network));
    }

    #[test]
    fn test_event_builder_when_custom_fields_set_then_stored_in_fields_map() {
        let event = KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::Syslog)
            .event_type("custom_event")
            .ts(Utc::now())
            .field("app_name", "nginx")
            .field("request_id", "abc123")
            .build()
            .expect("valid event");

        assert_eq!(
            event.fields.get("app_name").map(String::as_str),
            Some("nginx")
        );
        assert_eq!(
            event.fields.get("request_id").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn test_event_builder_when_severity_set_then_preserves_score() {
        let event = KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("brute_force")
            .ts(Utc::now())
            .severity(Severity::High)
            .severity_score(65)
            .build()
            .expect("valid event");

        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.severity_score, 65);
    }
}
