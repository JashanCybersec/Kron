//! `ClickHouse` row structs and conversion functions.
//!
//! Each struct maps one-to-one to a `ClickHouse` table schema.
//! All timestamps are stored as nanoseconds (Int64) for DateTime64(9).
//! IPs are stored as String for driver compatibility.
//! Arrays and maps are stored as JSON strings.

use kron_types::{
    AssetCriticality, AuthResult, EventCategory, EventId, EventSource, FileAction, KronAlert,
    KronError, KronEvent, NetworkDirection, Severity, TenantId, UserType,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::traits::StorageResult;

// ─── Schema version tracking ────────────────────────────────────────────────

/// Row for the `schema_versions` migration tracking table.
#[derive(clickhouse::Row, Serialize, Deserialize)]
pub struct SchemaVersionRow {
    pub version: i32,
    pub name: String,
    pub applied_at: u32, // DateTime (seconds since epoch)
    pub checksum: String,
}

/// Minimal row for reading back applied versions.
#[derive(clickhouse::Row, Deserialize)]
pub struct SchemaVersionQueryRow {
    pub version: i32,
    pub checksum: String,
}

// ─── Events ─────────────────────────────────────────────────────────────────

/// `ClickHouse` row mapping the `events` table.
///
/// All 60+ fields from the KRON event schema.
/// Timestamps are nanoseconds since Unix epoch (Int64 / DateTime64(9)).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ChEventRow {
    pub event_id: String,
    pub tenant_id: String,
    pub dedup_hash: u64,
    pub ts: i64,
    pub ts_received: i64,
    pub ingest_lag_ms: u32,
    pub source_type: String,
    pub collector_id: String,
    pub raw: String,
    pub host_id: Option<String>,
    pub hostname: Option<String>,
    pub host_ip: Option<String>,
    pub host_fqdn: Option<String>,
    pub asset_criticality: String,
    pub asset_tags: String,
    pub user_name: Option<String>,
    pub user_id: Option<String>,
    pub user_domain: Option<String>,
    pub user_type: Option<String>,
    pub event_type: String,
    pub event_category: Option<String>,
    pub event_action: Option<String>,
    pub src_ip: Option<String>,
    pub src_ip6: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_ip6: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub packets_in: Option<u32>,
    pub packets_out: Option<u32>,
    pub direction: Option<String>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub process_ppid: Option<u32>,
    pub process_path: Option<String>,
    pub process_cmdline: Option<String>,
    pub process_hash: Option<String>,
    pub parent_process: Option<String>,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_hash: Option<String>,
    pub file_size: Option<u64>,
    pub file_action: Option<String>,
    pub auth_result: Option<String>,
    pub auth_method: Option<String>,
    pub auth_protocol: Option<String>,
    pub src_country: Option<String>,
    pub src_city: Option<String>,
    pub src_asn: Option<u32>,
    pub src_asn_name: Option<String>,
    pub dst_country: Option<String>,
    pub ioc_hit: bool,
    pub ioc_type: Option<String>,
    pub ioc_value: Option<String>,
    pub ioc_feed: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub mitre_sub_tech: Option<String>,
    pub severity: String,
    pub severity_score: u8,
    pub anomaly_score: f32,
    pub ueba_score: f32,
    pub beacon_score: f32,
    pub exfil_score: f32,
    pub fields: String,
    pub schema_version: u8,
}

/// Convert a [`KronEvent`] to a [`ChEventRow`] ready for insertion.
///
/// # Errors
/// Returns `KronError::Storage` if timestamp overflows `i64` nanoseconds
/// or if JSON serialization of `fields`/`asset_tags` fails.
pub fn event_to_ch_row(event: &KronEvent) -> StorageResult<ChEventRow> {
    let ts = event
        .ts
        .timestamp_nanos_opt()
        .ok_or_else(|| KronError::Storage("event.ts timestamp out of i64 range".to_string()))?;
    let ts_received = event
        .ts_received
        .timestamp_nanos_opt()
        .ok_or_else(|| KronError::Storage("event.ts_received out of i64 range".to_string()))?;

    let fields_json = serde_json::to_string(&event.fields)
        .map_err(|e| KronError::Storage(format!("failed to serialize event.fields: {e}")))?;
    let asset_tags_json = serde_json::to_string(&event.asset_tags)
        .map_err(|e| KronError::Storage(format!("failed to serialize event.asset_tags: {e}")))?;

    Ok(ChEventRow {
        event_id: event.event_id.to_string(),
        tenant_id: event.tenant_id.to_string(),
        dedup_hash: event.dedup_hash,
        ts,
        ts_received,
        ingest_lag_ms: event.ingest_lag_ms,
        source_type: event.source_type.to_string(),
        collector_id: event.collector_id.clone(),
        raw: event.raw.clone(),
        host_id: event.host_id.clone(),
        hostname: event.hostname.clone(),
        host_ip: event.host_ip.map(|ip| ip.to_string()),
        host_fqdn: event.host_fqdn.clone(),
        asset_criticality: event.asset_criticality.to_string(),
        asset_tags: asset_tags_json,
        user_name: event.user_name.clone(),
        user_id: event.user_id.clone(),
        user_domain: event.user_domain.clone(),
        user_type: event.user_type.as_ref().map(ToString::to_string),
        event_type: event.event_type.clone(),
        event_category: event.event_category.as_ref().map(ToString::to_string),
        event_action: event.event_action.clone(),
        src_ip: event.src_ip.map(|ip| ip.to_string()),
        src_ip6: event.src_ip6.map(|ip| ip.to_string()),
        src_port: event.src_port,
        dst_ip: event.dst_ip.map(|ip| ip.to_string()),
        dst_ip6: event.dst_ip6.map(|ip| ip.to_string()),
        dst_port: event.dst_port,
        protocol: event.protocol.clone(),
        bytes_in: event.bytes_in,
        bytes_out: event.bytes_out,
        packets_in: event.packets_in,
        packets_out: event.packets_out,
        direction: event.direction.as_ref().map(ToString::to_string),
        process_name: event.process_name.clone(),
        process_pid: event.process_pid,
        process_ppid: event.process_ppid,
        process_path: event.process_path.clone(),
        process_cmdline: event.process_cmdline.clone(),
        process_hash: event.process_hash.clone(),
        parent_process: event.parent_process.clone(),
        file_path: event.file_path.clone(),
        file_name: event.file_name.clone(),
        file_hash: event.file_hash.clone(),
        file_size: event.file_size,
        file_action: event.file_action.as_ref().map(ToString::to_string),
        auth_result: event.auth_result.as_ref().map(ToString::to_string),
        auth_method: event.auth_method.clone(),
        auth_protocol: event.auth_protocol.clone(),
        src_country: event.src_country.clone(),
        src_city: event.src_city.clone(),
        src_asn: event.src_asn,
        src_asn_name: event.src_asn_name.clone(),
        dst_country: event.dst_country.clone(),
        ioc_hit: event.ioc_hit,
        ioc_type: event.ioc_type.clone(),
        ioc_value: event.ioc_value.clone(),
        ioc_feed: event.ioc_feed.clone(),
        mitre_tactic: event.mitre_tactic.clone(),
        mitre_technique: event.mitre_technique.clone(),
        mitre_sub_tech: event.mitre_sub_tech.clone(),
        severity: event.severity.to_string(),
        severity_score: event.severity_score,
        anomaly_score: event.anomaly_score,
        ueba_score: event.ueba_score,
        beacon_score: event.beacon_score,
        exfil_score: event.exfil_score,
        fields: fields_json,
        schema_version: event.schema_version,
    })
}

/// Parse the identity and timestamp fields from a [`ChEventRow`].
///
/// # Errors
/// Returns `KronError::Parse` if UUIDs are malformed or timestamps are out of range.
fn parse_row_identity(
    row: &ChEventRow,
) -> StorageResult<(
    EventId,
    TenantId,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
)> {
    let event_id = EventId::from_str(&row.event_id)
        .map_err(|e| KronError::Parse(format!("invalid event_id UUID: {e}")))?;
    let tenant_id = TenantId::from_str(&row.tenant_id)
        .map_err(|e| KronError::Parse(format!("invalid tenant_id UUID: {e}")))?;
    let ts = nanos_to_datetime(row.ts)
        .ok_or_else(|| KronError::Parse(format!("event ts {} out of range", row.ts)))?;
    let ts_received = nanos_to_datetime(row.ts_received).ok_or_else(|| {
        KronError::Parse(format!(
            "event ts_received {} out of range",
            row.ts_received
        ))
    })?;
    Ok((event_id, tenant_id, ts, ts_received))
}

/// Convert a [`ChEventRow`] read from `ClickHouse` back to a [`KronEvent`].
///
/// # Errors
/// Returns `KronError::Parse` if required ID fields are not valid UUIDs.
pub fn ch_row_to_event(row: ChEventRow) -> StorageResult<KronEvent> {
    let (event_id, tenant_id, ts, ts_received) = parse_row_identity(&row)?;

    let fields: std::collections::HashMap<String, String> =
        serde_json::from_str(&row.fields).unwrap_or_default();
    let asset_tags: Vec<String> = serde_json::from_str(&row.asset_tags).unwrap_or_default();

    Ok(KronEvent {
        event_id,
        tenant_id,
        dedup_hash: row.dedup_hash,
        ts,
        ts_received,
        ingest_lag_ms: row.ingest_lag_ms,
        source_type: EventSource::from_str(&row.source_type).unwrap_or(EventSource::Unknown),
        collector_id: row.collector_id,
        raw: row.raw,
        host_id: row.host_id,
        hostname: row.hostname,
        host_ip: row.host_ip.as_deref().and_then(|s| s.parse().ok()),
        host_fqdn: row.host_fqdn,
        asset_criticality: AssetCriticality::from_str(&row.asset_criticality).unwrap_or_default(),
        asset_tags,
        user_name: row.user_name,
        user_id: row.user_id,
        user_domain: row.user_domain,
        user_type: row
            .user_type
            .as_deref()
            .and_then(|s| UserType::from_str(s).ok()),
        event_type: row.event_type,
        event_category: row
            .event_category
            .as_deref()
            .and_then(|s| EventCategory::from_str(s).ok()),
        event_action: row.event_action,
        src_ip: row.src_ip.as_deref().and_then(|s| s.parse().ok()),
        src_ip6: row.src_ip6.as_deref().and_then(|s| s.parse().ok()),
        src_port: row.src_port,
        dst_ip: row.dst_ip.as_deref().and_then(|s| s.parse().ok()),
        dst_ip6: row.dst_ip6.as_deref().and_then(|s| s.parse().ok()),
        dst_port: row.dst_port,
        protocol: row.protocol,
        bytes_in: row.bytes_in,
        bytes_out: row.bytes_out,
        packets_in: row.packets_in,
        packets_out: row.packets_out,
        direction: row
            .direction
            .as_deref()
            .and_then(|s| NetworkDirection::from_str(s).ok()),
        process_name: row.process_name,
        process_pid: row.process_pid,
        process_ppid: row.process_ppid,
        process_path: row.process_path,
        process_cmdline: row.process_cmdline,
        process_hash: row.process_hash,
        parent_process: row.parent_process,
        file_path: row.file_path,
        file_name: row.file_name,
        file_hash: row.file_hash,
        file_size: row.file_size,
        file_action: row
            .file_action
            .as_deref()
            .and_then(|s| FileAction::from_str(s).ok()),
        auth_result: row
            .auth_result
            .as_deref()
            .and_then(|s| AuthResult::from_str(s).ok()),
        auth_method: row.auth_method,
        auth_protocol: row.auth_protocol,
        src_country: row.src_country,
        src_city: row.src_city,
        src_asn: row.src_asn,
        src_asn_name: row.src_asn_name,
        dst_country: row.dst_country,
        ioc_hit: row.ioc_hit,
        ioc_type: row.ioc_type,
        ioc_value: row.ioc_value,
        ioc_feed: row.ioc_feed,
        mitre_tactic: row.mitre_tactic,
        mitre_technique: row.mitre_technique,
        mitre_sub_tech: row.mitre_sub_tech,
        severity: Severity::from_str(&row.severity).unwrap_or_default(),
        severity_score: row.severity_score,
        anomaly_score: row.anomaly_score,
        ueba_score: row.ueba_score,
        beacon_score: row.beacon_score,
        exfil_score: row.exfil_score,
        fields,
        schema_version: row.schema_version,
    })
}

// ─── Audit log ───────────────────────────────────────────────────────────────

/// `ClickHouse` row mapping the `audit_log` table.
#[derive(clickhouse::Row, Serialize, Deserialize)]
pub struct ChAuditLogRow {
    pub audit_id: String,
    pub tenant_id: String,
    pub ts: i64,
    pub actor_id: String,
    pub actor_type: String,
    pub actor_ip: Option<String>,
    pub session_id: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub result: String,
    pub request_body: Option<String>,
    pub response_code: Option<u16>,
    pub duration_ms: Option<u32>,
    pub prev_hash: String,
    pub row_hash: String,
    pub chain_seq: u64,
}

// ─── Alerts (Phase 2.5 placeholder) ─────────────────────────────────────────

/// `ClickHouse` row for the `alerts` table.
///
/// Alert INSERT/SELECT is fully implemented in Phase 2.5 (kron-alert).
/// This struct exists so that the CH schema compiles and migrations pass.
// Notification flags (dpdp_applicable, whatsapp_sent, sms_sent, email_sent) map directly
// to the DB schema columns and cannot be collapsed into a bitfield without a schema change.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, clickhouse::Row, Serialize, Deserialize)]
pub struct ChAlertRow {
    pub alert_id: String,
    pub tenant_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_version: Option<String>,
    pub detection_source: Option<String>,
    pub created_at: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: u32,
    pub risk_score: u8,
    pub severity: String,
    pub confidence: Option<f32>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub mitre_sub_tech: Option<String>,
    pub kill_chain_stage: Option<String>,
    pub affected_assets: String,
    pub affected_users: String,
    pub affected_ips: String,
    pub evidence_event_ids: String,
    pub raw_matches: Option<String>,
    pub narrative_en: Option<String>,
    pub narrative_hi: Option<String>,
    pub narrative_ta: Option<String>,
    pub narrative_te: Option<String>,
    pub root_cause_chain: Option<String>,
    pub fp_probability: Option<f32>,
    pub suggested_playbook: Option<String>,
    pub status: String,
    pub assigned_to: Option<String>,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
    pub resolution_notes: Option<String>,
    pub case_id: Option<String>,
    pub cert_in_category: Option<String>,
    pub rbi_control: Option<String>,
    pub dpdp_applicable: bool,
    pub whatsapp_sent: bool,
    pub sms_sent: bool,
    pub email_sent: bool,
    pub notification_ts: Option<i64>,
    pub schema_version: u8,
}

/// Convert a [`KronAlert`] to a [`ChAlertRow`] for insertion.
///
/// # Errors
/// Returns `KronError::Storage` if timestamp serialization fails.
pub fn alert_to_ch_row(alert: &KronAlert) -> StorageResult<ChAlertRow> {
    let created_at = alert.created_at.timestamp_millis();
    let first_seen = alert.first_seen.timestamp_millis();
    let last_seen = alert.last_seen.timestamp_millis();

    let affected_assets = serde_json::to_string(&alert.affected_assets)
        .map_err(|e| KronError::Storage(format!("serialize affected_assets: {e}")))?;
    let affected_users = serde_json::to_string(&alert.affected_users)
        .map_err(|e| KronError::Storage(format!("serialize affected_users: {e}")))?;
    let affected_ips = serde_json::to_string(&alert.affected_ips)
        .map_err(|e| KronError::Storage(format!("serialize affected_ips: {e}")))?;
    let evidence_event_ids = serde_json::to_string(&alert.evidence_event_ids)
        .map_err(|e| KronError::Storage(format!("serialize evidence_event_ids: {e}")))?;

    Ok(ChAlertRow {
        alert_id: alert.alert_id.to_string(),
        tenant_id: alert.tenant_id.to_string(),
        rule_id: alert.rule_id.to_string(),
        rule_name: alert.rule_name.clone(),
        rule_version: alert.rule_version.clone(),
        detection_source: Some(alert.detection_source.to_string()),
        created_at,
        first_seen,
        last_seen,
        event_count: alert.event_count,
        risk_score: alert.risk_score,
        severity: alert.severity.to_string(),
        confidence: alert.confidence,
        mitre_tactic: alert.mitre_tactic.clone(),
        mitre_technique: alert.mitre_technique.clone(),
        mitre_sub_tech: alert.mitre_sub_tech.clone(),
        kill_chain_stage: alert.kill_chain_stage.clone(),
        affected_assets,
        affected_users,
        affected_ips,
        evidence_event_ids,
        raw_matches: alert.raw_matches.clone(),
        narrative_en: alert.narrative_en.clone(),
        narrative_hi: alert.narrative_hi.clone(),
        narrative_ta: alert.narrative_ta.clone(),
        narrative_te: alert.narrative_te.clone(),
        root_cause_chain: alert.root_cause_chain.clone(),
        fp_probability: alert.fp_probability,
        suggested_playbook: alert.suggested_playbook.clone(),
        status: alert.status.to_string(),
        assigned_to: alert.assigned_to.clone(),
        resolved_at: alert.resolved_at.map(|t| t.timestamp_millis()),
        resolved_by: alert.resolved_by.clone(),
        resolution_notes: alert.resolution_notes.clone(),
        case_id: alert.case_id.as_ref().map(ToString::to_string),
        cert_in_category: alert.cert_in_category.clone(),
        rbi_control: alert.rbi_control.clone(),
        dpdp_applicable: alert.dpdp_applicable,
        whatsapp_sent: alert.whatsapp_sent,
        sms_sent: alert.sms_sent,
        email_sent: alert.email_sent,
        notification_ts: alert.notification_ts.map(|t| t.timestamp_millis()),
        schema_version: alert.schema_version,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert nanoseconds since Unix epoch to `DateTime<Utc>`.
///
/// Returns `None` if the value is out of the representable range.
pub fn nanos_to_datetime(nanos: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    let secs = nanos / 1_000_000_000;
    let sub_nanos = u32::try_from(nanos.rem_euclid(1_000_000_000)).ok()?;
    chrono::DateTime::from_timestamp(secs, sub_nanos)
}
