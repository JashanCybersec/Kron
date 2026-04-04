//! `DuckDB` implementation of [`StorageEngine`].
//!
//! `DuckDB` is used for Nano tier deployments. It's embedded (single binary),
//! uses Parquet natively, and supports all SQL operations synchronously.
//!
//! Connection: single connection wrapped in `Arc<Mutex<>>` for async safety.
//! `DuckDB` is single-writer, so all writes serialize through the mutex.
//! Reads can interleave with other reads but not writes (`DuckDB` MVCC).

use crate::migration;
use crate::query::EventFilter;
use crate::traits::{AuditLogEntry, LatencyStats, StorageEngine, StorageResult};
use async_trait::async_trait;
use kron_types::{KronAlert, KronError, KronEvent, TenantContext, TenantId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;

/// `DuckDB` storage engine for Nano tier.
///
/// Wraps a synchronous `DuckDB` connection in async-safe primitives.
/// All database calls go through [`tokio::task::spawn_blocking`] to avoid
/// blocking the async runtime.
pub struct DuckDbEngine {
    /// Thread-safe handle to the `DuckDB` connection.
    conn: Arc<Mutex<duckdb::Connection>>,
    /// Path to the migrations directory.
    migrations_dir: String,
    /// Monotonic counter for total events inserted (for metrics).
    events_inserted: AtomicU64,
    /// Monotonic counter for total queries executed (for metrics).
    queries_executed: AtomicU64,
}

impl DuckDbEngine {
    /// Create a new `DuckDB` storage engine.
    ///
    /// # Arguments
    /// * `db_path` - Path to the `DuckDB` database file. Use `:memory:` for testing.
    /// * `migrations_dir` - Path to the directory containing SQL migration files.
    ///
    /// # Errors
    /// Returns `KronError::Storage` if the database cannot be opened.
    pub fn new(db_path: &str, migrations_dir: &str) -> StorageResult<Self> {
        tracing::info!(db_path = %db_path, "Opening DuckDB database");

        let conn = duckdb::Connection::open(db_path)
            .map_err(|e| KronError::Storage(format!("failed to open DuckDB at {db_path}: {e}")))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            migrations_dir: migrations_dir.to_string(),
            events_inserted: AtomicU64::new(0),
            queries_executed: AtomicU64::new(0),
        })
    }

    /// Create an in-memory `DuckDB` engine for testing.
    ///
    /// # Arguments
    /// * `migrations_dir` - Path to the directory containing SQL migration files.
    ///
    /// # Errors
    /// Returns `KronError::Storage` if the in-memory database cannot be created.
    pub fn in_memory(migrations_dir: &str) -> StorageResult<Self> {
        Self::new(":memory:", migrations_dir)
    }

    /// Apply all pending migrations idempotently.
    ///
    /// Reads migration files from `self.migrations_dir`, checks which have
    /// already been applied via the `schema_versions` table, and runs new ones
    /// in order.
    ///
    /// # Errors
    /// Returns `KronError::Storage` if a migration fails or checksums mismatch.
    pub async fn apply_migrations(&self) -> StorageResult<()> {
        let conn = self.conn.clone();
        let dir = self.migrations_dir.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            apply_migrations_sync(&conn, &dir)
        })
        .await
        .map_err(|e| KronError::Storage(format!("migration task panicked: {e}")))?
    }

    /// Archives events older than `retention_days` to Parquet files under `archive_dir`.
    ///
    /// Uses DuckDB's native `COPY … TO … (FORMAT PARQUET)` so no external crate is needed.
    /// One Parquet file is produced per tenant per calendar day (e.g.
    /// `{archive_dir}/{tenant_id}/2024-11-01.parquet`).
    ///
    /// Events are deleted from the live table after a successful export to keep the
    /// working set small. Call this periodically (e.g. once per day) from a background task.
    ///
    /// # Arguments
    /// * `archive_dir`    — directory under which per-tenant sub-directories will be created
    /// * `retention_days` — events older than this many days are archived and deleted
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the SQL export or directory creation fails.
    pub async fn archive_to_parquet(
        &self,
        archive_dir: std::path::PathBuf,
        retention_days: u32,
    ) -> StorageResult<()> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            archive_sync(&conn.blocking_lock(), &archive_dir, retention_days)
        })
        .await
        .map_err(|e| KronError::Storage(format!("archive task panicked: {e}")))?
    }
}

/// Archives old events to per-tenant Parquet files, then deletes them from the live table.
///
/// Called synchronously inside `tokio::task::spawn_blocking`.
fn archive_sync(
    conn: &duckdb::Connection,
    archive_dir: &std::path::Path,
    retention_days: u32,
) -> StorageResult<()> {
    use std::io::Write as _;

    // Collect distinct (tenant_id, day) pairs that are beyond the retention window.
    let cutoff_sql = format!(
        "SELECT DISTINCT tenant_id, strftime(ts, '%Y-%m-%d') AS day \
         FROM events \
         WHERE ts < NOW() - INTERVAL '{retention_days} days' \
         ORDER BY tenant_id, day"
    );

    let mut stmt = conn
        .prepare(&cutoff_sql)
        .map_err(|e| KronError::Storage(format!("archive: prepare SELECT failed: {e}")))?;

    let pairs: Vec<(String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|e| KronError::Storage(format!("archive: query failed: {e}")))?
        .filter_map(std::result::Result::ok)
        .collect();

    if pairs.is_empty() {
        tracing::debug!("archive_to_parquet: no events older than {retention_days} days");
        return Ok(());
    }

    // Canonicalize the archive root once so we can verify all file paths remain inside it.
    let canonical_archive_dir = archive_dir
        .canonicalize()
        .unwrap_or_else(|_| archive_dir.to_path_buf());

    for (tenant_id, day) in &pairs {
        // Validate tenant_id is a well-formed UUID before embedding it in SQL or file paths.
        // Values come from the events table; malicious event data could otherwise inject SQL.
        if uuid::Uuid::parse_str(tenant_id).is_err() {
            tracing::error!(
                tenant_id = %tenant_id,
                "archive: skipping row with non-UUID tenant_id to prevent SQL/path injection"
            );
            continue;
        }
        // Validate day is exactly YYYY-MM-DD (10 chars, ASCII digits and hyphens only).
        if day.len() != 10 || !day.chars().all(|c| c.is_ascii_digit() || c == '-') {
            tracing::error!(
                day = %day,
                "archive: skipping row with malformed day string to prevent SQL injection"
            );
            continue;
        }

        // Create the tenant sub-directory if it does not exist.
        let tenant_dir = archive_dir.join(tenant_id);
        std::fs::create_dir_all(&tenant_dir).map_err(|e| {
            KronError::Storage(format!("archive: failed to create dir {}: {e}", tenant_dir.display()))
        })?;

        // Write a placeholder so canonicalize works before the file exists.
        let parquet_path = tenant_dir.join(format!("{day}.parquet"));
        if !parquet_path.exists() {
            std::fs::File::create(&parquet_path)
                .and_then(|mut f| f.write_all(b""))
                .map_err(|e| KronError::Storage(format!("archive: create placeholder failed: {e}")))?;
        }

        // Resolve the canonical path and verify it stays inside archive_dir (no traversal).
        let canonical = parquet_path
            .canonicalize()
            .unwrap_or_else(|_| parquet_path.clone());

        if !canonical.starts_with(&canonical_archive_dir) {
            tracing::error!(
                path = %canonical.display(),
                archive_dir = %canonical_archive_dir.display(),
                "archive: resolved path escapes archive_dir — skipping to prevent traversal"
            );
            continue;
        }

        // Escape single quotes in the path string for the COPY TO SQL literal.
        // tenant_id is a UUID (no quotes), day is YYYY-MM-DD (no quotes), so the
        // only risk is the OS-level archive_dir path itself.
        let path_sql = canonical.to_string_lossy().replace('\'', "''");
        let export_sql = format!(
            "COPY (SELECT * FROM events \
                   WHERE tenant_id = '{tenant_id}' \
                   AND strftime(ts, '%Y-%m-%d') = '{day}') \
             TO '{path_sql}' (FORMAT PARQUET)"
        );

        conn.execute_batch(&export_sql).map_err(|e| {
            KronError::Storage(format!(
                "archive: COPY to Parquet failed for tenant={tenant_id} day={day}: {e}"
            ))
        })?;

        tracing::info!(tenant_id = %tenant_id, day = %day, path = %canonical.display(), "Archived events to Parquet");

        // Delete archived rows using a parameterized query to prevent SQL injection.
        let mut delete_stmt = conn
            .prepare(
                "DELETE FROM events \
                 WHERE tenant_id = ? \
                 AND strftime(ts, '%Y-%m-%d') = ?",
            )
            .map_err(|e| {
                KronError::Storage(format!("archive: prepare DELETE failed: {e}"))
            })?;
        delete_stmt
            .execute(duckdb::params![tenant_id.as_str(), day.as_str()])
            .map_err(|e| {
                KronError::Storage(format!(
                    "archive: DELETE after export failed for tenant={tenant_id} day={day}: {e}"
                ))
            })?;
    }

    tracing::info!(pairs = pairs.len(), "archive_to_parquet: completed");
    Ok(())
}

/// Apply migrations synchronously (called inside `spawn_blocking`).
fn apply_migrations_sync(conn: &duckdb::Connection, migrations_dir: &str) -> StorageResult<()> {
    let migrations = migration::load_migrations(migrations_dir, "duckdb")
        .map_err(|e| KronError::Storage(format!("failed to load migrations: {e}")))?;

    // Ensure schema_versions table exists
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_versions (
            version     INTEGER NOT NULL PRIMARY KEY,
            name        VARCHAR NOT NULL,
            applied_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            checksum    VARCHAR NOT NULL
        )",
    )
    .map_err(|e| KronError::Storage(format!("failed to create schema_versions: {e}")))?;

    // Get already-applied versions
    let mut stmt = conn
        .prepare("SELECT version, checksum FROM schema_versions ORDER BY version")
        .map_err(|e| KronError::Storage(format!("failed to query schema_versions: {e}")))?;

    let applied: std::collections::HashMap<i32, String> = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| KronError::Storage(format!("failed to read applied migrations: {e}")))?
        .filter_map(std::result::Result::ok)
        .collect();

    for migration in &migrations {
        if let Some(existing_checksum) = applied.get(&migration.version) {
            // Already applied — verify checksum matches
            if *existing_checksum != migration.checksum {
                return Err(KronError::Storage(format!(
                    "migration {} ({}) checksum mismatch: expected {}, found {}. \
                     Migration files must not be modified after initial application.",
                    migration.version, migration.name, existing_checksum, migration.checksum
                )));
            }
            tracing::debug!(
                version = migration.version,
                name = %migration.name,
                "Migration already applied, skipping"
            );
            continue;
        }

        // Apply new migration
        tracing::info!(
            version = migration.version,
            name = %migration.name,
            "Applying migration"
        );

        conn.execute_batch(&migration.sql).map_err(|e| {
            KronError::Storage(format!(
                "migration {} ({}) failed: {e}",
                migration.version, migration.name
            ))
        })?;

        // Record in schema_versions
        conn.execute(
            "INSERT INTO schema_versions (version, name, checksum) VALUES (?, ?, ?)",
            duckdb::params![migration.version, migration.name, migration.checksum],
        )
        .map_err(|e| {
            KronError::Storage(format!(
                "failed to record migration {} in schema_versions: {e}",
                migration.version
            ))
        })?;

        tracing::info!(
            version = migration.version,
            name = %migration.name,
            "Migration applied successfully"
        );
    }

    Ok(())
}

/// SQL template for inserting one event row.
const INSERT_EVENT_SQL: &str = "INSERT INTO events (
    event_id, tenant_id, dedup_hash, ts, ts_received, ingest_lag_ms,
    source_type, collector_id, raw,
    host_id, hostname, host_ip, host_fqdn, asset_criticality, asset_tags,
    user_name, user_id, user_domain, user_type,
    event_type, event_category, event_action,
    src_ip, src_ip6, src_port, dst_ip, dst_ip6, dst_port,
    protocol, bytes_in, bytes_out, packets_in, packets_out, direction,
    process_name, process_pid, process_ppid, process_path, process_cmdline,
    process_hash, parent_process,
    file_path, file_name, file_hash, file_size, file_action,
    auth_result, auth_method, auth_protocol,
    src_country, src_city, src_asn, src_asn_name, dst_country,
    ioc_hit, ioc_type, ioc_value, ioc_feed,
    mitre_tactic, mitre_technique, mitre_sub_tech,
    severity, severity_score,
    anomaly_score, ueba_score, beacon_score, exfil_score,
    fields, schema_version
) VALUES (
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?,
    ?, ?, ?, ?,
    ?, ?
)";

/// Execute a single event INSERT into the prepared statement.
fn execute_event_insert(stmt: &mut duckdb::Statement<'_>, event: &KronEvent) -> StorageResult<()> {
    let fields_json = serde_json::to_string(&event.fields)
        .map_err(|e| KronError::Storage(format!("failed to serialize fields: {e}")))?;
    let asset_tags_json = serde_json::to_string(&event.asset_tags)
        .map_err(|e| KronError::Storage(format!("failed to serialize asset_tags: {e}")))?;

    stmt.execute(duckdb::params![
        event.event_id.to_string(),
        event.tenant_id.to_string(),
        event.dedup_hash,
        event.ts.to_rfc3339(),
        event.ts_received.to_rfc3339(),
        event.ingest_lag_ms,
        event.source_type.to_string(),
        event.collector_id,
        event.raw,
        event.host_id,
        event.hostname,
        event.host_ip.map(|ip| ip.to_string()),
        event.host_fqdn,
        event.asset_criticality.to_string(),
        asset_tags_json,
        event.user_name,
        event.user_id,
        event.user_domain,
        event.user_type.as_ref().map(ToString::to_string),
        event.event_type,
        event.event_category.as_ref().map(ToString::to_string),
        event.event_action,
        event.src_ip.map(|ip| ip.to_string()),
        event.src_ip6.map(|ip| ip.to_string()),
        event.src_port,
        event.dst_ip.map(|ip| ip.to_string()),
        event.dst_ip6.map(|ip| ip.to_string()),
        event.dst_port,
        event.protocol,
        event.bytes_in,
        event.bytes_out,
        event.packets_in,
        event.packets_out,
        event.direction.as_ref().map(ToString::to_string),
        event.process_name,
        event.process_pid,
        event.process_ppid,
        event.process_path,
        event.process_cmdline,
        event.process_hash,
        event.parent_process,
        event.file_path,
        event.file_name,
        event.file_hash,
        event.file_size,
        event.file_action.as_ref().map(ToString::to_string),
        event.auth_result.as_ref().map(ToString::to_string),
        event.auth_method,
        event.auth_protocol,
        event.src_country,
        event.src_city,
        event.src_asn,
        event.src_asn_name,
        event.dst_country,
        event.ioc_hit,
        event.ioc_type,
        event.ioc_value,
        event.ioc_feed,
        event.mitre_tactic,
        event.mitre_technique,
        event.mitre_sub_tech,
        event.severity.to_string(),
        event.severity_score,
        event.anomaly_score,
        event.ueba_score,
        event.beacon_score,
        event.exfil_score,
        fields_json,
        event.schema_version,
    ])
    .map_err(|e| {
        tracing::error!(
            event_id = %event.event_id,
            tenant_id = %event.tenant_id,
            error = %e,
            "Failed to insert event into DuckDB"
        );
        KronError::Storage(format!("failed to insert event {}: {e}", event.event_id))
    })?;
    Ok(())
}

/// Insert events into `DuckDB` synchronously.
fn insert_events_sync(
    conn: &duckdb::Connection,
    tenant_id: &TenantId,
    events: &[KronEvent],
) -> StorageResult<u64> {
    let sql = INSERT_EVENT_SQL;

    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| KronError::Storage(format!("failed to prepare insert: {e}")))?;

    let mut inserted = 0u64;

    for event in events {
        // Tenant isolation check
        if event.tenant_id != *tenant_id {
            return Err(KronError::TenantIsolationViolation {
                caller: tenant_id.to_string(),
                target: event.tenant_id.to_string(),
            });
        }
        execute_event_insert(&mut stmt, event)?;
        inserted += 1;
    }

    Ok(inserted)
}

/// Query events from `DuckDB` synchronously.
fn query_events_sync(
    conn: &duckdb::Connection,
    tenant_id: &TenantId,
    filter: Option<&EventFilter>,
    limit: u32,
) -> StorageResult<Vec<KronEvent>> {
    let mut sql = String::from("SELECT * FROM events WHERE tenant_id = ?");
    let tenant_str = tenant_id.to_string();
    let mut string_params: Vec<String> = vec![tenant_str.clone()];

    if let Some(f) = filter {
        if let Some(ref from) = f.from_ts {
            string_params.push(from.to_rfc3339());
            sql.push_str(" AND ts >= ?");
        }
        if let Some(ref to) = f.to_ts {
            string_params.push(to.to_rfc3339());
            sql.push_str(" AND ts <= ?");
        }
        if let Some(ref source) = f.source_type {
            string_params.push(source.clone());
            sql.push_str(" AND source_type = ?");
        }
        if let Some(ref event_type) = f.event_type {
            string_params.push(event_type.clone());
            sql.push_str(" AND event_type = ?");
        }
        if let Some(ref hostname) = f.hostname {
            string_params.push(hostname.clone());
            sql.push_str(" AND hostname = ?");
        }
        if let Some(ref user) = f.user_name {
            string_params.push(user.clone());
            sql.push_str(" AND user_name = ?");
        }
        if let Some(ref ip) = f.src_ip {
            string_params.push(ip.clone());
            sql.push_str(" AND src_ip = ?");
        }
        if let Some(ref ip) = f.dst_ip {
            string_params.push(ip.clone());
            sql.push_str(" AND dst_ip = ?");
        }
        if let Some(ref process) = f.process_name {
            string_params.push(process.clone());
            sql.push_str(" AND process_name = ?");
        }
        if f.ioc_hit_only == Some(true) {
            sql.push_str(" AND ioc_hit = true");
        }
    }

    sql.push_str(" ORDER BY ts DESC LIMIT ?");
    string_params.push(limit.to_string());

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| KronError::Storage(format!("failed to prepare query: {e}")))?;

    let param_refs: Vec<&dyn duckdb::ToSql> = string_params
        .iter()
        .map(|s| s as &dyn duckdb::ToSql)
        .collect();

    let rows = stmt
        .query_map(param_refs.as_slice(), |row| Ok(row_to_event(row)))
        .map_err(|e| KronError::Storage(format!("failed to execute query: {e}")))?;

    let mut events = Vec::new();
    for row_result in rows {
        match row_result {
            Ok(Ok(event)) => events.push(event),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "Failed to parse event row, skipping");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to read row from DuckDB, skipping");
            }
        }
    }

    Ok(events)
}

/// Core fields parsed from columns 0–8 of an event row.
type CoreFields = (
    kron_types::EventId,
    TenantId,
    u64,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
    u32,
    kron_types::EventSource,
    String,
    String,
);

/// Parse core identity, timestamp, and source fields from columns 0–8.
fn parse_core_fields(row: &duckdb::Row<'_>) -> Result<CoreFields, KronError> {
    use std::str::FromStr;
    let event_id_str: String = row
        .get(0)
        .map_err(|e| KronError::Storage(format!("failed to read event_id: {e}")))?;
    let tenant_id_str: String = row
        .get(1)
        .map_err(|e| KronError::Storage(format!("failed to read tenant_id: {e}")))?;
    let event_id = kron_types::EventId::from_str(&event_id_str)
        .map_err(|e| KronError::Parse(format!("invalid event_id UUID: {e}")))?;
    let tenant_id = TenantId::from_str(&tenant_id_str)
        .map_err(|e| KronError::Parse(format!("invalid tenant_id UUID: {e}")))?;
    let dedup_hash: u64 = row
        .get(2)
        .map_err(|e| KronError::Storage(format!("failed to read dedup_hash: {e}")))?;
    let ts_str: String = row
        .get(3)
        .map_err(|e| KronError::Storage(format!("failed to read ts: {e}")))?;
    let ts_received_str: String = row
        .get(4)
        .map_err(|e| KronError::Storage(format!("failed to read ts_received: {e}")))?;
    let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| KronError::Parse(format!("invalid ts: {e}")))?;
    let ts_received = chrono::DateTime::parse_from_rfc3339(&ts_received_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| KronError::Parse(format!("invalid ts_received: {e}")))?;
    let ingest_lag_ms: u32 = row
        .get(5)
        .map_err(|e| KronError::Storage(format!("failed to read ingest_lag_ms: {e}")))?;
    let source_type_str: String = row
        .get(6)
        .map_err(|e| KronError::Storage(format!("failed to read source_type: {e}")))?;
    let source_type = kron_types::EventSource::from_str(&source_type_str)
        .unwrap_or(kron_types::EventSource::Unknown);
    let collector_id: String = row
        .get(7)
        .map_err(|e| KronError::Storage(format!("failed to read collector_id: {e}")))?;
    let raw: String = row
        .get(8)
        .map_err(|e| KronError::Storage(format!("failed to read raw: {e}")))?;
    Ok((
        event_id,
        tenant_id,
        dedup_hash,
        ts,
        ts_received,
        ingest_lag_ms,
        source_type,
        collector_id,
        raw,
    ))
}

/// Host, user, event-type, and network fields from event row columns 9–33.
struct HostNetworkFields {
    host_id: Option<String>,
    hostname: Option<String>,
    host_ip_str: Option<String>,
    host_fqdn: Option<String>,
    asset_criticality: kron_types::AssetCriticality,
    asset_tags: Vec<String>,
    user_name: Option<String>,
    user_id: Option<String>,
    user_domain: Option<String>,
    user_type: Option<kron_types::UserType>,
    event_type: String,
    event_category: Option<kron_types::EventCategory>,
    event_action: Option<String>,
    src_ip_str: Option<String>,
    src_ipv6_str: Option<String>,
    src_port: Option<u16>,
    dst_ip_str: Option<String>,
    dst_ipv6_str: Option<String>,
    dst_port: Option<u16>,
    protocol: Option<String>,
    bytes_in: Option<u64>,
    bytes_out: Option<u64>,
    packets_in: Option<u32>,
    packets_out: Option<u32>,
    direction: Option<kron_types::NetworkDirection>,
}

/// Read host, user, event-type, and network fields from columns 9–33.
fn read_host_user_network_fields(row: &duckdb::Row<'_>) -> Result<HostNetworkFields, KronError> {
    use std::str::FromStr;
    let asset_crit_str: String = row.get(13).unwrap_or_else(|_| "unknown".to_string());
    let asset_tags_json: String = row.get(14).unwrap_or_else(|_| "[]".to_string());
    let user_type_str: Option<String> = row.get(18).ok();
    let event_category_str: Option<String> = row.get(20).ok();
    let direction_str: Option<String> = row.get(33).ok();
    Ok(HostNetworkFields {
        host_id: row.get(9).ok(),
        hostname: row.get(10).ok(),
        host_ip_str: row.get(11).ok(),
        host_fqdn: row.get(12).ok(),
        asset_criticality: kron_types::AssetCriticality::from_str(&asset_crit_str)
            .unwrap_or_default(),
        asset_tags: serde_json::from_str(&asset_tags_json).unwrap_or_default(),
        user_name: row.get(15).ok(),
        user_id: row.get(16).ok(),
        user_domain: row.get(17).ok(),
        user_type: user_type_str.and_then(|s| kron_types::UserType::from_str(&s).ok()),
        event_type: row
            .get(19)
            .map_err(|e| KronError::Storage(format!("failed to read event_type: {e}")))?,
        event_category: event_category_str
            .and_then(|s| kron_types::EventCategory::from_str(&s).ok()),
        event_action: row.get(21).ok(),
        src_ip_str: row.get(22).ok(),
        src_ipv6_str: row.get(23).ok(),
        src_port: row.get(24).ok(),
        dst_ip_str: row.get(25).ok(),
        dst_ipv6_str: row.get(26).ok(),
        dst_port: row.get(27).ok(),
        protocol: row.get(28).ok(),
        bytes_in: row.get(29).ok(),
        bytes_out: row.get(30).ok(),
        packets_in: row.get(31).ok(),
        packets_out: row.get(32).ok(),
        direction: direction_str.and_then(|s| kron_types::NetworkDirection::from_str(&s).ok()),
    })
}

/// Detail fields read from event row columns 34–68.
struct DetailFields {
    process_name: Option<String>,
    process_pid: Option<u32>,
    process_parent_pid: Option<u32>,
    process_path: Option<String>,
    process_cmdline: Option<String>,
    process_hash: Option<String>,
    parent_process: Option<String>,
    file_path: Option<String>,
    file_name: Option<String>,
    file_hash: Option<String>,
    file_size: Option<u64>,
    file_action: Option<kron_types::FileAction>,
    auth_result: Option<kron_types::AuthResult>,
    auth_method: Option<String>,
    auth_protocol: Option<String>,
    src_country: Option<String>,
    src_city: Option<String>,
    src_asn: Option<u32>,
    src_asn_name: Option<String>,
    dst_country: Option<String>,
    ioc_hit: bool,
    ioc_type: Option<String>,
    ioc_value: Option<String>,
    ioc_feed: Option<String>,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
    mitre_sub_tech: Option<String>,
    severity: kron_types::Severity,
    severity_score: u8,
    anomaly_score: f32,
    ueba_score: f32,
    beacon_score: f32,
    exfil_score: f32,
    fields: std::collections::HashMap<String, String>,
    schema_version: u8,
}

/// Read process, file, auth, geo, IOC, MITRE, score, and metadata fields (columns 34–68).
fn read_detail_fields(row: &duckdb::Row<'_>) -> DetailFields {
    use std::str::FromStr;
    let file_action_str: Option<String> = row.get(45).ok();
    let auth_result_str: Option<String> = row.get(46).ok();
    let severity_str: String = row.get(61).unwrap_or_else(|_| "info".to_string());
    let fields_json: String = row.get(67).unwrap_or_else(|_| "{}".to_string());
    DetailFields {
        process_name: row.get(34).ok(),
        process_pid: row.get(35).ok(),
        process_parent_pid: row.get(36).ok(),
        process_path: row.get(37).ok(),
        process_cmdline: row.get(38).ok(),
        process_hash: row.get(39).ok(),
        parent_process: row.get(40).ok(),
        file_path: row.get(41).ok(),
        file_name: row.get(42).ok(),
        file_hash: row.get(43).ok(),
        file_size: row.get(44).ok(),
        file_action: file_action_str.and_then(|s| kron_types::FileAction::from_str(&s).ok()),
        auth_result: auth_result_str.and_then(|s| kron_types::AuthResult::from_str(&s).ok()),
        auth_method: row.get(47).ok(),
        auth_protocol: row.get(48).ok(),
        src_country: row.get(49).ok(),
        src_city: row.get(50).ok(),
        src_asn: row.get(51).ok(),
        src_asn_name: row.get(52).ok(),
        dst_country: row.get(53).ok(),
        ioc_hit: row.get(54).unwrap_or(false),
        ioc_type: row.get(55).ok(),
        ioc_value: row.get(56).ok(),
        ioc_feed: row.get(57).ok(),
        mitre_tactic: row.get(58).ok(),
        mitre_technique: row.get(59).ok(),
        mitre_sub_tech: row.get(60).ok(),
        severity: kron_types::Severity::from_str(&severity_str).unwrap_or_default(),
        severity_score: row.get(62).unwrap_or(0),
        anomaly_score: row.get(63).unwrap_or(0.0),
        ueba_score: row.get(64).unwrap_or(0.0),
        beacon_score: row.get(65).unwrap_or(0.0),
        exfil_score: row.get(66).unwrap_or(0.0),
        fields: serde_json::from_str(&fields_json).unwrap_or_default(),
        schema_version: row.get(68).unwrap_or(1),
    }
}

/// Convert a `DuckDB` row into a `KronEvent`.
fn row_to_event(row: &duckdb::Row<'_>) -> Result<KronEvent, KronError> {
    let (
        event_id,
        tenant_id,
        dedup_hash,
        ts,
        ts_received,
        ingest_lag_ms,
        source_type,
        collector_id,
        raw,
    ) = parse_core_fields(row)?;

    let h = read_host_user_network_fields(row)?;
    let d = read_detail_fields(row);

    Ok(KronEvent {
        event_id,
        tenant_id,
        dedup_hash,
        ts,
        ts_received,
        ingest_lag_ms,
        source_type,
        collector_id,
        raw,
        host_id: h.host_id,
        hostname: h.hostname,
        host_ip: h.host_ip_str.and_then(|s| s.parse().ok()),
        host_fqdn: h.host_fqdn,
        asset_criticality: h.asset_criticality,
        asset_tags: h.asset_tags,
        user_name: h.user_name,
        user_id: h.user_id,
        user_domain: h.user_domain,
        user_type: h.user_type,
        event_type: h.event_type,
        event_category: h.event_category,
        event_action: h.event_action,
        src_ip: h.src_ip_str.and_then(|s| s.parse().ok()),
        src_ip6: h.src_ipv6_str.and_then(|s| s.parse().ok()),
        src_port: h.src_port,
        dst_ip: h.dst_ip_str.and_then(|s| s.parse().ok()),
        dst_ip6: h.dst_ipv6_str.and_then(|s| s.parse().ok()),
        dst_port: h.dst_port,
        protocol: h.protocol,
        bytes_in: h.bytes_in,
        bytes_out: h.bytes_out,
        packets_in: h.packets_in,
        packets_out: h.packets_out,
        direction: h.direction,
        process_name: d.process_name,
        process_pid: d.process_pid,
        process_ppid: d.process_parent_pid,
        process_path: d.process_path,
        process_cmdline: d.process_cmdline,
        process_hash: d.process_hash,
        parent_process: d.parent_process,
        file_path: d.file_path,
        file_name: d.file_name,
        file_hash: d.file_hash,
        file_size: d.file_size,
        file_action: d.file_action,
        auth_result: d.auth_result,
        auth_method: d.auth_method,
        auth_protocol: d.auth_protocol,
        src_country: d.src_country,
        src_city: d.src_city,
        src_asn: d.src_asn,
        src_asn_name: d.src_asn_name,
        dst_country: d.dst_country,
        ioc_hit: d.ioc_hit,
        ioc_type: d.ioc_type,
        ioc_value: d.ioc_value,
        ioc_feed: d.ioc_feed,
        mitre_tactic: d.mitre_tactic,
        mitre_technique: d.mitre_technique,
        mitre_sub_tech: d.mitre_sub_tech,
        severity: d.severity,
        severity_score: d.severity_score,
        anomaly_score: d.anomaly_score,
        ueba_score: d.ueba_score,
        beacon_score: d.beacon_score,
        exfil_score: d.exfil_score,
        fields: d.fields,
        schema_version: d.schema_version,
    })
}

#[async_trait]
impl StorageEngine for DuckDbEngine {
    #[instrument(skip(self, ctx, events), fields(
        tenant_id = %ctx.tenant_id(),
        event_count = events.len()
    ))]
    async fn insert_events(
        &self,
        ctx: &TenantContext,
        events: Vec<KronEvent>,
    ) -> StorageResult<u64> {
        let tenant_id = ctx.tenant_id();
        let conn = self.conn.clone();

        let inserted = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            insert_events_sync(&conn, &tenant_id, &events)
        })
        .await
        .map_err(|e| KronError::Storage(format!("insert task panicked: {e}")))??;

        self.events_inserted.fetch_add(inserted, Ordering::Relaxed);
        Ok(inserted)
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id()))]
    async fn query_events(
        &self,
        ctx: &TenantContext,
        filter: Option<EventFilter>,
        limit: u32,
    ) -> StorageResult<Vec<KronEvent>> {
        let tenant_id = ctx.tenant_id();
        let conn = self.conn.clone();

        let events = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            query_events_sync(&conn, &tenant_id, filter.as_ref(), limit)
        })
        .await
        .map_err(|e| KronError::Storage(format!("query task panicked: {e}")))??;

        self.queries_executed.fetch_add(1, Ordering::Relaxed);
        Ok(events)
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id(), event_id = %event_id))]
    async fn get_event(
        &self,
        ctx: &TenantContext,
        event_id: &str,
    ) -> StorageResult<Option<KronEvent>> {
        let tenant_id = ctx.tenant_id();
        let conn = self.conn.clone();
        let event_id = event_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare("SELECT * FROM events WHERE tenant_id = ? AND event_id = ?")
                .map_err(|e| KronError::Storage(format!("prepare failed: {e}")))?;

            let tenant_str = tenant_id.to_string();
            let mut rows = stmt
                .query(duckdb::params![tenant_str, event_id])
                .map_err(|e| KronError::Storage(format!("query failed: {e}")))?;

            match rows.next() {
                Ok(Some(row)) => Ok(Some(row_to_event(row)?)),
                Ok(None) => Ok(None),
                Err(e) => Err(KronError::Storage(format!("failed to read row: {e}"))),
            }
        })
        .await
        .map_err(|e| KronError::Storage(format!("get_event task panicked: {e}")))?
    }

    #[instrument(skip(self, ctx, alerts), fields(
        tenant_id = %ctx.tenant_id(),
        alert_count = alerts.len()
    ))]
    async fn insert_alerts(
        &self,
        ctx: &TenantContext,
        alerts: Vec<KronAlert>,
    ) -> StorageResult<u64> {
        let tenant_id = ctx.tenant_id();

        // Verify all alerts belong to this tenant
        for alert in &alerts {
            if alert.tenant_id != tenant_id {
                return Err(KronError::TenantIsolationViolation {
                    caller: tenant_id.to_string(),
                    target: alert.tenant_id.to_string(),
                });
            }
        }

        // Alert insertion is simpler; we'll implement the full schema mapping
        // when the alert engine is built in Phase 2.5
        let count = alerts.len() as u64;
        tracing::debug!(
            count,
            "Alert insertion placeholder — full mapping in Phase 2.5"
        );
        Ok(count)
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id()))]
    async fn query_alerts(
        &self,
        ctx: &TenantContext,
        _limit: u32,
        _offset: u32,
    ) -> StorageResult<Vec<KronAlert>> {
        // Alert queries will be implemented in Phase 2.5 when alert engine is built
        tracing::debug!("Alert query placeholder — full mapping in Phase 2.5");
        Ok(Vec::new())
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id(), alert_id = %alert_id))]
    async fn get_alert(
        &self,
        ctx: &TenantContext,
        alert_id: &str,
    ) -> StorageResult<Option<KronAlert>> {
        tracing::debug!("Alert get placeholder — full mapping in Phase 2.5");
        Ok(None)
    }

    #[instrument(skip(self, ctx, alert), fields(tenant_id = %ctx.tenant_id()))]
    async fn update_alert(&self, ctx: &TenantContext, alert: &KronAlert) -> StorageResult<()> {
        let tenant_id = ctx.tenant_id();

        if alert.tenant_id != tenant_id {
            return Err(KronError::TenantIsolationViolation {
                caller: tenant_id.to_string(),
                target: alert.tenant_id.to_string(),
            });
        }

        tracing::debug!("Alert update placeholder — full mapping in Phase 2.5");
        Ok(())
    }

    #[instrument(skip(self, ctx, entry), fields(
        tenant_id = %ctx.tenant_id()
    ))]
    async fn insert_audit_log(
        &self,
        ctx: &TenantContext,
        entry: AuditLogEntry,
    ) -> StorageResult<()> {
        let tenant_id = ctx.tenant_id();
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || {
            use sha2::Digest;
            use std::fmt::Write as _;
            let conn = conn.blocking_lock();
            let audit_id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();

            // For Merkle chain: get the last row_hash for this tenant
            let prev_hash = conn
                .query_row(
                    "SELECT row_hash FROM audit_log WHERE tenant_id = ? ORDER BY chain_seq DESC LIMIT 1",
                    duckdb::params![tenant_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap_or_else(|_| "0".repeat(64)); // Genesis hash

            let chain_seq: u64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(chain_seq), 0) + 1 FROM audit_log WHERE tenant_id = ?",
                    duckdb::params![tenant_id.to_string()],
                    |row| row.get(0),
                )
                .unwrap_or(1);

            // Compute row_hash = SHA256(prev_hash + action + actor_id + ts)
            let mut hasher = sha2::Sha256::new();
            hasher.update(prev_hash.as_bytes());
            hasher.update(entry.action.as_bytes());
            hasher.update(entry.actor_id.as_bytes());
            hasher.update(now.as_bytes());
            let row_hash_bytes = hasher.finalize();
            let row_hash: String = row_hash_bytes.iter().fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });

            conn.execute(
                "INSERT INTO audit_log (audit_id, tenant_id, ts, actor_id, actor_type, action, resource_type, resource_id, result, prev_hash, row_hash, chain_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                duckdb::params![
                    audit_id,
                    tenant_id.to_string(),
                    now,
                    entry.actor_id,
                    entry.actor_type,
                    entry.action,
                    entry.resource_type,
                    entry.resource_id,
                    entry.result,
                    prev_hash,
                    row_hash,
                    chain_seq,
                ],
            )
            .map_err(|e| {
                tracing::error!(
                    tenant_id = %tenant_id,
                    action = %entry.action,
                    error = %e,
                    "Failed to insert audit log entry"
                );
                KronError::Storage(format!("failed to insert audit log: {e}"))
            })?;

            Ok(())
        })
        .await
        .map_err(|e| KronError::Storage(format!("audit_log task panicked: {e}")))?
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> StorageResult<()> {
        let conn = self.conn.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute_batch("SELECT 1")
                .map_err(|e| KronError::Storage(format!("DuckDB health check failed: {e}")))
        })
        .await
        .map_err(|e| KronError::Storage(format!("health check task panicked: {e}")))?
    }

    fn backend_name(&self) -> &'static str {
        "duckdb"
    }

    fn latency_stats(&self) -> LatencyStats {
        LatencyStats {
            p50_ms: 0.0,
            p99_ms: 0.0,
            total_queries: self.queries_executed.load(Ordering::Relaxed),
            total_events_inserted: self.events_inserted.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kron_types::{EventSource, TenantId};

    fn test_migrations_dir() -> String {
        let manifest = env!("CARGO_MANIFEST_DIR");
        format!("{}/../../migrations", manifest)
    }

    fn make_test_ctx() -> TenantContext {
        TenantContext::new(TenantId::new(), "test-user".to_string(), "admin")
    }

    fn make_test_event(tenant_id: TenantId) -> KronEvent {
        KronEvent::builder()
            .tenant_id(tenant_id)
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .ts(chrono::Utc::now())
            .hostname("test-host")
            .raw("test raw log line")
            .build()
            .expect("valid test event")
    }

    #[tokio::test]
    async fn test_duckdb_new_in_memory() {
        let engine = DuckDbEngine::in_memory(&test_migrations_dir());
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_duckdb_apply_migrations() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        let result = engine.apply_migrations().await;
        assert!(result.is_ok(), "migrations failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_duckdb_health_check() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        let result = engine.health_check().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_duckdb_insert_and_query_events() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx = make_test_ctx();
        let tenant_id = ctx.tenant_id();
        let event = make_test_event(tenant_id);
        let event_id = event.event_id.to_string();

        // Insert
        let inserted = engine
            .insert_events(&ctx, vec![event])
            .await
            .expect("insert must succeed");
        assert_eq!(inserted, 1);

        // Query all
        let events = engine
            .query_events(&ctx, None, 100)
            .await
            .expect("query must succeed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id.to_string(), event_id);
        assert_eq!(events[0].tenant_id, tenant_id);
        assert_eq!(events[0].event_type, "process_create");
    }

    #[tokio::test]
    async fn test_duckdb_tenant_isolation_on_insert() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx = make_test_ctx();
        let wrong_tenant = TenantId::new();
        let event = make_test_event(wrong_tenant);

        // Should fail: event tenant_id doesn't match context tenant_id
        let result = engine.insert_events(&ctx, vec![event]).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tenant isolation violation"), "got: {err}");
    }

    #[tokio::test]
    async fn test_duckdb_tenant_isolation_on_query() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx_a = make_test_ctx();
        let ctx_b = make_test_ctx(); // Different tenant

        let event_a = make_test_event(ctx_a.tenant_id());
        let event_b = make_test_event(ctx_b.tenant_id());

        // Insert events for both tenants
        engine
            .insert_events(&ctx_a, vec![event_a])
            .await
            .expect("insert a");
        engine
            .insert_events(&ctx_b, vec![event_b])
            .await
            .expect("insert b");

        // Query as tenant A — must only see tenant A's events
        let events_a = engine
            .query_events(&ctx_a, None, 100)
            .await
            .expect("query a");
        assert_eq!(events_a.len(), 1);
        assert_eq!(events_a[0].tenant_id, ctx_a.tenant_id());

        // Query as tenant B — must only see tenant B's events
        let events_b = engine
            .query_events(&ctx_b, None, 100)
            .await
            .expect("query b");
        assert_eq!(events_b.len(), 1);
        assert_eq!(events_b[0].tenant_id, ctx_b.tenant_id());
    }

    #[tokio::test]
    async fn test_duckdb_get_event_by_id() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx = make_test_ctx();
        let event = make_test_event(ctx.tenant_id());
        let event_id = event.event_id.to_string();

        engine
            .insert_events(&ctx, vec![event])
            .await
            .expect("insert");

        let found = engine
            .get_event(&ctx, &event_id)
            .await
            .expect("get must succeed");
        assert!(found.is_some());
        assert_eq!(
            found.as_ref().map(|e| e.event_id.to_string()),
            Some(event_id)
        );
    }

    #[tokio::test]
    async fn test_duckdb_get_event_not_found() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx = make_test_ctx();
        let found = engine
            .get_event(&ctx, "00000000-0000-0000-0000-000000000000")
            .await
            .expect("get must succeed");
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_duckdb_insert_audit_log() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx = make_test_ctx();
        let entry = AuditLogEntry {
            actor_id: "user-1".to_string(),
            actor_type: "human".to_string(),
            action: "view_event".to_string(),
            resource_type: Some("event".to_string()),
            resource_id: Some("event-123".to_string()),
            result: "success".to_string(),
            detail: None,
        };

        let result = engine.insert_audit_log(&ctx, entry).await;
        assert!(
            result.is_ok(),
            "audit log insert failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_duckdb_batch_insert_10000_events() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx = make_test_ctx();
        let events: Vec<KronEvent> = (0..10_000)
            .map(|_| make_test_event(ctx.tenant_id()))
            .collect();

        let inserted = engine
            .insert_events(&ctx, events)
            .await
            .expect("batch insert must succeed");
        assert_eq!(inserted, 10_000);

        // Verify count
        let queried = engine
            .query_events(&ctx, None, 10_001)
            .await
            .expect("query must succeed");
        assert_eq!(queried.len(), 10_000);
    }

    #[tokio::test]
    async fn test_duckdb_query_with_filter() {
        let engine =
            DuckDbEngine::in_memory(&test_migrations_dir()).expect("must create in-memory db");
        engine.apply_migrations().await.expect("migrations");

        let ctx = make_test_ctx();
        let mut event1 = make_test_event(ctx.tenant_id());
        event1.event_type = "process_create".to_string();
        let mut event2 = make_test_event(ctx.tenant_id());
        event2.event_type = "network_connect".to_string();

        engine
            .insert_events(&ctx, vec![event1, event2])
            .await
            .expect("insert");

        let filter = EventFilter::new().with_event_type("process_create".to_string());
        let events = engine
            .query_events(&ctx, Some(filter), 100)
            .await
            .expect("query");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "process_create");
    }
}
