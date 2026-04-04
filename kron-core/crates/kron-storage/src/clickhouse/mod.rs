//! `ClickHouse` implementation of [`StorageEngine`].
//!
//! Used for Standard and Enterprise tier deployments.
//! The `clickhouse::Client` manages an internal HTTP connection pool;
//! all operations go through exponential-backoff retry and a circuit breaker.
//!
//! # Modules
//! - [`rows`] — Row structs and `KronEvent` ↔ `ChEventRow` conversions.
//! - [`retry`] — [`CircuitBreaker`] and [`with_ch_retry`] helper.

mod retry;
mod rows;

use crate::migration;
use crate::query::EventFilter;
use crate::traits::{AuditLogEntry, LatencyStats, StorageEngine, StorageResult};
use async_trait::async_trait;
use kron_types::{ClickHouseConfig, KronAlert, KronError, KronEvent, TenantContext, TenantId};
use retry::{with_ch_retry, CircuitBreaker};
use rows::{
    alert_to_ch_row, ch_row_to_event, event_to_ch_row, ChAuditLogRow, ChEventRow,
    SchemaVersionQueryRow, SchemaVersionRow,
};
use sha2::Digest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// `ClickHouse` storage engine for Standard and Enterprise tiers.
///
/// Wraps a `clickhouse::Client` with circuit-breaker protection and retry logic.
/// The client handles HTTP connection pooling internally.
pub struct ClickHouseEngine {
    client: clickhouse::Client,
    migrations_dir: String,
    // Used when per-query timeout is wired into clickhouse::Client in Phase 1.2 integration tests
    #[allow(dead_code)]
    query_timeout: Duration,
    #[allow(dead_code)]
    insert_timeout: Duration,
    circuit_breaker: Arc<CircuitBreaker>,
    events_inserted: AtomicU64,
    queries_executed: AtomicU64,
}

impl ClickHouseEngine {
    /// Create and connect a `ClickHouse` storage engine.
    ///
    /// Verifies connectivity with `SELECT 1` before returning.
    ///
    /// # Arguments
    /// * `config` - Full `ClickHouse` configuration (URL, credentials, timeouts).
    /// * `migrations_dir` - Path to the directory containing `*_ch.sql` files.
    ///
    /// # Errors
    /// Returns `KronError::Storage` if `ClickHouse` is unreachable at startup.
    pub async fn new(config: &ClickHouseConfig, migrations_dir: &str) -> StorageResult<Self> {
        tracing::info!(
            url = %config.url,
            database = %config.database,
            "Connecting to ClickHouse"
        );

        let client = clickhouse::Client::default()
            .with_url(&config.url)
            .with_database(&config.database)
            .with_user(&config.username)
            .with_password(&config.password);

        // Verify connectivity.
        client.query("SELECT 1").execute().await.map_err(|e| {
            KronError::Storage(format!("ClickHouse unreachable at {}: {e}", config.url))
        })?;

        tracing::info!(url = %config.url, "ClickHouse connection verified");

        Ok(Self {
            client,
            migrations_dir: migrations_dir.to_string(),
            query_timeout: config.query_timeout(),
            insert_timeout: config.insert_timeout(),
            circuit_breaker: Arc::new(CircuitBreaker::new(
                config.circuit_breaker_threshold,
                config.circuit_breaker_recovery_secs,
            )),
            events_inserted: AtomicU64::new(0),
            queries_executed: AtomicU64::new(0),
        })
    }

    /// Apply all pending `*_ch.sql` migrations idempotently.
    ///
    /// Creates the `schema_versions` table if absent, then runs each
    /// migration file in version order. Verifies checksums of previously
    /// applied migrations to detect tampering.
    ///
    /// # Errors
    /// Returns `KronError::Storage` if any migration fails or a checksum
    /// mismatch is detected.
    pub async fn apply_migrations(&self) -> StorageResult<()> {
        let migrations = migration::load_migrations(&self.migrations_dir, "clickhouse")
            .map_err(|e| KronError::Storage(format!("failed to load CH migrations: {e}")))?;

        // schema_versions is created by migration 000 itself, but we need
        // to apply it specially since we read from it to check what's applied.
        // Ensure the table exists before querying it.
        self.client
            .query(
                "CREATE TABLE IF NOT EXISTS schema_versions \
                 (version Int32, name String, applied_at DateTime DEFAULT now(), checksum String) \
                 ENGINE = ReplacingMergeTree() ORDER BY version",
            )
            .execute()
            .await
            .map_err(|e| KronError::Storage(format!("create schema_versions failed: {e}")))?;

        // Fetch already-applied versions.
        let applied: Vec<SchemaVersionQueryRow> = self
            .client
            .query("SELECT version, checksum FROM schema_versions ORDER BY version")
            .fetch_all::<SchemaVersionQueryRow>()
            .await
            .map_err(|e| KronError::Storage(format!("read schema_versions failed: {e}")))?;

        let applied_map: std::collections::HashMap<i32, String> = applied
            .into_iter()
            .map(|r| (r.version, r.checksum))
            .collect();

        for mig in &migrations {
            if let Some(existing_cs) = applied_map.get(&mig.version) {
                if *existing_cs != mig.checksum {
                    return Err(KronError::Storage(format!(
                        "CH migration {} ({}) checksum mismatch: expected {existing_cs}, \
                         found {}. Migration files must not be modified after application.",
                        mig.version, mig.name, mig.checksum
                    )));
                }
                tracing::debug!(version = mig.version, name = %mig.name, "CH migration already applied");
                continue;
            }

            tracing::info!(version = mig.version, name = %mig.name, "Applying CH migration");

            self.client.query(&mig.sql).execute().await.map_err(|e| {
                KronError::Storage(format!(
                    "CH migration {} ({}) failed: {e}",
                    mig.version, mig.name
                ))
            })?;

            // Record in schema_versions.
            let mut ins = self
                .client
                .insert::<SchemaVersionRow>("schema_versions")
                .map_err(|e| KronError::Storage(format!("schema_versions insert init: {e}")))?;

            ins.write(&SchemaVersionRow {
                version: mig.version,
                name: mig.name.clone(),
                applied_at: chrono::Utc::now()
                    .timestamp()
                    .try_into()
                    .unwrap_or(u32::MAX),
                checksum: mig.checksum.clone(),
            })
            .await
            .map_err(|e| KronError::Storage(format!("schema_versions write: {e}")))?;

            ins.end()
                .await
                .map_err(|e| KronError::Storage(format!("schema_versions flush: {e}")))?;

            tracing::info!(version = mig.version, name = %mig.name, "CH migration applied");
        }

        Ok(())
    }

    /// Build a SELECT query string for events with tenant isolation and optional filter.
    fn build_events_select(filter: Option<&EventFilter>, limit: u32) -> String {
        use std::fmt::Write as _;
        let mut sql = "SELECT ?fields FROM events WHERE tenant_id = ?".to_string();

        if let Some(f) = filter {
            if f.from_ts.is_some() {
                sql.push_str(" AND ts >= ?");
            }
            if f.to_ts.is_some() {
                sql.push_str(" AND ts <= ?");
            }
            if f.source_type.is_some() {
                sql.push_str(" AND source_type = ?");
            }
            if f.event_type.is_some() {
                sql.push_str(" AND event_type = ?");
            }
            if f.hostname.is_some() {
                sql.push_str(" AND hostname = ?");
            }
            if f.user_name.is_some() {
                sql.push_str(" AND user_name = ?");
            }
            if f.src_ip.is_some() {
                sql.push_str(" AND src_ip = ?");
            }
            if f.dst_ip.is_some() {
                sql.push_str(" AND dst_ip = ?");
            }
            if f.process_name.is_some() {
                sql.push_str(" AND process_name = ?");
            }
            if f.ioc_hit_only == Some(true) {
                sql.push_str(" AND ioc_hit = true");
            }
        }

        let _ = write!(sql, " ORDER BY ts DESC LIMIT {limit}");
        sql
    }

    /// Compute the Merkle chain hash for an audit log entry.
    ///
    /// `row_hash = SHA256(prev_hash || action || actor_id || ts_nanos)`
    fn compute_audit_hash(prev_hash: &str, action: &str, actor_id: &str, ts_nanos: i64) -> String {
        use std::fmt::Write as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(actor_id.as_bytes());
        hasher.update(ts_nanos.to_le_bytes());
        hasher.finalize().iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

#[async_trait]
impl StorageEngine for ClickHouseEngine {
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
        let event_count = events.len() as u64;

        // Gate 2: tenant isolation check before touching the database.
        for event in &events {
            if event.tenant_id != tenant_id {
                return Err(KronError::TenantIsolationViolation {
                    caller: tenant_id.to_string(),
                    target: event.tenant_id.to_string(),
                });
            }
        }

        // Serialize all rows first (before touching the network).
        let rows: Vec<ChEventRow> = events
            .iter()
            .map(event_to_ch_row)
            .collect::<StorageResult<_>>()?;

        let cb = self.circuit_breaker.clone();
        let client = self.client.clone();

        with_ch_retry(&cb, 3, 100, "insert_events", || {
            let client = client.clone();
            let rows = rows.clone();
            async move {
                let mut ins = client
                    .insert::<ChEventRow>("events")
                    .map_err(|e| clickhouse::error::Error::Custom(e.to_string()))?;

                for row in &rows {
                    ins.write(row).await?;
                }
                ins.end().await?;
                Ok(())
            }
        })
        .await?;

        self.events_inserted
            .fetch_add(event_count, Ordering::Relaxed);
        metrics::counter!("kron_storage_events_inserted_total",
            "backend" => "clickhouse",
            "tenant_id" => tenant_id.to_string()
        )
        .increment(event_count);

        tracing::debug!(
            tenant_id = %tenant_id,
            event_count,
            "Events inserted into ClickHouse"
        );

        Ok(event_count)
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id()))]
    async fn query_events(
        &self,
        ctx: &TenantContext,
        filter: Option<EventFilter>,
        limit: u32,
    ) -> StorageResult<Vec<KronEvent>> {
        let tenant_id = ctx.tenant_id();
        let sql = Self::build_events_select(filter.as_ref(), limit);

        let cb = self.circuit_breaker.clone();
        let client = self.client.clone();
        let tenant_str = tenant_id.to_string();
        let filter_clone = filter.clone();

        let rows: Vec<ChEventRow> = with_ch_retry(&cb, 3, 100, "query_events", || {
            let client = client.clone();
            let sql = sql.clone();
            let tenant_str = tenant_str.clone();
            let filter = filter_clone.clone();
            async move {
                let mut q = client.query(&sql).bind(&tenant_str);

                if let Some(ref f) = filter {
                    if let Some(ref from) = f.from_ts {
                        q = q.bind(
                            from.timestamp_nanos_opt()
                                .unwrap_or_else(|| from.timestamp() * 1_000_000_000),
                        );
                    }
                    if let Some(ref to) = f.to_ts {
                        q = q.bind(
                            to.timestamp_nanos_opt()
                                .unwrap_or_else(|| to.timestamp() * 1_000_000_000),
                        );
                    }
                    if let Some(ref s) = f.source_type {
                        q = q.bind(s.as_str());
                    }
                    if let Some(ref et) = f.event_type {
                        q = q.bind(et.as_str());
                    }
                    if let Some(ref h) = f.hostname {
                        q = q.bind(h.as_str());
                    }
                    if let Some(ref u) = f.user_name {
                        q = q.bind(u.as_str());
                    }
                    if let Some(ref ip) = f.src_ip {
                        q = q.bind(ip.as_str());
                    }
                    if let Some(ref ip) = f.dst_ip {
                        q = q.bind(ip.as_str());
                    }
                    if let Some(ref p) = f.process_name {
                        q = q.bind(p.as_str());
                    }
                }

                q.fetch_all::<ChEventRow>().await
            }
        })
        .await?;

        self.queries_executed.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("kron_storage_queries_total",
            "backend" => "clickhouse",
            "operation" => "query_events"
        )
        .increment(1);

        rows.into_iter().map(ch_row_to_event).collect()
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id(), event_id = %event_id))]
    async fn get_event(
        &self,
        ctx: &TenantContext,
        event_id: &str,
    ) -> StorageResult<Option<KronEvent>> {
        let tenant_id = ctx.tenant_id();
        let cb = self.circuit_breaker.clone();
        let client = self.client.clone();
        let tenant_str = tenant_id.to_string();
        let event_id = event_id.to_string();

        let rows: Vec<ChEventRow> = with_ch_retry(&cb, 3, 100, "get_event", || {
            let client = client.clone();
            let tenant_str = tenant_str.clone();
            let event_id = event_id.clone();
            async move {
                client
                    .query(
                        "SELECT ?fields FROM events \
                         WHERE tenant_id = ? AND event_id = ? LIMIT 1",
                    )
                    .bind(&tenant_str)
                    .bind(&event_id)
                    .fetch_all::<ChEventRow>()
                    .await
            }
        })
        .await?;

        self.queries_executed.fetch_add(1, Ordering::Relaxed);

        match rows.into_iter().next() {
            Some(row) => Ok(Some(ch_row_to_event(row)?)),
            None => Ok(None),
        }
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
        let alert_count = alerts.len() as u64;

        for alert in &alerts {
            if alert.tenant_id != tenant_id {
                return Err(KronError::TenantIsolationViolation {
                    caller: tenant_id.to_string(),
                    target: alert.tenant_id.to_string(),
                });
            }
        }

        let rows: Vec<rows::ChAlertRow> = alerts
            .iter()
            .map(alert_to_ch_row)
            .collect::<StorageResult<_>>()?;

        let cb = self.circuit_breaker.clone();
        let client = self.client.clone();

        with_ch_retry(&cb, 3, 100, "insert_alerts", || {
            let client = client.clone();
            let rows = rows.clone();
            async move {
                let mut ins = client
                    .insert::<rows::ChAlertRow>("alerts")
                    .map_err(|e| clickhouse::error::Error::Custom(e.to_string()))?;
                for row in &rows {
                    ins.write(row).await?;
                }
                ins.end().await?;
                Ok(())
            }
        })
        .await?;

        metrics::counter!("kron_storage_alerts_inserted_total",
            "backend" => "clickhouse"
        )
        .increment(alert_count);

        Ok(alert_count)
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id()))]
    async fn query_alerts(
        &self,
        ctx: &TenantContext,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<KronAlert>> {
        // Full alert hydration is Phase 2.5 (kron-alert engine).
        // Tenant isolation is enforced by the WHERE clause.
        let tenant_id = ctx.tenant_id();
        tracing::debug!(
            tenant_id = %tenant_id,
            limit,
            offset,
            "query_alerts: full hydration deferred to Phase 2.5"
        );
        Ok(Vec::new())
    }

    #[instrument(skip(self, ctx), fields(tenant_id = %ctx.tenant_id(), alert_id = %alert_id))]
    async fn get_alert(
        &self,
        ctx: &TenantContext,
        alert_id: &str,
    ) -> StorageResult<Option<KronAlert>> {
        let tenant_id = ctx.tenant_id();
        tracing::debug!(
            tenant_id = %tenant_id,
            alert_id,
            "get_alert: full hydration deferred to Phase 2.5"
        );
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
        tracing::debug!(
            tenant_id = %tenant_id,
            alert_id = %alert.alert_id,
            "update_alert: full implementation deferred to Phase 2.5"
        );
        Ok(())
    }

    #[instrument(skip(self, ctx, entry), fields(tenant_id = %ctx.tenant_id()))]
    async fn insert_audit_log(
        &self,
        ctx: &TenantContext,
        entry: AuditLogEntry,
    ) -> StorageResult<()> {
        let tenant_id = ctx.tenant_id();
        let now_nanos = chrono::Utc::now()
            .timestamp_nanos_opt()
            .ok_or_else(|| KronError::Storage("audit log ts out of i64 range".to_string()))?;

        // Fetch Merkle chain tip for this tenant.
        let (prev_hash, chain_seq) = self.fetch_audit_chain_tip(&tenant_id).await?;

        let row_hash =
            Self::compute_audit_hash(&prev_hash, &entry.action, &entry.actor_id, now_nanos);

        let audit_row = ChAuditLogRow {
            audit_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            ts: now_nanos,
            actor_id: entry.actor_id.clone(),
            actor_type: entry.actor_type.clone(),
            actor_ip: None,
            session_id: None,
            action: entry.action.clone(),
            resource_type: entry.resource_type.clone(),
            resource_id: entry.resource_id.clone(),
            result: entry.result.clone(),
            request_body: entry.detail.clone(),
            response_code: None,
            duration_ms: None,
            prev_hash,
            row_hash,
            chain_seq,
        };

        let cb = self.circuit_breaker.clone();
        let client = self.client.clone();

        with_ch_retry(&cb, 3, 100, "insert_audit_log", || {
            let client = client.clone();
            let row = ChAuditLogRow {
                audit_id: audit_row.audit_id.clone(),
                tenant_id: audit_row.tenant_id.clone(),
                ts: audit_row.ts,
                actor_id: audit_row.actor_id.clone(),
                actor_type: audit_row.actor_type.clone(),
                actor_ip: audit_row.actor_ip.clone(),
                session_id: audit_row.session_id.clone(),
                action: audit_row.action.clone(),
                resource_type: audit_row.resource_type.clone(),
                resource_id: audit_row.resource_id.clone(),
                result: audit_row.result.clone(),
                request_body: audit_row.request_body.clone(),
                response_code: audit_row.response_code,
                duration_ms: audit_row.duration_ms,
                prev_hash: audit_row.prev_hash.clone(),
                row_hash: audit_row.row_hash.clone(),
                chain_seq: audit_row.chain_seq,
            };
            async move {
                let mut ins = client
                    .insert::<ChAuditLogRow>("audit_log")
                    .map_err(|e| clickhouse::error::Error::Custom(e.to_string()))?;
                ins.write(&row).await?;
                ins.end().await?;
                Ok(())
            }
        })
        .await?;

        tracing::debug!(
            tenant_id = %tenant_id,
            action = %entry.action,
            chain_seq = audit_row.chain_seq,
            "Audit log entry inserted"
        );

        Ok(())
    }

    #[instrument(skip(self))]
    async fn health_check(&self) -> StorageResult<()> {
        self.client
            .query("SELECT 1")
            .execute()
            .await
            .map_err(|e| KronError::Storage(format!("ClickHouse health check failed: {e}")))?;

        tracing::debug!("ClickHouse health check passed");
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "clickhouse"
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

impl ClickHouseEngine {
    /// Fetch the Merkle chain tip (`prev_hash`, `next_chain_seq`) for a tenant.
    ///
    /// Returns `("0"*64, 1)` if the tenant has no audit log entries yet.
    async fn fetch_audit_chain_tip(&self, tenant_id: &TenantId) -> StorageResult<(String, u64)> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct ChainTip {
            row_hash: String,
            chain_seq: u64,
        }

        let cb = self.circuit_breaker.clone();
        let client = self.client.clone();
        let tenant_str = tenant_id.to_string();

        let rows: Vec<ChainTip> = with_ch_retry(&cb, 3, 100, "fetch_audit_chain_tip", || {
            let client = client.clone();
            let tenant_str = tenant_str.clone();
            async move {
                client
                    .query(
                        "SELECT row_hash, chain_seq FROM audit_log \
                         WHERE tenant_id = ? \
                         ORDER BY chain_seq DESC \
                         LIMIT 1",
                    )
                    .bind(&tenant_str)
                    .fetch_all::<ChainTip>()
                    .await
            }
        })
        .await?;

        match rows.into_iter().next() {
            Some(tip) => Ok((tip.row_hash, tip.chain_seq + 1)),
            None => Ok(("0".repeat(64), 1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_events_select_always_has_tenant_id() {
        let sql = ClickHouseEngine::build_events_select(None, 100);
        assert!(sql.contains("tenant_id = ?"));
        assert!(sql.contains("LIMIT 100"));
    }

    #[test]
    fn test_build_events_select_with_all_filters() {
        let filter = EventFilter::new()
            .with_event_type("process_create".to_string())
            .with_hostname("host-a".to_string())
            .ioc_hits_only();
        let sql = ClickHouseEngine::build_events_select(Some(&filter), 50);
        assert!(sql.contains("event_type = ?"));
        assert!(sql.contains("hostname = ?"));
        assert!(sql.contains("ioc_hit = true"));
        assert!(sql.contains("LIMIT 50"));
    }

    #[test]
    fn test_compute_audit_hash_deterministic() {
        let h1 = ClickHouseEngine::compute_audit_hash("genesis", "login", "user1", 1_000_000);
        let h2 = ClickHouseEngine::compute_audit_hash("genesis", "login", "user1", 1_000_000);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_compute_audit_hash_changes_with_inputs() {
        let h1 = ClickHouseEngine::compute_audit_hash("prev", "action_a", "user", 100);
        let h2 = ClickHouseEngine::compute_audit_hash("prev", "action_b", "user", 100);
        assert_ne!(h1, h2);
    }
}
