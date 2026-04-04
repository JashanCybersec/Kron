//! Core `StorageEngine` trait and associated types.
//!
//! All storage implementations (`DuckDB`, `ClickHouse`) must implement this trait.
//! The trait enforces tenant isolation at the type level.

use crate::query::EventFilter;
use async_trait::async_trait;
use kron_types::{KronAlert, KronError, KronEvent, TenantContext};

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, KronError>;

/// Storage backend trait. All implementations must enforce `tenant_id` on every operation.
///
/// The trait is async-aware and returns `StorageResult<T>`. Implementations must:
/// - Inject `tenant_id` into every query (via [`QueryRewriter`](crate::query::QueryRewriter))
/// - Never trust `tenant_id` from request body — always use [`TenantContext`]
/// - Log all failures with context
/// - Implement connection pooling and retry logic (internal to the backend)
#[async_trait]
pub trait StorageEngine: Send + Sync {
    /// Insert a batch of events into the events table.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context (provides `tenant_id` for isolation)
    /// * `events` - Vector of events to insert
    ///
    /// # Returns
    /// Number of events successfully inserted. Partial failures (some rows fail to insert)
    /// are logged but do not prevent other rows from being inserted (best-effort batch).
    ///
    /// # Tenant Isolation
    /// The implementation MUST verify that all events in the batch have `event.tenant_id == ctx.tenant_id()`.
    /// If any event has a mismatched `tenant_id`, return `KronError::TenantIsolationViolation`.
    async fn insert_events(
        &self,
        ctx: &TenantContext,
        events: Vec<KronEvent>,
    ) -> StorageResult<u64>;

    /// Insert a single event (convenience wrapper around `insert_events`).
    async fn insert_event(&self, ctx: &TenantContext, event: KronEvent) -> StorageResult<()> {
        self.insert_events(ctx, vec![event]).await?;
        Ok(())
    }

    /// Query events for a tenant with optional filtering.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context (provides `tenant_id` for isolation)
    /// * `filter` - Optional filter (timestamp range, event type, etc.)
    /// * `limit` - Max rows to return (prevents unbounded queries)
    ///
    /// # Returns
    /// Vector of events matching the filter, sorted by `ts` descending.
    ///
    /// # Tenant Isolation
    /// All queries automatically inject `AND tenant_id = ?` — no cross-tenant leakage possible.
    ///
    /// # Errors
    /// Returns `KronError::Storage` if the query fails.
    async fn query_events(
        &self,
        ctx: &TenantContext,
        filter: Option<EventFilter>,
        limit: u32,
    ) -> StorageResult<Vec<KronEvent>>;

    /// Query a single event by ID.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context
    /// * `event_id` - UUID of the event
    ///
    /// # Returns
    /// The event, or `KronError::NotFound` if not present or belongs to a different tenant.
    async fn get_event(
        &self,
        ctx: &TenantContext,
        event_id: &str,
    ) -> StorageResult<Option<KronEvent>>;

    /// Insert alerts into the alerts table.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context
    /// * `alerts` - Vector of alerts to insert
    ///
    /// # Returns
    /// Number of alerts inserted.
    async fn insert_alerts(
        &self,
        ctx: &TenantContext,
        alerts: Vec<KronAlert>,
    ) -> StorageResult<u64>;

    /// Query alerts for a tenant.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context
    /// * `limit` - Max rows to return
    /// * `offset` - Pagination offset
    ///
    /// # Returns
    /// Vector of alerts, sorted by `created_at` descending.
    async fn query_alerts(
        &self,
        ctx: &TenantContext,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<KronAlert>>;

    /// Get a single alert by ID.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context
    /// * `alert_id` - UUID of the alert
    ///
    /// # Returns
    /// The alert, or `KronError::NotFound` if not present or belongs to a different tenant.
    async fn get_alert(
        &self,
        ctx: &TenantContext,
        alert_id: &str,
    ) -> StorageResult<Option<KronAlert>>;

    /// Update alert status and metadata.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context
    /// * `alert_id` - UUID of the alert to update
    /// * `alert` - Updated alert struct (overwrites existing)
    ///
    /// # Returns
    /// Empty result, or error if alert not found or tenant mismatch.
    async fn update_alert(&self, ctx: &TenantContext, alert: &KronAlert) -> StorageResult<()>;

    /// Insert an audit log entry.
    ///
    /// # Arguments
    /// * `ctx` - Tenant context
    /// * `entry` - Audit log entry (see `AuditLogEntry` in kron-types)
    ///
    /// # Returns
    /// Empty result, or error if insert fails.
    async fn insert_audit_log(
        &self,
        ctx: &TenantContext,
        entry: AuditLogEntry,
    ) -> StorageResult<()>;

    /// Health check: verify storage is reachable and responsive.
    ///
    /// # Returns
    /// `Ok(())` if healthy, `Err(KronError::Storage)` if not.
    /// This should be <100ms in normal operation.
    async fn health_check(&self) -> StorageResult<()>;

    /// Get storage backend name for logging/monitoring.
    fn backend_name(&self) -> &'static str;

    /// Get estimated latency statistics for monitoring.
    fn latency_stats(&self) -> LatencyStats;
}

/// Simple audit log entry structure.
///
/// This will be expanded to match the `audit_log` table schema in `Database.md`.
#[derive(Clone, Debug)]
pub struct AuditLogEntry {
    /// User/service performing the action.
    pub actor_id: String,
    /// `'human'`, `'service'`, or `'system'`.
    pub actor_type: String,
    /// Action performed: `'view_event'`, `'update_alert'`, `'run_query'`, etc.
    pub action: String,
    /// Resource type: `'event'`, `'alert'`, `'rule'`, etc.
    pub resource_type: Option<String>,
    /// Resource ID (`event_id`, `alert_id`, `rule_id`, etc.).
    pub resource_id: Option<String>,
    /// `'success'`, `'failure'`, or `'denied'`.
    pub result: String,
    /// Optional detail message.
    pub detail: Option<String>,
}

/// Latency statistics for monitoring.
#[derive(Clone, Debug, Default)]
pub struct LatencyStats {
    /// P50 query latency in milliseconds.
    pub p50_ms: f64,
    /// P99 query latency in milliseconds.
    pub p99_ms: f64,
    /// Total queries executed since startup.
    pub total_queries: u64,
    /// Total events inserted since startup.
    pub total_events_inserted: u64,
}
