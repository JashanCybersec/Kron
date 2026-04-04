//! Adaptive storage backend selection.
//!
//! [`AdaptiveStorage`] reads the [`KronConfig`] and instantiates
//! either `DuckDB` or `ClickHouse` based on the deployment mode.
//!
//! `ClickHouse` support is compiled in only when the `clickhouse-backend`
//! Cargo feature is enabled. Nano builds (DuckDB only) never activate that
//! feature and therefore never link the ClickHouse client.
//!
//! # Feature gates
//!
//! | Feature               | Backend compiled in           |
//! |-----------------------|-------------------------------|
//! | *(none / default)*    | DuckDB only (Nano)            |
//! | `clickhouse-backend`  | DuckDB + ClickHouse (Standard)|

use crate::assets::AssetStore;
use crate::duckdb::DuckDbEngine;
use crate::login_attempts::LoginAttemptsStore;
use crate::revoked_tokens::RevokedTokenStore;
use crate::tenant::TenantStore;
use crate::traits::{AuditLogEntry, LatencyStats, StorageEngine, StorageResult};
use crate::users::UserStore;
use async_trait::async_trait;
use kron_types::KronError;
use kron_types::{DeploymentMode, KronAlert, KronConfig, KronEvent, TenantContext};
use std::sync::Arc;
use tracing::info;

#[cfg(feature = "clickhouse-backend")]
use crate::clickhouse::ClickHouseEngine;

/// Enum of compiled-in storage backends.
#[derive(Clone)]
enum BackendEnum {
    DuckDb(Arc<DuckDbEngine>),
    #[cfg(feature = "clickhouse-backend")]
    ClickHouse(Arc<ClickHouseEngine>),
}

/// Adaptive storage engine that selects `DuckDB` or `ClickHouse` from config.
///
/// Also holds all platform-level stores (tenants, users, auth, assets) that
/// are not per-tenant-scoped event data.
///
/// # Usage
/// ```ignore
/// let config = KronConfig::from_file("config.toml")?;
/// let storage = AdaptiveStorage::new(&config).await?;
///
/// let ctx = TenantContext::new(tenant_id, user_id, "viewer");
/// let events = storage.query_events(&ctx, None, 1000).await?;
///
/// // Platform-level stores:
/// storage.users.verify_password("email", "password").await?;
/// storage.revoked_tokens.revoke("jti", exp).await?;
/// storage.assets.get_by_hostname("tenant_id", "web-01").await?;
/// ```
pub struct AdaptiveStorage {
    backend: BackendEnum,
    /// Cross-tenant registry for MSSP tenant lifecycle (create, config, offboard).
    pub tenants: Arc<TenantStore>,
    /// Platform user registry with Argon2id-hashed credentials.
    pub users: Arc<UserStore>,
    /// Persistent JWT revocation list — survives restarts.
    pub revoked_tokens: Arc<RevokedTokenStore>,
    /// Persistent brute-force protection — survives restarts.
    pub login_attempts: Arc<LoginAttemptsStore>,
    /// Asset inventory for event enrichment and risk scoring.
    pub assets: Arc<AssetStore>,
}

impl AdaptiveStorage {
    /// Create a new adaptive storage instance from configuration.
    ///
    /// # Arguments
    /// * `config` - Full KRON configuration (determines deployment mode)
    ///
    /// # Returns
    /// Initialized storage engine, or error if backend cannot be reached.
    ///
    /// # Errors
    ///
    /// Returns [`KronError::Storage`] if:
    /// - The selected backend cannot be reached or initialized.
    /// - Standard/Enterprise mode is requested but `clickhouse-backend` feature
    ///   is not compiled in (Nano builds return a clear error instead of panicking).
    ///
    /// # Deployment Mode Selection
    ///
    /// - Nano → `DuckDB` at `config.duckdb.path`
    /// - Standard/Enterprise → `ClickHouse` at `config.clickhouse.url`
    ///   *(requires `clickhouse-backend` Cargo feature)*
    pub async fn new(config: &KronConfig) -> StorageResult<Self> {
        let backend = match config.mode {
            DeploymentMode::Nano => {
                info!("Initializing Nano tier storage (DuckDB)");
                let db_path = config.duckdb.path.to_string_lossy();
                let migrations_dir = config.duckdb.migrations_dir.to_string_lossy();
                let engine = DuckDbEngine::new(&db_path, &migrations_dir)
                    .map_err(|e| KronError::Storage(format!("DuckDB init failed: {e}")))?;
                engine.apply_migrations().await?;
                BackendEnum::DuckDb(Arc::new(engine))
            }
            #[cfg(feature = "clickhouse-backend")]
            DeploymentMode::Standard => {
                info!("Initializing Standard tier storage (ClickHouse)");
                let migrations_dir = config.clickhouse.migrations_dir.to_string_lossy();
                let engine = ClickHouseEngine::new(&config.clickhouse, &migrations_dir).await?;
                engine.apply_migrations().await?;
                BackendEnum::ClickHouse(Arc::new(engine))
            }
            #[cfg(feature = "clickhouse-backend")]
            DeploymentMode::Enterprise => {
                info!("Initializing Enterprise tier storage (ClickHouse sharded)");
                let migrations_dir = config.clickhouse.migrations_dir.to_string_lossy();
                let engine = ClickHouseEngine::new(&config.clickhouse, &migrations_dir).await?;
                engine.apply_migrations().await?;
                BackendEnum::ClickHouse(Arc::new(engine))
            }
            #[cfg(not(feature = "clickhouse-backend"))]
            DeploymentMode::Standard | DeploymentMode::Enterprise => {
                return Err(KronError::Storage(
                    "ClickHouse backend is not compiled in. \
                     This binary was built for Nano (DuckDB-only) mode. \
                     Rebuild with --features clickhouse-backend for Standard/Enterprise, \
                     or change mode to \"nano\" in kron.toml."
                        .to_owned(),
                ));
            }
        };

        // All platform-level JSON stores share the same data directory.
        let data_dir = config.duckdb.path.parent().unwrap_or(std::path::Path::new("."));

        let tenant_store = TenantStore::open(data_dir).await.map_err(|e| {
            KronError::Storage(format!("failed to open tenant registry: {e}"))
        })?;

        let user_store = UserStore::open(data_dir).await.map_err(|e| {
            KronError::Storage(format!("failed to open user registry: {e}"))
        })?;

        let revoked_tokens = RevokedTokenStore::open(data_dir).await.map_err(|e| {
            KronError::Storage(format!("failed to open revoked-token store: {e}"))
        })?;

        let login_attempts = LoginAttemptsStore::open(
            data_dir,
            u32::from(config.auth.max_failed_attempts),
            config.auth.lockout_duration_secs,
        )
        .await
        .map_err(|e| KronError::Storage(format!("failed to open login-attempts store: {e}")))?;

        let assets = AssetStore::open(data_dir).await.map_err(|e| {
            KronError::Storage(format!("failed to open asset store: {e}"))
        })?;

        Ok(Self {
            backend,
            tenants: Arc::new(tenant_store),
            users: Arc::new(user_store),
            revoked_tokens: Arc::new(revoked_tokens),
            login_attempts: Arc::new(login_attempts),
            assets: Arc::new(assets),
        })
    }
}

impl AdaptiveStorage {
    /// Archives DuckDB events older than `retention_days` to Parquet files under `archive_dir`.
    ///
    /// No-op on ClickHouse tiers (ClickHouse manages its own TTL and tiered storage).
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the export or deletion fails.
    pub async fn archive_to_parquet(
        &self,
        archive_dir: std::path::PathBuf,
        retention_days: u32,
    ) -> StorageResult<()> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => {
                engine.archive_to_parquet(archive_dir, retention_days).await
            }
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(_) => {
                tracing::debug!("archive_to_parquet: no-op on ClickHouse (uses built-in TTL)");
                Ok(())
            }
        }
    }
}

#[async_trait]
impl StorageEngine for AdaptiveStorage {
    async fn insert_events(
        &self,
        ctx: &TenantContext,
        events: Vec<KronEvent>,
    ) -> StorageResult<u64> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.insert_events(ctx, events).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.insert_events(ctx, events).await,
        }
    }

    async fn query_events(
        &self,
        ctx: &TenantContext,
        filter: Option<crate::query::EventFilter>,
        limit: u32,
    ) -> StorageResult<Vec<KronEvent>> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.query_events(ctx, filter, limit).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.query_events(ctx, filter, limit).await,
        }
    }

    async fn get_event(
        &self,
        ctx: &TenantContext,
        event_id: &str,
    ) -> StorageResult<Option<KronEvent>> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.get_event(ctx, event_id).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.get_event(ctx, event_id).await,
        }
    }

    async fn insert_alerts(
        &self,
        ctx: &TenantContext,
        alerts: Vec<KronAlert>,
    ) -> StorageResult<u64> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.insert_alerts(ctx, alerts).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.insert_alerts(ctx, alerts).await,
        }
    }

    async fn query_alerts(
        &self,
        ctx: &TenantContext,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<KronAlert>> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.query_alerts(ctx, limit, offset).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.query_alerts(ctx, limit, offset).await,
        }
    }

    async fn get_alert(
        &self,
        ctx: &TenantContext,
        alert_id: &str,
    ) -> StorageResult<Option<KronAlert>> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.get_alert(ctx, alert_id).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.get_alert(ctx, alert_id).await,
        }
    }

    async fn update_alert(&self, ctx: &TenantContext, alert: &KronAlert) -> StorageResult<()> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.update_alert(ctx, alert).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.update_alert(ctx, alert).await,
        }
    }

    async fn insert_audit_log(
        &self,
        ctx: &TenantContext,
        entry: AuditLogEntry,
    ) -> StorageResult<()> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.insert_audit_log(ctx, entry).await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.insert_audit_log(ctx, entry).await,
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.health_check().await,
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.health_check().await,
        }
    }

    fn backend_name(&self) -> &'static str {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.backend_name(),
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.backend_name(),
        }
    }

    fn latency_stats(&self) -> LatencyStats {
        match &self.backend {
            BackendEnum::DuckDb(engine) => engine.latency_stats(),
            #[cfg(feature = "clickhouse-backend")]
            BackendEnum::ClickHouse(engine) => engine.latency_stats(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adaptive_storage_duckdb() {
        // TODO(#TBD, hardik, v1.1): Test DuckDB path in AdaptiveStorage
    }

    #[tokio::test]
    async fn test_adaptive_storage_clickhouse() {
        // TODO(#TBD, hardik, v1.1): Test ClickHouse path in AdaptiveStorage
    }
}
