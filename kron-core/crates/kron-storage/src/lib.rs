//! `kron-storage` — Storage abstraction for the KRON SIEM platform.
//!
//! Abstracts `ClickHouse` (Standard/Enterprise) and `DuckDB` (Nano) behind a
//! single [`StorageEngine`] trait. All SQL strings live in this crate — no
//! other crate may construct SQL directly (see `CLAUDE.md` prime directive 7).
//!
//! # Strict rule
//!
//! Every query, insert, and update in this crate enforces `tenant_id`.
//! The [`query::QueryBuilder`] module constructs parameterized queries that
//! always inject `AND tenant_id = ?` — this is gate 2 of the 4-gate
//! multi-tenancy isolation model.
//!
//! # Module structure
//!
//! - [`traits`] — `StorageEngine` trait definition and `AuditLogEntry`
//! - [`query`] — `EventFilter`, `QueryBuilder` with parameterized queries
//! - [`adaptive`] — `AdaptiveStorage` picks `ClickHouse` or `DuckDB` from config
//! - [`duckdb`] — `DuckDB` implementation (Nano tier)
//! - [`clickhouse`] — `ClickHouse` implementation (Standard/Enterprise)
//!
//! # Usage
//!
//! ```ignore
//! use kron_storage::AdaptiveStorage;
//! use kron_types::KronConfig;
//!
//! let config = KronConfig::from_file("config.toml")?;
//! let storage = AdaptiveStorage::new(&config).await?;
//!
//! // All operations automatically enforce tenant isolation
//! let events = storage.query_events(&ctx, None, 1000).await?;
//! ```

pub mod adaptive;
pub mod assets;
#[cfg(feature = "clickhouse-backend")]
pub mod clickhouse;
pub mod duckdb;
pub mod login_attempts;
pub mod migration;
pub mod query;
pub mod revoked_tokens;
pub mod tenant;
pub mod traits;
pub mod users;

// Re-export key types
pub use adaptive::AdaptiveStorage;
pub use assets::{AssetCriticality, AssetStore, KronAsset};
pub use login_attempts::LoginAttemptsStore;
pub use revoked_tokens::RevokedTokenStore;
pub use tenant::{TenantRecord, TenantStore};
pub use traits::{AuditLogEntry, LatencyStats, StorageEngine, StorageResult};
pub use users::{KronUser, UserStore};
