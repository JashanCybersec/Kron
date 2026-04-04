//! Asset inventory store: persistent asset metadata for enrichment and risk scoring.
//!
//! Stores asset records in `{data_dir}/assets.json`. The normalizer uses this
//! store to enrich events with `asset_criticality` and `asset_tags` at ingest time.
//!
//! Without asset data, risk scoring degrades (criticality multiplier defaults to 1.0)
//! and alert prioritization loses accuracy. This store is the fix for that gap.
//!
//! # Tenant isolation
//!
//! All operations require a `tenant_id`. Assets from different tenants are stored
//! in separate key namespaces (`{tenant_id}:{host_id}`) so no cross-tenant leakage
//! is possible.
//!
//! # Thread safety
//!
//! All methods are `&self` with a `tokio::sync::RwLock` protecting internal state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use kron_types::KronError;

/// Asset criticality level, used as a risk-score multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetCriticality {
    /// Non-production, low-value assets. Multiplier: 0.5.
    Low,
    /// Standard production assets. Multiplier: 1.0.
    Medium,
    /// Domain controllers, databases, HSMs, payment systems. Multiplier: 2.0.
    High,
    /// Crown jewel assets; breach = regulatory incident. Multiplier: 3.0.
    Critical,
}

impl AssetCriticality {
    /// Returns the risk-score multiplier for this criticality level.
    #[must_use]
    pub fn multiplier(self) -> f32 {
        match self {
            Self::Low => 0.5,
            Self::Medium => 1.0,
            Self::High => 2.0,
            Self::Critical => 3.0,
        }
    }
}

impl Default for AssetCriticality {
    fn default() -> Self {
        Self::Medium
    }
}

/// A single asset record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KronAsset {
    /// Unique asset identifier (UUID or `hostname.fqdn`).
    pub asset_id: String,
    /// Tenant this asset belongs to.
    pub tenant_id: String,
    /// Short hostname (e.g. `web-01`).
    pub hostname: String,
    /// Fully-qualified domain name, if available.
    pub fqdn: Option<String>,
    /// Primary IP address (IPv4).
    pub ip: Option<String>,
    /// Operating system family: `"linux"` | `"windows"` | `"macos"` | `"network"`.
    pub os_type: Option<String>,
    /// Asset owner (team or individual contact).
    pub owner: Option<String>,
    /// Criticality level — drives the risk-score multiplier.
    pub criticality: AssetCriticality,
    /// Free-form tags for grouping (e.g. `["pci", "dmz"]`).
    pub tags: Vec<String>,
    /// Whether a KRON agent is installed on this asset.
    pub agent_installed: bool,
    /// ISO-8601 UTC timestamp of the last observed event from this asset.
    pub last_seen_at: Option<String>,
    /// ISO-8601 UTC creation timestamp.
    pub created_at: String,
}

/// File layout persisted to `{data_dir}/assets.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct AssetDb {
    /// Maps `"{tenant_id}:{asset_id}"` → asset record.
    assets: HashMap<String, KronAsset>,
}

/// Persistent, thread-safe asset inventory.
///
/// Lives inside [`crate::AdaptiveStorage`] and is accessible via
/// `state.storage.assets`.
pub struct AssetStore {
    state: Arc<RwLock<AssetDb>>,
    file_path: PathBuf,
}

impl AssetStore {
    /// Opens (or creates) the asset store at `{data_dir}/assets.json`.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the file cannot be read or parsed.
    pub async fn open(data_dir: &Path) -> Result<Self, KronError> {
        let file_path = data_dir.join("assets.json");

        let db = if file_path.exists() {
            let raw = tokio::fs::read_to_string(&file_path).await.map_err(|e| {
                KronError::Storage(format!("failed to read assets.json: {e}"))
            })?;
            serde_json::from_str::<AssetDb>(&raw).map_err(|e| {
                KronError::Storage(format!("failed to parse assets.json: {e}"))
            })?
        } else {
            AssetDb::default()
        };

        Ok(Self {
            state: Arc::new(RwLock::new(db)),
            file_path,
        })
    }

    /// Looks up an asset by hostname within a tenant, returning the first match.
    ///
    /// Used by the normalizer to enrich events with criticality and tags.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the lock cannot be acquired.
    pub async fn get_by_hostname(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<Option<KronAsset>, KronError> {
        let db = self.state.read().await;
        let result = db
            .assets
            .values()
            .find(|a| a.tenant_id == tenant_id && a.hostname.eq_ignore_ascii_case(hostname))
            .cloned();
        Ok(result)
    }

    /// Looks up an asset by IP address within a tenant.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the lock cannot be acquired.
    pub async fn get_by_ip(
        &self,
        tenant_id: &str,
        ip: &str,
    ) -> Result<Option<KronAsset>, KronError> {
        let db = self.state.read().await;
        let result = db
            .assets
            .values()
            .find(|a| a.tenant_id == tenant_id && a.ip.as_deref() == Some(ip))
            .cloned();
        Ok(result)
    }

    /// Inserts or replaces an asset record.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if persistence fails.
    pub async fn upsert(&self, asset: KronAsset) -> Result<(), KronError> {
        let key = format!("{}:{}", asset.tenant_id, asset.asset_id);
        let mut db = self.state.write().await;
        db.assets.insert(key, asset);
        persist(&self.file_path, &*db).await
    }

    /// Returns all assets for the given tenant.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the lock cannot be acquired.
    pub async fn list_by_tenant(&self, tenant_id: &str) -> Result<Vec<KronAsset>, KronError> {
        let db = self.state.read().await;
        let assets = db
            .assets
            .values()
            .filter(|a| a.tenant_id == tenant_id)
            .cloned()
            .collect();
        Ok(assets)
    }

    /// Updates `last_seen_at` for an asset identified by hostname within a tenant.
    ///
    /// Called by the normalizer on every event that references the asset.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if persistence fails.
    pub async fn touch(&self, tenant_id: &str, hostname: &str) -> Result<(), KronError> {
        let hostname_lower = hostname.to_lowercase();
        let mut db = self.state.write().await;
        let now = chrono::Utc::now().to_rfc3339();
        let mut touched = false;
        for asset in db.assets.values_mut() {
            if asset.tenant_id == tenant_id
                && asset.hostname.to_lowercase() == hostname_lower
            {
                asset.last_seen_at = Some(now.clone());
                touched = true;
                break;
            }
        }
        if touched {
            persist(&self.file_path, &*db).await
        } else {
            Ok(())
        }
    }
}

async fn persist(path: &Path, db: &AssetDb) -> Result<(), KronError> {
    let json = serde_json::to_string_pretty(db)
        .map_err(|e| KronError::Storage(format!("failed to serialize assets: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &json).await.map_err(|e| {
        KronError::Storage(format!("failed to write assets.json.tmp: {e}"))
    })?;
    tokio::fs::rename(&tmp, path).await.map_err(|e| {
        KronError::Storage(format!("failed to rename assets.json.tmp: {e}"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_asset(tenant_id: &str, hostname: &str, ip: &str) -> KronAsset {
        KronAsset {
            asset_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_owned(),
            hostname: hostname.to_owned(),
            fqdn: None,
            ip: Some(ip.to_owned()),
            os_type: Some("linux".to_owned()),
            owner: None,
            criticality: AssetCriticality::High,
            tags: vec!["pci".to_owned()],
            agent_installed: true,
            last_seen_at: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    async fn tmp_store() -> (AssetStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = AssetStore::open(dir.path()).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_asset_store_when_empty_then_get_by_hostname_returns_none() {
        let (store, _dir) = tmp_store().await;
        assert!(store.get_by_hostname("t1", "web-01").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_asset_store_when_upserted_then_get_by_hostname_finds_it() {
        let (store, _dir) = tmp_store().await;
        store.upsert(make_asset("t1", "web-01", "10.0.0.1")).await.unwrap();
        let found = store.get_by_hostname("t1", "web-01").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().criticality, AssetCriticality::High);
    }

    #[tokio::test]
    async fn test_asset_store_tenant_isolation() {
        let (store, _dir) = tmp_store().await;
        store.upsert(make_asset("t1", "db-01", "10.0.0.2")).await.unwrap();
        assert!(store.get_by_hostname("t2", "db-01").await.unwrap().is_none());
    }
}
