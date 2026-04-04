//! Persistent JWT revocation store.
//!
//! Stores revoked JWT IDs (`jti` claims) in `{data_dir}/revoked_tokens.json`.
//! This survives process restarts, closing the security gap where a restart
//! cleared the in-memory blocklist and allowed revoked tokens to be reused.
//!
//! # Thread safety
//!
//! All methods are `&self` with a `tokio::sync::RwLock` protecting internal state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use kron_types::KronError;

/// File layout persisted to `{data_dir}/revoked_tokens.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RevokedTokenDb {
    /// Maps JWT ID (`jti`) → Unix timestamp at which the token expires.
    ///
    /// Once `now > expires_at`, the entry can be safely evicted because
    /// an expired token is already rejected by the JWT validator independently.
    tokens: HashMap<String, u64>,
}

/// Persistent, thread-safe JWT revocation store.
///
/// Lives inside [`crate::AdaptiveStorage`] and is accessible via
/// `state.storage.revoked_tokens`.
pub struct RevokedTokenStore {
    state: Arc<RwLock<RevokedTokenDb>>,
    file_path: PathBuf,
}

impl RevokedTokenStore {
    /// Opens (or creates) the revocation store at `{data_dir}/revoked_tokens.json`.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the file cannot be read or parsed.
    pub async fn open(data_dir: &Path) -> Result<Self, KronError> {
        let file_path = data_dir.join("revoked_tokens.json");

        let db = if file_path.exists() {
            let raw = tokio::fs::read_to_string(&file_path).await.map_err(|e| {
                KronError::Storage(format!("failed to read revoked_tokens.json: {e}"))
            })?;
            serde_json::from_str::<RevokedTokenDb>(&raw).map_err(|e| {
                KronError::Storage(format!("failed to parse revoked_tokens.json: {e}"))
            })?
        } else {
            RevokedTokenDb::default()
        };

        Ok(Self {
            state: Arc::new(RwLock::new(db)),
            file_path,
        })
    }

    /// Revokes a JWT by its `jti`, storing its natural expiry timestamp.
    ///
    /// # Arguments
    /// * `jti`              — the `jti` claim value from the JWT being revoked
    /// * `expires_at_unix`  — Unix seconds when this token would have expired
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if persistence fails.
    #[tracing::instrument(skip(self))]
    pub async fn revoke(&self, jti: &str, expires_at_unix: u64) -> Result<(), KronError> {
        let mut db = self.state.write().await;
        db.tokens.insert(jti.to_owned(), expires_at_unix);
        tracing::info!(jti = jti, "JWT revoked persistently");
        persist(&self.file_path, &*db).await
    }

    /// Returns `true` if the given `jti` has been revoked.
    pub async fn is_revoked(&self, jti: &str) -> bool {
        self.state.read().await.tokens.contains_key(jti)
    }

    /// Removes entries whose natural expiry has already passed.
    ///
    /// Safe to call from a background task (e.g. every 5 minutes).
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if persistence fails.
    pub async fn evict_expired(&self) -> Result<(), KronError> {
        let now = unix_now();
        let mut db = self.state.write().await;
        let before = db.tokens.len();
        db.tokens.retain(|_, expires_at| *expires_at > now);
        let evicted = before - db.tokens.len();
        if evicted > 0 {
            tracing::debug!(evicted, "Evicted expired revoked tokens");
            persist(&self.file_path, &*db).await
        } else {
            Ok(())
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn persist(path: &Path, db: &RevokedTokenDb) -> Result<(), KronError> {
    let json = serde_json::to_string_pretty(db)
        .map_err(|e| KronError::Storage(format!("failed to serialize revoked_tokens: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &json).await.map_err(|e| {
        KronError::Storage(format!("failed to write revoked_tokens.json.tmp: {e}"))
    })?;
    tokio::fs::rename(&tmp, path).await.map_err(|e| {
        KronError::Storage(format!("failed to rename revoked_tokens.json.tmp: {e}"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn tmp_store() -> (RevokedTokenStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = RevokedTokenStore::open(dir.path()).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_revoked_tokens_when_not_revoked_then_is_revoked_false() {
        let (store, _dir) = tmp_store().await;
        assert!(!store.is_revoked("some-jti").await);
    }

    #[tokio::test]
    async fn test_revoked_tokens_when_revoked_then_is_revoked_true() {
        let (store, _dir) = tmp_store().await;
        store.revoke("jti-abc", unix_now() + 3600).await.unwrap();
        assert!(store.is_revoked("jti-abc").await);
    }

    #[tokio::test]
    async fn test_revoked_tokens_survives_reload() {
        let dir = TempDir::new().unwrap();
        {
            let store = RevokedTokenStore::open(dir.path()).await.unwrap();
            store.revoke("jti-persist", unix_now() + 3600).await.unwrap();
        }
        let store2 = RevokedTokenStore::open(dir.path()).await.unwrap();
        assert!(store2.is_revoked("jti-persist").await);
    }

    #[tokio::test]
    async fn test_revoked_tokens_evict_expired_removes_old_entries() {
        let (store, _dir) = tmp_store().await;
        store.revoke("jti-old", 1).await.unwrap(); // expires in the past
        store.revoke("jti-new", unix_now() + 3600).await.unwrap();
        store.evict_expired().await.unwrap();
        assert!(!store.is_revoked("jti-old").await);
        assert!(store.is_revoked("jti-new").await);
    }
}
