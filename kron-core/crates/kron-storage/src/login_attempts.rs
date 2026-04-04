//! Persistent brute-force protection store.
//!
//! Tracks failed login attempts per key (email or IP) in
//! `{data_dir}/login_attempts.json`. This survives process restarts so that
//! an attacker cannot clear lockouts by triggering a service restart.
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

/// Per-key record of failed login attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttemptRecord {
    /// Number of consecutive failures since the last success.
    count: u32,
    /// Unix timestamp at which the lockout expires, or `None` if not locked.
    lockout_until: Option<u64>,
}

/// File layout persisted to `{data_dir}/login_attempts.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct LoginAttemptsDb {
    /// Maps key (email or IP) → attempt record.
    attempts: HashMap<String, AttemptRecord>,
}

/// Persistent, thread-safe brute-force protection store.
///
/// Lives inside [`crate::AdaptiveStorage`] and is accessible via
/// `state.storage.login_attempts`.
pub struct LoginAttemptsStore {
    state: Arc<RwLock<LoginAttemptsDb>>,
    file_path: PathBuf,
    max_attempts: u32,
    lockout_secs: u64,
}

impl LoginAttemptsStore {
    /// Opens (or creates) the login-attempts store at `{data_dir}/login_attempts.json`.
    ///
    /// # Arguments
    /// * `data_dir`      — directory containing the JSON file
    /// * `max_attempts`  — consecutive failures before lockout
    /// * `lockout_secs`  — lockout duration in seconds
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the file cannot be read or parsed.
    pub async fn open(
        data_dir: &Path,
        max_attempts: u32,
        lockout_secs: u64,
    ) -> Result<Self, KronError> {
        let file_path = data_dir.join("login_attempts.json");

        let db = if file_path.exists() {
            let raw = tokio::fs::read_to_string(&file_path).await.map_err(|e| {
                KronError::Storage(format!("failed to read login_attempts.json: {e}"))
            })?;
            serde_json::from_str::<LoginAttemptsDb>(&raw).map_err(|e| {
                KronError::Storage(format!("failed to parse login_attempts.json: {e}"))
            })?
        } else {
            LoginAttemptsDb::default()
        };

        Ok(Self {
            state: Arc::new(RwLock::new(db)),
            file_path,
            max_attempts,
            lockout_secs,
        })
    }

    /// Returns the remaining lockout seconds for `key`, or `None` if not locked.
    ///
    /// Must be called before any credential validation. If this returns `Some`,
    /// the caller must reject the attempt immediately.
    pub async fn check_lockout(&self, key: &str) -> Option<u64> {
        let db = self.state.read().await;
        let Some(record) = db.attempts.get(key) else {
            return None;
        };
        let Some(lockout_until) = record.lockout_until else {
            return None;
        };
        let now = unix_now();
        if now < lockout_until {
            Some(lockout_until - now)
        } else {
            None
        }
    }

    /// Records a failed login attempt for `key`.
    ///
    /// Triggers a lockout when failures reach `max_attempts`.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if persistence fails.
    #[tracing::instrument(skip(self))]
    pub async fn record_failure(&self, key: &str) -> Result<(), KronError> {
        let now = unix_now();
        let lockout_at = now + self.lockout_secs;
        let max = self.max_attempts;

        let mut db = self.state.write().await;
        let record = db.attempts.entry(key.to_owned()).or_insert(AttemptRecord {
            count: 0,
            lockout_until: None,
        });

        // Reset expired lockouts before counting
        if let Some(lockout_until) = record.lockout_until {
            if now >= lockout_until {
                record.count = 0;
                record.lockout_until = None;
            }
        }

        record.count += 1;
        if record.count >= max {
            record.lockout_until = Some(lockout_at);
            tracing::warn!(key = key, count = record.count, "brute-force lockout triggered (persistent)");
        }

        persist(&self.file_path, &*db).await
    }

    /// Clears the failure record for `key` after a successful login.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if persistence fails.
    pub async fn record_success(&self, key: &str) -> Result<(), KronError> {
        let mut db = self.state.write().await;
        if db.attempts.remove(key).is_some() {
            persist(&self.file_path, &*db).await
        } else {
            Ok(())
        }
    }

    /// Removes entries whose lockout has expired.
    ///
    /// Safe to call from a background task (e.g. every 5 minutes).
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if persistence fails.
    pub async fn evict_expired(&self) -> Result<(), KronError> {
        let now = unix_now();
        let mut db = self.state.write().await;
        let before = db.attempts.len();
        db.attempts.retain(|_, r| match r.lockout_until {
            Some(until) => now < until,
            None => r.count > 0,
        });
        if db.attempts.len() < before {
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

async fn persist(path: &Path, db: &LoginAttemptsDb) -> Result<(), KronError> {
    let json = serde_json::to_string_pretty(db)
        .map_err(|e| KronError::Storage(format!("failed to serialize login_attempts: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &json).await.map_err(|e| {
        KronError::Storage(format!("failed to write login_attempts.json.tmp: {e}"))
    })?;
    tokio::fs::rename(&tmp, path).await.map_err(|e| {
        KronError::Storage(format!("failed to rename login_attempts.json.tmp: {e}"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn tmp_store(max: u32, lockout_secs: u64) -> (LoginAttemptsStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = LoginAttemptsStore::open(dir.path(), max, lockout_secs).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_login_attempts_when_no_failures_then_not_locked() {
        let (store, _dir) = tmp_store(5, 900).await;
        assert!(store.check_lockout("user@example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_login_attempts_when_below_max_then_not_locked() {
        let (store, _dir) = tmp_store(5, 900).await;
        store.record_failure("user@example.com").await.unwrap();
        store.record_failure("user@example.com").await.unwrap();
        assert!(store.check_lockout("user@example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_login_attempts_when_max_failures_then_locked() {
        let (store, _dir) = tmp_store(3, 900).await;
        store.record_failure("user@example.com").await.unwrap();
        store.record_failure("user@example.com").await.unwrap();
        store.record_failure("user@example.com").await.unwrap();
        assert!(store.check_lockout("user@example.com").await.is_some());
    }

    #[tokio::test]
    async fn test_login_attempts_when_success_then_unlocked() {
        let (store, _dir) = tmp_store(5, 900).await;
        store.record_failure("user@example.com").await.unwrap();
        store.record_success("user@example.com").await.unwrap();
        assert!(store.check_lockout("user@example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_login_attempts_survives_reload() {
        let dir = TempDir::new().unwrap();
        {
            let store = LoginAttemptsStore::open(dir.path(), 2, 900).await.unwrap();
            store.record_failure("user@example.com").await.unwrap();
            store.record_failure("user@example.com").await.unwrap();
            assert!(store.check_lockout("user@example.com").await.is_some());
        }
        let store2 = LoginAttemptsStore::open(dir.path(), 2, 900).await.unwrap();
        assert!(store2.check_lockout("user@example.com").await.is_some());
    }
}
