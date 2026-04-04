//! User registry: persistent credential store for KRON platform users.
//!
//! Stores user records in a JSON file at `{data_dir}/users.json`.
//! Passwords are hashed with Argon2id before storage. No plaintext credentials
//! ever touch disk.
//!
//! # Thread safety
//!
//! All methods are `&self` and safe to call from concurrent async tasks.
//! Internal state is protected by a `tokio::sync::RwLock`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use kron_types::KronError;

/// A single platform user record stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KronUser {
    /// UUID string that is the canonical user identifier.
    pub user_id: String,
    /// Email address used as the login identifier.
    pub email: String,
    /// Argon2id password hash.
    pub password_hash: String,
    /// RBAC role: `"viewer"` | `"analyst"` | `"engineer"` | `"admin"` | `"mssp_admin"`.
    pub role: String,
    /// Tenant UUID this user belongs to.
    pub tenant_id: String,
    /// Optional TOTP secret (base32-encoded). `None` means MFA is not enrolled.
    pub mfa_secret: Option<String>,
    /// `"active"` | `"suspended"`.
    pub status: String,
    /// ISO-8601 UTC creation timestamp.
    pub created_at: String,
    /// ISO-8601 UTC timestamp of the last successful login. `None` if never logged in.
    pub last_login_at: Option<String>,
}

/// File layout persisted to `{data_dir}/users.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct UserDb {
    /// Maps email (lowercase) → user record.
    users: HashMap<String, KronUser>,
}

/// Persistent, thread-safe user registry.
///
/// Lives inside [`crate::AdaptiveStorage`] and is accessible from all
/// auth handlers via `state.storage.users`.
pub struct UserStore {
    state: Arc<RwLock<UserDb>>,
    file_path: PathBuf,
}

impl UserStore {
    /// Opens (or creates) the user registry at `{data_dir}/users.json`.
    ///
    /// If the file does not exist it is created with an empty registry.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the file cannot be read or parsed.
    pub async fn open(data_dir: &Path) -> Result<Self, KronError> {
        let file_path = data_dir.join("users.json");

        let db = if file_path.exists() {
            let raw = tokio::fs::read_to_string(&file_path).await.map_err(|e| {
                KronError::Storage(format!("failed to read users.json: {e}"))
            })?;
            serde_json::from_str::<UserDb>(&raw).map_err(|e| {
                KronError::Storage(format!("failed to parse users.json: {e}"))
            })?
        } else {
            UserDb::default()
        };

        Ok(Self {
            state: Arc::new(RwLock::new(db)),
            file_path,
        })
    }

    /// Returns the user record for the given email, or `None` if not found.
    ///
    /// Email comparison is case-insensitive.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the registry lock cannot be acquired.
    pub async fn get_by_email(&self, email: &str) -> Result<Option<KronUser>, KronError> {
        let db = self.state.read().await;
        Ok(db.users.get(&email.to_lowercase()).cloned())
    }

    /// Returns the user record for the given user ID, or `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the registry lock cannot be acquired.
    pub async fn get_by_id(&self, user_id: &str) -> Result<Option<KronUser>, KronError> {
        let db = self.state.read().await;
        Ok(db.users.values().find(|u| u.user_id == user_id).cloned())
    }

    /// Inserts a new user with an Argon2id-hashed password.
    ///
    /// # Arguments
    /// * `user_id`   — UUID string for the new user
    /// * `email`     — Login email (stored lowercase)
    /// * `password`  — Plaintext password; hashed before storage
    /// * `role`      — RBAC role string
    /// * `tenant_id` — Tenant UUID string
    ///
    /// # Errors
    ///
    /// Returns `KronError::Auth` if email is already registered.
    /// Returns `KronError::Storage` if hashing or persistence fails.
    pub async fn create(
        &self,
        user_id: &str,
        email: &str,
        password: &str,
        role: &str,
        tenant_id: &str,
    ) -> Result<(), KronError> {
        let email_lower = email.to_lowercase();
        let password_hash = hash_password(password)?;

        let mut db = self.state.write().await;
        if db.users.contains_key(&email_lower) {
            return Err(KronError::Auth(format!("email already registered: {email}")));
        }

        let user = KronUser {
            user_id: user_id.to_owned(),
            email: email_lower.clone(),
            password_hash,
            role: role.to_owned(),
            tenant_id: tenant_id.to_owned(),
            mfa_secret: None,
            status: "active".to_owned(),
            created_at: chrono::Utc::now().to_rfc3339(),
            last_login_at: None,
        };

        db.users.insert(email_lower, user);
        persist(&self.file_path, &*db).await
    }

    /// Verifies a plaintext password against the stored Argon2id hash.
    ///
    /// Returns `true` only if the password matches and the user account is active.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the user cannot be read from the registry.
    pub async fn verify_password(&self, email: &str, password: &str) -> Result<bool, KronError> {
        let Some(user) = self.get_by_email(email).await? else {
            return Ok(false);
        };
        if user.status != "active" {
            return Ok(false);
        }
        Ok(verify_password(password, &user.password_hash))
    }

    /// Updates `last_login_at` to the current UTC timestamp for the given email.
    ///
    /// Called after a successful authentication to maintain an accurate last-seen timestamp.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the user is not found or persistence fails.
    pub async fn record_login(&self, email: &str) -> Result<(), KronError> {
        let email_lower = email.to_lowercase();
        let mut db = self.state.write().await;
        let user = db.users.get_mut(&email_lower).ok_or_else(|| {
            KronError::Storage(format!("user not found for last_login update: {email}"))
        })?;
        user.last_login_at = Some(chrono::Utc::now().to_rfc3339());
        persist(&self.file_path, &*db).await
    }

    /// Returns the total number of registered users.
    pub async fn count(&self) -> usize {
        self.state.read().await.users.len()
    }

    /// Enrolls a TOTP secret for the given user.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the user is not found or persistence fails.
    pub async fn set_mfa_secret(&self, email: &str, secret: &str) -> Result<(), KronError> {
        let email_lower = email.to_lowercase();
        let mut db = self.state.write().await;
        let user = db.users.get_mut(&email_lower).ok_or_else(|| {
            KronError::Storage(format!("user not found for MFA enrollment: {email}"))
        })?;
        user.mfa_secret = Some(secret.to_owned());
        persist(&self.file_path, &*db).await
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Hash a plaintext password with Argon2id.
///
/// Uses Argon2id (ADR-013) with default parameters (memory=64MB, iterations=3, parallelism=4).
///
/// # Errors
///
/// Returns `KronError::Storage` if the hashing operation fails.
fn hash_password(password: &str) -> Result<String, KronError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| KronError::Storage(format!("Argon2 hash failed: {e}")))
}

/// Verify a plaintext password against an Argon2id hash string.
///
/// Returns `true` if the password is correct, `false` otherwise.
/// Never panics; a malformed hash returns `false`.
fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        tracing::warn!("malformed Argon2 hash in user store");
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Atomically persist the in-memory `UserDb` to disk as JSON.
///
/// Writes to a `.tmp` sibling file first, then renames to ensure atomicity.
///
/// # Errors
///
/// Returns `KronError::Storage` if serialization or I/O fails.
async fn persist(path: &Path, db: &UserDb) -> Result<(), KronError> {
    let json = serde_json::to_string_pretty(db)
        .map_err(|e| KronError::Storage(format!("failed to serialize users: {e}")))?;

    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &json).await.map_err(|e| {
        KronError::Storage(format!("failed to write users.json.tmp: {e}"))
    })?;
    tokio::fs::rename(&tmp, path).await.map_err(|e| {
        KronError::Storage(format!("failed to rename users.json.tmp: {e}"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn tmp_store() -> (UserStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = UserStore::open(dir.path()).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_user_store_when_empty_then_get_by_email_returns_none() {
        let (store, _dir) = tmp_store().await;
        assert!(store.get_by_email("nobody@kron.local").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_user_store_when_user_created_then_get_by_email_returns_user() {
        let (store, _dir) = tmp_store().await;
        store
            .create("uid-1", "alice@kron.local", "password123!", "analyst", "tenant-1")
            .await
            .unwrap();
        let user = store.get_by_email("alice@kron.local").await.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().role, "analyst");
    }

    #[tokio::test]
    async fn test_user_store_when_correct_password_then_verify_returns_true() {
        let (store, _dir) = tmp_store().await;
        store
            .create("uid-2", "bob@kron.local", "s3cr3t!", "admin", "tenant-1")
            .await
            .unwrap();
        assert!(store.verify_password("bob@kron.local", "s3cr3t!").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_store_when_wrong_password_then_verify_returns_false() {
        let (store, _dir) = tmp_store().await;
        store
            .create("uid-3", "carol@kron.local", "right!", "viewer", "tenant-1")
            .await
            .unwrap();
        assert!(!store.verify_password("carol@kron.local", "wrong!").await.unwrap());
    }

    #[tokio::test]
    async fn test_user_store_when_duplicate_email_then_create_returns_error() {
        let (store, _dir) = tmp_store().await;
        store
            .create("uid-4", "dup@kron.local", "pass", "viewer", "t1")
            .await
            .unwrap();
        let result = store.create("uid-5", "dup@kron.local", "pass2", "admin", "t1").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_user_store_email_case_insensitive() {
        let (store, _dir) = tmp_store().await;
        store
            .create("uid-6", "Eve@kron.local", "pass", "analyst", "t1")
            .await
            .unwrap();
        assert!(store.get_by_email("EVE@KRON.LOCAL").await.unwrap().is_some());
    }
}
