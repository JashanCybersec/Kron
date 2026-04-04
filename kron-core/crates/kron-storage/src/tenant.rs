//! Tenant registry: persistent metadata store for MSSP multi-tenant management.
//!
//! Stores tenant records in a JSON file at `{data_dir}/tenants.json`.
//! This is the global (non-tenant-scoped) metadata layer — all other storage
//! operations are scoped per-tenant; only this module is cross-tenant.
//!
//! # Isolation
//!
//! This store holds **metadata about** tenants (name, config, status) — it does
//! not hold tenant event data. Tenant event data lives in ClickHouse/DuckDB
//! tables partitioned by `tenant_id`.
//!
//! # Thread safety
//!
//! All methods are `&self` and safe to call from concurrent async tasks.
//! Internal state is protected by a `tokio::sync::RwLock`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use kron_types::KronError;

/// A single tenant record as stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRecord {
    /// UUID string that is the canonical tenant identifier.
    pub tenant_id: String,
    /// Human-readable organisation name.
    pub name: String,
    /// Primary contact email for compliance reports.
    pub contact_email: String,
    /// WhatsApp number in E.164 format for P1/P2 alerts, if configured.
    pub whatsapp_number: Option<String>,
    /// Compliance frameworks enabled: `["cert_in", "dpdp", "rbi", "sebi"]`.
    pub compliance_frameworks: Vec<String>,
    /// BCP-47 language tag for reports and alerts (e.g. `"en"`, `"hi"`).
    pub language: String,
    /// ISO-8601 UTC creation timestamp.
    pub created_at: String,
    /// `"active"` | `"suspended"` | `"offboarded"`.
    pub status: String,
}

/// File layout persisted to `{data_dir}/tenants.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TenantDb {
    tenants: HashMap<String, TenantRecord>,
}

/// Persistent, thread-safe tenant registry.
///
/// Lives inside [`crate::AdaptiveStorage`] and is accessible from all
/// handlers via `state.storage.tenants`.
pub struct TenantStore {
    /// Live in-memory state.
    state: Arc<RwLock<TenantDb>>,
    /// Absolute path to the JSON file.
    file_path: PathBuf,
}

impl TenantStore {
    /// Opens (or creates) the tenant registry at `{data_dir}/tenants.json`.
    ///
    /// If the file does not exist it is created with an empty registry.
    /// If the file exists it is loaded and validated.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the file cannot be read or parsed.
    pub async fn open(data_dir: &Path) -> Result<Self, KronError> {
        let file_path = data_dir.join("tenants.json");

        let db = if file_path.exists() {
            let raw = tokio::fs::read_to_string(&file_path).await.map_err(|e| {
                KronError::Storage(format!("failed to read tenants.json: {e}"))
            })?;
            serde_json::from_str::<TenantDb>(&raw).map_err(|e| {
                KronError::Storage(format!("tenants.json is corrupt: {e}"))
            })?
        } else {
            // Ensure parent directory exists.
            if let Some(parent) = file_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    KronError::Storage(format!("failed to create data_dir: {e}"))
                })?;
            }
            TenantDb::default()
        };

        Ok(Self {
            state: Arc::new(RwLock::new(db)),
            file_path,
        })
    }

    /// Inserts a new tenant record.
    ///
    /// Returns `KronError::Storage` with a "duplicate" message if the tenant ID
    /// already exists (callers should generate a fresh UUID).
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the ID is a duplicate or if the file
    /// cannot be flushed to disk.
    pub async fn insert(&self, record: TenantRecord) -> Result<(), KronError> {
        let mut db = self.state.write().await;

        if db.tenants.contains_key(&record.tenant_id) {
            return Err(KronError::Storage(format!(
                "tenant '{}' already exists",
                record.tenant_id
            )));
        }

        db.tenants.insert(record.tenant_id.clone(), record);
        self.flush(&db).await
    }

    /// Returns all tenant records sorted by `created_at` ascending.
    pub async fn list(&self) -> Vec<TenantRecord> {
        let db = self.state.read().await;
        let mut records: Vec<TenantRecord> = db.tenants.values().cloned().collect();
        records.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        records
    }

    /// Returns the tenant record for the given ID, or `None` if not found.
    pub async fn get(&self, tenant_id: &str) -> Option<TenantRecord> {
        let db = self.state.read().await;
        db.tenants.get(tenant_id).cloned()
    }

    /// Updates mutable config fields for an existing tenant.
    ///
    /// Only the fields that are `Some` in the update are changed.
    /// Returns the updated record, or `None` if the tenant does not exist.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the file cannot be flushed.
    pub async fn update_config(
        &self,
        tenant_id: &str,
        whatsapp_number: Option<&str>,
        contact_email: Option<&str>,
        compliance_frameworks: Option<&[String]>,
        language: Option<&str>,
    ) -> Result<Option<TenantRecord>, KronError> {
        let mut db = self.state.write().await;

        let record = match db.tenants.get_mut(tenant_id) {
            Some(r) => r,
            None => return Ok(None),
        };

        if let Some(wn) = whatsapp_number {
            record.whatsapp_number = Some(wn.to_owned());
        }
        if let Some(email) = contact_email {
            record.contact_email = email.to_owned();
        }
        if let Some(frameworks) = compliance_frameworks {
            record.compliance_frameworks = frameworks.to_vec();
        }
        if let Some(lang) = language {
            record.language = lang.to_owned();
        }

        let updated = record.clone();
        self.flush(&db).await?;
        Ok(Some(updated))
    }

    /// Marks a tenant as offboarded.
    ///
    /// Does not delete the record (audit trail retention). Callers should
    /// schedule async deletion of `kron.raw.{tenant_id}` bus topics and
    /// storage partitions separately.
    ///
    /// # Errors
    ///
    /// Returns `KronError::Storage` if the tenant does not exist or the file
    /// cannot be flushed.
    pub async fn offboard(&self, tenant_id: &str) -> Result<(), KronError> {
        let mut db = self.state.write().await;

        let record = db.tenants.get_mut(tenant_id).ok_or_else(|| {
            KronError::Storage(format!("tenant '{tenant_id}' not found for offboarding"))
        })?;

        if record.status == "offboarded" {
            return Err(KronError::Storage(format!(
                "tenant '{tenant_id}' is already offboarded"
            )));
        }

        record.status = "offboarded".to_owned();
        self.flush(&db).await
    }

    /// Returns `true` if the tenant ID exists and is `active`.
    pub async fn is_active(&self, tenant_id: &str) -> bool {
        let db = self.state.read().await;
        db.tenants
            .get(tenant_id)
            .map(|r| r.status == "active")
            .unwrap_or(false)
    }

    /// Atomically writes the in-memory state to disk.
    ///
    /// Writes to a `.tmp` file then renames for atomicity.
    async fn flush(&self, db: &TenantDb) -> Result<(), KronError> {
        let json = serde_json::to_string_pretty(db).map_err(|e| {
            KronError::Storage(format!("failed to serialize tenants: {e}"))
        })?;

        let tmp_path = self.file_path.with_extension("json.tmp");
        tokio::fs::write(&tmp_path, &json).await.map_err(|e| {
            KronError::Storage(format!("failed to write tenants.tmp: {e}"))
        })?;
        tokio::fs::rename(&tmp_path, &self.file_path).await.map_err(|e| {
            KronError::Storage(format!("failed to rename tenants.tmp → tenants.json: {e}"))
        })?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn make_store(dir: &TempDir) -> TenantStore {
        TenantStore::open(dir.path()).await.unwrap()
    }

    fn record(id: &str, name: &str) -> TenantRecord {
        TenantRecord {
            tenant_id: id.to_owned(),
            name: name.to_owned(),
            contact_email: "admin@example.com".to_owned(),
            whatsapp_number: None,
            compliance_frameworks: vec!["cert_in".to_owned()],
            language: "en".to_owned(),
            created_at: "2026-03-25T00:00:00Z".to_owned(),
            status: "active".to_owned(),
        }
    }

    #[tokio::test]
    async fn test_insert_when_new_id_then_list_returns_record() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        store.insert(record("tid-1", "Acme")).await.unwrap();
        let list = store.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Acme");
    }

    #[tokio::test]
    async fn test_insert_when_duplicate_id_then_error() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        store.insert(record("tid-dup", "A")).await.unwrap();
        let err = store.insert(record("tid-dup", "B")).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_offboard_when_active_then_status_changed() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        store.insert(record("tid-ob", "OldCo")).await.unwrap();
        store.offboard("tid-ob").await.unwrap();
        let rec = store.get("tid-ob").await.unwrap();
        assert_eq!(rec.status, "offboarded");
    }

    #[tokio::test]
    async fn test_offboard_when_already_offboarded_then_error() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        store.insert(record("tid-ob2", "OldCo2")).await.unwrap();
        store.offboard("tid-ob2").await.unwrap();
        let err = store.offboard("tid-ob2").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_update_config_when_tenant_exists_then_fields_updated() {
        let dir = TempDir::new().unwrap();
        let store = make_store(&dir).await;
        store.insert(record("tid-up", "Widgets")).await.unwrap();
        let updated = store
            .update_config("tid-up", Some("+919876543210"), None, None, Some("hi"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.whatsapp_number.as_deref(), Some("+919876543210"));
        assert_eq!(updated.language, "hi");
    }

    #[tokio::test]
    async fn test_persistence_when_reopened_then_data_intact() {
        let dir = TempDir::new().unwrap();
        {
            let store = make_store(&dir).await;
            store.insert(record("tid-p", "Persist")).await.unwrap();
        }
        let store2 = TenantStore::open(dir.path()).await.unwrap();
        let rec = store2.get("tid-p").await;
        assert!(rec.is_some());
        assert_eq!(rec.unwrap().name, "Persist");
    }
}
