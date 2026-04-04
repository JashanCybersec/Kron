//! Database migration runner.
//!
//! Reads numbered SQL files from the `migrations/` directory and executes
//! them idempotently. Migration state is tracked in a `schema_versions` table.
//!
//! Migration files must follow the naming convention: `NNN_name.sql`
//! where NNN is a zero-padded integer (e.g., `001_create_events.sql`).

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// A single migration file parsed from disk.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Version number extracted from filename (e.g., 1 from `001_create_events.sql`).
    pub version: i32,
    /// Human-readable name extracted from filename (e.g., `"create_events"`).
    pub name: String,
    /// Raw SQL content.
    pub sql: String,
    /// SHA256 checksum of the SQL content.
    pub checksum: String,
}

/// Load all migration files from the given directory.
///
/// Files are sorted by version number. Only files matching `NNN_*.sql` are loaded.
/// `ClickHouse`-specific files (`*_ch.sql`) are excluded when loading `DuckDB` migrations
/// and vice versa.
///
/// # Arguments
/// * `dir` - Path to the migrations directory
/// * `backend` - "duckdb" or "clickhouse" — filters backend-specific files
///
/// # Errors
/// Returns error if directory cannot be read or files cannot be parsed.
pub fn load_migrations(dir: &str, backend: &str) -> Result<Vec<Migration>, String> {
    let path = std::path::Path::new(dir);
    if !path.exists() {
        return Err(format!("migrations directory not found: {dir}"));
    }

    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(path)
        .map_err(|e| format!("failed to read migrations dir: {e}"))?
        .filter_map(std::result::Result::ok)
        .collect();

    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut migrations = Vec::new();

    for entry in entries {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Skip non-SQL files
        if !name_str.ends_with(".sql") {
            continue;
        }

        // Skip ClickHouse-specific files when loading for DuckDB and vice versa
        if backend == "duckdb" && name_str.ends_with("_ch.sql") {
            continue;
        }
        if backend == "clickhouse" && !name_str.ends_with("_ch.sql") {
            // For ClickHouse, we only load *_ch.sql files
            // (standard .sql files are DuckDB-compatible)
            continue;
        }

        // Parse version number from filename (NNN_name.sql)
        let Some(prefix) = name_str.split('_').next() else {
            continue;
        };
        let Ok(version) = prefix.parse::<i32>() else {
            warn!(file = %name_str, "Skipping migration file with non-numeric prefix");
            continue;
        };

        // Extract name (strip version prefix and .sql suffix)
        let migration_name = name_str
            .trim_start_matches(|c: char| c.is_ascii_digit() || c == '_')
            .trim_end_matches(".sql")
            .trim_end_matches("_ch")
            .to_string();

        let sql = std::fs::read_to_string(entry.path())
            .map_err(|e| format!("failed to read {name_str}: {e}"))?;

        let checksum = compute_checksum(&sql);

        debug!(version, name = %migration_name, checksum = %checksum, "Loaded migration");

        migrations.push(Migration {
            version,
            name: migration_name,
            sql,
            checksum,
        });
    }

    migrations.sort_by_key(|m| m.version);

    info!(count = migrations.len(), backend, "Loaded migrations");

    Ok(migrations)
}

/// Compute SHA256 checksum of migration SQL content.
fn compute_checksum(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Hex encoding for SHA256 output (avoids adding another dependency).
mod hex {
    /// Encode bytes as lowercase hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write as _;
        bytes.as_ref().iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_checksum_when_same_input_then_same_output() {
        let a = compute_checksum("SELECT 1");
        let b = compute_checksum("SELECT 1");
        assert_eq!(a, b);
    }

    #[test]
    fn test_compute_checksum_when_different_input_then_different_output() {
        let a = compute_checksum("SELECT 1");
        let b = compute_checksum("SELECT 2");
        assert_ne!(a, b);
    }

    #[test]
    fn test_compute_checksum_produces_64_char_hex() {
        let checksum = compute_checksum("test");
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
