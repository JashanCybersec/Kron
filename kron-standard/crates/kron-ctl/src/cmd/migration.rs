//! `kron-ctl migration` — database migration commands.
//!
//! ## Subcommands
//!
//! - `run`    — apply all pending migrations (idempotent)
//! - `status` — list migration files on disk with their checksums

use kron_storage::{migration::load_migrations, AdaptiveStorage};

use crate::{config::CtlConfig, error::CtlError, output};

/// Run `kron-ctl migration run`.
///
/// Initialises [`AdaptiveStorage`], which applies all pending migrations on
/// startup via [`kron_storage::migration`].  The operation is idempotent —
/// already-applied migrations are skipped.
///
/// # Errors
/// Returns [`CtlError::Storage`] if the storage backend cannot be reached or
/// a migration fails to apply.
pub async fn run_migrate(config: &CtlConfig) -> Result<(), CtlError> {
    output::header("Migration: Run");
    println!("  Connecting to storage backend …");

    AdaptiveStorage::new(&config.inner)
        .await
        .map_err(|e| CtlError::Storage(e.to_string()))?;

    output::ok("migrations", "all pending migrations applied");
    println!();
    Ok(())
}

/// Run `kron-ctl migration status`.
///
/// Loads migration files from disk and prints their version, name, and
/// SHA-256 checksum.  Does not require a live storage connection.
///
/// # Errors
/// Returns [`CtlError::Migration`] if the migrations directory cannot be read.
pub fn run_status(config: &CtlConfig) -> Result<(), CtlError> {
    output::header("Migration: Status");

    // Choose the migrations dir and backend label from the deployment mode.
    let (migrations_dir, backend) = match config.inner.mode {
        kron_types::DeploymentMode::Nano => (
            config
                .inner
                .duckdb
                .migrations_dir
                .to_string_lossy()
                .to_string(),
            "duckdb",
        ),
        _ => (
            config
                .inner
                .clickhouse
                .migrations_dir
                .to_string_lossy()
                .to_string(),
            "clickhouse",
        ),
    };

    println!("  Directory : {migrations_dir}");
    println!("  Backend   : {backend}");
    println!();

    let migrations =
        load_migrations(&migrations_dir, backend).map_err(|e| CtlError::Migration(e))?;

    if migrations.is_empty() {
        println!("  No migration files found in {migrations_dir}");
        return Ok(());
    }

    let mut table = output::Table::new(vec!["VERSION", "NAME", "SHA256"]);
    for m in &migrations {
        table.add_row(vec![
            format!("{:03}", m.version),
            m.name.clone(),
            m.checksum[..16].to_owned() + "…",
        ]);
    }
    table.print();
    println!("\n{} migration file(s) on disk.", migrations.len());
    Ok(())
}
