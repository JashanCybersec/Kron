//! Directory-based SIGMA rule loader with polling hot-reload.
//!
//! [`RuleLoader`] walks a directory recursively, parses all `.yml` and `.yaml`
//! files as SIGMA rules, and reports whether any files have changed since the
//! last load (for polling-based hot-reload without a file-watcher crate).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use tracing::{error, info, warn};

use crate::error::StreamError;
use crate::sigma::ast::SigmaRule;
use crate::sigma::types::SigmaRuleRaw;

/// Loads SIGMA rules from a directory and tracks changes for hot-reload.
pub struct RuleLoader {
    /// Root directory to search for SIGMA rule files.
    rules_dir: PathBuf,
    /// The latest file modification time seen during the last `load_all` call.
    last_loaded: Option<SystemTime>,
}

impl RuleLoader {
    /// Creates a new `RuleLoader` for the given directory.
    ///
    /// The directory is not validated at construction time — errors are
    /// reported when [`load_all`](Self::load_all) is first called.
    #[must_use]
    pub fn new(rules_dir: PathBuf) -> Self {
        Self {
            rules_dir,
            last_loaded: None,
        }
    }

    /// Loads all `.yml` and `.yaml` files from the rules directory recursively.
    ///
    /// Files that fail to parse are logged and skipped — a single bad file
    /// does not abort the load. Updates the internal `last_loaded` timestamp.
    ///
    /// # Returns
    ///
    /// A list of `(path, rule)` pairs for each successfully parsed rule.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::Io`] if the rules directory cannot be read.
    pub fn load_all(&mut self) -> Result<Vec<(PathBuf, SigmaRule)>, StreamError> {
        let files = collect_rule_files(&self.rules_dir)?;
        let mut results = Vec::new();
        let mut latest_mtime: Option<SystemTime> = None;

        for path in files {
            // Track the most recent modification time.
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Ok(mtime) = meta.modified() {
                    latest_mtime = Some(match latest_mtime {
                        None => mtime,
                        Some(prev) => prev.max(mtime),
                    });
                }
            }

            match load_rule_file(&path) {
                Ok(rule) => {
                    info!(
                        rule_id = %rule.id,
                        rule_title = %rule.title,
                        path = %path.display(),
                        "Loaded SIGMA rule"
                    );
                    results.push((path, rule));
                }
                Err(e) => {
                    error!(
                        path = %path.display(),
                        error = %e,
                        "Failed to load SIGMA rule — skipping"
                    );
                }
            }
        }

        self.last_loaded = latest_mtime.or(self.last_loaded);
        Ok(results)
    }

    /// Returns `true` if any file in the rules directory has been modified
    /// since the last call to [`load_all`](Self::load_all).
    ///
    /// Uses filesystem modification timestamps — no external crate required.
    #[must_use]
    pub fn has_changed(&self) -> bool {
        let Some(last) = self.last_loaded else {
            // Never loaded — always needs a load.
            return true;
        };

        match collect_rule_files(&self.rules_dir) {
            Ok(files) => files.iter().any(|path| {
                std::fs::metadata(path)
                    .and_then(|m| m.modified())
                    .is_ok_and(|mtime| mtime > last)
            }),
            Err(e) => {
                warn!(error = %e, "Could not check rules directory for changes");
                false
            }
        }
    }
}

/// Recursively collects all `.yml` and `.yaml` file paths under `dir`.
fn collect_rule_files(dir: &Path) -> Result<Vec<PathBuf>, StreamError> {
    let mut files = Vec::new();
    collect_recursive(dir, &mut files)?;
    Ok(files)
}

/// Recursive helper that appends YAML rule file paths to `out`.
fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), StreamError> {
    let entries = std::fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            collect_recursive(&path, out)?;
        } else if is_yaml_file(&path) {
            out.push(path);
        }
    }

    Ok(())
}

/// Returns `true` if the path has a `.yml` or `.yaml` extension.
fn is_yaml_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yml") | Some("yaml")
    )
}

/// Parses a single YAML file into a [`SigmaRule`].
fn load_rule_file(path: &Path) -> Result<SigmaRule, StreamError> {
    let content = std::fs::read_to_string(path)?;

    let raw: SigmaRuleRaw =
        serde_yaml::from_str(&content).map_err(|e| StreamError::SigmaParse {
            file: path.to_path_buf(),
            reason: e.to_string(),
        })?;

    SigmaRule::from_raw(raw)
}
