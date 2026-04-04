//! Error types for the `kron-stream` crate.
//!
//! All errors carry context (rule ID, file path, etc.) so that log messages
//! at the handling site are self-contained and actionable.

use std::path::PathBuf;

/// Top-level error enum for the stream detection engine.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// YAML parsing of a SIGMA rule file failed.
    #[error("failed to parse SIGMA rule at {file}: {reason}")]
    SigmaParse {
        /// Path of the file that failed to parse.
        file: PathBuf,
        /// Human-readable description of the parse failure.
        reason: String,
    },

    /// AST-to-SQL compilation failed for a rule.
    #[error("failed to compile SIGMA rule '{rule_id}' to SQL: {reason}")]
    SigmaCompile {
        /// UUID of the rule whose compilation failed.
        rule_id: String,
        /// Human-readable description of the compilation failure.
        reason: String,
    },

    /// The condition string in a rule uses unsupported or invalid syntax.
    #[error("invalid condition in rule '{rule_id}': {condition}")]
    InvalidCondition {
        /// UUID of the rule with the invalid condition.
        rule_id: String,
        /// The raw condition string that could not be parsed.
        condition: String,
    },

    /// Generic rule loading error (directory access, etc.).
    #[error("rule load error: {0}")]
    RuleLoad(String),

    /// Underlying I/O error (directory listing, file read, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Regex compilation error.
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
}
