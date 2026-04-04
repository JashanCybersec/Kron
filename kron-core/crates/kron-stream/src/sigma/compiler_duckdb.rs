//! DuckDB SQL compiler for SIGMA rules.
//!
//! Generates `SELECT count(*) FROM events WHERE tenant_id = :tenant_id AND <detection>`
//! queries using DuckDB-specific SQL functions.

use crate::error::StreamError;
use crate::sigma::ast::SigmaRule;
use crate::sigma::compiler::{
    build_condition_clause, build_selection_clause, join_or, SqlCompiler,
};

/// Compiles [`SigmaRule`] detections into DuckDB SQL queries.
pub struct DuckDbCompiler;

impl SqlCompiler for DuckDbCompiler {
    /// Compiles the rule into a DuckDB `SELECT count(*)` query.
    ///
    /// Uses:
    /// - `LOWER(col) LIKE LOWER(pattern)` for case-insensitive matching.
    /// - `regexp_matches(col, pattern)` for regex matching.
    /// - CIDR matching degrades to `1=0` (not natively supported in DuckDB 0.10).
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::SigmaCompile`] if the detection block is empty.
    fn compile(&self, rule: &SigmaRule) -> Result<String, StreamError> {
        let detection_clause = compile_detection(rule)?;

        Ok(format!(
            "SELECT count(*) FROM events WHERE tenant_id = :tenant_id AND ({detection_clause})"
        ))
    }
}

/// Compiles the detection block to a DuckDB WHERE clause fragment.
fn compile_detection(rule: &SigmaRule) -> Result<String, StreamError> {
    if rule.detection.selections.is_empty() {
        return Err(StreamError::SigmaCompile {
            rule_id: rule.id.to_string(),
            reason: "detection block has no selections".to_string(),
        });
    }

    let selections = &rule.detection.selections;

    let sel_clause = |name: &str| -> String {
        selections.get(name).map_or_else(
            || "1=0".to_string(),
            |sel| {
                build_selection_clause(
                    sel,
                    duckdb_ilike,
                    "regexp_matches",
                    // DuckDB 0.10 does not have a built-in CIDR function.
                    None,
                    "raw",
                )
            },
        )
    };

    let raw_clause = build_condition_clause(&rule.detection.condition, &sel_clause);
    let resolved = resolve_quantifiers(&raw_clause, rule)?;
    Ok(resolved)
}

/// DuckDB case-insensitive LIKE using ILIKE.
///
/// Single quotes in `pattern` are escaped to prevent SQL injection.
fn duckdb_ilike(col: &str, pattern: &str) -> String {
    let escaped = pattern.replace('\'', "''");
    format!("{col} ILIKE '{escaped}'")
}

/// Resolves `__ONE_OF__` and `__ALL_OF__` placeholders for DuckDB.
fn resolve_quantifiers(clause: &str, rule: &SigmaRule) -> Result<String, StreamError> {
    let mut result = clause.to_string();
    let selection_names: Vec<&str> = rule
        .detection
        .selections
        .keys()
        .map(String::as_str)
        .collect();

    // Search for the closing `__` AFTER the 9-char prefix to avoid
    // matching the opening `__` of the placeholder itself.
    while let Some(start) = result.find("__ONE_OF_") {
        let after_prefix = start + 9;
        let end = result[after_prefix..].find("__").map(|e| after_prefix + e + 2);
        let Some(end) = end else { break };
        let pattern = result[after_prefix..end - 2].to_string();
        let replacement = build_one_of_clause(&pattern, rule, &selection_names)?;
        result = format!("{}{}{}", &result[..start], replacement, &result[end..]);
    }

    while let Some(start) = result.find("__ALL_OF_") {
        let after_prefix = start + 9;
        let end = result[after_prefix..].find("__").map(|e| after_prefix + e + 2);
        let Some(end) = end else { break };
        let pattern = result[after_prefix..end - 2].to_string();
        let replacement = build_all_of_clause(&pattern, rule, &selection_names)?;
        result = format!("{}{}{}", &result[..start], replacement, &result[end..]);
    }

    Ok(result)
}

/// Builds an OR clause from selections matching the glob pattern (DuckDB).
fn build_one_of_clause(
    pattern: &str,
    rule: &SigmaRule,
    names: &[&str],
) -> Result<String, StreamError> {
    let matching: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| glob_matches(pattern, n))
        .collect();

    if matching.is_empty() {
        return Ok("1=0".to_string());
    }

    let clauses: Vec<String> = matching
        .iter()
        .map(|n| {
            rule.detection.selections.get(*n).map_or_else(
                || "1=0".to_string(),
                |sel| build_selection_clause(sel, duckdb_ilike, "regexp_matches", None, "raw"),
            )
        })
        .collect();

    Ok(join_or(&clauses))
}

/// Builds an AND clause from all selections matching the glob pattern (DuckDB).
fn build_all_of_clause(
    pattern: &str,
    rule: &SigmaRule,
    names: &[&str],
) -> Result<String, StreamError> {
    let matching: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| glob_matches(pattern, n))
        .collect();

    if matching.is_empty() {
        return Ok("1=0".to_string());
    }

    let clauses: Vec<String> = matching
        .iter()
        .map(|n| {
            rule.detection.selections.get(*n).map_or_else(
                || "1=0".to_string(),
                |sel| build_selection_clause(sel, duckdb_ilike, "regexp_matches", None, "raw"),
            )
        })
        .collect();

    if clauses.len() == 1 {
        return Ok(clauses[0].clone());
    }
    Ok(format!("({})", clauses.join(" AND ")))
}

/// Simple glob match reused from the ClickHouse compiler.
fn glob_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }

    pattern == name
}
