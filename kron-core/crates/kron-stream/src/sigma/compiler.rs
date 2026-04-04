//! SQL compilation trait and shared utilities for SIGMA rules.
//!
//! Each SQL backend implements [`SqlCompiler`] and generates a `WHERE` clause
//! from a [`SigmaRule`]'s detection logic. The generated SQL always includes
//! a `tenant_id` filter.

use crate::error::StreamError;
use crate::sigma::ast::{
    ConditionExpr, FieldFilter, FieldFilterGroup, FieldModifier, FilterValue, Selection, SigmaRule,
};

/// Trait for compiling a [`SigmaRule`] into a SQL `SELECT` statement.
pub trait SqlCompiler {
    /// Compiles the rule into a SQL query for this backend.
    ///
    /// The generated query uses `:tenant_id` as a named parameter for the
    /// tenant isolation filter.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::SigmaCompile`] if the rule references unsupported
    /// constructs for this backend.
    fn compile(&self, rule: &SigmaRule) -> Result<String, StreamError>;
}

/// Maps a SIGMA field name to a SQL column name.
///
/// Shared by both SQL backends.
#[must_use]
pub fn sigma_field_to_column(field: &str) -> &str {
    match field {
        "CommandLine" | "command_line" => "process_cmdline",
        "Image" | "process_path" => "process_path",
        "ParentImage" | "parent_process_path" => "parent_process",
        "ProcessId" | "process_id" => "process_pid",
        "ParentProcessId" | "parent_pid" => "process_ppid",
        "ProcessName" | "process_name" => "process_name",
        "User" | "Username" | "user_name" => "user_name",
        "Computer" | "Hostname" | "hostname" => "hostname",
        "src_ip" | "SourceIp" | "SourceAddress" => "src_ip",
        "dst_ip" | "DestinationIp" | "DestinationAddress" => "dst_ip",
        "src_port" | "SourcePort" => "src_port",
        "dst_port" | "DestinationPort" => "dst_port",
        "Protocol" | "protocol" => "protocol",
        "TargetFilename" | "file_path" | "FileName" => "file_path",
        "file_name" => "file_name",
        "event_type" => "event_type",
        other => other,
    }
}

/// Escapes a string value for use in a SQL LIKE clause.
///
/// Escapes `%`, `_` metacharacters, and single quotes; does not convert SIGMA
/// wildcards (those are handled per-modifier).
#[must_use]
pub fn escape_sql_like(s: &str) -> String {
    s.replace('\'', "''")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Converts a SIGMA wildcard pattern (`*`, `?`) to a SQL LIKE pattern.
///
/// SIGMA `*` → SQL `%`, SIGMA `?` → SQL `_`.
#[must_use]
pub fn sigma_wildcard_to_like(pattern: &str) -> String {
    let escaped = escape_sql_like(pattern);
    escaped.replace('*', "%").replace('?', "_")
}

/// Renders a [`FilterValue`] as a quoted SQL string literal.
#[must_use]
pub fn render_value_as_string(v: &FilterValue) -> String {
    match v {
        FilterValue::Null => "NULL".to_string(),
        FilterValue::Int(i) => i.to_string(),
        FilterValue::Float(f) => f.to_string(),
        FilterValue::Text(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

/// Builds a SQL `WHERE` fragment for a single field filter.
///
/// `like_fn` is a backend-specific closure that wraps a column expression in a
/// case-insensitive LIKE / ILIKE call.
pub fn build_filter_clause<F>(
    filter: &FieldFilter,
    like_fn: F,
    re_fn: &str,
    cidr_fn: Option<&str>,
) -> String
where
    F: Fn(&str, &str) -> String,
{
    let col = sigma_field_to_column(&filter.field);

    match &filter.modifier {
        FieldModifier::Exact => {
            let clauses: Vec<String> = filter
                .values
                .iter()
                .map(|v| match v {
                    FilterValue::Null => format!("{col} IS NULL"),
                    FilterValue::Text(s) => {
                        if s.contains('*') || s.contains('?') {
                            like_fn(col, &sigma_wildcard_to_like(s))
                        } else {
                            format!("LOWER({col}) = LOWER({})", render_value_as_string(v))
                        }
                    }
                    _ => format!("{col} = {}", render_value_as_string(v)),
                })
                .collect();
            join_or(&clauses)
        }
        FieldModifier::Contains => {
            let clauses: Vec<String> = filter
                .values
                .iter()
                .map(|v| match v {
                    FilterValue::Text(s) => like_fn(col, &format!("%{}%", escape_sql_like(s))),
                    _ => format!("{col} = {}", render_value_as_string(v)),
                })
                .collect();
            join_or(&clauses)
        }
        FieldModifier::ContainsAll => {
            let clauses: Vec<String> = filter
                .values
                .iter()
                .map(|v| match v {
                    FilterValue::Text(s) => like_fn(col, &format!("%{}%", escape_sql_like(s))),
                    _ => format!("{col} = {}", render_value_as_string(v)),
                })
                .collect();
            join_and(&clauses)
        }
        FieldModifier::StartsWith => {
            let clauses: Vec<String> = filter
                .values
                .iter()
                .map(|v| match v {
                    FilterValue::Text(s) => like_fn(col, &format!("{}%", escape_sql_like(s))),
                    _ => format!("{col} = {}", render_value_as_string(v)),
                })
                .collect();
            join_or(&clauses)
        }
        FieldModifier::EndsWith => {
            let clauses: Vec<String> = filter
                .values
                .iter()
                .map(|v| match v {
                    FilterValue::Text(s) => like_fn(col, &format!("%{}", escape_sql_like(s))),
                    _ => format!("{col} = {}", render_value_as_string(v)),
                })
                .collect();
            join_or(&clauses)
        }
        FieldModifier::Re => {
            let clauses: Vec<String> = filter
                .values
                .iter()
                .map(|v| {
                    let pat = render_value_as_string(v);
                    format!("{re_fn}({col}, {pat})")
                })
                .collect();
            join_or(&clauses)
        }
        FieldModifier::Cidr => {
            if let Some(cidr_f) = cidr_fn {
                let clauses: Vec<String> = filter
                    .values
                    .iter()
                    .map(|v| {
                        let cidr = render_value_as_string(v);
                        format!("{cidr_f}({col}, {cidr})")
                    })
                    .collect();
                join_or(&clauses)
            } else {
                // DuckDB fallback: always-false placeholder.
                // TODO(#201, hardik, v1.2): Implement DuckDB CIDR matching via integer arithmetic
                "1=0".to_string()
            }
        }
        FieldModifier::Gt => join_or(
            &filter
                .values
                .iter()
                .map(|v| format!("{col} > {}", render_value_as_string(v)))
                .collect::<Vec<_>>(),
        ),
        FieldModifier::Gte => join_or(
            &filter
                .values
                .iter()
                .map(|v| format!("{col} >= {}", render_value_as_string(v)))
                .collect::<Vec<_>>(),
        ),
        FieldModifier::Lt => join_or(
            &filter
                .values
                .iter()
                .map(|v| format!("{col} < {}", render_value_as_string(v)))
                .collect::<Vec<_>>(),
        ),
        FieldModifier::Lte => join_or(
            &filter
                .values
                .iter()
                .map(|v| format!("{col} <= {}", render_value_as_string(v)))
                .collect::<Vec<_>>(),
        ),
        FieldModifier::All => {
            let clauses: Vec<String> = filter
                .values
                .iter()
                .map(|v| format!("LOWER({col}) = LOWER({})", render_value_as_string(v)))
                .collect();
            join_and(&clauses)
        }
    }
}

/// Builds a SQL WHERE clause for a [`FieldFilterGroup`] (all filters AND-ed).
pub fn build_group_clause<F>(
    group: &FieldFilterGroup,
    like_fn: F,
    re_fn: &str,
    cidr_fn: Option<&str>,
) -> String
where
    F: Fn(&str, &str) -> String,
{
    let clauses: Vec<String> = group
        .filters
        .iter()
        .map(|f| build_filter_clause(f, &like_fn, re_fn, cidr_fn))
        .collect();
    join_and(&clauses)
}

/// Builds a SQL WHERE clause for a [`Selection`].
pub fn build_selection_clause<F>(
    selection: &Selection,
    like_fn: F,
    re_fn: &str,
    cidr_fn: Option<&str>,
    raw_col: &str,
) -> String
where
    F: Fn(&str, &str) -> String,
{
    match selection {
        Selection::Keywords(kws) => {
            let clauses: Vec<String> = kws
                .iter()
                .map(|kw| like_fn(raw_col, &format!("%{}%", escape_sql_like(kw))))
                .collect();
            join_or(&clauses)
        }
        Selection::FieldGroups(groups) => {
            let clauses: Vec<String> = groups
                .iter()
                .map(|g| {
                    let c = build_group_clause(g, &like_fn, re_fn, cidr_fn);
                    format!("({c})")
                })
                .collect();
            join_or(&clauses)
        }
    }
}

/// Builds a SQL WHERE clause for a [`ConditionExpr`] tree.
///
/// Each named selection is resolved to its SQL clause by calling `sel_clause_fn`.
pub fn build_condition_clause<F>(expr: &ConditionExpr, sel_clause_fn: &F) -> String
where
    F: Fn(&str) -> String,
{
    match expr {
        ConditionExpr::Selection(name) => format!("({})", sel_clause_fn(name)),
        ConditionExpr::Not(inner) => {
            format!("NOT ({})", build_condition_clause(inner, sel_clause_fn))
        }
        ConditionExpr::And(a, b) => {
            format!(
                "({} AND {})",
                build_condition_clause(a, sel_clause_fn),
                build_condition_clause(b, sel_clause_fn)
            )
        }
        ConditionExpr::Or(a, b) => {
            format!(
                "({} OR {})",
                build_condition_clause(a, sel_clause_fn),
                build_condition_clause(b, sel_clause_fn)
            )
        }
        ConditionExpr::OneOf(pattern) => {
            // Will be resolved by the compiler with actual selection names.
            format!("__ONE_OF_{pattern}__")
        }
        ConditionExpr::AllOf(pattern) => {
            format!("__ALL_OF_{pattern}__")
        }
        // Aggregation/temporal unsupported in this path — produce always-false.
        ConditionExpr::Count { .. } | ConditionExpr::Near(_) => "1=0".to_string(),
    }
}

/// Joins clauses with ` OR `, wrapping in parens.
pub fn join_or(clauses: &[String]) -> String {
    if clauses.is_empty() {
        return "1=0".to_string();
    }
    if clauses.len() == 1 {
        return clauses[0].clone();
    }
    format!("({})", clauses.join(" OR "))
}

/// Joins clauses with ` AND `, wrapping in parens.
pub fn join_and(clauses: &[String]) -> String {
    if clauses.is_empty() {
        return "1=1".to_string();
    }
    if clauses.len() == 1 {
        return clauses[0].clone();
    }
    format!("({})", clauses.join(" AND "))
}
