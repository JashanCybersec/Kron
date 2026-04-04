//! SIGMA rule engine for real-time event detection.
//!
//! This module provides the full lifecycle of a SIGMA rule:
//! parsing YAML → typed AST → in-memory matching → SQL compilation.
//!
//! # Public API
//!
//! - [`SigmaRule`] — typed, validated rule
//! - [`RuleStatus`] — lifecycle status of a rule
//! - [`CompiledRule`] — rule with pre-compiled SQL and FP classification
//! - [`RuleRegistry`] — concurrent store of compiled rules
//! - [`RuleLoader`] — directory-based rule loader with hot-reload support
//! - [`RuleEvaluator`] — evaluates all production rules against a single event
//! - [`SqlCompiler`] — trait for SQL backends
//! - [`FpClassifier`] — classifies rules by false-positive rate

pub mod ast;
pub mod compiler;
pub mod compiler_clickhouse;
pub mod compiler_duckdb;
pub mod condition;
pub mod evaluator;
pub mod field_map;
pub mod fp_classifier;
pub mod loader;
pub mod matcher;
pub mod registry;
pub mod types;

pub use ast::{RuleStatus, SigmaRule};
pub use compiler::SqlCompiler;
pub use compiler_clickhouse::ClickHouseCompiler;
pub use compiler_duckdb::DuckDbCompiler;
pub use evaluator::{EvaluationResult, RuleEvaluator};
pub use fp_classifier::{FpClassification, FpClassifier};
pub use loader::RuleLoader;
pub use registry::{CompiledRule, RuleRegistry};
