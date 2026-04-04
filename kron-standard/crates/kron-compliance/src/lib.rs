//! `kron-compliance` — Compliance engine for the KRON SIEM platform.
//!
//! Generates compliance reports and evidence packages for Indian regulatory
//! frameworks, all from data already stored in KRON — no external calls.
//!
//! # Supported frameworks
//!
//! - **CERT-In**: 13 incident categories, 72-hour breach notification workflow
//! - **DPDP Act**: Personal data access audit, breach notification obligations
//! - **RBI IS**: IS audit trail, data localization verification
//! - **SEBI CSCRF**: Cyber Security and Cyber Resilience Framework
//!
//! # Outputs
//!
//! - Structured HTML compliance reports (renderable to PDF in browser)
//! - Evidence package ZIP (events + alerts + audit log for a date range)
//! - CERT-In incident report in the prescribed 13-category format

pub mod certin;
pub mod dpdp;
pub mod error;
pub mod evidence;
pub mod rbi;
pub mod report;
pub mod sebi;
pub mod types;

pub use error::ComplianceError;
pub use report::ReportEngine;
pub use types::{
    ComplianceFramework, ComplianceReport, EvidencePackage, ReportRequest, ReportStatus,
};
