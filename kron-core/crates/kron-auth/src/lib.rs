//! `kron-auth` — Authentication and authorization for the KRON SIEM platform.
//!
//! Implements JWT RS256 issuance and validation, Argon2id password hashing,
//! TOTP MFA, RBAC, brute-force protection, and session management.
//!
//! # Authentication flow
//!
//! 1. `POST /auth/login` — validates credentials + TOTP
//! 2. JWT issued (RS256, 8-hour expiry, non-renewable)
//! 3. JWT validated by Axum middleware on every request
//! 4. `TenantContext` extracted from JWT claim — never from request body
//!
//! # Module structure
//!
//! - [`jwt`] — JWT issuance, validation, and Axum extractor
//! - [`rbac`] — `can(role, action, resource)` function
//! - [`mfa`] — TOTP validation (totp-rs)
//! - [`password`] — Argon2id hashing and verification
//! - [`session`] — token blocklist (logout invalidation)
//! - [`brute_force`] — rate limiting on auth endpoints
//! - [`metrics`] — Prometheus counters for auth events

pub mod brute_force;
pub mod error;
pub mod jwt;
pub mod metrics;
pub mod mfa;
pub mod password;
pub mod rbac;
pub mod session;

pub use brute_force::BruteForceGuard;
pub use error::AuthError;
pub use jwt::{JwtClaims, JwtService};
pub use mfa::TotpService;
pub use password::PasswordService;
pub use rbac::{can, Action, Resource, Role};
pub use session::SessionBlocklist;
