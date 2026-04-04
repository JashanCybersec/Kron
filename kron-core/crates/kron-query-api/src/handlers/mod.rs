//! HTTP request handlers, one sub-module per resource group.
//!
//! All handlers follow the same contract:
//! - Require [`AuthUser`] (JWT extractor) for every protected endpoint.
//! - Check RBAC via `kron_auth::can(user.role, action, resource)`.
//! - Return `Result<impl IntoResponse, ApiError>`.
//! - Log all errors at the point of handling with structured fields.
//! - Never construct `TenantId` from request data — always from `AuthUser`.

pub mod alerts;
pub mod assets;
pub mod auth;
#[cfg(feature = "standard")]
pub mod compliance;
pub mod events;
pub mod health;
pub mod rules;
pub mod tenants;
