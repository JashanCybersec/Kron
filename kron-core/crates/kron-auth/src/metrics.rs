//! Prometheus metrics for the `kron-auth` crate.
//!
//! All metrics are prefixed `kron_auth_` and carry a `tenant_id` label so
//! that the MSSP portal can show per-tenant authentication statistics.
//!
//! Call these functions at the point where the auth outcome is determined —
//! never inside lower-level helpers that don't know the tenant context.

/// Records a successful login event for the given tenant.
///
/// # Arguments
/// * `tenant_id` — UUID string of the tenant whose user authenticated
pub fn record_login_success(tenant_id: &str) {
    metrics::counter!(
        "kron_auth_login_success_total",
        "tenant_id" => tenant_id.to_owned()
    )
    .increment(1);
}

/// Records a failed login attempt for the given tenant.
///
/// # Arguments
/// * `tenant_id` — UUID string of the tenant whose user failed to authenticate
/// * `reason` — short `snake_case` reason code (e.g. `"invalid_credentials"`,
///   `"account_locked"`, `"totp_invalid"`)
pub fn record_login_failure(tenant_id: &str, reason: &str) {
    metrics::counter!(
        "kron_auth_login_failure_total",
        "tenant_id" => tenant_id.to_owned(),
        "reason" => reason.to_owned()
    )
    .increment(1);
}

/// Records issuance of a new JWT for the given tenant.
///
/// # Arguments
/// * `tenant_id` — UUID string of the tenant for which the token was issued
pub fn record_token_issued(tenant_id: &str) {
    metrics::counter!(
        "kron_auth_tokens_issued_total",
        "tenant_id" => tenant_id.to_owned()
    )
    .increment(1);
}

/// Records revocation of a JWT (logout or forced session termination).
pub fn record_token_revoked() {
    metrics::counter!("kron_auth_tokens_revoked_total").increment(1);
}
