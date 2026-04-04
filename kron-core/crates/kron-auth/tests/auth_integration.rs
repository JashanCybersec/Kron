//! Integration tests for kron-auth.
//!
//! These tests exercise the full auth flow without external dependencies.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use kron_auth::{
    brute_force::BruteForceGuard,
    mfa::TotpService,
    password::PasswordService,
    rbac::{Action, Resource, Role},
    session::SessionBlocklist,
    AuthError,
};

#[test]
fn test_full_password_round_trip() {
    let hash = PasswordService::hash_password("hunter2").unwrap();
    assert!(PasswordService::verify_password("hunter2", &hash).unwrap());
    assert!(!PasswordService::verify_password("wrong", &hash).unwrap());
}

#[test]
fn test_brute_force_lockout_and_recovery() {
    let guard = BruteForceGuard::new(3, 1);
    assert!(guard.check("alice").is_ok());
    guard.record_failure("alice");
    guard.record_failure("alice");
    guard.record_failure("alice");
    assert!(matches!(
        guard.check("alice"),
        Err(AuthError::AccountLocked { .. })
    ));
    guard.record_success("alice");
    assert!(guard.check("alice").is_ok());
}

#[test]
fn test_session_blocklist_revocation() {
    use std::time::{Duration, Instant};
    let bl = SessionBlocklist::new();
    let exp = Instant::now() + Duration::from_secs(3600);
    bl.revoke("my-jti", exp);
    assert!(bl.is_revoked("my-jti"));
    assert!(!bl.is_revoked("other-jti"));
}

#[test]
fn test_totp_secret_is_valid() {
    let secret = TotpService::generate_secret();
    assert!(!secret.is_empty());
    // Validate with a dummy code (will return false but must not error)
    let result = TotpService::validate_totp(&secret, "999999");
    assert!(result.is_ok());
}

#[test]
fn test_rbac_matrix_spot_checks() {
    use kron_auth::rbac::can;
    // SuperAdmin can do everything
    assert!(can(Role::SuperAdmin, Action::Delete, Resource::Users));
    // Analyst cannot delete users
    assert!(!can(Role::Analyst, Action::Delete, Resource::Users));
    // Viewer is read-only
    assert!(can(Role::Viewer, Action::Read, Resource::Events));
    assert!(!can(Role::Viewer, Action::Write, Resource::Events));
    // ApiKey is very restricted
    assert!(can(Role::ApiKey, Action::Read, Resource::Events));
    assert!(!can(Role::ApiKey, Action::Write, Resource::Events));
    assert!(!can(Role::ApiKey, Action::Read, Resource::Users));
}
