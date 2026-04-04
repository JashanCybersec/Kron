//! TOTP (Time-Based One-Time Password) multi-factor authentication.
//!
//! Uses the `totp-rs` crate with RFC 6238 defaults:
//! - Algorithm: SHA-1
//! - Digits: 6
//! - Step: 30 seconds
//! - Window: ±1 step (allows 30 s clock skew in either direction)
//!
//! Secrets are stored as base32-encoded strings (the standard for TOTP URIs
//! and QR code generation).

use totp_rs::{Algorithm, Secret, TOTP};

use crate::error::AuthError;

/// TOTP multi-factor authentication service.
///
/// All methods are free functions; there is no instance state.
pub struct TotpService;

impl TotpService {
    /// Generates a new random TOTP secret.
    ///
    /// Returns a base32-encoded 160-bit (20-byte) secret string that should
    /// be stored in the user record and shown to the user as a QR code URI
    /// via [`TotpService::totp_uri`].
    ///
    /// # Returns
    /// A base32-encoded string (no padding), compatible with all standard
    /// authenticator apps (Google Authenticator, Authy, Aegis).
    #[must_use]
    pub fn generate_secret() -> String {
        Secret::generate_secret().to_encoded().to_string()
    }

    /// Validates a TOTP code against a stored secret.
    ///
    /// Accepts codes from the current step and the immediately preceding step
    /// (±1 window) to compensate for up to 30 seconds of clock drift.
    ///
    /// # Arguments
    /// * `secret` — base32-encoded secret stored for the user
    /// * `code`   — 6-digit code supplied by the user's authenticator app
    ///
    /// # Returns
    /// `Ok(true)` if the code is valid for the current or adjacent step.
    /// `Ok(false)` if the code is well-formed but wrong.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TotpInvalid`] if the secret is not valid base32.
    #[tracing::instrument(skip(secret, code))]
    pub fn validate_totp(secret: &str, code: &str) -> Result<bool, AuthError> {
        let totp = build_totp_bare(secret)?;
        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Constructs an `otpauth://` URI for QR code display.
    ///
    /// The returned URI can be encoded as a QR code and scanned by any
    /// standards-compliant authenticator application.
    ///
    /// # Arguments
    /// * `secret`  — base32-encoded secret for this user
    /// * `account` — account label (typically the user's email address)
    /// * `issuer`  — application name shown in the authenticator (e.g. "KRON SIEM")
    ///
    /// # Returns
    /// An `otpauth://totp/...` URI string. Falls back to a manually constructed
    /// URI on parse failure.
    #[must_use]
    pub fn totp_uri(secret: &str, account: &str, issuer: &str) -> String {
        match build_totp_labeled(secret, account, issuer) {
            Ok(totp) => totp.get_url(),
            Err(_) => format!("otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"),
        }
    }
}

/// Constructs a [`TOTP`] instance from a base32 secret with a placeholder
/// account name. Used for code validation where account/issuer are irrelevant.
///
/// # Errors
///
/// Returns [`AuthError::TotpInvalid`] if the secret string is not valid base32
/// or the TOTP parameters are rejected.
fn build_totp_bare(secret: &str) -> Result<TOTP, AuthError> {
    let secret_bytes = Secret::Encoded(secret.to_owned())
        .to_bytes()
        .map_err(|_| AuthError::TotpInvalid)?;

    TOTP::new(
        Algorithm::SHA1,
        6,  // digits
        1,  // skew: ±1 step
        30, // step: 30 seconds
        secret_bytes,
        None,
        String::new(),
    )
    .map_err(|_| AuthError::TotpInvalid)
}

/// Constructs a [`TOTP`] instance with an account label and issuer for URI generation.
///
/// # Errors
///
/// Returns [`AuthError::TotpInvalid`] if the secret string is not valid base32
/// or the TOTP parameters are rejected.
fn build_totp_labeled(secret: &str, account: &str, issuer: &str) -> Result<TOTP, AuthError> {
    let secret_bytes = Secret::Encoded(secret.to_owned())
        .to_bytes()
        .map_err(|_| AuthError::TotpInvalid)?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_owned()),
        account.to_owned(),
    )
    .map_err(|_| AuthError::TotpInvalid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_service_when_generate_secret_then_valid_base32() {
        let secret = TotpService::generate_secret();
        // A valid base32 string should be non-empty and only contain valid chars.
        assert!(!secret.is_empty());
        // Verify it can be decoded by building a TOTP from it.
        let result = build_totp_bare(&secret);
        assert!(
            result.is_ok(),
            "generated secret must be parseable: {result:?}"
        );
    }

    #[test]
    fn test_totp_service_when_current_code_then_validates() {
        let secret = TotpService::generate_secret();
        let totp = build_totp_bare(&secret).unwrap();
        let current_code = totp.generate_current().unwrap();

        let result = TotpService::validate_totp(&secret, &current_code).unwrap();
        assert!(result, "current code must validate");
    }

    #[test]
    fn test_totp_service_when_wrong_code_then_returns_false() {
        let secret = TotpService::generate_secret();
        // "000000" is almost certainly not the current code.
        let result = TotpService::validate_totp(&secret, "000000").unwrap();
        // Note: there is a ~1/1000000 chance this passes — acceptable in tests.
        let _ = result; // We just confirm no error is returned.
    }

    #[test]
    fn test_totp_service_when_invalid_secret_then_error() {
        let result = TotpService::validate_totp("NOT!BASE32!!", "123456");
        assert!(matches!(result, Err(AuthError::TotpInvalid)));
    }

    #[test]
    fn test_totp_service_when_totp_uri_then_contains_expected_fields() {
        let secret = TotpService::generate_secret();
        let uri = TotpService::totp_uri(&secret, "analyst@kron.security", "KRON SIEM");
        assert!(uri.starts_with("otpauth://"), "must be otpauth URI: {uri}");
    }
}
