//! Argon2id password hashing and verification for the KRON SIEM platform.
//!
//! Uses Argon2id with OWASP-recommended parameters:
//! - Memory: 64 MiB (`m_cost = 65536`)
//! - Iterations: 3 (`t_cost = 3`)
//! - Parallelism: 4 (`p_cost = 4`)
//!
//! The output is a PHC string that includes the algorithm, parameters, salt,
//! and hash — safe for direct storage in the database.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};

use crate::error::AuthError;

/// Argon2id password hashing service.
///
/// Constructed with fixed OWASP-recommended parameters.  All methods are
/// free functions on the unit struct; there is no mutable state.
pub struct PasswordService;

impl PasswordService {
    /// Hashes a plaintext password using Argon2id.
    ///
    /// Generates a cryptographically random 128-bit salt via [`OsRng`] on
    /// every call so that identical passwords produce different hashes.
    ///
    /// # Arguments
    /// * `plaintext` — the user's plaintext password
    ///
    /// # Returns
    /// A PHC-format string containing the algorithm identifier, parameters,
    /// salt, and hash — suitable for direct storage in the user table.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PasswordHash`] if the Argon2id computation fails
    /// (e.g. invalid parameter combination or `OsRng` failure).
    #[tracing::instrument(skip(plaintext))]
    pub fn hash_password(plaintext: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let params = build_params()?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        argon2
            .hash_password(plaintext.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AuthError::PasswordHash(e.to_string()))
    }

    /// Verifies a plaintext password against a stored Argon2id PHC hash.
    ///
    /// # Arguments
    /// * `plaintext` — the password supplied by the user at login
    /// * `hash`      — the PHC string retrieved from the database
    ///
    /// # Returns
    /// `Ok(true)` if the password matches, `Ok(false)` if it does not.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::PasswordHash`] if `hash` is not a valid PHC
    /// string (indicates database corruption, not a wrong password).
    #[tracing::instrument(skip(plaintext, hash))]
    pub fn verify_password(plaintext: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHash(format!("malformed PHC hash: {e}")))?;

        match Argon2::default().verify_password(plaintext.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AuthError::PasswordHash(format!("verification error: {e}"))),
        }
    }
}

/// Builds the Argon2id [`Params`] with OWASP-recommended values.
///
/// # Errors
///
/// Returns [`AuthError::PasswordHash`] if the parameter combination is
/// rejected by the argon2 crate (should never happen with these constants).
fn build_params() -> Result<Params, AuthError> {
    Params::new(
        65_536, // m_cost: 64 MiB
        3,      // t_cost: 3 iterations
        4,      // p_cost: 4 lanes
        None,   // output_len: use default (32 bytes)
    )
    .map_err(|e| AuthError::PasswordHash(format!("invalid Argon2id params: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_password_service_when_hashed_then_verifies_correctly() {
        let hash = PasswordService::hash_password("correct-horse-battery-staple").unwrap();
        let ok = PasswordService::verify_password("correct-horse-battery-staple", &hash).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_password_service_when_wrong_password_then_returns_false() {
        let hash = PasswordService::hash_password("correct-horse-battery-staple").unwrap();
        let ok = PasswordService::verify_password("wrong-password", &hash).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_password_service_when_same_plaintext_then_different_hashes() {
        let h1 = PasswordService::hash_password("same-password").unwrap();
        let h2 = PasswordService::hash_password("same-password").unwrap();
        // Salts must differ → hashes differ.
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_password_service_when_malformed_hash_then_error() {
        let result = PasswordService::verify_password("any", "not-a-phc-string");
        assert!(result.is_err());
    }

    #[test]
    fn test_password_service_when_hash_is_phc_format_then_starts_with_argon2id() {
        let hash = PasswordService::hash_password("test").unwrap();
        assert!(
            hash.starts_with("$argon2id$"),
            "expected PHC argon2id prefix, got: {hash}"
        );
    }
}
