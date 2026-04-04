//! Session blocklist for JWT revocation on logout.
//!
//! When a user logs out, the JWT `jti` (JWT ID) is stored in the
//! [`SessionBlocklist`] until the token would have expired anyway. Every
//! authenticated request checks this list after validating the JWT signature.
//!
//! The blocklist is in-memory only (intentional for Phase 2). In a
//! multi-replica deployment all replicas must share state — Phase 3 will
//! replace this with a Redis-backed implementation.
// TODO(#201, hardik, phase-3): Replace in-memory blocklist with Redis-backed
// implementation for multi-replica deployments.

use std::time::Instant;

use dashmap::DashMap;

/// In-memory JWT revocation list.
///
/// Maps JWT IDs (`jti` claim) to the instant at which the corresponding token
/// expires. Entries are garbage-collected by [`SessionBlocklist::evict_expired`].
pub struct SessionBlocklist {
    /// Maps `jti` → the instant at which the token would have expired.
    inner: DashMap<String, Instant>,
}

impl SessionBlocklist {
    /// Creates a new, empty [`SessionBlocklist`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Revokes a JWT by its `jti`, storing the token's expiry time.
    ///
    /// The entry is kept until `expires_at` so that the blocklist check
    /// remains authoritative for the token's full lifetime.
    ///
    /// # Arguments
    /// * `jti`        — the `jti` claim value from the JWT being revoked
    /// * `expires_at` — the instant at which this token would have expired
    ///                  (used to evict the entry once it is no longer needed)
    #[tracing::instrument(skip(self))]
    pub fn revoke(&self, jti: &str, expires_at: Instant) {
        self.inner.insert(jti.to_owned(), expires_at);
        tracing::info!(jti = jti, "JWT revoked");
    }

    /// Returns `true` if the given `jti` has been revoked.
    ///
    /// # Arguments
    /// * `jti` — the `jti` claim value extracted from the presented JWT
    #[must_use]
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.inner.contains_key(jti)
    }

    /// Removes entries whose token expiry has passed.
    ///
    /// Should be called periodically (e.g. every 60 seconds) from a background
    /// `tokio` task. After the token's natural expiry the entry is no longer
    /// needed — even without revocation an expired token is rejected by the
    /// JWT validator.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, expires_at| now < *expires_at);
    }
}

impl Default for SessionBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_session_blocklist_when_not_revoked_then_is_revoked_false() {
        let bl = SessionBlocklist::new();
        assert!(!bl.is_revoked("some-jti"));
    }

    #[test]
    fn test_session_blocklist_when_revoked_then_is_revoked_true() {
        let bl = SessionBlocklist::new();
        let expires_at = Instant::now() + Duration::from_secs(3600);
        bl.revoke("jti-abc", expires_at);
        assert!(bl.is_revoked("jti-abc"));
    }

    #[test]
    fn test_session_blocklist_when_evict_expired_then_entry_removed() {
        let bl = SessionBlocklist::new();
        // expires in the past (0 secs from now — already expired)
        let expired = Instant::now();
        bl.revoke("jti-old", expired);

        // tiny sleep to ensure Instant::now() > expired
        std::thread::sleep(Duration::from_millis(5));
        bl.evict_expired();

        assert!(!bl.is_revoked("jti-old"));
    }

    #[test]
    fn test_session_blocklist_when_evict_then_unexpired_entries_kept() {
        let bl = SessionBlocklist::new();
        let far_future = Instant::now() + Duration::from_secs(86400);
        bl.revoke("jti-valid", far_future);

        bl.evict_expired();

        assert!(bl.is_revoked("jti-valid"));
    }
}
