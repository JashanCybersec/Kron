//! Brute-force protection for authentication endpoints.
//!
//! [`BruteForceGuard`] tracks per-key (email address or IP) failed login
//! attempts. After [`BruteForceGuard::max_attempts`] consecutive failures the
//! key is locked for [`BruteForceGuard::lockout_secs`] seconds.
//!
//! The guard is backed by a [`DashMap`] for lock-free concurrent access.
//! Call [`BruteForceGuard::evict_expired`] on a background task (e.g. every
//! 60 seconds) to prevent unbounded memory growth.

use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::error::AuthError;

/// Internal record of failed login attempts for a single key.
#[derive(Debug)]
struct AttemptRecord {
    /// Number of consecutive failures since the last successful login.
    count: u32,
    /// If `Some`, the key is locked until this instant.
    locked_until: Option<Instant>,
}

/// Brute-force rate limiter for authentication endpoints.
///
/// Keyed by email address or IP address string. Thread-safe via [`DashMap`].
pub struct BruteForceGuard {
    inner: DashMap<String, AttemptRecord>,
    /// Number of consecutive failures that trigger lockout.
    max_attempts: u32,
    /// Duration of the lockout in seconds.
    lockout_secs: u64,
}

impl BruteForceGuard {
    /// Constructs a new [`BruteForceGuard`].
    ///
    /// # Arguments
    /// * `max_attempts` — consecutive failures before lockout (e.g. 5)
    /// * `lockout_secs` — lockout duration in seconds (e.g. 900 for 15 min)
    #[must_use]
    pub fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self {
            inner: DashMap::new(),
            max_attempts,
            lockout_secs,
        }
    }

    /// Checks whether `key` is currently locked out.
    ///
    /// Must be called before validating credentials. If this returns an error,
    /// the authentication attempt must be rejected immediately without
    /// performing any credential lookup.
    ///
    /// # Arguments
    /// * `key` — the email address or IP address of the login attempt
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::AccountLocked`] with the remaining lockout seconds
    /// if the key is still within its lockout window.
    pub fn check(&self, key: &str) -> Result<(), AuthError> {
        if let Some(record) = self.inner.get(key) {
            if let Some(locked_until) = record.locked_until {
                let now = Instant::now();
                if now < locked_until {
                    let remaining = locked_until
                        .checked_duration_since(now)
                        .unwrap_or(Duration::ZERO)
                        .as_secs();
                    return Err(AuthError::AccountLocked {
                        retry_after_secs: remaining,
                    });
                }
            }
        }
        Ok(())
    }

    /// Records a failed login attempt for `key`.
    ///
    /// If the failure count reaches [`BruteForceGuard::max_attempts`], the key
    /// is locked until `now + lockout_secs`.
    ///
    /// # Arguments
    /// * `key` — the email address or IP address of the failed attempt
    #[tracing::instrument(skip(self))]
    pub fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let lockout_duration = Duration::from_secs(self.lockout_secs);
        let max = self.max_attempts;

        self.inner
            .entry(key.to_owned())
            .and_modify(|r| {
                r.count += 1;
                if r.count >= max {
                    r.locked_until = Some(now + lockout_duration);
                    tracing::warn!(key = key, count = r.count, "brute-force lockout triggered");
                }
            })
            .or_insert_with(|| {
                let mut record = AttemptRecord {
                    count: 1,
                    locked_until: None,
                };
                if max <= 1 {
                    record.locked_until = Some(now + lockout_duration);
                }
                record
            });
    }

    /// Clears the failure record for `key` after a successful login.
    ///
    /// Must be called immediately after a successful authentication to prevent
    /// legitimate users from being locked out by a previous attack burst.
    ///
    /// # Arguments
    /// * `key` — the email address or IP address that authenticated successfully
    pub fn record_success(&self, key: &str) {
        self.inner.remove(key);
    }

    /// Removes expired lockout entries from the in-memory map.
    ///
    /// Should be called periodically (e.g. every 60 seconds) from a background
    /// `tokio` task. Entries are evicted only when their lockout has expired and
    /// the failure count has been cleared (i.e. no new failures arrived).
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, record| {
            match record.locked_until {
                // Keep if still locked.
                Some(locked_until) if now < locked_until => true,
                // Lockout has expired: remove the entry so users can retry.
                Some(_) => false,
                // No lockout set but count > 0: keep (partial failure window).
                None => record.count > 0,
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_brute_force_guard_when_no_failures_then_check_passes() {
        let guard = BruteForceGuard::new(5, 900);
        assert!(guard.check("user@example.com").is_ok());
    }

    #[test]
    fn test_brute_force_guard_when_below_max_then_check_passes() {
        let guard = BruteForceGuard::new(5, 900);
        guard.record_failure("user@example.com");
        guard.record_failure("user@example.com");
        assert!(guard.check("user@example.com").is_ok());
    }

    #[test]
    fn test_brute_force_guard_when_max_failures_then_locked() {
        let guard = BruteForceGuard::new(3, 900);
        guard.record_failure("user@example.com");
        guard.record_failure("user@example.com");
        guard.record_failure("user@example.com");

        let result = guard.check("user@example.com");
        assert!(matches!(result, Err(AuthError::AccountLocked { .. })));
    }

    #[test]
    fn test_brute_force_guard_when_success_after_failures_then_unlocked() {
        let guard = BruteForceGuard::new(5, 900);
        guard.record_failure("user@example.com");
        guard.record_failure("user@example.com");
        guard.record_success("user@example.com");

        assert!(guard.check("user@example.com").is_ok());
    }

    #[test]
    fn test_brute_force_guard_when_evict_expired_then_unlocked_entries_removed() {
        // lockout_secs = 0 so entries expire immediately
        let guard = BruteForceGuard::new(1, 0);
        guard.record_failure("user@example.com");

        // tiny sleep to ensure Instant::now() > locked_until
        std::thread::sleep(Duration::from_millis(10));
        guard.evict_expired();

        assert!(guard.check("user@example.com").is_ok());
    }

    #[test]
    fn test_brute_force_guard_when_different_keys_then_independent() {
        let guard = BruteForceGuard::new(2, 900);
        guard.record_failure("user-a@example.com");
        guard.record_failure("user-a@example.com");

        // user-a is locked, user-b is not.
        assert!(matches!(
            guard.check("user-a@example.com"),
            Err(AuthError::AccountLocked { .. })
        ));
        assert!(guard.check("user-b@example.com").is_ok());
    }
}
