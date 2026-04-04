//! Per-tenant, per-channel notification rate limiter.
//!
//! P1/P2 (Critical/High) alerts always bypass the rate limit.
//! P3+ alerts share a sliding 1-hour window with a configurable cap.

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use kron_types::Severity;

/// Thread-safe rate limiter for notification channels.
///
/// State is stored in a [`DashMap`] keyed by `(tenant_id, channel)`.
pub struct NotificationRateLimiter {
    /// Window state: `(count_this_hour, window_start)`.
    windows: DashMap<(String, String), (u32, DateTime<Utc>)>,
    /// Maximum notifications allowed per hour per `(tenant, channel)` pair.
    max_per_hour: u32,
}

impl NotificationRateLimiter {
    /// Creates a new `NotificationRateLimiter` with the given hourly cap.
    #[must_use]
    pub fn new(max_per_hour: u32) -> Self {
        Self {
            windows: DashMap::new(),
            max_per_hour,
        }
    }

    /// Checks whether a notification is allowed and, if so, consumes one slot.
    ///
    /// P1/P2 (Critical or High severity) alerts always return `true` without
    /// consuming a slot.  All other alerts consume from the hourly window.
    ///
    /// Returns `true` if the notification is allowed, `false` if rate-limited.
    #[must_use]
    pub fn allow(&self, tenant_id: &str, channel: &str, severity: Severity) -> bool {
        // Critical and High bypass all rate limiting.
        if severity.is_immediate() {
            return true;
        }

        let key = (tenant_id.to_string(), channel.to_string());
        let now = Utc::now();
        let hour = Duration::hours(1);

        let mut entry = self.windows.entry(key).or_insert_with(|| (0, now));

        // Reset window if the previous window has expired.
        if now - entry.1 >= hour {
            *entry = (0, now);
        }

        if entry.0 >= self.max_per_hour {
            return false;
        }

        entry.0 += 1;
        true
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_when_critical_then_always_allows() {
        let rl = NotificationRateLimiter::new(0); // 0 cap — nothing passes unless immediate
        assert!(rl.allow("tenant1", "whatsapp", Severity::Critical));
        assert!(rl.allow("tenant1", "whatsapp", Severity::High));
    }

    #[test]
    fn test_rate_limiter_when_medium_and_under_cap_then_allows() {
        let rl = NotificationRateLimiter::new(10);
        assert!(rl.allow("tenant1", "whatsapp", Severity::Medium));
    }

    #[test]
    fn test_rate_limiter_when_medium_and_cap_exceeded_then_blocks() {
        let rl = NotificationRateLimiter::new(2);
        rl.allow("t1", "sms", Severity::Medium);
        rl.allow("t1", "sms", Severity::Medium);
        let result = rl.allow("t1", "sms", Severity::Medium);
        assert!(!result, "should be blocked after cap exhausted");
    }
}
