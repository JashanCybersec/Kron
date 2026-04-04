//! Prometheus metrics for the alert engine.
//!
//! All metric names follow the `kron_alert_*` prefix convention.
//! Metrics are registered lazily on first call via the `metrics` crate.

use metrics::{counter, histogram};

/// Records that a new alert was created.
pub fn record_alert_created(tenant_id: &str, severity: &str) {
    counter!(
        "kron_alert_created_total",
        "tenant_id" => tenant_id.to_string(),
        "severity" => severity.to_string(),
    )
    .increment(1);
}

/// Records that an incoming alert candidate was merged into an existing window
/// (i.e., was deduplicated rather than producing a new alert).
pub fn record_alert_deduped(tenant_id: &str) {
    counter!(
        "kron_alert_deduped_total",
        "tenant_id" => tenant_id.to_string(),
    )
    .increment(1);
}

/// Records that a notification was successfully sent on `channel`.
pub fn record_notification_sent(channel: &str) {
    counter!(
        "kron_notification_sent_total",
        "channel" => channel.to_string(),
    )
    .increment(1);
}

/// Records that a notification delivery attempt failed on `channel`.
pub fn record_notification_failed(channel: &str) {
    counter!(
        "kron_notification_failed_total",
        "channel" => channel.to_string(),
    )
    .increment(1);
}

/// Records that a notification was suppressed by the rate limiter.
pub fn record_notification_rate_limited(channel: &str) {
    counter!(
        "kron_notification_rate_limited_total",
        "channel" => channel.to_string(),
    )
    .increment(1);
}

/// Records end-to-end alert engine processing latency in milliseconds.
pub fn record_engine_latency_ms(ms: u64) {
    // Precision loss is acceptable here: we only need millisecond granularity.
    #[allow(clippy::cast_precision_loss)]
    histogram!("kron_alert_engine_latency_ms").record(ms as f64);
}
