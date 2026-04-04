//! Metrics instrumentation for the IOC bloom filter subsystem.
//!
//! All functions emit counters or histograms via the [`metrics`] crate.
//! A Prometheus exporter (configured elsewhere) will expose them at
//! `/metrics`.

use metrics::{counter, histogram};

/// Marker type that groups all IOC-related metric helpers.
///
/// No instances are needed; all functions are free functions in this module.
/// This type exists solely so `mod.rs` can re-export a named `IocMetrics`
/// symbol as part of the public API contract.
pub struct IocMetrics;

/// Record that `count` IOC entries were inserted (or re-inserted after rebuild).
pub fn record_ioc_insert(count: u64) {
    counter!("kron_ioc_inserts_total").absolute(count);
}

/// Record an IOC lookup that returned `true` (possible match) for `ioc_type`.
pub fn record_ioc_hit(ioc_type: &str) {
    counter!("kron_ioc_lookups_total", "result" => "hit", "type" => ioc_type.to_owned())
        .increment(1);
}

/// Record an IOC lookup that returned `false` (definite miss) for `ioc_type`.
pub fn record_ioc_miss(ioc_type: &str) {
    counter!("kron_ioc_lookups_total", "result" => "miss", "type" => ioc_type.to_owned())
        .increment(1);
}

/// Record that `entry_count` entries were loaded from `feed_name`.
pub fn record_feed_load(feed_name: &str, entry_count: usize) {
    counter!(
        "kron_ioc_feed_entries_loaded_total",
        "feed" => feed_name.to_owned()
    )
    .absolute(entry_count as u64);
}

/// Record that loading `feed_name` failed.
pub fn record_feed_error(feed_name: &str) {
    counter!("kron_ioc_feed_errors_total", "feed" => feed_name.to_owned()).increment(1);
}

/// Record how long a full filter refresh took (in milliseconds).
pub fn record_refresh_duration_ms(ms: u64) {
    // u64 to f64 may lose precision for very large values; acceptable for histogram use.
    #[allow(clippy::cast_precision_loss)]
    let ms_f64 = ms as f64;
    histogram!("kron_ioc_refresh_duration_ms").record(ms_f64);
}
