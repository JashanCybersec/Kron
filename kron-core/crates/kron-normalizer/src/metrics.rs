//! Prometheus metrics for `kron-normalizer`.
//!
//! All counters and histograms are registered lazily on first use via the
//! `metrics` crate. The Prometheus exporter is started by `main.rs`.

use metrics::{counter, gauge, histogram};

/// Records one raw event received from the bus.
pub fn record_raw_received() {
    counter!("kron_normalizer_raw_received_total").increment(1);
}

/// Records one successfully normalized event, tagged with its detected format.
pub fn record_event_normalized(format: &str) {
    counter!(
        "kron_normalizer_events_normalized_total",
        "format" => format.to_owned()
    )
    .increment(1);
}

/// Records a parse or deserialization error, tagged by reason.
pub fn record_parse_error(reason: &str) {
    counter!(
        "kron_normalizer_parse_errors_total",
        "reason" => reason.to_owned()
    )
    .increment(1);
}

/// Records one event successfully written to storage.
pub fn record_storage_write() {
    counter!("kron_normalizer_storage_writes_total").increment(1);
}

/// Records a storage write failure.
pub fn record_storage_error() {
    counter!("kron_normalizer_storage_errors_total").increment(1);
}

/// Records one enriched event published to the bus.
pub fn record_enriched_published() {
    counter!("kron_normalizer_enriched_published_total").increment(1);
}

/// Records a GeoIP lookup served from the in-process MMDB reader.
pub fn record_geoip_lookup() {
    counter!("kron_normalizer_geoip_lookups_total").increment(1);
}

/// Records a GeoIP lookup that returned no result (unknown IP).
pub fn record_geoip_miss() {
    counter!("kron_normalizer_geoip_misses_total").increment(1);
}

/// Records an asset cache hit.
pub fn record_asset_hit() {
    counter!("kron_normalizer_asset_cache_hits_total").increment(1);
}

/// Records an asset cache miss.
pub fn record_asset_miss() {
    counter!("kron_normalizer_asset_cache_misses_total").increment(1);
}

/// Records end-to-end pipeline latency for one event in milliseconds.
pub fn record_pipeline_latency_ms(ms: f64) {
    histogram!("kron_normalizer_pipeline_latency_ms").record(ms);
}

/// Sets the current estimated consumer lag in messages.
pub fn set_consumer_lag(lag: f64) {
    gauge!("kron_normalizer_consumer_lag_messages").set(lag);
}
