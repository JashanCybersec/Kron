//! Prometheus metric helpers for the stream detection engine.
//!
//! All metrics use the `metrics` crate facade so they are exportable via
//! any compatible exporter (Prometheus, `StatsD`, etc.).
//!
//! Metric naming follows the `kron_stream_*` prefix convention.

/// Record that one event was processed for the given tenant.
pub fn record_events_processed(tenant_id: &str) {
    metrics::counter!("kron_stream_events_processed_total", "tenant_id" => tenant_id.to_string())
        .increment(1);
}

/// Record that one alert candidate was generated for the given tenant and severity.
pub fn record_alerts_generated(tenant_id: &str, severity: &str) {
    metrics::counter!(
        "kron_stream_alerts_generated_total",
        "tenant_id" => tenant_id.to_string(),
        "severity"  => severity.to_string()
    )
    .increment(1);
}

/// Record that an IOC bloom-filter hit occurred for the given tenant.
pub fn record_ioc_hits(tenant_id: &str) {
    metrics::counter!("kron_stream_ioc_hits_total", "tenant_id" => tenant_id.to_string())
        .increment(1);
}

/// Record that a SIGMA rule matched for the given tenant and rule ID.
pub fn record_sigma_matches(tenant_id: &str, rule_id: &str) {
    metrics::counter!(
        "kron_stream_sigma_matches_total",
        "tenant_id" => tenant_id.to_string(),
        "rule_id"   => rule_id.to_string()
    )
    .increment(1);
}

/// Record end-to-end pipeline latency in milliseconds for a single event.
pub fn record_pipeline_latency_ms(ms: u64) {
    #[allow(clippy::cast_precision_loss)]
    metrics::histogram!("kron_stream_pipeline_latency_ms").record(ms as f64);
}

/// Set the current consumer lag (messages behind head) for a tenant topic.
pub fn set_consumer_lag(tenant_id: &str, lag: i64) {
    // Lag values near i64::MAX would lose precision, but such values indicate
    // total consumer failure — the approximation is acceptable for metrics.
    #[allow(clippy::cast_precision_loss)]
    let lag_f64 = lag as f64;
    metrics::gauge!("kron_stream_consumer_lag", "tenant_id" => tenant_id.to_string()).set(lag_f64);
}
