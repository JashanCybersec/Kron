//! Collector self-monitoring metrics.
//!
//! All metrics use the `metrics` crate façade. Prometheus exposition is
//! configured by [`crate::collector::Collector`] via `metrics-exporter-prometheus`.
//!
//! # Registered metrics
//!
//! | Name | Type | Description |
//! |---|---|---|
//! | `kron_collector_events_received_total` | Counter | Events received, labelled by source |
//! | `kron_collector_events_published_total` | Counter | Events published to the message bus |
//! | `kron_collector_events_rejected_total` | Counter | Events rejected (invalid, rate-limited) |
//! | `kron_collector_agent_registrations_total` | Counter | Agent registrations processed |
//! | `kron_collector_agents_dark_total` | Counter | Agents marked dark (heartbeat timeout) |
//! | `kron_collector_heartbeats_total` | Counter | Heartbeats received from agents |
//! | `kron_collector_rate_limited_events_total` | Counter | Events dropped due to per-agent rate limit |
//! | `kron_collector_active_agents` | Gauge | Count of registered non-dark agents |
//! | `kron_collector_batch_size` | Histogram | Events per gRPC batch received |
//! | `kron_collector_publish_latency_ms` | Histogram | Bus publish round-trip latency in ms |

use metrics::{counter, gauge, histogram};

/// Records events received from a named source.
///
/// `source` is one of `"grpc"`, `"syslog_udp"`, `"syslog_tcp"`, or `"http"`.
pub fn record_events_received(source: &str, count: u64) {
    counter!("kron_collector_events_received_total", "source" => source.to_owned())
        .increment(count);
}

/// Records events successfully published to the message bus.
pub fn record_events_published(count: u64) {
    counter!("kron_collector_events_published_total").increment(count);
}

/// Records events rejected before reaching the bus.
///
/// `reason` is one of `"validation"`, `"rate_limit"`, `"auth"`, or `"parse"`.
pub fn record_events_rejected(reason: &str, count: u64) {
    counter!("kron_collector_events_rejected_total", "reason" => reason.to_owned())
        .increment(count);
}

/// Records a completed agent registration.
pub fn record_agent_registration() {
    counter!("kron_collector_agent_registrations_total").increment(1);
}

/// Records an agent being marked as "dark" (heartbeat timeout).
pub fn record_agent_dark() {
    counter!("kron_collector_agents_dark_total").increment(1);
}

/// Records a heartbeat received from an agent.
pub fn record_heartbeat() {
    counter!("kron_collector_heartbeats_total").increment(1);
}

/// Records events dropped because the agent exceeded its EPS limit.
pub fn record_rate_limited(count: u64) {
    counter!("kron_collector_rate_limited_events_total").increment(count);
}

/// Sets the count of currently active (non-dark) registered agents.
pub fn set_active_agents(count: usize) {
    #[allow(clippy::cast_precision_loss)]
    gauge!("kron_collector_active_agents").set(count as f64);
}

/// Records the number of events in a single gRPC batch.
pub fn record_batch_size(size: usize) {
    #[allow(clippy::cast_precision_loss)]
    histogram!("kron_collector_batch_size").record(size as f64);
}

/// Records the round-trip latency of a single bus publish call in milliseconds.
pub fn record_publish_latency_ms(latency_ms: f64) {
    histogram!("kron_collector_publish_latency_ms").record(latency_ms);
}
