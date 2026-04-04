//! Agent self-monitoring metrics.
//!
//! All metrics use the `metrics` crate façade. Prometheus exposition is
//! configured by [`crate::agent::Agent`] via `metrics-exporter-prometheus`.
//!
//! # Registered metrics
//!
//! | Name | Type | Description |
//! |---|---|---|
//! | `kron_agent_events_captured_total` | Counter | Events captured from eBPF ring buffer |
//! | `kron_agent_events_dropped_total` | Counter | Events dropped due to ring buffer overflow |
//! | `kron_agent_events_sent_total` | Counter | Events successfully sent to collector |
//! | `kron_agent_events_buffered_total` | Counter | Events written to disk buffer |
//! | `kron_agent_send_latency_ms` | Histogram | Batch send round-trip latency (ms) |
//! | `kron_agent_ring_buffer_utilization` | Gauge | Ring buffer utilization 0.0–1.0 |
//! | `kron_agent_disk_buffer_bytes` | Gauge | Bytes currently held in disk buffer |
//! | `kron_agent_batch_size` | Histogram | Number of events per batch |
//! | `kron_agent_collector_connected` | Gauge | 1.0 if collector is reachable, 0.0 otherwise |
//! | `kron_agent_heartbeat_failures_total` | Counter | Heartbeat send failures |

use metrics::{counter, gauge, histogram};

/// Records one or more events captured from the eBPF ring buffer.
///
/// `event_type` is one of `"process_create"`, `"network_connect"`,
/// or `"file_access"`.
pub fn record_events_captured(event_type: &str, count: u64) {
    counter!("kron_agent_events_captured_total", "event_type" => event_type.to_owned())
        .increment(count);
}

/// Records events dropped because the ring buffer was full.
pub fn record_events_dropped(count: u64) {
    counter!("kron_agent_events_dropped_total").increment(count);
}

/// Records events successfully sent to the collector in a single batch.
pub fn record_events_sent(count: u64) {
    counter!("kron_agent_events_sent_total").increment(count);
}

/// Records events written to the disk buffer (collector was unreachable).
pub fn record_events_buffered(count: u64) {
    counter!("kron_agent_events_buffered_total").increment(count);
}

/// Records the latency of a single batch send round-trip in milliseconds.
pub fn record_send_latency_ms(latency_ms: f64) {
    histogram!("kron_agent_send_latency_ms").record(latency_ms);
}

/// Sets the current ring buffer utilization as a fraction in [0.0, 1.0].
#[allow(dead_code)]
pub fn set_ring_buffer_utilization(fraction: f64) {
    gauge!("kron_agent_ring_buffer_utilization").set(fraction);
}

/// Sets the number of bytes currently held in the disk buffer.
pub fn set_disk_buffer_bytes(bytes: u64) {
    #[allow(clippy::cast_precision_loss)]
    gauge!("kron_agent_disk_buffer_bytes").set(bytes as f64);
}

/// Records the number of events in a batch that was sent to the collector.
pub fn record_batch_size(size: usize) {
    #[allow(clippy::cast_precision_loss)]
    histogram!("kron_agent_batch_size").record(size as f64);
}

/// Sets collector connectivity status.
///
/// `connected = true` sets the gauge to 1.0; false sets it to 0.0.
pub fn set_collector_connected(connected: bool) {
    gauge!("kron_agent_collector_connected").set(if connected { 1.0 } else { 0.0 });
}

/// Increments the heartbeat failure counter.
pub fn record_heartbeat_failure() {
    counter!("kron_agent_heartbeat_failures_total").increment(1);
}
