//! Prometheus metrics for the KRON message bus.
//!
//! All metrics use the `kron_bus_` prefix and are labeled by topic and (where
//! applicable) consumer group. The `metrics` crate is used as a façade;
//! the Prometheus exporter is configured in the binary crates.

use metrics::{counter, gauge, histogram};

/// Records a single message successfully sent to a topic.
pub fn record_message_sent(topic: &str) {
    counter!("kron_bus_messages_sent_total", "topic" => topic.to_owned()).increment(1);
}

/// Records `count` messages sent in a single batch.
pub fn record_batch_sent(topic: &str, count: u64) {
    counter!("kron_bus_messages_sent_total", "topic" => topic.to_owned()).increment(count);
}

/// Records a message successfully delivered to a consumer.
pub fn record_message_received(topic: &str, group_id: &str) {
    counter!(
        "kron_bus_messages_received_total",
        "topic" => topic.to_owned(),
        "group_id" => group_id.to_owned()
    )
    .increment(1);
}

/// Records a successful offset commit by a consumer.
pub fn record_commit(topic: &str, group_id: &str) {
    counter!(
        "kron_bus_commits_total",
        "topic" => topic.to_owned(),
        "group_id" => group_id.to_owned()
    )
    .increment(1);
}

/// Records a nack (failed processing) by a consumer.
pub fn record_nack(topic: &str, group_id: &str) {
    counter!(
        "kron_bus_nacks_total",
        "topic" => topic.to_owned(),
        "group_id" => group_id.to_owned()
    )
    .increment(1);
}

/// Records a message being moved to the dead letter queue.
pub fn record_dead_letter(source_topic: &str) {
    counter!(
        "kron_bus_dead_letter_total",
        "source_topic" => source_topic.to_owned()
    )
    .increment(1);
}

/// Updates the consumer lag gauge (messages behind the producer).
///
/// This should be updated after every commit and on consumer startup.
pub fn set_consumer_lag(topic: &str, group_id: &str, lag: u64) {
    // Precision loss is acceptable: gauge display does not require exact integer precision.
    #[allow(clippy::cast_precision_loss)]
    let lag_f64 = lag as f64;
    gauge!(
        "kron_bus_consumer_lag_messages",
        "topic" => topic.to_owned(),
        "group_id" => group_id.to_owned()
    )
    .set(lag_f64);
}

/// Records how long (in milliseconds) a producer send operation took end-to-end.
pub fn record_send_latency_ms(topic: &str, ms: f64) {
    histogram!(
        "kron_bus_send_latency_ms",
        "topic" => topic.to_owned()
    )
    .record(ms);
}

/// Records how long (in milliseconds) a consumer held a message before committing.
pub fn record_processing_latency_ms(topic: &str, group_id: &str, ms: f64) {
    histogram!(
        "kron_bus_processing_latency_ms",
        "topic" => topic.to_owned(),
        "group_id" => group_id.to_owned()
    )
    .record(ms);
}
