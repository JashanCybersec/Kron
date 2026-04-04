//! Circuit breaker and retry logic for `ClickHouse` operations.
//!
//! The circuit breaker prevents hammering a down `ClickHouse` cluster.
//! It opens after `threshold` consecutive failures and allows a test
//! request after `recovery_secs` seconds (half-open state).

use kron_types::KronError;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::traits::StorageResult;

/// Simple atomic circuit breaker.
///
/// States:
/// - **Closed** (normal): `failure_count < threshold`.
/// - **Open**: failures exceeded threshold and recovery window not elapsed.
/// - **Half-open**: recovery window elapsed — allows one test request through.
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    last_failure_ts_secs: AtomicU64,
    threshold: u32,
    recovery_secs: u64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// # Arguments
    /// * `threshold` - Consecutive failures before opening.
    /// * `recovery_secs` - Seconds after last failure before half-open.
    pub fn new(threshold: u32, recovery_secs: u64) -> Self {
        Self {
            failure_count: AtomicU32::new(0),
            last_failure_ts_secs: AtomicU64::new(0),
            threshold,
            recovery_secs,
        }
    }

    /// Returns `true` if the circuit is open (requests should be rejected).
    pub fn is_open(&self) -> bool {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.threshold {
            return false;
        }
        let last = self.last_failure_ts_secs.load(Ordering::Relaxed);
        now_secs().saturating_sub(last) < self.recovery_secs
    }

    /// Record a failed operation.
    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        self.last_failure_ts_secs
            .store(now_secs(), Ordering::Relaxed);
    }

    /// Record a successful operation — resets the failure counter.
    pub fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
    }
}

/// Returns the current Unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Returns `true` if a `clickhouse::error::Error` is likely transient.
///
/// Transient errors: network failures, 503 Service Unavailable, connection timeouts.
/// Non-transient: schema errors, wrong column types, authentication failures.
pub fn ch_error_is_transient(err: &clickhouse::error::Error) -> bool {
    use clickhouse::error::Error;
    if let Error::Network(_) = err {
        return true;
    }
    let msg = err.to_string();
    msg.contains("503")
        || msg.contains("Connection refused")
        || msg.contains("timed out")
        || msg.contains("reset by peer")
}

/// Convert a `clickhouse::error::Error` to `KronError::Storage`.
pub fn ch_to_kron(err: &clickhouse::error::Error) -> KronError {
    KronError::Storage(format!("ClickHouse error: {err}"))
}

/// Execute an async operation with exponential backoff retry and circuit breaker.
///
/// # Arguments
/// * `cb` - Circuit breaker instance.
/// * `max_retries` - Number of additional attempts after the first failure.
/// * `base_delay_ms` - Initial backoff delay; doubles each retry, capped at 30 s.
/// * `op_name` - Human-readable name for logging.
/// * `make_fut` - Closure that produces a new future for each attempt.
///
/// # Errors
/// Returns `KronError::Storage("circuit breaker open")` if the circuit is open.
/// Returns the last error if all retries are exhausted.
pub async fn with_ch_retry<F, Fut, T>(
    cb: &CircuitBreaker,
    max_retries: u32,
    base_delay_ms: u64,
    op_name: &str,
    mut make_fut: F,
) -> StorageResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, clickhouse::error::Error>>,
{
    if cb.is_open() {
        metrics::counter!("kron_storage_circuit_breaker_open_total",
            "backend" => "clickhouse"
        )
        .increment(1);
        return Err(KronError::Storage(
            "ClickHouse circuit breaker open: storage unavailable".to_string(),
        ));
    }

    let mut delay_ms = base_delay_ms;

    for attempt in 0..=max_retries {
        match make_fut().await {
            Ok(result) => {
                cb.record_success();
                return Ok(result);
            }
            Err(e) if ch_error_is_transient(&e) && attempt < max_retries => {
                cb.record_failure();
                metrics::counter!("kron_storage_clickhouse_retry_total",
                    "operation" => op_name.to_string()
                )
                .increment(1);
                warn!(
                    attempt,
                    delay_ms,
                    operation = op_name,
                    error = %e,
                    "Transient ClickHouse error, retrying with backoff"
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = (delay_ms * 2).min(30_000);
            }
            Err(e) => {
                cb.record_failure();
                metrics::counter!("kron_storage_clickhouse_error_total",
                    "operation" => op_name.to_string()
                )
                .increment(1);
                tracing::error!(
                    operation = op_name,
                    error = %e,
                    "ClickHouse operation failed"
                );
                return Err(ch_to_kron(&e));
            }
        }
    }

    // Unreachable: the loop either returns Ok or Err before exhausting retries.
    Err(KronError::Storage(format!(
        "{op_name}: all {max_retries} retries exhausted"
    )))
}
