//! Agent-specific error type.
//!
//! All fallible operations in `kron-agent` return [`AgentError`].
//! Every variant carries enough context for structured logging.

use thiserror::Error;

/// Errors produced by the kron-agent process.
#[derive(Debug, Error)]
pub enum AgentError {
    /// Configuration file could not be read or parsed.
    #[error("config error: {0}")]
    Config(String),

    /// An eBPF program could not be loaded or attached.
    ///
    /// Only emitted on Linux; gated by `#[cfg(target_os = "linux")]`.
    #[error("eBPF error: {0}")]
    #[allow(dead_code)]
    Ebpf(String),

    /// The eBPF ring buffer produced a record that could not be decoded.
    #[error("ring buffer decode error: {0}")]
    #[allow(dead_code)]
    RingBufferDecode(String),

    /// The collector gRPC endpoint is unreachable or returned an error.
    #[error("transport error: {0}")]
    Transport(String),

    /// The mTLS certificate or key could not be loaded.
    #[error("TLS error: {0}")]
    Tls(String),

    /// The local disk buffer failed during a read, write, or compaction.
    #[error("disk buffer error: {0}")]
    Buffer(String),

    /// A heartbeat send to the collector failed.
    #[error("heartbeat error: {0}")]
    Heartbeat(String),

    /// Agent registration with the collector failed.
    #[error("registration error: {0}")]
    Registration(String),

    /// The running kernel is below the minimum supported version (5.4).
    ///
    /// The agent logs a warning and recommends agentless collection.
    #[error("unsupported kernel {running}: minimum required is {minimum}")]
    #[allow(dead_code)]
    KernelTooOld {
        /// Detected kernel version string.
        running: String,
        /// Minimum required version string.
        minimum: String,
    },

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A tokio task panicked or was cancelled.
    #[error("task error: {0}")]
    Task(String),
}
