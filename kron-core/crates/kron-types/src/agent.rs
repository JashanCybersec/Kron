//! Agent ↔ Collector wire-protocol types.
//!
//! Shared by `kron-agent` (sender) and `kron-collector` (receiver).
//! Serialized as JSON over gRPC using a custom [`tonic::codec::Codec`].
//!
//! # Service definition (conceptual)
//!
//! ```text
//! service CollectorService {
//!     rpc Register(RegisterRequest)    -> RegisterResponse
//!     rpc SendEvents(EventBatch)       -> EventAck
//!     rpc Heartbeat(HeartbeatRequest)  -> HeartbeatResponse
//! }
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::KronEvent;
use crate::ids::AgentId;

// ─── Registration ─────────────────────────────────────────────────────────────

/// Sent by the agent on first startup to register with the collector.
///
/// The collector validates the mTLS client certificate and stores the
/// agent record. On success it returns an [`AgentId`] that is reused
/// on every subsequent connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// FQDN or short hostname of the agent host.
    pub hostname: String,
    /// Semantic version of the kron-agent binary.
    pub agent_version: String,
    /// Linux kernel version string (e.g. `"5.15.0-91-generic"`).
    pub kernel_version: String,
    /// OS distribution string (e.g. `"Ubuntu 22.04.3 LTS"`).
    pub os_name: String,
    /// Primary IPv4 address of the host (dotted-decimal string).
    pub host_ip: String,
    /// Arbitrary key=value labels configured in `agent.toml`.
    pub labels: std::collections::HashMap<String, String>,
}

/// Returned by the collector after successful agent registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Stable agent identifier assigned by the collector.
    pub agent_id: AgentId,
    /// Collector-assigned tenant for this agent's events.
    pub tenant_id: crate::ids::TenantId,
    /// UTC timestamp at which this registration was recorded.
    pub registered_at: DateTime<Utc>,
}

// ─── Event batch ──────────────────────────────────────────────────────────────

/// A batch of events sent from the agent to the collector.
///
/// The agent accumulates events until either `max_batch_size` or
/// `max_batch_delay_ms` is reached, then flushes as a single `EventBatch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    /// Stable agent identifier (from [`RegisterResponse`]).
    pub agent_id: AgentId,
    /// Monotonically-increasing sequence number for this agent session.
    /// Used by the collector to detect missed batches.
    pub sequence: u64,
    /// Events in this batch. Length is bounded by `AgentConfig.max_batch_size`.
    pub events: Vec<KronEvent>,
    /// UTC timestamp when this batch was assembled by the agent.
    pub assembled_at: DateTime<Utc>,
}

/// Acknowledgement returned by the collector after processing an [`EventBatch`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAck {
    /// Echo of the sequence number from the corresponding [`EventBatch`].
    pub sequence: u64,
    /// Number of events the collector accepted and enqueued.
    pub accepted: u32,
    /// Number of events rejected (schema validation failures, etc.).
    pub rejected: u32,
}

// ─── Heartbeat ────────────────────────────────────────────────────────────────

/// Periodic liveness signal sent from agent to collector every 30 s.
///
/// The collector marks an agent "dark" if no heartbeat is received for 90 s
/// (3× the heartbeat interval).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// Stable agent identifier.
    pub agent_id: AgentId,
    /// UTC timestamp on the agent host at the time of send.
    pub sent_at: DateTime<Utc>,
    /// Ring buffer utilization 0–100 (percent of 64 MB used).
    pub ring_buffer_utilization_pct: u8,
    /// Number of events dropped (ring buffer full) since the last heartbeat.
    pub events_dropped_since_last: u64,
    /// Number of events currently buffered on disk (not yet sent).
    pub disk_buffer_depth: u64,
}

/// Returned by the collector to acknowledge a heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// UTC timestamp on the collector host — allows the agent to detect
    /// large clock skew and emit a warning.
    pub collector_at: DateTime<Utc>,
}
