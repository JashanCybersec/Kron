//! Collector transport layer.
//!
//! Abstracts the agent→collector communication behind a [`CollectorTransport`]
//! trait so that the main agent loop does not depend on specific protocols.
//!
//! # Provided implementations
//!
//! - [`grpc::GrpcTransport`] — gRPC over mTLS, used in all deployment tiers.

pub mod codec;
pub mod grpc;

use async_trait::async_trait;

use kron_types::{
    EventAck, EventBatch, HeartbeatRequest, HeartbeatResponse, RegisterRequest, RegisterResponse,
};

use crate::error::AgentError;

/// Transport abstraction for the agent→collector channel.
///
/// Implementors handle connection management, retries, and serialization.
/// The agent core calls these methods and does not concern itself with the
/// underlying protocol.
#[async_trait]
pub trait CollectorTransport: Send + Sync {
    /// Registers this agent with the collector.
    ///
    /// Should be called once on startup (and again after a reconnect if the
    /// agent does not have a persisted [`AgentId`]). The returned [`AgentId`]
    /// must be stored and reused across reconnects.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Registration`] if the collector rejects the
    /// request, or [`AgentError::Transport`] for network-level failures.
    async fn register(&mut self, req: RegisterRequest) -> Result<RegisterResponse, AgentError>;

    /// Sends a batch of events to the collector.
    ///
    /// Returns an [`EventAck`] reporting how many events were accepted and
    /// how many were rejected (schema validation failures, etc.).
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Transport`] on network failures. The caller
    /// should route the batch to the disk buffer on error.
    async fn send_events(&mut self, batch: EventBatch) -> Result<EventAck, AgentError>;

    /// Sends a liveness heartbeat to the collector.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Heartbeat`] on failure. The caller should
    /// increment the heartbeat failure counter and continue operating;
    /// a failed heartbeat does not require disk-buffering of events.
    async fn heartbeat(&mut self, req: HeartbeatRequest) -> Result<HeartbeatResponse, AgentError>;

    /// Returns `true` if the transport currently has an active connection to
    /// the collector. Used by the agent to decide whether to buffer or send.
    fn is_connected(&self) -> bool;
}

/// The gRPC service path prefix used for all collector RPCs.
#[allow(dead_code)]
pub const COLLECTOR_SERVICE_PATH: &str = "/kron.collector.v1.CollectorService";
