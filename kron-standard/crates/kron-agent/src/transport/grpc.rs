//! gRPC mTLS transport to the collector service.
//!
//! Uses `tonic` with a custom JSON codec (no protoc, no generated code).
//! mTLS is configured via `rustls` with the agent's client certificate and the
//! collector's CA certificate.
//!
//! # Connection lifecycle
//!
//! 1. [`GrpcTransport::connect`] builds a `tonic::transport::Channel` with mTLS.
//! 2. The channel is wrapped in `tonic::client::Grpc` and reused for all RPCs.
//! 3. If any RPC returns a transport-level error, [`is_connected`] returns `false`
//!    and the agent falls back to the disk buffer until [`reconnect`] succeeds.

use std::path::Path;

use async_trait::async_trait;
use http::uri::PathAndQuery;
use tonic::client::Grpc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::Request;

use kron_types::{
    EventAck, EventBatch, HeartbeatRequest, HeartbeatResponse, RegisterRequest, RegisterResponse,
};

use super::codec::{EventBatchCodec, HeartbeatCodec, RegisterCodec};
use super::CollectorTransport;
use crate::config::AgentConfig;
use crate::error::AgentError;

/// gRPC transport to the `kron-collector` service over mTLS.
pub struct GrpcTransport {
    client: Grpc<Channel>,
    connected: bool,
    endpoint: String,
    /// Stored for use by [`reconnect`] to re-establish the mTLS channel.
    #[allow(dead_code)]
    identity: Identity,
    /// Stored for use by [`reconnect`] to re-establish the mTLS channel.
    #[allow(dead_code)]
    ca_cert: Certificate,
}

impl GrpcTransport {
    /// Creates a new [`GrpcTransport`] and establishes the initial mTLS connection.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Tls`] if the certificates cannot be read.
    /// Returns [`AgentError::Transport`] if the connection cannot be established.
    pub async fn connect(config: &AgentConfig) -> Result<Self, AgentError> {
        let identity = load_identity(&config.cert_path, &config.key_path)?;
        let ca_cert = load_ca_cert(&config.ca_path)?;
        let client = build_channel(
            &config.collector_endpoint,
            identity.clone(),
            ca_cert.clone(),
        )
        .await?;

        tracing::info!(
            endpoint = %config.collector_endpoint,
            "gRPC mTLS transport connected"
        );

        Ok(Self {
            client,
            connected: true,
            endpoint: config.collector_endpoint.clone(),
            identity,
            ca_cert,
        })
    }

    /// Attempts to re-establish the gRPC channel after a disconnection.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Transport`] if the reconnect fails.
    #[allow(dead_code)]
    pub async fn reconnect(&mut self) -> Result<(), AgentError> {
        self.client =
            build_channel(&self.endpoint, self.identity.clone(), self.ca_cert.clone()).await?;
        self.connected = true;
        tracing::info!(endpoint = %self.endpoint, "gRPC transport reconnected");
        Ok(())
    }

    fn mark_disconnected(&mut self, error: &str) {
        if self.connected {
            tracing::warn!(endpoint = %self.endpoint, error, "gRPC transport disconnected");
        }
        self.connected = false;
    }
}

#[async_trait]
impl CollectorTransport for GrpcTransport {
    async fn register(&mut self, req: RegisterRequest) -> Result<RegisterResponse, AgentError> {
        let path: PathAndQuery = "/kron.collector.v1.CollectorService/Register"
            .parse()
            .map_err(|e| AgentError::Transport(format!("invalid path: {e}")))?;

        let response = self
            .client
            .unary(Request::new(req), path, RegisterCodec::new())
            .await
            .map_err(|e| {
                self.mark_disconnected(&e.to_string());
                AgentError::Registration(e.to_string())
            })?;

        self.connected = true;
        Ok(response.into_inner())
    }

    async fn send_events(&mut self, batch: EventBatch) -> Result<EventAck, AgentError> {
        let path: PathAndQuery = "/kron.collector.v1.CollectorService/SendEvents"
            .parse()
            .map_err(|e| AgentError::Transport(format!("invalid path: {e}")))?;

        let response = self
            .client
            .unary(Request::new(batch), path, EventBatchCodec::new())
            .await
            .map_err(|e| {
                self.mark_disconnected(&e.to_string());
                AgentError::Transport(format!("send_events RPC failed: {e}"))
            })?;

        self.connected = true;
        Ok(response.into_inner())
    }

    async fn heartbeat(&mut self, req: HeartbeatRequest) -> Result<HeartbeatResponse, AgentError> {
        let path: PathAndQuery = "/kron.collector.v1.CollectorService/Heartbeat"
            .parse()
            .map_err(|e| AgentError::Transport(format!("invalid path: {e}")))?;

        let response = self
            .client
            .unary(Request::new(req), path, HeartbeatCodec::new())
            .await
            .map_err(|e| {
                // Heartbeat failures don't flip connected=false — the event
                // pipeline might still work even if the heartbeat RPC times out.
                tracing::warn!(error = %e, "Heartbeat RPC failed");
                AgentError::Heartbeat(e.to_string())
            })?;

        Ok(response.into_inner())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

// ─── TLS helpers ─────────────────────────────────────────────────────────────

/// Loads the agent's mTLS identity from PEM files.
///
/// # Errors
///
/// Returns [`AgentError::Tls`] if either file cannot be read.
fn load_identity(cert_path: &Path, key_path: &Path) -> Result<Identity, AgentError> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| AgentError::Tls(format!("cannot read cert {}: {e}", cert_path.display())))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| AgentError::Tls(format!("cannot read key {}: {e}", key_path.display())))?;
    Ok(Identity::from_pem(cert_pem, key_pem))
}

/// Loads the CA certificate for collector verification from a PEM file.
///
/// # Errors
///
/// Returns [`AgentError::Tls`] if the file cannot be read.
fn load_ca_cert(ca_path: &Path) -> Result<Certificate, AgentError> {
    let ca_pem = std::fs::read(ca_path)
        .map_err(|e| AgentError::Tls(format!("cannot read CA cert {}: {e}", ca_path.display())))?;
    Ok(Certificate::from_pem(ca_pem))
}

/// Builds a `tonic::transport::Channel` with mTLS configuration.
///
/// # Errors
///
/// Returns [`AgentError::Transport`] if the URI is invalid or TLS fails.
async fn build_channel(
    endpoint: &str,
    identity: Identity,
    ca_cert: Certificate,
) -> Result<Grpc<Channel>, AgentError> {
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity);

    let channel = Channel::from_shared(endpoint.to_owned())
        .map_err(|e| {
            AgentError::Transport(format!("invalid collector endpoint '{endpoint}': {e}"))
        })?
        .tls_config(tls_config)
        .map_err(|e| AgentError::Transport(format!("TLS config error: {e}")))?
        .connect()
        .await
        .map_err(|e| {
            AgentError::Transport(format!("cannot connect to collector '{endpoint}': {e}"))
        })?;

    Ok(Grpc::new(channel))
}
