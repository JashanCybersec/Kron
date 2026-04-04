//! gRPC service implementation for `kron.collector.v1.CollectorService`.
//!
//! Handles three unary RPCs from `kron-agent`:
//!
//! | RPC | Path | Description |
//! |---|---|---|
//! | `Register` | `/kron.collector.v1.CollectorService/Register` | Agent first-boot registration |
//! | `SendEvents` | `/kron.collector.v1.CollectorService/SendEvents` | Event batch ingestion |
//! | `Heartbeat` | `/kron.collector.v1.CollectorService/Heartbeat` | Liveness signal |
//!
//! The service is implemented as a `tower::Service` that routes by request path
//! and dispatches to per-RPC [`tonic::server::UnaryService`] implementations.
//! This avoids `protoc` and generated code while remaining fully gRPC-compliant.
//!
//! # mTLS
//!
//! The transport layer (configured in [`crate::collector`]) requires a valid
//! client certificate. Tenant ID is read from the `tenant_id` label in the
//! [`RegisterRequest`], falling back to the configured `default_tenant_id`.

use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use chrono::Utc;
use http_body::Body;
use kron_types::{
    AgentId, EventAck, EventBatch, HeartbeatRequest, HeartbeatResponse, RegisterRequest,
    RegisterResponse, TenantId,
};
use tokio::sync::RwLock;
use tonic::body::BoxBody;
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic::{Request, Response, Status};

use crate::codec::{EventBatchCodec, HeartbeatCodec, RegisterCodec};
use crate::metrics;
use crate::registry::AgentRegistry;

// ─── Shared state ────────────────────────────────────────────────────────────

/// State shared across all gRPC handlers.
pub struct GrpcState {
    /// Agent registry — holds all registered agents and their metadata.
    pub registry: Arc<RwLock<AgentRegistry>>,
    /// Message bus producer — publishes raw events to `kron.raw.{tenant_id}`.
    pub producer: Arc<dyn kron_bus::traits::BusProducer>,
    /// Fallback tenant UUID string used when the agent does not supply one.
    pub default_tenant_id: String,
}

// ─── Service implementation ───────────────────────────────────────────────────

/// `tower::Service` that routes gRPC requests to the correct RPC handler.
///
/// This struct is the entry point for `tonic::transport::Server`.
#[derive(Clone)]
pub struct CollectorGrpcService {
    state: Arc<GrpcState>,
}

impl CollectorGrpcService {
    /// Creates a new service wrapping the given shared state.
    #[must_use]
    pub fn new(state: Arc<GrpcState>) -> Self {
        Self { state }
    }
}

impl NamedService for CollectorGrpcService {
    const NAME: &'static str = "kron.collector.v1.CollectorService";
}

impl<B> tower::Service<http::Request<B>> for CollectorGrpcService
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    type Response = http::Response<BoxBody>;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let state = Arc::clone(&self.state);
        let path = req.uri().path().to_owned();

        Box::pin(async move {
            let resp = match path.as_str() {
                "/kron.collector.v1.CollectorService/Register" => {
                    let mut grpc = Grpc::new(RegisterCodec::new());
                    let svc = RegisterSvc(Arc::clone(&state));
                    grpc.unary(svc, req).await
                }
                "/kron.collector.v1.CollectorService/SendEvents" => {
                    let mut grpc = Grpc::new(EventBatchCodec::new());
                    let svc = SendEventsSvc(Arc::clone(&state));
                    grpc.unary(svc, req).await
                }
                "/kron.collector.v1.CollectorService/Heartbeat" => {
                    let mut grpc = Grpc::new(HeartbeatCodec::new());
                    let svc = HeartbeatSvc(Arc::clone(&state));
                    grpc.unary(svc, req).await
                }
                _ => unimplemented_response(),
            };
            Ok(resp)
        })
    }
}

/// Returns an `UNIMPLEMENTED` gRPC response for unknown paths.
fn unimplemented_response() -> http::Response<BoxBody> {
    http::Response::builder()
        .status(http::StatusCode::OK)
        .header("grpc-status", "12") // UNIMPLEMENTED
        .header("content-type", "application/grpc")
        .body(tonic::body::empty_body())
        .unwrap_or_else(|_| http::Response::new(tonic::body::empty_body()))
}

// ─── Register RPC ────────────────────────────────────────────────────────────

/// Handler for the `Register` unary RPC.
struct RegisterSvc(Arc<GrpcState>);

impl UnaryService<RegisterRequest> for RegisterSvc {
    type Response = RegisterResponse;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send + 'static>>;

    fn call(&mut self, req: Request<RegisterRequest>) -> Self::Future {
        let state = Arc::clone(&self.0);
        Box::pin(async move {
            let inner = req.into_inner();

            let tenant_id = resolve_tenant_id(&inner, &state.default_tenant_id)
                .map_err(Status::invalid_argument)?;

            let (agent_id, is_new) = state.registry.write().await.register(&inner, tenant_id);

            if is_new {
                metrics::record_agent_registration();
                tracing::info!(
                    agent_id = %agent_id,
                    tenant_id = %tenant_id,
                    hostname = %inner.hostname,
                    host_ip = %inner.host_ip,
                    agent_version = %inner.agent_version,
                    "Agent registered"
                );
            } else {
                tracing::debug!(
                    agent_id = %agent_id,
                    hostname = %inner.hostname,
                    "Agent re-registered (idempotent)"
                );
            }

            let active = state.registry.read().await.active_count();
            metrics::set_active_agents(active);

            Ok(Response::new(RegisterResponse {
                agent_id,
                tenant_id,
                registered_at: Utc::now(),
            }))
        })
    }
}

// ─── SendEvents RPC ──────────────────────────────────────────────────────────

/// Handler for the `SendEvents` unary RPC.
struct SendEventsSvc(Arc<GrpcState>);

impl UnaryService<EventBatch> for SendEventsSvc {
    type Response = EventAck;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send + 'static>>;

    fn call(&mut self, req: Request<EventBatch>) -> Self::Future {
        let state = Arc::clone(&self.0);
        Box::pin(async move {
            let batch = req.into_inner();
            let agent_id = batch.agent_id;
            let sequence = batch.sequence;
            let event_count = batch.events.len();

            // Look up tenant and validate agent is known.
            let tenant_id = {
                let reg = state.registry.read().await;
                reg.tenant_id(&agent_id).ok_or_else(|| {
                    tracing::warn!(
                        agent_id = %agent_id,
                        "SendEvents from unregistered agent"
                    );
                    Status::unauthenticated("agent not registered")
                })?
            };

            // Rate limit check.
            let event_count_u32 = u32::try_from(event_count).unwrap_or(u32::MAX);
            let allowed = state
                .registry
                .write()
                .await
                .check_rate_limit(&agent_id, event_count_u32);
            if !allowed {
                metrics::record_rate_limited(event_count as u64);
                metrics::record_events_rejected("rate_limit", event_count as u64);
                tracing::warn!(
                    agent_id = %agent_id,
                    event_count,
                    "Agent exceeded EPS rate limit; batch rejected"
                );
                return Ok(Response::new(EventAck {
                    sequence,
                    accepted: 0,
                    rejected: event_count_u32,
                }));
            }

            // Update sequence tracking (warn on gaps but still accept).
            state
                .registry
                .write()
                .await
                .update_sequence(&agent_id, sequence);

            metrics::record_events_received("grpc", event_count as u64);
            metrics::record_batch_size(event_count);

            // Publish each event to `kron.raw.{tenant_id}`.
            let topic = kron_bus::topics::raw_events(&tenant_id);
            let mut accepted: u32 = 0;
            let mut rejected: u32 = 0;

            let start = std::time::Instant::now();
            for event in batch.events {
                match publish_event(&state.producer, &topic, &event).await {
                    Ok(()) => accepted += 1,
                    Err(e) => {
                        tracing::error!(
                            agent_id = %agent_id,
                            event_id = %event.event_id,
                            error = %e,
                            "Failed to publish event to bus"
                        );
                        rejected += 1;
                    }
                }
            }

            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            metrics::record_publish_latency_ms(elapsed_ms);
            metrics::record_events_published(u64::from(accepted));
            if rejected > 0 {
                metrics::record_events_rejected("bus_error", u64::from(rejected));
            }

            tracing::debug!(
                agent_id = %agent_id,
                tenant_id = %tenant_id,
                sequence,
                accepted,
                rejected,
                elapsed_ms,
                "Batch processed"
            );

            Ok(Response::new(EventAck {
                sequence,
                accepted,
                rejected,
            }))
        })
    }
}

// ─── Heartbeat RPC ───────────────────────────────────────────────────────────

/// Handler for the `Heartbeat` unary RPC.
struct HeartbeatSvc(Arc<GrpcState>);

impl UnaryService<HeartbeatRequest> for HeartbeatSvc {
    type Response = HeartbeatResponse;
    type Future =
        Pin<Box<dyn Future<Output = Result<Response<Self::Response>, Status>> + Send + 'static>>;

    fn call(&mut self, req: Request<HeartbeatRequest>) -> Self::Future {
        let state = Arc::clone(&self.0);
        Box::pin(async move {
            let hb = req.into_inner();
            let agent_id: AgentId = hb.agent_id;

            let found = state.registry.write().await.record_heartbeat(agent_id);
            if !found {
                tracing::warn!(
                    agent_id = %agent_id,
                    "Heartbeat from unregistered agent"
                );
                return Err(Status::not_found("agent not registered"));
            }

            metrics::record_heartbeat();

            tracing::debug!(
                agent_id = %agent_id,
                ring_buffer_utilization_pct = hb.ring_buffer_utilization_pct,
                events_dropped = hb.events_dropped_since_last,
                disk_buffer_depth = hb.disk_buffer_depth,
                "Heartbeat received"
            );

            Ok(Response::new(HeartbeatResponse {
                collector_at: Utc::now(),
            }))
        })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Resolves the tenant ID from the agent's labels or the collector default.
///
/// Agents include `tenant_id` in their labels map (set in `agent.toml`).
/// If absent, the collector's `default_tenant_id` is used.
fn resolve_tenant_id(req: &RegisterRequest, default: &str) -> Result<TenantId, String> {
    let raw = req.labels.get("tenant_id").map_or(default, String::as_str);

    if raw.is_empty() {
        return Err("tenant_id is required: set labels.tenant_id in agent.toml \
             or default_tenant_id in collector config"
            .to_owned());
    }

    uuid::Uuid::from_str(raw)
        .map(TenantId::from_uuid)
        .map_err(|e| format!("invalid tenant_id UUID '{raw}': {e}"))
}

/// Serialises a single [`kron_types::KronEvent`] to JSON and publishes it to the bus.
async fn publish_event(
    producer: &Arc<dyn kron_bus::traits::BusProducer>,
    topic: &str,
    event: &kron_types::KronEvent,
) -> Result<(), kron_bus::error::BusError> {
    let payload = serde_json::to_vec(event)
        .map(bytes::Bytes::from)
        .map_err(|e| kron_bus::error::BusError::Serialization(e.to_string()))?;

    let key = bytes::Bytes::from(event.tenant_id.to_string());
    producer
        .send(topic, Some(key), payload, std::collections::HashMap::new())
        .await?;
    Ok(())
}
