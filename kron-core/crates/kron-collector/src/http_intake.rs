//! HTTP intake server for `kron-collector`.
//!
//! Exposes three route groups over an Axum HTTP server:
//!
//! ## Event intake
//! - `POST /intake/v1/events` — bulk JSON event ingestion (Bearer auth)
//!
//! ## Agent management (admin API)
//! - `POST /agents/register` — pre-register an agent and receive a token
//! - `POST /agents/heartbeat` — HTTP-based heartbeat for non-gRPC agents
//! - `GET  /agents` — list all registered agents and their status
//!
//! ## Health
//! - `GET /health` — liveness probe (returns 200 `{"status":"ok"}`)
//!
//! # Auth
//!
//! `POST /intake/v1/events` requires an `Authorization: Bearer <token>` header.
//! The token is compared against `CollectorConfig.intake_auth_token`.
//! Phase 3 replaces this with a per-tenant token registry.
//! // TODO(#TBD, hardik, phase-3): Per-tenant token registry for HTTP intake auth

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use chrono::Utc;
use kron_types::{AgentId, EventId, KronEvent, TenantId};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::metrics;
use crate::registry::AgentRegistry;

// ─── App state ────────────────────────────────────────────────────────────────

/// Shared state injected into every Axum handler.
#[derive(Clone)]
pub struct HttpState {
    /// Agent registry — for agent management endpoints.
    pub registry: Arc<RwLock<AgentRegistry>>,
    /// Bus producer — for event intake.
    pub producer: Arc<dyn kron_bus::traits::BusProducer>,
    /// Pre-shared Bearer token for `POST /intake/v1/events`.
    pub intake_auth_token: String,
    /// Tenant UUID assigned to all HTTP intake events (Phase 1.5).
    pub default_tenant_id: String,
}

// ─── HTTP server ──────────────────────────────────────────────────────────────

/// Runs the Axum HTTP server until a shutdown signal is received.
///
/// # Errors
///
/// Returns [`crate::error::CollectorError::Http`] if the listener cannot be bound
/// or the server exits with an error.
pub async fn run_http_server(
    bind_addr: SocketAddr,
    state: HttpState,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<(), crate::error::CollectorError> {
    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| crate::error::CollectorError::Http(format!("bind {bind_addr}: {e}")))?;

    tracing::info!(addr = %bind_addr, "HTTP intake server started");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
            tracing::info!("HTTP intake server shutting down");
        })
        .await
        .map_err(|e| crate::error::CollectorError::Http(e.to_string()))
}

/// Builds the Axum router with all routes and shared state.
fn build_router(state: HttpState) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/intake/v1/events", post(handle_intake_events))
        .route("/agents/register", post(handle_agent_register))
        .route("/agents/heartbeat", post(handle_agent_heartbeat))
        .route("/agents", get(handle_agents_list))
        .with_state(state)
}

// ─── Health ───────────────────────────────────────────────────────────────────

/// `GET /health` — liveness probe.
async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

// ─── Event intake ─────────────────────────────────────────────────────────────

/// `POST /intake/v1/events` — bulk event ingestion.
///
/// Accepts a JSON array of [`KronEvent`] objects. Each event is validated,
/// tagged with the default tenant ID, and published to `kron.raw.{tenant_id}`.
///
/// Requires `Authorization: Bearer <intake_auth_token>`.
async fn handle_intake_events(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(events): Json<Vec<KronEvent>>,
) -> impl IntoResponse {
    if let Err(resp) = verify_bearer(&headers, &state.intake_auth_token) {
        return resp;
    }

    let tenant_id = match parse_tenant_id_str(&state.default_tenant_id) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "HTTP intake: invalid default_tenant_id in config");
            return (StatusCode::INTERNAL_SERVER_ERROR, "misconfigured tenant").into_response();
        }
    };

    let count = events.len();
    metrics::record_events_received("http", count as u64);

    let topic = kron_bus::topics::raw_events(&tenant_id);
    let mut accepted = 0u64;
    let mut rejected = 0u64;

    for mut event in events {
        // Ensure tenant_id is correctly stamped.
        event.tenant_id = tenant_id;
        // Always assign a fresh EventId to avoid collisions from the sender.
        event.event_id = EventId::from_uuid(Uuid::new_v4());

        let payload = match serde_json::to_vec(&event) {
            Ok(v) => Bytes::from(v),
            Err(e) => {
                tracing::warn!(error = %e, "HTTP intake: event serialisation failed; skipped");
                rejected += 1;
                continue;
            }
        };

        let key = Bytes::from(tenant_id.to_string());
        match state
            .producer
            .send(&topic, Some(key), payload, std::collections::HashMap::new())
            .await
        {
            Ok(_) => accepted += 1,
            Err(e) => {
                tracing::error!(error = %e, "HTTP intake: bus publish failed");
                rejected += 1;
            }
        }
    }

    metrics::record_events_published(accepted);
    if rejected > 0 {
        metrics::record_events_rejected("bus_error", rejected);
    }

    let body = serde_json::json!({
        "accepted": accepted,
        "rejected": rejected,
    });
    (StatusCode::OK, Json(body)).into_response()
}

// ─── Agent management ─────────────────────────────────────────────────────────

/// Request body for `POST /agents/register`.
#[derive(Debug, Deserialize)]
pub struct AgentRegisterRequest {
    /// Hostname of the agent to pre-register.
    pub hostname: String,
    /// Optional tenant UUID; uses `default_tenant_id` if absent.
    pub tenant_id: Option<String>,
}

/// Response body for `POST /agents/register`.
#[derive(Debug, Serialize)]
pub struct AgentRegisterResponse {
    /// Assigned agent identifier.
    pub agent_id: String,
    /// Assigned tenant identifier.
    pub tenant_id: String,
    /// UTC registration timestamp.
    pub registered_at: chrono::DateTime<Utc>,
}

/// `POST /agents/register` — admin endpoint to pre-register an agent.
async fn handle_agent_register(
    State(state): State<HttpState>,
    Json(req): Json<AgentRegisterRequest>,
) -> impl IntoResponse {
    let tenant_id = match req
        .tenant_id
        .as_deref()
        .unwrap_or(&state.default_tenant_id)
        .parse::<uuid::Uuid>()
        .map(TenantId::from_uuid)
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid tenant_id: {e}") })),
            )
                .into_response()
        }
    };

    let grpc_req = kron_types::RegisterRequest {
        hostname: req.hostname,
        agent_version: "pre-registered".to_owned(),
        kernel_version: String::new(),
        os_name: String::new(),
        host_ip: String::new(),
        labels: std::collections::HashMap::new(),
    };

    let (agent_id, is_new) = state.registry.write().await.register(&grpc_req, tenant_id);

    if is_new {
        metrics::record_agent_registration();
    }

    let resp = AgentRegisterResponse {
        agent_id: agent_id.to_string(),
        tenant_id: tenant_id.to_string(),
        registered_at: Utc::now(),
    };

    (StatusCode::OK, Json(resp)).into_response()
}

/// Request body for `POST /agents/heartbeat`.
#[derive(Debug, Deserialize)]
pub struct AgentHeartbeatRequest {
    /// Agent ID to record a heartbeat for.
    pub agent_id: String,
}

/// `POST /agents/heartbeat` — HTTP heartbeat for non-gRPC agents.
async fn handle_agent_heartbeat(
    State(state): State<HttpState>,
    Json(req): Json<AgentHeartbeatRequest>,
) -> impl IntoResponse {
    let agent_id = match req.agent_id.parse::<uuid::Uuid>().map(AgentId::from_uuid) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid agent_id: {e}") })),
            )
                .into_response()
        }
    };

    let found = state.registry.write().await.record_heartbeat(agent_id);
    if !found {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "agent not registered" })),
        )
            .into_response();
    }

    metrics::record_heartbeat();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "collector_at": Utc::now() })),
    )
        .into_response()
}

/// Response item for `GET /agents`.
#[derive(Debug, Serialize)]
pub struct AgentSummary {
    /// Stable agent identifier.
    pub agent_id: String,
    /// Agent's tenant.
    pub tenant_id: String,
    /// FQDN or short hostname.
    pub hostname: String,
    /// Agent binary version.
    pub agent_version: String,
    /// UTC of last heartbeat.
    pub last_heartbeat_at: chrono::DateTime<Utc>,
    /// True if the agent has exceeded the heartbeat timeout.
    pub is_dark: bool,
}

/// `GET /agents` — list all registered agents.
async fn handle_agents_list(State(state): State<HttpState>) -> impl IntoResponse {
    let registry = state.registry.read().await;
    let agents: Vec<AgentSummary> = registry
        .all_agents()
        .map(|r| AgentSummary {
            agent_id: r.agent_id.to_string(),
            tenant_id: r.tenant_id.to_string(),
            hostname: r.hostname.clone(),
            agent_version: r.agent_version.clone(),
            last_heartbeat_at: r.last_heartbeat_at,
            is_dark: r.is_dark,
        })
        .collect();

    Json(agents).into_response()
}

// ─── Auth helper ──────────────────────────────────────────────────────────────

/// Verifies the `Authorization: Bearer <token>` header against the configured token.
///
/// Returns `Ok(())` if the token matches, `Err(response)` with a 401 status otherwise.
#[allow(clippy::result_large_err)]
fn verify_bearer(headers: &HeaderMap, expected: &str) -> Result<(), axum::response::Response> {
    if expected.is_empty() {
        // Auth disabled — no token configured.
        return Ok(());
    }

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if token == expected => Ok(()),
        _ => {
            metrics::record_events_rejected("auth", 1);
            Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid or missing Bearer token" })),
            )
                .into_response())
        }
    }
}

/// Parses a UUID string into a [`TenantId`].
fn parse_tenant_id_str(s: &str) -> Result<TenantId, String> {
    uuid::Uuid::from_str(s)
        .map(TenantId::from_uuid)
        .map_err(|e| format!("invalid UUID '{s}': {e}"))
}
