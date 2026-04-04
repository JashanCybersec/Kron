//! Event query handlers.
//!
//! All handlers require a valid JWT ([`AuthUser`]) and enforce
//! tenant isolation via `AuthUser.tenant_id` — never from the request.
//!
//! # Endpoints
//!
//! - `GET  /api/v1/events`         — paginated event list with filter
//! - `GET  /api/v1/events/{id}`    — single event by ID
//! - `POST /api/v1/events/query`   — natural language query (stub, Phase 3+)

use axum::{
    extract::{Path, Query, State},
    Json,
};
use kron_auth::rbac::{Action, Resource};
use kron_storage::query::EventFilter;
use kron_types::TenantContext;
use serde::{Deserialize, Serialize};
use std::time::Instant;

use kron_storage::StorageEngine;

use crate::{error::ApiError, middleware::AuthUser, state::AppState};

// ── Query / Response types ────────────────────────────────────────────────────

/// Query parameters for `GET /api/v1/events`.
#[derive(Debug, Deserialize)]
pub struct EventQuery {
    /// Start of time range (ISO-8601, required).
    pub from: String,
    /// End of time range (ISO-8601, optional; defaults to now).
    pub to: Option<String>,
    /// Filter by event source type (e.g. `linux_ebpf`, `syslog`).
    pub source_type: Option<String>,
    /// Filter by hostname.
    pub host: Option<String>,
    /// Filter by username.
    pub user: Option<String>,
    /// Filter by event type (e.g. `process_create`).
    pub event_type: Option<String>,
    /// Filter by minimum severity name.
    pub severity: Option<String>,
    /// If `true`, return only events with IOC hits.
    pub ioc_hit: Option<bool>,
    /// Maximum rows to return (1–10 000, default 100).
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// Response for event list queries.
#[derive(Debug, Serialize)]
pub struct EventListResponse {
    /// Total matching events (before limit/offset, if known).
    pub total: u64,
    /// The events in this page, serialized as JSON objects.
    pub events: Vec<serde_json::Value>,
    /// Query execution time in milliseconds.
    pub query_ms: u64,
}

/// Request body for `POST /api/v1/events/query` (natural language query).
#[derive(Debug, Deserialize)]
pub struct NlQueryRequest {
    /// Natural language question (e.g. "Show me all failed SSH logins today").
    pub query: String,
    /// Optional time range hint.
    pub from: Option<String>,
    /// Optional time range hint.
    pub to: Option<String>,
}

/// Response for the natural language query endpoint.
#[derive(Debug, Serialize)]
pub struct NlQueryResponse {
    /// SQL generated from the NL query (or placeholder if not yet implemented).
    pub generated_sql: String,
    /// Query results.
    pub results: Vec<serde_json::Value>,
    /// Query execution time in milliseconds.
    pub query_ms: u64,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Returns a paginated list of events for the authenticated tenant.
///
/// # Errors
///
/// - `400` — invalid query parameters (e.g. limit > 10 000, bad timestamp).
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Events.
/// - `500` — storage query failure.
#[tracing::instrument(
    skip(state),
    fields(
        user_id = %user.user_id,
        tenant_id = %user.tenant_id,
    )
)]
pub async fn list_events(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<EventQuery>,
) -> Result<Json<EventListResponse>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Events) {
        tracing::warn!(
            user_id = %user.user_id,
            role = %user.role,
            "insufficient permissions to read events"
        );
        return Err(ApiError::Forbidden(
            "insufficient permissions to read events".to_owned(),
        ));
    }

    let limit = params.limit.unwrap_or(100);
    if limit > 10_000 {
        return Err(ApiError::BadRequest(
            "limit must not exceed 10 000".to_owned(),
        ));
    }
    let limit = if limit == 0 { 100 } else { limit };

    // Build EventFilter from query params.
    let mut filter = EventFilter::new();

    if let Some(ref source) = params.source_type {
        filter = filter.with_source_type(source.clone());
    }
    if let Some(ref host) = params.host {
        filter = filter.with_hostname(host.clone());
    }
    if let Some(ref event_type) = params.event_type {
        filter = filter.with_event_type(event_type.clone());
    }
    if let Some(ref severity) = params.severity {
        filter = filter.with_min_severity(severity.clone());
    }
    if params.ioc_hit == Some(true) {
        filter = filter.ioc_hits_only();
    }
    if let Some(ref user_name) = params.user {
        filter.user_name = Some(user_name.clone());
    }

    // Parse timestamps.
    let from_ts = chrono::DateTime::parse_from_rfc3339(&params.from)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| ApiError::BadRequest(format!("invalid 'from' timestamp: {e}")))?;
    filter.from_ts = Some(from_ts);

    if let Some(ref to_str) = params.to {
        let to_ts = chrono::DateTime::parse_from_rfc3339(to_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| ApiError::BadRequest(format!("invalid 'to' timestamp: {e}")))?;
        filter.to_ts = Some(to_ts);
    }

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());
    let t0 = Instant::now();

    let events = state
        .storage
        .query_events(&ctx, Some(filter), limit)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %user.tenant_id,
                error = %e,
                "storage query_events failed"
            );
            ApiError::Internal("event query failed".to_owned())
        })?;

    let query_ms = t0.elapsed().as_millis() as u64;
    let total = events.len() as u64;
    let events_json: Vec<serde_json::Value> = events
        .into_iter()
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();

    Ok(Json(EventListResponse {
        total,
        events: events_json,
        query_ms,
    }))
}

/// Returns a single event by ID for the authenticated tenant.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Events.
/// - `404` — event not found or belongs to another tenant.
/// - `500` — storage query failure.
#[tracing::instrument(
    skip(state),
    fields(
        user_id = %user.user_id,
        tenant_id = %user.tenant_id,
        event_id = %event_id,
    )
)]
pub async fn get_event(
    State(state): State<AppState>,
    user: AuthUser,
    Path(event_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Events) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to read events".to_owned(),
        ));
    }

    let ctx = TenantContext::new(user.tenant_id, &user.user_id, &user.role.to_string());

    let event = state
        .storage
        .get_event(&ctx, &event_id)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %user.tenant_id,
                event_id = %event_id,
                error = %e,
                "storage get_event failed"
            );
            ApiError::Internal("event lookup failed".to_owned())
        })?;

    let event = event.ok_or_else(|| ApiError::NotFound(format!("event '{event_id}' not found")))?;

    serde_json::to_value(event).map(Json).map_err(|e| {
        tracing::error!(event_id = %event_id, error = %e, "event serialization failed");
        ApiError::Internal("event serialization failed".to_owned())
    })
}

/// Natural language event query (stub — NL→SQL engine not yet implemented).
///
/// Returns a placeholder SQL string and empty results. Wire to `kron-ai`
/// Mistral NL module when it is available.
///
/// # Errors
///
/// - `401` — missing or invalid JWT.
/// - `403` — role does not have Read permission on Events.
#[tracing::instrument(skip(state, _req), fields(user_id = %user.user_id, tenant_id = %user.tenant_id))]
pub async fn query_events(
    State(state): State<AppState>,
    user: AuthUser,
    Json(_req): Json<NlQueryRequest>,
) -> Result<Json<NlQueryResponse>, ApiError> {
    // TODO(#10, hardik, v1.1): Wire Mistral NL→SQL when kron-ai NL module is ready
    let _ = &state;
    if !kron_auth::rbac::can(user.role, Action::Read, Resource::Events) {
        return Err(ApiError::Forbidden(
            "insufficient permissions to read events".to_owned(),
        ));
    }

    Ok(Json(NlQueryResponse {
        generated_sql: "-- NL query not yet implemented".to_owned(),
        results: vec![],
        query_ms: 0,
    }))
}
