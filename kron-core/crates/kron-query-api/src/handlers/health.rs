//! Health, readiness, and version endpoints.
//!
//! Two separate probes are exposed so Kubernetes can distinguish between:
//! - **Liveness** (`/api/v1/health`) — process is alive; never checks dependencies.
//! - **Readiness** (`/api/v1/ready`) — storage backend is reachable; gates traffic.
//!
//! Failing readiness causes the load balancer to stop routing requests to this
//! instance, preventing analysts from hitting a pod with a broken database connection.

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::Serialize;

use kron_storage::StorageEngine;

use crate::state::AppState;

/// Response body for `GET /api/v1/health` (liveness probe).
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Always `"ok"` — the process is alive.
    pub status: &'static str,
}

/// Response body for `GET /api/v1/ready` (readiness probe).
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    /// `"ok"` when all checks pass, `"degraded"` when any check fails.
    pub status: &'static str,
    /// Storage backend health status.
    pub storage: &'static str,
    /// Name of the storage backend in use.
    pub backend: &'static str,
}

/// Response body for `GET /api/v1/version`.
#[derive(Debug, Serialize)]
pub struct VersionResponse {
    /// Semantic version of this build (from `Cargo.toml`).
    pub version: &'static str,
    /// Git commit SHA injected at build time via `GIT_COMMIT` env var.
    pub commit: &'static str,
}

/// `GET /api/v1/health` — Kubernetes liveness probe.
///
/// Returns `200 OK` if the process is running. This probe is intentionally
/// lightweight — it does **not** check downstream dependencies. Use the
/// readiness probe (`/api/v1/ready`) for dependency health.
///
/// Kubernetes should restart the pod only when this returns a non-2xx.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// `GET /api/v1/ready` — Kubernetes readiness probe.
///
/// Performs a live `health_check()` against the storage backend.
/// Returns `200 OK` when the backend is reachable, `503 Service Unavailable`
/// when it is not. The load balancer should stop routing traffic on `503`.
///
/// # Returns
///
/// - `200` — storage is healthy; instance is ready to serve requests.
/// - `503` — storage health check failed; instance should be removed from rotation.
pub async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let backend = state.storage.backend_name();

    match state.storage.health_check().await {
        Ok(()) => (
            StatusCode::OK,
            Json(ReadinessResponse {
                status: "ok",
                storage: "ok",
                backend,
            }),
        ),
        Err(e) => {
            tracing::error!(backend = %backend, error = %e, "Storage health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadinessResponse {
                    status: "degraded",
                    storage: "unavailable",
                    backend,
                }),
            )
        }
    }
}

/// `GET /api/v1/version` — build information.
///
/// Returns the crate version and the git commit SHA embedded at build time.
/// Useful for verifying which build is deployed without SSHing into the node.
pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        commit: option_env!("GIT_COMMIT").unwrap_or("unknown"),
    })
}
