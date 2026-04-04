//! Axum router construction for the KRON query API.
//!
//! Splits routes into two groups:
//! - **Public** — `/health`, `/version`, `/auth/login`, `/auth/refresh`:
//!   no JWT required.
//! - **Protected** — everything else: requires a valid JWT via the
//!   [`crate::middleware::AuthUser`] extractor (which is a
//!   `FromRequestParts<AppState>` impl).
//!
//! All routes are nested under `/api/v1`.
//!
//! # Middleware stack (outermost → innermost)
//!
//! 1. `DefaultBodyLimit` — enforces `config.api.max_body_bytes` (axum native; returns 413).
//! 2. `SetRequestIdLayer` — assigns `X-Request-Id` to every request for correlation.
//! 3. `TraceLayer` — structured tracing span per request, tagged with request ID.
//! 4. `TimeoutLayer` — enforces `config.api.response_timeout_ms`; returns 408 on breach.
//! 5. Security headers — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
//! 6. `CorsLayer` — CORS configured from `config.api.cors_allowed_origins`.

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue},
    routing::{delete, get, patch, post, put},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    handlers::{
        alerts::{acknowledge_alert, get_alert, list_alerts, update_alert},
        assets::{get_asset, list_assets},
        auth::{login, logout, refresh},

        events::{get_event, list_events, query_events},
        health::{health, readiness, version},
        rules::{create_rule, delete_rule, import_sigma, list_rules, update_rule},
        tenants::{create_tenant, get_tenant, list_tenants, offboard_tenant, update_tenant_config},
    },
    state::AppState,
    ws::{alerts::ws_alerts, events::ws_events},
};

/// Standard request-ID header name used throughout KRON for log correlation.
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Builds and returns the complete Axum [`Router`] for the KRON query API.
///
/// Wires the full production middleware stack:
/// - Request body size limit (DoS protection)
/// - Request timeout (thread pool protection)
/// - Security response headers (browser hardening)
/// - CORS from `config.api.cors_allowed_origins` (no wildcard in production)
/// - Correlation ID via `X-Request-Id` header
///
/// # Arguments
/// * `state` — shared application state injected into all handlers
pub fn build_router(state: AppState) -> Router {
    let config = state.config.clone();

    // ── CORS ──────────────────────────────────────────────────────────────────
    // Origins come from config. Empty list → no CORS (API clients must be same-origin).
    let cors = if config.api.cors_allowed_origins.is_empty() {
        CorsLayer::new()
    } else {
        let mut layer = CorsLayer::new();
        for origin_str in &config.api.cors_allowed_origins {
            if let Ok(origin) = origin_str.parse::<HeaderValue>() {
                layer = layer.allow_origin(origin);
            } else {
                tracing::warn!(origin = %origin_str, "Skipping invalid CORS origin in config");
            }
        }
        layer
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::PATCH,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
    };

    // ── Public routes (no JWT required) ──────────────────────────────────────
    let public = Router::new()
        .route("/health", get(health))
        .route("/ready", get(readiness))
        .route("/version", get(version))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh));

    // ── Protected routes (JWT required via AuthUser extractor) ───────────────
    let protected = Router::new()
        // Auth
        .route("/auth/logout", post(logout))
        // Events
        .route("/events", get(list_events))
        .route("/events/query", post(query_events))
        .route("/events/:event_id", get(get_event))
        // Alerts
        .route("/alerts", get(list_alerts))
        .route("/alerts/:alert_id", get(get_alert))
        .route("/alerts/:alert_id", patch(update_alert))
        .route("/alerts/:alert_id/acknowledge", post(acknowledge_alert))
        // Rules
        .route("/rules", get(list_rules))
        .route("/rules", post(create_rule))
        .route("/rules/import", post(import_sigma))
        .route("/rules/:rule_id", put(update_rule))
        .route("/rules/:rule_id", delete(delete_rule))
        // Assets
        .route("/assets", get(list_assets))
        .route("/assets/:asset_id", get(get_asset))
        // Tenants (MSSP portal)
        .route("/tenants", get(list_tenants))
        .route("/tenants", post(create_tenant))
        .route("/tenants/:tenant_id", get(get_tenant))
        .route("/tenants/:tenant_id/config", put(update_tenant_config))
        .route("/tenants/:tenant_id", delete(offboard_tenant))
        // Compliance (Standard/Enterprise only — compiled in with `standard` feature)

        // WebSocket streams
        .route("/ws/alerts", get(ws_alerts))
        .route("/ws/events", get(ws_events));

    // ── Compose with full production middleware stack ─────────────────────────
    Router::new()
        .nest("/api/v1", public)
        .nest("/api/v1", protected)
        // 1. Body size limit — axum-native, avoids type issues with TraceLayer.
        //    Returns 413 for oversized payloads (DoS protection).
        .layer(DefaultBodyLimit::max(
            usize::try_from(config.api.max_body_bytes).unwrap_or(10 * 1024 * 1024),
        ))
        .layer(
            ServiceBuilder::new()
                // 2. Assign X-Request-Id to every request (for log correlation).
                .layer(SetRequestIdLayer::new(
                    X_REQUEST_ID.clone(),
                    MakeRequestUuid,
                ))
                // 3. Propagate X-Request-Id from request into the response.
                .layer(PropagateRequestIdLayer::new(X_REQUEST_ID.clone()))
                // 4. Structured tracing span per request.
                .layer(TraceLayer::new_for_http())
                // 5. Hard response timeout — returns 408 if the handler is too slow.
                .layer(TimeoutLayer::new(config.api.response_timeout()))
                // 6. Security response headers (browser hardening).
                //    Prevents MIME-type sniffing attacks.
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::HeaderName::from_static("x-content-type-options"),
                    HeaderValue::from_static("nosniff"),
                ))
                //    Prevents embedding KRON in an iframe (clickjacking).
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::HeaderName::from_static("x-frame-options"),
                    HeaderValue::from_static("DENY"),
                ))
                //    Limits referrer leakage from the KRON portal to third-party sites.
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::HeaderName::from_static("referrer-policy"),
                    HeaderValue::from_static("strict-origin-when-cross-origin"),
                ))
                //    Prevents browsers from using outdated MIME detection.
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::HeaderName::from_static("x-permitted-cross-domain-policies"),
                    HeaderValue::from_static("none"),
                ))
                // 7. CORS — origins from config; never wildcard in production.
                .layer(cors),
        )
        .with_state(state)
}
