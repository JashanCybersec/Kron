//! WebSocket handler for the live event tail.
//!
//! Clients connect to `WS /api/v1/ws/events`, authenticate via Bearer token,
//! and receive a real-time feed of normalised KRON events for their tenant.
//! Optional `severity` query parameter filters by severity level.
//!
//! # Future work
//!
//! When `kron-bus` exposes a consumer API, this handler will subscribe to the
//! `kron.normalized.<tenant_id>` topic and forward messages to the socket.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tokio::time::interval;

use crate::{middleware::AuthUser, state::{ws_conn_acquire, ws_conn_release, AppState}};

/// Query parameters for the event stream WebSocket.
#[derive(Debug, Deserialize)]
pub struct EventStreamParams {
    /// Comma-separated severity levels to include (e.g. `"critical,high"`).
    /// When absent, all severity levels are forwarded.
    pub severity: Option<String>,
}

/// `GET /api/v1/ws/events` — live event tail WebSocket upgrade.
///
/// Validates the caller's JWT via [`AuthUser`] before performing the upgrade.
/// Accepts an optional `severity` query parameter to filter the event feed.
///
/// # Errors
///
/// Returns 401 if the JWT is missing or invalid (handled by [`AuthUser`]
/// extractor before this function is called).
pub async fn ws_events(
    ws: WebSocketUpgrade,
    user: AuthUser,
    Query(params): Query<EventStreamParams>,
    State(state): State<AppState>,
) -> Response {
    let max = state.config.api.max_ws_connections_per_tenant;
    let tenant_id = user.tenant_id.to_string();
    match ws_conn_acquire(&state.ws_conn_counts, &tenant_id, max) {
        Ok(counter) => {
            ws.on_upgrade(move |socket| handle_events_socket(socket, user, params, state, counter))
        }
        Err(()) => {
            tracing::warn!(tenant_id = %tenant_id, max, "WS event connection limit reached");
            (
                StatusCode::TOO_MANY_REQUESTS,
                format!("WebSocket connection limit of {max} reached for this tenant"),
            )
                .into_response()
        }
    }
}

/// Drives the WebSocket connection for the event tail.
///
/// Sends a heartbeat ping every 30 seconds and responds to client pings.
/// Exits when the client closes the connection or a send error occurs.
async fn handle_events_socket(
    socket: WebSocket,
    user: AuthUser,
    params: EventStreamParams,
    _state: AppState,
    conn_counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let (mut sender, mut receiver) = socket.split();
    let tenant_id = user.tenant_id.to_string();

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.user_id,
        severity_filter = ?params.severity,
        "WebSocket event stream connected"
    );

    // TODO(#15, hardik, v1.1): Subscribe to kron-bus kron.normalized.<tenant_id> topic and
    // forward messages (optionally filtered by severity) when the bus consumer API is available.

    let mut heartbeat = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let ping = json!({
                    "type": "heartbeat",
                    "tenant_id": &tenant_id
                });
                if sender
                    .send(Message::Text(ping.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if sender.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        tracing::warn!(
                            tenant_id = %tenant_id,
                            error = %e,
                            "WebSocket receive error on event stream"
                        );
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    ws_conn_release(&conn_counter);
    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.user_id,
        "WebSocket event stream disconnected"
    );
}
