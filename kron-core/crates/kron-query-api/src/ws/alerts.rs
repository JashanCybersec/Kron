//! WebSocket handler for the live alert stream.
//!
//! Clients connect to `WS /api/v1/ws/alerts`, authenticate via Bearer token,
//! and receive newline-delimited JSON alert objects as they fire. A heartbeat
//! ping is sent every 30 seconds to keep the connection alive through proxies.
//!
//! # Future work
//!
//! When `kron-bus` exposes a consumer API, this handler will subscribe to the
//! `kron.alerts.<tenant_id>` topic and forward messages to the socket.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use serde_json::json;
use std::time::Duration;
use tokio::time::interval;

use crate::{middleware::AuthUser, state::{ws_conn_acquire, ws_conn_release, AppState}};

/// `GET /api/v1/ws/alerts` — live alert stream WebSocket upgrade.
///
/// Validates the caller's JWT via [`AuthUser`] before performing the upgrade.
/// Streams heartbeat pings while waiting for the bus integration to land.
///
/// # Errors
///
/// Returns 401 if the JWT is missing or invalid (handled by [`AuthUser`]
/// extractor before this function is called).
pub async fn ws_alerts(
    ws: WebSocketUpgrade,
    user: AuthUser,
    State(state): State<AppState>,
) -> Response {
    let max = state.config.api.max_ws_connections_per_tenant;
    let tenant_id = user.tenant_id.to_string();
    match ws_conn_acquire(&state.ws_conn_counts, &tenant_id, max) {
        Ok(counter) => ws.on_upgrade(move |socket| handle_alerts_socket(socket, user, state, counter)),
        Err(()) => {
            tracing::warn!(tenant_id = %tenant_id, max, "WS alert connection limit reached");
            (
                StatusCode::TOO_MANY_REQUESTS,
                format!("WebSocket connection limit of {max} reached for this tenant"),
            )
                .into_response()
        }
    }
}

/// Drives the WebSocket connection for the alert stream.
///
/// Sends a heartbeat ping every 30 seconds and responds to client pings.
/// Exits when the client closes the connection or a send error occurs.
async fn handle_alerts_socket(
    socket: WebSocket,
    user: AuthUser,
    _state: AppState,
    conn_counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let (mut sender, mut receiver) = socket.split();
    let tenant_id = user.tenant_id.to_string();

    tracing::info!(
        tenant_id = %tenant_id,
        user_id = %user.user_id,
        "WebSocket alert stream connected"
    );

    // TODO(#15, hardik, v1.1): Subscribe to kron-bus kron.alerts.<tenant_id> topic and
    // forward messages to the socket when the bus consumer API is available.

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
                            "WebSocket receive error"
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
        "WebSocket alert stream disconnected"
    );
}
