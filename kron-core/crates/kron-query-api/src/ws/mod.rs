//! WebSocket upgrade handlers for real-time KRON event and alert streams.
//!
//! All WebSocket endpoints require a valid JWT in the `Authorization: Bearer`
//! header (validated by the [`crate::middleware::AuthUser`] extractor before
//! upgrade). Once upgraded, the connection streams newline-delimited JSON
//! until the client disconnects or the server shuts down.

pub mod alerts;
pub mod events;
