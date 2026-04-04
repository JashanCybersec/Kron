//! Periodic heartbeat sender.
//!
//! Sends a [`HeartbeatRequest`] to the collector every
//! [`HEARTBEAT_INTERVAL`]. The heartbeat carries ring buffer utilization
//! and disk buffer depth so the collector can detect degraded agents.
//!
//! # Behaviour on failure
//!
//! If the heartbeat RPC fails, the failure is logged, the
//! [`crate::metrics`] heartbeat failure counter is incremented, and the
//! task sleeps until the next interval. A failed heartbeat does NOT cause
//! the main event pipeline to stop — only 90 s of silence (3 × interval)
//! causes the collector to mark the agent "dark".

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::{broadcast, Mutex};

use kron_types::{AgentId, HeartbeatRequest};

use crate::metrics;
use crate::transport::CollectorTransport;

/// Interval between heartbeat sends.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Shared state passed into the heartbeat task.
pub struct HeartbeatState {
    /// Agent identifier assigned by the collector on registration.
    pub agent_id: AgentId,
    /// Current ring buffer utilization percent (0–100).
    /// Written by the ring buffer reader; read by heartbeat task.
    pub ring_buffer_utilization_pct: u8,
    /// Events dropped since the last heartbeat.
    pub events_dropped_since_last: u64,
    /// Events currently buffered on disk.
    pub disk_buffer_depth: u64,
}

/// Spawns a background task that sends heartbeats every 30 seconds.
///
/// The task runs until the `shutdown` receiver fires or the sender is dropped.
/// The `transport` is shared via `Arc<Mutex<_>>` with the main event sender.
///
/// Returns a [`tokio::task::JoinHandle`] for the background task.
pub fn spawn_heartbeat_task<T>(
    state: Arc<Mutex<HeartbeatState>>,
    transport: Arc<Mutex<T>>,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()>
where
    T: CollectorTransport + 'static,
{
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        // Skip the first tick so the heartbeat isn't sent immediately on startup
        // before the first event batch (which would also trigger a connection check).
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let (agent_id, ring_util, dropped, buffer_depth) = {
                        let s = state.lock().await;
                        (s.agent_id, s.ring_buffer_utilization_pct, s.events_dropped_since_last, s.disk_buffer_depth)
                    };

                    let req = HeartbeatRequest {
                        agent_id,
                        sent_at: Utc::now(),
                        ring_buffer_utilization_pct: ring_util,
                        events_dropped_since_last: dropped,
                        disk_buffer_depth: buffer_depth,
                    };

                    let result = {
                        let mut t = transport.lock().await;
                        t.heartbeat(req).await
                    };

                    match result {
                        Ok(resp) => {
                            // Detect large clock skew between agent and collector.
                            let skew = (Utc::now() - resp.collector_at).num_seconds().abs();
                            if skew > 60 {
                                tracing::warn!(
                                    skew_seconds = skew,
                                    "Clock skew between agent and collector exceeds 60 s — check NTP"
                                );
                            }
                            // Reset drop counter after successful heartbeat.
                            state.lock().await.events_dropped_since_last = 0;
                            tracing::debug!(skew_seconds = skew, "Heartbeat sent");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Heartbeat failed");
                            metrics::record_heartbeat_failure();
                        }
                    }
                }
                _ = shutdown.recv() => {
                    tracing::debug!("Heartbeat task received shutdown signal");
                    break;
                }
            }
        }
    })
}
