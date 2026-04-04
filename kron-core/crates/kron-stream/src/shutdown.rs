//! Graceful shutdown coordination for the stream processor.
//!
//! [`ShutdownHandle`] wraps a [`tokio::sync::broadcast`] channel so that any
//! number of tasks can await a shutdown signal. The handle is `Clone`-able;
//! clones share the same underlying sender.

use tokio::sync::broadcast;
use tracing::instrument;

/// Capacity of the broadcast channel.  One message is sufficient because
/// shutdown is a one-time, one-way signal.
const CHANNEL_CAPACITY: usize = 1;

/// Shutdown signal coordinator for `kron-stream`.
///
/// Obtain subscriber receivers via [`ShutdownHandle::subscribe`] and pass
/// them to tasks. Call [`ShutdownHandle::shutdown`] (or let the process
/// receive SIGTERM/Ctrl-C via [`ShutdownHandle::listen_for_signals`]) to
/// broadcast the shutdown.
pub struct ShutdownHandle {
    sender: broadcast::Sender<()>,
}

impl ShutdownHandle {
    /// Create a new shutdown handle with a fresh broadcast channel.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Subscribe to the shutdown signal.
    ///
    /// The returned receiver will yield `Ok(())` exactly once when
    /// [`ShutdownHandle::shutdown`] is called (or signals are received).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.sender.subscribe()
    }

    /// Broadcast the shutdown signal to all subscribers.
    ///
    /// Subsequent calls are no-ops (all subscribers have already received).
    pub fn shutdown(&self) {
        // send() only errors when there are no active receivers, which is
        // acceptable — it means all tasks have already exited.
        let _ = self.sender.send(());
        tracing::info!("shutdown signal broadcast");
    }

    /// Block until SIGTERM or Ctrl-C is received, then broadcast shutdown.
    ///
    /// This is the canonical entry-point for the main task. It awaits
    /// `tokio::signal` and calls [`Self::shutdown`] on receipt.
    #[instrument(skip(self))]
    pub async fn listen_for_signals(&self) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "failed to register SIGTERM handler");
                    // Fall through to ctrl_c only.
                    tokio::signal::ctrl_c()
                        .await
                        .unwrap_or_else(|e| tracing::error!(error = %e, "ctrl_c error"));
                    self.shutdown();
                    return;
                }
            };

            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("SIGTERM received");
                }
                res = tokio::signal::ctrl_c() => {
                    if let Err(e) = res {
                        tracing::error!(error = %e, "error waiting for ctrl_c");
                    } else {
                        tracing::info!("Ctrl-C received");
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .unwrap_or_else(|e| tracing::error!(error = %e, "ctrl_c error"));
            tracing::info!("Ctrl-C received");
        }

        self.shutdown();
    }
}

impl Default for ShutdownHandle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_when_called_then_subscriber_receives() {
        let handle = ShutdownHandle::new();
        let mut rx = handle.subscribe();

        handle.shutdown();

        let result = rx.recv().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown_when_no_subscribers_then_no_panic() {
        let handle = ShutdownHandle::new();
        // No subscribers — must not panic.
        handle.shutdown();
    }

    #[tokio::test]
    async fn test_multiple_subscribers_when_shutdown_then_all_receive() {
        let handle = ShutdownHandle::new();
        let mut rx1 = handle.subscribe();
        let mut rx2 = handle.subscribe();

        handle.shutdown();

        assert!(rx1.recv().await.is_ok());
        assert!(rx2.recv().await.is_ok());
    }
}
