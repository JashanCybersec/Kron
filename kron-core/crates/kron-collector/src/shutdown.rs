//! Graceful shutdown signalling for kron-collector.
//!
//! [`ShutdownHandle`] wraps a broadcast channel so that any number of
//! tasks can receive a single shutdown signal. On Unix, SIGTERM or SIGINT
//! triggers shutdown. On other platforms only SIGINT is handled.

use tokio::sync::broadcast;

/// Number of shutdown signal slots — enough for all collector tasks plus headroom.
const CHANNEL_CAPACITY: usize = 64;

/// A cloneable handle for the shutdown broadcast channel.
///
/// Cheaply cloneable — each clone shares the same underlying sender.
#[derive(Clone, Debug)]
pub struct ShutdownHandle {
    tx: broadcast::Sender<()>,
}

impl ShutdownHandle {
    /// Creates a new [`ShutdownHandle`] and spawns a background task that
    /// listens for OS signals and fires the shutdown broadcast.
    ///
    /// Returns `(handle, signal_task)`. The caller must keep `signal_task`
    /// alive (via `tokio::spawn` or holding it) to enable OS signal handling.
    #[must_use]
    pub fn new() -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        let handle = Self { tx: tx.clone() };

        let signal_task = tokio::spawn(async move {
            await_termination_signal().await;
            let _ = tx.send(());
        });

        (handle, signal_task)
    }

    /// Returns a receiver that fires when shutdown is triggered.
    ///
    /// Each task should call this once and hold its own receiver.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    /// Manually triggers shutdown without an OS signal.
    ///
    /// Useful when a fatal internal error requires a clean exit.
    #[allow(dead_code)]
    pub fn trigger(&self) {
        let _ = self.tx.send(());
    }
}

/// Waits for SIGTERM (Unix) or Ctrl-C, whichever arrives first.
async fn await_termination_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to register SIGTERM handler; only SIGINT will trigger shutdown"
                );
                tokio::signal::ctrl_c()
                    .await
                    .unwrap_or_else(|e| tracing::error!(error = %e, "ctrl_c handler failed"));
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received — initiating graceful shutdown");
            }
            result = tokio::signal::ctrl_c() => {
                match result {
                    Ok(()) => tracing::info!("SIGINT (Ctrl-C) received — initiating graceful shutdown"),
                    Err(e) => tracing::error!(error = %e, "ctrl_c handler failed"),
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => tracing::info!("Ctrl-C received — initiating graceful shutdown"),
            Err(e) => tracing::error!(error = %e, "ctrl_c handler failed"),
        }
    }
}
