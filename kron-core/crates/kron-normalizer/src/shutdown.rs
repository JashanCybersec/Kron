//! Graceful shutdown signal handling for `kron-normalizer`.
//!
//! [`ShutdownHandle`] wraps a broadcast channel so that multiple async tasks
//! can all be notified to stop when SIGTERM or Ctrl-C is received.

use tokio::sync::broadcast;

/// Capacity of the broadcast channel — one slot per subscriber is enough.
const CHANNEL_CAPACITY: usize = 8;

/// A handle to the global shutdown signal.
///
/// Clone or call [`ShutdownHandle::subscribe`] to get additional receivers.
#[derive(Clone)]
pub struct ShutdownHandle {
    sender: broadcast::Sender<()>,
}

impl ShutdownHandle {
    /// Creates a new [`ShutdownHandle`] and spawns a signal-listener task.
    ///
    /// Returns the handle and a `JoinHandle` for the signal task.
    /// The caller must keep the `JoinHandle` alive (hold it or `await` it).
    #[must_use]
    pub fn new() -> (Self, tokio::task::JoinHandle<()>) {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        let handle = Self {
            sender: sender.clone(),
        };
        let task = tokio::spawn(async move {
            wait_for_signal().await;
            tracing::info!("Shutdown signal received");
            let _ = sender.send(());
        });
        (handle, task)
    }

    /// Returns a new receiver that fires once on shutdown.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.sender.subscribe()
    }

    /// Triggers a programmatic shutdown (useful in tests and the main loop).
    pub fn trigger(&self) {
        let _ = self.sender.send(());
    }
}

/// Waits for SIGTERM (Unix) or Ctrl-C (all platforms).
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
