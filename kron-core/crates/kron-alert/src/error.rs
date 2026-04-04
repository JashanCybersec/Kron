//! Error types for the `kron-alert` engine.

/// All errors that can occur within the alert engine.
#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    /// A message bus operation failed.
    #[error("bus error: {0}")]
    Bus(String),

    /// Writing an alert to storage failed.
    #[error("storage error writing alert {alert_id}: {reason}")]
    Storage { alert_id: String, reason: String },

    /// A notification channel delivery failed.
    #[error("notification error ({channel}): {reason}")]
    Notification { channel: String, reason: String },

    /// Failed to deserialize a message payload.
    #[error("deserialize error: {0}")]
    Deserialize(String),

    /// An HTTP request to an external notification API failed.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}
