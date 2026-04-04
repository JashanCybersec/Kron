//! SMS notification via Textlocal API.

use kron_types::config::SmsConfig;
use tracing::instrument;

use crate::error::AlertError;

/// Sends SMS messages via the Textlocal HTTP API.
pub struct SmsNotifier {
    config: SmsConfig,
    client: reqwest::Client,
}

impl SmsNotifier {
    /// Creates a new `SmsNotifier`.
    ///
    /// If `config.api_key` is empty the notifier is effectively a no-op;
    /// [`send`](Self::send) will return `Ok(())` without making any network call.
    #[must_use]
    pub fn new(config: SmsConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Sends an SMS to `to_number` via the Textlocal API.
    ///
    /// Silently succeeds (returns `Ok(())`) when the notifier is not configured
    /// (i.e. `api_key` is empty).
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::Http`] if the Textlocal API call fails at the
    /// transport level, or [`AlertError::Notification`] if Textlocal returns a
    /// non-2xx HTTP status code.
    #[instrument(skip(self, message), fields(to = %to_number))]
    pub async fn send(&self, to_number: &str, message: &str) -> Result<(), AlertError> {
        if self.config.api_key.is_empty() {
            tracing::debug!("SMS not configured — skipping notification");
            return Ok(());
        }

        let params = [
            ("apikey", self.config.api_key.as_str()),
            ("numbers", to_number),
            ("message", message),
            ("sender", self.config.sender.as_str()),
        ];

        let response = self
            .client
            .post("https://api.textlocal.in/send/")
            .form(&params)
            .send()
            .await
            .map_err(AlertError::Http)?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            tracing::error!(
                status = %status,
                body = %body,
                "Textlocal SMS API returned non-2xx status"
            );
            return Err(AlertError::Notification {
                channel: "sms".to_string(),
                reason: format!("Textlocal returned {status}: {body}"),
            });
        }

        tracing::info!(to = %to_number, "SMS notification sent");
        Ok(())
    }
}
