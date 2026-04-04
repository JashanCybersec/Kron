//! `WhatsApp` notification via Twilio Messages API.

use kron_types::config::WhatsAppConfig;
use tracing::instrument;

use crate::error::AlertError;

/// Sends `WhatsApp` messages via Twilio's Messages API.
pub struct WhatsAppNotifier {
    config: WhatsAppConfig,
    client: reqwest::Client,
}

impl WhatsAppNotifier {
    /// Creates a new `WhatsAppNotifier`.
    ///
    /// If `config.account_sid` is empty the notifier is a no-op;
    /// [`send`](Self::send) will return `Ok(())` without making any network call.
    #[must_use]
    pub fn new(config: WhatsAppConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Sends a `WhatsApp` message to `to_number` via the Twilio Messages API.
    ///
    /// Silently succeeds (returns `Ok(())`) when the notifier is not configured
    /// (i.e. `account_sid` is empty).
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::Http`] if the Twilio API call fails at the
    /// transport level, or [`AlertError::Notification`] if Twilio returns a
    /// non-2xx HTTP status code.
    #[instrument(skip(self, message), fields(to = %to_number))]
    pub async fn send(&self, to_number: &str, message: &str) -> Result<(), AlertError> {
        if self.config.account_sid.is_empty() {
            tracing::debug!("WhatsApp not configured — skipping notification");
            return Ok(());
        }

        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.config.account_sid
        );

        let from = format!("whatsapp:{}", self.config.from_number);
        let to = format!("whatsapp:{to_number}");

        let params = [
            ("From", from.as_str()),
            ("To", to.as_str()),
            ("Body", message),
        ];

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.config.account_sid, Some(&self.config.auth_token))
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
                "Twilio WhatsApp API returned non-2xx status"
            );
            return Err(AlertError::Notification {
                channel: "whatsapp".to_string(),
                reason: format!("Twilio returned {status}: {body}"),
            });
        }

        tracing::info!(to = %to_number, "WhatsApp notification sent");
        Ok(())
    }
}
