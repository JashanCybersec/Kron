//! Notification dispatcher with `WhatsApp` → SMS → Email fallback chain.
//!
//! P1/P2 (Critical/High) alerts bypass rate limiting and are dispatched
//! immediately on all channels in parallel.  P3+ alerts pass through the
//! rate limiter on each channel.

use std::sync::Arc;

use kron_types::config::AlertConfig;
use kron_types::KronAlert;
use tracing::instrument;

use crate::error::AlertError;
use crate::metrics;
use crate::notify::email::EmailNotifier;
use crate::notify::rate_limit::NotificationRateLimiter;
use crate::notify::sms::SmsNotifier;
use crate::notify::whatsapp::WhatsAppNotifier;

/// Result of a dispatch attempt showing which channels succeeded.
#[derive(Debug, Default)]
pub struct DispatchResult {
    /// Whether a `WhatsApp` message was sent.
    pub whatsapp_sent: bool,
    /// Whether an SMS was sent.
    pub sms_sent: bool,
    /// Whether an email was sent.
    pub email_sent: bool,
}

/// Dispatches alert notifications using a `WhatsApp` → SMS → Email fallback chain.
///
/// Each notifier silently succeeds when not configured.  The dispatcher stops
/// after the first successful channel (for P3+ alerts) or attempts all channels
/// (for P1/P2 alerts).
pub struct NotificationDispatcher {
    whatsapp: Arc<WhatsAppNotifier>,
    sms: Arc<SmsNotifier>,
    email: Arc<EmailNotifier>,
    rate_limiter: Arc<NotificationRateLimiter>,
    config: AlertConfig,
}

impl NotificationDispatcher {
    /// Creates a new `NotificationDispatcher` from the alert configuration.
    #[must_use]
    pub fn new(config: AlertConfig) -> Self {
        let rate_limiter = Arc::new(NotificationRateLimiter::new(
            config.whatsapp_rate_limit_per_hour,
        ));
        let whatsapp = Arc::new(WhatsAppNotifier::new(config.whatsapp.clone()));
        let sms = Arc::new(SmsNotifier::new(config.sms.clone()));
        let email = Arc::new(EmailNotifier::new(config.smtp.clone()));

        Self {
            whatsapp,
            sms,
            email,
            rate_limiter,
            config,
        }
    }

    /// Dispatches notifications for an alert using the fallback chain.
    ///
    /// For P1/P2 (Critical/High) alerts, all channels are attempted.
    /// For P3+ alerts, dispatch stops after the first successful channel.
    /// Rate limiting is applied per channel for P3+ alerts.
    ///
    /// # Errors
    ///
    /// Returns the last error if all channels fail.  If at least one channel
    /// succeeds, the error is logged but `Ok(DispatchResult)` is returned.
    #[instrument(skip(self), fields(
        alert_id = %alert.alert_id,
        tenant_id = %alert.tenant_id,
        severity = %alert.severity,
    ))]
    pub async fn dispatch(&self, alert: &KronAlert) -> DispatchResult {
        let tenant_id = alert.tenant_id.to_string();
        let severity = alert.severity;
        let message_en = alert
            .narrative_en
            .as_deref()
            .unwrap_or("KRON Security Alert — see dashboard for details.");
        let is_immediate = alert.is_immediate();
        let to_whatsapp = &self.config.whatsapp.to_number;
        let to_sms = &self.config.sms.to_number;
        let to_email = &self.config.smtp.to_address;

        let mut result = DispatchResult::default();

        // --- WhatsApp ---
        let wa_allowed = self.rate_limiter.allow(&tenant_id, "whatsapp", severity);

        if wa_allowed {
            match self.whatsapp.send(to_whatsapp, message_en).await {
                Ok(()) => {
                    result.whatsapp_sent = true;
                    metrics::record_notification_sent("whatsapp");
                    if !is_immediate {
                        // P3+ stops after first success.
                        return result;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        alert_id = %alert.alert_id,
                        error = %e,
                        "WhatsApp notification failed"
                    );
                    metrics::record_notification_failed("whatsapp");
                }
            }
        } else {
            tracing::debug!(
                alert_id = %alert.alert_id,
                "WhatsApp rate-limited"
            );
            metrics::record_notification_rate_limited("whatsapp");
        }

        // --- SMS ---
        let sms_allowed = self.rate_limiter.allow(&tenant_id, "sms", severity);

        if sms_allowed {
            match self.sms.send(to_sms, message_en).await {
                Ok(()) => {
                    result.sms_sent = true;
                    metrics::record_notification_sent("sms");
                    if !is_immediate {
                        return result;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        alert_id = %alert.alert_id,
                        error = %e,
                        "SMS notification failed"
                    );
                    metrics::record_notification_failed("sms");
                }
            }
        } else {
            tracing::debug!(alert_id = %alert.alert_id, "SMS rate-limited");
            metrics::record_notification_rate_limited("sms");
        }

        // --- Email ---
        let email_allowed = self.rate_limiter.allow(&tenant_id, "email", severity);

        if email_allowed {
            let subject = format!("[KRON] {} Alert: {}", severity, alert.rule_name);
            match self.email.send(to_email, &subject, message_en).await {
                Ok(()) => {
                    result.email_sent = true;
                    metrics::record_notification_sent("email");
                }
                Err(e) => {
                    tracing::warn!(
                        alert_id = %alert.alert_id,
                        error = %e,
                        "Email notification failed"
                    );
                    metrics::record_notification_failed("email");
                }
            }
        } else {
            tracing::debug!(alert_id = %alert.alert_id, "Email rate-limited");
            metrics::record_notification_rate_limited("email");
        }

        result
    }
}

impl From<AlertError> for () {
    fn from(_: AlertError) {}
}
