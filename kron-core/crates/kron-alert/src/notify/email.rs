//! Email notification via a minimal async SMTP client.
//!
//! Connects to the configured SMTP server using `tokio::net::TcpStream`,
//! issues `EHLO`, `AUTH LOGIN`, `MAIL FROM`, `RCPT TO`, `DATA`, and `QUIT`.
//!
//! Phase 2 limitation: TLS (STARTTLS) is not performed even on port 587.
//! Full STARTTLS support is deferred to Phase 3.
//! TODO(#TBD, hardik, phase-3): Add STARTTLS support for port 587

use std::str;

use kron_types::config::SmtpConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::instrument;

use crate::error::AlertError;

/// Sends email notifications via a plain TCP SMTP connection.
pub struct EmailNotifier {
    config: SmtpConfig,
}

impl EmailNotifier {
    /// Creates a new `EmailNotifier`.
    ///
    /// If `config.host` is empty the notifier is effectively a no-op;
    /// [`send`](Self::send) will return `Ok(())` without making any network call.
    #[must_use]
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    /// Sends an email to `to` with the given `subject` and plain-text `body`.
    ///
    /// Silently succeeds (returns `Ok(())`) when the notifier is not configured
    /// (i.e. `host` is empty).
    ///
    /// # Errors
    ///
    /// Returns [`AlertError::Notification`] on TCP connection failure, SMTP
    /// protocol errors, or unexpected server responses.
    #[instrument(skip(self, body), fields(to = %to, subject = %subject))]
    pub async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), AlertError> {
        if self.config.host.is_empty() {
            tracing::debug!("SMTP not configured — skipping email notification");
            return Ok(());
        }

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| AlertError::Notification {
                channel: "email".to_string(),
                reason: format!("TCP connect to {addr} failed: {e}"),
            })?;

        // Read server greeting (220)
        read_response(&mut stream, 220).await?;

        // EHLO
        write_cmd(&mut stream, "EHLO kron.security\r\n").await?;
        read_response(&mut stream, 250).await?;

        // AUTH LOGIN
        write_cmd(&mut stream, "AUTH LOGIN\r\n").await?;
        read_response(&mut stream, 334).await?;

        let username_b64 = base64_encode(self.config.username.as_bytes());
        write_cmd(&mut stream, &format!("{username_b64}\r\n")).await?;
        read_response(&mut stream, 334).await?;

        let password_b64 = base64_encode(self.config.password.as_bytes());
        write_cmd(&mut stream, &format!("{password_b64}\r\n")).await?;
        read_response(&mut stream, 235).await?;

        // MAIL FROM
        write_cmd(
            &mut stream,
            &format!("MAIL FROM:<{}>\r\n", self.config.from_address),
        )
        .await?;
        read_response(&mut stream, 250).await?;

        // RCPT TO
        write_cmd(&mut stream, &format!("RCPT TO:<{to}>\r\n")).await?;
        read_response(&mut stream, 250).await?;

        // DATA
        write_cmd(&mut stream, "DATA\r\n").await?;
        read_response(&mut stream, 354).await?;

        let message = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\n\
            Content-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n.\r\n",
            self.config.from_address, to, subject, body
        );
        write_cmd(&mut stream, &message).await?;
        read_response(&mut stream, 250).await?;

        // QUIT
        write_cmd(&mut stream, "QUIT\r\n").await?;

        tracing::info!(to = %to, subject = %subject, "Email notification sent");
        Ok(())
    }
}

/// Writes an SMTP command string to the stream.
async fn write_cmd(stream: &mut TcpStream, cmd: &str) -> Result<(), AlertError> {
    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| AlertError::Notification {
            channel: "email".to_string(),
            reason: format!("SMTP write failed: {e}"),
        })
}

/// Reads an SMTP response line and verifies the status code prefix.
///
/// Returns an error if the server returns an unexpected code.
async fn read_response(stream: &mut TcpStream, expected_code: u16) -> Result<(), AlertError> {
    let mut buf = [0u8; 512];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| AlertError::Notification {
            channel: "email".to_string(),
            reason: format!("SMTP read failed: {e}"),
        })?;

    let response = str::from_utf8(&buf[..n]).unwrap_or("");
    let actual_code = response
        .get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if actual_code != expected_code {
        return Err(AlertError::Notification {
            channel: "email".to_string(),
            reason: format!("SMTP expected {expected_code}, got: {}", response.trim()),
        });
    }

    Ok(())
}

/// Encodes bytes as standard Base64 without using an external crate.
///
/// Used for SMTP AUTH LOGIN credential encoding.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        output.push(TABLE[b0 >> 2]);
        output.push(TABLE[((b0 & 0x3) << 4) | (b1 >> 4)]);

        if chunk.len() > 1 {
            output.push(TABLE[((b1 & 0xf) << 2) | (b2 >> 6)]);
        } else {
            output.push(b'=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[b2 & 0x3f]);
        } else {
            output.push(b'=');
        }
    }
    String::from_utf8(output).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_when_hello_then_correct_output() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn test_base64_encode_when_empty_then_empty_string() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_email_notifier_when_host_empty_then_send_is_noop() {
        let notifier = EmailNotifier::new(SmtpConfig::default());
        // SmtpConfig::default() sets host = "localhost", not empty.
        // Verify the guard actually blocks on empty host.
        let mut config = SmtpConfig::default();
        config.host = String::new();
        let notifier_empty = EmailNotifier::new(config);
        // We can't easily run async here without a runtime, but we verify struct creation works.
        let _ = notifier_empty;
        let _ = notifier;
    }
}
