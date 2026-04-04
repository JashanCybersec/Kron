//! Syslog receivers for RFC 3164 and RFC 5424 messages.
//!
//! Two receivers are provided:
//!
//! - [`SyslogUdpReceiver`] — UDP/514. Fire-and-forget; no delivery guarantee.
//! - [`SyslogTcpReceiver`] — TCP/6514. Connection-oriented; handles disconnects.
//!
//! # Syslog → `KronEvent` mapping
//!
//! | Syslog field | `KronEvent` field |
//! |---|---|
//! | HOSTNAME | `hostname` |
//! | PRI severity | `severity` (mapped via [`syslog_severity_to_kron`]) |
//! | Full message | `raw_message` |
//! | Parsed `APPNAME` / TAG | `process_name` |
//! | Timestamp | `ts` (UTC) |
//! | Source IP | `src_ip` |
//!
//! # TCP TLS
//!
//! TCP TLS is deferred to Phase 2.
//! // TODO(#TBD, hardik, phase-2): Wrap TCP listener with tokio-rustls acceptor

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use kron_types::{EventCategory, EventSource, KronEvent, Severity, TenantId};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::broadcast;

use crate::metrics;

// ─── UDP receiver ─────────────────────────────────────────────────────────────

/// Receives syslog datagrams over UDP (RFC 3164 / RFC 5424).
///
/// Each datagram is parsed and published to the message bus as a [`KronEvent`].
/// UDP is connectionless — there are no delivery guarantees beyond what the
/// network provides.
pub struct SyslogUdpReceiver {
    bind_addr: SocketAddr,
    producer: Arc<dyn kron_bus::traits::BusProducer>,
    tenant_id: TenantId,
}

impl SyslogUdpReceiver {
    /// Creates a new UDP syslog receiver.
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        producer: Arc<dyn kron_bus::traits::BusProducer>,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            bind_addr,
            producer,
            tenant_id,
        }
    }

    /// Runs the UDP receiver until a shutdown signal is received.
    ///
    /// Binds the socket, then enters a receive loop. Parse errors are logged
    /// and skipped — a single malformed datagram does not stop the receiver.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CollectorError::Syslog`] if the socket cannot be bound.
    pub async fn run(
        self,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<(), crate::error::CollectorError> {
        let socket = UdpSocket::bind(self.bind_addr).await.map_err(|e| {
            crate::error::CollectorError::Syslog(format!("UDP bind {}: {e}", self.bind_addr))
        })?;

        tracing::info!(addr = %self.bind_addr, "Syslog UDP receiver started");

        let mut buf = vec![0u8; 65_536];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer)) => {
                            let data = buf[..len].to_vec();
                            self.handle_datagram(data, peer).await;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "UDP receive error");
                        }
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("Syslog UDP receiver shutting down");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Parses a single datagram and publishes the resulting event to the bus.
    async fn handle_datagram(&self, data: Vec<u8>, peer: SocketAddr) {
        let raw = match std::str::from_utf8(&data) {
            Ok(s) => s.trim_end_matches('\n').trim_end_matches('\r').to_owned(),
            Err(e) => {
                tracing::warn!(peer = %peer, error = %e, "Non-UTF-8 syslog datagram; skipped");
                metrics::record_events_rejected("parse", 1);
                return;
            }
        };

        metrics::record_events_received("syslog_udp", 1);

        let event = match parse_syslog_to_event(&raw, peer, self.tenant_id) {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!(peer = %peer, error = %e, raw = %raw, "Syslog parse failed; skipped");
                metrics::record_events_rejected("parse", 1);
                return;
            }
        };

        publish_event(&self.producer, &self.tenant_id, &event).await;
    }
}

// ─── TCP receiver ─────────────────────────────────────────────────────────────

/// Receives syslog messages over TCP (RFC 5424 / RFC 3164).
///
/// Each accepted connection is handled in a dedicated Tokio task. Messages are
/// newline-delimited. The connection is closed when the client disconnects or
/// the shutdown signal is received.
///
/// TLS is not yet implemented — see module-level TODO.
pub struct SyslogTcpReceiver {
    bind_addr: SocketAddr,
    producer: Arc<dyn kron_bus::traits::BusProducer>,
    tenant_id: TenantId,
}

impl SyslogTcpReceiver {
    /// Creates a new TCP syslog receiver.
    #[must_use]
    pub fn new(
        bind_addr: SocketAddr,
        producer: Arc<dyn kron_bus::traits::BusProducer>,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            bind_addr,
            producer,
            tenant_id,
        }
    }

    /// Runs the TCP receiver until a shutdown signal is received.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CollectorError::Syslog`] if the listener cannot be bound.
    pub async fn run(
        self,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<(), crate::error::CollectorError> {
        let listener = TcpListener::bind(self.bind_addr).await.map_err(|e| {
            crate::error::CollectorError::Syslog(format!("TCP bind {}: {e}", self.bind_addr))
        })?;

        tracing::info!(addr = %self.bind_addr, "Syslog TCP receiver started");

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            let producer = Arc::clone(&self.producer);
                            let tenant_id = self.tenant_id;
                            tokio::spawn(async move {
                                handle_tcp_connection(stream, peer, producer, tenant_id).await;
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "TCP accept error");
                        }
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("Syslog TCP receiver shutting down");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Reads newline-delimited syslog messages from a single TCP connection.
async fn handle_tcp_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    producer: Arc<dyn kron_bus::traits::BusProducer>,
    tenant_id: TenantId,
) {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                metrics::record_events_received("syslog_tcp", 1);
                let line = line.trim_end_matches('\r').to_owned();
                match parse_syslog_to_event(&line, peer, tenant_id) {
                    Ok(event) => publish_event(&producer, &tenant_id, &event).await,
                    Err(e) => {
                        tracing::warn!(
                            peer = %peer,
                            error = %e,
                            line = %line,
                            "Syslog TCP parse failed; skipped"
                        );
                        metrics::record_events_rejected("parse", 1);
                    }
                }
            }
            Ok(None) => {
                tracing::debug!(peer = %peer, "Syslog TCP connection closed by client");
                break;
            }
            Err(e) => {
                tracing::warn!(peer = %peer, error = %e, "Syslog TCP read error; closing connection");
                break;
            }
        }
    }
}

// ─── Syslog parsing ───────────────────────────────────────────────────────────

/// Parsed fields extracted from a syslog message.
struct SyslogFields {
    priority: u8,
    hostname: String,
    app_name: String,
    #[allow(dead_code)]
    message: String,
    ts: chrono::DateTime<Utc>,
}

/// Parses a syslog message (RFC 3164 or RFC 5424) into a [`KronEvent`].
///
/// Falls back to a raw-message event if the format is unrecognised.
///
/// # Errors
///
/// Returns a description string if the message cannot be parsed at all
/// (e.g. empty string or completely invalid encoding).
fn parse_syslog_to_event(
    raw: &str,
    peer: SocketAddr,
    tenant_id: TenantId,
) -> Result<KronEvent, String> {
    if raw.is_empty() {
        return Err("empty message".to_owned());
    }

    let fields = parse_syslog_fields(raw);
    let severity = syslog_severity_to_kron(fields.priority & 0x07);

    let mut builder = KronEvent::builder()
        .tenant_id(tenant_id)
        .source_type(EventSource::Syslog)
        .event_type("syslog_message")
        .ts(fields.ts)
        .raw(raw)
        .event_category(EventCategory::Other)
        .severity(severity);

    if !fields.hostname.is_empty() {
        builder = builder.hostname(fields.hostname);
    }
    if !fields.app_name.is_empty() {
        builder = builder.process_name(fields.app_name);
    }
    // Map peer IP to src_ip if it is IPv4.
    if let std::net::IpAddr::V4(v4) = peer.ip() {
        builder = builder.src_ip(v4);
    }

    builder.build().map_err(|e| e.to_string())
}

/// Parses RFC 3164 or RFC 5424 fields from a raw syslog message.
///
/// Falls back gracefully on malformed messages: missing fields become empty
/// strings and the timestamp falls back to `Utc::now()`.
fn parse_syslog_fields(raw: &str) -> SyslogFields {
    // All syslog messages start with an optional `<PRI>` header.
    let (priority, rest) = extract_priority(raw);

    // RFC 5424: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG`
    // RFC 3164: `<PRI>MONTH DD HH:MM:SS HOSTNAME TAG: MSG`
    // Detect by checking if the first token after priority is a digit (version).
    let trimmed = rest.trim_start();
    if trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        parse_5424(priority, trimmed)
    } else {
        parse_3164(priority, trimmed)
    }
}

/// Extracts the `<PRI>` value from the start of a syslog message.
///
/// Returns `(priority, remainder)`. Priority is 0 if absent or invalid.
fn extract_priority(raw: &str) -> (u8, &str) {
    if !raw.starts_with('<') {
        return (0, raw);
    }
    let end = raw.find('>').unwrap_or(0);
    if end == 0 {
        return (0, raw);
    }
    let pri_str = &raw[1..end];
    let pri: u8 = pri_str.parse().unwrap_or(0);
    (pri, &raw[end + 1..])
}

/// Parses an RFC 5424 syslog message (after the `<PRI>` prefix is stripped).
///
/// Format: `VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG`
fn parse_5424(priority: u8, rest: &str) -> SyslogFields {
    let mut tokens = rest.splitn(8, ' ');
    let _version = tokens.next().unwrap_or("-");
    let ts_str = tokens.next().unwrap_or("-");
    let hostname = tokens.next().unwrap_or("-").to_owned();
    let app_name = tokens.next().unwrap_or("-").to_owned();
    let _proc_id = tokens.next().unwrap_or("-");
    let _msg_id = tokens.next().unwrap_or("-");
    let _sd = tokens.next().unwrap_or("-");
    let message = tokens.next().unwrap_or("").to_owned();

    let ts = chrono::DateTime::parse_from_rfc3339(ts_str)
        .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

    SyslogFields {
        priority,
        hostname: nilval_or(hostname),
        app_name: nilval_or(app_name),
        message,
        ts,
    }
}

/// Parses an RFC 3164 syslog message (after the `<PRI>` prefix is stripped).
///
/// Format: `MONTH DD HH:MM:SS HOSTNAME TAG: MSG`
fn parse_3164(priority: u8, rest: &str) -> SyslogFields {
    // RFC 3164 timestamp: "Jan  1 00:00:00"  (15 chars, space-padded day)
    let (ts, after_ts) = if rest.len() >= 15 {
        let ts_str = &rest[..15];
        let ts = parse_3164_timestamp(ts_str);
        (ts, rest[15..].trim_start())
    } else {
        (Utc::now(), rest)
    };

    let mut parts = after_ts.splitn(3, ' ');
    let hostname = parts.next().unwrap_or("").to_owned();
    let tag_and_msg =
        parts.next().map(str::to_owned).unwrap_or_default() + parts.next().unwrap_or("");
    let (app_name, message) = split_tag(tag_and_msg.trim());

    SyslogFields {
        priority,
        hostname,
        app_name,
        message,
        ts,
    }
}

/// Parses an RFC 3164 timestamp: `"Mon DD HH:MM:SS"`.
///
/// Year is assumed to be the current year. Falls back to `Utc::now()` on error.
fn parse_3164_timestamp(ts_str: &str) -> chrono::DateTime<Utc> {
    // Example: "Jan  1 12:00:00"
    let now = Utc::now();
    let with_year = format!("{} {}", now.format("%Y"), ts_str.trim());
    chrono::NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")
        .map(|ndt| chrono::DateTime::from_naive_utc_and_offset(ndt, Utc))
        .unwrap_or(now)
}

/// Splits a syslog TAG field into (`app_name`, `message`).
///
/// RFC 3164 TAG: `"sshd[1234]: message"` → `("sshd", "message")`.
fn split_tag(tag_and_msg: &str) -> (String, String) {
    // Tag ends at first '[', ':', or space.
    let end = tag_and_msg
        .find(['[', ':', ' '])
        .unwrap_or(tag_and_msg.len());
    let app = tag_and_msg[..end].to_owned();
    let msg = tag_and_msg[end..]
        .trim_start_matches(['[', ']', ':', ' '])
        .to_owned();
    (app, msg)
}

/// Returns an empty string for RFC 5424 nil-value (`-`).
fn nilval_or(s: String) -> String {
    if s == "-" {
        String::new()
    } else {
        s
    }
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

/// Converts a syslog severity (0–7) to a KRON [`Severity`].
///
/// | Syslog | KRON |
/// |---|---|
/// | 0 Emergency | Critical (P1) |
/// | 1 Alert | Critical (P1) |
/// | 2 Critical | Critical (P1) |
/// | 3 Error | High (P2) |
/// | 4 Warning | Medium (P3) |
/// | 5 Notice | Low (P4) |
/// | 6 Informational | Info |
/// | 7 Debug | Info |
fn syslog_severity_to_kron(sev: u8) -> Severity {
    match sev {
        0..=2 => Severity::Critical,
        3 => Severity::High,
        4 => Severity::Medium,
        5 => Severity::Low,
        _ => Severity::Info,
    }
}

// ─── Bus publish helper ───────────────────────────────────────────────────────

/// Serialises and publishes a single [`KronEvent`] to `kron.raw.{tenant_id}`.
async fn publish_event(
    producer: &Arc<dyn kron_bus::traits::BusProducer>,
    tenant_id: &TenantId,
    event: &KronEvent,
) {
    let topic = kron_bus::topics::raw_events(tenant_id);
    let payload = match serde_json::to_vec(event) {
        Ok(v) => Bytes::from(v),
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialise syslog event; skipped");
            metrics::record_events_rejected("validation", 1);
            return;
        }
    };

    let key = Bytes::from(tenant_id.to_string());
    match producer
        .send(&topic, Some(key), payload, std::collections::HashMap::new())
        .await
    {
        Ok(_) => {
            metrics::record_events_published(1);
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to publish syslog event to bus");
            metrics::record_events_rejected("bus_error", 1);
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc5424_when_valid_then_fields_extracted() {
        let msg = "<34>1 2026-03-22T10:00:00Z webserver sshd 1234 - - Failed password";
        let fields = parse_syslog_fields(msg);
        assert_eq!(fields.hostname, "webserver");
        assert_eq!(fields.app_name, "sshd");
        assert!(fields.message.contains("Failed password"));
        assert_eq!(fields.priority, 34);
    }

    #[test]
    fn test_parse_rfc3164_when_valid_then_fields_extracted() {
        let msg = "<13>Mar 22 10:00:00 myhost sshd[123]: Invalid user";
        let fields = parse_syslog_fields(msg);
        assert_eq!(fields.hostname, "myhost");
        assert_eq!(fields.app_name, "sshd");
        assert_eq!(fields.priority, 13);
    }

    #[test]
    fn test_syslog_severity_emergency_maps_to_critical() {
        assert_eq!(syslog_severity_to_kron(0), Severity::Critical);
        assert_eq!(syslog_severity_to_kron(1), Severity::Critical);
        assert_eq!(syslog_severity_to_kron(2), Severity::Critical);
    }

    #[test]
    fn test_syslog_severity_warning_maps_to_medium() {
        assert_eq!(syslog_severity_to_kron(4), Severity::Medium);
    }

    #[test]
    fn test_extract_priority_when_absent_then_zero() {
        let (pri, rest) = extract_priority("no priority here");
        assert_eq!(pri, 0);
        assert_eq!(rest, "no priority here");
    }

    #[test]
    fn test_split_tag_when_bracket_format_then_app_extracted() {
        let (app, msg) = split_tag("sshd[1234]: message text");
        assert_eq!(app, "sshd");
        assert_eq!(msg, "message text");
    }
}
