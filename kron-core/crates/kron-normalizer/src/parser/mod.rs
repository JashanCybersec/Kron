//! Format detection and dispatch for the KRON normalizer.
//!
//! [`detect_and_parse`] inspects the `raw` field of an event and delegates to
//! the appropriate sub-parser. Events from gRPC agents are already fully
//! structured and only need enrichment + dedup — they are passed through
//! without re-parsing.
//!
//! ## Detection order
//!
//! 1. Agent events (`LinuxEbpf`, `WindowsEtw`) — already structured; skip
//! 2. `CEF:` marker present → [`cef`] parser
//! 3. `LEEF:` marker present → [`leef`] parser
//! 4. Raw starts with `{` → [`json_event`] parser
//! 5. Otherwise → raw already parsed by collector (syslog, netflow, etc.);
//!    pass through without additional parsing

pub mod cef;
pub mod json_event;
pub mod leef;

use kron_types::{EventSource, KronEvent};

/// The format detected for an event's raw content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventFormat {
    /// Agent-originated event — already fully structured.
    AgentStructured,
    /// ArcSight CEF (Common Event Format).
    Cef,
    /// IBM LEEF (Log Event Extended Format).
    Leef,
    /// JSON object.
    Json,
    /// Already parsed by the collector (syslog, netflow, DHCP, etc.).
    CollectorParsed,
}

impl EventFormat {
    /// Returns the label string used in Prometheus metrics.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::AgentStructured => "agent",
            Self::Cef => "cef",
            Self::Leef => "leef",
            Self::Json => "json",
            Self::CollectorParsed => "collector_parsed",
        }
    }
}

/// Detects the format of `event.raw` based on `event.source_type` and content.
#[must_use]
pub fn detect(event: &KronEvent) -> EventFormat {
    match event.source_type {
        EventSource::LinuxEbpf | EventSource::WindowsEtw => EventFormat::AgentStructured,
        _ => detect_by_content(&event.raw),
    }
}

/// Detects format from the raw string content alone.
fn detect_by_content(raw: &str) -> EventFormat {
    if cef::is_cef(raw) {
        EventFormat::Cef
    } else if leef::is_leef(raw) {
        EventFormat::Leef
    } else if json_event::is_json_object(raw) {
        EventFormat::Json
    } else {
        EventFormat::CollectorParsed
    }
}

/// Detects the format and applies any additional parsing to `event`.
///
/// For `AgentStructured` and `CollectorParsed` formats no parsing is done
/// (the event is already sufficiently structured). For CEF, LEEF, and JSON
/// the respective parser overlays additional fields onto the event.
///
/// Parse failures are logged as warnings but do not abort processing; the
/// event is published as-is with the fields that were successfully extracted.
///
/// Returns the detected format for metrics labelling.
pub fn detect_and_parse(event: &mut KronEvent) -> EventFormat {
    let format = detect(event);

    match format {
        EventFormat::Cef => {
            let raw = event.raw.clone();
            if let Err(e) = cef::parse_into(&raw, event) {
                tracing::warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "CEF parse failed; event published with partial fields"
                );
            }
        }
        EventFormat::Leef => {
            let raw = event.raw.clone();
            if let Err(e) = leef::parse_into(&raw, event) {
                tracing::warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "LEEF parse failed; event published with partial fields"
                );
            }
        }
        EventFormat::Json => {
            let raw = event.raw.clone();
            if let Err(e) = json_event::parse_into(&raw, event) {
                tracing::warn!(
                    event_id = %event.event_id,
                    error = %e,
                    "JSON parse failed; event published with partial fields"
                );
            }
        }
        EventFormat::AgentStructured | EventFormat::CollectorParsed => {}
    }

    format
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kron_types::{Severity, TenantId};
    use uuid::Uuid;

    fn make_event(source: EventSource, raw: &str) -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::from_uuid(Uuid::new_v4()))
            .source_type(source)
            .event_type("placeholder")
            .raw(raw)
            .severity(Severity::Info)
            .build()
            .unwrap()
    }

    #[test]
    fn test_agent_event_detected_as_structured() {
        let event = make_event(EventSource::LinuxEbpf, "raw content");
        assert_eq!(detect(&event), EventFormat::AgentStructured);
    }

    #[test]
    fn test_cef_content_detected_as_cef() {
        let event = make_event(EventSource::Syslog, "CEF:0|V|P|1|100|Name|5|src=1.2.3.4");
        assert_eq!(detect(&event), EventFormat::Cef);
    }

    #[test]
    fn test_leef_content_detected_as_leef() {
        let event = make_event(EventSource::Syslog, "LEEF:1.0|V|P|1.0|E1|\tsrc=1.2.3.4");
        assert_eq!(detect(&event), EventFormat::Leef);
    }

    #[test]
    fn test_json_content_detected_as_json() {
        let event = make_event(EventSource::HttpIntake, "{\"key\":\"val\"}");
        assert_eq!(detect(&event), EventFormat::Json);
    }

    #[test]
    fn test_syslog_content_detected_as_collector_parsed() {
        let event = make_event(
            EventSource::Syslog,
            "<13>Jan 15 10:30:45 host sshd: accepted",
        );
        assert_eq!(detect(&event), EventFormat::CollectorParsed);
    }
}
