//! JSON structured event parser.
//!
//! Handles raw event bodies that are JSON objects. Applies well-known
//! top-level keys to canonical [`KronEvent`] fields; all other keys are
//! stored in `event.fields`.
//!
//! Used when `raw` starts with `{` (bare JSON) or when the syslog body
//! is a JSON object.

use std::net::Ipv4Addr;

use kron_types::{EventCategory, KronEvent, Severity};
use serde_json::Value;

use crate::timestamp;

// ─── Detection ───────────────────────────────────────────────────────────────

/// Returns `true` if `raw` looks like a JSON object.
#[must_use]
pub fn is_json_object(raw: &str) -> bool {
    raw.trim_start().starts_with('{')
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Parses `raw` as a JSON object and overlays extracted fields onto `event`.
///
/// Known top-level keys are mapped to canonical fields. Unknown keys are
/// stored in `event.fields` as their JSON string representation.
///
/// # Errors
///
/// Returns `Err` if `raw` is not valid JSON or is not a JSON object.
pub fn parse_into(raw: &str, event: &mut KronEvent) -> Result<(), String> {
    let value: Value = serde_json::from_str(raw).map_err(|e| format!("JSON parse error: {e}"))?;

    let obj = value.as_object().ok_or("JSON value is not an object")?;

    for (key, val) in obj {
        apply_field(key, val, event);
    }

    Ok(())
}

// ─── Field mapping ───────────────────────────────────────────────────────────

/// Maps a JSON key-value pair to a canonical `KronEvent` field.
fn apply_field(key: &str, val: &Value, event: &mut KronEvent) {
    match key {
        // Timing
        "timestamp" | "ts" | "@timestamp" | "time" | "eventTime" => {
            if let Some(s) = val.as_str() {
                if let Some(dt) = timestamp::parse_timestamp(s) {
                    event.ts = dt;
                }
            }
        }

        // Network
        "src_ip" | "sourceAddress" | "src" => {
            event.src_ip = val.as_str().and_then(|s| s.parse::<Ipv4Addr>().ok());
        }
        "dst_ip" | "destinationAddress" | "dst" => {
            event.dst_ip = val.as_str().and_then(|s| s.parse::<Ipv4Addr>().ok());
        }
        "src_port" | "sourcePort" => {
            event.src_port = as_u16(val);
        }
        "dst_port" | "destinationPort" => {
            event.dst_port = as_u16(val);
        }
        "protocol" | "proto" => {
            event.protocol = val.as_str().map(str::to_ascii_lowercase);
        }
        "bytes_in" | "bytesIn" => {
            event.bytes_in = val.as_u64();
        }
        "bytes_out" | "bytesOut" => {
            event.bytes_out = val.as_u64();
        }

        // Host
        "hostname" | "host" | "srcHost" => {
            if event.hostname.is_none() {
                event.hostname = val.as_str().map(str::to_owned);
            }
        }

        // User
        "username" | "user" | "user_name" | "actor" => {
            if event.user_name.is_none() {
                event.user_name = val.as_str().map(str::to_owned);
            }
        }
        "user_domain" | "domain" => {
            event.user_domain = val.as_str().map(str::to_owned);
        }

        // Process
        "process_name" | "proc" | "process" | "comm" => {
            event.process_name = val.as_str().map(str::to_owned);
        }
        "pid" | "process_pid" => {
            event.process_pid = val.as_u64().map(|n| n as u32);
        }
        "ppid" | "process_ppid" => {
            event.process_ppid = val.as_u64().map(|n| n as u32);
        }
        "cmdline" | "process_cmdline" | "args" => {
            event.process_cmdline = val.as_str().map(str::to_owned);
        }
        "exe" | "process_path" => {
            event.process_path = val.as_str().map(str::to_owned);
        }

        // File
        "file_path" | "filePath" | "path" => {
            event.file_path = val.as_str().map(str::to_owned);
        }
        "file_name" | "fileName" => {
            event.file_name = val.as_str().map(str::to_owned);
        }
        "file_hash" | "sha256" | "hash" => {
            event.file_hash = val.as_str().map(str::to_owned);
        }
        "file_size" | "fileSize" => {
            event.file_size = val.as_u64();
        }

        // Classification
        "event_type" | "eventType" | "type" => {
            if let Some(s) = val.as_str() {
                event.event_type = s.to_owned();
            }
        }
        "severity" | "sev" | "level" => {
            event.severity = parse_severity(val);
        }
        "category" | "event_category" => {
            event.event_category = val.as_str().and_then(parse_category);
        }
        "message" | "msg" | "description" => {
            if let Some(s) = val.as_str() {
                event.fields.insert("message".to_owned(), s.to_owned());
            }
        }

        // Auth
        "auth_result" | "result" | "outcome" => {
            event.fields.insert(key.to_owned(), json_to_string(val));
        }

        // Catch-all: flatten nested objects and store remaining keys
        _ => {
            event.fields.insert(key.to_owned(), json_to_string(val));
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extracts a `u16` from a JSON number or numeric string.
fn as_u16(val: &Value) -> Option<u16> {
    val.as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| val.as_str()?.parse::<u16>().ok())
}

/// Converts a JSON [`Value`] to a compact string for storage in `event.fields`.
fn json_to_string(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Parses a string into a Kron [`Severity`].
fn parse_severity(val: &Value) -> Severity {
    match val {
        Value::Number(n) => match n.as_u64().unwrap_or(0) {
            0..=2 => Severity::Info,
            3..=4 => Severity::Low,
            5..=6 => Severity::Medium,
            7..=8 => Severity::High,
            _ => Severity::Critical,
        },
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "info" | "informational" | "debug" | "notice" => Severity::Info,
            "low" | "minor" => Severity::Low,
            "medium" | "moderate" | "warning" | "warn" => Severity::Medium,
            "high" | "major" | "error" | "err" => Severity::High,
            "critical" | "crit" | "fatal" | "emergency" | "emerg" | "alert" => Severity::Critical,
            _ => Severity::Info,
        },
        _ => Severity::Info,
    }
}

/// Parses a string into an [`EventCategory`].
fn parse_category(s: &str) -> Option<EventCategory> {
    let lower = s.to_ascii_lowercase();
    if lower.contains("auth") || lower.contains("login") || lower.contains("logon") {
        Some(EventCategory::Authentication)
    } else if lower.contains("network") || lower.contains("traffic") {
        Some(EventCategory::Network)
    } else if lower.contains("file") || lower.contains("fs") {
        Some(EventCategory::File)
    } else if lower.contains("process") || lower.contains("exec") {
        Some(EventCategory::Process)
    } else if lower.contains("account") || lower.contains("user_mgmt") {
        Some(EventCategory::Account)
    } else if lower.contains("cloud") || lower.contains("aws") || lower.contains("azure") {
        Some(EventCategory::Cloud)
    } else {
        Some(EventCategory::Other)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kron_types::{EventSource, Severity, TenantId};
    use uuid::Uuid;

    fn blank_event() -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::from_uuid(Uuid::new_v4()))
            .source_type(EventSource::HttpIntake)
            .event_type("placeholder")
            .raw("{}")
            .severity(Severity::Info)
            .build()
            .unwrap()
    }

    #[test]
    fn test_is_json_object_detects_opening_brace() {
        assert!(is_json_object("{\"key\":\"value\"}"));
        assert!(is_json_object("  { }"));
        assert!(!is_json_object("not json"));
        assert!(!is_json_object("[1,2,3]"));
    }

    #[test]
    fn test_parse_json_network_fields() {
        let mut event = blank_event();
        let raw = r#"{"src_ip":"10.0.0.1","dst_ip":"8.8.8.8","src_port":1234,"protocol":"tcp"}"#;
        parse_into(raw, &mut event).unwrap();

        assert_eq!(event.src_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(event.dst_ip, Some("8.8.8.8".parse().unwrap()));
        assert_eq!(event.src_port, Some(1234));
        assert_eq!(event.protocol.as_deref(), Some("tcp"));
    }

    #[test]
    fn test_parse_json_nested_fields_go_to_fields_map() {
        let mut event = blank_event();
        let raw = r#"{"custom_key":"custom_val","count":42}"#;
        parse_into(raw, &mut event).unwrap();

        assert_eq!(
            event.fields.get("custom_key").map(|s| s.as_str()),
            Some("custom_val")
        );
    }

    #[test]
    fn test_parse_json_returns_error_on_invalid_json() {
        let mut event = blank_event();
        assert!(parse_into("not-json", &mut event).is_err());
    }
}
