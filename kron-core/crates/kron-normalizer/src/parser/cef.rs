//! CEF (Common Event Format) parser.
//!
//! Parses ArcSight CEF messages embedded in raw log lines, including CEF
//! carried inside syslog wrappers (`<13>Jan 15 ... CEF:0|...`).
//!
//! ## CEF wire format
//!
//! ```text
//! CEF:Version|Vendor|Product|DevVersion|EventClassId|Name|Severity|Extension
//! ```
//!
//! Extension is a series of `key=value` pairs separated by spaces.
//! Values that contain spaces must be escaped with `\` in compliant senders;
//! this parser uses a position-based approach that handles most real-world logs.

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use kron_types::{EventCategory, KronEvent, Severity};
use regex::Regex;

use crate::timestamp;

// ─── Detection ───────────────────────────────────────────────────────────────

/// Returns `true` if `raw` contains a CEF marker (`CEF:` followed by a digit).
#[must_use]
pub fn is_cef(raw: &str) -> bool {
    raw.find("CEF:")
        .and_then(|i| raw.get(i + 4..i + 5))
        .map(|c| c.chars().next().map_or(false, |ch| ch.is_ascii_digit()))
        .unwrap_or(false)
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Parses a CEF message and applies extracted fields to `event`.
///
/// Locates the `CEF:` marker in `raw`, splits the 7-field header, then
/// parses the extension key-value block. Unknown extension keys are stored in
/// `event.fields`.
///
/// # Errors
///
/// Returns `Err` if the CEF marker is missing or the header has fewer than
/// 7 pipe-separated fields.
pub fn parse_into(raw: &str, event: &mut KronEvent) -> Result<(), String> {
    let cef_start = raw.find("CEF:").ok_or("CEF marker not found")?;
    let cef_str = &raw[cef_start..];

    let (vendor, product, event_class_id, name, severity_str, extension) = split_header(cef_str)?;

    // Stamp event type from product + class ID
    event.event_type = format!("{}_{}", sanitize(product), sanitize(event_class_id));
    event.severity = parse_severity(severity_str);

    event
        .fields
        .insert("cef_vendor".to_owned(), vendor.to_owned());
    event
        .fields
        .insert("cef_product".to_owned(), product.to_owned());
    event.fields.insert("cef_name".to_owned(), name.to_owned());
    event
        .fields
        .insert("cef_class_id".to_owned(), event_class_id.to_owned());

    for (key, value) in parse_extension(extension) {
        apply_field(&key, &value, event);
    }

    Ok(())
}

// ─── Header splitting ────────────────────────────────────────────────────────

/// Splits the CEF string into (vendor, product, devVersion, classId, name,
/// severity, extension).
///
/// Returns `(vendor, product, event_class_id, name, severity, extension)`.
fn split_header(cef_str: &str) -> Result<(&str, &str, &str, &str, &str, &str), String> {
    // Up to 8 parts: CEF:ver | vendor | product | devver | classId | name | sev | ext
    let mut parts = cef_str.splitn(8, '|');

    let _ver = parts.next().ok_or("missing version")?; // "CEF:0"
    let vendor = parts.next().ok_or("missing vendor")?;
    let product = parts.next().ok_or("missing product")?;
    let _devver = parts.next().ok_or("missing device version")?;
    let class_id = parts.next().ok_or("missing event class ID")?;
    let name = parts.next().ok_or("missing event name")?;
    let severity = parts.next().ok_or("missing severity")?;
    let extension = parts.next().unwrap_or("");

    Ok((vendor, product, class_id, name, severity, extension))
}

// ─── Extension parser ────────────────────────────────────────────────────────

/// Returns the static regex used to locate `key=` boundaries in the extension.
fn key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Match optional leading space + word-chars key + '='
        Regex::new(r"(?:^|\s)([a-zA-Z][a-zA-Z0-9_]*)=").expect("valid regex")
    })
}

/// Parses the CEF extension string into `(key, value)` pairs.
///
/// Uses key-boundary positions to handle values that contain spaces.
fn parse_extension(ext: &str) -> Vec<(String, String)> {
    let ext = ext.trim();
    if ext.is_empty() {
        return Vec::new();
    }

    let re = key_regex();
    let matches: Vec<_> = re.find_iter(ext).collect();
    let mut result = Vec::with_capacity(matches.len());

    for (i, m) in matches.iter().enumerate() {
        let match_str = m.as_str();
        // Key = trimmed match, minus trailing '='
        let key = match_str.trim().trim_end_matches('=').to_owned();
        let val_start = m.end();
        let val_end = if i + 1 < matches.len() {
            matches[i + 1].start()
        } else {
            ext.len()
        };

        let value = ext
            .get(val_start..val_end)
            .map(str::trim_end)
            .unwrap_or("")
            .to_owned();

        if !key.is_empty() {
            result.push((key, value));
        }
    }
    result
}

// ─── Field mapping ───────────────────────────────────────────────────────────

/// Applies a single CEF extension key-value pair to canonical `KronEvent` fields.
fn apply_field(key: &str, value: &str, event: &mut KronEvent) {
    match key {
        "src" | "sourceAddress" => {
            event.src_ip = value.parse::<Ipv4Addr>().ok();
        }
        "dst" | "destinationAddress" => {
            event.dst_ip = value.parse::<Ipv4Addr>().ok();
        }
        "spt" | "sourcePort" => {
            event.src_port = value.parse::<u16>().ok();
        }
        "dpt" | "destinationPort" => {
            event.dst_port = value.parse::<u16>().ok();
        }
        "proto" | "transportProtocol" => {
            event.protocol = Some(value.to_ascii_lowercase());
        }
        "in" | "bytesIn" => {
            event.bytes_in = value.parse::<u64>().ok();
        }
        "out" | "bytesOut" => {
            event.bytes_out = value.parse::<u64>().ok();
        }
        "shost" | "sourceHostName" if event.hostname.is_none() => {
            event.hostname = Some(value.to_owned());
        }
        "dhost" | "destinationHostName" => {
            event
                .fields
                .insert("dst_hostname".to_owned(), value.to_owned());
        }
        "suser" | "sourceUserName" if event.user_name.is_none() => {
            event.user_name = Some(value.to_owned());
        }
        "duser" | "destinationUserName" if event.user_name.is_none() => {
            event.user_name = Some(value.to_owned());
        }
        "sproc" | "sourceProcessName" => {
            event.process_name = Some(value.to_owned());
        }
        "spid" | "sourceProcessId" => {
            event.process_pid = value.parse::<u32>().ok();
        }
        "fname" | "filePath" => {
            event.file_name = Some(value.to_owned());
        }
        "rt" | "deviceReceiptTime" | "end" | "start" => {
            if let Some(dt) = timestamp::parse_timestamp(value) {
                event.ts = dt;
            }
        }
        "msg" | "message" => {
            event.fields.insert("message".to_owned(), value.to_owned());
        }
        "cat" | "deviceEventCategory" => {
            event.event_category = map_category(value);
        }
        _ => {
            event.fields.insert(key.to_owned(), value.to_owned());
        }
    }
}

// ─── Severity / category helpers ─────────────────────────────────────────────

/// Maps a CEF severity string (0–10 or name) to a Kron [`Severity`].
fn parse_severity(s: &str) -> Severity {
    match s.trim() {
        "0" | "1" | "2" | "3" => Severity::Low,
        "4" | "5" | "6" => Severity::Medium,
        "7" | "8" => Severity::High,
        "9" | "10" => Severity::Critical,
        sev if sev.eq_ignore_ascii_case("low") => Severity::Low,
        sev if sev.eq_ignore_ascii_case("medium") => Severity::Medium,
        sev if sev.eq_ignore_ascii_case("high") => Severity::High,
        sev if sev.eq_ignore_ascii_case("very-high") => Severity::Critical,
        _ => Severity::Info,
    }
}

/// Heuristically maps a CEF category string to an [`EventCategory`].
fn map_category(cat: &str) -> Option<EventCategory> {
    let lower = cat.to_ascii_lowercase();
    if lower.contains("auth") || lower.contains("login") || lower.contains("logon") {
        Some(EventCategory::Authentication)
    } else if lower.contains("network") || lower.contains("traffic") || lower.contains("flow") {
        Some(EventCategory::Network)
    } else if lower.contains("file") || lower.contains("disk") {
        Some(EventCategory::File)
    } else if lower.contains("process") || lower.contains("exec") {
        Some(EventCategory::Process)
    } else if lower.contains("account") || lower.contains("user") {
        Some(EventCategory::Account)
    } else {
        Some(EventCategory::Other)
    }
}

/// Converts a string to a snake_case event-type component.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
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
            .source_type(EventSource::Syslog)
            .event_type("placeholder")
            .raw("raw")
            .severity(Severity::Info)
            .build()
            .unwrap()
    }

    #[test]
    fn test_is_cef_detects_marker() {
        assert!(is_cef("CEF:0|Vendor|Product|1.0|100|Login|5|"));
        assert!(is_cef(
            "<13>Jan 15 10:30:45 host CEF:0|ArcSight|Logger|1|100|Name|5|"
        ));
        assert!(!is_cef("Not a CEF message"));
        assert!(!is_cef("CEF: not-a-digit"));
    }

    #[test]
    fn test_parse_cef_network_fields() {
        let mut event = blank_event();
        parse_into(
            "CEF:0|V|P|1.0|100|Name|5|src=10.0.0.1 dst=8.8.8.8 spt=1234 dpt=443 proto=tcp",
            &mut event,
        )
        .unwrap();

        assert_eq!(event.src_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(event.dst_ip, Some("8.8.8.8".parse().unwrap()));
        assert_eq!(event.src_port, Some(1234));
        assert_eq!(event.dst_port, Some(443));
        assert_eq!(event.protocol.as_deref(), Some("tcp"));
    }

    #[test]
    fn test_parse_cef_severity_high() {
        let mut event = blank_event();
        parse_into("CEF:0|V|P|1.0|100|Name|7|", &mut event).unwrap();
        assert!(matches!(event.severity, Severity::High));
    }

    #[test]
    fn test_parse_cef_all_standard_field_types() {
        let mut event = blank_event();
        parse_into(
            "CEF:0|ArcSight|Logger|6.0|auth:1|User Login|5|suser=alice sproc=sshd spid=1234 in=512 out=256",
            &mut event,
        )
        .unwrap();

        assert_eq!(event.user_name.as_deref(), Some("alice"));
        assert_eq!(event.process_name.as_deref(), Some("sshd"));
        assert_eq!(event.process_pid, Some(1234));
        assert_eq!(event.bytes_in, Some(512));
        assert_eq!(event.bytes_out, Some(256));
    }
}
