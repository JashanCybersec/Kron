//! LEEF (Log Event Extended Format) parser.
//!
//! Supports LEEF 1.0 and LEEF 2.0 (configurable delimiter).
//!
//! ## LEEF 1.0 wire format
//!
//! ```text
//! LEEF:1.0|Vendor|Product|Version|EventId|key\tvalue\tkey2\tvalue2
//! ```
//!
//! ## LEEF 2.0 wire format
//!
//! ```text
//! LEEF:2.0|Vendor|Product|Version|EventId|DelimiterChar|key<delim>value...
//! ```

use std::net::Ipv4Addr;

use kron_types::{EventCategory, KronEvent, Severity};

use crate::timestamp;

// ─── Detection ───────────────────────────────────────────────────────────────

/// Returns `true` if `raw` contains a LEEF marker (`LEEF:` followed by a digit).
#[must_use]
pub fn is_leef(raw: &str) -> bool {
    raw.find("LEEF:")
        .and_then(|i| raw.get(i + 5..i + 6))
        .map(|c| c.chars().next().map_or(false, |ch| ch.is_ascii_digit()))
        .unwrap_or(false)
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

/// Parses a LEEF message and applies extracted fields to `event`.
///
/// Detects LEEF 1.0 (tab delimiter) and LEEF 2.0 (custom delimiter).
/// Unknown attribute keys go to `event.fields`.
///
/// # Errors
///
/// Returns `Err` if the LEEF marker is missing or the header is malformed.
pub fn parse_into(raw: &str, event: &mut KronEvent) -> Result<(), String> {
    let leef_start = raw.find("LEEF:").ok_or("LEEF marker not found")?;
    let leef_str = &raw[leef_start..];

    let (version, vendor, product, event_id, attrs_str) = split_header(leef_str)?;

    // Determine attribute delimiter: LEEF 2.0 has a 6th header field specifying it
    let delimiter = if version.starts_with('2') {
        extract_leef2_delimiter(attrs_str)
    } else {
        '\t'
    };

    // The actual attributes start after the delimiter spec in LEEF 2.0
    let attrs_body = if version.starts_with('2') {
        skip_delimiter_field(attrs_str)
    } else {
        attrs_str
    };

    event.event_type = format!("{}_leef_{}", sanitize(product), sanitize(event_id));
    event
        .fields
        .insert("leef_vendor".to_owned(), vendor.to_owned());
    event
        .fields
        .insert("leef_product".to_owned(), product.to_owned());
    event
        .fields
        .insert("leef_event_id".to_owned(), event_id.to_owned());

    for (key, value) in parse_attributes(attrs_body, delimiter) {
        apply_field(key, value, event);
    }

    Ok(())
}

// ─── Header splitting ────────────────────────────────────────────────────────

/// Splits the LEEF string into (version, vendor, product, eventId, attrs_string).
fn split_header(leef_str: &str) -> Result<(&str, &str, &str, &str, &str), String> {
    let mut parts = leef_str.splitn(6, '|');
    let ver_field = parts.next().ok_or("missing version")?; // "LEEF:1.0"
    let vendor = parts.next().ok_or("missing vendor")?;
    let product = parts.next().ok_or("missing product")?;
    let _dev_ver = parts.next().ok_or("missing device version")?;
    let event_id = parts.next().ok_or("missing event ID")?;
    let attrs = parts.next().unwrap_or("");

    let version = ver_field.trim_start_matches("LEEF:");
    Ok((version, vendor, product, event_id, attrs))
}

/// Extracts the LEEF 2.0 delimiter character from the sixth header field.
///
/// The field may be a literal char (`^`) or a hex sequence (`x5E`).
fn extract_leef2_delimiter(attrs_str: &str) -> char {
    // In LEEF 2.0, attrs_str starts with the delimiter field: "^|attrs..."
    // or "x5E|attrs..." — take everything up to the first '|'
    let delim_field = attrs_str.split('|').next().unwrap_or("");
    if delim_field.is_empty() {
        return '\t';
    }
    if delim_field.starts_with('x') || delim_field.starts_with('X') {
        u8::from_str_radix(&delim_field[1..], 16)
            .ok()
            .and_then(|b| char::from_u32(u32::from(b)))
            .unwrap_or('\t')
    } else {
        delim_field.chars().next().unwrap_or('\t')
    }
}

/// Skips the LEEF 2.0 delimiter field, returning only the attributes body.
fn skip_delimiter_field(attrs_str: &str) -> &str {
    attrs_str
        .find('|')
        .map(|i| &attrs_str[i + 1..])
        .unwrap_or(attrs_str)
}

// ─── Attribute parser ────────────────────────────────────────────────────────

/// Parses LEEF attribute string into `(key, value)` string pairs.
///
/// Attributes are separated by `delimiter`. Each attribute is `key=value`.
fn parse_attributes<'a>(attrs: &'a str, delimiter: char) -> Vec<(&'a str, &'a str)> {
    attrs
        .split(delimiter)
        .filter_map(|attr| {
            let eq = attr.find('=')?;
            let key = attr[..eq].trim();
            let value = attr[eq + 1..].trim();
            if key.is_empty() {
                None
            } else {
                Some((key, value))
            }
        })
        .collect()
}

// ─── Field mapping ───────────────────────────────────────────────────────────

/// Maps a LEEF attribute key-value pair to canonical `KronEvent` fields.
fn apply_field(key: &str, value: &str, event: &mut KronEvent) {
    match key {
        "src" => {
            event.src_ip = value.parse::<Ipv4Addr>().ok();
        }
        "dst" => {
            event.dst_ip = value.parse::<Ipv4Addr>().ok();
        }
        "srcPort" => {
            event.src_port = value.parse::<u16>().ok();
        }
        "dstPort" => {
            event.dst_port = value.parse::<u16>().ok();
        }
        "proto" => {
            event.protocol = Some(value.to_ascii_lowercase());
        }
        "usrName" | "identUsername" => {
            if event.user_name.is_none() {
                event.user_name = Some(value.to_owned());
            }
        }
        "srcPreNAT" | "srcPostNAT" => {
            event.fields.insert(key.to_owned(), value.to_owned());
        }
        "sev" | "severity" => {
            event.severity = parse_severity(value);
        }
        "cat" | "devEventCategory" => {
            event.event_category = map_category(value);
        }
        "devTime" | "eventTime" => {
            if let Some(dt) = timestamp::parse_timestamp(value) {
                event.ts = dt;
            }
        }
        "identSrc" | "srcHost" if event.hostname.is_none() => {
            event.hostname = Some(value.to_owned());
        }
        "msg" | "message" => {
            event.fields.insert("message".to_owned(), value.to_owned());
        }
        _ => {
            event.fields.insert(key.to_owned(), value.to_owned());
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Maps a LEEF severity value to a Kron [`Severity`].
fn parse_severity(s: &str) -> Severity {
    match s.trim() {
        "1" | "2" | "3" | "Low" | "low" => Severity::Low,
        "4" | "5" | "6" | "Medium" | "medium" | "Informational" => Severity::Medium,
        "7" | "8" | "High" | "high" => Severity::High,
        "9" | "10" | "Critical" | "critical" | "Very-High" => Severity::Critical,
        _ => Severity::Info,
    }
}

/// Heuristically maps a LEEF category string to an [`EventCategory`].
fn map_category(cat: &str) -> Option<EventCategory> {
    let lower = cat.to_ascii_lowercase();
    if lower.contains("auth") || lower.contains("login") {
        Some(EventCategory::Authentication)
    } else if lower.contains("network") || lower.contains("traffic") {
        Some(EventCategory::Network)
    } else if lower.contains("file") {
        Some(EventCategory::File)
    } else if lower.contains("process") {
        Some(EventCategory::Process)
    } else {
        Some(EventCategory::Other)
    }
}

/// Converts a string to a snake_case identifier component.
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
    fn test_is_leef_detects_marker() {
        assert!(is_leef("LEEF:1.0|IBM|QRadar|7.2.8|Login|src=10.0.0.1"));
        assert!(is_leef("LEEF:2.0|Vendor|Product|1.0|E1|^|key^val"));
        assert!(!is_leef("Not a LEEF message"));
    }

    #[test]
    fn test_parse_leef_10_tab_delimited() {
        let mut event = blank_event();
        let raw = "LEEF:1.0|IBM|QRadar|7.2.8|Login|\tsrc=10.0.0.1\tsrcPort=22\tusrName=alice";
        parse_into(raw, &mut event).unwrap();
        assert_eq!(event.src_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(event.src_port, Some(22));
        assert_eq!(event.user_name.as_deref(), Some("alice"));
    }

    #[test]
    fn test_parse_leef_vendor_stored_in_fields() {
        let mut event = blank_event();
        parse_into("LEEF:1.0|IBM|QRadar|7.2|E1|\tsrc=1.2.3.4", &mut event).unwrap();
        assert_eq!(
            event.fields.get("leef_vendor").map(|s| s.as_str()),
            Some("IBM")
        );
    }
}
