//! Multi-format timestamp parser for the KRON normalizer.
//!
//! [`parse_timestamp`] tries 15+ common log timestamp formats in order of
//! specificity, always returning a UTC [`DateTime`]. Returns `None` if no
//! format matches; callers should fall back to `Utc::now()` with a warning.

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};

/// Named format strings tried for naive (no-timezone) timestamps.
///
/// Each entry is `(label, strftime_format)`. Tried in order; first match wins.
static NAIVE_FORMATS: &[(&str, &str)] = &[
    // ISO 8601 with space separator
    ("ISO_SPACE_NS", "%Y-%m-%d %H:%M:%S%.9f"),
    ("ISO_SPACE_US", "%Y-%m-%d %H:%M:%S%.6f"),
    ("ISO_SPACE_MS", "%Y-%m-%d %H:%M:%S%.3f"),
    ("ISO_SPACE", "%Y-%m-%d %H:%M:%S"),
    // ISO 8601 compact with 'T' but no timezone suffix
    ("ISO_COMPACT_T", "%Y%m%dT%H%M%S"),
    // CEF extension timestamp: "Jan 15 2024 10:30:45"
    ("CEF_EXT", "%b %d %Y %H:%M:%S"),
    // Cisco: "Jan 15 2024 10:30:45"
    ("CISCO", "%b %d %Y %H:%M:%S"),
    // Common log / Apache access log: "15/Jan/2024:10:30:45"
    ("CLF", "%d/%b/%Y:%H:%M:%S"),
    // Windows MDY 12-hour: "01/15/2024 10:30:45 AM"
    ("WINDOWS_12H", "%m/%d/%Y %I:%M:%S %p"),
    // Windows MDY 24-hour: "01/15/2024 22:30:45"
    ("WINDOWS_24H", "%m/%d/%Y %H:%M:%S"),
    // SQL with fractional seconds: "2024-01-15 10:30:45.123"
    ("SQL_FRAC", "%Y-%m-%d %H:%M:%S%.f"),
    // Date only (midnight assumed): "2024-01-15"
    ("DATE_ONLY", "%Y-%m-%d"),
];

/// Parses a timestamp string into a UTC [`DateTime`].
///
/// Tries in order:
/// 1. RFC 3339 / ISO 8601 with timezone (`+05:30`, `Z`, etc.)
/// 2. RFC 2822 (email/HTTP style)
/// 3. Unix epoch seconds or milliseconds (all-digit / float strings)
/// 4. 12+ named strftime formats (assumed UTC)
/// 5. Syslog BSD `MMM DD HH:MM:SS` with current-year injection
///
/// Returns `None` if no format matches.
#[must_use]
pub fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // RFC 3339 / ISO 8601 with explicit timezone
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // RFC 2822 (Mon, 15 Jan 2024 10:30:45 +0000)
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Unix epoch (integer seconds or millis, or float seconds)
    if let Some(dt) = parse_unix_epoch(s) {
        return Some(dt);
    }

    // Named strftime formats (assumed UTC)
    for (_label, fmt) in NAIVE_FORMATS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
    }

    // Syslog BSD: "Jan 15 10:30:45" (no year — inject current year)
    parse_syslog_bsd(s)
}

/// Parses a numeric string as a Unix epoch (seconds or milliseconds).
fn parse_unix_epoch(s: &str) -> Option<DateTime<Utc>> {
    // Strip trailing 'Z' if present
    let s = s.strip_suffix('Z').unwrap_or(s);

    // Integer
    if let Ok(n) = s.parse::<i64>() {
        return if n > 10_000_000_000 {
            // Looks like milliseconds (after year 2001)
            DateTime::from_timestamp_millis(n)
        } else {
            DateTime::from_timestamp(n, 0)
        };
    }

    // Floating-point seconds
    if let Ok(f) = s.parse::<f64>() {
        let secs = f as i64;
        let nanos = ((f - secs as f64) * 1_000_000_000.0) as u32;
        return DateTime::from_timestamp(secs, nanos);
    }

    None
}

/// Parses syslog BSD timestamps that have no year component.
///
/// Injects the current UTC year. If the resulting timestamp would be more
/// than 24 hours in the future (December log arriving in January), rolls
/// back one year.
fn parse_syslog_bsd(s: &str) -> Option<DateTime<Utc>> {
    let year = Utc::now().year();
    let with_year = format!("{year} {s}");

    let naive = NaiveDateTime::parse_from_str(&with_year, "%Y %b %d %H:%M:%S").ok()?;
    let dt = naive.and_utc();

    if dt > Utc::now() + chrono::Duration::hours(24) {
        let prev = format!("{} {s}", year - 1);
        let naive_prev = NaiveDateTime::parse_from_str(&prev, "%Y %b %d %H:%M:%S").ok()?;
        return Some(naive_prev.and_utc());
    }

    Some(dt)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_utc() {
        let dt = parse_timestamp("2024-01-15T10:30:45Z").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn test_rfc3339_with_offset() {
        let dt = parse_timestamp("2024-01-15T10:30:45+05:30").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_unix_seconds() {
        let dt = parse_timestamp("1705318245").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_unix_millis() {
        let dt = parse_timestamp("1705318245000").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_iso_space_format() {
        let dt = parse_timestamp("2024-01-15 10:30:45").unwrap();
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn test_iso_space_with_millis() {
        let dt = parse_timestamp("2024-01-15 10:30:45.123").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_cef_extension_format() {
        let dt = parse_timestamp("Jan 15 2024 10:30:45").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
    }

    #[test]
    fn test_clf_apache_format() {
        let dt = parse_timestamp("15/Jan/2024:10:30:45").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn test_syslog_bsd_no_year() {
        // Must return Some — exact year depends on when test runs
        assert!(parse_timestamp("Jan 15 10:30:45").is_some());
    }

    #[test]
    fn test_empty_returns_none() {
        assert!(parse_timestamp("").is_none());
    }

    #[test]
    fn test_garbage_returns_none() {
        assert!(parse_timestamp("not-a-timestamp-at-all").is_none());
    }
}
