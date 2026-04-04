//! Deduplication fingerprinting for the KRON normalizer.
//!
//! Computes an xxHash3-64 fingerprint over a fixed set of canonical event
//! fields. The fingerprint is stored in [`KronEvent::dedup_hash`].
//!
//! ## Fields hashed (in order, NUL-separated)
//!
//! 1. `tenant_id`
//! 2. `hostname` (empty string if absent)
//! 3. `event_type`
//! 4. `src_ip` (empty string if absent)
//! 5. `dst_ip` (empty string if absent)
//! 6. `process_name` (empty string if absent)
//! 7. `raw[..256]` (first 256 bytes of the raw log line)

use kron_types::KronEvent;
use xxhash_rust::xxh3::xxh3_64;

/// Maximum prefix of `raw` included in the fingerprint.
const RAW_PREFIX_LEN: usize = 256;

/// Computes and assigns the deduplication fingerprint for `event`.
///
/// If `event.dedup_hash` is already non-zero it is left unchanged
/// (the collector may have pre-stamped it).
pub fn compute_and_assign(event: &mut KronEvent) {
    if event.dedup_hash != 0 {
        return;
    }
    event.dedup_hash = fingerprint(event);
}

/// Computes the xxHash3-64 fingerprint over canonical event fields.
///
/// Fields are concatenated as UTF-8 with NUL (`\x00`) separators to prevent
/// field-boundary collisions.
#[must_use]
pub fn fingerprint(event: &KronEvent) -> u64 {
    let mut buf = String::with_capacity(512);

    buf.push_str(&event.tenant_id.to_string());
    buf.push('\x00');
    buf.push_str(event.hostname.as_deref().unwrap_or(""));
    buf.push('\x00');
    buf.push_str(&event.event_type);
    buf.push('\x00');
    if let Some(ip) = event.src_ip {
        buf.push_str(&ip.to_string());
    }
    buf.push('\x00');
    if let Some(ip) = event.dst_ip {
        buf.push_str(&ip.to_string());
    }
    buf.push('\x00');
    buf.push_str(event.process_name.as_deref().unwrap_or(""));
    buf.push('\x00');

    let raw_len = event.raw.len().min(RAW_PREFIX_LEN);
    buf.push_str(&event.raw[..raw_len]);

    xxh3_64(buf.as_bytes())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kron_types::{EventSource, KronEvent, Severity, TenantId};
    use uuid::Uuid;

    fn base_event() -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::from_uuid(Uuid::new_v4()))
            .source_type(EventSource::Syslog)
            .event_type("test_event")
            .raw("raw log line")
            .severity(Severity::Low)
            .build()
            .unwrap()
    }

    #[test]
    fn test_fingerprint_is_stable() {
        let event = base_event();
        assert_eq!(fingerprint(&event), fingerprint(&event));
    }

    #[test]
    fn test_fingerprint_differs_on_raw_change() {
        let mut e1 = base_event();
        let mut e2 = base_event();
        e2.tenant_id = e1.tenant_id;
        e1.raw = "line one".to_owned();
        e2.raw = "line two".to_owned();
        assert_ne!(fingerprint(&e1), fingerprint(&e2));
    }

    #[test]
    fn test_fingerprint_differs_on_src_ip() {
        let mut e1 = base_event();
        let mut e2 = base_event();
        e2.tenant_id = e1.tenant_id;
        e1.raw = e2.raw.clone();
        e1.src_ip = Some("10.0.0.1".parse().unwrap());
        e2.src_ip = Some("10.0.0.2".parse().unwrap());
        assert_ne!(fingerprint(&e1), fingerprint(&e2));
    }

    #[test]
    fn test_compute_skips_when_hash_already_set() {
        let mut event = base_event();
        event.dedup_hash = 42;
        compute_and_assign(&mut event);
        assert_eq!(event.dedup_hash, 42);
    }

    #[test]
    fn test_compute_sets_nonzero_hash() {
        let mut event = base_event();
        event.dedup_hash = 0;
        compute_and_assign(&mut event);
        assert_ne!(event.dedup_hash, 0);
    }
}
