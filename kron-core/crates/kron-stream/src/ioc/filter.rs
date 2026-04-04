//! High-level IOC filter wrapping the counting bloom filter.
//!
//! [`IocFilter`] is the primary entry-point for IOC lookups. It namespaces
//! each value by [`IocType`] so that an IP address and a domain with the same
//! string representation hash to different positions.
//!
//! The filter is safe to share across threads via [`Arc`] because internal
//! mutation goes through an [`RwLock`].

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use super::{
    bloom::CountingBloomFilter,
    metrics::{record_ioc_hit, record_ioc_insert, record_ioc_miss},
    types::{IocEntry, IocType},
};

/// Production number of 4-bit counter slots (200 M → 100 MB backing store).
///
/// Achieves ≈ 0.008 % false-positive rate at 10 million entries with k = 7.
const PROD_M: usize = 200_000_000;

/// Number of hash functions for the production filter.
const PROD_K: usize = 7;

/// Thread-safe counting bloom filter for IOC lookups.
///
/// Internally wraps a [`CountingBloomFilter`] behind an `Arc<RwLock<…>>` so
/// it can be shared between the detection engine and the background refresh
/// task without requiring `mut` references at call sites.
#[derive(Clone)]
pub struct IocFilter {
    inner: Arc<RwLock<CountingBloomFilter>>,
    entry_count: Arc<AtomicU64>,
    /// Slot count stored so `rebuild` can recreate a same-sized filter.
    m: usize,
    /// Hash function count stored so `rebuild` can recreate a same-sized filter.
    k: usize,
}

impl IocFilter {
    /// Create a production-sized IOC filter (200 M slots, k = 7).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(PROD_M, PROD_K)
    }

    /// Create a filter with custom parameters.
    ///
    /// Use this in tests where allocating 100 MB per filter is impractical.
    #[must_use]
    pub fn with_capacity(m: usize, k: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CountingBloomFilter::new(m, k))),
            entry_count: Arc::new(AtomicU64::new(0)),
            m,
            k,
        }
    }

    /// Insert an IOC value of the given type into the filter.
    ///
    /// The value is normalized (see [`Self::normalize`]) before insertion.
    pub fn insert(&self, value: &str, ioc_type: &IocType) {
        let key = Self::make_key(value, *ioc_type);
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.insert(&key);
        drop(guard);
        self.entry_count.fetch_add(1, Ordering::Relaxed);
        record_ioc_insert(1);
    }

    /// Remove one occurrence of an IOC value from the filter.
    ///
    /// Only call this if the value was previously inserted. Spurious removals
    /// can produce false negatives.
    pub fn remove(&self, value: &str, ioc_type: &IocType) {
        let key = Self::make_key(value, *ioc_type);
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.remove(&key);
        drop(guard);
        // Saturating subtract: don't go below zero.
        let prev = self.entry_count.load(Ordering::Relaxed);
        if prev > 0 {
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Check whether an IOC value is (possibly) present in the filter.
    ///
    /// Returns `false` if the value is *definitely* absent.
    /// Returns `true` if the value is *possibly* present (false-positive rate
    /// ≈ 0.008 % at 10 M entries).
    #[must_use]
    pub fn check(&self, value: &str, ioc_type: &IocType) -> bool {
        let key = Self::make_key(value, *ioc_type);
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hit = guard.check(&key);
        drop(guard);
        if hit {
            record_ioc_hit(ioc_type.as_str());
        } else {
            record_ioc_miss(ioc_type.as_str());
        }
        hit
    }

    /// Atomically rebuild the filter from a fresh set of entries.
    ///
    /// A new [`CountingBloomFilter`] is constructed from `entries` and then
    /// swapped in under the write lock. The old filter is dropped immediately
    /// after the swap.
    pub fn rebuild(&self, entries: impl Iterator<Item = IocEntry>) {
        let mut new_filter = CountingBloomFilter::new(self.m, self.k);
        let mut count: u64 = 0;
        for entry in entries {
            let key = Self::make_key(&entry.value, entry.ioc_type);
            new_filter.insert(&key);
            count += 1;
        }
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = new_filter;
        drop(guard);
        self.entry_count.store(count, Ordering::Relaxed);
        record_ioc_insert(count);
    }

    /// Returns the approximate number of entries currently in the filter.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.entry_count.load(Ordering::Relaxed)
    }

    /// Returns `true` if the filter contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build the namespaced byte key for bloom filter operations.
    ///
    /// Format: `[namespace_byte] ++ normalize(value).as_bytes()`
    fn make_key(value: &str, ioc_type: IocType) -> Vec<u8> {
        let normalized = Self::normalize(value, ioc_type);
        let mut key = Vec::with_capacity(1 + normalized.len());
        key.push(ioc_type.namespace_byte());
        key.extend_from_slice(normalized.as_bytes());
        key
    }

    /// Normalize an IOC value according to its type.
    ///
    /// - `Ip`: parse with `std::net::IpAddr` and re-format for canonical form.
    ///   Falls back to the raw value if parsing fails (feed data may be dirty).
    /// - `Domain`: lowercase, strip trailing dot.
    /// - `Sha256`: lowercase.
    /// - `Url`: lowercase scheme and host; path is preserved.
    fn normalize(value: &str, ioc_type: IocType) -> String {
        match ioc_type {
            IocType::Ip => value
                .parse::<std::net::IpAddr>()
                .map_or_else(|_| value.to_string(), |ip| ip.to_string()),
            IocType::Domain => {
                let lower = value.to_lowercase();
                lower.trim_end_matches('.').to_string()
            }
            IocType::Sha256 => value.to_lowercase(),
            IocType::Url => normalize_url(value),
        }
    }
}

impl Default for IocFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a URL to lowercase scheme and host while preserving path.
fn normalize_url(url: &str) -> String {
    // Split on "://" to separate scheme from the rest.
    if let Some(sep_pos) = url.find("://") {
        let scheme = url[..sep_pos].to_lowercase();
        let rest = &url[sep_pos + 3..];
        // The host ends at the first '/' or end of string.
        let (host_part, path_part) = match rest.find('/') {
            Some(slash) => (&rest[..slash], &rest[slash..]),
            None => (rest, ""),
        };
        format!("{}://{}{}", scheme, host_part.to_lowercase(), path_part)
    } else {
        url.to_lowercase()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::ioc::types::IocEntry;

    /// Small test filter: 8 192 slots, k = 7.
    fn test_filter() -> IocFilter {
        IocFilter::with_capacity(8_192, 7)
    }

    #[test]
    fn test_check_when_ip_not_inserted_then_false() {
        let f = test_filter();
        assert!(!f.check("1.2.3.4", &IocType::Ip));
    }

    #[test]
    fn test_check_when_ip_inserted_then_true() {
        let f = test_filter();
        f.insert("1.2.3.4", &IocType::Ip);
        assert!(f.check("1.2.3.4", &IocType::Ip));
    }

    #[test]
    fn test_check_when_domain_inserted_then_true() {
        let f = test_filter();
        f.insert("malware.example.com", &IocType::Domain);
        assert!(f.check("malware.example.com", &IocType::Domain));
    }

    #[test]
    fn test_check_when_domain_different_case_then_true() {
        let f = test_filter();
        // Insert in mixed case; lookup in upper case — both normalize to lower.
        f.insert("Malware.Example.COM", &IocType::Domain);
        assert!(f.check("MALWARE.EXAMPLE.COM", &IocType::Domain));
    }

    #[test]
    fn test_rebuild_when_called_then_old_entries_gone() {
        let f = test_filter();
        f.insert("old-ioc.example.com", &IocType::Domain);
        assert!(f.check("old-ioc.example.com", &IocType::Domain));

        let new_entries = vec![IocEntry {
            value: "new-ioc.example.com".to_string(),
            ioc_type: IocType::Domain,
            source: "test".to_string(),
            severity: None,
        }];
        f.rebuild(new_entries.into_iter());

        assert!(
            !f.check("old-ioc.example.com", &IocType::Domain),
            "Old entry must be gone after rebuild"
        );
        assert!(
            f.check("new-ioc.example.com", &IocType::Domain),
            "New entry must be present after rebuild"
        );
    }
}
