//! Asset enrichment cache for the KRON normalizer.
//!
//! [`AssetCache`] maps hostnames and IP addresses to asset metadata sourced
//! from the KRON asset inventory. Entries expire after a configurable TTL
//! (default: 5 minutes) to avoid serving stale data.
//!
//! In Phase 1.6 the backing store (kron-storage) is not yet fully wired; the
//! cache is always empty on startup and populates only if a storage backend
//! is provided at construction. All misses fall through gracefully.
//! TODO(#TBD, hardik, phase-2): Wire asset lookup to kron-storage

use std::collections::HashMap;
use std::time::{Duration, Instant};

use kron_types::KronEvent;

use crate::metrics;

// ─── Asset record ────────────────────────────────────────────────────────────

/// Asset metadata returned from the inventory.
#[derive(Debug, Clone)]
pub struct AssetInfo {
    /// Opaque asset identifier.
    pub asset_id: String,
    /// FQDN or short hostname.
    pub hostname: String,
    /// Criticality rating string (maps to `AssetCriticality` in kron-types).
    pub criticality: String,
    /// Free-form tags (e.g. `["prod", "payment"]`).
    pub tags: Vec<String>,
}

// ─── Cache entry ─────────────────────────────────────────────────────────────

struct CacheEntry {
    info: Option<AssetInfo>,
    fetched_at: Instant,
}

// ─── AssetCache ──────────────────────────────────────────────────────────────

/// In-memory TTL cache for asset records keyed by hostname.
pub struct AssetCache {
    entries: HashMap<String, CacheEntry>,
    ttl: Duration,
    max_size: usize,
}

impl AssetCache {
    /// Creates a new cache with the given TTL and maximum entry count.
    #[must_use]
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            max_size,
        }
    }

    /// Looks up `hostname` in the cache.
    ///
    /// Returns `Some(&AssetInfo)` on a valid (non-expired) hit, `None` on a
    /// miss or expired entry.
    #[must_use]
    pub fn get(&self, hostname: &str) -> Option<&AssetInfo> {
        let entry = self.entries.get(hostname)?;
        if entry.fetched_at.elapsed() >= self.ttl {
            return None; // Expired — caller should re-fetch.
        }
        metrics::record_asset_hit();
        entry.info.as_ref()
    }

    /// Inserts or refreshes a cache entry for `hostname`.
    pub fn insert(&mut self, hostname: String, info: Option<AssetInfo>) {
        // Evict one random entry if at capacity to keep memory bounded.
        if self.entries.len() >= self.max_size {
            if let Some(key) = self.entries.keys().next().cloned() {
                self.entries.remove(&key);
            }
        }
        self.entries.insert(
            hostname,
            CacheEntry {
                info,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Removes expired entries from the cache (call periodically).
    pub fn evict_expired(&mut self) {
        self.entries
            .retain(|_, e| e.fetched_at.elapsed() < self.ttl);
    }

    /// Applies asset enrichment to `event.hostname` if a cache entry exists.
    ///
    /// On cache miss, records the miss metric and returns without modifying
    /// the event (no backend lookup in Phase 1.6).
    pub fn enrich(&self, event: &mut KronEvent) {
        let hostname = match event.hostname.as_deref() {
            Some(h) if !h.is_empty() => h,
            _ => return,
        };

        match self.get(hostname) {
            Some(info) => {
                event.host_id = Some(info.asset_id.clone());
                for tag in &info.tags {
                    if !event.asset_tags.contains(tag) {
                        event.asset_tags.push(tag.clone());
                    }
                }
            }
            None => {
                metrics::record_asset_miss();
                // No backend lookup in Phase 1.6 — the event is published
                // without asset metadata; the stream processor can enrich later.
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_hit_returns_stored_info() {
        let mut cache = AssetCache::new(Duration::from_secs(300), 100);
        cache.insert(
            "web-01".to_owned(),
            Some(AssetInfo {
                asset_id: "a1".to_owned(),
                hostname: "web-01".to_owned(),
                criticality: "high".to_owned(),
                tags: vec!["prod".to_owned()],
            }),
        );
        assert!(cache.get("web-01").is_some());
    }

    #[test]
    fn test_cache_miss_returns_none() {
        let cache = AssetCache::new(Duration::from_secs(300), 100);
        assert!(cache.get("unknown-host").is_none());
    }

    #[test]
    fn test_expired_entry_returns_none() {
        let mut cache = AssetCache::new(Duration::from_millis(1), 100);
        cache.insert("web-01".to_owned(), None);
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get("web-01").is_none());
    }
}
