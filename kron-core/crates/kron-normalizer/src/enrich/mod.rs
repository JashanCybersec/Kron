//! Enrichment pipeline for the KRON normalizer.
//!
//! [`Enricher`] holds all enrichment backends and applies them in order:
//!
//! 1. **GeoIP** — MaxMind GeoLite2 lookup for `src_ip` / `dst_ip`
//! 2. **Asset** — hostname → asset record lookup (in-memory TTL cache)

pub mod asset;
pub mod geoip;

use kron_types::KronEvent;

use asset::AssetCache;
use geoip::GeoIpLookup;

/// Holds all enrichment backends and applies them to events.
pub struct Enricher {
    geoip: GeoIpLookup,
    assets: AssetCache,
}

impl Enricher {
    /// Creates a new [`Enricher`] from the given backends.
    #[must_use]
    pub fn new(geoip: GeoIpLookup, assets: AssetCache) -> Self {
        Self { geoip, assets }
    }

    /// Applies all enrichment steps to `event` in order.
    ///
    /// Steps:
    /// 1. GeoIP for `src_ip` / `dst_ip`
    /// 2. Asset lookup for `hostname`
    pub fn enrich(&self, event: &mut KronEvent) {
        self.geoip.enrich(event);
        self.assets.enrich(event);
    }
}
