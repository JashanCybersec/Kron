//! MaxMind GeoLite2 IP enrichment.
//!
//! [`GeoIpLookup`] wraps a `maxminddb` reader and enriches events with
//! country code, city name, and ASN for their `src_ip` and `dst_ip` fields.
//!
//! If the MMDB file is absent the struct is created in disabled mode and
//! all lookups return `None` without error.

use std::net::IpAddr;
use std::path::Path;

use kron_types::KronEvent;
use maxminddb::geoip2;

use crate::metrics;

/// Enrichment data extracted from a GeoLite2 City lookup.
#[derive(Debug, Clone)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code (e.g. `"IN"`, `"US"`).
    pub country_code: Option<String>,
    /// English city name.
    pub city: Option<String>,
    /// Autonomous System Number.
    pub asn: Option<u32>,
    /// AS organization name.
    pub asn_name: Option<String>,
}

// ─── GeoIpLookup ─────────────────────────────────────────────────────────────

/// Thin wrapper around a MaxMind `Reader` for GeoLite2-City lookups.
///
/// Created once at startup and shared read-only across the pipeline.
pub struct GeoIpLookup {
    /// `None` when the MMDB file was not found (enrichment disabled).
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpLookup {
    /// Opens the GeoLite2-City MMDB file at `path`.
    ///
    /// If the file does not exist, returns a disabled [`GeoIpLookup`] with a
    /// warning rather than an error (GeoIP enrichment is optional).
    ///
    /// # Errors
    ///
    /// Returns `Err` only if the file exists but cannot be opened or parsed.
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "GeoLite2-City MMDB not found; GeoIP enrichment disabled. \
                 Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
            );
            return Ok(Self { reader: None });
        }

        let path_str = path
            .to_str()
            .ok_or_else(|| format!("GeoIP path is not valid UTF-8: {}", path.display()))?;

        let reader = maxminddb::Reader::open_readfile(path_str)
            .map_err(|e| format!("cannot open GeoIP DB {}: {e}", path.display()))?;

        tracing::info!(path = %path.display(), "GeoLite2-City MMDB loaded");
        Ok(Self {
            reader: Some(reader),
        })
    }

    /// Returns `true` if the MMDB file was successfully loaded.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.reader.is_some()
    }

    /// Looks up geo information for `addr`.
    ///
    /// Returns `None` if enrichment is disabled, the address is private/loopback,
    /// or the address is not in the database.
    #[must_use]
    pub fn lookup(&self, addr: IpAddr) -> Option<GeoInfo> {
        // Skip RFC-1918 and loopback — they are never in the GeoIP DB.
        if is_private(addr) {
            return None;
        }

        let reader = self.reader.as_ref()?;
        metrics::record_geoip_lookup();

        let city: geoip2::City = reader.lookup(addr).ok()?;

        let country_code = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(str::to_owned);

        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|names| names.get("en").copied())
            .map(str::to_owned);

        // ASN requires a separate GeoLite2-ASN database; not available here.
        if country_code.is_none() && city_name.is_none() {
            metrics::record_geoip_miss();
            return None;
        }

        Some(GeoInfo {
            country_code,
            city: city_name,
            asn: None,
            asn_name: None,
        })
    }

    /// Applies GeoIP enrichment to `event.src_ip` and `event.dst_ip`.
    pub fn enrich(&self, event: &mut KronEvent) {
        if let Some(ip) = event.src_ip {
            if let Some(geo) = self.lookup(IpAddr::V4(ip)) {
                event.src_country = geo.country_code;
                event.src_city = geo.city;
                event.src_asn = geo.asn;
                event.src_asn_name = geo.asn_name;
            }
        }

        if let Some(ip) = event.dst_ip {
            if let Some(geo) = self.lookup(IpAddr::V4(ip)) {
                event.dst_country = geo.country_code;
            }
        }
    }
}

/// Returns `true` for loopback, link-local, and RFC-1918 private addresses.
fn is_private(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified(),
    }
}
