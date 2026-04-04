//! IOC types shared across the bloom filter, feed loader, and filter modules.

use serde::{Deserialize, Serialize};

/// Classifies what kind of indicator of compromise a value represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    /// IPv4 or IPv6 address (stored in canonical string form).
    Ip,
    /// Domain name (normalized to lowercase, trailing dot stripped).
    Domain,
    /// SHA-256 file hash as a lowercase hex string.
    Sha256,
    /// URL (lowercase scheme and host, path preserved as-is).
    Url,
}

impl IocType {
    /// Returns the single-byte namespace prefix used when building bloom filter keys.
    ///
    /// Namespacing ensures that, for example, an IP address and a domain with
    /// identical string representations hash to different positions.
    #[must_use]
    pub fn namespace_byte(&self) -> u8 {
        match self {
            Self::Ip => 0x01,
            Self::Domain => 0x02,
            Self::Sha256 => 0x03,
            Self::Url => 0x04,
        }
    }

    /// Returns a human-readable label used in metric tags.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Sha256 => "sha256",
            Self::Url => "url",
        }
    }
}

/// A single indicator of compromise loaded from an external feed.
#[derive(Debug, Clone)]
pub struct IocEntry {
    /// The indicator value (IP, domain, hash, or URL).
    pub value: String,
    /// The type of this indicator.
    pub ioc_type: IocType,
    /// Human-readable name of the feed that provided this entry.
    pub source: String,
    /// Optional severity classification provided by the feed (e.g. `"high"`).
    pub severity: Option<String>,
}
