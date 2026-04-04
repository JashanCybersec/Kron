//! IOC feed configuration and loading.
//!
//! [`FeedLoader`] fetches IOC data from configured HTTP feeds, parses them
//! into [`IocEntry`] values, and returns a flat list for bulk insertion into
//! the bloom filter.  Each feed is fetched independently; a failure on one
//! feed is logged and skipped so the others still contribute.
//!
//! # Supported formats
//!
//! | Variant | Description |
//! |---------|-------------|
//! | [`FeedFormat::PlainText`] | One IOC value per non-empty, non-comment line |
//! | [`FeedFormat::Csv`] | Delimited text; pick a specific column |
//! | [`FeedFormat::MispJson`] | MISP attribute array |
//! | [`FeedFormat::AbuseCh`] | Abuse.ch JSON (`data` array of objects) |

use serde::{Deserialize, Serialize};
use tracing::{instrument, warn};

use crate::error::StreamError;

use super::{
    metrics::{record_feed_error, record_feed_load},
    types::{IocEntry, IocType},
};

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Format of the raw IOC data returned by a feed URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedFormat {
    /// One IOC value per line.  Lines starting with `#` or empty lines are
    /// ignored.
    PlainText,
    /// Delimiter-separated values.  `value_column` is zero-indexed.
    Csv {
        /// Zero-based column index containing the IOC value.
        value_column: usize,
        /// Skip the first line if the feed has a header row.
        skip_header: bool,
    },
    /// MISP JSON export: top-level `"Attribute"` array of objects each having
    /// a `"value"` string field.
    MispJson,
    /// Abuse.ch JSON: top-level object with a `"data"` array.  Each element
    /// is an object with an `"ioc"` or `"url_info_from_api"`-style value field.
    AbuseCh,
}

/// Configuration for a single threat-intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Human-readable feed name (used in metrics and log fields).
    pub name: String,
    /// Full HTTP or HTTPS URL of the feed endpoint.
    pub url: String,
    /// Type of IOC produced by this feed.
    pub ioc_type: IocType,
    /// Format of the feed's response body.
    pub format: FeedFormat,
    /// Whether this feed is enabled.  Disabled feeds are not fetched.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// FeedLoader
// ---------------------------------------------------------------------------

/// Fetches and parses one or more IOC feeds over HTTP.
///
/// Create with [`FeedLoader::new`] (custom feeds) or use
/// [`FeedLoader::default_feeds`] to get the built-in public feed list.
pub struct FeedLoader {
    client: reqwest::Client,
    config: Vec<FeedConfig>,
}

impl FeedLoader {
    /// Create a loader from a list of feed configurations.
    ///
    /// # Errors
    ///
    /// Returns a [`StreamError::RuleLoad`] if the underlying `reqwest` client
    /// cannot be constructed (e.g. invalid TLS configuration).
    pub fn new(config: Vec<FeedConfig>) -> Result<Self, StreamError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("kron-stream/0.1 IOC-feed-loader")
            .build()
            .map_err(|e| StreamError::RuleLoad(format!("failed to build HTTP client: {e}")))?;
        Ok(Self { client, config })
    }

    /// Fetch all enabled feeds and return a flat list of [`IocEntry`] values.
    ///
    /// Failed feeds are logged and skipped; they do **not** cause the method
    /// to return an error.
    pub async fn load_all(&self) -> Vec<IocEntry> {
        let mut all: Vec<IocEntry> = Vec::new();
        for feed in &self.config {
            if !feed.enabled {
                continue;
            }
            match self.load_feed(feed).await {
                Ok(entries) => {
                    record_feed_load(&feed.name, entries.len());
                    tracing::info!(
                        feed = %feed.name,
                        entries = entries.len(),
                        "IOC feed loaded successfully"
                    );
                    all.extend(entries);
                }
                Err(err) => {
                    record_feed_error(&feed.name);
                    warn!(
                        feed = %feed.name,
                        error = %err,
                        "Failed to load IOC feed — skipping"
                    );
                }
            }
        }
        all
    }

    /// Fetch and parse a single feed.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError::RuleLoad`] on HTTP or parse failures.
    #[instrument(skip(self), fields(feed = %feed.name, url = %feed.url))]
    async fn load_feed(&self, feed: &FeedConfig) -> Result<Vec<IocEntry>, StreamError> {
        let response =
            self.client.get(&feed.url).send().await.map_err(|e| {
                StreamError::RuleLoad(format!("HTTP GET '{}' failed: {e}", feed.url))
            })?;

        if !response.status().is_success() {
            return Err(StreamError::RuleLoad(format!(
                "feed '{}' returned HTTP {}",
                feed.name,
                response.status()
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| StreamError::RuleLoad(format!("failed to read feed body: {e}")))?;

        let entries = match &feed.format {
            FeedFormat::PlainText => Self::parse_plain_text(&body, feed.ioc_type, &feed.name),
            FeedFormat::Csv {
                value_column,
                skip_header,
            } => Self::parse_csv(
                &body,
                *value_column,
                *skip_header,
                feed.ioc_type,
                &feed.name,
            ),
            FeedFormat::MispJson => Self::parse_misp_json(&body, feed.ioc_type, &feed.name),
            FeedFormat::AbuseCh => Self::parse_abusech(&body, feed.ioc_type, &feed.name),
        };
        Ok(entries)
    }

    // -----------------------------------------------------------------------
    // Format parsers
    // -----------------------------------------------------------------------

    /// Parse a plain-text feed: one IOC value per non-empty, non-comment line.
    #[must_use]
    pub fn parse_plain_text(body: &str, ioc_type: IocType, source: &str) -> Vec<IocEntry> {
        body.lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return None;
                }
                Some(IocEntry {
                    value: trimmed.to_string(),
                    ioc_type,
                    source: source.to_string(),
                    severity: None,
                })
            })
            .collect()
    }

    /// Parse a CSV feed, extracting the IOC from column `value_col` (zero-indexed).
    ///
    /// Lines that do not have enough columns are silently skipped.
    #[must_use]
    pub fn parse_csv(
        body: &str,
        value_col: usize,
        skip_header: bool,
        ioc_type: IocType,
        source: &str,
    ) -> Vec<IocEntry> {
        body.lines()
            .skip(usize::from(skip_header))
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return None;
                }
                let cols: Vec<&str> = trimmed.splitn(value_col + 2, ',').collect();
                let raw = cols.get(value_col)?.trim().trim_matches('"');
                if raw.is_empty() {
                    return None;
                }
                Some(IocEntry {
                    value: raw.to_string(),
                    ioc_type,
                    source: source.to_string(),
                    severity: None,
                })
            })
            .collect()
    }

    /// Parse a MISP JSON export.
    ///
    /// Expects either `{"Attribute": [...]}` or a bare `[...]` array.  Each
    /// element should contain a `"value"` string field.
    #[must_use]
    pub fn parse_misp_json(body: &str, ioc_type: IocType, source: &str) -> Vec<IocEntry> {
        let root: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => {
                warn!(source = %source, error = %e, "Failed to parse MISP JSON feed");
                return vec![];
            }
        };
        let array = if let Some(attrs) = root.get("Attribute").and_then(|v| v.as_array()) {
            attrs.clone()
        } else if let Some(arr) = root.as_array() {
            arr.clone()
        } else {
            warn!(source = %source, "MISP JSON feed has unexpected structure");
            return vec![];
        };

        array
            .iter()
            .filter_map(|item| {
                let value = item.get("value")?.as_str()?.trim().to_string();
                if value.is_empty() {
                    return None;
                }
                let severity = item
                    .get("category")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                Some(IocEntry {
                    value,
                    ioc_type,
                    source: source.to_string(),
                    severity,
                })
            })
            .collect()
    }

    /// Field names used across `MalwareBazaar`, `URLhaus`, and `ThreatFox` responses.
    const ABUSECH_VALUE_FIELDS: &'static [&'static str] =
        &["sha256_hash", "url", "ioc", "hash", "domain", "ip_address"];

    /// Parse an Abuse.ch JSON feed.
    ///
    /// Expects `{"data": [...]}` where each element contains an IOC value
    /// under one of several known field names.
    #[must_use]
    pub fn parse_abusech(body: &str, ioc_type: IocType, source: &str) -> Vec<IocEntry> {
        let root: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => {
                warn!(source = %source, error = %e, "Failed to parse Abuse.ch JSON feed");
                return vec![];
            }
        };
        let Some(array) = root.get("data").and_then(|v| v.as_array()).cloned() else {
            warn!(source = %source, "Abuse.ch feed missing 'data' array");
            return vec![];
        };

        array
            .iter()
            .filter_map(|item| {
                let value = Self::ABUSECH_VALUE_FIELDS
                    .iter()
                    .find_map(|&field| item.get(field)?.as_str())
                    .map(str::trim)?
                    .to_string();
                if value.is_empty() {
                    return None;
                }
                let severity = item
                    .get("threat_type")
                    .or_else(|| item.get("tags"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                Some(IocEntry {
                    value,
                    ioc_type,
                    source: source.to_string(),
                    severity,
                })
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Default feed configurations
    // -----------------------------------------------------------------------

    /// Return the built-in set of public threat-intelligence feed configurations.
    ///
    /// All feeds in this list are publicly accessible without authentication.
    /// They cover SHA-256 hashes, URLs, IP addresses, and domain names from
    /// well-known sources (Abuse.ch, Feodo, Spamhaus, MISP).
    #[must_use]
    pub fn default_feeds() -> Vec<FeedConfig> {
        vec![
            FeedConfig {
                name: "abusech-malwarebazaar-recent-sha256".to_string(),
                url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
                ioc_type: IocType::Sha256,
                format: FeedFormat::PlainText,
                enabled: true,
            },
            FeedConfig {
                name: "abusech-urlhaus-online-urls".to_string(),
                url: "https://urlhaus.abuse.ch/downloads/csv_online/".to_string(),
                ioc_type: IocType::Url,
                format: FeedFormat::Csv {
                    value_column: 2,
                    skip_header: true,
                },
                enabled: true,
            },
            FeedConfig {
                name: "abusech-threatfox-ip-port".to_string(),
                url: "https://threatfox-api.abuse.ch/api/v1/".to_string(),
                ioc_type: IocType::Ip,
                format: FeedFormat::AbuseCh,
                enabled: true,
            },
            FeedConfig {
                name: "feodo-tracker-botnet-c2-ips".to_string(),
                url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
                ioc_type: IocType::Ip,
                format: FeedFormat::PlainText,
                enabled: true,
            },
            FeedConfig {
                name: "spamhaus-drop-ipv4".to_string(),
                url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
                ioc_type: IocType::Ip,
                format: FeedFormat::PlainText,
                enabled: true,
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_parse_plain_text_when_valid_lines_then_all_parsed() {
        let body = "# Comment line\n\n1.2.3.4\n10.0.0.1\n";
        let entries = FeedLoader::parse_plain_text(body, IocType::Ip, "test-feed");
        assert_eq!(
            entries.len(),
            2,
            "Only non-empty, non-comment lines must be parsed"
        );
        assert_eq!(entries[0].value, "1.2.3.4");
        assert_eq!(entries[1].value, "10.0.0.1");
        assert_eq!(entries[0].source, "test-feed");
    }

    #[test]
    fn test_parse_csv_when_valid_csv_then_correct_column_extracted() {
        // id,date,url,tags
        let body = "id,date,url,tags\n1,2024-01-01,http://evil.com/malware.exe,malware\n2,2024-01-02,http://bad.net/payload,ransomware\n";
        let entries = FeedLoader::parse_csv(body, 2, true, IocType::Url, "urlhaus-test");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, "http://evil.com/malware.exe");
        assert_eq!(entries[1].value, "http://bad.net/payload");
    }

    #[test]
    fn test_default_feeds_when_called_then_returns_non_empty_list() {
        let feeds = FeedLoader::default_feeds();
        assert!(
            !feeds.is_empty(),
            "default_feeds must return at least one feed"
        );
        // All entries must have non-empty names and URLs.
        for feed in &feeds {
            assert!(!feed.name.is_empty(), "feed name must not be empty");
            assert!(!feed.url.is_empty(), "feed URL must not be empty");
        }
    }
}
