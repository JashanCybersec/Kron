//! IOC (Indicator of Compromise) bloom filter subsystem.
//!
//! Provides sub-millisecond IOC lookups using a counting bloom filter backed
//! by 4-bit packed counters.  The filter is populated from configurable
//! threat-intelligence feeds and refreshed in the background every 5 minutes.
//!
//! # Quick-start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use kron_stream::ioc::{IocFilter, IocType, FeedLoader, IocRefreshTask};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let feeds = FeedLoader::default_feeds();
//! let loader = Arc::new(FeedLoader::new(feeds)?);
//! let filter = Arc::new(IocFilter::new());
//!
//! let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//! let task = IocRefreshTask::new(Arc::clone(&filter), Arc::clone(&loader), Duration::from_secs(300));
//! let _handle = task.spawn(shutdown_rx);
//!
//! // Later — check an IP:
//! let is_malicious = filter.check("192.0.2.1", &IocType::Ip);
//! # Ok(())
//! # }
//! ```
//!
//! # Module layout
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`bloom`] | Low-level counting bloom filter |
//! | [`types`] | [`IocType`] and [`IocEntry`] |
//! | [`filter`] | Thread-safe [`IocFilter`] wrapping the bloom filter |
//! | [`feed`] | [`FeedLoader`], [`FeedConfig`], [`FeedFormat`] |
//! | [`refresh`] | Background [`IocRefreshTask`] |
//! | [`metrics`] | Prometheus counter/histogram helpers |

mod bloom;
pub mod feed;
pub mod filter;
pub mod metrics;
pub mod refresh;
pub mod types;

pub use feed::{FeedConfig, FeedFormat, FeedLoader};
pub use filter::IocFilter;
pub use metrics::IocMetrics;
pub use refresh::IocRefreshTask;
pub use types::{IocEntry, IocType};
