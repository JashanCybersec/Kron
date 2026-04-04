//! Background IOC filter refresh task.
//!
//! [`IocRefreshTask`] runs as a Tokio task that periodically fetches all
//! configured feeds via [`FeedLoader`] and calls [`IocFilter::rebuild`] to
//! atomically swap in the fresh data.  Latency of the rebuild is measured
//! and emitted via [`record_refresh_duration_ms`].
//!
//! The task exits cleanly when the provided shutdown channel receives `true`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{error, info, instrument};

use super::{feed::FeedLoader, filter::IocFilter, metrics::record_refresh_duration_ms};

/// Owns the state required to run periodic IOC filter refreshes.
pub struct IocRefreshTask {
    filter: Arc<IocFilter>,
    loader: Arc<FeedLoader>,
    interval: Duration,
}

impl IocRefreshTask {
    /// Create a new refresh task.
    ///
    /// * `filter`   — shared filter to rebuild on each cycle.
    /// * `loader`   — feed loader used to fetch fresh IOC data.
    /// * `interval` — how often to rebuild the filter (typically 5 minutes).
    #[must_use]
    pub fn new(filter: Arc<IocFilter>, loader: Arc<FeedLoader>, interval: Duration) -> Self {
        Self {
            filter,
            loader,
            interval,
        }
    }

    /// Spawn the refresh task onto the current Tokio runtime.
    ///
    /// The task runs until `shutdown` receives the value `true`.  The returned
    /// [`tokio::task::JoinHandle`] can be awaited or aborted by the caller.
    #[must_use]
    pub fn spawn(
        self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            // The first tick fires immediately so the filter is populated
            // before the first real interval elapses.
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let loaded = self.run_refresh().await;
                        info!(entries = loaded, "IOC filter refresh complete");
                    }
                    result = shutdown.changed() => {
                        match result {
                            Ok(()) if *shutdown.borrow() => {
                                info!("IOC refresh task received shutdown signal — exiting");
                                break;
                            }
                            Ok(()) => {
                                // Value changed but not to `true`; keep running.
                            }
                            Err(e) => {
                                error!(
                                    error = %e,
                                    "IOC refresh task: shutdown channel closed unexpectedly"
                                );
                                break;
                            }
                        }
                    }
                }
            }
        })
    }

    /// Fetch all feeds and rebuild the filter.
    ///
    /// Returns the number of IOC entries loaded.
    #[instrument(skip(self), name = "ioc_refresh")]
    async fn run_refresh(&self) -> usize {
        let start = Instant::now();
        let entries = self.loader.load_all().await;
        let count = entries.len();
        self.filter.rebuild(entries.into_iter());
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = start.elapsed().as_millis() as u64;
        record_refresh_duration_ms(elapsed_ms);
        tracing::info!(
            entries = count,
            duration_ms = elapsed_ms,
            "IOC bloom filter rebuilt"
        );
        count
    }
}
