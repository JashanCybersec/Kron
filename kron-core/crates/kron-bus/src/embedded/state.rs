//! Shared state for the embedded bus: topic registry and global wakeup notify.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use kron_types::EmbeddedBusConfig;
use tokio::sync::Notify;

use super::wal::Wal;
use crate::error::BusError;

/// A single topic's runtime state.
pub struct TopicEntry {
    /// The write-ahead log for this topic.
    pub wal: Wal,
    /// Per-group committed offsets: `group_id` → last committed offset + 1.
    committed: HashMap<String, u64>,
}

impl TopicEntry {
    /// Returns the minimum committed offset across all consumer groups,
    /// or 0 if no groups are registered.
    #[must_use]
    pub fn min_committed_offset(&self) -> u64 {
        self.committed.values().copied().min().unwrap_or(0)
    }

    /// Commits `offset` for `group_id`.
    pub fn commit(&mut self, group_id: &str, offset: u64) {
        let entry = self.committed.entry(group_id.to_owned()).or_insert(0);
        // Only advance — never move offset backwards.
        if offset + 1 > *entry {
            *entry = offset + 1;
        }
    }

    /// Returns the committed offset (= next offset to deliver) for `group_id`.
    #[must_use]
    pub fn committed_offset(&self, group_id: &str) -> u64 {
        self.committed.get(group_id).copied().unwrap_or(0)
    }
}

/// Registry of all open topic WALs.
#[derive(Default)]
pub struct TopicRegistry {
    topics: HashMap<String, TopicEntry>,
}

impl TopicRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the [`TopicEntry`] for `topic_name`, creating it if necessary.
    ///
    /// # Errors
    /// Returns [`BusError::Wal`] if the WAL file cannot be opened.
    pub fn get_or_create(
        &mut self,
        topic_name: &str,
        data_dir: &Path,
    ) -> Result<&mut TopicEntry, BusError> {
        if !self.topics.contains_key(topic_name) {
            let wal = Wal::open(data_dir, topic_name)?;
            self.topics.insert(
                topic_name.to_owned(),
                TopicEntry {
                    wal,
                    committed: HashMap::new(),
                },
            );
        }
        // Safety: we just inserted if not present, so this is guaranteed to succeed.
        self.topics.get_mut(topic_name).ok_or_else(|| {
            BusError::Internal(format!(
                "topic registry entry disappeared after insert for '{topic_name}'"
            ))
        })
    }

    /// Returns a mutable reference to an existing topic entry.
    ///
    /// # Errors
    /// Returns [`BusError::TopicNotFound`] if the topic has not been created yet.
    pub fn get_mut(&mut self, topic_name: &str) -> Result<&mut TopicEntry, BusError> {
        self.topics
            .get_mut(topic_name)
            .ok_or_else(|| BusError::TopicNotFound(topic_name.to_owned()))
    }
}

/// Shared state for all embedded bus producers and consumers.
pub struct EmbeddedBusState {
    /// Embedded bus configuration (data dir, limits, etc.).
    pub config: EmbeddedBusConfig,
    /// Thread-safe registry of topic WALs and consumer offsets.
    pub topics: Mutex<TopicRegistry>,
    /// Global notify: signalled whenever any message is appended.
    pub notify: Arc<Notify>,
}

impl EmbeddedBusState {
    /// Creates new shared state backed by `config`.
    ///
    /// # Errors
    /// Returns [`BusError::Io`] if `config.data_dir` cannot be created.
    pub fn new(config: EmbeddedBusConfig) -> Result<Arc<Self>, BusError> {
        std::fs::create_dir_all(&config.data_dir)?;
        Ok(Arc::new(Self {
            config,
            topics: Mutex::new(TopicRegistry::new()),
            notify: Arc::new(Notify::new()),
        }))
    }

    /// Wakes all waiting consumers.
    pub fn notify_all(&self) {
        self.notify.notify_waiters();
    }

    /// Returns a short label for the topic suitable for use in metric labels.
    ///
    /// Currently returns the topic name unchanged; may be truncated in future
    /// if label cardinality becomes a concern.
    #[must_use]
    pub fn topic_name_for_metrics<'a>(&self, topic: &'a str) -> &'a str {
        topic
    }
}
