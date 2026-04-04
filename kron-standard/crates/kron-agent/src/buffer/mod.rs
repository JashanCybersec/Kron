//! Local disk buffer for events when the collector is unreachable.
//!
//! # Design
//!
//! Events are persisted as length-prefixed JSON records in segment files
//! under `BufferConfig.data_dir`. The design mirrors the WAL in `kron-bus`
//! but acts as a FIFO queue instead of an offset-indexed log:
//!
//! ```text
//! data_dir/
//!   segment_0000000001.buf   ← oldest, being drained
//!   segment_0000000002.buf   ← being written to
//!   READ_POS                 ← persists (segment_id, byte_offset)
//! ```
//!
//! ## Record format
//!
//! ```text
//! [4: body_len LE u32] [body_len: UTF-8 JSON of KronEvent] [4: xxhash32 checksum LE u32]
//! ```
//!
//! ## Segment rotation
//!
//! A new segment is created when the current segment reaches
//! `BufferConfig.segment_size_bytes()`.
//!
//! ## Capacity enforcement
//!
//! Before writing, total byte usage is checked against
//! `BufferConfig.max_size_bytes()`. If the limit would be exceeded, the
//! oldest segment is deleted and its events are counted as dropped.
//!
//! ## Crash recovery
//!
//! On `DiskBuffer::open`, the read position is restored from `READ_POS`.
//! Partial records at the end of a segment are detected via checksum and
//! truncated.

pub mod segment;

use std::fs;
use std::path::{Path, PathBuf};

use kron_types::KronEvent;

use crate::config::BufferConfig;
use crate::error::AgentError;
use crate::metrics;

use segment::Segment;

/// Filename for the persisted read position.
const READ_POS_FILE: &str = "READ_POS";

/// Stored read position: (`segment_id`, `byte_offset_in_segment`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ReadPos {
    segment_id: u64,
    offset: u64,
}

/// FIFO disk buffer for events that could not be sent to the collector.
///
/// All public methods execute synchronously (no async). Callers must wrap
/// calls in `tokio::task::spawn_blocking` when used from async context.
pub struct DiskBuffer {
    data_dir: PathBuf,
    config: BufferConfig,
    /// ID of the segment currently being written.
    write_segment_id: u64,
    /// Total bytes used across all segments (approximate; refreshed on open).
    total_bytes: u64,
    read_pos: ReadPos,
}

impl DiskBuffer {
    /// Opens (or creates) the disk buffer at `config.data_dir`.
    ///
    /// Existing segments are scanned to compute total byte usage.
    /// The read position is restored from `READ_POS` if it exists.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] if the data directory cannot be created
    /// or the read position file is corrupt.
    pub fn open(config: BufferConfig) -> Result<Self, AgentError> {
        fs::create_dir_all(&config.data_dir).map_err(|e| {
            AgentError::Buffer(format!(
                "cannot create buffer dir {}: {e}",
                config.data_dir.display()
            ))
        })?;

        let segment_ids = Self::list_segment_ids(&config.data_dir)?;

        let total_bytes = segment_ids
            .iter()
            .map(|&id| Self::segment_path(&config.data_dir, id))
            .filter_map(|p| fs::metadata(&p).ok())
            .map(|m| m.len())
            .sum();

        let write_segment_id = segment_ids.last().copied().unwrap_or(1);

        let read_pos = Self::load_read_pos(&config.data_dir)?.unwrap_or(ReadPos {
            segment_id: segment_ids.first().copied().unwrap_or(1),
            offset: 0,
        });

        tracing::info!(
            dir = %config.data_dir.display(),
            segments = segment_ids.len(),
            total_bytes,
            "Disk buffer opened"
        );

        Ok(Self {
            data_dir: config.data_dir.clone(),
            config,
            write_segment_id,
            total_bytes,
            read_pos,
        })
    }

    /// Appends a batch of [`KronEvent`]s to the disk buffer.
    ///
    /// If the current segment is full, a new one is created.
    /// If adding these events would exceed the configured maximum capacity,
    /// the oldest segment(s) are deleted to free space (events are dropped
    /// with a warning log and metric).
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] on I/O failure.
    pub fn push_batch(&mut self, events: &[KronEvent]) -> Result<(), AgentError> {
        for event in events {
            self.push_one(event)?;
        }
        Ok(())
    }

    /// Reads and removes up to `max_count` events from the front of the buffer.
    ///
    /// Returns an empty `Vec` if the buffer is empty.
    /// Advances the read position atomically after each event.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] on I/O failure.
    pub fn drain(&mut self, max_count: usize) -> Result<Vec<KronEvent>, AgentError> {
        let mut result = Vec::with_capacity(max_count);

        while result.len() < max_count {
            let segment_path = Self::segment_path(&self.data_dir, self.read_pos.segment_id);

            if !segment_path.exists() {
                // Buffer is empty.
                break;
            }

            let mut seg = Segment::open_read(&segment_path)?;
            if let Some((event, new_offset)) = seg.read_at(self.read_pos.offset)? {
                result.push(event);
                self.read_pos.offset = new_offset;
                self.save_read_pos()?;
            } else {
                // End of this segment; advance to the next.
                let next_id = self.read_pos.segment_id + 1;
                let next_path = Self::segment_path(&self.data_dir, next_id);
                if next_path.exists() || next_id <= self.write_segment_id {
                    // Delete the fully-consumed segment.
                    let freed = fs::metadata(&segment_path).map(|m| m.len()).unwrap_or(0);
                    fs::remove_file(&segment_path).map_err(|e| {
                        AgentError::Buffer(format!(
                            "cannot remove drained segment {}: {e}",
                            segment_path.display()
                        ))
                    })?;
                    self.total_bytes = self.total_bytes.saturating_sub(freed);
                    self.read_pos = ReadPos {
                        segment_id: next_id,
                        offset: 0,
                    };
                    self.save_read_pos()?;
                } else {
                    // No next segment — buffer is empty.
                    break;
                }
            }
        }

        metrics::set_disk_buffer_bytes(self.total_bytes);
        Ok(result)
    }

    /// Returns the approximate number of bytes used by the buffer on disk.
    #[must_use]
    #[allow(dead_code)]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns `true` if the buffer contains no unread events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let current = Self::segment_path(&self.data_dir, self.read_pos.segment_id);
        if !current.exists() {
            return true;
        }
        // Quick check: if the write segment is the same as the read segment
        // and the read offset equals the write segment's size, the buffer is empty.
        if self.read_pos.segment_id == self.write_segment_id {
            let size = fs::metadata(&current).map(|m| m.len()).unwrap_or(0);
            return self.read_pos.offset >= size;
        }
        false
    }

    // ─── private helpers ─────────────────────────────────────────────────────

    fn push_one(&mut self, event: &KronEvent) -> Result<(), AgentError> {
        let json = serde_json::to_vec(event)?;
        let record_size = 4 + json.len() as u64 + 8; // len_prefix + body + u64 checksum

        // Enforce capacity: drop oldest segments if needed.
        self.enforce_capacity(record_size)?;

        // Rotate segment if current one is full.
        let seg_path = Self::segment_path(&self.data_dir, self.write_segment_id);
        if seg_path.exists() {
            let seg_size = fs::metadata(&seg_path).map(|m| m.len()).unwrap_or(0);
            if seg_size + record_size > self.config.segment_size_bytes() {
                self.write_segment_id += 1;
            }
        }

        let seg_path = Self::segment_path(&self.data_dir, self.write_segment_id);
        let mut seg = Segment::open_append(&seg_path)?;
        let written = seg.append(&json)?;
        self.total_bytes += written;

        metrics::set_disk_buffer_bytes(self.total_bytes);
        Ok(())
    }

    fn enforce_capacity(&mut self, needed: u64) -> Result<(), AgentError> {
        while self.total_bytes + needed > self.config.max_size_bytes() {
            let segment_ids = Self::list_segment_ids(&self.data_dir)?;
            let Some(&oldest_id) = segment_ids.first() else {
                break;
            };

            // Never drop the segment we are currently reading.
            if oldest_id >= self.read_pos.segment_id {
                // All segments are being actively read; cannot free more.
                tracing::warn!(
                    total_bytes = self.total_bytes,
                    max_bytes = self.config.max_size_bytes(),
                    "Disk buffer full and cannot drop segments in use — events may be lost"
                );
                break;
            }

            let oldest_path = Self::segment_path(&self.data_dir, oldest_id);
            let freed = fs::metadata(&oldest_path).map(|m| m.len()).unwrap_or(0);

            // Count the events we are dropping for the metric/log.
            let dropped = Segment::open_read(&oldest_path)
                .and_then(|mut s| s.count_records())
                .unwrap_or(0);

            fs::remove_file(&oldest_path)
                .map_err(|e| AgentError::Buffer(format!("cannot drop oldest segment: {e}")))?;
            self.total_bytes = self.total_bytes.saturating_sub(freed);

            tracing::warn!(
                segment_id = oldest_id,
                dropped_events = dropped,
                "Disk buffer full: dropped oldest segment to make room"
            );
            metrics::record_events_dropped(dropped as u64);
        }
        Ok(())
    }

    fn segment_path(data_dir: &Path, id: u64) -> PathBuf {
        data_dir.join(format!("segment_{id:010}.buf"))
    }

    fn list_segment_ids(data_dir: &Path) -> Result<Vec<u64>, AgentError> {
        let mut ids = Vec::new();
        let entries = match fs::read_dir(data_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
            Err(e) => {
                return Err(AgentError::Buffer(format!(
                    "cannot read buffer dir {}: {e}",
                    data_dir.display()
                )))
            }
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(rest) = name_str.strip_prefix("segment_") {
                if let Some(id_str) = rest.strip_suffix(".buf") {
                    if let Ok(id) = id_str.parse::<u64>() {
                        ids.push(id);
                    }
                }
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    fn load_read_pos(data_dir: &Path) -> Result<Option<ReadPos>, AgentError> {
        let path = data_dir.join(READ_POS_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)
            .map_err(|e| AgentError::Buffer(format!("cannot read READ_POS: {e}")))?;
        let pos: ReadPos = serde_json::from_str(&content)
            .map_err(|e| AgentError::Buffer(format!("corrupt READ_POS: {e}")))?;
        Ok(Some(pos))
    }

    fn save_read_pos(&self) -> Result<(), AgentError> {
        let path = self.data_dir.join(READ_POS_FILE);
        let content = serde_json::to_string(&self.read_pos)?;
        // Write to temp file then rename for atomicity.
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &content)
            .map_err(|e| AgentError::Buffer(format!("cannot write READ_POS.tmp: {e}")))?;
        fs::rename(&tmp, &path)
            .map_err(|e| AgentError::Buffer(format!("cannot rename READ_POS.tmp: {e}")))?;
        Ok(())
    }
}
