//! Write-ahead log (WAL) for the embedded Nano-tier message bus.
//!
//! Each topic has one WAL file stored at `{data_dir}/{sanitized_topic}/wal.bin`.
//! The WAL is append-only with sequential record offsets. An in-memory index
//! (offset → byte position) is built on open by scanning the file.
//!
//! # Crash safety
//!
//! If the process crashes during a write, the last record may be partial.
//! On next open, [`Wal::open`] scans records and stops at the first one with
//! an invalid checksum, truncating the file to remove the partial record.
//!
//! # Compaction
//!
//! [`Wal::compact`] rewrites the WAL starting from `min_offset`, discarding
//! older records. Call this periodically when all consumer groups have
//! committed past a certain offset.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use chrono::Utc;
use xxhash_rust::xxh3::xxh3_64;

use crate::error::BusError;
use crate::traits::BusMessage;

/// Magic bytes identifying a KRON WAL file: ASCII "KRONWLOG".
const WAL_MAGIC: u64 = 0x4B52_4F4E_574C_4F47;
/// WAL format version stored in the file header.
const WAL_VERSION: u64 = 1;
/// Size of the WAL file header in bytes.
const HEADER_SIZE: u64 = 16;

/// An entry in the in-memory WAL index.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    /// Monotonic message offset.
    offset: u64,
    /// Byte position of `record_body_len` in the WAL file.
    byte_pos: u64,
}

/// Write-ahead log for a single topic.
///
/// All methods are synchronous and must be called from within
/// `tokio::task::spawn_blocking` to avoid blocking the async runtime.
pub struct Wal {
    /// Absolute path to the WAL file.
    path: PathBuf,
    /// Read-write file handle (positioned at end for appends).
    file: File,
    /// In-memory index: ordered by offset.
    index: Vec<IndexEntry>,
    /// Next offset to assign to the next appended record.
    next_offset: u64,
    /// Topic name (used in error messages).
    topic: String,
}

impl Wal {
    /// Opens (or creates) the WAL file for `topic` under `data_dir`.
    ///
    /// Scans the existing WAL to rebuild the in-memory index. Truncates any
    /// partial record at the end of the file.
    ///
    /// # Errors
    /// Returns [`BusError::Io`] if the file cannot be opened or read.
    /// Returns [`BusError::Wal`] if the file header is invalid.
    pub fn open(data_dir: &Path, topic: &str) -> Result<Self, BusError> {
        let topic_dir = data_dir.join(sanitize_topic_name(topic));
        fs::create_dir_all(&topic_dir)?;

        let wal_path = topic_dir.join("wal.bin");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&wal_path)?;

        let mut wal = Self {
            path: wal_path,
            file,
            index: Vec::new(),
            next_offset: 0,
            topic: topic.to_owned(),
        };

        wal.initialize()?;
        Ok(wal)
    }

    /// Initialises the WAL: writes the header on a new file, or validates and
    /// scans an existing file to rebuild the index.
    fn initialize(&mut self) -> Result<(), BusError> {
        let file_len = self.file.seek(SeekFrom::End(0))?;

        if file_len == 0 {
            // Brand-new WAL file — write header.
            self.file.seek(SeekFrom::Start(0))?;
            {
                // BufWriter scope: must be dropped before seeking again.
                let mut w = BufWriter::new(&self.file);
                w.write_all(&WAL_MAGIC.to_be_bytes())?;
                w.write_all(&WAL_VERSION.to_le_bytes())?;
                w.flush()?;
            }
            self.file.seek(SeekFrom::End(0))?;
            return Ok(());
        }

        // Existing file — validate header.
        self.file.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; 16];
        self.file
            .read_exact(&mut header)
            .map_err(|e| BusError::Wal {
                topic: self.topic.clone(),
                reason: format!("cannot read WAL header: {e}"),
            })?;

        let magic = u64::from_be_bytes(header[0..8].try_into().map_err(|_| BusError::Wal {
            topic: self.topic.clone(),
            reason: "WAL header too short for magic bytes".to_owned(),
        })?);
        if magic != WAL_MAGIC {
            return Err(BusError::Wal {
                topic: self.topic.clone(),
                reason: format!("invalid WAL magic: expected {WAL_MAGIC:#x}, got {magic:#x}"),
            });
        }

        let version = u64::from_le_bytes(header[8..16].try_into().map_err(|_| BusError::Wal {
            topic: self.topic.clone(),
            reason: "WAL header too short for version bytes".to_owned(),
        })?);
        if version != WAL_VERSION {
            return Err(BusError::Wal {
                topic: self.topic.clone(),
                reason: format!("unsupported WAL version {version}; expected {WAL_VERSION}"),
            });
        }

        // Scan records to build index.
        self.scan_and_build_index()?;
        Ok(())
    }

    /// Scans all records from the header to EOF, builds the in-memory index,
    /// and truncates any partial record at the end.
    fn scan_and_build_index(&mut self) -> Result<(), BusError> {
        self.file.seek(SeekFrom::Start(HEADER_SIZE))?;
        let mut index = Vec::new();
        let mut last_valid_pos = HEADER_SIZE;

        loop {
            let record_start = self.file.stream_position().map_err(BusError::Io)?;

            // Read record_body_len (4 bytes).
            let mut len_buf = [0u8; 4];
            match self.file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(BusError::Io(e)),
            }
            let record_body_len = u64::from(u32::from_le_bytes(len_buf));

            // Read the record body.
            let mut body = vec![
                0u8;
                usize::try_from(record_body_len).map_err(|e| BusError::Wal {
                    topic: self.topic.clone(),
                    reason: format!("record body length too large for platform: {e}"),
                })?
            ];
            match self.file.read_exact(&mut body) {
                Ok(()) => {}
                Err(_) => {
                    // Partial record — will be truncated below.
                    break;
                }
            }

            // Validate: offset is first 8 bytes of body.
            if body.len() < 8 {
                break;
            }
            let offset = u64::from_le_bytes(body[0..8].try_into().map_err(|_| BusError::Wal {
                topic: self.topic.clone(),
                reason: "record body too short to contain offset".to_owned(),
            })?);

            // Validate checksum: last 8 bytes of body.
            if body.len() < 16 {
                break;
            }
            let checksum_offset = body.len() - 8;
            let stored_checksum =
                u64::from_le_bytes(body[checksum_offset..].try_into().map_err(|_| {
                    BusError::Wal {
                        topic: self.topic.clone(),
                        reason: "record body too short for checksum".to_owned(),
                    }
                })?);
            let computed_checksum = xxh3_64(&body[..checksum_offset]);
            if stored_checksum != computed_checksum {
                tracing::warn!(
                    topic = %self.topic,
                    byte_pos = record_start,
                    offset,
                    "WAL checksum mismatch — truncating at this record"
                );
                break;
            }

            index.push(IndexEntry {
                offset,
                byte_pos: record_start,
            });
            last_valid_pos = record_start + 4 + record_body_len;
        }

        // Truncate any partial record.
        let current_len = self.file.seek(SeekFrom::End(0))?;
        if current_len != last_valid_pos {
            tracing::info!(
                topic = %self.topic,
                truncated_bytes = current_len - last_valid_pos,
                "Truncating partial WAL record"
            );
            self.file.set_len(last_valid_pos)?;
        }

        self.next_offset = index.last().map_or(0, |e| e.offset + 1);
        self.index = index;
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }

    /// Appends a message to the WAL and returns its assigned offset.
    ///
    /// # Arguments
    /// * `id` — Unique message ID (UUID string).
    /// * `key` — Optional routing key.
    /// * `headers` — Key-value headers.
    /// * `payload` — Message payload bytes.
    /// * `sync` — If true, calls `sync_data()` after write for crash durability.
    ///
    /// # Errors
    /// Returns [`BusError::Io`] on file write failure.
    /// Returns [`BusError::Serialization`] if headers cannot be serialized.
    pub fn append(
        &mut self,
        id: &str,
        key: Option<&[u8]>,
        headers: &HashMap<String, String>,
        payload: &[u8],
        sync: bool,
    ) -> Result<u64, BusError> {
        let offset = self.next_offset;
        // timestamp_millis() returns i64; UNIX epoch ms is always positive for current time.
        #[allow(clippy::cast_sign_loss)]
        let timestamp_ms = Utc::now().timestamp_millis() as u64;

        let id_bytes = id.as_bytes();
        let id_len = u16::try_from(id_bytes.len()).map_err(|e| BusError::Wal {
            topic: self.topic.clone(),
            reason: format!("message ID too long for WAL (max 65535 bytes): {e}"),
        })?;

        let key_bytes = key.unwrap_or(&[]);
        let key_len = u16::try_from(key_bytes.len()).map_err(|e| BusError::Wal {
            topic: self.topic.clone(),
            reason: format!("message key too long for WAL (max 65535 bytes): {e}"),
        })?;

        let headers_json = serde_json::to_vec(headers)
            .map_err(|e| BusError::Serialization(format!("failed to serialize headers: {e}")))?;
        let headers_json_len = u32::try_from(headers_json.len()).map_err(|e| BusError::Wal {
            topic: self.topic.clone(),
            reason: format!("headers JSON too large for WAL (max 4 GiB): {e}"),
        })?;

        let payload_len = u32::try_from(payload.len()).map_err(|e| BusError::Wal {
            topic: self.topic.clone(),
            reason: format!("payload too large for WAL (max 4 GiB): {e}"),
        })?;

        // Build the record body (everything except record_body_len and checksum).
        let body_without_checksum_len: usize = 8  // offset
            + 8  // timestamp_ms
            + 2 + id_bytes.len()
            + 2 + key_bytes.len()
            + 4 + headers_json.len()
            + 4 + payload.len();

        let mut body = Vec::with_capacity(body_without_checksum_len + 8);
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&timestamp_ms.to_le_bytes());
        body.extend_from_slice(&id_len.to_le_bytes());
        body.extend_from_slice(id_bytes);
        body.extend_from_slice(&key_len.to_le_bytes());
        body.extend_from_slice(key_bytes);
        body.extend_from_slice(&headers_json_len.to_le_bytes());
        body.extend_from_slice(&headers_json);
        body.extend_from_slice(&payload_len.to_le_bytes());
        body.extend_from_slice(payload);

        let checksum = xxh3_64(&body);
        body.extend_from_slice(&checksum.to_le_bytes());

        let record_body_len = u32::try_from(body.len()).map_err(|e| BusError::Wal {
            topic: self.topic.clone(),
            reason: format!("record body too large for WAL (max 4 GiB): {e}"),
        })?;
        let byte_pos = self.file.seek(SeekFrom::End(0))?;

        let mut w = BufWriter::new(&self.file);
        w.write_all(&record_body_len.to_le_bytes())?;
        w.write_all(&body)?;
        w.flush()?;

        if sync {
            self.file.sync_data()?;
        }

        self.index.push(IndexEntry { offset, byte_pos });
        self.next_offset = offset + 1;

        tracing::trace!(
            topic = %self.topic,
            offset,
            payload_len = payload.len(),
            "WAL record appended"
        );

        Ok(offset)
    }

    /// Reads the record at `offset` and returns a [`BusMessage`].
    ///
    /// Returns `None` if `offset` is beyond the current end of the WAL.
    ///
    /// # Errors
    /// Returns [`BusError::Io`] on file read failure.
    /// Returns [`BusError::Wal`] if the record is corrupt.
    pub fn read_at_offset(
        &mut self,
        topic: &str,
        offset: u64,
    ) -> Result<Option<BusMessage>, BusError> {
        let Some(byte_pos) = self.byte_pos_for_offset(offset) else {
            return Ok(None);
        };

        self.file.seek(SeekFrom::Start(byte_pos))?;

        let mut len_buf = [0u8; 4];
        match self.file.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(BusError::Io(e)),
        }
        let record_body_len =
            usize::try_from(u32::from_le_bytes(len_buf)).map_err(|e| BusError::Wal {
                topic: topic.to_owned(),
                reason: format!("record body length too large for platform: {e}"),
            })?;

        let mut body = vec![0u8; record_body_len];
        self.file.read_exact(&mut body)?;

        if body.len() < 16 {
            return Err(BusError::Wal {
                topic: topic.to_owned(),
                reason: format!(
                    "record at offset {offset} body too short ({} bytes)",
                    body.len()
                ),
            });
        }

        // Validate checksum.
        let checksum_offset = body.len() - 8;
        let stored =
            u64::from_le_bytes(
                body[checksum_offset..]
                    .try_into()
                    .map_err(|_| BusError::Wal {
                        topic: topic.to_owned(),
                        reason: format!("record at offset {offset}: cannot read checksum"),
                    })?,
            );
        let computed = xxh3_64(&body[..checksum_offset]);
        if stored != computed {
            return Err(BusError::Wal {
                topic: topic.to_owned(),
                reason: format!("record at offset {offset}: checksum mismatch"),
            });
        }

        // Deserialize fields.
        let msg = deserialize_record_body(&body, topic, checksum_offset)?;
        Ok(Some(msg))
    }

    /// Returns the byte position of `offset` in the WAL file, or `None` if not indexed.
    fn byte_pos_for_offset(&self, offset: u64) -> Option<u64> {
        // Binary search since index is ordered by offset.
        self.index
            .binary_search_by_key(&offset, |e| e.offset)
            .ok()
            .map(|idx| self.index[idx].byte_pos)
    }

    /// Returns the number of records currently in the WAL.
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.index.len() as u64
    }

    /// Returns the next offset that will be assigned to the next appended record.
    #[must_use]
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Returns the current WAL file size in bytes.
    ///
    /// # Errors
    /// Returns [`BusError::Io`] on file stat failure.
    pub fn byte_size(&self) -> Result<u64, BusError> {
        Ok(self.file.metadata()?.len())
    }

    /// Compacts the WAL by discarding all records with `offset < min_offset`.
    ///
    /// Rewrites the WAL from `min_offset` into a new temp file, then atomically
    /// renames it over the existing WAL. Rebuilds the in-memory index.
    ///
    /// # Errors
    /// Returns [`BusError::Io`] if the rewrite fails.
    pub fn compact(&mut self, min_offset: u64) -> Result<(), BusError> {
        let parent = self.path.parent().ok_or_else(|| BusError::Wal {
            topic: self.topic.clone(),
            reason: "WAL path has no parent directory".to_owned(),
        })?;

        let tmp_path = parent.join("wal.bin.compact");
        let mut tmp = File::create(&tmp_path)?;

        // Write header.
        tmp.write_all(&WAL_MAGIC.to_be_bytes())?;
        tmp.write_all(&WAL_VERSION.to_le_bytes())?;

        // Copy records from min_offset onwards.
        let mut new_index: Vec<IndexEntry> = Vec::new();
        let mut write_pos: u64 = HEADER_SIZE;

        for entry in &self.index {
            if entry.offset < min_offset {
                continue;
            }

            self.file.seek(SeekFrom::Start(entry.byte_pos))?;

            let mut len_buf = [0u8; 4];
            self.file.read_exact(&mut len_buf)?;
            let record_body_len = u32::from_le_bytes(len_buf) as usize;

            let mut body = vec![0u8; record_body_len];
            self.file.read_exact(&mut body)?;

            tmp.write_all(&len_buf)?;
            tmp.write_all(&body)?;

            new_index.push(IndexEntry {
                offset: entry.offset,
                byte_pos: write_pos,
            });
            write_pos += 4 + record_body_len as u64;
        }

        tmp.sync_data()?;
        drop(tmp);

        // Atomic rename.
        fs::rename(&tmp_path, &self.path)?;

        // Reopen the compacted file.
        self.file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        self.file.seek(SeekFrom::End(0))?;
        self.index = new_index;

        tracing::info!(
            topic = %self.topic,
            min_offset,
            records_retained = self.index.len(),
            "WAL compaction complete"
        );

        Ok(())
    }
}

/// Converts a topic name to a safe directory name by replacing dots and slashes.
fn sanitize_topic_name(topic: &str) -> String {
    topic
        .chars()
        .map(|c| {
            if matches!(c, '.' | '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Deserializes a WAL record body (without the trailing checksum) into a [`BusMessage`].
// The `read_u8_slice!` macro assigns to `cursor` on every call including the last;
// the final assignment is intentionally unused since we only care about the extracted value.
#[allow(unused_assignments)]
fn deserialize_record_body(
    body: &[u8],
    topic: &str,
    body_len_without_checksum: usize,
) -> Result<BusMessage, BusError> {
    let data = &body[..body_len_without_checksum];
    let mut cursor = 0usize;

    macro_rules! read_u8_slice {
        ($n:expr) => {{
            let end = cursor + $n;
            if end > data.len() {
                return Err(BusError::Wal {
                    topic: topic.to_owned(),
                    reason: format!("record truncated at byte {cursor}"),
                });
            }
            let slice = &data[cursor..end];
            cursor = end;
            slice
        }};
    }

    let offset = u64::from_le_bytes(read_u8_slice!(8).try_into().map_err(|_| BusError::Wal {
        topic: topic.to_owned(),
        reason: "offset read".to_owned(),
    })?);
    let timestamp_ms =
        u64::from_le_bytes(read_u8_slice!(8).try_into().map_err(|_| BusError::Wal {
            topic: topic.to_owned(),
            reason: "timestamp read".to_owned(),
        })?);

    let id_len = u16::from_le_bytes(read_u8_slice!(2).try_into().map_err(|_| BusError::Wal {
        topic: topic.to_owned(),
        reason: "id_len read".to_owned(),
    })?) as usize;
    let id = std::str::from_utf8(read_u8_slice!(id_len))
        .map_err(|_| BusError::Deserialization("message ID is not valid UTF-8".to_owned()))?
        .to_owned();

    let key_len = u16::from_le_bytes(read_u8_slice!(2).try_into().map_err(|_| BusError::Wal {
        topic: topic.to_owned(),
        reason: "key_len read".to_owned(),
    })?) as usize;
    let key = if key_len > 0 {
        Some(Bytes::copy_from_slice(read_u8_slice!(key_len)))
    } else {
        None
    };

    let headers_json_len =
        u32::from_le_bytes(read_u8_slice!(4).try_into().map_err(|_| BusError::Wal {
            topic: topic.to_owned(),
            reason: "headers_json_len read".to_owned(),
        })?) as usize;
    let headers: HashMap<String, String> = serde_json::from_slice(read_u8_slice!(headers_json_len))
        .map_err(|e| BusError::Deserialization(format!("failed to deserialize headers: {e}")))?;

    let payload_len =
        u32::from_le_bytes(read_u8_slice!(4).try_into().map_err(|_| BusError::Wal {
            topic: topic.to_owned(),
            reason: "payload_len read".to_owned(),
        })?) as usize;
    let payload = Bytes::copy_from_slice(read_u8_slice!(payload_len));

    // timestamp_ms was stored as u64 but originates from i64 millis; values
    // within the valid range of i64 are safe to convert back.
    let timestamp_i64 = i64::try_from(timestamp_ms).unwrap_or(i64::MAX);
    let timestamp = chrono::DateTime::from_timestamp_millis(timestamp_i64).unwrap_or_else(Utc::now);

    Ok(BusMessage {
        id,
        topic: topic.to_owned(),
        partition: -1,
        offset,
        key,
        payload,
        headers,
        timestamp,
        retry_count: 0,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tmp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn test_wal_when_new_then_opens_and_writes_header() {
        let dir = tmp_dir();
        let wal = Wal::open(dir.path(), "kron.raw.test");
        assert!(wal.is_ok());
        let wal = wal.unwrap();
        assert_eq!(wal.next_offset(), 0);
        assert_eq!(wal.record_count(), 0);
    }

    #[test]
    fn test_wal_when_appended_then_record_readable() {
        let dir = tmp_dir();
        let mut wal = Wal::open(dir.path(), "kron.test").unwrap();
        let mut headers = HashMap::new();
        headers.insert("tenant".to_owned(), "t1".to_owned());

        let offset = wal
            .append("msg-id-1", None, &headers, b"hello world", false)
            .unwrap();
        assert_eq!(offset, 0);
        assert_eq!(wal.next_offset(), 1);

        let msg = wal.read_at_offset("kron.test", 0).unwrap();
        assert!(msg.is_some());
        let msg = msg.unwrap();
        assert_eq!(msg.id, "msg-id-1");
        assert_eq!(msg.payload.as_ref(), b"hello world");
        assert_eq!(msg.headers.get("tenant"), Some(&"t1".to_owned()));
    }

    #[test]
    fn test_wal_when_reopened_then_index_rebuilt() {
        let dir = tmp_dir();
        {
            let mut wal = Wal::open(dir.path(), "kron.test").unwrap();
            wal.append("id-1", None, &HashMap::new(), b"payload1", false)
                .unwrap();
            wal.append("id-2", None, &HashMap::new(), b"payload2", false)
                .unwrap();
        }

        // Reopen — should rebuild index from file.
        let wal = Wal::open(dir.path(), "kron.test").unwrap();
        assert_eq!(wal.record_count(), 2);
        assert_eq!(wal.next_offset(), 2);
    }

    #[test]
    fn test_wal_when_offset_beyond_end_then_returns_none() {
        let dir = tmp_dir();
        let mut wal = Wal::open(dir.path(), "kron.test").unwrap();
        let msg = wal.read_at_offset("kron.test", 99).unwrap();
        assert!(msg.is_none());
    }

    #[test]
    fn test_wal_compact_when_min_offset_set_then_removes_old_records() {
        let dir = tmp_dir();
        let mut wal = Wal::open(dir.path(), "kron.test").unwrap();
        for i in 0..10u8 {
            wal.append(&format!("id-{i}"), None, &HashMap::new(), &[i], false)
                .unwrap();
        }
        assert_eq!(wal.record_count(), 10);

        // Compact: discard offsets 0..5, keep 5..9.
        wal.compact(5).unwrap();
        assert_eq!(wal.record_count(), 5);

        // Records at offsets < 5 must be gone; >= 5 must still be readable.
        let old = wal.read_at_offset("kron.test", 0).unwrap();
        assert!(old.is_none());

        let kept = wal.read_at_offset("kron.test", 5).unwrap();
        assert!(kept.is_some());
    }
}
