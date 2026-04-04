//! Single segment file for the disk buffer.
//!
//! Each segment is an append-only file of length-prefixed records:
//!
//! ```text
//! [4: body_len LE u32] [body_len: UTF-8 JSON] [4: xxhash32 checksum LE u32]
//! ```
//!
//! The checksum covers the `body_len` + `body` bytes together, allowing
//! truncation of partial records on crash recovery.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use kron_types::KronEvent;
use xxhash_rust::xxh3::xxh3_64;

use crate::error::AgentError;

/// A segment file opened in append mode.
pub struct Segment {
    file: File,
    #[allow(dead_code)]
    mode: SegmentMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentMode {
    Append,
    Read,
}

impl Segment {
    /// Opens a segment file for appending (creates if not present).
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] on I/O failure.
    pub fn open_append(path: &Path) -> Result<Self, AgentError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AgentError::Buffer(format!("open segment {}: {e}", path.display())))?;
        Ok(Self {
            file,
            mode: SegmentMode::Append,
        })
    }

    /// Opens a segment file for reading.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] on I/O failure.
    pub fn open_read(path: &Path) -> Result<Self, AgentError> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| AgentError::Buffer(format!("open segment {}: {e}", path.display())))?;
        Ok(Self {
            file,
            mode: SegmentMode::Read,
        })
    }

    /// Appends a JSON-encoded event body to the segment.
    ///
    /// Returns the number of bytes written (header + body + checksum).
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] on I/O failure.
    pub fn append(&mut self, json_body: &[u8]) -> Result<u64, AgentError> {
        let len = u32::try_from(json_body.len()).map_err(|e| {
            AgentError::Buffer(format!("event JSON too large for segment (max 4 GiB): {e}"))
        })?;
        let checksum: u64 = {
            let mut data = Vec::with_capacity(4 + json_body.len());
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(json_body);
            xxh3_64(&data)
        };

        let mut writer = BufWriter::new(&mut self.file);
        writer
            .write_all(&len.to_le_bytes())
            .map_err(|e| AgentError::Buffer(format!("write segment len prefix: {e}")))?;
        writer
            .write_all(json_body)
            .map_err(|e| AgentError::Buffer(format!("write segment body: {e}")))?;
        writer
            .write_all(&checksum.to_le_bytes())
            .map_err(|e| AgentError::Buffer(format!("write segment checksum: {e}")))?;
        writer
            .flush()
            .map_err(|e| AgentError::Buffer(format!("flush segment: {e}")))?;

        Ok(4 + u64::from(len) + 4)
    }

    /// Reads one event starting at `offset` bytes from the start of the segment.
    ///
    /// Returns `Ok(Some((event, new_offset)))` if a valid record was found, or
    /// `Ok(None)` if `offset` is at the end of the file.
    ///
    /// Partial or corrupt records (checksum mismatch, body too short) are
    /// logged as warnings and `None` is returned to signal end-of-segment.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] on hard I/O failures.
    pub fn read_at(&mut self, offset: u64) -> Result<Option<(KronEvent, u64)>, AgentError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| AgentError::Buffer(format!("seek in segment: {e}")))?;

        let mut reader = BufReader::new(&mut self.file);

        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => {
                return Err(AgentError::Buffer(format!("read len prefix: {e}")));
            }
        }
        // u32 body length from disk — fits in usize on all supported (64-bit) platforms.
        #[allow(clippy::cast_possible_truncation)]
        let body_len = u32::from_le_bytes(len_buf) as usize;

        // Read body.
        let mut body = vec![0u8; body_len];
        match reader.read_exact(&mut body) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::warn!(
                    offset,
                    body_len,
                    "Partial record in segment (body truncated); stopping drain"
                );
                return Ok(None);
            }
            Err(e) => return Err(AgentError::Buffer(format!("read body: {e}"))),
        }

        // Read and verify checksum (u64, 8 bytes).
        let mut cs_buf = [0u8; 8];
        match reader.read_exact(&mut cs_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::warn!(
                    offset,
                    "Partial record in segment (checksum truncated); stopping drain"
                );
                return Ok(None);
            }
            Err(e) => return Err(AgentError::Buffer(format!("read checksum: {e}"))),
        }

        let stored_checksum = u64::from_le_bytes(cs_buf);
        let computed: u64 = {
            let mut data = Vec::with_capacity(4 + body_len);
            // body_len was read from a u32 on-disk, so this conversion is safe.
            #[allow(clippy::cast_possible_truncation)]
            data.extend_from_slice(&(body_len as u32).to_le_bytes());
            data.extend_from_slice(&body);
            xxh3_64(&data)
        };
        if stored_checksum != computed {
            tracing::warn!(
                offset,
                stored_checksum,
                computed,
                "Checksum mismatch in segment; stopping drain"
            );
            return Ok(None);
        }

        let event: KronEvent = serde_json::from_slice(&body).map_err(|e| {
            AgentError::Buffer(format!("JSON decode event at offset {offset}: {e}"))
        })?;

        let new_offset = offset + 4 + body_len as u64 + 8;
        Ok(Some((event, new_offset)))
    }

    /// Counts the number of valid records in the segment.
    ///
    /// Used when dropping a segment to log how many events were lost.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Buffer`] on hard I/O failure.
    pub fn count_records(&mut self) -> Result<usize, AgentError> {
        let mut count = 0;
        let mut offset = 0u64;
        while let Some((_, new_offset)) = self.read_at(offset)? {
            count += 1;
            offset = new_offset;
        }
        Ok(count)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use kron_types::{enums::EventSource, event::KronEvent, ids::TenantId};

    fn make_event() -> KronEvent {
        KronEvent::builder()
            .tenant_id(TenantId::new())
            .source_type(EventSource::LinuxEbpf)
            .event_type("process_create")
            .ts(chrono::Utc::now())
            .build()
            .expect("build test event")
    }

    #[test]
    fn test_segment_when_append_and_read_then_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("seg.buf");
        let event = make_event();
        let json = serde_json::to_vec(&event).expect("serialize");

        {
            let mut seg = Segment::open_append(&path).expect("open append");
            seg.append(&json).expect("append");
        }

        let mut seg = Segment::open_read(&path).expect("open read");
        let (got, new_offset) = seg.read_at(0).expect("read").expect("should have record");
        assert_eq!(got.event_id, event.event_id);
        assert!(new_offset > 0);
    }

    #[test]
    fn test_segment_when_multiple_events_then_all_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("multi.buf");

        let events: Vec<KronEvent> = (0..5).map(|_| make_event()).collect();

        {
            let mut seg = Segment::open_append(&path).expect("open append");
            for ev in &events {
                let json = serde_json::to_vec(ev).expect("serialize");
                seg.append(&json).expect("append");
            }
        }

        let mut seg = Segment::open_read(&path).expect("open read");
        let count = seg.count_records().expect("count");
        assert_eq!(count, 5);
    }

    #[test]
    fn test_segment_when_read_past_end_then_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.buf");
        std::fs::File::create(&path).expect("create");

        let mut seg = Segment::open_read(&path).expect("open read");
        let result = seg.read_at(0).expect("read");
        assert!(result.is_none());
    }
}
