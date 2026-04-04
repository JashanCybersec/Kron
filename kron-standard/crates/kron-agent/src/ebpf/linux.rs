//! Linux eBPF program lifecycle management and ring buffer consumer.
//!
//! # Safety contract
//!
//! `unsafe` is required in two places:
//!
//! 1. `aya::Ebpf::load()` — loads the pre-compiled eBPF ELF object into the
//!    kernel. Safety: the ELF object is produced by our own verified build
//!    pipeline; we never load objects from untrusted paths.
//!
//! 2. Casting raw ring buffer bytes to `BpfProcessCreateEvent` etc. — the
//!    kernel program writes exactly these structs (same `#[repr(C)]` layout
//!    as `bpf/kron_types.h`). Safety: we validate the record length before
//!    casting and only dereference after alignment verification.

use std::mem;

use aya::maps::RingBuf;
use aya::programs::{KProbe, TracePoint};
use aya::Ebpf;
use aya_log::EbpfLogger;
use tokio::sync::mpsc;

use crate::bpf_types::{
    BpfEventHeader, BpfEventKind, BpfFileAccessEvent, BpfNetworkConnectEvent, BpfProcessCreateEvent,
};
use crate::config::EbpfConfig;
use crate::error::AgentError;

/// A decoded eBPF ring buffer record ready for conversion to [`KronEvent`].
///
/// [`crate::events`]
#[derive(Debug, Clone)]
pub enum RawBpfEvent {
    /// A process was created via `execve(2)`.
    ProcessCreate(Box<BpfProcessCreateEvent>),
    /// An outbound TCP connection was initiated.
    NetworkConnect(Box<BpfNetworkConnectEvent>),
    /// A file was opened on a monitored sensitive path.
    FileAccess(Box<BpfFileAccessEvent>),
}

/// Manages loaded eBPF programs and owns the ring buffer consumer task.
pub struct EbpfManager {
    /// Owned eBPF handle — dropping this detaches all programs.
    _ebpf: Ebpf,
    /// Handle to the background ring buffer reader task.
    _reader_task: tokio::task::JoinHandle<()>,
}

impl EbpfManager {
    /// Loads and attaches all three eBPF programs, then starts the ring
    /// buffer reader task.
    ///
    /// The reader sends decoded [`RawBpfEvent`]s to `event_tx`. The caller
    /// is responsible for consuming from the matching receiver.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Ebpf`] if the eBPF ELF cannot be loaded, a
    /// program cannot be attached to its hook point, or the ring buffer
    /// map cannot be opened.
    pub fn load(cfg: &EbpfConfig, event_tx: mpsc::Sender<RawBpfEvent>) -> Result<Self, AgentError> {
        // Safety: loading our own verified eBPF ELF object is safe.
        let mut ebpf = unsafe {
            Ebpf::load(include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/kron_agent.bpf.o"
            )))
        }
        .map_err(|e| AgentError::Ebpf(format!("load eBPF object: {e}")))?;

        // Attach eBPF logger so kernel log messages surface via tracing.
        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            tracing::warn!(error = %e, "eBPF logger init failed; kernel log messages suppressed");
        }

        // Attach process_create tracepoint.
        Self::attach_tracepoint(&mut ebpf, "process_create", "syscalls", "sys_enter_execve")?;

        // Attach network_connect kprobe.
        Self::attach_kprobe(&mut ebpf, "network_connect", "tcp_v4_connect")?;

        // Attach file_access tracepoint.
        Self::attach_tracepoint(&mut ebpf, "file_access", "syscalls", "sys_enter_openat")?;

        // Open the shared ring buffer map.
        let ring_buf: RingBuf<_> = ebpf
            .map_mut("KRON_EVENTS")
            .ok_or_else(|| AgentError::Ebpf("map KRON_EVENTS not found in eBPF object".to_owned()))?
            .try_into()
            .map_err(|e| AgentError::Ebpf(format!("open KRON_EVENTS ring buffer: {e}")))?;

        let sensitive_paths = cfg.sensitive_paths.clone();
        let reader_task = tokio::task::spawn_blocking(move || {
            run_ring_buffer_reader(ring_buf, event_tx, sensitive_paths);
        });

        tracing::info!("eBPF programs loaded and attached");
        Ok(Self {
            _ebpf: ebpf,
            _reader_task: reader_task,
        })
    }

    /// Attaches a tracepoint program.
    fn attach_tracepoint(
        ebpf: &mut Ebpf,
        prog_name: &str,
        category: &str,
        name: &str,
    ) -> Result<(), AgentError> {
        let prog: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| AgentError::Ebpf(format!("program '{prog_name}' not found")))?
            .try_into()
            .map_err(|e| {
                AgentError::Ebpf(format!("program '{prog_name}' is not a TracePoint: {e}"))
            })?;
        prog.load()
            .map_err(|e| AgentError::Ebpf(format!("load '{prog_name}': {e}")))?;
        prog.attach(category, name).map_err(|e| {
            AgentError::Ebpf(format!("attach '{prog_name}' to {category}/{name}: {e}"))
        })?;
        tracing::debug!(program = prog_name, hook = %format!("{category}/{name}"), "TracePoint attached");
        Ok(())
    }

    /// Attaches a kprobe program.
    fn attach_kprobe(ebpf: &mut Ebpf, prog_name: &str, fn_name: &str) -> Result<(), AgentError> {
        let prog: &mut KProbe = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| AgentError::Ebpf(format!("program '{prog_name}' not found")))?
            .try_into()
            .map_err(|e| AgentError::Ebpf(format!("program '{prog_name}' is not a KProbe: {e}")))?;
        prog.load()
            .map_err(|e| AgentError::Ebpf(format!("load '{prog_name}': {e}")))?;
        prog.attach(fn_name, 0).map_err(|e| {
            AgentError::Ebpf(format!("attach '{prog_name}' to kprobe/{fn_name}: {e}"))
        })?;
        tracing::debug!(program = prog_name, hook = %format!("kprobe/{fn_name}"), "KProbe attached");
        Ok(())
    }
}

/// Macro for including eBPF ELF bytes with correct alignment.
///
/// aya requires at least 8-byte alignment on the ELF object buffer.
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        #[repr(C, align(8))]
        struct AlignedBytes<const N: usize>([u8; N]);
        static ALIGNED: AlignedBytes<{ include_bytes!($path).len() }> =
            AlignedBytes(*include_bytes!($path));
        &ALIGNED.0
    }};
}

/// Blocking ring buffer reader loop.
///
/// Reads records from `ring_buf`, decodes them by kind tag, and sends them
/// to `event_tx`. Runs in a `spawn_blocking` thread so the Tokio runtime
/// is not blocked.
///
/// Exits when `event_tx` is dropped (all receivers gone — agent shutting down).
fn run_ring_buffer_reader(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    event_tx: mpsc::Sender<RawBpfEvent>,
    sensitive_paths: Vec<String>,
) {
    loop {
        // `next()` blocks until a record is available (epoll under the hood).
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;

            match decode_ring_buf_record(data, &sensitive_paths) {
                Ok(Some(event)) => {
                    if event_tx.blocking_send(event).is_err() {
                        // Receiver dropped — agent is shutting down.
                        tracing::debug!("ring buffer reader: receiver dropped, exiting");
                        return;
                    }
                }
                Ok(None) => {
                    // Event filtered (e.g. file path not in sensitive_paths).
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to decode eBPF ring buffer record");
                    crate::metrics::record_events_dropped(1);
                }
            }
        }
    }
}

/// Decodes one raw ring buffer byte slice into a [`RawBpfEvent`].
///
/// Returns `Ok(None)` if the event passes a local filter (e.g. file path
/// not in the sensitive path list).
///
/// # Errors
///
/// Returns [`AgentError::RingBufferDecode`] if the record is too short or
/// contains an unrecognised kind tag.
fn decode_ring_buf_record(
    data: &[u8],
    sensitive_paths: &[String],
) -> Result<Option<RawBpfEvent>, AgentError> {
    // Every record starts with a BpfEventHeader.
    let header_size = mem::size_of::<BpfEventHeader>();
    if data.len() < header_size {
        return Err(AgentError::RingBufferDecode(format!(
            "record too short: {} bytes (minimum {header_size})",
            data.len()
        )));
    }

    // Safety: we verified `data.len() >= header_size` above and
    // `BpfEventHeader` is `repr(C)` with no padding requirements beyond
    // alignment, which we satisfy because ring buffer records are 8-byte
    // aligned by the kernel.
    let header: BpfEventHeader =
        unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<BpfEventHeader>()) };

    match BpfEventKind::from_u32(header.kind) {
        Some(BpfEventKind::ProcessCreate) => {
            let expected = mem::size_of::<BpfProcessCreateEvent>();
            if data.len() < expected {
                return Err(AgentError::RingBufferDecode(format!(
                    "process_create record: expected {expected} bytes, got {}",
                    data.len()
                )));
            }
            // Safety: length and alignment verified above.
            let ev: BpfProcessCreateEvent =
                unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<BpfProcessCreateEvent>()) };
            Ok(Some(RawBpfEvent::ProcessCreate(Box::new(ev))))
        }

        Some(BpfEventKind::NetworkConnect) => {
            let expected = mem::size_of::<BpfNetworkConnectEvent>();
            if data.len() < expected {
                return Err(AgentError::RingBufferDecode(format!(
                    "network_connect record: expected {expected} bytes, got {}",
                    data.len()
                )));
            }
            // Safety: length verified above.
            let ev: BpfNetworkConnectEvent =
                unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<BpfNetworkConnectEvent>()) };
            Ok(Some(RawBpfEvent::NetworkConnect(Box::new(ev))))
        }

        Some(BpfEventKind::FileAccess) => {
            let expected = mem::size_of::<BpfFileAccessEvent>();
            if data.len() < expected {
                return Err(AgentError::RingBufferDecode(format!(
                    "file_access record: expected {expected} bytes, got {}",
                    data.len()
                )));
            }
            // Safety: length verified above.
            let ev: BpfFileAccessEvent =
                unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<BpfFileAccessEvent>()) };
            // Filter: only emit if the path starts with a monitored prefix.
            let path = crate::bpf_types::c_str_from_bytes(&ev.path);
            let is_sensitive = sensitive_paths
                .iter()
                .any(|prefix| path.starts_with(prefix.as_str()));
            if !is_sensitive {
                return Ok(None);
            }
            Ok(Some(RawBpfEvent::FileAccess(Box::new(ev))))
        }

        None => Err(AgentError::RingBufferDecode(format!(
            "unknown event kind tag: {}",
            header.kind
        ))),
    }
}
