//! eBPF program loader and ring buffer reader.
//!
//! This module is only compiled on Linux (`#[cfg(target_os = "linux")]`).
//! On other platforms a no-op stub is provided so the rest of the crate
//! compiles without changes.
//!
//! # eBPF program layout
//!
//! Three programs are compiled from C source in `bpf/`:
//!
//! | Program | Hook point | Event type |
//! |---|---|---|
//! | `process_create` | `sys_enter_execve` tracepoint | [`BpfProcessCreateEvent`] |
//! | `network_connect` | `kprobe/tcp_v4_connect` | [`BpfNetworkConnectEvent`] |
//! | `file_access` | `sys_enter_openat` tracepoint | [`BpfFileAccessEvent`] |
//!
//! All programs share a single `BPF_MAP_TYPE_RINGBUF` map named
//! `KRON_EVENTS`. Userspace reads this map through `aya`'s async ring
//! buffer API and converts records to [`RawBpfEvent`]s.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{EbpfManager, RawBpfEvent};

/// Stub visible on non-Linux targets so callers compile cleanly.
///
/// All methods panic with an explanatory message if somehow called outside
/// of Linux, which cannot happen in practice because the caller
/// (`agent.rs`) is also gated on `#[cfg(target_os = "linux")]`.
#[cfg(not(target_os = "linux"))]
pub mod stub {
    /// Raw eBPF event variant — exists only to satisfy type references on
    /// non-Linux builds.
    #[derive(Debug)]
    #[allow(dead_code)]
    pub enum RawBpfEvent {}
}

#[cfg(not(target_os = "linux"))]
#[allow(unused_imports)]
pub use stub::RawBpfEvent;
