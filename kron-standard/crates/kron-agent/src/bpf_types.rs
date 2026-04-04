//! C-compatible structs shared between eBPF kernel programs and userspace.
//!
//! These types are laid out to exactly match the structs in
//! `bpf/kron_types.h`. Every field offset and padding byte must agree
//! exactly — the kernel writes raw bytes into the ring buffer and
//! userspace reads them as these types.
//!
//! # Layout invariants
//!
//! - All structs are `#[repr(C)]` to guarantee field order and ABI.
//! - All structs are padded to 8-byte alignment so the ring buffer reader
//!   does not need to handle partial reads.
//! - Strings are fixed-length C arrays; unused bytes are zero-padded.
//! - IP addresses are stored as network-byte-order (big-endian) `u32`.
//!
//! # Note on dead-code warnings
//!
//! These types are only constructed by the Linux eBPF subsystem at runtime.
//! On non-Linux platforms they appear unused; the `#[allow(dead_code)]`
//! attributes below suppress those warnings while keeping the types
//! available for `cargo check` on all platforms.

// All items here are only live on Linux (eBPF ring buffer), but we compile
// them unconditionally so `cargo check` catches type errors everywhere.
#![allow(dead_code)]

/// Maximum length of a path string in eBPF events (including NUL terminator).
pub const PATH_LEN: usize = 256;

/// Maximum length of a command/process name string.
pub const COMM_LEN: usize = 64;

/// Maximum length of a username string.
pub const USERNAME_LEN: usize = 32;

/// Maximum number of arguments captured for a process-create event.
pub const ARGV_COUNT: usize = 16;

/// Maximum length of a single argv string.
pub const ARGV_ITEM_LEN: usize = 64;

/// Discriminant tag embedded at the start of every ring buffer record.
///
/// Userspace switches on this value to deserialise the correct event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfEventKind {
    /// `sys_enter_execve` — process creation.
    ProcessCreate = 1,
    /// `tcp_v4_connect` — outbound TCP connection.
    NetworkConnect = 2,
    /// `sys_enter_openat` — file open on a sensitive path.
    FileAccess = 3,
}

impl BpfEventKind {
    /// Converts the raw `u32` tag written by the kernel back to an enum variant.
    ///
    /// Returns `None` for unrecognised values (future event types, kernel ABI
    /// mismatch, memory corruption).
    #[must_use]
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::ProcessCreate),
            2 => Some(Self::NetworkConnect),
            3 => Some(Self::FileAccess),
            _ => None,
        }
    }
}

/// Common header prepended to every eBPF ring buffer record.
///
/// Total size: 32 bytes.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BpfEventHeader {
    /// [`BpfEventKind`] discriminant.
    pub kind: u32,
    /// Kernel time in nanoseconds since boot (`ktime_get_ns()`).
    /// Converted to wall-clock time in userspace using the boot-time offset.
    pub ktime_ns: u64,
    /// PID of the process that triggered the event.
    pub pid: u32,
    /// Effective UID of the process.
    pub uid: u32,
    /// Effective GID of the process.
    pub gid: u32,
    /// Network namespace inode (distinguishes containers from the host).
    pub netns_ino: u32,
    /// Padding to align the struct to 8 bytes.
    pub _pad: u64,
}

/// Process creation event (`sys_enter_execve`).
///
/// Total size: `sizeof(BpfEventHeader)` + variable payload area.
/// The fixed-size layout here captures the most useful fields within the
/// eBPF stack limit (512 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BpfProcessCreateEvent {
    pub header: BpfEventHeader,
    /// Name of the newly executed binary (from `task_struct->comm`).
    pub comm: [u8; COMM_LEN],
    /// Absolute path of the executable.
    pub exe_path: [u8; PATH_LEN],
    /// Working directory of the new process.
    pub cwd: [u8; PATH_LEN],
    /// Username of the caller (from UID→name lookup, best-effort).
    pub username: [u8; USERNAME_LEN],
    /// Parent PID.
    pub ppid: u32,
    /// Number of valid entries in `argv`.
    pub argc: u32,
    /// Captured argv strings (first `argc` entries are valid).
    pub argv: [[u8; ARGV_ITEM_LEN]; ARGV_COUNT],
}

/// Outbound TCP connection event (`tcp_v4_connect`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BpfNetworkConnectEvent {
    pub header: BpfEventHeader,
    /// Name of the process opening the connection.
    pub comm: [u8; COMM_LEN],
    /// Source IPv4 address in network byte order.
    pub src_ip: u32,
    /// Destination IPv4 address in network byte order.
    pub dst_ip: u32,
    /// Source port in host byte order.
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,
    /// IP protocol: `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17).
    pub proto: u8,
    /// Padding.
    pub _pad: [u8; 7],
}

/// File access event (`sys_enter_openat` on a sensitive path).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BpfFileAccessEvent {
    pub header: BpfEventHeader,
    /// Name of the process accessing the file.
    pub comm: [u8; COMM_LEN],
    /// Full path passed to `openat(2)`.
    pub path: [u8; PATH_LEN],
    /// `flags` argument passed to `openat(2)` (e.g. `O_RDONLY`).
    pub flags: i32,
    /// Padding.
    pub _pad: u32,
}

// ─── Helper utilities ─────────────────────────────────────────────────────────

/// Reads a NUL-terminated C string from a fixed-length byte array.
///
/// Truncates at the first NUL byte or the array length, whichever comes first.
/// Non-UTF-8 bytes are replaced with the Unicode replacement character U+FFFD.
#[must_use]
pub fn c_str_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_event_kind_when_valid_u32_then_converts() {
        assert_eq!(BpfEventKind::from_u32(1), Some(BpfEventKind::ProcessCreate));
        assert_eq!(
            BpfEventKind::from_u32(2),
            Some(BpfEventKind::NetworkConnect)
        );
        assert_eq!(BpfEventKind::from_u32(3), Some(BpfEventKind::FileAccess));
        assert_eq!(BpfEventKind::from_u32(0), None);
        assert_eq!(BpfEventKind::from_u32(99), None);
    }

    #[test]
    fn test_c_str_from_bytes_when_nul_terminated_then_stops_at_nul() {
        let mut buf = [0u8; 64];
        buf[..5].copy_from_slice(b"hello");
        assert_eq!(c_str_from_bytes(&buf), "hello");
    }

    #[test]
    fn test_c_str_from_bytes_when_no_nul_then_returns_full_slice() {
        let buf = [b'a'; 4];
        assert_eq!(c_str_from_bytes(&buf), "aaaa");
    }

    #[test]
    fn test_c_str_from_bytes_when_invalid_utf8_then_replaces() {
        let buf = [0xFF, 0xFE, 0, 0];
        let s = c_str_from_bytes(&buf);
        assert!(s.contains('\u{FFFD}'));
    }
}
