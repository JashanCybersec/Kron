//! Converts raw eBPF events into normalized [`KronEvent`]s.
//!
//! Each converter function maps a [`RawBpfEvent`] variant to the canonical
//! `KronEvent` schema defined in `kron-types`. Fields that cannot be determined
//! from kernel space (`GeoIP`, asset criticality, MITRE tags) are left `None`
//! and will be populated downstream by `kron-normalizer`.
//!
//! # Note on dead-code warnings
//!
//! These functions are only called from the Linux eBPF path in `agent.rs`.
//! On non-Linux builds they appear unused; the allow below suppresses that
//! while keeping the module compiled for `cargo check` on all platforms.

// Functions here are only called from the Linux-gated eBPF path.
#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::time::{Duration, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use kron_types::{
    enums::{AssetCriticality, EventCategory, EventSource, FileAction, NetworkDirection, Severity},
    event::KronEvent,
    ids::{EventId, TenantId},
};

use crate::bpf_types::{
    c_str_from_bytes, BpfFileAccessEvent, BpfNetworkConnectEvent, BpfProcessCreateEvent,
};

/// Reads the kernel boot time from `/proc/stat` as nanoseconds since the
/// UNIX epoch.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if `/proc/stat` cannot be read or if the
/// `btime` field is absent or unparseable. Callers should treat errors as
/// non-fatal and default to `0`, which produces approximate timestamps.
pub fn read_boot_time_ns() -> Result<u64, std::io::Error> {
    let content = std::fs::read_to_string("/proc/stat")?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            let secs: u64 = rest.trim().parse().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("cannot parse btime from /proc/stat: {e}"),
                )
            })?;
            return Ok(secs * 1_000_000_000);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "btime field not found in /proc/stat",
    ))
}

/// Converts kernel monotonic time (`ktime_get_ns()`) to a wall-clock UTC
/// timestamp.
///
/// `boot_time_ns` is the UNIX epoch at boot, obtained from [`read_boot_time_ns`].
fn ktime_to_utc(ktime_ns: u64, boot_time_ns: u64) -> DateTime<Utc> {
    let wall_ns = boot_time_ns.saturating_add(ktime_ns);
    let secs = wall_ns / 1_000_000_000;
    let nanos = (wall_ns % 1_000_000_000) as u32;
    let system_time = UNIX_EPOCH + Duration::new(secs, nanos);
    DateTime::<Utc>::from_timestamp(
        system_time
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
        nanos,
    )
    .unwrap_or_else(Utc::now)
}

// ─── Process Create ────────────────────────────────────────────────────────────

/// Converts a [`BpfProcessCreateEvent`] to a [`KronEvent`].
///
/// `tenant_id` comes from `AgentConfig.tenant_id`.
/// `collector_id` is the agent's [`AgentId`] string.
/// `hostname` is the local hostname read once on startup.
/// `boot_time_ns` is from [`read_boot_time_ns`].
#[must_use]
pub fn process_create_to_kron_event(
    ev: &BpfProcessCreateEvent,
    tenant_id: TenantId,
    collector_id: &str,
    hostname: &str,
    boot_time_ns: u64,
) -> KronEvent {
    let ts = ktime_to_utc(ev.header.ktime_ns, boot_time_ns);
    let exe_path = c_str_from_bytes(&ev.exe_path);
    let cwd = c_str_from_bytes(&ev.cwd);
    let comm = c_str_from_bytes(&ev.comm);
    let username = c_str_from_bytes(&ev.username);

    let mut argv_parts: Vec<String> = Vec::with_capacity(ev.argc as usize);
    for i in 0..(ev.argc as usize).min(ev.argv.len()) {
        let arg = c_str_from_bytes(&ev.argv[i]);
        if !arg.is_empty() {
            argv_parts.push(arg);
        }
    }
    let cmdline = argv_parts.join(" ");

    let raw = format!(
        r#"{{"type":"process_create","pid":{},"ppid":{},"exe":{},"cmdline":{}}}"#,
        ev.header.pid,
        ev.ppid,
        serde_json::to_string(&exe_path).unwrap_or_default(),
        serde_json::to_string(&cmdline).unwrap_or_default(),
    );

    KronEvent {
        event_id: EventId::from_uuid(Uuid::new_v4()),
        tenant_id,
        dedup_hash: 0,
        ts,
        ts_received: Utc::now(),
        ingest_lag_ms: 0,
        source_type: EventSource::LinuxEbpf,
        collector_id: collector_id.to_owned(),
        raw,
        host_id: None,
        hostname: Some(hostname.to_owned()),
        host_ip: None,
        host_fqdn: None,
        asset_criticality: AssetCriticality::Unknown,
        asset_tags: Vec::new(),
        user_name: if username.is_empty() {
            None
        } else {
            Some(username)
        },
        user_id: Some(ev.header.uid.to_string()),
        user_domain: None,
        user_type: None,
        event_type: "process_create".to_owned(),
        event_category: Some(EventCategory::Process),
        event_action: Some("execve".to_owned()),
        src_ip: None,
        src_ip6: None,
        src_port: None,
        dst_ip: None,
        dst_ip6: None,
        dst_port: None,
        protocol: None,
        bytes_in: None,
        bytes_out: None,
        packets_in: None,
        packets_out: None,
        direction: None,
        process_name: Some(comm),
        process_pid: Some(ev.header.pid),
        process_ppid: Some(ev.ppid),
        process_path: Some(exe_path),
        process_cmdline: Some(cmdline),
        process_hash: None,
        parent_process: None,
        file_path: Some(cwd),
        file_name: None,
        file_hash: None,
        file_size: None,
        file_action: None,
        auth_result: None,
        auth_method: None,
        auth_protocol: None,
        src_country: None,
        src_city: None,
        src_asn: None,
        src_asn_name: None,
        dst_country: None,
        ioc_hit: false,
        ioc_type: None,
        ioc_value: None,
        ioc_feed: None,
        mitre_tactic: None,
        mitre_technique: None,
        mitre_sub_tech: None,
        severity: Severity::Info,
        severity_score: 0,
        anomaly_score: 0.0,
        ueba_score: 0.0,
        beacon_score: 0.0,
        exfil_score: 0.0,
        fields: std::collections::HashMap::new(),
        schema_version: 1,
    }
}

// ─── Network Connect ───────────────────────────────────────────────────────────

/// Converts a [`BpfNetworkConnectEvent`] to a [`KronEvent`].
#[must_use]
pub fn network_connect_to_kron_event(
    ev: &BpfNetworkConnectEvent,
    tenant_id: TenantId,
    collector_id: &str,
    hostname: &str,
    boot_time_ns: u64,
) -> KronEvent {
    let ts = ktime_to_utc(ev.header.ktime_ns, boot_time_ns);
    let comm = c_str_from_bytes(&ev.comm);
    let src_ip = Ipv4Addr::from(u32::from_be(ev.src_ip));
    let dst_ip_addr = Ipv4Addr::from(u32::from_be(ev.dst_ip));

    let proto = match ev.proto {
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    };

    let raw = format!(
        r#"{{"type":"network_connect","pid":{},"src":"{}:{}","dst":"{}:{}","proto":"{}"}}"#,
        ev.header.pid, src_ip, ev.src_port, dst_ip_addr, ev.dst_port, proto
    );

    KronEvent {
        event_id: EventId::from_uuid(Uuid::new_v4()),
        tenant_id,
        dedup_hash: 0,
        ts,
        ts_received: Utc::now(),
        ingest_lag_ms: 0,
        source_type: EventSource::LinuxEbpf,
        collector_id: collector_id.to_owned(),
        raw,
        host_id: None,
        hostname: Some(hostname.to_owned()),
        host_ip: None,
        host_fqdn: None,
        asset_criticality: AssetCriticality::Unknown,
        asset_tags: Vec::new(),
        user_name: None,
        user_id: Some(ev.header.uid.to_string()),
        user_domain: None,
        user_type: None,
        event_type: "network_connect".to_owned(),
        event_category: Some(EventCategory::Network),
        event_action: Some("connect".to_owned()),
        src_ip: Some(src_ip),
        src_ip6: None,
        src_port: Some(ev.src_port),
        dst_ip: Some(dst_ip_addr),
        dst_ip6: None,
        dst_port: Some(ev.dst_port),
        protocol: Some(proto.to_owned()),
        bytes_in: None,
        bytes_out: None,
        packets_in: None,
        packets_out: None,
        direction: Some(NetworkDirection::Outbound),
        process_name: Some(comm),
        process_pid: Some(ev.header.pid),
        process_ppid: None,
        process_path: None,
        process_cmdline: None,
        process_hash: None,
        parent_process: None,
        file_path: None,
        file_name: None,
        file_hash: None,
        file_size: None,
        file_action: None,
        auth_result: None,
        auth_method: None,
        auth_protocol: None,
        src_country: None,
        src_city: None,
        src_asn: None,
        src_asn_name: None,
        dst_country: None,
        ioc_hit: false,
        ioc_type: None,
        ioc_value: None,
        ioc_feed: None,
        mitre_tactic: None,
        mitre_technique: None,
        mitre_sub_tech: None,
        severity: Severity::Info,
        severity_score: 0,
        anomaly_score: 0.0,
        ueba_score: 0.0,
        beacon_score: 0.0,
        exfil_score: 0.0,
        fields: std::collections::HashMap::new(),
        schema_version: 1,
    }
}

// ─── File Access ───────────────────────────────────────────────────────────────

/// Converts a [`BpfFileAccessEvent`] to a [`KronEvent`].
#[must_use]
pub fn file_access_to_kron_event(
    ev: &BpfFileAccessEvent,
    tenant_id: TenantId,
    collector_id: &str,
    hostname: &str,
    boot_time_ns: u64,
) -> KronEvent {
    let ts = ktime_to_utc(ev.header.ktime_ns, boot_time_ns);
    let comm = c_str_from_bytes(&ev.comm);
    let path = c_str_from_bytes(&ev.path);
    let file_name = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned);

    // Determine read vs write from O_WRONLY (1) / O_RDWR (2) flags.
    let action = if (ev.flags & 0x1) != 0 || (ev.flags & 0x2) != 0 {
        FileAction::Write
    } else {
        FileAction::Read
    };

    let raw = format!(
        r#"{{"type":"file_access","pid":{},"path":{},"flags":{}}}"#,
        ev.header.pid,
        serde_json::to_string(&path).unwrap_or_default(),
        ev.flags,
    );

    KronEvent {
        event_id: EventId::from_uuid(Uuid::new_v4()),
        tenant_id,
        dedup_hash: 0,
        ts,
        ts_received: Utc::now(),
        ingest_lag_ms: 0,
        source_type: EventSource::LinuxEbpf,
        collector_id: collector_id.to_owned(),
        raw,
        host_id: None,
        hostname: Some(hostname.to_owned()),
        host_ip: None,
        host_fqdn: None,
        asset_criticality: AssetCriticality::Unknown,
        asset_tags: Vec::new(),
        user_name: None,
        user_id: Some(ev.header.uid.to_string()),
        user_domain: None,
        user_type: None,
        event_type: "file_access".to_owned(),
        event_category: Some(EventCategory::File),
        event_action: Some("openat".to_owned()),
        src_ip: None,
        src_ip6: None,
        src_port: None,
        dst_ip: None,
        dst_ip6: None,
        dst_port: None,
        protocol: None,
        bytes_in: None,
        bytes_out: None,
        packets_in: None,
        packets_out: None,
        direction: None,
        process_name: Some(comm),
        process_pid: Some(ev.header.pid),
        process_ppid: None,
        process_path: None,
        process_cmdline: None,
        process_hash: None,
        parent_process: None,
        file_path: Some(path),
        file_name,
        file_hash: None,
        file_size: None,
        file_action: Some(action),
        auth_result: None,
        auth_method: None,
        auth_protocol: None,
        src_country: None,
        src_city: None,
        src_asn: None,
        src_asn_name: None,
        dst_country: None,
        ioc_hit: false,
        ioc_type: None,
        ioc_value: None,
        ioc_feed: None,
        mitre_tactic: None,
        mitre_technique: None,
        mitre_sub_tech: None,
        severity: Severity::Info,
        severity_score: 0,
        anomaly_score: 0.0,
        ueba_score: 0.0,
        beacon_score: 0.0,
        exfil_score: 0.0,
        fields: std::collections::HashMap::new(),
        schema_version: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_types::BpfEventHeader;

    fn make_header(kind: u32, pid: u32) -> BpfEventHeader {
        BpfEventHeader {
            kind,
            ktime_ns: 1_000_000_000,
            pid,
            uid: 1000,
            gid: 1000,
            netns_ino: 0,
            _pad: 0,
        }
    }

    #[test]
    fn test_file_access_to_kron_event_when_write_flags_then_write_action() {
        let mut ev = BpfFileAccessEvent {
            header: make_header(3, 42),
            comm: [0; crate::bpf_types::COMM_LEN],
            path: [0; crate::bpf_types::PATH_LEN],
            flags: 0x1, // O_WRONLY
            _pad: 0,
        };
        ev.comm[..4].copy_from_slice(b"bash");
        ev.path[..9].copy_from_slice(b"/etc/test");
        let tenant = TenantId::new();
        let event = file_access_to_kron_event(&ev, tenant, "agent-1", "host1", 0);
        assert_eq!(event.event_type, "file_access");
        assert_eq!(event.file_action, Some(FileAction::Write));
        assert_eq!(event.file_path, Some("/etc/test".to_owned()));
    }

    #[test]
    fn test_network_connect_to_kron_event_when_called_then_fields_set() {
        let ev = BpfNetworkConnectEvent {
            header: make_header(2, 100),
            comm: {
                let mut a = [0u8; crate::bpf_types::COMM_LEN];
                a[..4].copy_from_slice(b"curl");
                a
            },
            src_ip: u32::to_be(0xC0A8_0001), // 192.168.0.1
            dst_ip: u32::to_be(0x0808_0808), // 8.8.8.8
            src_port: 12345,
            dst_port: 443,
            proto: 6,
            _pad: [0; 7],
        };
        let tenant = TenantId::new();
        let event = network_connect_to_kron_event(&ev, tenant, "agent-1", "host1", 0);
        assert_eq!(event.event_type, "network_connect");
        assert_eq!(event.dst_port, Some(443));
        assert_eq!(event.protocol, Some("tcp".to_owned()));
        assert_eq!(event.direction, Some(NetworkDirection::Outbound));
    }
}
