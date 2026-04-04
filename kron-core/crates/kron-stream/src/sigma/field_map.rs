//! SIGMA field name to `KronEvent` field mapping.
//!
//! SIGMA rules use field names that vary by log source (Sysmon, Windows Security,
//! Linux auditd, etc.). This module resolves a SIGMA field name to the
//! corresponding value in a [`KronEvent`].
//!
//! Unknown fields fall back to the flexible `event.fields` map, allowing rules
//! to match source-specific fields that were not normalised into canonical columns.

use kron_types::event::KronEvent;

/// A resolved field value from a [`KronEvent`].
#[derive(Debug, Clone)]
pub enum FieldValue {
    /// String value.
    Str(String),
    /// Integer value.
    Int(i64),
    /// Boolean value.
    Bool(bool),
}

/// Resolves a SIGMA field name to the corresponding value in a `KronEvent`.
///
/// Returns `None` if the field is not mapped or the mapped event field is `None`.
/// Unknown field names are looked up in `event.fields` as a fallback.
#[must_use]
pub fn resolve_field(event: &KronEvent, sigma_field: &str) -> Option<FieldValue> {
    match sigma_field {
        // Process fields.
        "CommandLine" | "command_line" => event.process_cmdline.as_deref().map(str_val),
        "Image" | "process_path" => event.process_path.as_deref().map(str_val),
        "ParentImage" | "parent_process_path" => event.parent_process.as_deref().map(str_val),
        "ProcessId" | "process_id" => event.process_pid.map(|v| FieldValue::Int(i64::from(v))),
        "ParentProcessId" | "parent_pid" => {
            event.process_ppid.map(|v| FieldValue::Int(i64::from(v)))
        }
        "ProcessName" | "process_name" => event.process_name.as_deref().map(str_val),

        // User fields.
        "User" | "Username" | "user_name" => event.user_name.as_deref().map(str_val),

        // Host / asset fields.
        "Computer" | "Hostname" | "hostname" => event.hostname.as_deref().map(str_val),

        // Network fields.
        "src_ip" | "SourceIp" | "SourceAddress" => event.src_ip.map(|ip| str_val(&ip.to_string())),
        "dst_ip" | "DestinationIp" | "DestinationAddress" => {
            event.dst_ip.map(|ip| str_val(&ip.to_string()))
        }
        "src_port" | "SourcePort" => event.src_port.map(|p| FieldValue::Int(i64::from(p))),
        "dst_port" | "DestinationPort" => event.dst_port.map(|p| FieldValue::Int(i64::from(p))),
        "Protocol" | "protocol" => event.protocol.as_deref().map(str_val),

        // File fields.
        "TargetFilename" | "file_path" | "FileName" => event.file_path.as_deref().map(str_val),
        "file_name" => event.file_name.as_deref().map(str_val),

        // Auth fields.
        "auth_method" => event.auth_method.as_deref().map(str_val),
        "auth_protocol" => event.auth_protocol.as_deref().map(str_val),

        // Event classification.
        "event_type" => Some(str_val(&event.event_type)),

        // Fallback: check the flexible fields map.
        other => event.fields.get(other).map(|v| str_val(v.as_str())),
    }
}

/// Wraps a `&str` in a [`FieldValue::Str`].
fn str_val(s: &str) -> FieldValue {
    FieldValue::Str(s.to_string())
}
