//! Enumerated types for KRON event and alert classification.
//!
//! All enums derive `Serialize`/`Deserialize` with lowercase or `snake_case`
//! string representations matching the `ClickHouse` `LowCardinality(String)`
//! column values in the database schema.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error returned when parsing an enum from a string fails.
#[derive(Debug, Clone)]
pub struct EnumParseError {
    /// The value that could not be parsed.
    pub value: String,
    /// The enum type name.
    pub enum_name: &'static str,
}

impl fmt::Display for EnumParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {} value: '{}'", self.enum_name, self.value)
    }
}

impl std::error::Error for EnumParseError {}

/// Event severity level.
///
/// Used in both events and alerts. Derives `Ord` so severity levels can be
/// compared directly (e.g. `severity >= Severity::High`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — no action required.
    #[default]
    Info,
    /// Low severity — monitor or log.
    Low,
    /// Medium severity — investigate soon.
    Medium,
    /// High severity — investigate promptly.
    High,
    /// Critical severity — immediate action required.
    Critical,
}

impl Severity {
    /// Returns the minimum numeric risk score for this severity level.
    ///
    /// Score bands: Critical ≥ 80, High ≥ 60, Medium ≥ 40, Low ≥ 20, Info = 0.
    #[must_use]
    pub fn score_threshold(&self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 20,
            Self::Medium => 40,
            Self::High => 60,
            Self::Critical => 80,
        }
    }

    /// Returns `true` if this severity requires immediate notification (Critical or High).
    #[must_use]
    pub fn is_immediate(&self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }

    /// Derives a `Severity` from a numeric risk score (0–100).
    #[must_use]
    pub fn from_score(score: u8) -> Self {
        match score {
            80..=100 => Self::Critical,
            60..=79 => Self::High,
            40..=59 => Self::Medium,
            20..=39 => Self::Low,
            _ => Self::Info,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl FromStr for Severity {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "Severity",
            }),
        }
    }
}

/// The source system or collection method that produced the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// eBPF agent on a Linux endpoint.
    #[default]
    LinuxEbpf,
    /// Windows ETW (Event Tracing for Windows) agent.
    WindowsEtw,
    /// Syslog over UDP or TCP (RFC 3164 / RFC 5424).
    Syslog,
    /// AWS `CloudTrail` API events.
    Cloudtrail,
    /// Azure Monitor Activity Log.
    AzureActivityLog,
    /// GCP Cloud Audit Log.
    GcpAuditLog,
    /// HTTP POST intake endpoint (`/intake/v1/events`).
    HttpIntake,
    /// OT/SCADA device log.
    OtScada,
    /// Network flow record (`NetFlow` v9 / IPFIX / sFlow).
    NetworkFlow,
    /// DHCP server log.
    Dhcp,
    /// DNS query/response log.
    Dns,
    /// Custom or unknown source.
    Unknown,
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinuxEbpf => write!(f, "linux_ebpf"),
            Self::WindowsEtw => write!(f, "windows_etw"),
            Self::Syslog => write!(f, "syslog"),
            Self::Cloudtrail => write!(f, "cloudtrail"),
            Self::AzureActivityLog => write!(f, "azure_activity_log"),
            Self::GcpAuditLog => write!(f, "gcp_audit_log"),
            Self::HttpIntake => write!(f, "http_intake"),
            Self::OtScada => write!(f, "ot_scada"),
            Self::NetworkFlow => write!(f, "network_flow"),
            Self::Dhcp => write!(f, "dhcp"),
            Self::Dns => write!(f, "dns"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl FromStr for EventSource {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "linux_ebpf" => Ok(Self::LinuxEbpf),
            "windows_etw" => Ok(Self::WindowsEtw),
            "syslog" => Ok(Self::Syslog),
            "cloudtrail" => Ok(Self::Cloudtrail),
            "azure_activity_log" => Ok(Self::AzureActivityLog),
            "gcp_audit_log" => Ok(Self::GcpAuditLog),
            "http_intake" => Ok(Self::HttpIntake),
            "ot_scada" => Ok(Self::OtScada),
            "network_flow" => Ok(Self::NetworkFlow),
            "dhcp" => Ok(Self::Dhcp),
            "dns" => Ok(Self::Dns),
            "unknown" => Ok(Self::Unknown),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "EventSource",
            }),
        }
    }
}

/// High-level OCSF-aligned category of the security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EventCategory {
    /// Authentication and authorization events (login, sudo, certificate).
    Authentication,
    /// Network connection and flow events.
    Network,
    /// File system access events.
    File,
    /// Process creation and execution events.
    Process,
    /// Windows registry modification events.
    Registry,
    /// User account management events (create, delete, privilege change).
    Account,
    /// Cloud provider API events.
    Cloud,
    /// Other or uncategorized events.
    #[default]
    Other,
}

impl fmt::Display for EventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication => write!(f, "authentication"),
            Self::Network => write!(f, "network"),
            Self::File => write!(f, "file"),
            Self::Process => write!(f, "process"),
            Self::Registry => write!(f, "registry"),
            Self::Account => write!(f, "account"),
            Self::Cloud => write!(f, "cloud"),
            Self::Other => write!(f, "other"),
        }
    }
}

impl FromStr for EventCategory {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authentication" => Ok(Self::Authentication),
            "network" => Ok(Self::Network),
            "file" => Ok(Self::File),
            "process" => Ok(Self::Process),
            "registry" => Ok(Self::Registry),
            "account" => Ok(Self::Account),
            "cloud" => Ok(Self::Cloud),
            "other" => Ok(Self::Other),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "EventCategory",
            }),
        }
    }
}

/// Criticality rating of the asset that generated the event.
///
/// Used as a multiplier when computing composite risk scores. Higher
/// criticality amplifies the score of the same event on a more important asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AssetCriticality {
    /// Tier-0 asset — domain controllers, payment systems, prod databases.
    Critical,
    /// Tier-1 asset — production servers, VPN gateways.
    High,
    /// Tier-2 asset — standard workstations and servers.
    Medium,
    /// Tier-3 asset — development or test systems.
    Low,
    /// Criticality not yet assessed.
    #[default]
    Unknown,
}

impl AssetCriticality {
    /// Returns the score multiplier for this criticality level (0.5–2.0).
    ///
    /// Applied to the base risk score during composite score computation.
    #[must_use]
    pub fn score_multiplier(&self) -> f32 {
        match self {
            Self::Critical => 2.0,
            Self::High => 1.5,
            Self::Medium => 1.0,
            Self::Low => 0.7,
            Self::Unknown => 0.5,
        }
    }
}

impl fmt::Display for AssetCriticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl FromStr for AssetCriticality {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "unknown" => Ok(Self::Unknown),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "AssetCriticality",
            }),
        }
    }
}

/// Type of user account that performed an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UserType {
    /// Interactive human user.
    #[default]
    Human,
    /// Service account or daemon.
    Service,
    /// Local OS system account (e.g. SYSTEM, root).
    System,
}

impl fmt::Display for UserType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Human => write!(f, "human"),
            Self::Service => write!(f, "service"),
            Self::System => write!(f, "system"),
        }
    }
}

impl FromStr for UserType {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "human" => Ok(Self::Human),
            "service" => Ok(Self::Service),
            "system" => Ok(Self::System),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "UserType",
            }),
        }
    }
}

/// Authentication result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthResult {
    /// Authentication succeeded.
    Success,
    /// Authentication failed (wrong credentials, locked account, etc.).
    Failure,
    /// Result unknown (event truncated or source does not log results).
    #[default]
    Unknown,
}

impl fmt::Display for AuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl FromStr for AuthResult {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "unknown" => Ok(Self::Unknown),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "AuthResult",
            }),
        }
    }
}

/// Network traffic direction relative to the monitored asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDirection {
    /// Traffic originating from outside the network toward the asset.
    Inbound,
    /// Traffic leaving the network from the asset.
    #[default]
    Outbound,
    /// Lateral movement within the network segment.
    Lateral,
}

impl fmt::Display for NetworkDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "inbound"),
            Self::Outbound => write!(f, "outbound"),
            Self::Lateral => write!(f, "lateral"),
        }
    }
}

impl FromStr for NetworkDirection {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "inbound" => Ok(Self::Inbound),
            "outbound" => Ok(Self::Outbound),
            "lateral" => Ok(Self::Lateral),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "NetworkDirection",
            }),
        }
    }
}

/// File system operation performed on a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FileAction {
    /// File was read.
    #[default]
    Read,
    /// File contents were modified.
    Write,
    /// File was created (new file).
    Create,
    /// File was deleted.
    Delete,
    /// File was renamed or moved.
    Rename,
}

impl fmt::Display for FileAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Create => write!(f, "create"),
            Self::Delete => write!(f, "delete"),
            Self::Rename => write!(f, "rename"),
        }
    }
}

impl FromStr for FileAction {
    type Err = EnumParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "create" => Ok(Self::Create),
            "delete" => Ok(Self::Delete),
            "rename" => Ok(Self::Rename),
            _ => Err(EnumParseError {
                value: s.to_string(),
                enum_name: "FileAction",
            }),
        }
    }
}

/// Which detection subsystem produced a [`crate::KronAlert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSource {
    /// SIGMA rule match.
    #[default]
    Sigma,
    /// ONNX anomaly model score exceeded threshold.
    Onnx,
    /// UEBA behavioral baseline deviation.
    Ueba,
    /// IOC bloom filter hit.
    Ioc,
    /// Event count threshold exceeded.
    Threshold,
}

impl fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sigma => write!(f, "sigma"),
            Self::Onnx => write!(f, "onnx"),
            Self::Ueba => write!(f, "ueba"),
            Self::Ioc => write!(f, "ioc"),
            Self::Threshold => write!(f, "threshold"),
        }
    }
}

/// Lifecycle status of a [`crate::KronAlert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    /// Alert is new and unacknowledged.
    #[default]
    Open,
    /// Alert has been seen but investigation has not started.
    Acknowledged,
    /// Alert is actively being investigated.
    InProgress,
    /// Alert investigation is complete and the incident is closed.
    Resolved,
    /// Alert was determined to be a false positive.
    FalsePositive,
    /// Alert is suppressed — will not re-notify for this pattern.
    Suppressed,
}

impl fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Acknowledged => write!(f, "acknowledged"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Resolved => write!(f, "resolved"),
            Self::FalsePositive => write!(f, "false_positive"),
            Self::Suppressed => write!(f, "suppressed"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_when_compared_then_ordered_correctly() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_score_thresholds_when_compared_then_ordered() {
        assert!(Severity::Info.score_threshold() < Severity::Low.score_threshold());
        assert!(Severity::Low.score_threshold() < Severity::Medium.score_threshold());
        assert!(Severity::Medium.score_threshold() < Severity::High.score_threshold());
        assert!(Severity::High.score_threshold() < Severity::Critical.score_threshold());
    }

    #[test]
    fn test_severity_from_score_when_score_85_then_critical() {
        assert_eq!(Severity::from_score(85), Severity::Critical);
    }

    #[test]
    fn test_severity_from_score_when_score_65_then_high() {
        assert_eq!(Severity::from_score(65), Severity::High);
    }

    #[test]
    fn test_severity_from_score_when_score_10_then_info() {
        assert_eq!(Severity::from_score(10), Severity::Info);
    }

    #[test]
    fn test_severity_is_immediate_when_critical_then_true() {
        assert!(Severity::Critical.is_immediate());
        assert!(Severity::High.is_immediate());
        assert!(!Severity::Medium.is_immediate());
        assert!(!Severity::Low.is_immediate());
        assert!(!Severity::Info.is_immediate());
    }

    #[test]
    fn test_asset_criticality_multipliers_when_compared_then_ordered() {
        assert!(
            AssetCriticality::Unknown.score_multiplier() < AssetCriticality::Low.score_multiplier()
        );
        assert!(
            AssetCriticality::Low.score_multiplier() < AssetCriticality::Medium.score_multiplier()
        );
        assert!(
            AssetCriticality::Medium.score_multiplier() < AssetCriticality::High.score_multiplier()
        );
        assert!(
            AssetCriticality::High.score_multiplier()
                < AssetCriticality::Critical.score_multiplier()
        );
    }

    #[test]
    fn test_severity_when_serialized_then_lowercase_string() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).expect("serializes"),
            "\"critical\""
        );
    }

    #[test]
    fn test_event_source_when_serialized_then_snake_case_string() {
        assert_eq!(
            serde_json::to_string(&EventSource::LinuxEbpf).expect("serializes"),
            "\"linux_ebpf\""
        );
    }

    #[test]
    fn test_alert_status_when_serialized_then_snake_case_string() {
        assert_eq!(
            serde_json::to_string(&AlertStatus::InProgress).expect("serializes"),
            "\"in_progress\""
        );
    }
}
