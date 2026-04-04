//! Agent configuration loaded from `agent.toml` and overridable via environment.
//!
//! # Configuration file example
//!
//! ```toml
//! tenant_id = "01234567-89ab-cdef-0123-456789abcdef"
//! collector_endpoint = "https://collector.internal:4443"
//! cert_path = "/etc/kron/agent.crt"
//! key_path  = "/etc/kron/agent.key"
//! ca_path   = "/etc/kron/ca.crt"
//!
//! [ebpf]
//! ring_buffer_size_mb     = 64
//! max_batch_size          = 1000
//! max_batch_delay_ms      = 100
//! sensitive_paths         = ["/etc", "/root", "/home"]
//!
//! [buffer]
//! data_dir                = "/var/lib/kron/agent/buffer"
//! max_size_gb             = 1
//!
//! [metrics]
//! bind_addr               = "127.0.0.1:9101"
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

/// Full configuration for the kron-agent process.
///
/// Loaded from TOML via [`AgentConfig::from_file`].
/// All durations are stored as milliseconds in the TOML file and
/// converted to [`Duration`] on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Tenant UUID that all events emitted by this agent will be tagged with.
    ///
    /// Must match the tenant registered in the collector's agent registry.
    pub tenant_id: String,

    /// gRPC endpoint of the collector service, including scheme and port.
    ///
    /// Example: `https://collector.kron.internal:4443`
    pub collector_endpoint: String,

    /// Path to the agent's mTLS client certificate (PEM).
    pub cert_path: PathBuf,

    /// Path to the agent's mTLS private key (PEM).
    pub key_path: PathBuf,

    /// Path to the CA certificate used to verify the collector (PEM).
    pub ca_path: PathBuf,

    /// Arbitrary key=value labels included in every [`RegisterRequest`].
    #[serde(default)]
    pub labels: HashMap<String, String>,

    /// eBPF-specific tuning.
    #[serde(default)]
    pub ebpf: EbpfConfig,

    /// Local disk buffer settings.
    #[serde(default)]
    pub buffer: BufferConfig,

    /// Prometheus metrics exposition settings.
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// eBPF ring buffer and batching configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfConfig {
    /// Size of the eBPF ring buffer in megabytes.
    ///
    /// Must be a power of two. Larger buffers reduce event drop risk under
    /// burst loads at the cost of kernel memory.
    pub ring_buffer_size_mb: u32,

    /// Maximum number of events per batch sent to the collector.
    pub max_batch_size: usize,

    /// Maximum time (milliseconds) to accumulate a batch before flushing.
    pub max_batch_delay_ms: u64,

    /// Filesystem paths monitored by the `file_access` eBPF hook.
    ///
    /// The hook only emits events for files whose path prefix matches
    /// one of these entries (e.g. `"/etc"` matches `/etc/passwd`).
    pub sensitive_paths: Vec<String>,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            ring_buffer_size_mb: 64,
            max_batch_size: 1_000,
            max_batch_delay_ms: 100,
            sensitive_paths: vec![
                "/etc".to_owned(),
                "/root".to_owned(),
                "/home".to_owned(),
                "/var/lib/kron".to_owned(),
            ],
        }
    }
}

impl EbpfConfig {
    /// Returns `max_batch_delay_ms` as a [`Duration`].
    #[must_use]
    pub fn max_batch_delay(&self) -> Duration {
        Duration::from_millis(self.max_batch_delay_ms)
    }

    /// Returns the ring buffer size in bytes.
    ///
    /// # Errors
    /// Returns [`AgentError::Config`] if the size is not a power of two.
    pub fn ring_buffer_size_bytes(&self) -> Result<u32, AgentError> {
        let bytes = self
            .ring_buffer_size_mb
            .checked_mul(1024 * 1024)
            .ok_or_else(|| AgentError::Config("ring_buffer_size_mb overflows u32".to_owned()))?;
        if bytes == 0 || (bytes & (bytes - 1)) != 0 {
            return Err(AgentError::Config(format!(
                "ring_buffer_size_mb={} is not a power of two; eBPF requires power-of-two ring buffers",
                self.ring_buffer_size_mb
            )));
        }
        Ok(bytes)
    }
}

/// Local disk buffer settings for offline operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Directory where buffered event segments are stored.
    pub data_dir: PathBuf,

    /// Maximum total disk space used by buffered events, in gigabytes.
    ///
    /// When this limit is reached, the oldest segments are dropped to make
    /// room for new events. The drop is logged with a count of lost events.
    pub max_size_gb: u64,

    /// Maximum size of a single segment file in megabytes.
    pub segment_size_mb: u64,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/kron/agent/buffer"),
            max_size_gb: 1,
            segment_size_mb: 64,
        }
    }
}

impl BufferConfig {
    /// Returns `max_size_gb` in bytes.
    #[must_use]
    pub fn max_size_bytes(&self) -> u64 {
        self.max_size_gb * 1024 * 1024 * 1024
    }

    /// Returns `segment_size_mb` in bytes.
    #[must_use]
    pub fn segment_size_bytes(&self) -> u64 {
        self.segment_size_mb * 1024 * 1024
    }
}

/// Prometheus metrics endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// TCP address on which the Prometheus `/metrics` HTTP endpoint listens.
    ///
    /// Set to an empty string to disable metrics exposition.
    pub bind_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9101".to_owned(),
        }
    }
}

impl AgentConfig {
    /// Loads configuration from a TOML file at `path`.
    ///
    /// # Errors
    /// Returns [`AgentError::Config`] if the file cannot be read or parsed,
    /// or if required fields are missing / invalid.
    pub fn from_file(path: &Path) -> Result<Self, AgentError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| AgentError::Config(format!("cannot read {}: {e}", path.display())))?;
        let cfg: Self = toml::from_str(&raw).map_err(|e| {
            AgentError::Config(format!("TOML parse error in {}: {e}", path.display()))
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates all required fields and constraints.
    ///
    /// Called automatically by [`from_file`].
    ///
    /// # Errors
    /// Returns [`AgentError::Config`] with a human-readable description of the
    /// first validation failure.
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.tenant_id.is_empty() {
            return Err(AgentError::Config("tenant_id is required".to_owned()));
        }
        if self.collector_endpoint.is_empty() {
            return Err(AgentError::Config(
                "collector_endpoint is required".to_owned(),
            ));
        }
        if !self.cert_path.exists() {
            return Err(AgentError::Config(format!(
                "cert_path does not exist: {}",
                self.cert_path.display()
            )));
        }
        if !self.key_path.exists() {
            return Err(AgentError::Config(format!(
                "key_path does not exist: {}",
                self.key_path.display()
            )));
        }
        if !self.ca_path.exists() {
            return Err(AgentError::Config(format!(
                "ca_path does not exist: {}",
                self.ca_path.display()
            )));
        }
        // Validate ring buffer size is power-of-two.
        self.ebpf.ring_buffer_size_bytes()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_config_when_default_then_ring_buffer_is_power_of_two() {
        let cfg = EbpfConfig::default();
        // 64 MB = 0x4000000 — power of two.
        assert!(cfg.ring_buffer_size_bytes().is_ok());
    }

    #[test]
    fn test_ebpf_config_when_non_power_of_two_then_error() {
        let cfg = EbpfConfig {
            ring_buffer_size_mb: 65,
            ..EbpfConfig::default()
        };
        assert!(cfg.ring_buffer_size_bytes().is_err());
    }

    #[test]
    fn test_buffer_config_when_default_then_max_size_correct() {
        let cfg = BufferConfig::default();
        assert_eq!(cfg.max_size_bytes(), 1024 * 1024 * 1024);
    }

    #[test]
    fn test_ebpf_config_when_delay_then_duration_correct() {
        let cfg = EbpfConfig {
            max_batch_delay_ms: 250,
            ..EbpfConfig::default()
        };
        assert_eq!(cfg.max_batch_delay(), Duration::from_millis(250));
    }
}
