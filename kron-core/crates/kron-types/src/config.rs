//! KRON platform configuration.
//!
//! All configuration is loaded from a TOML file with optional environment
//! variable overrides. No service may hardcode IPs, ports, timeouts, or
//! credentials — everything configurable lives in [`KronConfig`].
//!
//! # Loading
//!
//! ```no_run
//! use std::path::Path;
//! use kron_types::KronConfig;
//!
//! let config = KronConfig::from_file(Path::new("/etc/kron/kron.toml"))
//!     .expect("valid config");
//! ```
//!
//! # Environment variable overrides
//!
//! Variables with the `KRON_` prefix override file values.
//! Nested keys use double underscores: `KRON_CLICKHOUSE__URL`.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::KronError;

/// Returns the platform-appropriate base data directory for KRON.
///
/// - **Windows**: `C:\ProgramData\kron`
/// - **Unix/Linux**: `/var/lib/kron`
#[inline]
#[must_use]
fn kron_data_dir() -> PathBuf {
    #[cfg(windows)]
    return PathBuf::from(r"C:\ProgramData\kron");
    #[cfg(not(windows))]
    return PathBuf::from("/var/lib/kron");
}

/// Returns the platform-appropriate configuration directory for KRON.
///
/// - **Windows**: `C:\ProgramData\kron\etc`
/// - **Unix/Linux**: `/etc/kron`
#[inline]
#[must_use]
fn kron_etc_dir() -> PathBuf {
    #[cfg(windows)]
    return PathBuf::from(r"C:\ProgramData\kron\etc");
    #[cfg(not(windows))]
    return PathBuf::from("/etc/kron");
}

/// The deployment tier of this KRON installation.
///
/// Controls which storage and bus implementations are selected at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Single-node, `DuckDB` + embedded bus. For SMBs.
    Nano,
    /// Single-node or HA cluster, `ClickHouse` + Redpanda. For mid-market.
    #[default]
    Standard,
    /// Multi-node HA, SPIFFE/SPIRE, MSSP portal. For enterprises.
    Enterprise,
}

/// Full KRON platform configuration.
///
/// Loaded from TOML file. All fields have sensible production defaults.
/// No service may access hardcoded values — use this struct instead.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct KronConfig {
    /// Deployment mode controlling storage and bus implementations.
    pub mode: DeploymentMode,
    /// `ClickHouse` storage configuration (Standard/Enterprise).
    pub clickhouse: ClickHouseConfig,
    /// `DuckDB` storage configuration (Nano).
    pub duckdb: DuckDbConfig,
    /// Redpanda/Kafka bus configuration (Standard/Enterprise).
    pub redpanda: RedpandaConfig,
    /// Embedded disk-backed bus configuration (Nano tier).
    pub embedded_bus: EmbeddedBusConfig,
    /// `MinIO` object storage configuration.
    pub minio: MinioConfig,
    /// Authentication and JWT configuration.
    pub auth: AuthConfig,
    /// eBPF collection agent configuration.
    pub agent: AgentConfig,
    /// Collector service configuration.
    pub collector: CollectorConfig,
    /// Normalizer service configuration.
    pub normalizer: NormalizerConfig,
    /// Alert engine and notification configuration.
    pub alert: AlertConfig,
    /// Query API server configuration.
    pub api: ApiConfig,
    /// Metrics and tracing configuration.
    pub telemetry: TelemetryConfig,
}

/// `ClickHouse` connection and pool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    /// HTTP endpoint URL (e.g. `<http://localhost:8123>`).
    pub url: String,
    /// Database name.
    pub database: String,
    /// Username for authentication.
    pub username: String,
    /// Password for authentication.
    pub password: String,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Query timeout in seconds.
    pub query_timeout_secs: u64,
    /// Insert batch timeout in seconds.
    pub insert_timeout_secs: u64,
    /// Path to the directory containing SQL migration files.
    pub migrations_dir: PathBuf,
    /// Number of consecutive failures before the circuit breaker opens.
    pub circuit_breaker_threshold: u32,
    /// Seconds after the last failure before the circuit breaker allows a test request.
    pub circuit_breaker_recovery_secs: u64,
}

impl ClickHouseConfig {
    /// Returns the query timeout as a [`Duration`].
    #[must_use]
    pub fn query_timeout(&self) -> Duration {
        Duration::from_secs(self.query_timeout_secs)
    }

    /// Returns the insert timeout as a [`Duration`].
    #[must_use]
    pub fn insert_timeout(&self) -> Duration {
        Duration::from_secs(self.insert_timeout_secs)
    }
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".to_string(),
            database: "kron".to_string(),
            username: "kron".to_string(),
            password: String::new(),
            max_connections: 10,
            query_timeout_secs: 30,
            insert_timeout_secs: 10,
            migrations_dir: kron_etc_dir().join("migrations"),
            circuit_breaker_threshold: 5,
            circuit_breaker_recovery_secs: 60,
        }
    }
}

/// `DuckDB` configuration for Nano tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuckDbConfig {
    /// Path to the `DuckDB` database file.
    pub path: PathBuf,
    /// Maximum memory `DuckDB` may use in megabytes.
    pub memory_limit_mb: u32,
    /// Number of CPU threads for analytical queries.
    pub threads: u32,
    /// Path to the directory containing SQL migration files.
    pub migrations_dir: PathBuf,
    /// Cold-tier Parquet archive directory.
    ///
    /// Events older than `cold_storage_retention_days` are exported to this
    /// directory as `{cold_archive_dir}/{tenant_id}/{date}.parquet` and deleted
    /// from the live DuckDB file. Set to an empty path to disable archival.
    pub cold_archive_dir: PathBuf,
    /// Number of days to keep events in the live DuckDB table before archiving.
    ///
    /// Matches CERT-In's 180-day hot-tier requirement (total retention is
    /// 5 years across hot + cold tiers).
    pub cold_storage_retention_days: u32,
    /// How often (in hours) to run the archive background task.
    pub cold_archive_interval_hours: u64,
}

impl Default for DuckDbConfig {
    fn default() -> Self {
        let data_dir = kron_data_dir().join("data");
        Self {
            path: data_dir.join("events.duckdb"),
            memory_limit_mb: 2048,
            threads: 4,
            migrations_dir: kron_etc_dir().join("migrations"),
            cold_archive_dir: data_dir.join("archive"),
            cold_storage_retention_days: 180,
            cold_archive_interval_hours: 24,
        }
    }
}

/// Embedded disk-backed message bus configuration (Nano tier).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedBusConfig {
    /// Directory where WAL files are stored per topic.
    pub data_dir: PathBuf,
    /// Maximum WAL file size in megabytes before compaction is triggered.
    pub max_wal_size_mb: u64,
    /// Whether to call `fdatasync` after each write for crash durability.
    /// Set false in tests / high-throughput dev mode.
    pub sync_writes: bool,
    /// Maximum retry attempts before a message is moved to the dead letter topic.
    pub max_retry_count: u8,
    /// Backpressure threshold: block producer if consumer lag exceeds this many messages.
    pub backpressure_lag_threshold: u64,
}

impl Default for EmbeddedBusConfig {
    fn default() -> Self {
        Self {
            data_dir: kron_data_dir().join("bus"),
            max_wal_size_mb: 512,
            sync_writes: true,
            max_retry_count: 3,
            backpressure_lag_threshold: 100_000,
        }
    }
}

/// Redpanda/Kafka broker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedpandaConfig {
    /// List of broker addresses (e.g. `["localhost:9092"]`).
    pub brokers: Vec<String>,
    /// Consumer group ID prefix (service name appended automatically).
    pub group_id_prefix: String,
    /// Maximum number of messages per batch before flushing.
    pub batch_size: usize,
    /// Maximum time to wait before flushing a partial batch, in milliseconds.
    pub batch_timeout_ms: u64,
    /// Consumer lag threshold for backpressure (number of messages behind).
    pub backpressure_lag_threshold: u64,
}

impl RedpandaConfig {
    /// Returns the batch timeout as a [`Duration`].
    #[must_use]
    pub fn batch_timeout(&self) -> Duration {
        Duration::from_millis(self.batch_timeout_ms)
    }
}

impl Default for RedpandaConfig {
    fn default() -> Self {
        Self {
            brokers: vec!["localhost:9092".to_string()],
            group_id_prefix: "kron".to_string(),
            batch_size: 1000,
            batch_timeout_ms: 100,
            backpressure_lag_threshold: 100_000,
        }
    }
}

/// `MinIO` object storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinioConfig {
    /// `MinIO` endpoint URL.
    pub endpoint: String,
    /// Access key ID.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// Bucket for cold-tier Parquet storage.
    pub cold_bucket: String,
    /// Whether to require TLS for `MinIO` connections.
    pub use_tls: bool,
}

impl Default for MinioConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9000".to_string(),
            access_key: "kron".to_string(),
            secret_key: String::new(),
            cold_bucket: "kron-cold".to_string(),
            use_tls: false,
        }
    }
}

/// Authentication and JWT configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Path to the RSA private key PEM file for JWT signing (RS256).
    pub jwt_private_key_path: PathBuf,
    /// Path to the RSA public key PEM file for JWT verification.
    pub jwt_public_key_path: PathBuf,
    /// JWT token validity in seconds (default: 8 hours).
    pub jwt_expiry_secs: u64,
    /// Number of failed login attempts before account lockout.
    pub max_failed_attempts: u8,
    /// Account lockout duration in seconds (default: 15 minutes).
    pub lockout_duration_secs: u64,
}

impl AuthConfig {
    /// Returns the JWT expiry as a [`Duration`].
    #[must_use]
    pub fn jwt_expiry(&self) -> Duration {
        Duration::from_secs(self.jwt_expiry_secs)
    }

    /// Returns the lockout duration as a [`Duration`].
    #[must_use]
    pub fn lockout_duration(&self) -> Duration {
        Duration::from_secs(self.lockout_duration_secs)
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_private_key_path: kron_data_dir().join("keys").join("jwt.key"),
            jwt_public_key_path: kron_data_dir().join("keys").join("jwt.pub"),
            jwt_expiry_secs: 8 * 3600, // 8 hours
            max_failed_attempts: 5,
            lockout_duration_secs: 15 * 60, // 15 minutes
        }
    }
}

/// eBPF agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Path to the mTLS client certificate.
    pub tls_cert_path: PathBuf,
    /// Path to the mTLS client private key.
    pub tls_key_path: PathBuf,
    /// Collector gRPC endpoint address.
    pub collector_endpoint: String,
    /// eBPF ring buffer size in bytes (default: 64 MB).
    pub ring_buffer_bytes: u64,
    /// Maximum events per batch before flushing.
    pub batch_size: usize,
    /// Maximum time to wait before flushing a partial batch, in milliseconds.
    pub batch_timeout_ms: u64,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval_secs: u64,
    /// Local disk buffer directory for offline buffering.
    pub disk_buffer_path: PathBuf,
    /// Maximum disk buffer size in bytes (default: 1 GB).
    pub disk_buffer_max_bytes: u64,
}

impl AgentConfig {
    /// Returns the batch timeout as a [`Duration`].
    #[must_use]
    pub fn batch_timeout(&self) -> Duration {
        Duration::from_millis(self.batch_timeout_ms)
    }

    /// Returns the heartbeat interval as a [`Duration`].
    #[must_use]
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            tls_cert_path: kron_data_dir().join("agent").join("client.crt"),
            tls_key_path: kron_data_dir().join("agent").join("client.key"),
            collector_endpoint: "https://localhost:9001".to_string(),
            ring_buffer_bytes: 64 * 1024 * 1024, // 64 MB
            batch_size: 1000,
            batch_timeout_ms: 100,
            heartbeat_interval_secs: 30,
            disk_buffer_path: kron_data_dir().join("agent").join("buffer"),
            disk_buffer_max_bytes: 1024 * 1024 * 1024, // 1 GB
        }
    }
}

/// Collector service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    /// gRPC listen address for agent connections (mTLS required).
    pub grpc_addr: String,
    /// Syslog UDP listen address (RFC 3164 / RFC 5424).
    pub syslog_udp_addr: String,
    /// Syslog TCP listen address (plaintext; TLS added in Phase 2).
    pub syslog_tcp_addr: String,
    /// HTTP intake listen address (`POST /intake/v1/events`).
    pub http_addr: String,
    /// Maximum events per second per agent before rate limiting.
    pub max_eps_per_agent: u32,
    /// Duration after which a silent agent is marked "dark", in seconds.
    pub agent_heartbeat_timeout_secs: u64,
    /// Path to the collector's TLS server certificate (PEM).
    pub tls_cert_path: PathBuf,
    /// Path to the collector's TLS server private key (PEM).
    pub tls_key_path: PathBuf,
    /// Path to the CA certificate used to verify agent client certs (PEM).
    pub tls_ca_path: PathBuf,
    /// Default tenant UUID string for syslog and HTTP intake sources.
    ///
    /// Events received over syslog or HTTP (Phase 1.5) are tagged with this tenant.
    /// Phase 3 replaces this with per-token tenant assignment.
    // TODO(#TBD, hardik, phase-3): Replace with per-token tenant mapping
    pub default_tenant_id: String,
    /// Pre-shared Bearer token required for `POST /intake/v1/events`.
    ///
    /// Phase 3 replaces this with a proper token registry.
    // TODO(#TBD, hardik, phase-3): Replace with per-tenant token registry
    pub intake_auth_token: String,
    /// Prometheus metrics bind address for the collector.
    pub metrics_addr: String,
}

impl CollectorConfig {
    /// Returns the agent heartbeat timeout as a [`Duration`].
    #[must_use]
    pub fn agent_heartbeat_timeout(&self) -> Duration {
        Duration::from_secs(self.agent_heartbeat_timeout_secs)
    }
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            grpc_addr: "0.0.0.0:9001".to_string(),
            syslog_udp_addr: "0.0.0.0:514".to_string(),
            syslog_tcp_addr: "0.0.0.0:6514".to_string(),
            http_addr: "0.0.0.0:9002".to_string(),
            max_eps_per_agent: 100_000,
            agent_heartbeat_timeout_secs: 90,
            tls_cert_path: kron_data_dir().join("collector").join("server.crt"),
            tls_key_path: kron_data_dir().join("collector").join("server.key"),
            tls_ca_path: kron_data_dir().join("collector").join("ca.crt"),
            default_tenant_id: String::new(),
            intake_auth_token: String::new(),
            metrics_addr: "127.0.0.1:9102".to_string(),
        }
    }
}

/// Normalizer service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizerConfig {
    /// Path to the `GeoLite2` City MMDB file for IP enrichment.
    pub geoip_db_path: PathBuf,
    /// Path to directory containing source-to-schema mapping YAML files.
    pub mappings_dir: PathBuf,
    /// Asset enrichment cache TTL in seconds (default: 5 minutes).
    pub asset_cache_ttl_secs: u64,
    /// Maximum number of asset records to hold in the enrichment cache.
    pub asset_cache_size: usize,
    /// Tenant UUIDs whose `kron.raw.{id}` topics this normalizer should consume.
    /// If empty, the normalizer subscribes to no topics and exits immediately.
    pub raw_tenant_ids: Vec<String>,
    /// Consumer group ID for the bus subscriber.
    pub consumer_group_id: String,
    /// Prometheus metrics HTTP bind address (e.g. `"0.0.0.0:9092"`).
    /// Leave empty to disable metrics exposition.
    pub metrics_addr: String,
}

impl NormalizerConfig {
    /// Returns the asset cache TTL as a [`Duration`].
    #[must_use]
    pub fn asset_cache_ttl(&self) -> Duration {
        Duration::from_secs(self.asset_cache_ttl_secs)
    }
}

impl Default for NormalizerConfig {
    fn default() -> Self {
        Self {
            geoip_db_path: kron_data_dir().join("geoip").join("GeoLite2-City.mmdb"),
            mappings_dir: kron_data_dir().join("mappings"),
            asset_cache_ttl_secs: 5 * 60,
            asset_cache_size: 10_000,
            raw_tenant_ids: Vec::new(),
            consumer_group_id: "kron-normalizer".to_owned(),
            metrics_addr: "0.0.0.0:9092".to_owned(),
        }
    }
}

/// Alert engine and notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// `WhatsApp` Business API (Twilio + Meta) configuration.
    pub whatsapp: WhatsAppConfig,
    /// Textlocal SMS configuration.
    pub sms: SmsConfig,
    /// SMTP email configuration.
    pub smtp: SmtpConfig,
    /// Deduplication window for grouping related events, in seconds (default: 15 min).
    pub dedup_window_secs: u64,
    /// Maximum `WhatsApp` notifications per hour for P3+ (non-critical) alerts.
    pub whatsapp_rate_limit_per_hour: u32,
}

impl AlertConfig {
    /// Returns the deduplication window as a [`Duration`].
    #[must_use]
    pub fn dedup_window(&self) -> Duration {
        Duration::from_secs(self.dedup_window_secs)
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            whatsapp: WhatsAppConfig::default(),
            sms: SmsConfig::default(),
            smtp: SmtpConfig::default(),
            dedup_window_secs: 15 * 60, // 15 minutes
            whatsapp_rate_limit_per_hour: 10,
        }
    }
}

/// `WhatsApp` Business API configuration (via Twilio + Meta).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhatsAppConfig {
    /// Twilio Account SID.
    pub account_sid: String,
    /// Twilio Auth Token.
    pub auth_token: String,
    /// Sender phone number with country code (e.g. "+919999999999").
    pub from_number: String,
    /// Default recipient `WhatsApp` number.
    pub to_number: String,
}

/// Textlocal SMS configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmsConfig {
    /// Textlocal API key.
    pub api_key: String,
    /// Sender name (max 11 characters for Textlocal DLT compliance).
    pub sender: String,
    /// Default recipient phone number.
    pub to_number: String,
}

/// SMTP email configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname.
    pub host: String,
    /// SMTP server port.
    pub port: u16,
    /// SMTP username for authentication.
    pub username: String,
    /// SMTP password for authentication.
    pub password: String,
    /// From address for outgoing alert emails.
    pub from_address: String,
    /// Default recipient email address.
    pub to_address: String,
    /// Whether to require TLS (STARTTLS or SMTPS).
    pub require_tls: bool,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 587,
            username: String::new(),
            password: String::new(),
            from_address: "kron-alerts@kron.security".to_string(),
            to_address: String::new(),
            require_tls: true,
        }
    }
}

/// Query API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// HTTP listen address.
    pub listen_addr: String,
    /// Maximum number of in-flight requests before rate limiting.
    pub max_in_flight: u32,
    /// Maximum request body size in bytes (default: 10 MB).
    pub max_body_bytes: u64,
    /// Response timeout target in milliseconds (default: 200 ms).
    pub response_timeout_ms: u64,
    /// Maximum concurrent WebSocket connections allowed per tenant.
    ///
    /// Applies independently to both the alert stream and the event stream.
    /// Connections exceeding this limit receive `429 Too Many Requests`.
    pub max_ws_connections_per_tenant: usize,
    /// Allowed CORS origins for the API (e.g. `["https://portal.kron.local"]`).
    ///
    /// An empty list disables CORS entirely (browser clients cannot reach the API).
    /// Do NOT use `["*"]` in production — this allows any website to make
    /// cross-origin requests on behalf of authenticated analysts.
    pub cors_allowed_origins: Vec<String>,
}

impl ApiConfig {
    /// Returns the response timeout as a [`Duration`].
    #[must_use]
    pub fn response_timeout(&self) -> Duration {
        Duration::from_millis(self.response_timeout_ms)
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            max_in_flight: 1000,
            max_body_bytes: 10 * 1024 * 1024, // 10 MB
            response_timeout_ms: 200,
            max_ws_connections_per_tenant: 10,
            cors_allowed_origins: Vec::new(),
        }
    }
}

/// Telemetry (metrics + tracing) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Prometheus metrics scrape port.
    pub metrics_port: u16,
    /// OTLP trace exporter endpoint. Empty string disables tracing.
    pub otlp_endpoint: Option<String>,
    /// Log level filter (e.g. "info", "kron=debug,warn").
    pub log_level: String,
    /// Whether to emit logs as JSON (true) or human-readable text (false).
    pub json_logs: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            metrics_port: 9100,
            otlp_endpoint: None,
            log_level: "info".to_string(),
            json_logs: true,
        }
    }
}

impl KronConfig {
    /// Loads configuration from a TOML file.
    ///
    /// Environment variables with the `KRON_` prefix override file values.
    /// Nested keys use double underscores: `KRON_CLICKHOUSE__URL`.
    ///
    /// # Errors
    ///
    /// Returns [`KronError::Config`] if the file cannot be read, if the TOML
    /// is malformed, or if required fields are invalid after applying overrides.
    pub fn from_file(path: &std::path::Path) -> Result<Self, KronError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            KronError::Config(format!("cannot read config file {}: {}", path.display(), e))
        })?;

        let mut config: KronConfig = toml::from_str(&contents)
            .map_err(|e| KronError::Config(format!("invalid TOML in config file: {e}")))?;

        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// Applies `KRON_*` environment variable overrides to the loaded config.
    ///
    /// Only the most commonly overridden fields are supported via env vars.
    /// The full configuration should be set via the TOML file.
    fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("KRON_MODE") {
            self.mode = match val.to_lowercase().as_str() {
                "nano" => DeploymentMode::Nano,
                "enterprise" => DeploymentMode::Enterprise,
                _ => DeploymentMode::Standard,
            };
        }
        if let Ok(val) = std::env::var("KRON_CLICKHOUSE__URL") {
            self.clickhouse.url = val;
        }
        if let Ok(val) = std::env::var("KRON_CLICKHOUSE__DATABASE") {
            self.clickhouse.database = val;
        }
        if let Ok(val) = std::env::var("KRON_CLICKHOUSE__PASSWORD") {
            self.clickhouse.password = val;
        }
        if let Ok(val) = std::env::var("KRON_REDPANDA__BROKERS") {
            self.redpanda.brokers = val.split(',').map(str::to_string).collect();
        }
        if let Ok(val) = std::env::var("KRON_LOG_LEVEL") {
            self.telemetry.log_level = val;
        }
    }

    /// Validates the configuration for required non-empty values.
    ///
    /// # Errors
    ///
    /// Returns [`KronError::Config`] if any required field is empty or invalid.
    pub fn validate(&self) -> Result<(), KronError> {
        if self.clickhouse.url.is_empty() {
            return Err(KronError::Config(
                "clickhouse.url must not be empty".to_string(),
            ));
        }
        if self.clickhouse.database.is_empty() {
            return Err(KronError::Config(
                "clickhouse.database must not be empty".to_string(),
            ));
        }
        if self.redpanda.brokers.is_empty() {
            return Err(KronError::Config(
                "redpanda.brokers must not be empty".to_string(),
            ));
        }
        if self.collector.max_eps_per_agent == 0 {
            return Err(KronError::Config(
                "collector.max_eps_per_agent must be greater than 0".to_string(),
            ));
        }
        if self.api.max_body_bytes == 0 {
            return Err(KronError::Config(
                "api.max_body_bytes must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_when_validated_then_passes() {
        let config = KronConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_when_clickhouse_url_empty_then_validation_fails() {
        let mut config = KronConfig::default();
        config.clickhouse.url = String::new();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("clickhouse.url"));
    }

    #[test]
    fn test_config_when_redpanda_brokers_empty_then_validation_fails() {
        let mut config = KronConfig::default();
        config.redpanda.brokers = vec![];
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("redpanda.brokers"));
    }

    #[test]
    fn test_config_when_serialized_then_round_trips_through_toml() {
        let config = KronConfig::default();
        let toml_str = toml::to_string(&config).expect("must serialize");
        let back: KronConfig = toml::from_str(&toml_str).expect("must deserialize");
        assert_eq!(back.clickhouse.url, config.clickhouse.url);
        assert_eq!(back.redpanda.brokers, config.redpanda.brokers);
        assert_eq!(
            back.collector.max_eps_per_agent,
            config.collector.max_eps_per_agent
        );
    }

    #[test]
    fn test_clickhouse_config_when_duration_accessed_then_returns_correct_value() {
        let config = ClickHouseConfig::default();
        assert_eq!(config.query_timeout(), Duration::from_secs(30));
        assert_eq!(config.insert_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_auth_config_when_duration_accessed_then_returns_correct_value() {
        let config = AuthConfig::default();
        assert_eq!(config.jwt_expiry(), Duration::from_secs(8 * 3600));
        assert_eq!(config.lockout_duration(), Duration::from_secs(15 * 60));
    }

    #[test]
    fn test_deployment_mode_when_serialized_then_lowercase() {
        assert_eq!(
            serde_json::to_string(&DeploymentMode::Nano).expect("serializes"),
            "\"nano\""
        );
    }
}
