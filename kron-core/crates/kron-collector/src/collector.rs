//! Main collector orchestrator.
//!
//! [`Collector`] ties together all intake subsystems:
//!
//! - gRPC mTLS server (agent event batches, registration, heartbeats)
//! - HTTP intake server (bulk JSON events, agent management API, health)
//! - Syslog UDP receiver (RFC 3164 / RFC 5424)
//! - Syslog TCP receiver (RFC 3164 / RFC 5424)
//! - Dark-agent monitor (marks agents "dark" on heartbeat timeout)
//! - Prometheus metrics exposition

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use kron_bus::adaptive::AdaptiveBus;
use kron_types::{KronConfig, TenantId};
use tokio::sync::RwLock;

use crate::error::CollectorError;
use crate::grpc::{CollectorGrpcService, GrpcState};
use crate::http_intake::{run_http_server, HttpState};
use crate::metrics;
use crate::registry::AgentRegistry;
use crate::shutdown::ShutdownHandle;
use crate::syslog::{SyslogTcpReceiver, SyslogUdpReceiver};

/// The KRON collector service.
pub struct Collector {
    config: KronConfig,
    shutdown: ShutdownHandle,
}

impl Collector {
    /// Creates a new collector from the given platform configuration.
    #[must_use]
    pub fn new(config: KronConfig, shutdown: ShutdownHandle) -> Self {
        Self { config, shutdown }
    }

    /// Runs the collector until a shutdown signal is received.
    ///
    /// Steps:
    /// 1. Start Prometheus metrics exporter
    /// 2. Connect to the message bus
    /// 3. Build the agent registry
    /// 4. Start gRPC server
    /// 5. Start HTTP intake server
    /// 6. Start syslog UDP receiver
    /// 7. Start syslog TCP receiver
    /// 8. Start dark-agent monitor
    /// 9. Await all tasks until shutdown
    ///
    /// # Errors
    ///
    /// Returns [`CollectorError`] on critical startup failures. Non-critical
    /// task errors are logged and do not stop the collector.
    pub async fn run(self) -> Result<(), CollectorError> {
        self.start_metrics_exporter()?;

        let cfg = &self.config.collector;

        // Parse default tenant ID.
        let default_tenant_id = if cfg.default_tenant_id.is_empty() {
            None
        } else {
            let t = uuid::Uuid::from_str(&cfg.default_tenant_id)
                .map(TenantId::from_uuid)
                .map_err(|e| {
                    CollectorError::Config(format!(
                        "invalid default_tenant_id '{}': {e}",
                        cfg.default_tenant_id
                    ))
                })?;
            Some(t)
        };

        // Connect to the message bus (embedded or Redpanda based on mode).
        let bus = AdaptiveBus::new(self.config.clone()).map_err(CollectorError::Bus)?;
        let producer = Arc::new(bus.new_producer().map_err(CollectorError::Bus)?)
            as Arc<dyn kron_bus::traits::BusProducer>;

        let registry = Arc::new(RwLock::new(AgentRegistry::new(cfg.max_eps_per_agent)));

        let grpc_state = Arc::new(GrpcState {
            registry: Arc::clone(&registry),
            producer: Arc::clone(&producer),
            default_tenant_id: cfg.default_tenant_id.clone(),
        });

        let http_state = HttpState {
            registry: Arc::clone(&registry),
            producer: Arc::clone(&producer),
            intake_auth_token: cfg.intake_auth_token.clone(),
            default_tenant_id: cfg.default_tenant_id.clone(),
        };

        // Spawn all tasks.
        let grpc_handle = self.spawn_grpc_server(Arc::clone(&grpc_state))?;
        let http_handle = self.spawn_http_server(http_state)?;
        let udp_handle = self.spawn_syslog_udp(Arc::clone(&producer), default_tenant_id)?;
        let tcp_handle = self.spawn_syslog_tcp(Arc::clone(&producer), default_tenant_id)?;
        let monitor_handle =
            self.spawn_dark_agent_monitor(Arc::clone(&registry), cfg.agent_heartbeat_timeout());

        tracing::info!("Collector started — all subsystems running");

        // Wait for any task to finish (normally only on shutdown).
        tokio::select! {
            res = grpc_handle => {
                log_task_result("gRPC server", res);
            }
            res = http_handle => {
                log_task_result("HTTP intake", res);
            }
            res = udp_handle => {
                log_task_result("syslog UDP", res);
            }
            res = tcp_handle => {
                log_task_result("syslog TCP", res);
            }
            res = monitor_handle => {
                log_task_result("dark-agent monitor", res);
            }
        }

        tracing::info!("Collector shut down cleanly");
        Ok(())
    }

    /// Starts the Prometheus metrics HTTP exporter.
    ///
    /// # Errors
    ///
    /// Returns [`CollectorError::Config`] if the bind address is invalid or
    /// the exporter cannot be installed.
    fn start_metrics_exporter(&self) -> Result<(), CollectorError> {
        let addr = &self.config.collector.metrics_addr;
        if addr.is_empty() {
            return Ok(());
        }
        let addr_parsed: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| CollectorError::Config(format!("invalid metrics_addr '{addr}': {e}")))?;
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(addr_parsed)
            .install()
            .map_err(|e| {
                CollectorError::Config(format!("cannot start Prometheus exporter: {e}"))
            })?;
        tracing::info!(bind_addr = %addr, "Prometheus metrics exporter started");
        Ok(())
    }

    /// Spawns the gRPC server task.
    fn spawn_grpc_server(
        &self,
        state: Arc<GrpcState>,
    ) -> Result<tokio::task::JoinHandle<()>, CollectorError> {
        let addr: SocketAddr = self.config.collector.grpc_addr.parse().map_err(|e| {
            CollectorError::Config(format!(
                "invalid grpc_addr '{}': {e}",
                self.config.collector.grpc_addr
            ))
        })?;

        let tls_cert_path = self.config.collector.tls_cert_path.clone();
        let tls_key_path = self.config.collector.tls_key_path.clone();
        let tls_ca_path = self.config.collector.tls_ca_path.clone();
        let mut shutdown_rx = self.shutdown.subscribe();

        let handle = tokio::spawn(async move {
            let svc = CollectorGrpcService::new(state);

            // Load TLS identity and CA cert for mTLS.
            let tls_result = load_server_tls(&tls_cert_path, &tls_key_path, &tls_ca_path);

            let mut server_builder = match tls_result {
                Ok(tls_cfg) => {
                    tracing::info!(%addr, "gRPC server starting with mTLS");
                    tonic::transport::Server::builder()
                        .tls_config(tls_cfg)
                        .unwrap_or_else(|e| {
                            tracing::error!(error = %e, "TLS config failed; gRPC running without TLS");
                            tonic::transport::Server::builder()
                        })
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "mTLS certs not found; gRPC running in plaintext mode (dev only)"
                    );
                    tonic::transport::Server::builder()
                }
            };

            let result = server_builder
                .add_service(svc)
                .serve_with_shutdown(addr, async move {
                    let _ = shutdown_rx.recv().await;
                })
                .await;

            if let Err(e) = result {
                tracing::error!(error = %e, "gRPC server exited with error");
            }
        });

        Ok(handle)
    }

    /// Spawns the Axum HTTP intake server task.
    fn spawn_http_server(
        &self,
        state: HttpState,
    ) -> Result<tokio::task::JoinHandle<()>, CollectorError> {
        let addr: SocketAddr = self.config.collector.http_addr.parse().map_err(|e| {
            CollectorError::Config(format!(
                "invalid http_addr '{}': {e}",
                self.config.collector.http_addr
            ))
        })?;
        let shutdown_rx = self.shutdown.subscribe();

        let handle = tokio::spawn(async move {
            if let Err(e) = run_http_server(addr, state, shutdown_rx).await {
                tracing::error!(error = %e, "HTTP intake server exited with error");
            }
        });

        Ok(handle)
    }

    /// Spawns the syslog UDP receiver task.
    fn spawn_syslog_udp(
        &self,
        producer: Arc<dyn kron_bus::traits::BusProducer>,
        tenant_id: Option<TenantId>,
    ) -> Result<tokio::task::JoinHandle<()>, CollectorError> {
        let addr: SocketAddr = self.config.collector.syslog_udp_addr.parse().map_err(|e| {
            CollectorError::Config(format!(
                "invalid syslog_udp_addr '{}': {e}",
                self.config.collector.syslog_udp_addr
            ))
        })?;

        // Syslog receivers require a tenant; skip if not configured.
        let Some(tid) = tenant_id else {
            tracing::warn!(
                "default_tenant_id not set; syslog UDP receiver disabled. \
                 Set collector.default_tenant_id in kron.toml to enable it."
            );
            return Ok(tokio::spawn(async {}));
        };

        let receiver = SyslogUdpReceiver::new(addr, producer, tid);
        let shutdown_rx = self.shutdown.subscribe();

        let handle = tokio::spawn(async move {
            if let Err(e) = receiver.run(shutdown_rx).await {
                tracing::error!(error = %e, "Syslog UDP receiver exited with error");
            }
        });

        Ok(handle)
    }

    /// Spawns the syslog TCP receiver task.
    fn spawn_syslog_tcp(
        &self,
        producer: Arc<dyn kron_bus::traits::BusProducer>,
        tenant_id: Option<TenantId>,
    ) -> Result<tokio::task::JoinHandle<()>, CollectorError> {
        let addr: SocketAddr = self.config.collector.syslog_tcp_addr.parse().map_err(|e| {
            CollectorError::Config(format!(
                "invalid syslog_tcp_addr '{}': {e}",
                self.config.collector.syslog_tcp_addr
            ))
        })?;

        let Some(tid) = tenant_id else {
            tracing::warn!("default_tenant_id not set; syslog TCP receiver disabled.");
            return Ok(tokio::spawn(async {}));
        };

        let receiver = SyslogTcpReceiver::new(addr, producer, tid);
        let shutdown_rx = self.shutdown.subscribe();

        let handle = tokio::spawn(async move {
            if let Err(e) = receiver.run(shutdown_rx).await {
                tracing::error!(error = %e, "Syslog TCP receiver exited with error");
            }
        });

        Ok(handle)
    }

    /// Spawns the dark-agent monitor background task.
    ///
    /// Runs every 30 seconds and marks agents that have not sent a heartbeat
    /// within `timeout` as "dark". A log warning and metric are emitted per agent.
    fn spawn_dark_agent_monitor(
        &self,
        registry: Arc<RwLock<AgentRegistry>>,
        timeout: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let mut shutdown_rx = self.shutdown.subscribe();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(30);
            loop {
                tokio::select! {
                    () = tokio::time::sleep(check_interval) => {
                        run_dark_check(&registry, timeout).await;
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Dark-agent monitor shutting down");
                        break;
                    }
                }
            }
        })
    }
}

// ─── Dark-agent check ─────────────────────────────────────────────────────────

/// Checks for timed-out agents and marks them as dark.
async fn run_dark_check(registry: &Arc<RwLock<AgentRegistry>>, timeout: Duration) {
    let timed_out = registry.read().await.find_timed_out_agents(timeout);

    if timed_out.is_empty() {
        return;
    }

    let mut reg = registry.write().await;
    for agent_id in timed_out {
        reg.mark_dark(agent_id);
        metrics::record_agent_dark();
        tracing::warn!(
            agent_id = %agent_id,
            "Agent marked dark — no heartbeat within timeout window"
        );
    }

    metrics::set_active_agents(reg.active_count());
}

// ─── TLS helper ───────────────────────────────────────────────────────────────

/// Loads the server TLS configuration from PEM files.
///
/// Returns a [`tonic::transport::ServerTlsConfig`] with client authentication
/// required (full mTLS). Falls back gracefully if files are absent.
///
/// # Errors
///
/// Returns a string description if any PEM file cannot be read.
fn load_server_tls(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    ca_path: &std::path::Path,
) -> Result<tonic::transport::ServerTlsConfig, String> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| format!("cannot read server cert {}: {e}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| format!("cannot read server key {}: {e}", key_path.display()))?;
    let ca_pem = std::fs::read(ca_path)
        .map_err(|e| format!("cannot read CA cert {}: {e}", ca_path.display()))?;

    let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
    let ca_cert = tonic::transport::Certificate::from_pem(ca_pem);

    Ok(tonic::transport::ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(ca_cert))
}

// ─── Task result helper ───────────────────────────────────────────────────────

/// Logs the outcome of a task join handle.
fn log_task_result(name: &str, result: Result<(), tokio::task::JoinError>) {
    match result {
        Ok(()) => tracing::info!("{name} task finished"),
        Err(e) if e.is_cancelled() => tracing::info!("{name} task cancelled"),
        Err(e) => tracing::error!(error = %e, "{name} task panicked"),
    }
}
