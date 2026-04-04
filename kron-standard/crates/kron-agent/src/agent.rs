//! Main agent orchestrator.
//!
//! [`Agent`] ties together all subsystems:
//! - eBPF program loading and ring buffer reading (Linux only)
//! - Event batch assembly and send pipeline
//! - Disk buffer for offline operation
//! - Heartbeat sender
//! - Prometheus metrics exposition
//! - Graceful shutdown

use std::sync::Arc;

use chrono::Utc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;

use kron_types::{AgentId, EventBatch, KronEvent, RegisterRequest, TenantId};

use crate::buffer::DiskBuffer;
use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::heartbeat::{spawn_heartbeat_task, HeartbeatState};
use crate::metrics;
use crate::shutdown::ShutdownHandle;
use crate::transport::grpc::GrpcTransport;
use crate::transport::CollectorTransport;

#[cfg(target_os = "linux")]
use crate::ebpf::{EbpfManager, RawBpfEvent};

/// Maximum events queued between the ring buffer reader and batch assembler.
const EVENT_CHANNEL_CAPACITY: usize = 65_536;

/// The KRON agent: captures eBPF events and streams them to the collector.
pub struct Agent {
    config: AgentConfig,
    shutdown: ShutdownHandle,
}

impl Agent {
    /// Creates a new agent from the given configuration.
    #[must_use]
    pub fn new(config: AgentConfig, shutdown: ShutdownHandle) -> Self {
        Self { config, shutdown }
    }

    /// Runs the agent until a shutdown signal is received.
    ///
    /// Steps:
    /// 1. Kernel version check (Linux only)
    /// 2. Prometheus metrics exporter start
    /// 3. Disk buffer open
    /// 4. gRPC mTLS connection and agent registration
    /// 5. eBPF program load + ring buffer reader start (Linux only)
    /// 6. Heartbeat background task start
    /// 7. Main batch assembly and send loop
    /// 8. Graceful shutdown flush
    ///
    /// # Errors
    ///
    /// Returns [`AgentError`] on critical startup failure (TLS, registration,
    /// eBPF load). Non-critical runtime errors are logged and absorbed.
    pub async fn run(self) -> Result<(), AgentError> {
        #[cfg(target_os = "linux")]
        self.check_kernel_version()?;

        self.start_metrics_exporter()?;

        // tenant_id and hostname are used only on Linux (eBPF path).
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let (transport, agent_id, tenant_id, hostname, disk_buffer) =
            self.connect_and_register().await?;

        let transport = Arc::new(Mutex::new(transport));
        let heartbeat_state = Arc::new(Mutex::new(HeartbeatState {
            agent_id,
            ring_buffer_utilization_pct: 0,
            events_dropped_since_last: 0,
            disk_buffer_depth: 0,
        }));
        let mut disk_buffer = disk_buffer;

        let _heartbeat_task = spawn_heartbeat_task(
            Arc::clone(&heartbeat_state),
            Arc::clone(&transport),
            self.shutdown.subscribe(),
        );

        // Channel between ring buffer reader and batch assembler.
        // event_tx is only used on Linux (moved into eBPF converter task below).
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let (event_tx, mut event_rx) = mpsc::channel::<KronEvent>(EVENT_CHANNEL_CAPACITY);

        // Load eBPF programs on Linux only.
        #[cfg(target_os = "linux")]
        self.start_ebpf_converter(tenant_id, agent_id, &hostname, event_tx)?;

        // Drain leftover disk buffer events from a prior offline period.
        if !disk_buffer.is_empty() {
            tracing::info!("Draining disk buffer from previous offline period");
            drain_disk_buffer(
                &mut disk_buffer,
                &mut 0u64,
                agent_id,
                &mut *transport.lock().await,
                &heartbeat_state,
            )
            .await
            .unwrap_or_else(|e| tracing::warn!(error = %e, "Initial disk buffer drain failed"));
        }

        run_event_loop(
            &mut event_rx,
            &transport,
            &heartbeat_state,
            &mut disk_buffer,
            agent_id,
            &self.config,
            self.shutdown.subscribe(),
        )
        .await?;

        tracing::info!("Agent shut down cleanly");
        Ok(())
    }

    /// Connects to the collector, registers, and opens the disk buffer.
    ///
    /// Returns `(transport, agent_id, tenant_id, hostname, disk_buffer)`.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError`] on connection, TLS, or registration failure.
    async fn connect_and_register(
        &self,
    ) -> Result<(GrpcTransport, AgentId, TenantId, String, DiskBuffer), AgentError> {
        // Open disk buffer on a blocking thread.
        let buffer_config = self.config.buffer.clone();
        let disk_buffer = tokio::task::spawn_blocking(move || DiskBuffer::open(buffer_config))
            .await
            .map_err(|e| AgentError::Task(format!("disk buffer open panicked: {e}")))?
            .map_err(|e| AgentError::Buffer(e.to_string()))?;

        // Establish gRPC mTLS connection.
        let mut transport = GrpcTransport::connect(&self.config).await?;
        metrics::set_collector_connected(true);

        let hostname = read_hostname();

        // Register agent with collector.
        let reg_resp = transport
            .register(RegisterRequest {
                hostname: hostname.clone(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                kernel_version: kernel_version_string(),
                os_name: os_name(),
                host_ip: primary_ipv4(),
                labels: self.config.labels.clone(),
            })
            .await?;

        let agent_id: AgentId = reg_resp.agent_id;
        let tenant_id: TenantId = reg_resp.tenant_id;

        tracing::info!(
            agent_id = %agent_id,
            tenant_id = %tenant_id,
            "Agent registered with collector"
        );

        Ok((transport, agent_id, tenant_id, hostname, disk_buffer))
    }

    /// Loads eBPF programs and spawns the event converter task (Linux only).
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Ebpf`] if any eBPF program fails to load.
    #[cfg(target_os = "linux")]
    fn start_ebpf_converter(
        &self,
        tenant_id: TenantId,
        agent_id: AgentId,
        hostname: &str,
        event_tx: mpsc::Sender<KronEvent>,
    ) -> Result<(), AgentError> {
        let boot_time_ns = crate::events::read_boot_time_ns().unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "Cannot read boot time from /proc/stat; timestamps approximate"
            );
            0
        });

        let (raw_tx, raw_rx) = mpsc::channel::<RawBpfEvent>(EVENT_CHANNEL_CAPACITY);
        let _ebpf = EbpfManager::load(&self.config.ebpf, raw_tx)?;

        let collector_id = agent_id.to_string();
        let h = hostname.to_owned();
        tokio::spawn(async move {
            run_event_converter(raw_rx, event_tx, tenant_id, collector_id, h, boot_time_ns).await;
        });
        Ok(())
    }

    /// Checks that the running kernel is >= 5.4.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::KernelTooOld`] if below 5.4.
    #[cfg(target_os = "linux")]
    fn check_kernel_version(&self) -> Result<(), AgentError> {
        let version = kernel_version_string();
        let parts: Vec<u64> = version
            .split('.')
            .take(2)
            .filter_map(|p| p.parse().ok())
            .collect();

        let (major, minor) = match parts.as_slice() {
            [ma, mi, ..] => (*ma, *mi),
            [ma] => (*ma, 0),
            _ => {
                tracing::warn!(version = %version, "Cannot parse kernel version; proceeding anyway");
                return Ok(());
            }
        };

        if major < 5 || (major == 5 && minor < 4) {
            tracing::warn!(
                version = %version,
                "Kernel {version} is below 5.4 — eBPF CO-RE may not function. \
                Consider agentless collection via kron-collector syslog."
            );
            return Err(AgentError::KernelTooOld {
                running: version,
                minimum: "5.4".to_owned(),
            });
        }

        tracing::info!(version = %version, "Kernel version check passed");
        Ok(())
    }

    /// Starts the Prometheus metrics HTTP endpoint.
    ///
    /// No-op if `config.metrics.bind_addr` is empty.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError::Config`] if the bind address is invalid.
    fn start_metrics_exporter(&self) -> Result<(), AgentError> {
        let addr = &self.config.metrics.bind_addr;
        if addr.is_empty() {
            return Ok(());
        }
        let addr_parsed: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| AgentError::Config(format!("invalid metrics bind_addr '{addr}': {e}")))?;
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(addr_parsed)
            .install()
            .map_err(|e| AgentError::Config(format!("cannot start Prometheus exporter: {e}")))?;
        tracing::info!(bind_addr = %addr, "Prometheus metrics exporter started");
        Ok(())
    }
}

// ─── Module-level helpers ────────────────────────────────────────────────────

/// Runs the main event collection loop until shutdown is signalled.
///
/// Receives events from `event_rx`, assembles them into batches, and sends
/// them to the collector. Falls back to the disk buffer when the collector
/// is unreachable. On shutdown, flushes remaining events.
///
/// # Errors
///
/// Returns [`AgentError`] on unrecoverable batch flush errors.
async fn run_event_loop(
    event_rx: &mut mpsc::Receiver<KronEvent>,
    transport: &Arc<Mutex<GrpcTransport>>,
    heartbeat_state: &Arc<Mutex<HeartbeatState>>,
    disk_buffer: &mut DiskBuffer,
    agent_id: AgentId,
    config: &crate::config::AgentConfig,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), AgentError> {
    let mut sequence: u64 = 0;
    let mut batch: Vec<KronEvent> = Vec::with_capacity(config.ebpf.max_batch_size);
    let max_batch = config.ebpf.max_batch_size;
    let batch_delay = config.ebpf.max_batch_delay();
    let mut batch_deadline = Instant::now() + batch_delay;

    loop {
        tokio::select! {
            maybe_event = event_rx.recv() => {
                if let Some(event) = maybe_event {
                    metrics::record_events_captured(&event.event_type, 1);
                    batch.push(event);
                    if batch.len() >= max_batch {
                        flush_batch(
                            &mut batch,
                            &mut sequence,
                            agent_id,
                            &mut *transport.lock().await,
                            disk_buffer,
                            heartbeat_state,
                        ).await?;
                        batch_deadline = Instant::now() + batch_delay;
                    }
                } else {
                    tracing::warn!("Event channel closed — eBPF reader terminated");
                    break;
                }
            }

            () = tokio::time::sleep_until(batch_deadline) => {
                if !batch.is_empty() {
                    flush_batch(
                        &mut batch,
                        &mut sequence,
                        agent_id,
                        &mut *transport.lock().await,
                        disk_buffer,
                        heartbeat_state,
                    ).await?;
                }
                drain_disk_buffer(
                    disk_buffer,
                    &mut sequence,
                    agent_id,
                    &mut *transport.lock().await,
                    heartbeat_state,
                ).await.unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "Disk buffer drain failed");
                });
                batch_deadline = Instant::now() + batch_delay;
            }

            _ = shutdown_rx.recv() => {
                tracing::info!("Shutdown signal — flushing remaining events");
                break;
            }
        }
    }

    // Graceful flush on shutdown.
    if !batch.is_empty() {
        flush_batch(
            &mut batch,
            &mut sequence,
            agent_id,
            &mut *transport.lock().await,
            disk_buffer,
            heartbeat_state,
        )
        .await
        .unwrap_or_else(|e| tracing::error!(error = %e, "Final flush failed"));
    }

    Ok(())
}

/// Sends `batch` to the collector or writes to disk buffer on failure.
async fn flush_batch<T: CollectorTransport>(
    batch: &mut Vec<KronEvent>,
    sequence: &mut u64,
    agent_id: AgentId,
    transport: &mut T,
    disk_buffer: &mut DiskBuffer,
    heartbeat_state: &Arc<Mutex<HeartbeatState>>,
) -> Result<(), AgentError> {
    if batch.is_empty() {
        return Ok(());
    }

    let events = std::mem::take(batch);
    let count = events.len();
    metrics::record_batch_size(count);

    if transport.is_connected() {
        let eb = EventBatch {
            agent_id,
            sequence: *sequence,
            events,
            assembled_at: Utc::now(),
        };
        let start = std::time::Instant::now();
        match transport.send_events(eb).await {
            Ok(ack) => {
                *sequence += 1;
                let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
                metrics::record_events_sent(u64::from(ack.accepted));
                metrics::record_send_latency_ms(elapsed_ms);
                metrics::set_collector_connected(true);
                tracing::debug!(
                    sequence = *sequence - 1,
                    accepted = ack.accepted,
                    rejected = ack.rejected,
                    elapsed_ms,
                    "Batch sent to collector"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = %e, count, "Send failed; collector marked offline");
                metrics::set_collector_connected(false);
                // Events were serialized into the gRPC frame and ownership transferred;
                // we cannot recover them from the transport error. Log as dropped.
                metrics::record_events_dropped(u64::try_from(count).unwrap_or(u64::MAX));
                heartbeat_state.lock().await.events_dropped_since_last +=
                    u64::try_from(count).unwrap_or(u64::MAX);
                return Ok(());
            }
        }
    }

    // Collector offline — write to disk buffer via spawn_blocking.
    buffer_batch_to_disk(events, disk_buffer, heartbeat_state).await
}

/// Writes a batch of events to the disk buffer.
async fn buffer_batch_to_disk(
    events: Vec<KronEvent>,
    disk_buffer: &mut DiskBuffer,
    heartbeat_state: &Arc<Mutex<HeartbeatState>>,
) -> Result<(), AgentError> {
    let count = u64::try_from(events.len()).unwrap_or(u64::MAX);
    // DiskBuffer::push_batch is synchronous; call from async via block_in_place.
    tokio::task::block_in_place(|| disk_buffer.push_batch(&events))?;
    metrics::record_events_buffered(count);
    heartbeat_state.lock().await.disk_buffer_depth += count;
    tracing::debug!(count, "Batch written to disk buffer (collector offline)");
    Ok(())
}

/// Drains disk-buffered events and sends them when the collector is reachable.
async fn drain_disk_buffer<T: CollectorTransport>(
    disk_buffer: &mut DiskBuffer,
    sequence: &mut u64,
    agent_id: AgentId,
    transport: &mut T,
    heartbeat_state: &Arc<Mutex<HeartbeatState>>,
) -> Result<(), AgentError> {
    if !transport.is_connected() || disk_buffer.is_empty() {
        return Ok(());
    }

    let events = tokio::task::block_in_place(|| disk_buffer.drain(1_000))?;
    if events.is_empty() {
        return Ok(());
    }

    let count = events.len();
    let eb = EventBatch {
        agent_id,
        sequence: *sequence,
        events,
        assembled_at: Utc::now(),
    };

    match transport.send_events(eb).await {
        Ok(ack) => {
            *sequence += 1;
            metrics::record_events_sent(u64::from(ack.accepted));
            let mut hs = heartbeat_state.lock().await;
            hs.disk_buffer_depth = hs
                .disk_buffer_depth
                .saturating_sub(u64::try_from(count).unwrap_or(u64::MAX));
            tracing::info!(count, "Replayed disk-buffered events to collector");
        }
        Err(e) => {
            tracing::warn!(error = %e, "Disk buffer replay failed; will retry next interval");
            metrics::set_collector_connected(false);
        }
    }
    Ok(())
}

/// Converts raw eBPF events to `KronEvent`s and forwards them to the batch assembler.
#[cfg(target_os = "linux")]
async fn run_event_converter(
    mut raw_rx: mpsc::Receiver<RawBpfEvent>,
    event_tx: mpsc::Sender<KronEvent>,
    tenant_id: TenantId,
    collector_id: String,
    hostname: String,
    boot_time_ns: u64,
) {
    use crate::events::{
        file_access_to_kron_event, network_connect_to_kron_event, process_create_to_kron_event,
    };

    while let Some(raw) = raw_rx.recv().await {
        let event = match raw {
            RawBpfEvent::ProcessCreate(ev) => {
                process_create_to_kron_event(&ev, tenant_id, &collector_id, &hostname, boot_time_ns)
            }
            RawBpfEvent::NetworkConnect(ev) => network_connect_to_kron_event(
                &ev,
                tenant_id,
                &collector_id,
                &hostname,
                boot_time_ns,
            ),
            RawBpfEvent::FileAccess(ev) => {
                file_access_to_kron_event(&ev, tenant_id, &collector_id, &hostname, boot_time_ns)
            }
        };

        if event_tx.send(event).await.is_err() {
            break;
        }
    }
}

/// Returns the system hostname.
fn read_hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_owned())
    }
}

/// Returns the kernel version string.
fn kernel_version_string() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/version")
            .ok()
            .and_then(|s| s.split_whitespace().nth(2).map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::consts::OS.to_owned()
    }
}

/// Returns the OS name.
fn os_name() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| {
                        l.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_owned()
                    })
            })
            .unwrap_or_else(|| "Linux".to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::consts::OS.to_owned()
    }
}

/// Returns the primary IPv4 address as a dotted-decimal string.
fn primary_ipv4() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map_or_else(|_| "0.0.0.0".to_owned(), |a| a.ip().to_string())
}
