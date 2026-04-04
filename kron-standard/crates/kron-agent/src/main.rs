//! `kron-agent` — eBPF/ETW collection agent for the KRON SIEM platform.
//!
//! Deployed on monitored Linux (eBPF) and Windows (ETW, future) endpoints.
//! Captures process creation, network connections, file access, and
//! authentication events and streams them to `kron-collector` via gRPC mTLS.
//!
//! # Key properties
//!
//! - CO-RE: BTF-based, compiles once, runs on kernel 5.4+
//! - Static binary: < 20 MB, no runtime dependencies
//! - Local disk buffer: survives collector outages up to 1 GB
//! - CPU overhead: < 1% on idle system; memory: < 50 MB RSS
//!
//! # Usage
//!
//! ```text
//! sudo kron-agent --config /etc/kron/agent.toml [--log-level debug]
//! ```

mod agent;
mod buffer;
mod config;
mod ebpf;
mod error;
mod heartbeat;
mod metrics;
mod shutdown;
mod transport;

// bpf_types and events are only meaningful on Linux (eBPF is Linux-only),
// but we keep them unconditionally compiled so that `cargo check` on any
// platform catches type errors in those modules.
mod bpf_types;
mod events;

use std::path::PathBuf;
use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

use crate::agent::Agent;
use crate::config::AgentConfig;
use crate::shutdown::ShutdownHandle;

/// Default configuration file path.
const DEFAULT_CONFIG_PATH: &str = "/etc/kron/agent.toml";

fn main() -> ExitCode {
    let args = parse_args();

    init_tracing(&args.log_level);

    let config = match AgentConfig::from_file(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kron-agent")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: cannot create Tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let exit_code = runtime.block_on(async move {
        let (shutdown, signal_task) = ShutdownHandle::new();

        // Ensure the signal task runs.
        let _signal = signal_task;

        let agent = Agent::new(config, shutdown);
        match agent.run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "Agent exited with error");
                ExitCode::FAILURE
            }
        }
    });

    exit_code
}

// ─── CLI argument parsing ────────────────────────────────────────────────────

/// Parsed command-line arguments.
struct Args {
    config_path: PathBuf,
    log_level: String,
}

/// Minimal CLI parser (no external dependencies).
///
/// Supports:
/// - `--config <path>` — path to `agent.toml`
/// - `--log-level <level>` — tracing filter (e.g. `debug`, `info`)
/// - `--help` / `-h` — print usage and exit
/// - `--version` / `-v` — print version and exit
fn parse_args() -> Args {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut log_level = "info".to_owned();

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "kron-agent {version}\n\
                    KRON eBPF collection agent\n\n\
                    USAGE:\n\
                    \tkron-agent [OPTIONS]\n\n\
                    OPTIONS:\n\
                    \t--config <path>       Configuration file (default: {DEFAULT_CONFIG_PATH})\n\
                    \t--log-level <level>   Log level: error,warn,info,debug,trace (default: info)\n\
                    \t--help, -h            Print this help\n\
                    \t--version, -v         Print version",
                    version = env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            "--version" | "-v" => {
                println!("kron-agent {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--config" => {
                config_path = iter.next().map_or_else(
                    || {
                        eprintln!("ERROR: --config requires a value");
                        std::process::exit(1);
                    },
                    PathBuf::from,
                );
            }
            "--log-level" => {
                log_level = iter.next().unwrap_or_else(|| {
                    eprintln!("ERROR: --log-level requires a value");
                    std::process::exit(1);
                });
            }
            unknown => {
                eprintln!("ERROR: unknown argument: {unknown}");
                eprintln!("Run `kron-agent --help` for usage.");
                std::process::exit(1);
            }
        }
    }

    Args {
        config_path,
        log_level,
    }
}

// ─── Tracing initialisation ──────────────────────────────────────────────────

/// Initialises the `tracing` subscriber with structured JSON output.
///
/// The log level is set from `--log-level` and can be overridden per-crate
/// via the `RUST_LOG` environment variable.
fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(true)
        .with_span_list(true)
        .init();
}
