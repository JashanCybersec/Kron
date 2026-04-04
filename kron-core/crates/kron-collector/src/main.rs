//! `kron-collector` — Event intake service for the KRON SIEM platform.
//!
//! Receives events from agents and external sources, validates them,
//! and routes them to the message bus topic `kron.raw.{tenant_id}`.
//!
//! # Intake sources
//!
//! - gRPC stream from `kron-agent` (mTLS required, plaintext rejected)
//! - Syslog UDP (RFC 3164 / RFC 5424, port 514)
//! - Syslog TCP (RFC 3164 / RFC 5424, port 6514; TLS in Phase 2)
//! - HTTP batch: `POST /intake/v1/events` (JSON, Bearer auth)
//!
//! # Agent management
//!
//! - Registration: gRPC `Register` RPC + `POST /agents/register`
//! - Heartbeat: gRPC `Heartbeat` RPC + `POST /agents/heartbeat`
//! - Agent marked "dark" after 90 s of no heartbeat (configurable)
//!
//! # Usage
//!
//! ```text
//! kron-collector --config /etc/kron/kron.toml [--log-level debug]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use kron_collector::{Collector, ShutdownHandle};
use kron_types::KronConfig;
use tracing_subscriber::EnvFilter;

/// Default configuration file path.
const DEFAULT_CONFIG_PATH: &str = "/etc/kron/kron.toml";

fn main() -> ExitCode {
    let args = parse_args();

    init_tracing(&args.log_level);

    let config = match KronConfig::from_file(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kron-collector")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: cannot create Tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move {
        let (shutdown, signal_task) = ShutdownHandle::new();
        let _signal = signal_task;

        let collector = Collector::new(config, shutdown);
        match collector.run().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "Collector exited with error");
                ExitCode::FAILURE
            }
        }
    })
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
/// - `--config <path>` — path to `kron.toml`
/// - `--log-level <level>` — tracing filter
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
                    "kron-collector {version}\n\
                    KRON event intake service\n\n\
                    USAGE:\n\
                    \tkron-collector [OPTIONS]\n\n\
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
                println!("kron-collector {}", env!("CARGO_PKG_VERSION"));
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
                eprintln!("Run `kron-collector --help` for usage.");
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
