//! `kron-normalizer` — Event normalization service for the KRON SIEM platform.
//!
//! Consumes raw events from `kron.raw.{tenant_id}`, normalizes them to the
//! KRON canonical schema, enriches with GeoIP and asset context,
//! deduplicates, then publishes to `kron.enriched.{tenant_id}` and writes to
//! storage.
//!
//! # Usage
//!
//! ```text
//! kron-normalizer --config /etc/kron/kron.toml [--log-level debug]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use kron_normalizer::ShutdownHandle;
use kron_types::KronConfig;
use tracing_subscriber::EnvFilter;

/// Default configuration file path.
#[cfg(not(windows))]
const DEFAULT_CONFIG_PATH: &str = "/etc/kron/kron.toml";
#[cfg(windows)]
const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\kron\etc\kron.toml";

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
        .thread_name("kron-normalizer")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: cannot create Tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move {
        let (shutdown, _signal_task) = ShutdownHandle::new();

        match kron_normalizer::run(config, shutdown).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "Normalizer exited with error");
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

/// Minimal CLI parser.
///
/// Supports `--config <path>`, `--log-level <level>`, `--help`, `--version`.
fn parse_args() -> Args {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut log_level = "info".to_owned();

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "kron-normalizer {version}\n\
                    KRON event normalization service\n\n\
                    USAGE:\n\
                    \tkron-normalizer [OPTIONS]\n\n\
                    OPTIONS:\n\
                    \t--config <path>       Configuration file (default: {DEFAULT_CONFIG_PATH})\n\
                    \t--log-level <level>   Log level (default: info)\n\
                    \t--help, -h            Print this help\n\
                    \t--version, -v         Print version",
                    version = env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            "--version" | "-v" => {
                println!("kron-normalizer {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--config" => {
                config_path = iter.next().map(PathBuf::from).unwrap_or_else(|| {
                    eprintln!("ERROR: --config requires a value");
                    std::process::exit(1);
                });
            }
            "--log-level" => {
                log_level = iter.next().unwrap_or_else(|| {
                    eprintln!("ERROR: --log-level requires a value");
                    std::process::exit(1);
                });
            }
            unknown => {
                eprintln!("ERROR: unknown argument: {unknown}");
                eprintln!("Run `kron-normalizer --help` for usage.");
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
fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(true)
        .with_span_list(true)
        .init();
}
