//! `kron-ctl` — CLI management tool for the KRON SIEM platform.
//!
//! Distributed as a static binary on both server and admin workstations.
//! Used for health checks, event queries, agent management, and migrations.
//!
//! # Usage
//!
//! ```text
//! kron-ctl [OPTIONS] <COMMAND>
//!
//! Options:
//!   -c, --config <PATH>          Path to kron.toml [default: /etc/kron/kron.toml]
//!       --collector-url <URL>    Override collector base URL [default: from config]
//!   -o, --output <FORMAT>        Output format: table or json [default: table]
//!
//! Commands:
//!   health                       Check all services
//!   events query                 Query events from storage
//!   events tail                  Live tail events
//!   agents list                  List registered agents
//!   agents create                Pre-register a new agent
//!   storage stats                Show storage statistics
//!   migration run                Apply pending migrations
//!   migration status             Show migration file status
//! ```

use std::path::PathBuf;
use std::process;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod client;
mod cmd;
mod config;
mod error;
mod output;

use config::CtlConfig;

// ─── CLI structure ────────────────────────────────────────────────────────────

/// kron-ctl — KRON SIEM management CLI.
#[derive(Debug, Parser)]
#[command(name = "kron-ctl", version, about)]
struct Cli {
    /// Path to the KRON configuration file.
    #[arg(short = 'c', long = "config", default_value = "/etc/kron/kron.toml")]
    config: PathBuf,

    /// Override the collector base URL (e.g. `http://localhost:9002`).
    /// Defaults to the value derived from `collector.http_addr` in the config file.
    #[arg(long = "collector-url")]
    collector_url: Option<String>,

    /// Output format for tabular commands.
    #[arg(short = 'o', long = "output", default_value = "table")]
    output: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check health of all KRON services.
    Health,

    /// Event query and tail commands.
    Events {
        #[command(subcommand)]
        subcommand: EventsCommand,
    },

    /// Agent management commands.
    Agents {
        #[command(subcommand)]
        subcommand: AgentsCommand,
    },

    /// Storage statistics.
    Storage {
        #[command(subcommand)]
        subcommand: StorageCommand,
    },

    /// Database migration commands.
    Migration {
        #[command(subcommand)]
        subcommand: MigrationCommand,
    },
}

#[derive(Debug, Subcommand)]
enum EventsCommand {
    /// Query events from storage.
    Query {
        /// Tenant UUID (required).
        #[arg(long)]
        tenant: String,

        /// Earliest timestamp (RFC 3339 or relative: 1h, 30m, 7d).
        #[arg(long)]
        from: Option<String>,

        /// Latest timestamp (RFC 3339).
        #[arg(long)]
        to: Option<String>,

        /// Maximum number of events to return.
        #[arg(long, default_value = "50")]
        limit: u32,
    },

    /// Live tail events from storage (polls every 2 seconds).
    Tail {
        /// Tenant UUID (required).
        #[arg(long)]
        tenant: String,

        /// Poll interval in seconds.
        #[arg(long, default_value = "2")]
        interval: u64,
    },
}

#[derive(Debug, Subcommand)]
enum AgentsCommand {
    /// List all registered agents and their heartbeat status.
    List,

    /// Pre-register a new agent with the collector.
    Create {
        /// Hostname for the new agent.
        #[arg(long)]
        hostname: String,

        /// Tenant UUID to assign (uses collector default if omitted).
        #[arg(long)]
        tenant_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum StorageCommand {
    /// Show storage backend statistics and health.
    Stats,
}

#[derive(Debug, Subcommand)]
enum MigrationCommand {
    /// Apply all pending database migrations (idempotent).
    Run,

    /// Show migration files on disk and their checksums.
    Status,
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Minimal tracing subscriber: errors and warnings only by default.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

/// Dispatch to the appropriate command handler.
async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = CtlConfig::load(&cli.config, cli.collector_url.as_deref())
        .context("failed to load configuration")?;

    match cli.command {
        Commands::Health => {
            cmd::health::run(&config).await?;
        }

        Commands::Events { subcommand } => match subcommand {
            EventsCommand::Query {
                tenant,
                from,
                to,
                limit,
            } => {
                cmd::events::run_query(
                    &config,
                    cmd::events::QueryArgs {
                        tenant,
                        from,
                        to,
                        limit,
                        output: cli.output,
                    },
                )
                .await?;
            }
            EventsCommand::Tail { tenant, interval } => {
                cmd::events::run_tail(
                    &config,
                    cmd::events::TailArgs {
                        tenant,
                        interval_secs: interval,
                    },
                )
                .await?;
            }
        },

        Commands::Agents { subcommand } => match subcommand {
            AgentsCommand::List => {
                cmd::agents::run_list(&config).await?;
            }
            AgentsCommand::Create {
                hostname,
                tenant_id,
            } => {
                cmd::agents::run_create(
                    &config,
                    cmd::agents::CreateArgs {
                        hostname,
                        tenant_id,
                    },
                )
                .await?;
            }
        },

        Commands::Storage { subcommand } => match subcommand {
            StorageCommand::Stats => {
                cmd::storage::run_stats(&config).await?;
            }
        },

        Commands::Migration { subcommand } => match subcommand {
            MigrationCommand::Run => {
                cmd::migration::run_migrate(&config).await?;
            }
            MigrationCommand::Status => {
                cmd::migration::run_status(&config)?;
            }
        },
    }

    Ok(())
}
