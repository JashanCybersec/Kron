//! `kron-ctl agents` — agent management commands.
//!
//! ## Subcommands
//!
//! - `list`   — fetch all registered agents from the collector and print a table
//! - `create` — pre-register a new agent; prints the assigned agent_id

use crate::{
    client::CollectorClient,
    config::CtlConfig,
    error::CtlError,
    output::{self, Table},
};

/// Run `kron-ctl agents list`.
///
/// Calls `GET /agents` on the collector and renders a table of all registered
/// agents with their last-heartbeat time and dark status.
///
/// # Errors
/// Returns [`CtlError`] if the HTTP request fails.
pub async fn run_list(config: &CtlConfig) -> Result<(), CtlError> {
    let client = CollectorClient::new(config.collector_base_url.clone())?;
    let agents = client.list_agents().await?;

    output::header("Registered Agents");

    let mut table = Table::new(vec![
        "AGENT_ID",
        "TENANT_ID",
        "HOSTNAME",
        "VERSION",
        "LAST_HEARTBEAT",
        "STATUS",
    ]);

    for a in &agents {
        let status = if a.is_dark { "DARK" } else { "alive" };
        table.add_row(vec![
            a.agent_id.clone(),
            a.tenant_id.clone(),
            a.hostname.clone(),
            a.agent_version.clone(),
            a.last_heartbeat_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            status.to_owned(),
        ]);
    }

    table.print();
    println!("\n{} agent(s) registered.", agents.len());
    Ok(())
}

/// Arguments for `kron-ctl agents create` (pre-register an agent).
pub struct CreateArgs {
    /// Hostname to assign to the new agent.
    pub hostname: String,
    /// Optional tenant UUID; the collector uses its default if absent.
    pub tenant_id: Option<String>,
}

/// Run `kron-ctl agents create`.
///
/// Calls `POST /agents/register` on the collector and prints the assigned
/// `agent_id`.  The operator then sets `agent.id` in the agent's config file
/// to this value before starting the agent binary.
///
/// # Errors
/// Returns [`CtlError`] if the HTTP request fails.
pub async fn run_create(config: &CtlConfig, args: CreateArgs) -> Result<(), CtlError> {
    let client = CollectorClient::new(config.collector_base_url.clone())?;
    let resp = client
        .register_agent(&args.hostname, args.tenant_id.as_deref())
        .await?;

    output::header("Agent Registered");
    println!("  agent_id      : {}", resp.agent_id);
    println!("  tenant_id     : {}", resp.tenant_id);
    println!(
        "  registered_at : {}",
        resp.registered_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!();
    println!(
        "Set agent.id = \"{}\" in the agent's kron.toml.",
        resp.agent_id
    );
    Ok(())
}
