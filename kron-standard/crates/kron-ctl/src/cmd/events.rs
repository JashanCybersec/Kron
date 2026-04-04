//! `kron-ctl events` — query and tail events from storage.
//!
//! ## Subcommands
//!
//! - `query` — one-shot filtered query, printed as a table
//! - `tail`  — poll storage for new events every 2 seconds

use chrono::{DateTime, Utc};
use kron_storage::{AdaptiveStorage, StorageEngine as _};
use kron_types::{TenantContext, TenantId};
use uuid::Uuid;

use crate::{
    config::CtlConfig,
    error::CtlError,
    output::{self, Table},
};

/// Arguments for `kron-ctl events query`.
pub struct QueryArgs {
    /// Tenant UUID string (required).
    pub tenant: String,
    /// Earliest event timestamp, RFC 3339 or shorthand like "1h".
    pub from: Option<String>,
    /// Latest event timestamp, RFC 3339.
    pub to: Option<String>,
    /// Maximum rows to return.
    pub limit: u32,
    /// Output format: "table" or "json".
    pub output: String,
}

/// Arguments for `kron-ctl events tail`.
pub struct TailArgs {
    /// Tenant UUID string (required).
    pub tenant: String,
    /// Poll interval in seconds.
    pub interval_secs: u64,
}

/// Run `kron-ctl events query`.
///
/// # Errors
/// Returns [`CtlError`] on storage or argument errors.
pub async fn run_query(config: &CtlConfig, args: QueryArgs) -> Result<(), CtlError> {
    let tenant_id = parse_tenant_id(&args.tenant)?;
    let ctx = TenantContext::new(tenant_id, "kron-ctl", "operator");

    let storage = AdaptiveStorage::new(&config.inner)
        .await
        .map_err(|e| CtlError::Storage(e.to_string()))?;

    let filter = build_filter(args.from.as_deref(), args.to.as_deref())?;

    let events = storage
        .query_events(&ctx, filter, args.limit)
        .await
        .map_err(|e| CtlError::Storage(e.to_string()))?;

    if args.output == "json" {
        let json = serde_json::to_string_pretty(&events)?;
        println!("{json}");
        return Ok(());
    }

    // Table output.
    let mut table = Table::new(vec![
        "TIMESTAMP",
        "TYPE",
        "HOST",
        "SRC_IP",
        "USER",
        "PROCESS",
    ]);
    for e in &events {
        table.add_row(vec![
            e.ts.format("%Y-%m-%d %H:%M:%S").to_string(),
            e.event_type.clone(),
            e.hostname.clone().unwrap_or_default(),
            e.src_ip
                .as_ref()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            e.user_name.clone().unwrap_or_default(),
            e.process_name.clone().unwrap_or_default(),
        ]);
    }
    println!();
    table.print();
    println!("\n{} event(s) returned.", events.len());
    Ok(())
}

/// Run `kron-ctl events tail`.
///
/// Polls storage every `args.interval_secs` seconds and prints new events
/// as they arrive.  Runs until interrupted by Ctrl-C.
///
/// # Errors
/// Returns [`CtlError`] on storage or argument errors.
pub async fn run_tail(config: &CtlConfig, args: TailArgs) -> Result<(), CtlError> {
    let tenant_id = parse_tenant_id(&args.tenant)?;
    let ctx = TenantContext::new(tenant_id, "kron-ctl", "operator");

    let storage = AdaptiveStorage::new(&config.inner)
        .await
        .map_err(|e| CtlError::Storage(e.to_string()))?;

    output::header(&format!("Tailing events for tenant {}", args.tenant));
    println!("Press Ctrl-C to stop.\n");
    println!(
        "{:<20} {:<20} {:<20} {:<15}",
        "TIMESTAMP", "TYPE", "HOST", "SRC_IP"
    );
    println!("{}", "─".repeat(80));

    let mut last_seen: Option<DateTime<Utc>> = None;
    let interval = tokio::time::Duration::from_secs(args.interval_secs);

    loop {
        // Query events newer than the last seen timestamp.
        let from_ts = last_seen.unwrap_or_else(|| Utc::now() - chrono::Duration::seconds(5));
        let filter = kron_storage::query::EventFilter {
            from_ts: Some(from_ts),
            ..Default::default()
        };

        match storage.query_events(&ctx, Some(filter), 100).await {
            Ok(events) => {
                for e in &events {
                    // Only print events strictly newer than our cursor.
                    if last_seen.map_or(true, |t| e.ts > t) {
                        last_seen = Some(e.ts);
                        println!(
                            "{:<20} {:<20} {:<20} {:<15}",
                            e.ts.format("%Y-%m-%d %H:%M:%S"),
                            e.event_type,
                            e.hostname.as_deref().unwrap_or("-"),
                            e.src_ip
                                .as_ref()
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "-".to_owned()),
                        );
                    }
                }
            }
            Err(e) => {
                output::warn("storage", &e.to_string());
            }
        }

        tokio::time::sleep(interval).await;
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Parse a tenant UUID string into a [`TenantId`].
fn parse_tenant_id(s: &str) -> Result<TenantId, CtlError> {
    s.parse::<Uuid>()
        .map(TenantId::from_uuid)
        .map_err(|e| CtlError::InvalidArg(format!("invalid tenant UUID '{s}': {e}")))
}

/// Build an [`EventFilter`] from CLI timestamp arguments.
///
/// Accepts:
/// - RFC 3339 strings: `2024-01-15T10:30:00Z`
/// - Relative shorthand: `1h`, `30m`, `7d`, `24h`
fn build_filter(
    from: Option<&str>,
    to: Option<&str>,
) -> Result<Option<kron_storage::query::EventFilter>, CtlError> {
    let from_ts = from.map(parse_ts).transpose()?;
    let to_ts = to.map(parse_ts).transpose()?;

    if from_ts.is_none() && to_ts.is_none() {
        return Ok(None);
    }

    Ok(Some(kron_storage::query::EventFilter {
        from_ts,
        to_ts,
        ..Default::default()
    }))
}

/// Parse a timestamp from RFC 3339 or a relative shorthand like `1h`, `30m`, `7d`.
fn parse_ts(s: &str) -> Result<DateTime<Utc>, CtlError> {
    // Try RFC 3339 first.
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try relative shorthand: number + unit.
    let (num_str, unit) = s
        .find(|c: char| c.is_alphabetic())
        .map(|i| s.split_at(i))
        .ok_or_else(|| CtlError::InvalidArg(format!("cannot parse timestamp '{s}'")))?;

    let n: i64 = num_str
        .parse()
        .map_err(|_| CtlError::InvalidArg(format!("cannot parse timestamp '{s}'")))?;

    let duration = match unit {
        "s" => chrono::Duration::seconds(n),
        "m" => chrono::Duration::minutes(n),
        "h" => chrono::Duration::hours(n),
        "d" => chrono::Duration::days(n),
        _ => {
            return Err(CtlError::InvalidArg(format!(
                "unknown time unit '{unit}' in '{s}' — use s, m, h, or d"
            )))
        }
    };

    Ok(Utc::now() - duration)
}
