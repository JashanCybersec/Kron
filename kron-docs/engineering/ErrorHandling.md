# ErrorHandling.md — KRON Error Handling Patterns

**Rule:** Errors are first-class citizens. Every error has context. No error is silently swallowed.

---

## Error Type Structure

Each crate defines its own `Error` enum using `thiserror`.
All errors eventually convert to `KronError` at the API boundary.

```rust
// kron-storage/src/error.rs

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("ClickHouse connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Query execution failed (tenant={tenant_id}): {source}")]
    QueryFailed {
        tenant_id: String,
        source: clickhouse::error::Error,
    },

    #[error("Tenant isolation violation detected: query for tenant {requested} returned rows from tenant {found}")]
    TenantIsolationViolation {
        requested: String,
        found: String,
    },

    #[error("Migration {version} failed: {reason}")]
    MigrationFailed { version: u32, reason: String },

    #[error("Connection pool exhausted after {timeout_ms}ms")]
    PoolTimeout { timeout_ms: u64 },
}
```

## Error Propagation

```rust
// Propagate with ? — add context at the call site
async fn get_alert(tenant_id: TenantId, alert_id: AlertId, db: &Storage) -> Result<KronAlert, StorageError> {
    db.query_one(tenant_id, alert_id)
        .await
        .map_err(|e| StorageError::QueryFailed {
            tenant_id: tenant_id.to_string(),
            source: e,
        })
}
```

## Logging at Error Site

```rust
// Log at the point where the error is HANDLED (not where it's propagated)
match send_whatsapp_alert(&alert).await {
    Ok(_) => {
        tracing::info!(alert_id = %alert.id, "WhatsApp alert sent");
    }
    Err(e) => {
        // Log here — this is the handler
        tracing::error!(
            alert_id = %alert.id,
            tenant_id = %alert.tenant_id,
            error = %e,
            "WhatsApp delivery failed, attempting SMS fallback"
        );
        // Attempt fallback
        send_sms_alert(&alert).await?;
    }
}
```

## API Error Responses

All API errors return consistent JSON:

```rust
// kron-query-api/src/error.rs

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub code: &'static str,
    pub message: String,
    pub request_id: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.error.code {
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "INSUFFICIENT_PERMISSION" => StatusCode::FORBIDDEN,
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "RATE_LIMITED" => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}
```

## Panic Policy

`panic!`, `unwrap()`, and `expect()` are forbidden in production code paths.
The only allowed panics are:
1. In `main()` for configuration loading failures (before server starts)
2. In tests
3. In `#[cfg(debug_assertions)]` blocks for invariant checking

```rust
// ALLOWED — startup configuration panic:
fn main() {
    let config = KronConfig::load()
        .expect("Failed to load configuration — check /etc/kron/kron.toml");
    // ...
}

// ALLOWED — test:
#[test]
fn test_something() {
    let result = do_thing().unwrap(); // fine in tests
}

// NOT ALLOWED — production code path:
async fn handle_request(req: Request) -> Response {
    let tenant_id = extract_tenant_id(&req).unwrap(); // FORBIDDEN
}
```
