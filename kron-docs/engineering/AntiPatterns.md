# AntiPatterns.md — What KRON Code Must Never Do

**Purpose:** Concrete examples of bad patterns with the correct alternative.
Claude reads this to avoid repeating common mistakes.
Every item here was added because it was a real problem or a predictable one.

---

## 1. The Skeleton Implementation

**Problem:** Writing a function that compiles but doesn't actually work, with the intention of "filling it in later."

```rust
// BAD — This looks like code but does nothing useful:
pub async fn send_whatsapp_alert(alert: &KronAlert) -> Result<()> {
    // TODO: implement WhatsApp integration
    tracing::info!("WhatsApp alert would be sent here");
    Ok(())
}
```

**Why it's dangerous:** It passes tests. It passes code review. It ships. Users get no alerts.

**Correct approach:** If you can't implement it now, don't write it at all.
Instead, write in PHASES.md:
```
- [ ] WhatsApp alert delivery (kron-alert/src/notifications/whatsapp.rs)
```
And return an explicit error from callers that need it:
```rust
pub async fn send_whatsapp_alert(_alert: &KronAlert) -> Result<()> {
    Err(KronError::NotImplemented("WhatsApp alerting not yet configured"))
}
```

---

## 2. The God Function

**Problem:** One function that does too many things.

```rust
// BAD — 200 lines, does everything:
pub async fn process_event(raw: &str, tenant_id: TenantId, db: &Storage, bus: &Bus) -> Result<()> {
    // Parse the event
    // Normalize it
    // Enrich with GeoIP
    // Check IOCs
    // Run SIGMA rules
    // Score with ONNX
    // Write to ClickHouse
    // Write to Redpanda
    // Check for alerts
    // Send WhatsApp if P1
}
```

**Correct approach:** Single responsibility. Each step is its own function or module.

```rust
// GOOD — pipeline of single-responsibility functions:
pub async fn process_event(raw: RawEvent, ctx: &ProcessingContext) -> Result<()> {
    let parsed = parse_event(&raw)?;
    let normalized = normalize_event(parsed, &ctx.mappings)?;
    let enriched = enrich_event(normalized, &ctx.geoip, &ctx.assets).await?;
    let scored = score_event(enriched, &ctx.ioc_filter, &ctx.sigma, &ctx.onnx).await?;
    
    ctx.storage.insert_event(scored.clone()).await?;
    
    if let Some(alert) = scored.alert_candidate {
        ctx.alert_engine.process_candidate(alert).await?;
    }
    
    Ok(())
}
```

---

## 3. SQL Strings Outside kron-storage

**Problem:** Writing SQL anywhere except the storage layer.

```rust
// BAD — SQL in a query handler:
// kron-query-api/src/routes/alerts.rs
async fn get_alerts(tenant_id: TenantId, db: &Storage) -> Result<Vec<KronAlert>> {
    let sql = format!(
        "SELECT * FROM alerts WHERE tenant_id = '{tenant_id}' ORDER BY created_at DESC LIMIT 100"
    );
    db.raw_query(&sql).await  // SQL injection vulnerability + bypasses tenant isolation
}
```

**Correct approach:** All queries in kron-storage:

```rust
// kron-storage/src/clickhouse/alerts.rs
pub async fn list_alerts(
    &self, 
    tenant_id: TenantId,
    filter: AlertFilter,
) -> Result<Vec<KronAlert>, StorageError> {
    // SQL is here, parameterized, tenant_id enforced
    let query = self.builder.build_alert_list_query(tenant_id, filter)?;
    self.client.query(&query).fetch_all::<KronAlert>().await
        .map_err(|e| StorageError::QueryFailed { tenant_id: tenant_id.to_string(), source: e })
}

// kron-query-api/src/routes/alerts.rs  
async fn get_alerts(ctx: TenantContext, db: &Storage) -> Result<Vec<KronAlert>> {
    db.list_alerts(ctx.tenant_id, AlertFilter::default()).await
}
```

---

## 4. Tenant ID from Request Body

**Problem:** Accepting tenant_id from the request body or query params.

```rust
// BAD — tenant_id comes from the request, not the JWT:
async fn get_events(
    Query(params): Query<EventParams>,  // has tenant_id field
    db: &Storage,
) -> Result<Json<Vec<KronEvent>>> {
    // Attacker sets tenant_id to any value they want
    db.query_events(params.tenant_id, EventFilter::default()).await
}
```

**Correct approach:** tenant_id always and only from the JWT claim:

```rust
// GOOD — TenantContext extracted from JWT by middleware:
async fn get_events(
    ctx: TenantContext,  // injected by auth middleware from JWT
    Query(filter): Query<EventFilter>,  // no tenant_id here
    db: &Storage,
) -> Result<Json<Vec<KronEvent>>> {
    db.query_events(ctx.tenant_id, filter).await
}
```

---

## 5. Swallowing Errors

**Problem:** Ignoring errors with `let _ =` or empty catch blocks.

```rust
// BAD:
let _ = storage.insert_audit_log(entry).await;  // audit log might be silently failing

// ALSO BAD:
if let Err(_) = send_alert(alert).await {
    // silently continue — analyst never gets notified of P1 alert
}
```

**Correct approach:**

```rust
// GOOD — every error is handled explicitly:
storage.insert_audit_log(entry).await
    .map_err(|e| {
        // Audit log failure is critical — it must be surfaced, not ignored
        tracing::error!(error = %e, "CRITICAL: audit log write failed");
        // Still return the error so the caller can decide
        e
    })?;

// For non-critical paths, log and continue but don't pretend success:
if let Err(e) = send_whatsapp_alert(&alert).await {
    tracing::warn!(
        alert_id = %alert.id,
        error = %e,
        "WhatsApp failed, attempting SMS fallback"
    );
    send_sms_alert(&alert).await?;  // this one we do propagate
}
```

---

## 6. Copying Types Instead of Sharing

**Problem:** Defining the same concept in multiple crates.

```rust
// BAD — Severity defined in kron-stream:
// crates/kron-stream/src/types.rs
pub enum Severity { P1, P2, P3, P4, P5 }

// AND ALSO in kron-alert:
// crates/kron-alert/src/types.rs
pub enum AlertSeverity { Critical, High, Medium, Low, Info }

// Now you need conversion functions and they drift apart
```

**Correct approach:** One definition in `kron-types`, used everywhere.

---

## 7. Blocking in Async Context

**Problem:** Using synchronous I/O or CPU-heavy work in an async function without `spawn_blocking`.

```rust
// BAD — blocks the tokio executor thread:
async fn compute_risk_score(event: &KronEvent) -> f32 {
    // ONNX inference is CPU-heavy
    let session = load_onnx_session();  // blocking I/O
    let result = session.run(input)?;   // CPU-heavy
    result[0]
}
```

**Correct approach:**

```rust
// GOOD — CPU work on blocking thread pool:
async fn compute_risk_score(event: &KronEvent) -> Result<f32> {
    let features = extract_features(event);  // fast, can be async
    
    let score = tokio::task::spawn_blocking(move || {
        // ONNX inference runs here, on a blocking thread
        ONNX_SESSION.run(features)
    })
    .await
    .map_err(|e| KronError::InferenceError(e.to_string()))??;
    
    Ok(score)
}
```

---

## 8. Magic Numbers and Strings

**Problem:** Hardcoded values scattered through business logic.

```rust
// BAD:
if risk_score > 80 { send_immediate_alert() }
if risk_score > 60 { send_batched_alert() }
let timeout = Duration::from_secs(30);
let topic = "kron.events.enriched";
```

**Correct approach:** Named constants or config values.

```rust
// GOOD — in kron-types/src/enums.rs:
impl Severity {
    pub fn from_risk_score(score: u8) -> Self {
        match score {
            80..=100 => Severity::P1,
            60..=79  => Severity::P2,
            40..=59  => Severity::P3,
            20..=39  => Severity::P4,
            _        => Severity::P5,
        }
    }
}

// In kron-types/src/config.rs:
pub struct AlertConfig {
    pub p1_threshold: u8,  // default 80
    pub p2_threshold: u8,  // default 60
}

// In kron-bus/src/topics.rs:
pub const TOPIC_ENRICHED_EVENTS: &str = "kron.events.enriched";
```

---

## 9. Feature Branches That Diverge Too Long

**Problem:** Working on a feature for 2 weeks without merging to main.

**Correct approach:** Feature flags for incomplete features. Merge to main daily.

```rust
// kron-types/src/config.rs
pub struct FeatureFlags {
    pub mistral_enabled: bool,    // off until CPU inference is optimized
    pub ot_bridge_enabled: bool,  // off until Phase 2
    pub gpu_inference: bool,      // off unless GPU detected
}
```

---

## 10. Tests That Test Nothing

**Problem:** Tests that always pass regardless of correctness.

```rust
// BAD — this test proves nothing:
#[test]
fn test_risk_score() {
    let score = compute_risk_score(50, 0.5, false, AssetCriticality::Medium);
    assert!(score >= 0);   // always true
    assert!(score <= 100); // always true
}

// ALSO BAD — testing implementation, not behaviour:
#[test]
fn test_risk_score_calls_formula() {
    // This test would pass even if the formula was wrong
}
```

**Correct approach:** Tests assert specific expected values from known inputs.

```rust
// GOOD — specific assertions:
#[test]
fn test_risk_score_when_ioc_hit_high_severity_then_p1() {
    let score = compute_risk_score(
        RuleMatch { base_severity: 75 },
        anomaly_score: 0.8,
        ioc_hit: true,
        AssetCriticality::High,
    );
    // IOC hit on high-severity rule with high anomaly on critical asset = P1
    assert!(score >= 80, "Expected P1 (>=80), got {score}");
}

#[test]
fn test_risk_score_when_all_low_signals_then_p4_or_below() {
    let score = compute_risk_score(
        RuleMatch { base_severity: 10 },
        anomaly_score: 0.1,
        ioc_hit: false,
        AssetCriticality::Low,
    );
    assert!(score < 40, "Expected P4 or below (<40), got {score}");
}
```
