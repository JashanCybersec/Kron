# TestingGuide.md — KRON Testing Standards

**Rule:** A feature is not done until it has tests. Tests are not optional.

---

## Test Pyramid

```
        ┌─────────────┐
        │   E2E Tests  │  ← few, slow, high confidence
        │   (scripts/) │
        ├─────────────┤
        │ Integration  │  ← medium count, real services
        │   Tests      │  (tests/integration/)
        ├─────────────┤
        │  Unit Tests  │  ← many, fast, pure logic
        │  (in crate)  │
        └─────────────┘
```

Target coverage: **unit tests cover all business logic**, integration tests cover all I/O paths.

---

## Unit Tests

### Location
In the same file as the code being tested:

```rust
// src/scoring/risk.rs

pub fn compute_risk_score(...) -> u8 { ... }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_when_ioc_hit_then_minimum_high() {
        let score = compute_risk_score(
            RuleMatch { base_severity: 30 },
            0.3,  // anomaly score
            true, // ioc_hit
            AssetCriticality::Medium,
        );
        assert!(score >= 60, "IOC hit must always produce High or above, got {score}");
    }

    #[test]
    fn test_risk_score_when_all_low_then_below_threshold() {
        let score = compute_risk_score(
            RuleMatch { base_severity: 10 },
            0.1,
            false,
            AssetCriticality::Low,
        );
        assert!(score < 40, "All-low inputs must produce P4 or below, got {score}");
    }
}
```

### Naming convention
`test_{what}_when_{condition}_then_{expected}`

Good: `test_dedup_when_same_event_twice_in_window_then_one_alert`
Bad: `test1`, `test_dedup`, `dedup_works`

### What to test in unit tests
- Every branch of every function
- Edge cases: empty input, max input, None, 0
- Error cases: invalid input returns correct error variant
- Business rules: risk score thresholds, dedup windows, rate limits

### What NOT to test in unit tests
- Database queries (use integration tests)
- HTTP calls (use integration tests)
- eBPF programs (use integration tests)

---

## Integration Tests

### Location
`tests/integration/{crate_name}/`

### Setup
All integration tests require real services. Use testcontainers:

```rust
// tests/integration/storage/test_events.rs

use testcontainers::{clients::Cli, images::clickhouse::ClickHouse};
use kron_storage::{AdaptiveStorage, StorageEngine};
use kron_types::*;

#[tokio::test]
#[ignore] // Run with: cargo test -- --include-ignored integration
async fn test_insert_events_when_valid_tenant_then_queryable() {
    let docker = Cli::default();
    let clickhouse = docker.run(ClickHouse::default());
    let port = clickhouse.get_host_port_ipv4(8123);
    
    let storage = AdaptiveStorage::clickhouse(format!("http://localhost:{port}"))
        .await
        .expect("Failed to connect to ClickHouse");
    
    storage.run_migrations().await.expect("Migrations failed");
    
    let tenant_id = TenantId::new();
    let events = vec![
        KronEvent::builder()
            .tenant_id(tenant_id.clone())
            .source_type(EventSource::Syslog)
            .event_type("authentication")
            .ts(Utc::now())
            .build()
            .unwrap()
    ];
    
    storage.insert_events(tenant_id.clone(), events.clone()).await
        .expect("Insert failed");
    
    let results = storage.query_events(tenant_id.clone(), EventFilter::default()).await
        .expect("Query failed");
    
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].event_id, events[0].event_id);
}

#[tokio::test]
#[ignore]
async fn test_query_events_when_wrong_tenant_then_returns_empty() {
    // ... setup same as above ...
    
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    
    // Insert for tenant A
    storage.insert_events(tenant_a.clone(), vec![make_event(tenant_a.clone())]).await.unwrap();
    
    // Query as tenant B — must return NOTHING
    let results = storage.query_events(tenant_b.clone(), EventFilter::default()).await.unwrap();
    
    assert_eq!(results.len(), 0, 
        "CRITICAL: tenant isolation failure — tenant B can see tenant A data");
}
```

### The Multi-Tenancy Canary Test

This test MUST exist and MUST run in CI:

```rust
// tests/integration/security/test_tenant_isolation.rs

/// This is the most critical test in the codebase.
/// If this fails, we have a data breach.
/// This must never be deleted or disabled.
#[tokio::test]
#[ignore]
async fn test_CRITICAL_tenant_isolation_no_cross_tenant_data_leakage() {
    let storage = setup_clickhouse().await;
    
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    
    // Insert 1000 events for tenant A
    let events_a: Vec<KronEvent> = (0..1000)
        .map(|_| make_event(tenant_a.clone()))
        .collect();
    storage.insert_events(tenant_a.clone(), events_a).await.unwrap();
    
    // Attempt 20 different query patterns as tenant B
    let queries = vec![
        EventFilter::default(),
        EventFilter::all_time(),
        EventFilter { source_type: Some(EventSource::Syslog), ..Default::default() },
        // ... more patterns
    ];
    
    for query in queries {
        let results = storage.query_events(tenant_b.clone(), query).await.unwrap();
        assert_eq!(
            results.len(), 0,
            "CRITICAL SECURITY FAILURE: Cross-tenant data leak detected! \
             Query returned {} rows from tenant A while authenticated as tenant B",
            results.len()
        );
    }
}
```

---

## Performance Tests

For any function on the hot path (processes every event):

```rust
#[cfg(test)]
mod bench {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_ioc_lookup_meets_latency_target() {
        let filter = setup_bloom_filter_with_1m_iocs();
        
        let start = Instant::now();
        for _ in 0..10_000 {
            let _ = filter.check("8.8.8.8", IocType::Ip);
        }
        let elapsed = start.elapsed();
        let avg_us = elapsed.as_micros() / 10_000;
        
        assert!(
            avg_us < 1000, // 1ms = 1000 microseconds
            "IOC lookup avg {avg_us}μs exceeds 1ms target"
        );
    }
}
```

---

## Security Tests

Tests that must exist for every security-critical function:

### Authentication
```rust
// Must test: correct credentials succeed
// Must test: wrong password fails
// Must test: expired JWT fails
// Must test: wrong tenant JWT fails
// Must test: brute force lockout triggers after 5 failures
// Must test: TOTP replay attack rejected (same code used twice)
```

### Authorization
```rust
// Must test: viewer cannot execute SOAR actions
// Must test: analyst cannot access admin endpoints
// Must test: MSSP admin cannot access other MSSP's tenants
```

### Input Validation
```rust
// Must test: SQL injection in query param is rejected (not just sanitized — REJECTED)
// Must test: XSS payload in alert notes is escaped
// Must test: oversized payload is rejected with 413
// Must test: malformed JSON returns 400 not 500
```

---

## Test Data

Use builders, not inline struct initialization:

```rust
// Good:
let event = KronEvent::test_builder()
    .with_tenant(tenant_id)
    .with_source(EventSource::LinuxEbpf)
    .with_suspicious_network_connection("185.220.101.1")
    .build();

// Bad:
let event = KronEvent {
    event_id: EventId::new(),
    tenant_id,
    ts: Utc::now(),
    source_type: EventSource::LinuxEbpf,
    dst_ip: Some("185.220.101.1".parse().unwrap()),
    // ... 50 more fields ...
    ..Default::default()
};
```

`KronEvent::test_builder()` exists in `kron-types/src/testing.rs` (compiled only in test/dev).

---

## Test Coverage Targets

| Crate | Min coverage |
|---|---|
| `kron-types` | 90% |
| `kron-storage` | 85% |
| `kron-stream` (SIGMA engine) | 90% |
| `kron-auth` | 95% |
| `kron-query-api` (handlers) | 80% |
| `kron-alert` (notification logic) | 85% |
| `kron-ai` (feature extraction) | 80% |

Measure with: `cargo tarpaulin --workspace --ignore-tests`

---

## CI Test Execution

```yaml
# .github/workflows/ci.yml

- name: Unit tests
  run: cargo test --workspace --lib

- name: Integration tests (with services)
  run: |
    docker-compose -f docker-compose.test.yml up -d
    sleep 10
    cargo test --workspace -- --include-ignored integration
    docker-compose -f docker-compose.test.yml down

- name: Security tests
  run: cargo test --workspace -- security --include-ignored

- name: Coverage check
  run: |
    cargo tarpaulin --workspace --ignore-tests --fail-under 80
```

---

## What Never Gets Merged Without Tests

- New storage queries
- New API endpoints
- New detection logic
- Any authentication/authorization code
- Any cryptographic operation
- Any multi-tenancy code
- Any WhatsApp/SMS notification code

If you write code in these categories without tests, the PR will not be merged.
