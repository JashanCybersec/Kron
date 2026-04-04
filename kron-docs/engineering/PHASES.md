# PHASES.md — KRON Build Phases

**Current phase:** PHASE 1  
**Rule:** Do not start a task in Phase N+1 until all P0 tasks in Phase N are complete and tested.  
**Rule:** Each task has an acceptance criteria. A task is NOT done until its acceptance criteria passes.

---

## How to Use This File

- `[ ]` — not started
- `[~]` — in progress (add your name: `[~ jashan]`)
- `[x]` — complete (add date: `[x 2026-01-15]`)
- `[!]` — blocked (add reason: `[! waiting for X]`)

When you complete a task, write the completion date.
When you start a task, write your name.
Never mark a task complete without running its acceptance criteria.

---

## Phase 0 — Project Setup (Week 1–2)

These must be done before any feature work. No exceptions.

### Repository & Tooling
- [ ] Initialize Rust workspace (`Cargo.toml` with all crates defined)
- [ ] Set up `rustfmt.toml` with project formatting rules
- [ ] Set up `clippy.toml` with all lints including `unwrap_used = deny`
- [ ] Set up `cargo-deny` with approved license list and dependency policy
- [ ] Set up `cargo-audit` in CI
- [ ] Set up GitHub Actions CI pipeline (test + clippy + fmt + audit on every PR)
- [ ] Set up pre-commit hooks (fmt, clippy, no secrets scan)
- [ ] Create all crate skeletons with correct `Cargo.toml` dependencies
- [ ] Verify workspace builds cleanly with zero warnings

### Development Environment
- [ ] `docker-compose.dev.yml` with: ClickHouse, Redpanda, MinIO, Prometheus, Grafana
- [ ] `scripts/dev-up.sh` — starts dev environment in one command
- [ ] `scripts/dev-down.sh` — tears down cleanly
- [ ] `scripts/dev-reset.sh` — wipes and recreates all state
- [ ] Verify all engineers can `./scripts/dev-up.sh` and get a working environment
- [ ] ClickHouse reachable at `localhost:8123`
- [ ] Redpanda reachable at `localhost:9092`
- [ ] MinIO reachable at `localhost:9000`

**Acceptance criteria for Phase 0:**
```bash
cargo build --workspace          # must succeed, zero warnings
cargo test --workspace           # must succeed (even if no tests yet)
cargo clippy --workspace         # must succeed, zero warnings
./scripts/dev-up.sh && sleep 10 && ./scripts/dev-health-check.sh  # all services healthy
```

---

## Phase 1 — Foundation (Month 1–3)

Goal: Events flow from a Linux endpoint into ClickHouse and are queryable via CLI.
No UI. No alerts. No AI. Just reliable data pipeline.

### 1.1 Shared Types (`kron-types`)

**Priority: P0 — nothing else can start without this**

- [ ] `TenantId` newtype (UUID wrapper with Display, Serialize, Deserialize)
- [ ] `EventId` newtype (UUID wrapper)
- [ ] `AlertId` newtype (UUID wrapper)
- [ ] `KronEvent` struct — all 60+ fields from Database.md schema
- [ ] `EventSource` enum — all source types
- [ ] `EventCategory` enum
- [ ] `Severity` enum (P1–P5 and info/low/medium/high/critical)
- [ ] `AssetCriticality` enum
- [ ] `KronError` enum — top-level error type using thiserror
- [ ] `KronConfig` struct — full configuration (all services)
- [ ] Config loading from TOML file + environment variable overrides
- [ ] Config validation (returns detailed errors on invalid config)
- [ ] `TenantContext` struct (holds tenant_id for request-scoped operations)

**Acceptance criteria:**
```rust
// These must compile and pass:
let event = KronEvent::builder()
    .tenant_id(TenantId::new())
    .source_type(EventSource::LinuxEbpf)
    .event_type("process_create")
    .ts(Utc::now())
    .build()?;

let json = serde_json::to_string(&event)?;
let back: KronEvent = serde_json::from_str(&json)?;
assert_eq!(event.event_id, back.event_id);
```

### 1.2 Storage Layer (`kron-storage`)

- [ ] `StorageEngine` trait — abstracts DuckDB and ClickHouse behind same interface
- [ ] `StorageEngine::insert_events(tenant_id, events)` 
- [ ] `StorageEngine::query_events(tenant_id, filter)` 
- [ ] `StorageEngine::insert_audit_log(tenant_id, entry)`
- [ ] DuckDB implementation of `StorageEngine`
- [ ] ClickHouse implementation of `StorageEngine`
- [ ] `AdaptiveStorage::new(config)` — selects DuckDB or ClickHouse based on config/mode
- [ ] All migrations in `migrations/` applied on startup (idempotent)
- [ ] `tenant_id` enforced on every query — middleware layer in storage, not caller
- [ ] Connection pooling (ClickHouse: `deadpool`, DuckDB: single connection with mutex)
- [ ] Retry logic with exponential backoff on transient failures
- [ ] Circuit breaker on storage failures (stops hammering a down DB)
- [ ] Prometheus metrics: query latency histogram, insert throughput, error count

**Acceptance criteria:**
```bash
# Integration test (requires running ClickHouse):
cargo test -p kron-storage -- --include-ignored integration
# Must:
# - Insert 10,000 events for tenant A
# - Insert 10,000 events for tenant B
# - Query tenant A events — returns exactly 10,000
# - Query tenant B events — returns exactly 10,000
# - Cross-tenant query (raw SQL injected) — must be BLOCKED by storage layer
# - Insert latency p99 < 50ms for batch of 100
# - Query latency p99 < 500ms for 1M rows
```

### 1.3 Message Bus (`kron-bus`)

- [ ] `BusProducer` trait with `send(topic, key, payload)` and `send_batch()`
- [ ] `BusConsumer` trait with `subscribe(topic, group)` and `poll()`
- [ ] `EmbeddedBusProducer` — disk-backed async channel (Nano tier)
- [ ] `EmbeddedBusConsumer` — reads from embedded channel
- [ ] `RedpandaProducer` — wraps rdkafka, Standard/Enterprise
- [ ] `RedpandaConsumer` — wraps rdkafka, Standard/Enterprise
- [ ] `AdaptiveBus::new(config)` — selects embedded or Redpanda
- [ ] Topics: `kron.raw.{tenant_id}`, `kron.enriched.{tenant_id}`, `kron.alerts.{tenant_id}`, `kron.audit`
- [ ] At-least-once delivery guaranteed (consumer commits offset only after successful processing)
- [ ] Dead letter queue for poison messages (failed after 3 retries)
- [ ] Backpressure: producer blocks/retries when consumer lag exceeds threshold
- [ ] Prometheus metrics: consumer lag, throughput, error rate

**Acceptance criteria:**
```bash
cargo test -p kron-bus -- --include-ignored integration
# Must:
# - Send 100,000 messages, all received in order
# - Kill consumer mid-stream, restart — no messages lost
# - Verify dead letter queue receives poison messages after 3 retries
```

### 1.4 eBPF Agent (`kron-agent`)

- [ ] `AgentConfig` loaded from config file + CLI flags
- [ ] eBPF program: `process_create` hook (`sys_enter_execve`)
- [ ] eBPF program: `network_connect` hook (`tcp_v4_connect`)
- [ ] eBPF program: `file_access` hook (`sys_enter_openat` for sensitive paths)
- [ ] Ring buffer: shared memory between kernel and userspace, 64MB default
- [ ] Userspace reader: drains ring buffer, batches events (max 1000 or 100ms)
- [ ] Event serialization to `KronEvent` (partial — fields available from eBPF)
- [ ] mTLS client certificate — loaded from config, used for all connections to collector
- [ ] Heartbeat: sends heartbeat to collector every 30s
- [ ] Local disk buffer: if collector unreachable, buffers to disk (LevelDB, max 1GB)
- [ ] Buffer replay: drains disk buffer when collector reconnects
- [ ] Graceful shutdown: flushes ring buffer and disk buffer before exit
- [ ] CO-RE: uses BTF for kernel version portability
- [ ] Kernel version check on startup: warns if <5.4, falls back to agentless recommendation
- [ ] Agent self-monitoring: metrics on ring buffer utilization, drop rate

**Acceptance criteria:**
```bash
# Run on Ubuntu 22.04 with kernel 5.15:
sudo ./kron-agent --config agent.toml &
# Then in another terminal:
curl https://example.com  # triggers network_connect
ls /etc/passwd            # triggers file_access
# Verify in ClickHouse:
clickhouse-client -q "SELECT count() FROM events WHERE event_type IN ('network_connect','file_access') AND hostname = '$(hostname)'"
# Must return > 0 within 2 seconds
# Must return 0 results for a different tenant_id
```

### 1.5 Collector (`kron-collector`)

- [ ] gRPC server: accepts event batches from agents (mTLS required)
- [ ] Agent authentication: validates client cert against agent registry
- [ ] Syslog UDP receiver (RFC 3164 + RFC 5424)
- [ ] Syslog TCP receiver (with TLS)
- [ ] HTTP intake endpoint: `POST /intake/v1/events` (JSON batch)
- [ ] Agent registration endpoint: `POST /agents/register`
- [ ] Agent heartbeat endpoint: `POST /agents/heartbeat`
- [ ] Publishes received events to bus topic `kron.raw.{tenant_id}`
- [ ] Rate limiting per agent (configurable, default 100K EPS per agent)
- [ ] Prometheus metrics: events received/sec per source, error rate

**Acceptance criteria:**
```bash
cargo test -p kron-collector -- --include-ignored integration
# Must:
# - Reject connection without valid client cert
# - Accept connection with valid cert, extract tenant_id from cert CN
# - Receive 10,000 events/sec sustained for 60 seconds without dropping
# - Heartbeat timeout: agent marked "dark" after 90s of no heartbeat
```

### 1.6 Normalizer (`kron-normalizer`)

- [ ] Consumes from `kron.raw.{tenant_id}` 
- [ ] Format detection: CEF, LEEF, JSON, syslog RFC3164/5424
- [ ] Field extraction: path-based for JSON, regex for text formats
- [ ] Schema mapping: every source type has a mapping config in `rules/mappings/`
- [ ] Timestamp parsing: handles 15+ common formats, always outputs UTC nanoseconds
- [ ] GeoIP enrichment: MaxMind GeoLite2 (embedded DB file)
- [ ] Asset enrichment: hostname → asset record lookup (with 5-min cache)
- [ ] Dedup fingerprinting: xxHash of canonical fields
- [ ] Publishes normalized events to `kron.enriched.{tenant_id}`
- [ ] Publishes normalized events to ClickHouse `events` table
- [ ] Dead letter: unparseable events go to DLQ with raw content preserved
- [ ] Prometheus metrics: parse success/failure rate, enrichment cache hit rate

**Acceptance criteria:**
```bash
cargo test -p kron-normalizer
# Unit tests must cover:
# - CEF parsing with all standard field types
# - RFC 3164 syslog parsing
# - RFC 5424 syslog parsing
# - JSON with nested fields
# - 10 different timestamp formats
# - GeoIP lookup returns correct country for known IPs
# - Dedup: identical events within 1s window produce same fingerprint
```

### 1.7 CLI Tool (`kron-ctl`)

- [ ] `kron-ctl health` — check all services
- [ ] `kron-ctl events query --tenant X --from Y --to Z --limit N` — query events
- [ ] `kron-ctl events tail --tenant X` — live tail events
- [ ] `kron-ctl agents list` — show registered agents and status
- [ ] `kron-ctl agent-token create` — generate agent registration token
- [ ] `kron-ctl storage stats` — ClickHouse storage usage
- [ ] `kron-ctl migration run` — apply pending migrations
- [ ] `kron-ctl migration status` — show migration state

**Acceptance criteria:**
```bash
kron-ctl health
# Output: all services green or specific failure details

kron-ctl events query --tenant default --from "1 hour ago" --limit 10
# Output: formatted table of 10 most recent events
```

### Phase 1 Gate — Must Pass Before Phase 2

```bash
# Full end-to-end test:
./scripts/phase1-acceptance.sh

# This script:
# 1. Starts dev environment
# 2. Starts kron-collector and kron-normalizer
# 3. Installs kron-agent on localhost
# 4. Waits 60 seconds
# 5. Runs curl commands and ls commands to generate events
# 6. Queries ClickHouse directly
# 7. Asserts > 100 events in ClickHouse for default tenant
# 8. Asserts 0 events visible for wrong tenant
# 9. Asserts dedup working (same event not duplicated)
# 10. Reports PASS or FAIL with details

# Must PASS before Phase 2 starts.
```

---

## Phase 2 — Detection Engine (Month 3–5)

Goal: SIGMA rules fire on events. IOC matches detected. Risk scores computed. Alerts written to ClickHouse.

### 2.1 SIGMA Rule Engine

- [ ] SIGMA YAML parser: all condition operators
- [ ] SIGMA AST: typed representation of all SIGMA constructs
- [ ] AST → DuckDB SQL compiler
- [ ] AST → ClickHouse SQL compiler  
- [ ] Rule loader: reads from `rules/` directory, hot-reloads on file change
- [ ] Rule registry: in-memory map of rule_id → compiled rule
- [ ] Rule evaluator: applies compiled rules to event stream
- [ ] Rule test harness: test any rule against a sample event JSON
- [ ] False-positive rate estimator: runs rule against last 24h, returns match rate
- [ ] Import 3,000+ upstream SIGMA rules from corpus
- [ ] Classify each rule: `production` (<2% FP), `review` (2–10%), `experimental` (>10%)

**Acceptance criteria:**
```bash
cargo test -p kron-stream -- sigma
# Must:
# - Parse all 3,000+ SIGMA rules without error
# - Compile > 95% to valid ClickHouse SQL
# - Test rule: "Failed login from new country" fires on matching event
# - Test rule: does NOT fire on non-matching event
# - FP classifier assigns correct category to 10 known rules
```

### 2.2 IOC Bloom Filter

- [ ] Bloom filter struct: counting bloom, allows deletion
- [ ] IOC types: IP, domain, SHA256, URL
- [ ] Feed loader: MISP community, Abuse.ch MalwareBazaar, Abuse.ch URLhaus
- [ ] Feed parser for each source format
- [ ] Refresh scheduler: rebuild filter every 5 minutes from latest feeds
- [ ] Lookup function: `check_ioc(value: &str, ioc_type: IocType) -> bool` — must be <1ms
- [ ] Offline snapshot: feeds bundled as gzipped file for air-gap deployments
- [ ] Prometheus metrics: filter size, lookup latency, hit rate

**Acceptance criteria:**
```bash
cargo test -p kron-stream -- ioc
# Must:
# - Load 1 million IOCs in <10 seconds
# - Lookup latency p99 < 1ms
# - False positive rate < 0.01% (verified against test set)
# - Known malicious IP returns true
# - Known clean IP returns false
# - Memory usage < 200MB for 10M IOCs
```

### 2.3 ONNX Inference Engine

- [ ] ONNX Runtime session management (one session per model, reused)
- [ ] Model loader: loads from `/var/lib/kron/models/` with hash verification
- [ ] `AnomalyScorer::score(features: AnomalyFeatures) -> f32`
- [ ] `UebaClassifier::classify(features: UebaFeatures) -> f32`
- [ ] `BeaconingDetector::detect(inter_arrival_times: &[f32]) -> f32`
- [ ] `ExfilScorer::score(features: ExfilFeatures) -> f32`
- [ ] Feature extractor: `KronEvent` → feature structs for each model
- [ ] Inference called async (does not block event stream)
- [ ] Model hot-reload: new model loads in background, promoted atomically
- [ ] Inference latency target: <5ms per event on CPU

**Acceptance criteria:**
```bash
cargo test -p kron-ai -- inference
# Must:
# - Load all 4 ONNX models without error
# - Score 1,000 events/second on single CPU core
# - Anomaly scorer: known anomalous event scores > 0.75
# - Anomaly scorer: normal event scores < 0.3
# - No model produces NaN or Inf output
# - Model hot-reload completes without dropping any inference requests
```

### 2.4 Stream Processor (`kron-stream`)

- [ ] Consumes from `kron.enriched.{tenant_id}`
- [ ] Pipeline (in order, per event):
  - IOC bloom filter check
  - SIGMA rule evaluation
  - ONNX anomaly scoring
  - UEBA deviation computation
  - Entity graph update
  - Risk score computation
  - MITRE ATT&CK tagging
- [ ] Risk scorer: formula from `docs/Features.md` section F-007
- [ ] MITRE tagger: rule_id → (tactic, technique, sub-technique) mapping table
- [ ] Entity graph: in-memory graph (user ↔ host ↔ IP), updated per event
- [ ] If risk_score > threshold: publish to alert engine topic
- [ ] Processes > 10,000 events/sec on single Standard-tier server
- [ ] Prometheus metrics: processing latency, events/sec, alerts fired/sec

**Acceptance criteria:**
```bash
./scripts/phase2-acceptance.sh
# End-to-end: inject 1,000 test events (including known attack patterns)
# Must:
# - Fire alert on "failed login from new country" pattern
# - Fire alert on IOC-matched IP
# - NOT fire alert on normal login event
# - Processing latency p99 < 200ms from event ingestion to alert
# - 0 events lost under 10,000 EPS sustained load for 5 minutes
```

### 2.5 Alert Engine (`kron-alert`)

- [ ] Consumes alert-candidate events from stream processor
- [ ] Deduplication: group by (rule_id + affected_asset + 15-min window)
- [ ] Alert assembler: builds full `KronAlert` struct
- [ ] Writes alerts to ClickHouse `alerts` table
- [ ] Publishes to `kron.alerts.{tenant_id}` topic
- [ ] WhatsApp notification (Twilio + Meta API)
- [ ] SMS notification (Textlocal)
- [ ] Email notification (SMTP)
- [ ] Fallback chain: WhatsApp → SMS → Email
- [ ] Plain-language EN summary (rule-based template, no LLM in Phase 2)
- [ ] Hindi summary (rule-based template translation)
- [ ] Notification rate limiting: max 10 WhatsApp/hour for P3+, P1/P2 always immediate

**Acceptance criteria:**
```bash
cargo test -p kron-alert -- --include-ignored integration
# Must:
# - P1 alert: WhatsApp sent within 30 seconds of alert creation
# - Dedup: 100 identical events in 15 min → 1 alert, not 100
# - Group: 5 variants of same attack on same host → 1 alert with 5 evidence events
# - Fallback: with WhatsApp unavailable, SMS sent within 60 seconds
# - Rate limit: P3 alert 11 in 1 hour → 10 WhatsApp + 1 queued for next hour
```

### Phase 2 Gate

```bash
./scripts/phase2-acceptance.sh
# Runs full end-to-end attack simulation
# Attack 1: brute force login → P1 alert on WhatsApp within 60 seconds
# Attack 2: known C2 IP connection → IOC hit → P2 alert
# Attack 3: normal activity → 0 alerts
# All must PASS
```

---

## Phase 3 — Web UI + Query API (Month 5–7)

Goal: Analyst can log in, see alerts, search events, query in plain English.

### 3.1 Auth Service (`kron-auth`)

- [ ] JWT issuance (RS256, 8-hour expiry)
- [ ] JWT validation middleware for Axum
- [ ] `TenantContext` extraction from JWT (injected into every handler)
- [ ] Password hashing (Argon2id)
- [ ] TOTP validation (totp-rs crate)
- [ ] Login endpoint: `POST /auth/login`
- [ ] Refresh endpoint: `POST /auth/refresh`
- [ ] Logout endpoint (token invalidation via blocklist in Redis/memory)
- [ ] Brute-force protection: 5 failures → 15-min lockout
- [ ] RBAC: `can(role, action, resource)` function used in all handlers
- [ ] Login anomaly detection: KRON fires on its own login events

**Acceptance criteria:**
```bash
cargo test -p kron-auth
# Must:
# - Valid credentials + TOTP → JWT issued
# - Invalid password → 401
# - Valid JWT → tenant_id extracted correctly
# - Expired JWT → 401
# - Brute force: 6th attempt blocked for 15 minutes
# - Cross-tenant: JWT for tenant A cannot access tenant B data
```

### 3.2 Query API (`kron-query-api`)

- [ ] Axum HTTP server
- [ ] All endpoints from `docs/API.md`
- [ ] Query rewrite middleware: injects `tenant_id` on every storage query
- [ ] Input validation on all endpoints (no raw SQL from request body ever executes directly)
- [ ] Rate limiting (tower middleware)
- [ ] WebSocket handler for live alert stream
- [ ] WebSocket handler for live event tail
- [ ] OpenAPI spec auto-generated (utoipa)
- [ ] Serves SolidJS static files from embedded assets
- [ ] Request tracing: every request gets a trace_id
- [ ] Response time target: p99 < 200ms for read endpoints

**Acceptance criteria:**
```bash
cargo test -p kron-query-api -- --include-ignored integration
# Must pass all API contract tests (one test per endpoint)
# SQL injection attempt in query param → 400, no DB query executed
# JWT for tenant A, query for tenant B data → 403
# WebSocket: alert fires → client receives within 500ms
```

### 3.3 SolidJS Web UI

- [ ] Project scaffolded with Vite + SolidJS + TypeScript
- [ ] Design system implemented: colours, typography, spacing (from UIUX.md)
- [ ] API client (`/web/src/api/client.ts`) — all endpoints typed
- [ ] Auth flow: login, TOTP, redirect to dashboard
- [ ] Dashboard: 4 metric cards, alert trend chart, MITRE mini-heatmap
- [ ] Alert queue: list, filter, severity badges, inline expand
- [ ] Alert detail panel: narrative, evidence table, MITRE info, action buttons
- [ ] Event search: NL query bar, filter sidebar, results table
- [ ] MITRE ATT&CK heatmap: full matrix, colour by hit count
- [ ] No-code rule builder: Phase 3 basic version (filter + threshold only)
- [ ] Settings: org name, WhatsApp number, notifications
- [ ] Error states: network error, query timeout, empty results
- [ ] Loading states: skeleton screens (not spinners)
- [ ] Dark mode
- [ ] Keyboard shortcuts for alert queue (J/K/A/F/Space)

**Acceptance criteria:**
```
Manual walkthrough checklist (run by human):
[ ] Can log in with valid credentials
[ ] Dashboard loads in < 2 seconds
[ ] Alert queue shows P1 alert at top
[ ] Clicking alert shows narrative and evidence
[ ] "Block IP" button triggers confirmation → executes (in test mode)
[ ] Event search: "failed logins last hour" returns results
[ ] MITRE heatmap: clicking cell filters alert queue
[ ] Dark mode toggle works
[ ] Keyboard: J moves to next alert, A acknowledges
[ ] Works correctly at 1920×1080 and 1366×768
```

### Phase 3 Gate

```bash
./scripts/phase3-acceptance.sh
# Full demo flow:
# 1. Log in to web UI
# 2. Trigger attack simulation
# 3. Alert appears in queue within 60 seconds
# 4. Analyst searches for related events
# 5. Alert acknowledged and resolved
# 6. All actions visible in audit log
# Must PASS before Phase 4
```

---

## Phase 4 — MSSP + Compliance + Mobile (Month 7–9)

### 4.1 Multi-Tenancy Hardening
- [ ] 4-gate isolation fully implemented and tested
- [ ] Continuous canary test deployed (runs every 5 min in production)
- [ ] Tenant onboarding wizard (UI)
- [ ] Tenant offboarding (data purge, audit trail preserved)
- [ ] MSSP portal: per-tenant dashboard, billing metrics
- [ ] Per-tenant config: WhatsApp number, language, compliance frameworks

### 4.2 Compliance Engine
- [ ] CERT-In module: all 13 incident categories mapped
- [ ] DPDP Act module: personal data access trail
- [ ] RBI IS audit module
- [ ] SEBI CSCRF module
- [ ] Compliance dashboard UI
- [ ] PDF report generation (weasyprint or similar)
- [ ] Evidence package export

### 4.3 Flutter Mobile App
- [ ] Project scaffolded (Flutter 3.x, Riverpod)
- [ ] Auth: email/password/TOTP + biometric
- [ ] Alert feed screen
- [ ] Alert detail screen
- [ ] SOAR approval screen (with biometric confirmation)
- [ ] Push notifications (P1/P2 immediate)
- [ ] On-call schedule screen
- [ ] iOS + Android build pipelines

### Phase 4 Gate
- All 4 isolation gates pass automated test
- CERT-In report generated correctly for test scenario
- Mobile app installs and receives P1 alert push notification within 60 seconds

---

## Phase 5 — Hardening + Launch (Month 9–12)

### 5.1 Security Hardening
- [ ] Internal penetration test
- [ ] All findings remediated
- [ ] `cargo audit` clean
- [ ] SBOM generated
- [ ] Release artifacts signed

### 5.2 Operational Readiness
- [ ] All runbooks written and fire-drilled (RB-001 through RB-006)
- [ ] Prometheus alerts tuned (no false positive meta-alerts)
- [ ] Backup and restore tested (RTO verified)
- [ ] USB installer tested on 3 different hardware configurations
- [ ] One-line installer tested on Ubuntu 20.04, 22.04, RHEL 9

### 5.3 SOC 2 Type I
- [ ] Vanta/Drata connected and collecting evidence
- [ ] All required controls documented
- [ ] Type I audit scheduled

### 5.4 Performance Validation
- [ ] Load test: 50,000 EPS sustained for 1 hour — 0 events lost
- [ ] Query test: 1B row query completes in <3 seconds
- [ ] Alert latency: source → WhatsApp notification p99 < 2 minutes

### 5.5 Launch Readiness
- [ ] kron.security website live
- [ ] Pricing page live
- [ ] Documentation site live (generated from /docs)
- [ ] 3 design partners actively using KRON in production
- [ ] Sales deck ready
- [ ] Support process defined

### Phase 5 Gate = v1.0 GA
All above complete. 3 design partners signed. No P0/P1 bugs open.

---

## Milestone Summary

| Milestone | Target | Gate |
|---|---|---|
| Phase 0 complete | Week 2 | Workspace builds, dev env works |
| Phase 1 complete | Month 3 | Events flow end-to-end |
| Phase 2 complete | Month 5 | Attacks detected, alerts fired |
| Phase 3 complete | Month 7 | Analysts can use the UI |
| Phase 4 complete | Month 9 | MSSP + compliance + mobile |
| Phase 5 complete | Month 12 | v1.0 GA |
