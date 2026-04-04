# Standard-BuildOrder.md — KRON Standard Tier Build Plan

**Timeline:** Month 1–7  
**Goal:** 3 design partners running KRON Standard on real infrastructure  
**Output:** Shippable product. Not a demo. Not a POC.

---

## Week-by-Week Plan

### Week 1–2 — Project Setup (Phase 0)

No feature code. Infrastructure only.

**Tasks:**
```
[ ] Rust workspace initialised (Cargo.toml with all 13 crates)
[ ] rustfmt.toml, clippy.toml, deny.toml configured
[ ] CI pipeline live: test + clippy + fmt + audit on every PR
[ ] Pre-commit hooks: fmt + no-secrets scan
[ ] docker-compose.dev.yml: ClickHouse + Redpanda + MinIO + Prometheus + Grafana
[ ] scripts/dev-up.sh works in < 2 minutes
[ ] scripts/dev-health-check.sh verifies all services
[ ] All crate skeletons compile with zero warnings
[ ] GitHub repository with branch protection on main
```

**Gate:**
```bash
cargo build --workspace  # zero warnings
cargo clippy --workspace # zero warnings
./scripts/dev-up.sh && ./scripts/dev-health-check.sh  # all green
```

**Do not proceed until gate passes.**

---

### Week 3–4 — Shared Types + Storage Trait

The most important two weeks. Everything builds on this.

**`kron-types` (week 3):**
```
[ ] TenantId, EventId, AlertId newtypes (UUID wrappers)
[ ] KronEvent struct — all fields from Database.md
[ ] KronAlert struct
[ ] Severity enum (P1–P5)
[ ] EventSource enum (all source types)
[ ] EventCategory enum
[ ] AssetCriticality enum
[ ] KronError enum (top-level, thiserror)
[ ] KronConfig struct (full config tree, serde + toml)
[ ] Config validation with descriptive errors
[ ] TenantContext (request-scoped tenant_id holder)
[ ] KronEvent::test_builder() for use in tests
[ ] 100% serde roundtrip test for all types
```

**`kron-storage` trait (week 4 — interface only, no implementation):**
```
[ ] StorageEngine trait defined
[ ] StorageEngine::insert_events()
[ ] StorageEngine::query_events() with EventFilter
[ ] StorageEngine::insert_alert()
[ ] StorageEngine::query_alerts()
[ ] StorageEngine::insert_audit_log()
[ ] EventFilter struct (type-safe query params)
[ ] QueryRewriter: injects tenant_id on every query (gate 2 of isolation)
[ ] StorageError enum
[ ] AdaptiveStorage struct (selects implementation from config)
```

**Why interface before implementation:**
Writing the trait first forces you to think about what the API should look like
before you get buried in ClickHouse client details. If the trait is wrong,
fixing it before any implementation exists costs zero time.

**Gate:**
```bash
cargo test -p kron-types  # all type tests pass
cargo check -p kron-storage  # trait compiles cleanly
```

---

### Week 5–6 — ClickHouse Implementation

**`kron-storage` ClickHouse implementation:**
```
[ ] ClickHouse connection pool (deadpool-clickhouse)
[ ] Migration runner: applies migrations/ in order on startup, idempotent
[ ] Migration 001: events table DDL (exact schema from Database.md)
[ ] Migration 002: alerts table DDL
[ ] Migration 003: audit_log table DDL (Merkle chain columns)
[ ] Migration 004: assets, users tables
[ ] Migration 005: rules, tenants, kron_users tables
[ ] Migration 006: all skip indexes
[ ] Migration 007: materialized views
[ ] ClickHouseStorage::insert_events() — batch insert, idempotent (ReplacingMergeTree)
[ ] ClickHouseStorage::query_events() — parameterized, tenant_id enforced
[ ] ClickHouseStorage::insert_audit_log() — append-only, Merkle chain
[ ] ClickHouseStorage::query_alerts()
[ ] Retry logic: exponential backoff on connection failures
[ ] Circuit breaker: stops retrying after 5 consecutive failures
[ ] Prometheus metrics: query latency histogram, insert throughput
```

**Critical test — write this before any other storage test:**
```rust
// This test must exist and must pass before ANY other storage feature
#[tokio::test]
#[ignore]
async fn test_CRITICAL_cross_tenant_query_returns_zero_rows() {
    // Insert 1000 events for tenant A
    // Query as tenant B
    // Assert: 0 rows returned
    // If this fails, STOP. Fix isolation before continuing.
}
```

**Gate:**
```bash
cargo test -p kron-storage -- --include-ignored integration
# cross-tenant isolation test: MUST PASS
# insert 10K events + query: MUST complete in < 500ms p99
```

---

### Week 7–8 — Message Bus + Redpanda

**`kron-bus`:**
```
[ ] BusProducer trait, BusConsumer trait
[ ] Topic constants (kron.raw, kron.enriched, kron.alerts, kron.audit)
[ ] RedpandaProducer: rdkafka wrapper, batching, compression
[ ] RedpandaConsumer: rdkafka wrapper, offset management
[ ] At-least-once delivery: commit offset only after successful processing
[ ] Dead letter queue: failed after 3 retries → kron.deadletter
[ ] Backpressure: producer waits when consumer lag > configured threshold
[ ] AdaptiveBus: selects Redpanda or embedded based on config
[ ] Embedded channel (disk-backed async): for Nano tier (build now, used in month 8)
[ ] Bus health check endpoint
[ ] Prometheus metrics: consumer lag, throughput, error rate
```

**Gate:**
```bash
cargo test -p kron-bus -- --include-ignored integration
# Send 100K messages: all received, none lost
# Kill consumer, restart: no messages lost
# Dead letter queue receives poison messages after 3 retries
```

---

### Week 9–11 — eBPF Agent

The hardest component. Allocate 3 weeks. Do not rush this.

**`kron-agent`:**
```
[ ] AgentConfig: loads from file + CLI overrides
[ ] eBPF program: process_create (sys_enter_execve)
[ ] eBPF program: network_connect (tcp_v4_connect kprobe)
[ ] eBPF program: file_access (sys_enter_openat, sensitive paths only)
[ ] eBPF program: auth_events (sys_enter_accept for SSH patterns)
[ ] Ring buffer: 64MB default, configurable
[ ] Userspace ring buffer reader: drains to event batch
[ ] Batching: max 1000 events OR 100ms, whichever first
[ ] Event → KronEvent serialization (partial fields available from eBPF)
[ ] CO-RE: BTF-based, compiles once, runs on kernel 5.4+
[ ] Kernel version check: warn if < 5.4, suggest agentless fallback
[ ] mTLS client certificate: loaded from config
[ ] gRPC stream to kron-collector (long-lived connection)
[ ] Local disk buffer (LevelDB): activated when collector unreachable
[ ] Buffer size limit: configurable (default 1GB), drops oldest on overflow
[ ] Buffer replay: automatic drain on reconnect
[ ] Heartbeat: every 30 seconds to collector
[ ] Graceful shutdown: flushes ring buffer + disk buffer before exit
[ ] Self-metrics: ring buffer utilization %, drop rate, events/sec
[ ] Agent binary: static, stripped, < 20MB
```

**eBPF-specific testing:**
```bash
# Must test on real kernel, not container
# Ubuntu 22.04 kernel 5.15:
sudo ./target/release/kron-agent --config test-agent.toml &
sleep 5
curl https://1.1.1.1  # triggers network_connect
cat /etc/passwd       # triggers file_access
ls /tmp               # should NOT trigger (not sensitive path)
# Verify events appear in ClickHouse within 2 seconds
```

**Gate:**
```bash
./scripts/test-agent-kernels.sh
# Tests on: Ubuntu 20.04, 22.04, 24.04, RHEL 9
# Each: install agent, generate test events, verify in ClickHouse
# CPU overhead: < 1% on idle system
# Memory: < 50MB RSS
# Zero crashes after 24-hour soak test
```

---

### Week 12–13 — Collector + Syslog

**`kron-collector`:**
```
[ ] tonic gRPC server (mTLS required, rejects plaintext)
[ ] Agent cert validation: validates CN against agent registry
[ ] Agent registration: POST /agents/register (one-time token)
[ ] Agent heartbeat: POST /agents/heartbeat, marks agent active
[ ] Agent dark alert: fires P2 alert if heartbeat missing > 90s
[ ] Event routing: received events → Redpanda kron.raw.{tenant_id}
[ ] Syslog UDP receiver (RFC 3164, port 514)
[ ] Syslog TCP receiver (RFC 5424, port 514 + TLS port 6514)
[ ] HTTP intake: POST /intake/v1/events (JSON batch, for apps)
[ ] Rate limiting: per-agent, configurable (default 100K EPS)
[ ] Prometheus metrics: events/sec per source, error rate
```

**Gate:**
```bash
cargo test -p kron-collector -- --include-ignored integration
# Reject connection without valid cert: PASS
# 10K events/sec sustained 60 seconds: 0 dropped
# Agent dark: missing heartbeat 90s → P2 alert in ClickHouse
```

---

### Week 14–16 — Normalizer

**`kron-normalizer`:**
```
[ ] Pipeline orchestrator: parse → map → enrich → dedup → publish
[ ] Format detector: CEF, LEEF, JSON, syslog RFC3164, syslog RFC5424, Windows XML EventLog
[ ] CEF parser: all standard CEF extensions
[ ] LEEF parser
[ ] JSON parser: nested field path extraction
[ ] Syslog RFC 3164 parser
[ ] Syslog RFC 5424 parser
[ ] Field mapper: source-type → KRON canonical schema (config-driven, from rules/mappings/)
[ ] Mappings: linux_ebpf.yml, windows_etw.yml, syslog_generic.yml, aws_cloudtrail.yml
[ ] Timestamp parser: 15 common formats → UTC nanoseconds
[ ] GeoIP enrichment: MaxMind GeoLite2 (embedded DB, loaded once)
[ ] Asset enrichment: hostname/IP → asset record (5-min LRU cache, 10K entries)
[ ] User identity enrichment: username → canonical user (5-min LRU cache)
[ ] Dedup fingerprint: xxHash3 of (tenant_id + source + event_type + key_fields + 1s_bucket)
[ ] Dead letter: unparseable events → kron.deadletter with raw preserved
[ ] Writes enriched events to kron.enriched.{tenant_id} AND ClickHouse events table
[ ] Prometheus: parse success rate, enrichment cache hit rate, throughput
```

**Gate:**
```bash
cargo test -p kron-normalizer
# CEF parsing: 100% of CEF extension types: PASS
# Timestamp: 15 formats all parse to correct UTC: PASS
# GeoIP: known IPs return correct country: PASS
# Dedup: identical event twice in 1s → same fingerprint: PASS
# Dedup: same event at 1.1s interval → different fingerprint: PASS
# Throughput: 20K events/sec single thread: PASS
```

---

### Week 17 — End-to-End Pipeline Test (MVD Gate)

**Stop. Test the entire pipeline before building detection.**

```bash
./scripts/mvd-test.sh
# 1. Start: collector, normalizer (connected to ClickHouse + Redpanda)
# 2. Install agent on localhost
# 3. Wait 30 seconds — verify events appear in ClickHouse
# 4. Run: for i in {1..50}; do ssh invalid@localhost 2>/dev/null; done
# 5. Verify: events in ClickHouse with correct event_type, hostname, tenant_id
# 6. Verify: dedup working (50 attempts → less than 50 distinct events due to bucketing)
# 7. Cross-tenant: ZERO rows visible to wrong tenant
# MUST PASS before building detection engine
```

If MVD test fails — fix the pipeline. Do not move forward.

---

### Week 18–20 — SIGMA Rule Engine

**`kron-stream` — SIGMA subsystem:**
```
[ ] SIGMA YAML parser (full spec: all condition types, all operators)
[ ] SIGMA AST types (typed representation, not stringly-typed)
[ ] Logsource mapper: (product, category, service) → KRON source types
[ ] AST → ClickHouse SQL compiler
[ ] AST → DuckDB SQL compiler (reuse for Nano, build now)
[ ] Compiled rule struct: rule_id + compiled SQL + metadata
[ ] Rule registry: in-memory HashMap, hot-reload on file change
[ ] Rule evaluator: applies rules to event stream
[ ] FP rate estimator: runs rule against last 24h, returns match %
[ ] Rule classifier: production (<2% FP), review (2–10%), experimental (>10%)
[ ] Import 3,000+ upstream SIGMA rules from corpus
[ ] Classify all imported rules, enable only "production" by default
[ ] India detection pack: UPI fraud, Aadhaar abuse, GST scraping, 3 APT groups
[ ] Rule test CLI: kron-ctl rule test --rule-id X --event-file Y
```

**Gate:**
```bash
cargo test -p kron-stream -- sigma
# Parse all 3,000+ SIGMA rules: 0 parse errors
# Compile > 95% to valid ClickHouse SQL: PASS
# "Brute force login" rule fires on matching event: PASS
# "Brute force login" rule does NOT fire on normal login: PASS
# FP classifier assigns correct tier to 20 known rules: PASS
```

---

### Week 21–22 — IOC Filter + ONNX Inference

**`kron-stream` — IOC and ONNX subsystems:**
```
[ ] IOC bloom filter: counting bloom, false positive < 0.01% at 10M entries
[ ] IOC types: IP, domain, SHA256, URL
[ ] Feed loader: MISP community feeds, Abuse.ch MalwareBazaar, URLhaus, ThreatFox
[ ] Feed refresh: full rebuild every 5 minutes (background task)
[ ] Offline snapshot: bundled gzip for air-gap deployments
[ ] IOC lookup: < 1ms (enforced by performance test)
[ ] ONNX Runtime session management (one session per model, reused)
[ ] Model loader: loads from /var/lib/kron/models/, hash verified on load
[ ] Anomaly scorer (isolation forest ONNX): KronEvent → score 0–1
[ ] UEBA classifier (XGBoost ONNX): deviation features → probability 0–1
[ ] Beaconing detector (FFT ONNX): inter-arrival times → score 0–1
[ ] Exfil scorer (XGBoost ONNX): volume features → probability 0–1
[ ] Feature extractor: KronEvent → feature structs for each model
[ ] Inference: async, does not block event stream (spawn_blocking)
[ ] Model hot-reload: new model promoted atomically, zero dropped inferences
```

**Gate:**
```bash
cargo test -p kron-stream -- ioc onnx
# IOC: 1M entries loaded in < 10s: PASS
# IOC: lookup p99 < 1ms: PASS
# IOC: known malicious IP returns true: PASS
# IOC: known clean IP returns false: PASS
# ONNX: known anomalous event scores > 0.75: PASS
# ONNX: normal event scores < 0.3: PASS
# ONNX: 1000 inferences/sec on single CPU core: PASS
# ONNX: no NaN or Inf output: PASS
```

---

### Week 23–24 — Stream Processor (Full Pipeline)

**`kron-stream` — complete pipeline:**
```
[ ] Main consumer loop: reads from kron.enriched.{tenant_id}
[ ] Pipeline fan-out per event: IOC → SIGMA → ONNX → UEBA → score → tag
[ ] UEBA baseline: loads 30-day user baselines from ClickHouse (cached)
[ ] Entity graph: in-memory user↔host↔IP graph, updated per event
[ ] Lateral movement detection: entity graph pattern matching
[ ] Risk scorer: composite formula (rule severity + anomaly + IOC + criticality)
[ ] Severity assignment: risk score → P1–P5
[ ] MITRE tagger: rule_id → (tactic, technique, sub-technique) lookup table
[ ] Alert candidate: events above threshold published to kron-alert
[ ] Throughput: > 10K events/sec on Standard hardware (single node)
[ ] Zero events lost under load (Redpanda holds queue)
[ ] Prometheus: processing latency histogram, events/sec, alerts/sec
```

**Gate:**
```bash
./scripts/test-detection-pipeline.sh
# Inject 1000 test events (10 known attack patterns)
# Assert: all 10 attack patterns detected (0 missed)
# Assert: 0 false positives on 990 normal events
# Assert: processing latency p99 < 200ms
# Sustain 10K EPS for 10 minutes: 0 events lost
```

---

### Week 25–26 — Alert Engine + WhatsApp

**`kron-alert`:**
```
[ ] Alert consumer: reads alert candidates from stream processor
[ ] Alert assembler: builds KronAlert from candidate + evidence event IDs
[ ] Deduplication: group by (rule_id + affected_asset + 15-min window)
[ ] Grouping: multiple events for same rule+asset → one alert with event_count
[ ] Alert written to ClickHouse alerts table
[ ] Alert published to kron.alerts.{tenant_id} topic
[ ] Plain-language EN summary: rule-based template (no LLM in v1)
[ ] Hindi summary: translated template (8MB ONNX T5 model)
[ ] WhatsApp Business API: send alert, action buttons (Block/Isolate/Ignore/Escalate)
[ ] WhatsApp reply handler: parse 1/2/3/4 → trigger SOAR action
[ ] SMS fallback (Textlocal): activated when WhatsApp fails
[ ] Email fallback (SMTP): activated when SMS fails
[ ] Notification rate limiting: P3+ max 10/hour, P1/P2 always immediate
[ ] Autopilot mode: auto-executes safe actions (block IP, disable account)
[ ] Daily summary: WhatsApp digest of P3–P5 alerts
[ ] Prometheus: delivery success rate per channel, latency
```

**Gate:**
```bash
./scripts/test-alert-delivery.sh
# P1 alert: WhatsApp received within 30 seconds: PASS
# P1 alert: analyst replies "1" → IP blocked in iptables: PASS
# Dedup: 100 identical events in 15 min → 1 alert: PASS
# WhatsApp down: SMS received within 60 seconds: PASS
# Rate limit: 11 P3 alerts in 1 hour → 10 sent, 1 queued: PASS
# Hindi summary: correctly formatted: PASS (manual check)
```

---

### Week 27–28 — Auth Service

**`kron-auth`:**
```
[ ] JWT issuer (RS256, 8-hour expiry, RS private key in Vault)
[ ] JWT validator middleware for Axum
[ ] TenantContext extractor: gets tenant_id from JWT claim
[ ] Password hashing: Argon2id (memory=64MB, iterations=3, parallelism=4)
[ ] TOTP validation (totp-rs)
[ ] Login endpoint: POST /auth/login
[ ] Refresh endpoint: POST /auth/refresh
[ ] Logout: token blocklist (in-memory + persisted)
[ ] Brute force: 5 failures → 15-min lockout
[ ] RBAC: can(role, action, resource) function
[ ] Roles: viewer, analyst, responder, admin, mssp_admin
[ ] KRON logins audited: every login → audit_log
[ ] Login anomaly: KRON fires its own detection rules on login events
```

**Gate:**
```bash
cargo test -p kron-auth
# Valid credentials + TOTP: JWT issued: PASS
# Invalid password: 401: PASS
# Expired JWT: 401: PASS
# JWT tenant A: cannot access tenant B data (tested at API layer): PASS
# Brute force: 6th attempt blocked: PASS
# Viewer: SOAR endpoint returns 403: PASS
```

---

### Week 29–32 — Query API + Web UI

**`kron-query-api` (week 29–30):**
```
[ ] Axum server, TLS termination
[ ] All endpoints from API.md implemented
[ ] Query rewrite middleware (gate 2 of tenant isolation)
[ ] Input validation on all endpoints (no raw SQL passthrough ever)
[ ] Rate limiting (tower)
[ ] WebSocket: live alert stream
[ ] WebSocket: live event tail
[ ] OpenAPI spec (utoipa)
[ ] Serves SolidJS static files
[ ] Request tracing: trace_id on every request
[ ] p99 response time < 200ms (tested under load)
```

**SolidJS web UI (week 31–32):**
```
[ ] Project setup: Vite + SolidJS + TypeScript
[ ] Design system: all colours, typography from UIUX.md
[ ] API client (typed, all endpoints)
[ ] Auth flow: login + TOTP
[ ] Dashboard: 4 metric cards + alert trend + MITRE mini-heatmap
[ ] Alert queue: list, filter, severity badges, inline expand
[ ] Alert detail: narrative, evidence table, MITRE info, action buttons
[ ] Event search: NL query bar, filter sidebar, results table
[ ] MITRE ATT&CK heatmap: full matrix, colour by hit count
[ ] Settings: WhatsApp number, email, org name
[ ] Dark mode
[ ] Keyboard shortcuts: J/K/A/F/Space
[ ] Skeleton loading states (not spinners)
[ ] Error states for all failure modes
[ ] Works at 1920×1080 and 1366×768
```

**Gate:**
```bash
# Automated:
cargo test -p kron-query-api -- --include-ignored integration
# All endpoint contract tests pass
# SQL injection in query param: rejected with 400: PASS
# JWT tenant A accessing tenant B: 403: PASS
# WebSocket: alert fires → client receives < 500ms: PASS

# Manual walkthrough (human must run this):
./scripts/ui-walkthrough-checklist.sh
# Opens browser, guides through each screen
# Human marks each item pass/fail
# All items must pass
```

---

### Week 33–34 — Multi-Tenancy + MSSP

```
[ ] Tenant onboarding wizard (UI)
[ ] Tenant isolation: all 4 gates verified by automated test
[ ] Continuous canary: cross-tenant test every 5 min in production
[ ] MSSP portal: per-tenant dashboard, billing metrics
[ ] Per-tenant config: language, WhatsApp, compliance frameworks
[ ] Tenant offboarding: data purge workflow (audit trail preserved)
[ ] kron-ctl tenant-create, tenant-list, tenant-delete
```

---

### Week 35–36 — Compliance Engine

```
[ ] CERT-In module: 13 incident categories, evidence collection
[ ] DPDP Act module: personal data access trail
[ ] RBI IS audit module
[ ] SEBI CSCRF module
[ ] Compliance dashboard (web UI)
[ ] PDF report generation
[ ] Evidence package export
[ ] kron-ctl compliance report --framework cert-in --from X --to Y
```

---

### Week 37–40 — Flutter Mobile App

```
[ ] Flutter project setup (Riverpod, dio)
[ ] Auth: email/password/TOTP + biometric
[ ] Alert feed screen: P1/P2 cards, action buttons
[ ] Alert detail screen
[ ] SOAR approval screen (biometric confirmation required)
[ ] Push notifications (P1/P2 immediate)
[ ] On-call schedule screen
[ ] iOS build pipeline (App Store or TestFlight)
[ ] Android build pipeline (Play Store or direct APK)
```

---

### Week 41–44 — Hardening + Standard Gate

```
[ ] Internal penetration test
[ ] All pentest findings remediated
[ ] cargo audit: zero findings
[ ] SBOM generated and published
[ ] All runbooks written and fire-drilled
[ ] Backup/restore tested (actual RTO measured)
[ ] Load test: 50K EPS for 1 hour, 0 events lost
[ ] Query test: 1B rows in < 3 seconds
[ ] One-line installer tested: Ubuntu 20.04, 22.04, RHEL 9
[ ] 3 design partners live in production for > 30 days
```

**Standard Gate:**
```bash
./scripts/gate-standard.sh
# ALL checks pass → Standard is shippable
# 3 design partners confirm: PASS
```

---

## Standard Milestone Summary

| Milestone | Week | What it proves |
|---|---|---|
| Workspace + CI live | 2 | Can build and test |
| Types + storage trait | 4 | Architecture is sound |
| ClickHouse working | 6 | Data flows in |
| Bus working | 8 | Events route correctly |
| Agent working | 11 | Can collect from real endpoints |
| MVD gate | 17 | End-to-end pipeline proven |
| SIGMA engine | 20 | Rules fire on real attacks |
| Alert → WhatsApp | 26 | Analyst actually gets notified |
| Web UI live | 32 | Analyst can use KRON |
| 3 design partners | 44 | Real customers validate the product |
