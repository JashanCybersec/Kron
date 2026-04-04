# CodeStructure.md — KRON Code Organization

**Purpose:** Exact file layout, module responsibilities, and what goes where.
If you are unsure where to put something, this file answers it.
If something is not in this file, ask before creating a new module.

---

## Workspace Root

```
kron/
├── Cargo.toml              ← workspace manifest, lists all crates
├── Cargo.lock              ← committed (binary project)
├── rustfmt.toml            ← formatting rules
├── .cargo/
│   └── config.toml         ← build targets, linker config
├── clippy.toml             ← lint configuration
├── deny.toml               ← cargo-deny: licenses + banned crates
├── .github/
│   └── workflows/
│       ├── ci.yml          ← PR checks: test, clippy, fmt, audit
│       └── release.yml     ← release builds and signing
├── CLAUDE.md               ← Claude instructions (THIS MATTERS)
├── PHASES.md               ← build phase checklist
├── DECISIONS.md            ← architectural decisions
├── CONTEXT.md              ← session log
├── CodeStructure.md        ← you are here
├── TestingGuide.md         ← how to write tests
├── docs/                   ← product documentation
├── crates/                 ← Rust workspace members
├── web/                    ← SolidJS frontend
├── mobile/                 ← Flutter app
├── deploy/                 ← deployment configs
├── migrations/             ← SQL migrations
├── models/                 ← ONNX model files
├── rules/                  ← SIGMA detection rules
├── tests/                  ← integration + e2e tests
└── scripts/                ← build and ops scripts
```

---

## Rust Workspace (`crates/`)

### Dependency Graph (arrow = depends on)

```
kron-types (no dependencies on other kron crates)
    ↑
    ├── kron-storage
    ├── kron-bus
    ├── kron-auth
    └── kron-ai
         ↑
         ├── kron-agent
         ├── kron-collector
         ├── kron-normalizer
         ├── kron-stream
         ├── kron-alert
         ├── kron-soar
         ├── kron-compliance
         └── kron-query-api
```

**Rule:** No circular dependencies. `kron-types` depends on nothing internal.
`kron-query-api` can depend on everything. Nothing depends on `kron-query-api`.

---

### `crates/kron-types/`

Shared types used by all other crates. Zero internal dependencies.

```
kron-types/
├── Cargo.toml
└── src/
    ├── lib.rs              ← re-exports everything
    ├── ids.rs              ← TenantId, EventId, AlertId, RuleId, etc. (newtype wrappers)
    ├── event.rs            ← KronEvent struct (canonical event schema)
    ├── alert.rs            ← KronAlert struct
    ├── rule.rs             ← KronRule struct
    ├── asset.rs            ← KronAsset struct
    ├── user.rs             ← KronUser struct (monitored user, not KRON user)
    ├── tenant.rs           ← Tenant struct
    ├── config.rs           ← KronConfig (full config tree)
    ├── error.rs            ← KronError enum (top-level)
    ├── enums.rs            ← Severity, EventSource, EventCategory, AssetCriticality, etc.
    └── context.rs          ← TenantContext (request-scoped)
```

**What belongs here:** Structs and enums that are shared between 2+ crates.
**What does NOT belong here:** Business logic, database queries, HTTP handlers.

---

### `crates/kron-storage/`

Abstracts ClickHouse and DuckDB behind a single trait.

```
kron-storage/
├── Cargo.toml
└── src/
    ├── lib.rs              ← exports StorageEngine trait + AdaptiveStorage
    ├── traits.rs           ← StorageEngine trait definition
    ├── adaptive.rs         ← AdaptiveStorage::new() — picks implementation
    ├── clickhouse/
    │   ├── mod.rs
    │   ├── client.rs       ← ClickHouse connection pool
    │   ├── events.rs       ← events table operations
    │   ├── alerts.rs       ← alerts table operations
    │   ├── audit.rs        ← audit_log table operations
    │   ├── assets.rs       ← assets table operations
    │   ├── rules.rs        ← rules table operations
    │   └── migrations.rs   ← applies SQL migrations on startup
    ├── duckdb/
    │   ├── mod.rs
    │   ├── client.rs       ← DuckDB connection (single + mutex)
    │   ├── events.rs
    │   ├── alerts.rs
    │   ├── audit.rs
    │   └── migrations.rs
    ├── query/
    │   ├── mod.rs
    │   ├── filter.rs       ← EventFilter struct (type-safe query builder)
    │   ├── builder.rs      ← builds parameterized SQL from EventFilter
    │   └── rewrite.rs      ← injects tenant_id (this is gate 2 of isolation)
    └── parquet/
        ├── mod.rs
        ├── export.rs       ← ClickHouse/DuckDB → Parquet
        └── import.rs       ← Parquet → ClickHouse/DuckDB (for restore)
```

**Strict rule:** All SQL strings live in this crate. Zero SQL in any other crate.
`query/rewrite.rs` injects `tenant_id` on EVERY query. This is non-negotiable.

---

### `crates/kron-bus/`

Message bus abstraction.

```
kron-bus/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── traits.rs           ← BusProducer, BusConsumer traits
    ├── topics.rs           ← Topic enum + topic name constants
    ├── adaptive.rs         ← AdaptiveBus::new() — picks implementation
    ├── embedded/
    │   ├── mod.rs
    │   ├── channel.rs      ← async disk-backed channel
    │   └── storage.rs      ← LevelDB persistence for Nano tier
    └── redpanda/
        ├── mod.rs
        ├── producer.rs     ← rdkafka producer wrapper
        └── consumer.rs     ← rdkafka consumer wrapper + offset management
```

---

### `crates/kron-agent/`

eBPF collection agent. Deployed on monitored endpoints.

```
kron-agent/
├── Cargo.toml
└── src/
    ├── main.rs             ← CLI entry point, loads config, starts tasks
    ├── config.rs           ← AgentConfig (separate from KronConfig)
    ├── ebpf/
    │   ├── mod.rs
    │   ├── loader.rs       ← loads eBPF programs, attaches to hooks
    │   ├── ringbuf.rs      ← ring buffer reader (kernel → userspace)
    │   └── programs/       ← eBPF program source (.bpf.rs files)
    │       ├── process.bpf.rs
    │       ├── network.bpf.rs
    │       └── file.bpf.rs
    ├── etw/                ← Windows ETW collector (compiled on Windows only)
    │   └── mod.rs
    ├── sender/
    │   ├── mod.rs
    │   ├── grpc.rs         ← gRPC stream to kron-collector
    │   └── buffer.rs       ← local disk buffer when collector unreachable
    ├── heartbeat.rs        ← sends heartbeat every 30s
    └── metrics.rs          ← Prometheus metrics for agent itself
```

---

### `crates/kron-collector/`

Receives events from agents and external sources.

```
kron-collector/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── config.rs
    ├── grpc/
    │   ├── mod.rs
    │   ├── server.rs       ← tonic gRPC server
    │   └── auth.rs         ← client cert validation
    ├── syslog/
    │   ├── mod.rs
    │   ├── udp.rs          ← RFC 3164 UDP receiver
    │   └── tcp.rs          ← RFC 5424 TCP/TLS receiver
    ├── http/
    │   ├── mod.rs
    │   └── intake.rs       ← POST /intake/v1/events
    ├── cloud/              ← Phase 2
    │   ├── mod.rs
    │   ├── aws.rs
    │   └── gcp.rs
    ├── ot/                 ← Phase 2
    │   └── mod.rs
    ├── router.rs           ← routes received events to bus topic
    └── registry.rs         ← agent registry (registered agents + heartbeat tracking)
```

---

### `crates/kron-normalizer/`

Parses and enriches raw events.

```
kron-normalizer/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── config.rs
    ├── pipeline.rs         ← orchestrates the normalization steps
    ├── parser/
    │   ├── mod.rs
    │   ├── cef.rs
    │   ├── leef.rs
    │   ├── json.rs
    │   ├── syslog.rs
    │   └── detector.rs     ← detects format of raw event
    ├── mapper/
    │   ├── mod.rs
    │   └── loader.rs       ← loads field mapping configs from rules/mappings/
    ├── enrichment/
    │   ├── mod.rs
    │   ├── geoip.rs        ← MaxMind GeoLite2 lookup
    │   ├── asset.rs        ← hostname → asset record
    │   ├── user.rs         ← username → canonical user (AD/LDAP)
    │   └── timestamp.rs    ← timestamp normalization to UTC nanoseconds
    ├── dedup.rs            ← xxHash fingerprinting
    └── schema.rs           ← KRON canonical schema validation
```

---

### `crates/kron-stream/`

Detection engine — applies rules, scores, tags.

```
kron-stream/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── config.rs
    ├── pipeline.rs         ← fan-out pipeline: IOC → SIGMA → ONNX → score
    ├── sigma/
    │   ├── mod.rs
    │   ├── parser.rs       ← SIGMA YAML → AST
    │   ├── ast.rs          ← SIGMA AST types
    │   ├── compiler/
    │   │   ├── mod.rs
    │   │   ├── clickhouse.rs   ← AST → ClickHouse SQL
    │   │   └── duckdb.rs       ← AST → DuckDB SQL
    │   ├── evaluator.rs    ← applies compiled rules to events
    │   └── registry.rs     ← in-memory rule registry + hot-reload
    ├── ioc/
    │   ├── mod.rs
    │   ├── bloom.rs        ← counting bloom filter
    │   └── feeds.rs        ← feed loader + refresh scheduler
    ├── scoring/
    │   ├── mod.rs
    │   └── risk.rs         ← composite risk score formula
    ├── mitre/
    │   ├── mod.rs
    │   └── tagger.rs       ← rule → (tactic, technique) mapping
    ├── ueba/
    │   ├── mod.rs
    │   └── baseline.rs     ← computes deviation from user baseline
    └── graph/
        ├── mod.rs
        └── entity.rs       ← entity graph (user ↔ host ↔ IP)
```

---

### `crates/kron-ai/`

ONNX inference + Mistral integration.

```
kron-ai/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── config.rs
    ├── onnx/
    │   ├── mod.rs
    │   ├── session.rs      ← ONNX Runtime session management
    │   ├── models/
    │   │   ├── anomaly.rs      ← IsolationForest wrapper
    │   │   ├── ueba.rs         ← XGBoost UEBA wrapper
    │   │   ├── beacon.rs       ← beaconing detector wrapper
    │   │   └── exfil.rs        ← exfil scorer wrapper
    │   ├── features.rs     ← KronEvent → feature structs
    │   └── registry.rs     ← model registry + hot-reload
    ├── mistral/
    │   ├── mod.rs
    │   ├── cpu.rs          ← llama.cpp backend (Standard)
    │   ├── gpu.rs          ← candle CUDA backend (Enterprise)
    │   └── prompts.rs      ← all Mistral prompt templates
    └── language/
        ├── mod.rs
        └── summarizer.rs   ← multilingual alert summarizer (T5 ONNX)
```

**Critical:** `kron-ai` must have a test that verifies zero outbound HTTP calls during inference. See ADR-014.

---

### `crates/kron-alert/`

Alert assembly, deduplication, notification.

```
kron-alert/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── config.rs
    ├── assembler.rs        ← builds KronAlert from raw alert candidate
    ├── dedup.rs            ← groups alerts by (rule + asset + 15min window)
    ├── narrative.rs        ← calls kron-ai for plain language summary
    ├── notifications/
    │   ├── mod.rs
    │   ├── whatsapp.rs     ← WhatsApp Business API
    │   ├── sms.rs          ← Textlocal SMS
    │   ├── email.rs        ← SMTP
    │   └── router.rs       ← fallback chain: WA → SMS → Email
    └── autopilot.rs        ← autonomous response for zero-staff orgs
```

---

### `crates/kron-auth/`

Authentication and authorization.

```
kron-auth/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── jwt/
    │   ├── mod.rs
    │   ├── issuer.rs       ← JWT creation (RS256)
    │   ├── validator.rs    ← JWT validation + claims extraction
    │   └── middleware.rs   ← Axum middleware for JWT validation
    ├── rbac.rs             ← can(role, action, resource) function
    ├── mfa.rs              ← TOTP validation
    ├── password.rs         ← Argon2id hashing + verification
    ├── session.rs          ← token blocklist (invalidation)
    └── brute_force.rs      ← rate limiting on auth endpoints
```

---

### `crates/kron-query-api/`

HTTP API server. Depends on all other service crates.

```
kron-query-api/
├── Cargo.toml
└── src/
    ├── main.rs             ← starts Axum server
    ├── config.rs
    ├── state.rs            ← AppState (shared across handlers)
    ├── routes/
    │   ├── mod.rs          ← router definition
    │   ├── auth.rs         ← /auth/* endpoints
    │   ├── events.rs       ← /events/* endpoints
    │   ├── alerts.rs       ← /alerts/* endpoints
    │   ├── rules.rs        ← /rules/* endpoints
    │   ├── assets.rs       ← /assets/* endpoints
    │   ├── soar.rs         ← /playbooks/* endpoints
    │   ├── compliance.rs   ← /compliance/* endpoints
    │   ├── tenants.rs      ← /tenants/* endpoints (MSSP)
    │   └── system.rs       ← /health, /metrics, /version
    ├── ws/
    │   ├── mod.rs
    │   ├── alerts.rs       ← WebSocket alert stream
    │   └── events.rs       ← WebSocket event tail
    ├── middleware/
    │   ├── mod.rs
    │   ├── tenant.rs       ← extracts + validates TenantContext from JWT
    │   ├── rate_limit.rs
    │   └── tracing.rs      ← request tracing (trace_id injection)
    └── openapi.rs          ← utoipa OpenAPI spec generation
```

---

## SQL Migrations (`migrations/`)

```
migrations/
├── 001_initial_schema.sql      ← events, alerts, audit_log tables
├── 002_asset_tables.sql        ← assets, users tables
├── 003_rule_tables.sql         ← rules, playbooks tables
├── 004_tenant_tables.sql       ← tenants, kron_users tables
├── 005_indexes.sql             ← all skip indexes
├── 006_materialized_views.sql  ← mv_alert_counts_hourly etc.
└── README.md                   ← migration rules and naming convention
```

**Rules:**
- Numbered sequentially. Gaps not allowed.
- Never modify a committed migration. Add a new one.
- Every migration is idempotent (uses `IF NOT EXISTS`, `IF EXISTS`)
- Test migrations in CI against a fresh ClickHouse instance

---

## SIGMA Rules (`rules/`)

```
rules/
├── sigma-oss/              ← upstream SIGMA corpus (git submodule)
├── india-pack/
│   ├── financial/
│   │   ├── upi_fraud.yml
│   │   ├── aadhaar_abuse.yml
│   │   └── gst_scraping.yml
│   ├── apt/
│   │   ├── sidewinder.yml
│   │   ├── patchwork.yml
│   │   └── bitter.yml
│   └── regulatory/
│       ├── swift_anomaly.yml
│       └── core_banking_offhours.yml
└── mappings/               ← source type → KRON schema field mappings
    ├── linux_ebpf.yml
    ├── windows_etw.yml
    ├── aws_cloudtrail.yml
    └── syslog_generic.yml
```

---

## Frontend (`web/`)

```
web/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── .eslintrc.js
├── src/
│   ├── main.tsx            ← entry point
│   ├── App.tsx             ← root component + router
│   ├── api/
│   │   ├── client.ts       ← typed API client (all fetch calls here)
│   │   ├── types.ts        ← TypeScript types matching API responses
│   │   └── websocket.ts    ← WebSocket connection management
│   ├── components/         ← reusable UI components (no API calls)
│   │   ├── AlertCard.tsx
│   │   ├── SeverityBadge.tsx
│   │   ├── MitreHeatmap.tsx
│   │   └── ...
│   ├── pages/              ← page-level components (use API)
│   │   ├── Dashboard.tsx
│   │   ├── AlertQueue.tsx
│   │   ├── EventSearch.tsx
│   │   └── ...
│   ├── stores/             ← SolidJS stores (global state)
│   │   ├── auth.ts
│   │   └── alerts.ts
│   └── utils/              ← pure utility functions
│       ├── format.ts       ← date/number formatting
│       └── severity.ts     ← severity colour/label helpers
└── public/
    └── ...
```

---

## Mobile (`mobile/`)

```
mobile/
├── pubspec.yaml
├── lib/
│   ├── main.dart
│   ├── app.dart            ← MaterialApp + router
│   ├── services/
│   │   ├── api_service.dart    ← all HTTP calls
│   │   └── notification_service.dart
│   ├── providers/          ← Riverpod providers
│   │   ├── auth_provider.dart
│   │   └── alerts_provider.dart
│   ├── screens/
│   │   ├── login_screen.dart
│   │   ├── alert_feed_screen.dart
│   │   ├── alert_detail_screen.dart
│   │   └── soar_approval_screen.dart
│   └── widgets/            ← reusable widgets
└── test/
```

---

## Scripts (`scripts/`)

```
scripts/
├── dev-up.sh               ← start dev environment
├── dev-down.sh             ← stop dev environment
├── dev-reset.sh            ← wipe and restart dev environment
├── dev-health-check.sh     ← verify all services healthy
├── phase1-acceptance.sh    ← Phase 1 gate test
├── phase2-acceptance.sh    ← Phase 2 gate test
├── phase3-acceptance.sh    ← Phase 3 gate test
├── load-test.sh            ← 50K EPS load test
├── build-release.sh        ← builds release artifacts
├── build-usb-image.sh      ← builds bootable USB ISO
└── sign-release.sh         ← signs artifacts with cosign
```

---

## What Goes Where — Decision Table

| "I need to..." | Put it in |
|---|---|
| Define a new data type used by 2+ crates | `kron-types/src/` |
| Write a SQL query | `kron-storage/src/{engine}/` |
| Add a new API endpoint | `kron-query-api/src/routes/` |
| Add a new detection rule | `rules/india-pack/` (if India-specific) or SIGMA corpus |
| Add a new SIGMA field mapping | `rules/mappings/` |
| Add a new notification channel | `kron-alert/src/notifications/` |
| Add a new ONNX model | `kron-ai/src/onnx/models/` |
| Add a new Mistral prompt | `kron-ai/src/mistral/prompts.rs` |
| Add a database migration | `migrations/NNN_description.sql` |
| Add a new config option | `kron-types/src/config.rs` |
| Add an integration test | `tests/integration/` |
| Add a script for ops | `scripts/` |
| Add a reusable UI component | `web/src/components/` |
| Add an API call from UI | `web/src/api/client.ts` |
