# ComponentDependencies.md — KRON Component Dependency Graph

**Purpose:** Before starting any component, check this file.
If a dependency is not `[x]` complete, do not start the dependent component.

---

## Rust Crate Dependencies

### Level 0 — No Internal Dependencies

```
kron-types
  External deps only: serde, uuid, chrono, thiserror
  Internal deps: none
  Can start: immediately (first thing built)
  Must be complete before: everything else
```

### Level 1 — Depends Only on kron-types

```
kron-storage
  External deps: clickhouse, duckdb, deadpool
  Internal deps: kron-types
  Can start: after kron-types types + error are stable
  Blocking: kron-normalizer, kron-stream, kron-alert, kron-query-api

kron-bus
  External deps: rdkafka, leveldb
  Internal deps: kron-types
  Can start: after kron-types is stable
  Blocking: kron-collector, kron-normalizer, kron-stream, kron-alert

kron-auth
  External deps: jsonwebtoken, argon2, totp-rs
  Internal deps: kron-types
  Can start: after kron-types is stable
  Blocking: kron-query-api
```

### Level 2 — Depends on Level 1

```
kron-agent
  External deps: aya, aya-log, tonic (client), leveldb
  Internal deps: kron-types
  Note: does NOT depend on kron-storage or kron-bus (agent is standalone)
  Can start: after kron-types is stable
  Blocking: nothing (agent is a leaf — collected data flows to kron-collector)

kron-collector
  External deps: tonic (server), tokio
  Internal deps: kron-types, kron-bus
  Can start: after kron-bus is stable
  Blocking: kron-normalizer (needs collector to receive events)

kron-ai
  External deps: ort (ONNX), ndarray, llama-cpp-rs or candle
  Internal deps: kron-types
  Can start: after kron-types is stable
  Blocking: kron-stream (ONNX scoring), kron-alert (narrative generation)
```

### Level 3 — Depends on Level 2

```
kron-normalizer
  External deps: maxminddb, regex, serde_yaml
  Internal deps: kron-types, kron-bus, kron-storage
  Can start: after kron-collector + kron-bus + kron-storage are stable
  Blocking: kron-stream (needs normalized events)
  Critical path: this is the middle of the ingestion pipeline

kron-stream
  External deps: bloomfilter, xxhash-rust
  Internal deps: kron-types, kron-bus, kron-storage, kron-ai
  Can start: after kron-normalizer + kron-ai are stable
  Blocking: kron-alert (needs scored alert candidates)
  Critical path: this is the detection engine
```

### Level 4 — Depends on Level 3

```
kron-alert
  External deps: reqwest (WhatsApp/SMS APIs), lettre (email)
  Internal deps: kron-types, kron-storage, kron-bus, kron-ai, kron-stream (types only)
  Can start: after kron-stream output types are stable
  Blocking: kron-soar (alert triggers playbooks), kron-query-api (alert read endpoints)

kron-compliance
  External deps: weasyprint (PDF), chrono
  Internal deps: kron-types, kron-storage, kron-alert (types only)
  Can start: after kron-alert types stable + core storage works
  Blocking: nothing critical (compliance is a read-only reporting layer)
```

### Level 5 — Depends on Level 4

```
kron-soar
  External deps: reqwest (action APIs), tokio-process
  Internal deps: kron-types, kron-storage, kron-auth, kron-alert (types only)
  Can start: after kron-alert is stable
  Note: basic SOAR (block IP, notify) can start earlier — full playbook engine after

kron-query-api
  External deps: axum, tower, utoipa
  Internal deps: ALL other kron crates (it is the API surface for everything)
  Can start: after kron-auth is stable (for auth middleware)
  Note: can stub out unimplemented features with 501 Not Implemented
  Blocking: web UI (needs API to call), kron-ctl (shares API)
```

---

## Build in This Order (No Exceptions)

```
Week 1-2:   [Project setup] (no crates, just tooling)
Week 3-4:   kron-types (complete)
Week 5-6:   kron-storage (ClickHouse impl)
Week 7-8:   kron-bus (Redpanda impl)
             kron-auth (can build in parallel with kron-bus)
Week 9-11:  kron-agent
Week 12-13: kron-collector
             kron-ai (ONNX only, no Mistral yet — can parallel with collector)
Week 14-16: kron-normalizer
Week 17:    [MVD gate — test pipeline end-to-end]
Week 18-20: kron-stream (SIGMA engine)
Week 21-22: kron-stream (IOC + ONNX integration)
Week 23-24: kron-stream (full pipeline)
Week 25-26: kron-alert (WhatsApp + notifications)
Week 27-28: kron-auth (finalize + harden)
Week 29-30: kron-query-api (all endpoints)
Week 31-32: web UI (SolidJS)
Week 33-34: multi-tenancy hardening
Week 35-36: kron-compliance
Week 37-40: Flutter mobile
Week 41-44: Hardening + Standard gate
```

---

## What Can Be Built in Parallel

These pairs can be developed simultaneously by different engineers:

| Pair | Why parallel is safe |
|---|---|
| kron-storage + kron-bus | No dependency between them |
| kron-auth + kron-bus | No dependency between them |
| kron-agent + kron-collector | Agent sends TO collector, but agent can be tested standalone |
| kron-ai + kron-collector | No dependency between them |
| kron-compliance + kron-soar | Neither depends on the other |
| Web UI + Flutter mobile | Both consume the same API |

**What cannot be parallel:**
- kron-normalizer and kron-stream both need kron-storage to be stable first
- kron-query-api cannot be built before kron-auth (needs auth middleware)
- Web UI cannot be built before kron-query-api has the endpoints it needs

---

## Infrastructure Dependencies

These infrastructure components must be running before their dependent services:

| Infrastructure | Must be up before |
|---|---|
| ClickHouse | kron-normalizer, kron-stream, kron-alert, kron-query-api |
| Redpanda | kron-collector, kron-normalizer, kron-stream, kron-alert |
| Vault (Standard) | kron-auth (for JWT signing keys), all services (for DB creds) |
| MinIO | kron-storage (cold tier Parquet) |
| Prometheus | All services (metrics endpoint required for health checks) |

---

## Data Flow Dependencies (for testing)

To test end-to-end, services must be started in this order:

```
1. ClickHouse + Redpanda + MinIO + Vault (infrastructure)
2. kron-storage migrations (run migrations/ against ClickHouse)
3. kron-collector (start receiving events)
4. kron-normalizer (start consuming from Redpanda)
5. kron-stream (start consuming normalized events)
6. kron-alert (start consuming alert candidates)
7. kron-query-api (start serving HTTP)
8. kron-agent (deploy on endpoint — last, after everything is ready to receive)
```

**Never start kron-agent before kron-collector is running.**
The agent will buffer locally but you will waste time debugging when
the real issue is the collector isn't up.

---

## Feature Dependency Matrix

Some features depend on other features being complete before they add value:

| Feature | Depends on being built first |
|---|---|
| UEBA baselines | 30 days of event data (can't shortcut this) |
| Compliance reports | Compliance mappings + 7+ days of alerts |
| AI alert narrative | ONNX models trained + kron-ai service running |
| NL query | kron-query-api + kron-ai + ClickHouse schema stable |
| SOAR WhatsApp reply | WhatsApp alerts working + SOAR actions implemented |
| MSSP portal | Multi-tenancy + per-tenant config working |
| GPU Mistral | Standard Mistral CPU mode working (GPU is an upgrade) |
| Enterprise HA | Standard single-node working (HA is an upgrade) |
| USB installer | All Nano services working via Docker Compose first |
