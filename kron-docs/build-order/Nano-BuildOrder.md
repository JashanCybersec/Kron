# Nano-BuildOrder.md — KRON Nano Tier Build Plan

**Prerequisite:** Standard gate must pass before Nano work starts.  
**Timeline:** 5 weeks after Standard ships (month 8–9)  
**Key principle:** Nano is NOT a rewrite. It is Standard with two components swapped.

---

## What Nano Is

Nano reuses 95% of Standard code unchanged:
- `kron-types` — identical
- `kron-agent` — identical
- `kron-collector` — identical  
- `kron-normalizer` — identical
- `kron-stream` — identical (SIGMA, IOC, ONNX all same)
- `kron-alert` — identical (WhatsApp, SMS, autopilot all same)
- `kron-auth` — identical
- `kron-query-api` — identical
- Web UI — identical
- Compliance engine — CERT-In + DPDP only (RBI/SEBI deferred)

Only two components change:
- `kron-storage`: ClickHouse implementation → DuckDB implementation
- `kron-bus`: Redpanda → embedded disk-backed channel

Plus one new component:
- USB stick installer

The `StorageEngine` trait and `BusProducer/BusConsumer` traits were designed
specifically so these swaps require zero changes to any other crate.

---

## Why DuckDB for Nano

| Concern | ClickHouse | DuckDB |
|---|---|---|
| Binary size | 200MB+ | 40MB |
| RAM minimum | 4GB standalone | 512MB |
| Config required | Yes — many settings | Zero |
| Setup time | 5+ minutes | Instant |
| External process | Yes | Embedded in kron-server |
| Performance at 1K EPS | Overkill | Ideal |
| Parquet compatibility | Native | Native |

DuckDB runs embedded inside the kron-server process.
No separate service. No config. No ports. No ops knowledge required.

---

## Week 1 — DuckDB Storage Implementation

**`kron-storage` DuckDB implementation:**
```
[ ] DuckdbStorage struct: wraps DuckDB connection with Mutex<Connection>
[ ] DuckDB migrations: same migration runner, DuckDB SQL dialect
[ ] Migration 001-007: converted from ClickHouse DDL to DuckDB DDL
    [ ] ReplacingMergeTree → DuckDB table with UNIQUE constraint
    [ ] DateTime64 → TIMESTAMPTZ
    [ ] LowCardinality(String) → VARCHAR
    [ ] Array(String) → VARCHAR[] (DuckDB array)
    [ ] IPv4 → INET
    [ ] Map(String, String) → JSON
[ ] DuckdbStorage::insert_events(): uses DuckDB prepared statement
[ ] DuckdbStorage::query_events(): same EventFilter → DuckDB SQL
[ ] DuckdbStorage::insert_audit_log()
[ ] DuckdbStorage::query_alerts()
[ ] Tenant isolation: same QueryRewriter, DuckDB parameterized queries
[ ] Parquet export: DuckDB COPY TO PARQUET command (native, no library needed)
[ ] Parquet import: DuckDB COPY FROM PARQUET command
[ ] WAL mode: enabled for crash safety
[ ] File location: /var/lib/kron/data/kron.duckdb
[ ] Single connection + mutex: DuckDB is not concurrent-write safe
[ ] Read concurrency: DuckDB supports concurrent reads, single writer pattern
[ ] Performance test: 1K EPS sustained on 8GB RAM machine: must be stable
```

**DuckDB schema differences from ClickHouse:**
```sql
-- ClickHouse:
CREATE TABLE events ENGINE = ReplacingMergeTree(ts_received)
PARTITION BY (tenant_id, toYYYYMM(ts))
ORDER BY (tenant_id, ts, source_type, host_ip, event_type);

-- DuckDB equivalent:
CREATE TABLE IF NOT EXISTS events (
    event_id        VARCHAR DEFAULT gen_random_uuid()::VARCHAR,
    tenant_id       VARCHAR NOT NULL,
    dedup_hash      UBIGINT NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    ts_received     TIMESTAMPTZ NOT NULL,
    source_type     VARCHAR NOT NULL,
    -- ... same fields, adapted types
    PRIMARY KEY (event_id)
);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts ON events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(tenant_id, hostname, ts DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events(tenant_id, dedup_hash);
```

**Gate:**
```bash
cargo test -p kron-storage -- --include-ignored duckdb
# All StorageEngine trait tests pass on DuckDB implementation
# Cross-tenant isolation: MUST PASS (same test as ClickHouse)
# Insert 100K events: completes without error
# Query on 100K rows: < 2 seconds
# DuckDB file size after 100K events: consistent with expected compression
```

---

## Week 2 — Embedded Bus Implementation

**`kron-bus` embedded channel:**
```
[ ] EmbeddedChannel struct: async channel with disk persistence
[ ] Persistence layer: LevelDB (rocksdb feature = false, leveldb = true)
[ ] EmbeddedProducer::send(): writes to LevelDB, notifies consumer
[ ] EmbeddedConsumer::poll(): reads from LevelDB, returns batch
[ ] Offset tracking: persisted in LevelDB (survives restart)
[ ] At-least-once delivery: offset committed only after processing
[ ] Max disk usage: configurable (default 10GB), drops oldest on overflow
[ ] Overflow notification: Prometheus alert when buffer > 80% full
[ ] Throughput: handles 1K EPS without blocking on 8GB RAM machine
[ ] Memory usage: < 100MB for the bus component
[ ] AdaptiveBus::new(): selects EmbeddedChannel when config.mode = nano
```

**Why LevelDB not in-memory:**
An 8GB machine can lose power. The agent buffers events during restart.
If the embedded channel is in-memory only, events from the last N minutes
are lost on crash. LevelDB provides crash-safe persistence with minimal overhead.

**Gate:**
```bash
cargo test -p kron-bus -- --include-ignored embedded
# Send 10K messages: all received: PASS
# Kill process mid-stream, restart: no messages lost: PASS
# 1K EPS for 10 minutes on 8GB RAM machine: stable memory: PASS
# Overflow: buffer at 100%: drops oldest, continues accepting new: PASS
```

---

## Week 3 — Adaptive Mode Selector + Single Binary

**`kron-server` (new binary for Nano, single process):**
```
[ ] Adaptive resource detector: reads /proc/meminfo, nproc, df, nvidia-smi
[ ] Mode selection logic:
    RAM < 12GB   → mode = nano (DuckDB + embedded bus)
    RAM 12–32GB  → mode = standard-lite (ClickHouse single + embedded bus)
    RAM 32–64GB  → mode = standard (ClickHouse single + Redpanda single)
    RAM 64GB+    → mode = standard-full (+ CPU Mistral)
    GPU detected → mode = enterprise-ready (+ GPU Mistral)
[ ] Writes selected mode to /etc/kron/mode (human-readable)
[ ] Logs selected mode prominently at startup
[ ] All services started in single tokio runtime (Nano only — Standard uses separate processes)
[ ] Health endpoint: /health returns mode + component status
[ ] kron-ctl mode show: prints current mode and why it was selected
[ ] Override flag: --force-mode nano (for testing on high-RAM machines)
```

**Single-binary architecture for Nano:**
```
Nano runs as one process: kron-server
  └─ tokio runtime
       ├─ collector task
       ├─ normalizer task
       ├─ stream processor task
       ├─ alert engine task
       ├─ query API task (Axum)
       └─ DuckDB + embedded channel (in-process)

Standard runs as separate processes:
  kron-collector
  kron-normalizer
  kron-stream
  kron-alert
  kron-query-api
  (+ ClickHouse and Redpanda as separate services)
```

This means Nano installs and starts with a single `systemd enable kron && systemctl start kron`.

---

## Week 4 — USB Stick Installer

**`scripts/build-usb-image.sh`:**
```
[ ] Base: Ubuntu 22.04 minimal (headless, no GUI)
[ ] All KRON binaries built statically for x86_64
[ ] All container images pre-pulled and saved as .tar
[ ] All ONNX model files bundled
[ ] MaxMind GeoLite2 DB bundled
[ ] SIGMA rules (production tier only) bundled
[ ] Mistral GGUF (q4_k_m) bundled (optional — USB with/without AI variant)
[ ] CLI installer wizard: scripts/nano-install-wizard.sh
[ ] Wizard prompts:
    [ ] Organisation name
    [ ] Admin password (with confirmation)
    [ ] WhatsApp number (with test send)
    [ ] Email (optional)
    [ ] Timezone (default: Asia/Kolkata)
    [ ] Language (default: Hindi)
    [ ] Retention period (default: 90 days)
[ ] Post-install: starts KRON, shows access URL, shows first login credentials
[ ] Total install time: < 15 minutes on any x86_64 machine
[ ] ISO size: < 4GB (fits on standard 4GB USB)
[ ] ISO size with AI: < 8GB (fits on 8GB USB)
```

**USB hardware compatibility test matrix:**
```
[ ] Dell OptiPlex 3060 (common Indian enterprise desktop)
[ ] HP ProDesk 400 G5
[ ] Lenovo ThinkCentre M720
[ ] Generic AMD64 server (Supermicro)
[ ] Intel NUC
# At least 3 of 5 must succeed for gate to pass
```

---

## Week 5 — Autopilot Mode + Nano Gate

**Autopilot mode (already in `kron-alert`, needs Nano-specific tuning):**
```
[ ] Default ON for Nano (explicitly opt-out, not opt-in)
[ ] Safe auto-actions for Nano: block IP (iptables), rate-limit source
[ ] Approval-required for Nano: host isolation, account disable
[ ] Daily WhatsApp summary: "Yesterday KRON blocked X threats. No action needed."
[ ] Weekly summary: full threat report
[ ] Escalation threshold: if 3+ P1 alerts in 1 hour → escalate to IT vendor number
[ ] IT vendor contact: configurable in setup wizard
```

**Nano Gate:**
```bash
./scripts/gate-nano.sh

# Hardware tests (run on actual hardware, not VM):
# Test 1: Install on 8GB RAM machine
#   Time must be < 15 minutes
#   Memory after install: < 2GB used at idle
#   All services healthy

# Test 2: USB installer on 3 different hardware configs
#   All 3 must succeed

# Test 3: Detection on Nano
#   Run brute force simulation
#   P1 alert WhatsApp within 2 minutes: PASS

# Test 4: Autopilot
#   Enable autopilot
#   Run brute force simulation
#   IP blocked automatically without analyst action: PASS
#   Daily summary WhatsApp received: PASS

# Test 5: Stability
#   Run 1K EPS for 60 minutes
#   Memory usage: stable (no leak)
#   DuckDB file size: grows at expected rate
#   CPU: < 20% on 4-core machine

# Test 6: Upgrade path
#   Install Nano
#   Upgrade to Standard (change config, restart)
#   Parquet data: all preserved and queryable in ClickHouse
#   No data loss: PASS

# ALL must pass → Nano is shippable
```

---

## Nano Pricing and Distribution

**Distribution channels:**
- Direct download: kron.security/download (ISO + one-line installer)
- MSSP partner kit: USB sticks with partner branding
- Future: annual USB update subscription for air-gapped customers

**Support model for Nano:**
- Free tier: community forum, documentation
- Paid support (₹2,999/month): email support, 48h response
- MSSP white-label: partner manages their customers' Nano instances
