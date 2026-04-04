# KRON — Getting Started Guide

> **Version:** Phase 5 (v1.0-rc)
> **Last updated:** 2026-04-02
> **Audience:** Developers, SOC engineers, design partners

This guide walks you through setting up, running, and testing the full KRON SIEM stack — from infrastructure services to the web dashboard to attack simulations.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Repository Setup](#3-repository-setup)
4. [Start the Dev Infrastructure](#4-start-the-dev-infrastructure)
5. [Build the Rust Workspace](#5-build-the-rust-workspace)
6. [Run the KRON Backend Services](#6-run-the-kron-backend-services)
7. [Open the Web Dashboard](#7-open-the-web-dashboard)
8. [Run the SolidJS Frontend in Dev Mode](#8-run-the-solidjs-frontend-in-dev-mode)
9. [Run the Flutter Mobile App](#9-run-the-flutter-mobile-app)
10. [Send Test Events & Trigger Alerts](#10-send-test-events--trigger-alerts)
11. [Use the CLI Tool (kron-ctl)](#11-use-the-cli-tool-kron-ctl)
12. [Run the Full Test Suite](#12-run-the-full-test-suite)
13. [Run Phase Acceptance Tests](#13-run-phase-acceptance-tests)
14. [Explore Observability (Grafana + Prometheus)](#14-explore-observability-grafana--prometheus)
15. [Useful Dev Scripts](#15-useful-dev-scripts)
16. [Service Port Reference](#16-service-port-reference)
17. [Environment Variables Reference](#17-environment-variables-reference)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. Architecture Overview

```
                          ┌─────────────────────────────────────┐
                          │           KRON Platform              │
                          │                                      │
  Linux Host              │   kron-agent  ──►  kron-collector   │
  (eBPF events)  ────────►│                         │           │
                          │                    Redpanda bus      │
  Syslog / Cloud ────────►│   kron-collector        │           │
  / OT / EDR              │                    kron-normalizer   │
                          │                         │           │
                          │                    kron-stream       │
                          │                  (SIGMA + AI + IOC)  │
                          │                         │           │
                          │                    kron-alert        │
                          │                  (WhatsApp/SMS/email)│
                          │                         │           │
                          │                    ClickHouse        │
                          │                         │           │
                          │                    kron-query-api    │
                          │                         │           │
                          │                    Web UI / Mobile   │
                          └─────────────────────────────────────┘
```

**Data flow:** Events → Collect → Normalize → Detect → Score → Alert → Store → Query

---

## 2. Prerequisites

### Required on all platforms

| Tool | Version | Install |
|---|---|---|
| Docker Desktop | 4.x+ | https://www.docker.com/products/docker-desktop |
| Docker Compose v2 | bundled with Docker Desktop | `docker compose version` to verify |
| Rust toolchain | stable (1.75+) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Node.js | 18+ | https://nodejs.org |
| Git | any | already installed |

### Required for eBPF agent (Linux only)

The `kron-agent` uses eBPF and **must run on Linux kernel 5.4+**.
On Windows, use WSL2 (Ubuntu 22.04 recommended) or a Linux VM.

```bash
# Check your kernel version
uname -r
# Must show 5.4 or higher
```

### Required for Flutter mobile app

```bash
# Install Flutter SDK
flutter --version  # must be 3.x
```

### Verify Docker is working

```bash
docker --version         # Docker version 24.x or higher
docker compose version   # Docker Compose version v2.x
docker run hello-world   # must succeed
```

---

## 3. Repository Setup

```bash
# Clone the repository
git clone https://github.com/Hardik364/Kron.git
cd Kron

# Copy the environment file
cp .env.dev.example .env.dev

# The defaults in .env.dev work out of the box for local development.
# Edit .env.dev only if you need custom ports or passwords.
```

### What `.env.dev` contains

```bash
CLICKHOUSE_HTTP_PORT=8123
CLICKHOUSE_NATIVE_PORT=9000
CLICKHOUSE_PASSWORD=kron-dev-password

REDPANDA_KAFKA_PORT=9092
REDPANDA_ADMIN_PORT=9644

MINIO_API_PORT=9000
MINIO_CONSOLE_PORT=9001
MINIO_ROOT_USER=kron
MINIO_ROOT_PASSWORD=kron-dev-password

PROMETHEUS_PORT=9090
GRAFANA_PORT=3000
```

---

## 4. Start the Dev Infrastructure

This single command starts all backing services (ClickHouse, Redpanda, MinIO, Prometheus, Grafana) using Docker Compose and waits for all of them to be healthy.

```bash
./scripts/dev-up.sh
```

Expected output:

```
Starting KRON dev environment...
Waiting for all services to be healthy...
  ClickHouse  OK        (http://localhost:8123/ping)
  Redpanda    OK        (localhost:9644)
  MinIO       OK        (http://localhost:9000)
  Prometheus  OK        (http://localhost:9090)
  Grafana     OK        (http://localhost:3000)

All services healthy (25s).

KRON dev environment is ready.

  ClickHouse:  http://localhost:8123
  Redpanda:    localhost:9092  (admin: localhost:9644)
  MinIO:       http://localhost:9000  (console: http://localhost:9001)
  Prometheus:  http://localhost:9090
  Grafana:     http://localhost:3000
```

### Verify services manually

```bash
# ClickHouse
curl http://localhost:8123/ping
# Expected: Ok.

# Redpanda
curl http://localhost:9644/v1/cluster/health_overview
# Expected: {"is_healthy": true, ...}

# MinIO
curl http://localhost:9000/minio/health/live
# Expected: HTTP 200

# Prometheus
curl http://localhost:9090/-/healthy
# Expected: Prometheus Server is Healthy.

# Grafana
curl http://localhost:3000/api/health
# Expected: {"commit":"...", "database":"ok", "version":"..."}
```

---

## 5. Build the Rust Workspace

```bash
# From the repo root
cargo build --workspace

# First build downloads all crates — takes 3–5 minutes.
# Subsequent builds are incremental and take ~10–30 seconds.
```

> **Note:** The build enforces `unwrap_used = deny` and `expect_used = deny` via `clippy.toml`.
> Any `unwrap()` or `expect()` in production code paths will be a compile-time error.

### Verify zero warnings

```bash
cargo clippy --workspace -- -D warnings
# Must exit 0 with no output
```

### Run all unit tests

```bash
cargo test --workspace
```

---

## 6. Run the KRON Backend Services

Each service is a separate binary. Open a terminal for each, or use a terminal multiplexer like `tmux`.

```bash
# Terminal 1 — Collector
# Receives raw events from eBPF agents, syslog sources, HTTP intake, and cloud connectors.
# Listens: gRPC :50051, Syslog UDP :514, Syslog TCP :601, HTTP :8090
cargo run -p kron-collector

# Terminal 2 — Normalizer
# Consumes raw events from Redpanda, parses/enriches them, writes to ClickHouse.
cargo run -p kron-normalizer

# Terminal 3 — Stream Processor
# Runs SIGMA rules, ONNX anomaly scoring, IOC matching, risk scoring.
cargo run -p kron-stream

# Terminal 4 — Alert Engine
# Assembles alerts, deduplicates, sends WhatsApp/SMS/Email notifications.
cargo run -p kron-alert

# Terminal 5 — Query API + Web UI
# REST + WebSocket API. Serves the SolidJS dashboard.
# Listens: http://localhost:8080
cargo run -p kron-query-api
```

### Recommended startup order

```
kron-collector → kron-normalizer → kron-stream → kron-alert → kron-query-api
```

### Verify all services started

```bash
cargo run -p kron-ctl -- health
```

Expected output:

```
Service         Status    Latency
─────────────── ───────── ───────
collector       OK        12ms
normalizer      OK        8ms
stream          OK        5ms
alert           OK        6ms
query-api       OK        3ms
clickhouse      OK        14ms
redpanda        OK        9ms
```

---

## 7. Open the Web Dashboard

With `kron-query-api` running, open your browser:

```
http://localhost:8080
```

### Default login credentials

| Field | Value |
|---|---|
| Email | `admin@kron.local` |
| Password | `kron-dev-admin` |
| TOTP | Use any TOTP app; scan the QR on first login |

> In dev mode, TOTP can be bypassed by setting `KRON_AUTH__TOTP_REQUIRED=false` in `.env.dev`.

### Dashboard sections

| Section | What you see |
|---|---|
| **Dashboard** | 4 metric cards, alert trend chart, MITRE ATT&CK mini-heatmap |
| **Alert Queue** | Live alert list, severity badges, filter by P1–P5 |
| **Alert Detail** | Narrative summary, evidence table, MITRE technique, action buttons |
| **Event Search** | Natural language query bar + filter sidebar |
| **MITRE Heatmap** | Full ATT&CK matrix coloured by hit count |
| **Rules** | SIGMA rule browser, enable/disable, test against sample events |
| **Compliance** | RBI/SEBI/CERT-In/ISO 27001 coverage, report generation |
| **Tenants** | MSSP portal — create/manage tenants (admin only) |
| **Settings** | Org config, notification channels, API keys |

### Keyboard shortcuts

| Key | Action |
|---|---|
| `J` / `K` | Next / previous alert |
| `A` | Acknowledge alert |
| `F` | Flag for follow-up |
| `Space` | Expand / collapse alert detail |
| `/` | Focus search bar |

---

## 8. Run the SolidJS Frontend in Dev Mode

For hot-reload during UI development:

```bash
cd web
npm install        # first time only
npm run dev
# → http://localhost:5173
```

The dev server proxies API calls to `http://localhost:8080` automatically.
Edit any file in `web/src/` and changes reflect instantly in the browser.

---

## 9. Run the Flutter Mobile App

```bash
cd mobile

# List available devices
flutter devices

# Run on Android emulator
flutter run -d android

# Run on iOS simulator (macOS only)
flutter run -d ios

# Run on Chrome (web preview)
flutter run -d chrome
```

### Mobile app features

- **Login** with email/password + TOTP + biometric unlock
- **Alert feed** — real-time push notifications for P1/P2 alerts
- **Alert detail** — narrative, evidence, MITRE info
- **SOAR approval** — approve/reject automated response actions with biometric confirmation
- **On-call schedule** — view who is on call

---

## 10. Send Test Events & Trigger Alerts

### Option A — HTTP intake (simplest, no agent needed)

```bash
# Send a single test event via the HTTP intake endpoint
curl -X POST http://localhost:8090/intake/v1/events \
  -H "Authorization: Bearer kron-dev-intake-token" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "hostname": "test-host-01",
      "event_type": "process_create",
      "process_name": "powershell.exe",
      "process_cmdline": "powershell.exe -EncodedCommand dGVzdA==",
      "src_ip": "192.168.1.100",
      "dst_ip": "185.220.101.47",
      "severity": "high",
      "raw": "test event"
    }]
  }'
```

The encoded PowerShell command + the destination IP (a known Tor exit node) should trigger:
- SIGMA rule: `proc_creation_win_susp_powershell_enc_cmd`
- IOC match: known Tor exit node IP
- P1 alert in the dashboard within ~5 seconds

### Option B — Run the attack simulation script

```bash
# Injects 50 pre-crafted attack events covering multiple SIGMA rules
./scripts/phase2-acceptance.sh
```

This simulates:
- Brute-force login attack → fires alert
- Known C2 IP connection → IOC hit → alert
- Suspicious PowerShell execution → alert
- Normal activity → no alert

### Option C — Run the eBPF agent (Linux / WSL2 only)

```bash
# In WSL2 or a Linux machine, build and run the agent
cargo build -p kron-agent
sudo ./target/debug/kron-agent --config crates/kron-agent/agent.dev.toml

# In another terminal, generate events
curl https://example.com        # triggers network_connect event
ls /etc/passwd                  # triggers file_access event
bash -c "id; whoami"           # triggers process_create event

# Check events arrived in ClickHouse
curl "http://localhost:8123/?query=SELECT+count()+FROM+kron.events+WHERE+tenant_id='default'"
```

### Option D — Send syslog events

```bash
# UDP syslog (RFC 3164)
echo "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8" \
  | nc -u -w1 localhost 514

# TCP syslog (RFC 5424)
echo "<165>1 2026-04-02T10:00:00Z myhost myapp 1234 ID47 - Test message" \
  | nc -w1 localhost 601
```

---

## 11. Use the CLI Tool (kron-ctl)

```bash
# Build the CLI
cargo build -p kron-ctl

# Or run directly
cargo run -p kron-ctl -- <command>
```

### Available commands

```bash
# Check health of all services
kron-ctl health

# Query recent events
kron-ctl events query \
  --tenant default \
  --from "1 hour ago" \
  --to "now" \
  --limit 20

# Live-tail events as they arrive (like tail -f)
kron-ctl events tail --tenant default

# List all registered agents
kron-ctl agents list

# Pre-register a new agent (returns agent_id for use in agent config)
kron-ctl agents create --hostname my-server-01

# Storage statistics
kron-ctl storage stats

# Apply pending database migrations
kron-ctl migration run

# Show migration status
kron-ctl migration status
```

### Example output — `kron-ctl events query`

```
Tenant: default   Time range: 2026-04-02 09:00 → 10:00   Showing: 5 of 247 events

  TIME                  HOST           TYPE              SRC IP          SEVERITY
  ──────────────────    ────────────   ───────────────── ─────────────── ────────
  2026-04-02 09:58:12   web-server-01  network_connect   185.220.101.47  HIGH
  2026-04-02 09:57:44   web-server-01  process_create    —               MEDIUM
  2026-04-02 09:55:01   db-server-02   file_access       —               LOW
  2026-04-02 09:52:18   web-server-01  failed_login      203.0.113.42    HIGH
  2026-04-02 09:50:33   dc-01          process_create    —               INFO
```

---

## 12. Run the Full Test Suite

```bash
# All unit tests (no external dependencies)
cargo test --workspace

# All tests including integration tests (requires dev infrastructure running)
cargo test --workspace -- --include-ignored

# Specific crate tests
cargo test -p kron-types
cargo test -p kron-storage -- --include-ignored integration
cargo test -p kron-normalizer
cargo test -p kron-stream -- sigma
cargo test -p kron-stream -- ioc
cargo test -p kron-ai    -- inference
cargo test -p kron-auth
cargo test -p kron-alert -- --include-ignored integration
cargo test -p kron-query-api -- --include-ignored integration

# Run with output visible (useful for debugging)
cargo test -p kron-stream -- sigma --nocapture

# Run a specific test by name
cargo test -p kron-normalizer test_cef_parsing_all_field_types
```

### Test naming convention

All tests follow: `test_<what>_when_<condition>_then_<expected>`

```bash
# Examples
cargo test test_risk_score_when_p1_severity_then_score_above_80
cargo test test_tenant_isolation_when_wrong_tenant_then_returns_empty
cargo test test_sigma_rule_when_encoded_powershell_then_fires_alert
```

---

## 13. Run Phase Acceptance Tests

These are the official gate tests. Each must pass before moving to the next phase.

```bash
# Phase 1 — End-to-end data pipeline
# Events flow from agent → collector → normalizer → ClickHouse
./scripts/phase1-acceptance.sh

# Phase 2 — Detection engine
# Attack simulation → SIGMA + IOC + AI detection → alerts fired
./scripts/phase2-acceptance.sh

# Phase 3 — Web UI (manual checklist)
# Run the script then follow the on-screen checklist in the browser
./scripts/phase3-acceptance.sh
```

### What phase1-acceptance.sh does

1. Starts dev environment
2. Starts `kron-collector` and `kron-normalizer`
3. Installs `kron-agent` on localhost
4. Waits 60 seconds
5. Runs `curl` and `ls` commands to generate events
6. Queries ClickHouse directly
7. Asserts > 100 events in ClickHouse for `default` tenant
8. Asserts 0 events visible for a wrong `tenant_id`
9. Asserts dedup is working (same event not duplicated)
10. Reports `PASS` or `FAIL` with details

---

## 14. Explore Observability (Grafana + Prometheus)

### Grafana dashboards

Open `http://localhost:3000` (login: `admin / kron-dev`)

| Dashboard | What it shows |
|---|---|
| **KRON Overview** | Events/sec, alert rate, pipeline latency end-to-end |
| **Collector** | Events received per source type, agent heartbeat status |
| **Normalizer** | Parse success rate, GeoIP hits, dedup rate |
| **Stream Processor** | SIGMA match rate, ONNX inference latency, IOC hit rate |
| **Alert Engine** | Alerts fired per hour, notification delivery status |
| **Storage** | ClickHouse insert/query latency, disk usage |
| **Infrastructure** | CPU, memory, disk for all Docker containers |

### Key Prometheus metrics to watch

```promql
# Events ingested per second
rate(kron_collector_events_received_total[1m])

# SIGMA rules firing per minute
rate(kron_stream_sigma_matches_total[1m])

# ONNX inference latency p99
histogram_quantile(0.99, kron_ai_inference_duration_seconds_bucket)

# Alert pipeline latency (source to alert) p99
histogram_quantile(0.99, kron_alert_pipeline_duration_seconds_bucket)

# ClickHouse insert latency p99
histogram_quantile(0.99, kron_storage_insert_duration_seconds_bucket)

# Consumer lag (should be near 0 in a healthy system)
kron_bus_consumer_lag_records
```

---

## 15. Useful Dev Scripts

| Script | What it does |
|---|---|
| `./scripts/dev-up.sh` | Starts all Docker services, waits for health |
| `./scripts/dev-down.sh` | Stops all Docker services gracefully |
| `./scripts/dev-reset.sh` | Wipes all Docker volumes + recreates (clean slate) |
| `./scripts/dev-health-check.sh` | Checks health of all 5 backing services |
| `./scripts/phase1-acceptance.sh` | Runs Phase 1 end-to-end acceptance test |
| `./scripts/phase2-acceptance.sh` | Runs Phase 2 attack simulation |
| `./scripts/phase3-acceptance.sh` | Runs Phase 3 manual UI checklist |
| `./scripts/backup.sh` | Backs up ClickHouse data + config to MinIO |
| `./scripts/restore.sh` | Restores from a backup |
| `./scripts/install.sh` | Production one-line installer (Ubuntu/RHEL) |

---

## 16. Service Port Reference

| Service | Protocol | Port | URL |
|---|---|---|---|
| `kron-query-api` | HTTP REST + WS | `8080` | http://localhost:8080 |
| `kron-collector` gRPC | gRPC (mTLS) | `50051` | — |
| `kron-collector` HTTP intake | HTTP | `8090` | http://localhost:8090/intake/v1/events |
| `kron-collector` Syslog UDP | UDP | `514` | — |
| `kron-collector` Syslog TCP | TCP | `601` | — |
| ClickHouse HTTP | HTTP | `8123` | http://localhost:8123 |
| ClickHouse native | TCP | `9000` | — |
| Redpanda Kafka | TCP | `9092` | — |
| Redpanda Admin API | HTTP | `9644` | http://localhost:9644 |
| MinIO API | HTTP | `9000` | http://localhost:9000 |
| MinIO Console | HTTP | `9001` | http://localhost:9001 |
| Prometheus | HTTP | `9090` | http://localhost:9090 |
| Grafana | HTTP | `3000` | http://localhost:3000 |
| SolidJS dev server | HTTP | `5173` | http://localhost:5173 |

---

## 17. Environment Variables Reference

All KRON services read config from `kron.toml` (or the path in `--config`), with environment variable overrides using the `KRON_` prefix and `__` as separator.

| Environment Variable | Default | Description |
|---|---|---|
| `KRON_CLICKHOUSE__URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `KRON_CLICKHOUSE__DATABASE` | `kron` | ClickHouse database name |
| `KRON_CLICKHOUSE__PASSWORD` | — | ClickHouse password |
| `KRON_REDPANDA__BROKERS` | `localhost:9092` | Comma-separated Redpanda brokers |
| `KRON_API__LISTEN_ADDR` | `0.0.0.0:8080` | Query API bind address |
| `KRON_AUTH__TOTP_REQUIRED` | `true` | Set `false` to skip TOTP in dev |
| `KRON_COLLECTOR__INTAKE_AUTH_TOKEN` | — | Bearer token for HTTP intake |
| `KRON_AI__MODELS_DIR` | `/var/lib/kron/models` | Path to ONNX model files |
| `KRON_STORAGE__TIER` | `standard` | `nano`, `standard`, or `enterprise` |

---

## 18. Troubleshooting

### Docker services not starting

```bash
# Check if ports are already in use
netstat -tulpn | grep -E "8123|9092|9000|9090|3000"

# View service logs
docker compose -f deploy/compose/docker-compose.dev.yml logs --follow

# Full reset (WARNING: deletes all local data)
./scripts/dev-reset.sh
```

### Cargo build fails

```bash
# Update Rust toolchain
rustup update stable

# Clear build cache
cargo clean
cargo build --workspace

# Check for missing system dependencies (eBPF agent needs clang + libbpf on Linux)
# On Ubuntu:
sudo apt install clang llvm libelf-dev libbpf-dev
```

### ClickHouse connection refused

```bash
# Verify ClickHouse is running
curl http://localhost:8123/ping
# If no response, check Docker:
docker ps | grep clickhouse
docker logs kron-clickhouse-dev
```

### Events not appearing in ClickHouse

```bash
# Check Redpanda consumer lag
cargo run -p kron-ctl -- storage stats

# Check normalizer logs for parse errors
cargo run -p kron-normalizer 2>&1 | grep -i error

# Verify the raw topic has messages
docker exec kron-redpanda-dev rpk topic consume kron.raw.default --num 5
```

### Web UI shows blank page or 401

```bash
# Verify query API is running
curl http://localhost:8080/health

# Check CORS — make sure frontend is proxying to :8080
# In web/vite.config.ts, proxy target should be http://localhost:8080
```

### ONNX models not loading

```bash
# Check model files exist
ls models/

# Models required:
#   models/isolation_forest.onnx
#   models/ueba_classifier.onnx
#   models/beaconing_detector.onnx
#   models/exfil_scorer.onnx

# If missing, generate placeholder models:
python3 scripts/generate_dev_models.py
```

---

## Quick Start — TL;DR

```bash
# 1. Setup
cp .env.dev.example .env.dev

# 2. Start infrastructure
./scripts/dev-up.sh

# 3. Build
cargo build --workspace

# 4. Run backend (5 terminals)
cargo run -p kron-collector
cargo run -p kron-normalizer
cargo run -p kron-stream
cargo run -p kron-alert
cargo run -p kron-query-api

# 5. Open dashboard
# http://localhost:8080  (admin@kron.local / kron-dev-admin)

# 6. Trigger a test alert
./scripts/phase2-acceptance.sh

# 7. Watch the alert appear in the dashboard
```

---

*For architecture details see [`docs/Architecture.md`](Architecture.md)*
*For API reference see [`docs/API.md`](API.md)*
*For deployment see [`docs/Deployment.md`](Deployment.md)*
*For security hardening see [`docs/Security.md`](Security.md)*
