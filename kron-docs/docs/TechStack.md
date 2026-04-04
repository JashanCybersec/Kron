# KRON — Technology Stack

**Version:** 1.0

---

## Stack Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Analyst Surface                                                  │
│  SolidJS (web) · Flutter (mobile) · REST/WebSocket API           │
├─────────────────────────────────────────────────────────────────┤
│  Application Layer                                                │
│  Rust (tokio async) · Axum (HTTP) · tonic (gRPC)                │
├─────────────────────────────────────────────────────────────────┤
│  AI / ML Layer                                                    │
│  ONNX Runtime · llama.cpp (CPU Mistral) · candle (GPU Mistral)   │
├─────────────────────────────────────────────────────────────────┤
│  Stream Processing                                                │
│  Rust (tokio) · Redpanda (Standard/Enterprise)                   │
│  Embedded async channel (Nano)                                   │
├─────────────────────────────────────────────────────────────────┤
│  Storage                                                          │
│  DuckDB (Nano) · ClickHouse (Standard/Enterprise)                │
│  Parquet + MinIO (cold tier, all tiers)                          │
├─────────────────────────────────────────────────────────────────┤
│  Collection                                                       │
│  aya (eBPF/Rust) · Windows ETW (Rust FFI) · SSH (async-ssh2)    │
├─────────────────────────────────────────────────────────────────┤
│  Security Fabric                                                  │
│  mTLS (rustls) · SPIFFE/SPIRE (Enterprise) · Cilium (Enterprise)│
│  Vault · systemd-creds (Nano/Standard)                           │
├─────────────────────────────────────────────────────────────────┤
│  Deployment                                                       │
│  Docker Compose (Nano) · k3s/k8s (Standard/Enterprise)          │
│  Helm · Terraform · Ansible                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Backend

### Primary Language: Rust

**Why Rust:**
- Memory safety without GC — critical for a security product
- Zero-cost abstractions — eBPF, stream processing, encryption at native performance
- No JVM — eliminates heap pressure that kills Kafka/Elasticsearch at scale
- Excellent async story via tokio
- First-class eBPF support via `aya` framework
- Compiles to a single static binary — trivial deployment

**Key Rust crates:**

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime — all I/O, timers, task scheduling |
| `axum` | HTTP API server |
| `tonic` | gRPC server/client |
| `aya` | eBPF program loader and userspace bridge |
| `clickhouse` | ClickHouse async client |
| `duckdb` | DuckDB embedded client |
| `rdkafka` | Redpanda/Kafka client (librdkafka bindings) |
| `ort` | ONNX Runtime bindings |
| `serde` / `serde_json` | Serialization |
| `sqlparser` | SQL parsing for query rewrite middleware |
| `rustls` | TLS implementation (no OpenSSL dependency) |
| `jsonwebtoken` | JWT validation |
| `tracing` | Structured logging and distributed tracing |
| `metrics` | Prometheus metrics export |
| `xxhash-rust` | Dedup fingerprinting |
| `bloomfilter` | IOC bloom filter |
| `chrono` | Timestamp handling |
| `regex` | Log parsing |
| `yaml-rust2` | SIGMA YAML parsing |
| `uuid` | ID generation |
| `argon2` | Password hashing |

---

## Storage

### DuckDB (Nano Tier)

**Version:** 0.10+  
**Why:** Single 40MB binary, zero config, embedded in the KRON process, handles 100M rows with sub-3s analytical queries on modest hardware. Native Parquet read/write for cold tier compatibility.

**Configuration:** In-process, memory-mapped files, WAL for durability. Database stored at `/var/lib/kron/data/events.duckdb`.

### ClickHouse (Standard/Enterprise Tier)

**Version:** 24.x  
**Why:** Best-in-class columnar OLAP. 8–15x compression on log data vs Elasticsearch. Sub-second queries on billion-row tables. Native TTL and tiered storage. No JVM.

**Engine selection:**
- `ReplacingMergeTree` — events table (dedup on `dedup_hash`)
- `MergeTree` — alerts table
- `ReplicatedMergeTree` — Enterprise HA tables
- `AggregatingMergeTree` — pre-aggregated materialized views for dashboards

**ClickHouse Keeper** (replaces ZooKeeper in Enterprise). Built-in, no external dependency.

### Parquet + MinIO (Cold Tier, All Tiers)

**Why Parquet:** Universal columnar format. DuckDB reads it natively. ClickHouse reads it natively. Migration between tiers is zero-copy file transfer.

**MinIO:** S3-compatible object store, runs on-premise. Single binary. Compatible with all S3 client libraries.

---

## Message Bus

### Embedded Rust Channel (Nano)

Custom disk-backed async channel implemented in Rust. Survives process restart. Configurable max disk usage (default: 20 GB). No external dependency.

### Redpanda (Standard/Enterprise)

**Version:** Latest stable  
**Why over Kafka:** No JVM, no ZooKeeper, same API as Kafka. 5x lower memory. No GC pauses. C++ implementation.

**Configuration:**
- Standard: Single node, RF=1, 72-hour retention minimum
- Enterprise: 3-node Raft cluster, RF=3, 72-hour retention minimum

**Topics:**
- `kron.raw.{tenant_id}` — raw events from agents
- `kron.enriched.{tenant_id}` — normalized events
- `kron.alerts.{tenant_id}` — fired alerts
- `kron.audit` — audit trail events
- `kron.deadletter` — failed processing events

---

## AI / ML

### ONNX Runtime

**Version:** 1.17+  
**Backend:** CPU (all tiers), CUDA (Enterprise with GPU)  
**Why:** Single runtime for all models regardless of training framework. Runs on CPU with no GPU. 2–10ms inference latency on CPU.

Models stored at `/var/lib/kron/models/`. Version-pinned in `kron.toml`. Hot-reloadable without service restart.

### llama.cpp (CPU Mistral — Standard)

**Why:** Runs Mistral 7B GGUF (4-bit quantized) on CPU with no GPU. 3–8 second inference on 16-core CPU. Acceptable for non-real-time features (alert summarization, NL query, report generation).

GGUF model file: ~4 GB. Loaded on demand, kept in memory if available RAM >16 GB.

### candle (GPU Mistral — Enterprise)

Hugging Face `candle` Rust framework for GPU inference. Runs Mistral 7B at full precision on NVIDIA GPU. <500ms inference. Requires CUDA 11.8+.

---

## Frontend

### SolidJS (Web UI)

**Why SolidJS over React:**
- No virtual DOM — direct DOM updates, faster than React
- Smaller bundle size (~7KB vs React's ~40KB)
- Fine-grained reactivity — surgical UI updates on alert queue with 1000+ items
- TypeScript-first

**Key libraries:**
- `@solidjs/router` — client-side routing
- `solid-query` — server state management (like React Query)
- `chart.js` — MITRE heatmap, event timelines, trend charts
- `@codemirror/lang-sql` — SQL query editor
- `tailwindcss` — utility-first styling
- `lucide-solid` — icons

**Build:** Vite + SolidJS plugin. Output: static files served from KRON query API service.

### Flutter (Mobile)

**Version:** Flutter 3.x, Dart 3.x  
**Platforms:** iOS 15+, Android 10+  
**Why Flutter:** Single codebase for iOS and Android. Dart is easy to learn. Excellent push notification support.

**Key packages:**
- `dio` — HTTP client
- `web_socket_channel` — WebSocket for live alerts
- `firebase_messaging` — push notifications (via self-hosted FCM proxy for air-gap)
- `local_auth` — biometric authentication
- `flutter_local_notifications` — local notification scheduling
- `riverpod` — state management

---

## Security Infrastructure

### mTLS (All Tiers)

**Implementation:** `rustls` — pure Rust TLS, no OpenSSL dependency, no C FFI vulnerabilities.

Nano/Standard: Self-signed CA managed by KRON on first boot. Certs auto-rotated every 90 days. Stored in `systemd-creds` encrypted storage.

Enterprise: SPIFFE/SPIRE-issued X.509 SVIDs. Short TTL (4 hours). Auto-rotated.

### SPIFFE/SPIRE (Enterprise)

**Version:** SPIRE 1.9+  
**Deployment:** 3-node HA SPIRE server cluster  
**SVID format:** X.509 (for service mesh mTLS)  
**Trust domain:** `spiffe://kron.{org_domain}`

### Cilium (Enterprise)

**Version:** 1.15+  
**eBPF-based** network policy enforcement, L7 visibility, Hubble flow observability  
**Policy model:** Deny-by-default, explicit allow per service pair

### HashiCorp Vault (Standard/Enterprise)

**Version:** 1.15+  
**Mode:** Standard — single node. Enterprise — 3-node Raft HA with HSM auto-unseal.  
**Secrets managed:** DB credentials (dynamic), API keys, TLS certificates, agent tokens

### systemd-creds (Nano)

OS-level credential encryption using the machine's TPM or a derived key. No external dependency. Sufficient for single-node deployments.

---

## Deployment Infrastructure

### Docker Compose (Nano)

Single `docker-compose.yml` defines all Nano services. Run with `docker-compose up -d`. No Kubernetes.

### k3s (Standard)

Lightweight Kubernetes distribution. Single binary. Runs on 512 MB RAM minimum. Full Kubernetes API compatibility. Used for Standard tier single-server deployments.

### Kubernetes / k8s (Enterprise)

Full Kubernetes for multi-node HA deployments. Anti-affinity rules spread pods across racks/AZs. Operators for ClickHouse, Redpanda, SPIRE.

### Helm (Standard/Enterprise)

All KRON services packaged as a single Helm chart with sub-charts per component. Values override for each tier. `helm install kron ./kron-chart -f values-standard.yaml`

### Terraform (Enterprise)

Infrastructure provisioning for bare-metal or private cloud deployments. Modules for: server provisioning, network config, storage volumes, DNS.

### Ansible (All Tiers)

Agent deployment across endpoint fleet. One command installs/updates eBPF agent on all Linux servers. Windows ETW agent deployed via PowerShell DSC or Ansible WinRM.

---

## Observability (KRON monitors itself)

| Tool | Purpose |
|---|---|
| Prometheus | Metrics collection from all KRON services |
| Grafana | Dashboards — pipeline lag, query perf, EPS, storage |
| KRON itself | KRON ingests its own logs and runs detection rules on them |
| Alertmanager | Meta-alerts (Redpanda consumer lag, ClickHouse slow queries) |
| Jaeger | Distributed tracing for API latency debugging |

---

## Third-Party Services

| Service | Purpose | Fallback |
|---|---|---|
| Meta WhatsApp Business API | Alert delivery | Twilio WhatsApp |
| Textlocal | SMS (India) | AWS SNS India |
| MaxMind GeoLite2 | GeoIP enrichment | Offline DB bundled |
| MISP community feeds | Threat intel | Offline snapshot |
| Abuse.ch feeds | Malware IOCs | Offline snapshot |

All third-party services are optional. KRON runs fully air-gapped with bundled offline snapshots. No required external connectivity.

---

## Development Tools

| Tool | Purpose |
|---|---|
| Rust toolchain (stable) | Backend development |
| cargo-watch | Hot reload during development |
| cargo-tarpaulin | Code coverage |
| cargo-audit | Dependency vulnerability scanning |
| cargo-deny | License compliance |
| clippy | Rust linter |
| miri | Rust undefined behaviour detector |
| bpftool | eBPF debugging |
| Vite + SolidJS | Frontend dev server |
| Flutter SDK | Mobile development |
| ClickHouse local | Schema testing |
| Docker Compose | Local development environment |
| GitHub Actions | CI/CD |
| Dependabot | Dependency updates |
