# KRON — System Architecture

**Version:** 1.0

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  DATA SOURCES                                                         │
│  Linux hosts · Windows hosts · Cloud APIs · Network devices          │
│  Kubernetes · OT/SCADA · Applications · Syslog sources               │
└────────────────────────────┬────────────────────────────────────────┘
                             │ encrypted (mTLS)
┌────────────────────────────▼────────────────────────────────────────┐
│  COLLECTION LAYER                                                     │
│  eBPF agent · ETW collector · Agentless SSH · Cloud puller           │
│  Syslog rx · OT bridge · HTTP intake                                 │
│  └─ Agent control plane (fleet management, cert rotation)            │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  MESSAGE BUS                                                          │
│  Nano: embedded Rust channel (disk-backed)                           │
│  Standard/Enterprise: Redpanda (Kafka-compatible, no JVM)            │
│  Topics: raw-events · enriched-events · alerts · audit               │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│  STREAM PROCESSING (Rust + tokio)                                    │
│  Normalize → Enrich → Dedup → IOC bloom → SIGMA rules               │
│  ONNX inference → UEBA → Entity graph → Risk score → MITRE tag      │
└──────────┬─────────────────────────────────────┬────────────────────┘
           │                                     │
┌──────────▼──────────────┐         ┌────────────▼────────────────────┐
│  STORAGE                │         │  ALERT ENGINE                    │
│  Nano: DuckDB           │         │  Dedup · Group · Score · Tag     │
│  Standard: ClickHouse   │         │  Narrative (ONNX/Mistral)        │
│  Enterprise: CH sharded │         │  WhatsApp · SMS · Email · Push   │
│  Cold: Parquet + MinIO  │         └────────────┬────────────────────┘
└──────────┬──────────────┘                      │
           │                                     │
┌──────────▼──────────────────────────────────────▼────────────────────┐
│  APPLICATION LAYER (Rust + Axum)                                      │
│  Query API · SOAR engine · Compliance engine · Auth service           │
│  Tenant management · Rule management · Asset management               │
└──────────┬─────────────────────────────────────┬─────────────────────┘
           │                                     │
┌──────────▼──────────┐               ┌──────────▼──────────────────────┐
│  WEB UI (SolidJS)   │               │  MOBILE APP (Flutter)            │
│  Alert queue        │               │  Push alerts                     │
│  NL query           │               │  SOAR approve/reject             │
│  MITRE heatmap      │               │  Incident view                   │
│  Rule builder       │               │  On-call management              │
│  Compliance dash    │               └─────────────────────────────────┘
└─────────────────────┘
```

---

## Service Inventory

| Service | Language | Purpose | Tier |
|---|---|---|---|
| `kron-agent` | Rust | eBPF/ETW collection agent | All |
| `kron-collector` | Rust | Agentless, syslog, cloud, OT intake | All |
| `kron-normalizer` | Rust | Parse, enrich, normalize events | All |
| `kron-stream-processor` | Rust | Detection, scoring, routing | All |
| `kron-query-api` | Rust (Axum) | REST + WebSocket API | All |
| `kron-alert-engine` | Rust | Alert assembly, dedup, notification | All |
| `kron-soar` | Rust | Playbook execution engine | Standard+ |
| `kron-compliance` | Rust | Compliance mapping, report generation | All |
| `kron-auth` | Rust | JWT issuance, RBAC, MFA | All |
| `kron-ai` | Rust + ONNX | Inference service (ONNX + Mistral) | All |
| `kron-web` | SolidJS | Analyst web UI | All |
| `kron-mobile` | Flutter | Mobile app | Standard+ |
| `kron-installer` | Bash + Rust | One-line/USB installer | All |
| `kron-ctl` | Rust | Admin CLI | All |

---

## Nano Tier Architecture

```
┌──────────────────────────────────────────────────────┐
│  Single process: kron-server                          │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Collector  │  │   Stream     │  │  Query API   │  │
│  │ (tokio)    │→ │  Processor   │→ │  (Axum)      │  │
│  └────────────┘  │  (tokio)     │  └──────────────┘  │
│                  └──────┬───────┘                     │
│  ┌────────────┐         │         ┌──────────────┐    │
│  │  DuckDB    │ ←───────┘         │  Alert Engine│    │
│  │ (embedded) │                   │  + Notifier  │    │
│  └────────────┘                   └──────────────┘    │
│                                                        │
│  Embedded queue (disk-backed async channel)            │
│  ONNX Runtime (CPU)                                    │
│  Self-signed TLS (systemd-creds)                       │
└──────────────────────────────────────────────────────┘
Single binary, ~180MB. Docker Compose or systemd service.
```

---

## Standard Tier Architecture

```
┌─────────────────────────────────────────────────────────┐
│  One server (16–32 GB RAM)                               │
│                                                           │
│  ┌─────────────────┐   ┌─────────────────────────────┐  │
│  │  Redpanda       │   │  ClickHouse (single-node)   │  │
│  │  (single-node)  │   │  events + alerts + audit    │  │
│  └────────┬────────┘   └──────────────┬──────────────┘  │
│           │                            │                  │
│  ┌────────▼────────────────────────────▼──────────────┐  │
│  │          k3s Kubernetes                             │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │  │
│  │  │ stream-proc  │  │  query-api   │  │  soar    │  │  │
│  │  │  (3 pods)    │  │  (2 pods)    │  │ (1 pod)  │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────┘  │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │  │
│  │  │  auth-svc    │  │  compliance  │  │  kron-ai │  │  │
│  │  │  (2 pods)    │  │  (1 pod)     │  │ (1 pod)  │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────┘  │  │
│  │                                                      │  │
│  │  Vault (single-node)  ·  KRON web (served by API)  │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Enterprise Tier Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Rack / AZ 1           Rack / AZ 2          Rack / AZ 3      │
│                                                                │
│  Redpanda-1  ─────── Redpanda-2  ─────── Redpanda-3          │
│  (Raft leader)        (follower)           (follower)         │
│                                                                │
│  ClickHouse           ClickHouse           ClickHouse         │
│  Shard-1 Rep-A  ─── Shard-1 Rep-B         Shard-2 Rep-A      │
│                                                                │
│  k8s Control-1  ─── k8s Control-2  ─── k8s Control-3        │
│                                                                │
│  ┌──────────────────────────────────────────────────────┐     │
│  │  k8s Worker Nodes (spread across AZs)                │     │
│  │  stream-processor × 6    query-api × 3               │     │
│  │  soar × 2                compliance × 2              │     │
│  │  auth-svc × 2            kron-ai × 1 (GPU node)      │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                │
│  SPIRE Server × 3 (Raft)   Vault × 3 (Raft + HSM)           │
│                                                                │
│  Primary HSM  ──── Backup HSM                                 │
│                                                                │
│  Off-site: Parquet → MinIO → cold object store               │
└──────────────────────────────────────────────────────────────┘
```

---

## Data Flow: Event Ingestion

```
1. Source generates event
   └─ (e.g. process exec on Linux host)

2. eBPF agent captures in kernel ring buffer
   └─ Ring buffer: 64MB shared memory, zero-copy

3. Userspace agent reads ring buffer
   └─ Batches events: max 1000 events OR 100ms, whichever first

4. Agent compresses batch (LZ4) + encrypts (AES-256-GCM)
   └─ Sends via gRPC stream to kron-collector

5. kron-collector validates client cert, decrypts, decompresses
   └─ Writes to Redpanda topic: kron.raw.{tenant_id}

6. kron-normalizer reads from raw topic
   └─ Parses event format
   └─ Maps to canonical KRON schema
   └─ Enriches: GeoIP, asset lookup, user identity
   └─ Computes dedup_hash
   └─ Writes to: ClickHouse events table + kron.enriched.{tenant_id}

7. kron-stream-processor reads from enriched topic
   └─ Runs SIGMA rule matching
   └─ Runs ONNX inference (anomaly score, beaconing, exfil)
   └─ Checks IOC bloom filter
   └─ Updates entity graph
   └─ Computes risk score
   └─ Tags MITRE ATT&CK

8. If rule matches or risk_score > threshold:
   └─ kron-alert-engine assembles alert
   └─ Deduplicates against recent alerts (15-min window)
   └─ Generates narrative (ONNX language model)
   └─ Writes to: ClickHouse alerts table
   └─ Publishes to: kron.alerts.{tenant_id}
   └─ Routes notifications: WhatsApp → SMS → email (fallback chain)

Total latency source → alert: target <500ms
```

---

## Data Flow: Analyst Query

```
1. Analyst opens web UI
   └─ SolidJS app loaded from kron-query-api static files

2. Analyst types query or filter
   └─ If NL query: POST /api/v1/events/query { mode: "nl" }
   └─ kron-query-api → kron-ai (NL→SQL translation)
   └─ If direct filter: builds SQL from parameters

3. Query rewrite middleware
   └─ Injects: AND tenant_id = 'uuid'
   └─ Validates: no prohibited operations (DROP, UPDATE, etc.)
   └─ Sets ClickHouse session variable: kron.tenant_id = 'uuid'

4. ClickHouse executes query
   └─ Row policy enforces tenant_id at DB layer (gate 3)
   └─ Returns results

5. kron-query-api serializes response
   └─ Streams results to browser (chunked JSON for large results)

Total latency query → first results: target <200ms
```

---

## Caching Architecture

| Cache | Implementation | TTL | Purpose |
|---|---|---|---|
| GeoIP lookup | In-process HashMap | 1 hour | Avoid MaxMind DB lookup per event |
| Asset lookup | In-process LRU (10K entries) | 5 min | Hostname → asset_id enrichment |
| User identity | In-process LRU (5K entries) | 5 min | Username → canonical user |
| IOC bloom filter | In-process BloomFilter | 5 min refresh | Sub-ms IOC lookup |
| JWT validation | In-process LRU (1K tokens) | until expiry | Avoid crypto verify per request |
| SIGMA compiled rules | In-process HashMap | until change | Avoid recompile per event |
| Dashboard aggregations | ClickHouse MVs | continuous | Pre-aggregated chart data |

---

## Failure Modes and Handling

| Failure | Detection | Response |
|---|---|---|
| Agent crash | Missed heartbeat >60s | P2 alert: "host dark" |
| Redpanda node loss | Raft reelection | Automatic failover, no data loss |
| ClickHouse node loss | Prometheus alert | Replica promotion, read continues |
| Stream processor crash | k8s pod restart | Automatic restart, Redpanda holds events |
| Query API crash | k8s pod restart + LB health check | Traffic routed to healthy pods |
| SPIRE server loss | HA quorum maintained | SVIDs continue until TTL, new issuance resumes |
| Vault sealed | Prometheus alert, page on-call | HSM auto-unseal (Enterprise), manual unseal (Standard) |
| Full ClickHouse loss | Prometheus alert, page on-call | Runbook: restore from Parquet + Redpanda replay |
| Network partition | Redpanda Raft handles split | Agents buffer locally |

---

## Observability Architecture

### Metrics (Prometheus)
All services expose `/metrics` on port 9090 (internal only). Key metrics:

```
kron_events_ingested_total{tenant_id, source_type}
kron_events_processing_lag_seconds
kron_alerts_fired_total{tenant_id, severity}
kron_onnx_inference_duration_seconds
kron_clickhouse_query_duration_seconds
kron_redpanda_consumer_lag{topic, consumer_group}
kron_agent_count{tenant_id, status}
kron_rule_match_total{rule_id, tenant_id}
```

### Tracing (Jaeger)
Distributed traces for API requests spanning multiple services. Trace ID propagated via `X-Trace-Id` header. Sampled at 1% in production (100% for errors).

### Logging (structured)
All services log structured JSON to stdout. Collected by k8s logging driver → KRON itself (KRON monitors KRON).

```json
{
  "ts": "2026-01-01T00:00:00Z",
  "level": "info",
  "service": "kron-stream-processor",
  "trace_id": "uuid",
  "tenant_id": "uuid",
  "msg": "alert fired",
  "alert_id": "uuid",
  "rule_id": "uuid",
  "risk_score": 87
}
```

---

## Deployment Topology Summary

| Aspect | Nano | Standard | Enterprise |
|---|---|---|---|
| Nodes | 1 | 1–2 | 3+ |
| Orchestration | Docker Compose / systemd | k3s | k8s |
| Storage | DuckDB | ClickHouse single | ClickHouse sharded HA |
| Message bus | Embedded channel | Redpanda single | Redpanda 3-node |
| Identity | systemd-creds | Self-signed CA | SPIFFE/SPIRE |
| Network policy | iptables | k8s NetworkPolicy | Cilium eBPF |
| Secrets | systemd-creds | Vault single | Vault HA + HSM |
| Monitoring | Prometheus + Grafana | Prometheus + Grafana | Prometheus + Grafana + Jaeger |
| HA | None | Single-server restart | Multi-node, 99.9% SLA |
