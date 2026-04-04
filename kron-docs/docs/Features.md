# KRON — Features Specification

**Version:** 1.0  
**Status:** Active

---

## Feature Map by Tier

| Feature | Nano | Standard | Enterprise |
|---|:---:|:---:|:---:|
| eBPF Linux agent | ✓ | ✓ | ✓ |
| ETW Windows collector | ✓ | ✓ | ✓ |
| Agentless SSH collection | ✓ | ✓ | ✓ |
| Cloud API puller | — | ✓ | ✓ |
| Syslog / NetFlow receiver | ✓ | ✓ | ✓ |
| OT/SCADA bridge | — | ✓ | ✓ |
| Universal normalizer | ✓ | ✓ | ✓ |
| GeoIP + ASN enrichment | ✓ | ✓ | ✓ |
| SIGMA detection engine | ✓ | ✓ | ✓ |
| India detection pack | ✓ | ✓ | ✓ |
| IOC bloom filter | ✓ | ✓ | ✓ |
| ONNX anomaly scoring | ✓ | ✓ | ✓ |
| UEBA baselines | — | ✓ | ✓ |
| Entity graph | — | ✓ | ✓ |
| MITRE ATT&CK tagging | ✓ | ✓ | ✓ |
| WhatsApp alerting | ✓ | ✓ | ✓ |
| SMS alerting | ✓ | ✓ | ✓ |
| Multilingual summaries | ✓ | ✓ | ✓ |
| Autopilot mode | ✓ | ✓ | ✓ |
| SolidJS web UI | ✓ | ✓ | ✓ |
| Flutter mobile app | — | ✓ | ✓ |
| NL query interface | — | ✓ | ✓ |
| No-code rule builder | ✓ | ✓ | ✓ |
| Multi-tenancy (MSSP) | — | ✓ | ✓ |
| SOAR basic actions | — | ✓ | ✓ |
| SOAR full playbook engine | — | — | ✓ |
| AI playbook generation | — | — | ✓ |
| CERT-In compliance module | ✓ | ✓ | ✓ |
| RBI compliance module | — | ✓ | ✓ |
| DPDP Act module | ✓ | ✓ | ✓ |
| SEBI CSCRF module | — | ✓ | ✓ |
| NIS2 / DORA modules | — | — | ✓ |
| Merkle audit chain | — | ✓ | ✓ |
| HSM encryption | — | — | ✓ |
| SPIFFE/SPIRE identity | — | — | ✓ |
| Cilium eBPF mesh | — | — | ✓ |
| Full HA (3-node) | — | — | ✓ |
| GPU Mistral 7B | — | — | ✓ |
| CPU Mistral (GGUF) | — | ✓ | ✓ |
| USB stick installer | ✓ | ✓ | — |

---

## Feature Details

---

### F-001: Adaptive Resource Detector

**Priority:** P0 — ships day one  
**Tier:** All

On startup, KRON reads:
- Available RAM (`/proc/meminfo`)
- CPU core count (`nproc`)
- Available disk (`df`)
- GPU presence (`nvidia-smi` or ROCm check)

Selects tier automatically and writes `~/.kron/mode` file. No manual config required.

| RAM | Selected mode |
|---|---|
| <12 GB | Nano (DuckDB + embedded queue) |
| 12–32 GB | Standard-lite (ClickHouse single-node, no Redpanda) |
| 32–64 GB | Standard (ClickHouse + Redpanda single-node) |
| 64 GB+ | Standard-full (Mistral CPU enabled) |
| 64 GB+ + GPU | Enterprise-ready (Mistral GPU enabled) |

---

### F-002: eBPF Kernel Agent

**Priority:** P0  
**Tier:** All  
**Language:** Rust (aya framework)

Kernel-space collection using eBPF programs attached to:
- `sys_enter_execve` / `sys_exit_execve` — process creation
- `sys_enter_openat` / `sys_exit_openat` — file access
- `sys_enter_connect` / `sys_exit_connect` — network connections
- `sys_enter_accept` / `sys_exit_accept` — inbound connections
- `sys_enter_read` / `sys_exit_read` — file reads (sensitive paths)
- `sys_enter_write` — file writes (sensitive paths)
- `tcp_v4_connect` kprobe — TCP connection tracking
- XDP program — ingress packet metadata

Uses CO-RE (Compile Once Run Everywhere) for kernel version portability. BTF-enabled kernels only (5.4+). Falls back to agentless SSH on unsupported kernels.

Ring buffer: shared memory between kernel and userspace. Zero-copy event delivery. Default ring buffer size: 64 MB (configurable).

Heartbeat sent to control plane every 30 seconds. Missed heartbeat fires P2 alert within 60 seconds.

---

### F-003: Universal Normalizer

**Priority:** P0  
**Tier:** All

Processes every raw event through the following pipeline:

1. **Format detection** — CEF, LEEF, JSON, XML, syslog RFC3164/5424, Windows XML EventLog, OCSF
2. **Field extraction** — regex-based for unstructured, path-based for structured
3. **Schema mapping** — every field mapped to KRON canonical schema (OCSF-aligned)
4. **Timestamp normalization** — parse any format, convert to UTC epoch nanoseconds
5. **Asset enrichment** — source IP/hostname → asset record (CMDB or auto-discovered)
6. **User identity resolution** — username → canonical user (AD/LDAP lookup, cached 5 min)
7. **GeoIP enrichment** — external IPs → country, city, ASN (MaxMind GeoLite2)
8. **Dedup fingerprint** — xxHash of (tenant_id + source + event_type + key_fields + 1s_bucket)
9. **Severity pre-triage** — basic heuristic scoring before rule engine

Output: KRON canonical event object (see Database.md for schema).

---

### F-004: SIGMA Rule Engine

**Priority:** P0  
**Tier:** All

Full SIGMA specification support including:
- All condition types: keywords, field-value, aggregation
- All operators: contains, startswith, endswith, re, cidr, gt, lt, gte, lte, all, 1of, allof
- Temporal conditions (within X seconds)
- Logsource mapping (product/category/service → KRON source types)
- SIGMA correlation rules (multi-event sequences)

Pipeline:
1. SIGMA YAML → parsed AST
2. AST → optimized query plan
3. Query plan → DuckDB SQL (Nano) or ClickHouse SQL (Standard/Enterprise)
4. Compiled rule stored with hash for change detection
5. Rule hot-reload without service restart

Ships with 3,000+ rules from SIGMA HQ corpus, pre-classified by false-positive rate:
- `production` — FP rate <2%, auto-enabled
- `review` — FP rate 2–10%, requires analyst to enable
- `experimental` — untested, disabled by default

---

### F-005: India Detection Pack

**Priority:** P0  
**Tier:** All

Detection rules specific to India's threat landscape, not covered by generic SIGMA:

**Financial fraud patterns:**
- UPI transaction velocity anomaly (>X transactions/minute from single device)
- Aadhaar API enumeration (sequential UIDAI API calls)
- GST portal credential stuffing
- NPCI gateway unusual access patterns
- DigiLocker bulk document access
- Banking trojan lateral movement patterns (Drinik, AxBanker)

**Indian APT TTPs:**
- SideWinder (APT-C-17) — spearphishing with India-themed lures, DLL sideloading
- Patchwork (APT-C-09) — BADNEWS RAT, Ragnatela RAT indicators
- BITTER (APT-C-08) — MSIL/Bitter RAT, ArtraDownloader
- Transparent Tribe (APT-36) — Crimson RAT, ObliqueRAT
- SilverTerrier — BEC infrastructure indicators

**Regulatory-specific:**
- SWIFT terminal unauthorized access
- Core banking system unusual off-hours access
- Patient record bulk export (ABDM/hospital systems)
- Election system access anomaly

All rules include CERT-In incident category mapping for automatic compliance evidence generation.

---

### F-006: IOC Bloom Filter

**Priority:** P0  
**Tier:** All

In-memory bloom filter for sub-millisecond IOC lookups against:
- Malicious IPs (C2 infrastructure, bulletproof hosting)
- Malicious domains (DGA domains, known C2)
- Malicious file hashes (SHA256 — malware samples)
- Malicious URLs
- Tor exit nodes
- Known proxy/VPN exit IPs

Sources:
- MISP community feeds (refreshed every 5 minutes)
- Abuse.ch (MalwareBazaar, URLhaus, ThreatFox)
- OTX AlienVault (free feeds)
- CERT-In advisories (parsed and ingested)
- Custom feeds (configurable)

Implementation:
- Counting bloom filter (allows deletion on feed update)
- False positive rate: <0.01% at 10M entries
- Memory: ~120 MB for 10M entries at 0.01% FP rate
- Refresh: full rebuild every 5 minutes from latest feed

---

### F-007: ONNX Anomaly Scoring

**Priority:** P0  
**Tier:** All

Four ONNX models running on-device, no GPU required:

**Model 1: Isolation Forest (anomaly score)**
- Input features: login time, failed auth count, data volume, connection count, process count, unique IPs
- Output: anomaly score 0.0–1.0
- Threshold: >0.75 → contribute to risk score
- Inference time: <3ms on CPU

**Model 2: XGBoost UEBA classifier**
- Input features: 30-day baseline deviation on login time, geo, device, data volume
- Output: anomaly probability 0.0–1.0
- Threshold: >0.8 → UEBA flag
- Inference time: <5ms on CPU

**Model 3: Beaconing detector (FFT-based)**
- Input: connection timestamps for a given src→dst pair over 1-hour window
- Output: beaconing score 0.0–1.0 (periodic pattern strength)
- Threshold: >0.7 → C2 beacon candidate
- Inference time: <10ms

**Model 4: Exfil volume scorer**
- Input: bytes out over time window vs 30-day baseline for that asset
- Output: exfil probability 0.0–1.0
- Threshold: >0.85 → potential exfiltration
- Inference time: <3ms

Models exported as ONNX from scikit-learn / XGBoost. Updated via model registry. Version-pinned in deployment config.

---

### F-008: WhatsApp + SMS Alerting

**Priority:** P0  
**Tier:** All

P1 and P2 alerts sent immediately via WhatsApp Business API. P3 and below batched into hourly digest or daily summary depending on config.

**Alert message format:**
```
🔴 KRON ALERT — P1

[Organization Name]
[Time] | [Asset]

[Plain language summary in configured language]

Tap to respond:
1️⃣ Block IP
2️⃣ Isolate machine  
3️⃣ Ignore (false positive)
4️⃣ Escalate to IT vendor
```

**Response handling:**
- User replies with 1/2/3/4
- KRON parses reply → executes SOAR action (if approved in config)
- Destructive actions (isolate) require confirmation: "Reply YES to confirm isolation of ACCOUNTS-PC-01"
- All responses logged to audit trail

**Fallback chain:**
1. WhatsApp Business API (Meta direct or Twilio)
2. SMS via Textlocal (India) or AWS SNS
3. Email SMTP
4. Web UI only (if all channels fail)

**Languages supported:** EN, HI, TA, TE, MR, BN, GU (v1: EN + HI, others in v1.5)

---

### F-009: Autopilot Mode

**Priority:** P1  
**Tier:** All

Zero-staff autonomous operation mode. Enabled per-organization in config.

**Safe actions (auto-execute without approval):**
- Block IP at firewall (via iptables/pf/NGFW API)
- Disable user account (AD/LDAP — reversible)
- Rate-limit suspicious source
- Capture network pcap for evidence
- Create Jira/ticket

**Requires approval (never auto-executes):**
- Host isolation (could disrupt business operations)
- Permanent account deletion
- Any action on a server tagged as `critical` in asset inventory

**Daily summary format (WhatsApp/email):**
```
KRON Daily Summary — [Date]
[Organization]

Yesterday KRON:
• Blocked 3 suspicious IPs from attempting login
• Flagged 1 unusual file access on FINANCE-SERVER
• All threats resolved automatically

No action required. Full report: [URL]
```

---

### F-010: Multilingual Alert Engine

**Priority:** P1  
**Tier:** All

A fine-tuned 8MB ONNX sequence-to-sequence model converts structured alert data into plain-language summaries in Indian languages.

Input: structured alert object (type, asset, user, time, risk_score, indicators)  
Output: 2–3 sentence human-readable summary

Example (Hindi):
> "कल रात 2 बजे अकाउंट्स सर्वर पर दिल्ली से एक अजनबी लॉगिन हुआ। यह पिछले 30 दिनों में कभी नहीं हुआ। आपको तुरंत कार्रवाई करनी चाहिए।"

Languages in v1: English, Hindi  
Languages in v1.5: Tamil, Telugu, Marathi, Bengali, Gujarati

---

### F-011: Multi-Tenancy (MSSP Mode)

**Priority:** P1  
**Tier:** Standard, Enterprise

Single KRON instance serves multiple organizations (tenants) with complete data isolation.

**Isolation guarantees:**
- Every row in every table has `tenant_id`
- ClickHouse row-level security policy enforces tenant filter at DB layer
- Query rewrite middleware injects `WHERE tenant_id = ?` before every query
- JWT tokens carry `tenant_id` claim, validated on every request
- Continuous canary test: cross-tenant query must return 0 rows every 5 minutes

**MSSP portal:**
- Per-tenant dashboard with independent alert queues
- Per-tenant compliance reports
- Per-tenant billing metrics (EPS, storage, endpoints)
- Tenant onboarding wizard (creates isolated schema partition)
- Tenant offboarding (purge all data, exportable)

---

### F-012: No-Code Rule Builder

**Priority:** P1  
**Tier:** All

Visual drag-drop interface for building detection rules without writing SIGMA YAML.

Components:
- **Event filter block** — select source type, field conditions
- **Threshold block** — count, rate, unique count over time window
- **Sequence block** — event A then event B within N seconds
- **Aggregation block** — group by field, apply condition to group
- **Action block** — what to do when rule fires (alert, SOAR action)

Features:
- Test against last 24h of historical data before saving
- Estimated false positive rate shown before activation
- Auto-generates SIGMA YAML for export/import
- Rule versioning and rollback
- Rule performance metrics (match rate, processing time)

---

### F-013: Compliance Engine

**Priority:** P1  
**Tier:** All (CERT-In/DPDP on Nano, full suite on Standard+)

Continuously maps KRON detections and SOAR actions to compliance controls.

**CERT-In (NCIIPC guidelines):**
- Control mapping to all 13 incident categories
- 72-hour breach notification evidence package (auto-generated)
- 180-day log retention verification
- Monthly incident summary report

**RBI (IS Audit Framework):**
- IS audit evidence collection
- Data localization compliance attestation
- Incident response time tracking (IS.1.x controls)
- Third-party access monitoring evidence

**DPDP Act 2023:**
- Personal data access audit trail
- Data breach detection and notification workflow
- Data processing activity log
- Consent violation detection rules

**Report formats:**
- PDF (regulator-ready)
- Excel (detailed evidence)
- JSON (for integration with GRC tools)

---

### F-014: Natural Language Query

**Priority:** P1  
**Tier:** Standard, Enterprise

Analyst types plain English, KRON returns results.

v1 implementation: rule-based NL→SQL using pattern matching + field synonym dictionary  
v1.5 implementation: Mistral 7B for complex multi-part queries

Example queries:
- "Show all failed logins from outside India in the last 6 hours"
- "Which users accessed the finance server after midnight this week"
- "List all processes that made network connections to unknown IPs yesterday"
- "How many P1 alerts did we get last month compared to this month"
- "Show me everything related to user john.doe since Monday"

---

### F-015: USB Stick Installer

**Priority:** P1  
**Tier:** Nano, Standard

Bootable USB that installs KRON on any x86 machine without internet access.

Contents:
- Custom Ubuntu 22.04 minimal base (headless)
- All KRON binaries and container images (offline)
- SIGMA ruleset snapshot
- ONNX models
- MaxMind GeoLite2 database
- Installer script with guided setup wizard

Setup wizard (CLI, no GUI required):
1. Select deployment mode (Nano/Standard auto-detected)
2. Set organization name and admin password
3. Configure alert destinations (WhatsApp number, email)
4. Set retention period
5. Deploy — complete in <15 minutes

Monthly USB update shipping available for air-gapped customers.
