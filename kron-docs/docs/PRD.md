# KRON — Product Requirements Document

**Version:** 1.0  
**Status:** Active  
**Owner:** Jashan (Founder)  
**Last Updated:** 2026

---

## 1. Product Vision

KRON is an Indian-first, on-premise Security Information and Event Management (SIEM) platform designed for organizations that cannot, will not, or should not send their security telemetry to a foreign cloud. It is the first SIEM built around the realities of the Indian market — lean security teams, regulated data environments, cost sensitivity, and the need for zero-expertise operation at the smallest tier.

KRON competes on four axes where every existing SIEM fails India:
- **Data sovereignty** — every byte stays on-premise, air-gap capable
- **Cost** — per-asset pricing, no per-GB ingest tax, runs on existing hardware
- **Operational simplicity** — adaptive self-configuration, WhatsApp alerting, autopilot mode
- **Indian compliance** — CERT-In, RBI, DPDP Act, SEBI built-in from day one

---

## 2. Problem Statement

### 2.1 The Indian SIEM Gap

Existing SIEMs (Splunk, Microsoft Sentinel, QRadar, Wazuh) were designed for US/EU enterprises with dedicated SOC teams, $2M+ security budgets, and cloud-first infrastructure. They fail Indian organizations in the following ways:

| Problem | Impact |
|---|---|
| Cloud-only or cloud-preferred | Violates CERT-In, RBI data localization, DPDP Act |
| Per-GB ingest pricing | Makes full-fidelity logging unaffordable |
| Requires security expertise to operate | 90% of Indian orgs have no dedicated security staff |
| English-only interfaces and alerts | Non-expert staff cannot act on alerts |
| No Indian compliance templates | Manual quarterly compliance assembly |
| No OT/SCADA support | Leaves manufacturing, power, and utilities unprotected |
| Minimum 32–64 GB RAM | Unaffordable hardware for SMBs |

### 2.2 Target Pain

**Primary:** A 200-person NBFC being fined for CERT-In non-compliance because their IT team has no visibility into their own infrastructure.

**Secondary:** A regional hospital with patient data on-premise, no security staff, and a sysadmin who cannot tell if someone is exfiltrating data.

**Tertiary:** An MSSP trying to offer managed security to 50 small businesses but unable to find an affordable, multi-tenant platform that fits on one server.

---

## 3. Target Users

### 3.1 Primary Personas

**Persona 1 — The Overwhelmed IT Admin (Nano/Standard)**
- Works at a 50–500 person company
- Manages everything: network, servers, printers, software
- Zero dedicated security background
- Needs: simple alerts he can act on, WhatsApp notifications, autopilot mode
- Budget: ₹5,000–25,000/month

**Persona 2 — The Lean SOC Analyst (Standard/Enterprise)**
- Works at a mid-market bank, hospital, or manufacturer
- 1–5 person security team covering everything
- Understands security but overwhelmed by alert volume
- Needs: pre-triaged alerts, MITRE mapping, one-click response, compliance reports
- Budget: ₹50,000–3L/month

**Persona 3 — The MSSP Operator (Standard)**
- Runs an IT services company serving 10–100 SMB clients
- Wants to offer managed security as a new revenue line
- Needs: multi-tenancy, per-client dashboards, scalable on one server
- Budget: ₹15,000–50,000/month (charges ₹3,000–10,000 per client)

**Persona 4 — The Enterprise CISO (Enterprise)**
- Works at a large bank, PSU, or telco
- Has a real SOC team but needs to replace expensive foreign SIEM
- Needs: full HA, compliance automation, SOAR, audit trails, custom integrations
- Budget: Custom (replaces ₹40–80L/yr Splunk spend)

### 3.2 Secondary Users

- Compliance officers needing audit evidence
- CISOs presenting board-level risk posture
- Incident responders working active cases
- Security engineers building custom detection rules

---

## 4. Product Tiers

### 4.1 KRON Nano
- **Hardware:** Any x86 machine, 8 GB RAM, 4 cores, 250 GB disk
- **Storage engine:** DuckDB (embedded, zero config)
- **Queue:** Embedded Rust async channel (disk-backed)
- **AI:** ONNX on-device only
- **Scale:** Up to 50 endpoints, 1K EPS
- **Alerting:** WhatsApp, SMS, email
- **Price:** Free (open core) or ₹2,999/month hosted support
- **Target:** SMBs, clinics, schools, small NBFCs

### 4.2 KRON Standard
- **Hardware:** 1–2 dedicated servers, 16–32 GB RAM
- **Storage engine:** ClickHouse single-node
- **Queue:** Redpanda single-node
- **AI:** ONNX + CPU-mode Mistral (optional)
- **Scale:** Up to 500 endpoints, 50K EPS
- **Alerting:** WhatsApp, SMS, email, web UI, mobile app
- **Multi-tenancy:** Yes — MSSP ready
- **Price:** ₹8,000–25,000/month
- **Target:** Mid-market enterprises, MSSPs

### 4.3 KRON Enterprise
- **Hardware:** 3+ dedicated servers, 128 GB RAM/node
- **Storage engine:** ClickHouse sharded HA
- **Queue:** Redpanda 3-node Raft cluster
- **AI:** ONNX + GPU Mistral 7B
- **Security fabric:** SPIFFE/SPIRE, Cilium eBPF mesh
- **Encryption:** HSM envelope encryption, Merkle audit chain
- **Scale:** Unlimited, 1M+ EPS with sharding
- **Alerting:** All channels + SOAR automation
- **Price:** Custom (₹50L–2Cr/yr depending on scale)
- **Target:** Large banks, PSUs, telcos, critical infrastructure

---

## 5. Core Features

### 5.1 Collection
- eBPF kernel agent (Linux, CO-RE, zero-copy ring buffer)
- ETW collector (Windows event tracing)
- Agentless SSH pull (read-only, scheduled or streaming)
- Cloud API puller (AWS CloudTrail, GCP Audit, Azure AD)
- Syslog receiver (UDP 514, TCP, TLS syslog)
- NetFlow/IPFIX/sFlow collector
- OT bridge (Modbus, DNP3, IEC 61850, S7)
- HTTP/gRPC structured log intake
- Kubernetes pod log collector
- Agent heartbeat and fleet management

### 5.2 Normalization
- Universal parser (CEF, LEEF, JSON, XML, custom)
- OCSF schema alignment
- Timestamp normalization (all timezones → UTC)
- GeoIP and ASN enrichment (MaxMind GeoLite2)
- Asset enrichment (CMDB integration)
- User identity resolution (AD/LDAP lookup)
- Deduplication fingerprinting (xxHash)
- Severity triage (P1–P5)

### 5.3 Detection
- SIGMA rule engine (full SIGMA spec support)
- 3,000+ rules imported from open SIGMA corpus
- India-specific detection pack (UPI fraud, Aadhaar abuse, GST scraping, NPCI anomalies)
- Indian APT group TTPs (SideWinder, Patchwork, BITTER, Transparent Tribe)
- IOC bloom filter (in-memory, <1ms lookup, 5-min refresh)
- ONNX anomaly scoring (isolation forest, XGBoost, beaconing detector, exfil scorer)
- UEBA baselines (rolling 30-day window, z-score + MAD)
- Entity graph (user ↔ host ↔ IP ↔ process relationship scoring)
- Temporal correlation engine (multi-event sequence detection)
- Threshold and rate-based rules
- MITRE ATT&CK auto-tagging (tactic + technique + sub-technique)

### 5.4 Alerting
- Risk scoring (0–100 composite score → P1–P5 tier)
- Alert deduplication and grouping (15-minute windows)
- WhatsApp Business API alerting with action buttons
- SMS fallback (Textlocal, AWS SNS India)
- Email (SMTP, daily digest mode)
- Web UI real-time alert queue
- Flutter mobile push notifications
- Plain-language alert summaries (EN/HI/TA/TE/MR)
- Autopilot mode (zero-staff autonomous operation)

### 5.5 Response (SOAR)
- Playbook library with pre-built responses
- No-code drag-drop playbook builder
- AI-assisted playbook generation (Mistral, Enterprise only)
- Dry-run mode (simulate before execute)
- Analyst approval gate for destructive actions
- Response actions: host isolation (Cilium/iptables), credential revoke (AD/LDAP/Vault), firewall block, evidence capture (pcap/memory dump), ticket creation (Jira), notifications
- Action audit log (Merkle-chained)
- Incident timeline (event → detection → response → close)
- Analyst feedback loop (TP/FP labels → retraining queue)

### 5.6 Compliance
- CERT-In compliance module (72-hour breach reporting, log retention evidence)
- RBI compliance module (IS audit, data localization evidence)
- DPDP Act module (data audit trail, breach notification)
- SEBI CSCRF module
- NIS2 and DORA modules (Enterprise)
- Continuous evidence collection (every alert + action mapped to control)
- Automated report generation (PDF, scheduled or on-demand)
- Compliance posture dashboard (real-time pass/fail per control)
- Gap alerts before audit dates
- Evidence package export for auditors

### 5.7 Analyst Interface
- SolidJS web app (browser-only, no install)
- Alert queue with filter, sort, search
- Natural language query (plain English → ClickHouse SQL)
- MITRE ATT&CK heatmap (live, 7/30/90 day views)
- Case management (group alerts → incidents)
- Incident timeline view
- No-code rule builder (drag-drop + SIGMA import)
- Asset inventory and risk posture
- User behaviour analytics dashboard
- Compliance posture dashboard
- Flutter mobile app (iOS + Android)

---

## 6. Non-Functional Requirements

### 6.1 Performance
- Ingest latency: <500ms end-to-end (source to alert)
- Alert generation: <2 seconds from event ingestion
- Query on 1 billion rows: <3 seconds (ClickHouse)
- IOC lookup: <1ms (bloom filter)
- ONNX inference: <5ms per event
- API response time: <200ms p99
- UI load time: <2 seconds initial, <500ms navigation

### 6.2 Reliability
- Nano tier: no HA, single node, agent local buffer on outage
- Standard tier: single server, agent buffer + Redpanda retention for recovery
- Enterprise tier: 99.9% uptime SLA, full HA, RPO <1 minute, RTO <2 hours

### 6.3 Security
- Zero telemetry leaves the organization
- Air-gap capable (all tiers)
- mTLS on all inter-service communication
- AES-256-GCM encryption at rest
- Merkle-chained tamper-evident audit log
- No static secrets — Vault dynamic credentials
- RBAC with tenant isolation
- All admin destructive actions require 4-eyes approval (Enterprise)

### 6.4 Scalability
- Nano: 1K EPS, 50 endpoints
- Standard: 50K EPS, 500 endpoints
- Enterprise: 1M+ EPS, unlimited endpoints (horizontal sharding)
- Storage scales independently via cold tier offload to object store

### 6.5 Compatibility
- Linux: Ubuntu 20.04/22.04/24.04, RHEL 8/9, Debian 11/12, Amazon Linux 2/2023
- Windows: Server 2016/2019/2022, Windows 10/11
- Kubernetes: 1.24+
- Browsers: Chrome 100+, Firefox 100+, Edge 100+
- Mobile: iOS 15+, Android 10+

---

## 7. Out of Scope for v1

- Mistral 7B full inference (deferred to v1.5)
- SPIFFE/SPIRE identity fabric (Enterprise v1, Standard v2)
- HSM hardware encryption (Enterprise v1, Standard v2)
- Full SOAR playbook library (basic SOAR in v1, full library v1.5)
- macOS agent (v2)
- SaaS/hosted offering (v2)
- Custom threat intel feed management UI (v2)

---

## 8. Success Metrics

### 8.1 Product Metrics
- Time to first alert after install: <30 minutes
- False positive rate: <5% on default ruleset
- Alert response rate (analyst acts within 1 hour): >80%
- Compliance report generation time: <5 minutes

### 8.2 Business Metrics
- Month 6: 3 paying design partners
- Month 12: 10–15 paying customers, ₹50–80L ARR
- Month 18: 50+ customers, MSSP programme launched
- Month 24: ₹3–5Cr ARR, SOC 2 Type II certified

---

## 9. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| eBPF kernel compatibility failure | Medium | High | CO-RE, kernel matrix CI, SSH fallback |
| Multi-tenancy data leak | Low | Critical | 4-gate isolation, continuous canary tests |
| KRON itself compromised | Low | Critical | Minimal attack surface, KRON monitors KRON |
| No SOC 2 → enterprise deals stall | High | High | Start SOC 2 process month 3 |
| GPU requirement blocks Mistral adoption | High | Medium | CPU-mode Mistral, template fallback |
| eBPF engineer hire fails | Medium | High | Budget higher, contract option |

---

## 10. Glossary

| Term | Definition |
|---|---|
| EPS | Events per second — measure of ingest throughput |
| SIGMA | Open standard for detection rule format |
| ONNX | Open Neural Network Exchange — portable ML model format |
| CO-RE | Compile Once Run Everywhere — eBPF portability mechanism |
| BTF | BPF Type Format — kernel type information for CO-RE |
| UEBA | User and Entity Behaviour Analytics |
| IOC | Indicator of Compromise |
| TTP | Tactics, Techniques and Procedures (MITRE ATT&CK) |
| MSSP | Managed Security Service Provider |
| DEK | Data Encryption Key |
| KEK | Key Encryption Key |
| SVID | SPIFFE Verifiable Identity Document |
| Merkle chain | Cryptographic linked-list providing tamper evidence |
