# KRON — Roadmap

**Version:** 1.0  
**Principle:** Roadmap is driven by customer pain, not internal preference. First 15 customers override any plan below.

---

## v1.0 — Foundation (Month 1–12)

### Must ship (P0)
- [ ] Adaptive resource detector (auto Nano/Standard/Enterprise mode)
- [ ] eBPF Linux agent (CO-RE, kernel 5.4+)
- [ ] ETW Windows collector
- [ ] Agentless SSH collection
- [ ] Syslog / NetFlow receiver
- [ ] Universal normalizer (OCSF schema)
- [ ] DuckDB storage (Nano)
- [ ] ClickHouse storage (Standard/Enterprise)
- [ ] Parquet cold store (all tiers)
- [ ] SIGMA rule engine (full spec)
- [ ] India detection pack (UPI, Aadhaar, GST, Indian APT TTPs)
- [ ] IOC bloom filter + MISP/Abuse.ch feeds
- [ ] ONNX anomaly scoring (4 models)
- [ ] MITRE ATT&CK auto-tagging
- [ ] Risk scorer (composite 0–100)
- [ ] Alert dedup + grouping
- [ ] WhatsApp Business API alerting
- [ ] SMS fallback (Textlocal)
- [ ] Plain language alert summaries (EN + HI)
- [ ] Autopilot mode
- [ ] SolidJS web UI (alert queue, dashboard, event search, MITRE map)
- [ ] No-code rule builder
- [ ] CERT-In compliance module
- [ ] DPDP Act module
- [ ] REST + WebSocket API
- [ ] Agent fleet management (heartbeat, cert rotation)
- [ ] Multi-tenancy with 4-gate isolation (Standard+)
- [ ] mTLS inter-service (self-signed CA, Nano/Standard)
- [ ] Merkle audit chain (Standard+)
- [ ] Docker Compose installer (Nano)
- [ ] Helm chart installer (Standard/Enterprise)
- [ ] USB stick installer (Nano)
- [ ] One-line install script
- [ ] Prometheus + Grafana observability

### Should ship (P1)
- [ ] Cloud API puller (AWS CloudTrail, GCP Audit, Azure AD)
- [ ] OT bridge (Modbus, DNP3)
- [ ] Flutter mobile app (iOS + Android)
- [ ] Natural language query (rule-based v1)
- [ ] SOAR basic actions (block IP, notify, ticket)
- [ ] RBI compliance module
- [ ] SEBI CSCRF module
- [ ] CPU Mistral (llama.cpp, Standard)
- [ ] UEBA baselines + entity graph
- [ ] Vault secrets management (Standard)
- [ ] Ansible agent deployment playbooks
- [ ] kron-ctl admin CLI

---

## v1.5 — Intelligence (Month 13–18)

- [ ] GPU Mistral 7B inference (Enterprise)
- [ ] Full SOAR playbook engine with AI generation
- [ ] NL query via Mistral (complex multi-part queries)
- [ ] Root cause chain analysis (Mistral)
- [ ] Tamil, Telugu, Marathi, Bengali, Gujarati alert summaries
- [ ] SPIFFE/SPIRE identity fabric (Enterprise)
- [ ] Cilium eBPF mesh (Enterprise)
- [ ] HSM envelope encryption (Enterprise)
- [ ] Full HA Enterprise deployment (3-node all components)
- [ ] Connector SDK (third-party integrations)
- [ ] Okta connector
- [ ] CrowdStrike Falcon connector
- [ ] Palo Alto NGFW connector
- [ ] Cisco ISE connector
- [ ] macOS agent
- [ ] IEC 61850 OT protocol support
- [ ] Case management UI (full)
- [ ] Custom threat intel feed management
- [ ] SOC 2 Type I certification (submit)

---

## v2.0 — Scale (Month 19–24)

- [ ] KRON MSSP portal (partner-facing)
- [ ] SOC 2 Type II certification
- [ ] CERT-In empanelment
- [ ] SaaS / hosted option (India data center only)
- [ ] Model retraining pipeline (customer feedback loop → new ONNX models)
- [ ] Threat intelligence sharing between KRON instances (opt-in)
- [ ] Advanced correlation (graph-based attack path detection)
- [ ] ServiceNow connector
- [ ] SAP connector
- [ ] Splunk migration tool (import Splunk searches as SIGMA rules)
- [ ] Sentinel migration tool
- [ ] KRON API marketplace (third-party connectors)
- [ ] Mobile app: full case management
- [ ] Offline model update (USB) for air-gapped customers

---

## Deliberately Not on Roadmap

- US/EU localization (focus India first, expand only after ₹5Cr ARR)
- Blockchain-based audit (Merkle chain already provides tamper evidence without the complexity)
- On-premise hardware appliance (software-only is more profitable)
- Building our own threat intel feed (MISP community + Abuse.ch is sufficient for v2)
