# MilestoneChecklist.md — KRON Go/No-Go Checklists

**Purpose:** Before declaring any milestone complete, run the relevant checklist.
A milestone is NOT complete until every item is checked.
Partial completion is not completion.

---

## M0: Development Environment Ready

**Run:** `./scripts/dev-health-check.sh`

```
[ ] cargo build --workspace: zero errors, zero warnings
[ ] cargo clippy --workspace: zero warnings
[ ] cargo fmt --check: passes
[ ] cargo audit: zero vulnerabilities
[ ] cargo deny check: passes (licenses, bans, advisories)
[ ] ./scripts/dev-up.sh: completes in < 2 minutes
[ ] ClickHouse reachable: curl http://localhost:8123/ping → "Ok."
[ ] Redpanda reachable: rpk cluster health → all brokers healthy
[ ] MinIO reachable: curl http://localhost:9000/minio/health/live → 200
[ ] Prometheus reachable: curl http://localhost:9090/-/ready → 200
[ ] Grafana reachable: http://localhost:3000 → login page
[ ] Pre-commit hooks installed and working
[ ] GitHub Actions CI pipeline runs on dummy PR → all checks green
[ ] DECISIONS.md has all 16 initial ADRs
[ ] PHASES.md has all phases defined
[ ] CodeStructure.md matches actual directory layout
```

---

## M1: MVD (Minimum Viable Detection) Complete

**Run:** `./scripts/mvd-test.sh`

```
[ ] kron-agent installs on Ubuntu 22.04 in < 5 minutes
[ ] kron-agent installs on Ubuntu 20.04: works
[ ] kron-agent installs on RHEL 9: works
[ ] Agent appears in ClickHouse agents table within 30 seconds of install
[ ] SSH failed login generates event in ClickHouse within 10 seconds
[ ] Network connection to external IP generates event within 10 seconds
[ ] Process creation (bash, curl) generates event within 10 seconds
[ ] Syslog UDP test event: appears in ClickHouse within 5 seconds
[ ] All events have correct tenant_id
[ ] Cross-tenant isolation: zero rows returned for wrong tenant
[ ] Dedup: same event 5 times in 1 second → 1 event in ClickHouse (not 5)
[ ] Agent heartbeat: agent_last_seen updates every 30 seconds
[ ] Agent dark: stop agent → P2 alert fires in ClickHouse within 90 seconds
[ ] kron-ctl health: all services green
[ ] kron-ctl events query: returns events from last hour
```

---

## M2: Detection Engine Complete

**Run:** `./scripts/test-detection-pipeline.sh`

```
[ ] SIGMA rule import: 3000+ rules imported, 0 parse errors
[ ] SIGMA rule compile: > 95% compile to valid ClickHouse SQL
[ ] Production rules enabled: all rules with FP < 2% auto-enabled
[ ] IOC bloom filter: loaded with 1M+ IOCs
[ ] IOC lookup: p99 < 1ms (measured over 10,000 lookups)
[ ] Brute force simulation: "10 failed logins in 60 seconds" → SIGMA rule fires
[ ] C2 simulation: connection to known malicious IP → IOC hit → alert fired
[ ] ONNX anomaly: login from new country scores > 0.75
[ ] ONNX anomaly: normal login scores < 0.3
[ ] Risk scorer: IOC hit on critical asset → risk_score >= 80 (P1)
[ ] MITRE tagging: brute force alert tagged T1110 (Brute Force)
[ ] Alert dedup: 100 brute force events in 15 min → 1 alert (not 100)
[ ] Processing latency: event ingestion → alert creation p99 < 500ms
[ ] Throughput: 10K EPS sustained 10 minutes: 0 events lost
[ ] India pack: UPI fraud pattern rule exists and compiles
[ ] India pack: SideWinder APT rule exists and compiles
```

---

## M3: Alert Delivery Complete

**Run on real phone:** `./scripts/test-alert-delivery.sh`

```
[ ] WhatsApp: P1 alert → WhatsApp message received in < 30 seconds
[ ] WhatsApp: message contains: org name, severity, asset, plain-language summary
[ ] WhatsApp: message contains action buttons (1/2/3/4)
[ ] WhatsApp reply "1": IP blocked in iptables on target server
[ ] WhatsApp reply "2": confirmation sent, then isolation executed
[ ] WhatsApp reply "3": alert marked false positive in ClickHouse
[ ] Hindi summary: WhatsApp message in Hindi readable and correct (human review)
[ ] SMS fallback: disable WhatsApp → SMS received in < 60 seconds
[ ] Email fallback: disable both → email received in < 5 minutes
[ ] Rate limit: 11 P3 alerts in 1 hour → 10 WhatsApp sent, 1 held
[ ] P1 bypasses rate limit: P1 always sends immediately
[ ] Autopilot: enable autopilot mode → brute force → IP auto-blocked → WhatsApp summary
[ ] Daily summary: advance clock 24h → daily summary WhatsApp received
```

---

## M4: Web UI Complete

**Human walkthrough — run with actual browser:**

```
Auth:
[ ] Login page loads in < 2 seconds
[ ] Valid credentials + TOTP: redirects to dashboard
[ ] Invalid password: shows error, does not crash
[ ] Expired JWT: redirects to login, does not show blank page
[ ] Session timeout: after 8 hours, redirected to login

Dashboard:
[ ] Loads in < 3 seconds
[ ] P1 alert count metric card shows correct number (verify against ClickHouse)
[ ] Alert trend chart shows data for last 7 days
[ ] MITRE mini-heatmap shows at least 1 coloured cell
[ ] Real-time: new alert fires → metric card updates without page refresh

Alert Queue:
[ ] All open alerts visible
[ ] P1 alerts appear before P2 appears before P3
[ ] Severity filter: select P1 only → only P1 shown
[ ] Status filter: open only → no resolved alerts shown
[ ] Clicking alert expands inline panel (no page navigation)
[ ] Inline panel: narrative in English shows
[ ] Inline panel: Hindi toggle works
[ ] Inline panel: evidence events table shows matching events
[ ] Inline panel: MITRE technique link goes to correct URL
[ ] "Acknowledge" button: alert status changes, audit log entry created
[ ] "Block IP" button: confirmation dialog appears, executes on confirm
[ ] Keyboard J: moves to next alert
[ ] Keyboard A: acknowledges current alert

Event Search:
[ ] NL query "failed logins last hour": returns results
[ ] Results table: sortable by timestamp
[ ] Click event row: shows all 60+ fields
[ ] SQL view toggle: shows generated SQL
[ ] Time range: "Last 6 hours" preset works
[ ] Empty results: shows helpful empty state, not blank page

MITRE Heatmap:
[ ] Full matrix renders without overflow
[ ] Cells with hits are coloured (amber scale)
[ ] Hover: tooltip shows technique name and hit count
[ ] Click cell: filters alert queue to that technique
[ ] 7d/30d/90d toggle: updates heatmap

General:
[ ] Dark mode toggle works, persists on refresh
[ ] Works at 1920×1080: no horizontal scroll
[ ] Works at 1366×768: no content cut off
[ ] No console errors in browser DevTools
[ ] All API calls return 200 (check Network tab)
```

---

## M5: Standard Tier Complete (Standard Gate)

**Run:** `./scripts/gate-standard.sh`

```
Technical:
[ ] All previous milestone checklists passed
[ ] 50K EPS sustained 60 minutes: 0 events lost
[ ] 1B row query in ClickHouse: < 3 seconds
[ ] Cross-tenant isolation: automated canary running every 5 minutes
[ ] Internal pentest completed
[ ] All Critical/High pentest findings resolved
[ ] cargo audit: zero advisories
[ ] SBOM generated
[ ] All 4 runbooks (RB-001 through RB-004) documented and fire-drilled

Operational:
[ ] One-line installer works on: Ubuntu 20.04, 22.04, 24.04, RHEL 9
[ ] Helm chart deploys cleanly on k3s 1.28
[ ] Backup/restore: full restore tested, RTO measured (record here: ___ minutes)
[ ] Monitoring: Prometheus + Grafana deployed and showing real metrics
[ ] All Prometheus alerts tuned: no false positive meta-alerts

Product:
[ ] 3 design partners have been using KRON Standard in production for ≥ 30 days
[ ] Each design partner confirms: events flowing, alerts received
[ ] At least 1 real attack detected and alerted on in production
[ ] CERT-In compliance report generated for at least 1 design partner
[ ] Zero P0 or P1 bugs open in issue tracker

Before Enterprise or Nano work starts:
[ ] This checklist complete: YES / NO
[ ] Sign-off from: [name] on [date]
```

---

## M6: Nano Tier Complete

**Run:** `./scripts/gate-nano.sh`

```
[ ] DuckDB: all Standard gate technical tests pass (adapted for DuckDB)
[ ] Cross-tenant isolation: works on DuckDB (same canary test)
[ ] 8GB RAM machine: installs cleanly in < 15 minutes
[ ] 8GB RAM machine: idle memory < 2GB
[ ] 8GB RAM machine: 1K EPS for 60 minutes, stable memory (no leak)
[ ] USB installer: tested on 3 different x86_64 hardware configs (list them):
    [ ] Hardware 1: ___________________ — PASS/FAIL
    [ ] Hardware 2: ___________________ — PASS/FAIL
    [ ] Hardware 3: ___________________ — PASS/FAIL
[ ] Autopilot mode: brute force → auto-blocked → WhatsApp summary: PASS
[ ] Nano → Standard upgrade path: Parquet data migrates, no loss: PASS
[ ] kron-ctl mode show: prints correct mode on both 8GB and 32GB machines
[ ] All SIGMA production rules work on DuckDB
[ ] IOC bloom filter: same performance on Nano as Standard

Sign-off: [name] on [date]
```

---

## M7: Enterprise Tier Complete

**Run:** `./scripts/gate-enterprise.sh`

```
HA resilience (each test run 3 times, must pass all 3):
[ ] Kill ClickHouse shard-0-replica-0: queries continue, < 5s interruption
[ ] Kill Redpanda broker-0: no events lost, replication catches up in < 60s
[ ] Kill SPIRE server-0: mTLS continues to SVID TTL, new SVIDs issued on restart
[ ] Kill Vault active node: standby promotes in < 30s, all services reconnect
[ ] Disconnect primary HSM: backup HSM activates in < 5 minutes, Vault stays unsealed
[ ] Kill entire rack/AZ: other AZs continue, agents buffer and replay on reconnect

Security:
[ ] SPIFFE CA rotation: completes in < 60 minutes, zero downtime
[ ] Cilium: direct service-to-service call (stream → query-api): BLOCKED
[ ] Vault: all DB credentials are dynamic (no static passwords): VERIFIED
[ ] HSM: master key cannot be retrieved without physical HSM access: VERIFIED
[ ] Pentest by CERT-In empanelled auditor: no Critical/High open

Performance:
[ ] 1M EPS sustained 30 minutes: 0 events lost
[ ] 1B row ClickHouse query: < 3 seconds
[ ] GPU Mistral inference: < 500ms p99
[ ] SPIFFE SVID issuance: < 100ms

Compliance:
[ ] CERT-In report: generated in < 5 minutes
[ ] RBI IS audit report: generated in < 5 minutes
[ ] DPDP evidence export: complete and accurate

Sign-off: [name] on [date]
```

---

## M8: v1.0 GA Launch

```
Product:
[ ] Standard gate: PASSED
[ ] Nano gate: PASSED
[ ] Enterprise gate: PASSED
[ ] 3 design partners live on Standard: CONFIRMED
[ ] 1 Enterprise POC scheduled: CONFIRMED
[ ] Zero P0/P1 bugs open

External:
[ ] kron.security website live: pricing, features, documentation
[ ] Documentation site live (generated from /docs)
[ ] SOC 2 Type I audit submitted (or scheduled)
[ ] CERT-In empanelment application submitted
[ ] Legal: DPA template ready for enterprise customers
[ ] Support process: defined and staffed

Business:
[ ] 10+ customers in pipeline (any tier)
[ ] MSSP partner programme: at least 2 partners enrolled
[ ] ARR target: ₹50–80L within 90 days of GA: plan exists

Sign-off: [name] on [date]
```
