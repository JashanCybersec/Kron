# Enterprise-BuildOrder.md — KRON Enterprise Tier Build Plan

**Prerequisite:** Standard gate must pass before Enterprise work starts.  
**Timeline:** Month 10–12 (14–16 weeks after Standard ships)  
**Key principle:** Enterprise is Standard hardened and scaled — not a different product.

---

## What Enterprise Adds to Standard

Every Enterprise feature is an addition or upgrade. Nothing is removed or rewritten.

| Component | Standard | Enterprise change |
|---|---|---|
| ClickHouse | Single node | Sharded HA (ReplicatedMergeTree, CH Keeper) |
| Redpanda | Single node | 3-node Raft cluster (RF=3) |
| mTLS identity | Self-signed CA | SPIFFE/SPIRE (short TTL SVIDs) |
| Network policy | k8s NetworkPolicy | Cilium eBPF (L7 visibility, Hubble) |
| Secrets | Vault single node | Vault HA Raft + HSM auto-unseal |
| Encryption | OS disk encryption | HSM envelope encryption (DEK per tenant) |
| Audit log | Merkle chain | Same + HSM-signed chain root |
| AI inference | CPU Mistral (GGUF) | GPU Mistral (candle, full precision) |
| SOAR | Basic actions | Full playbook engine + AI generation |
| Deployment | k3s single server | k8s multi-node, anti-affinity rules |
| Observability | Prometheus + Grafana | + Jaeger distributed tracing |
| Compliance | CERT-In, RBI, DPDP, SEBI | + NIS2, DORA |

---

## Sprint 1 (Weeks 1–3) — ClickHouse HA

**The most impactful change — requires careful migration path.**

**New crate: `kron-ch-operator` (or use upstream ClickHouse Operator for k8s)**

```
[ ] Decision: use Altinity ClickHouse Operator or build custom?
    → Use Altinity operator for k8s deployment
    → Write KRON-specific operator config (not upstream defaults)

[ ] ClickHouseCluster CRD: defines shard count, replica count, keeper count
[ ] Default Enterprise layout:
    - 2 shards × 2 replicas = 4 ClickHouse pods
    - 3 ClickHouse Keeper pods (replaces ZooKeeper)
[ ] Data migration: single-node → sharded cluster
    [ ] Pause writes (redirect to Redpanda queue only)
    [ ] Export all data to Parquet (kron-storage parquet exporter)
    [ ] Provision HA cluster
    [ ] Import Parquet into new cluster
    [ ] Resume writes
    [ ] Verify row counts match
    [ ] Zero downtime window: < 2 hours (Redpanda holds events during migration)

[ ] Distributed table: CREATE TABLE events_distributed on cluster
[ ] Shard key: cityHash64(tenant_id) % shard_count (tenant-aware sharding)
[ ] ReplicatedMergeTree on each shard
[ ] Cross-shard query: distributed table handles fan-out automatically
[ ] kron-storage ClickHouse implementation: no changes needed (distributed table is transparent)

[ ] HA test: kill one ClickHouse pod → queries continue (< 5s interruption)
[ ] Scale test: 1M EPS sustained for 30 minutes, 0 events lost
[ ] Replication lag monitor: Prometheus alert if replica lag > 10s
```

**Gate:**
```bash
./scripts/test-clickhouse-ha.sh
# Kill shard-0-replica-0: queries on shard-0 route to replica-1: PASS
# Kill entire shard-1: shard-0 data still queryable: PASS (reduced capacity)
# Data consistency: row counts identical on both replicas after 5 minutes: PASS
# Replication lag: < 1 second under 100K EPS write load: PASS
```

---

## Sprint 2 (Weeks 3–5) — Redpanda HA

```
[ ] Redpanda 3-node cluster: RF=3, Raft consensus
[ ] Anti-affinity: one Redpanda pod per k8s node/rack
[ ] Topic configuration: replication.factor=3 on all kron.* topics
[ ] Producer config: acks=all (wait for all replicas before ack)
[ ] Consumer group: at-least-once delivery verified on node failure
[ ] Topic retention: 72 hours minimum (agent replay window)
[ ] Redpanda Console deployed (management UI)
[ ] HA test: kill one broker → producers/consumers continue automatically
[ ] HA test: kill leader → new leader elected in < 10 seconds
[ ] Data test: no messages lost during broker failure
```

---

## Sprint 3 (Weeks 5–9) — SPIFFE/SPIRE Identity Fabric

**New crate: `kron-identity`**

```
[ ] SPIRE server: 3-node HA cluster (Raft backend)
[ ] SPIFFE trust domain: spiffe://kron.{org_domain}
[ ] SPIRE agent: deployed as DaemonSet on every k8s node
[ ] SVID issuance: X.509 SVIDs, 4-hour TTL
[ ] Auto-rotation: agent rotates SVIDs before expiry (handles without restart)

[ ] Workload registration (one entry per service):
    [ ] spiffe://kron.{domain}/collector
    [ ] spiffe://kron.{domain}/normalizer
    [ ] spiffe://kron.{domain}/stream-processor
    [ ] spiffe://kron.{domain}/alert-engine
    [ ] spiffe://kron.{domain}/query-api
    [ ] spiffe://kron.{domain}/soar
    [ ] spiffe://kron.{domain}/compliance
    [ ] spiffe://kron.{domain}/auth
    [ ] spiffe://kron.{domain}/ai

[ ] mTLS upgrade: replace self-signed CA with SPIFFE SVIDs in all services
    [ ] kron-collector: present SVID as server cert, require client SVID
    [ ] kron-normalizer: use SVID for Redpanda connection
    [ ] kron-stream: use SVID for Redpanda + ClickHouse
    [ ] kron-query-api: present SVID, accept analyst JWT (separate)

[ ] SVID watching: services watch for SVID rotation, reload certs without restart
[ ] Rotation runbook: documented in Runbooks.md (RB-003)
[ ] HA test: kill SPIRE server → SVIDs valid until TTL (4hr window)
[ ] HA test: restart SPIRE → new SVIDs issued automatically

[ ] kron-ctl identity show: prints all registered workload SVIDs and expiry
```

---

## Sprint 4 (Weeks 9–11) — Cilium eBPF Network Policy

```
[ ] Cilium installed as CNI (replaces k8s default CNI)
[ ] Hubble: network flow observability enabled
[ ] Hubble UI: internal network traffic visualization

[ ] CiliumNetworkPolicy resources (one per service pair that needs to communicate):
    [ ] collector → redpanda: allow port 9092
    [ ] normalizer → redpanda: allow port 9092
    [ ] normalizer → clickhouse: allow port 9000 + 8123
    [ ] stream-processor → redpanda: allow port 9092
    [ ] stream-processor → clickhouse: allow port 9000
    [ ] alert-engine → redpanda: allow port 9092
    [ ] alert-engine → clickhouse: allow port 9000
    [ ] query-api → clickhouse: allow port 9000 + 8123
    [ ] query-api → auth: allow port 50051 (gRPC)
    [ ] soar → clickhouse: allow port 9000
    [ ] All others: deny by default

[ ] Test: stream-processor directly accessing query-api: BLOCKED
[ ] Test: query-api directly accessing alert-engine: BLOCKED
[ ] Test: lateral movement simulation: contained to single service: PASS
[ ] Hubble: can visualize actual traffic for audit evidence
```

---

## Sprint 5 (Weeks 11–13) — Vault HA + HSM

```
[ ] Vault 3-node Raft cluster
[ ] Anti-affinity: one Vault pod per k8s node
[ ] HSM auto-unseal: Vault uses HSM for master key (never stored on disk)
[ ] Primary HSM + backup HSM (separate hardware)
[ ] Shamir key shares: 3 shares, 2-of-3 threshold (for Vault unseal without HSM)
[ ] Key escrow: documented procedure for share custody

[ ] Per-tenant DEK: Vault Transit engine, one key per tenant
[ ] DEK rotation: monthly automated rotation via Vault
[ ] ClickHouse cold tier encryption:
    [ ] kron-storage parquet exporter: encrypts Parquet with tenant DEK before upload
    [ ] kron-storage parquet importer: decrypts with tenant DEK on restore

[ ] Dynamic credentials: ClickHouse user credentials issued by Vault, auto-rotated every hour
    [ ] kron-normalizer: requests fresh DB creds from Vault on startup + renewal
    [ ] kron-query-api: same
    [ ] All kron services: same
    [ ] No static DB passwords anywhere in the codebase or config files

[ ] Vault audit log: all secret operations logged
[ ] HA test: kill Vault active node → standby promotes automatically in < 30s
[ ] HSM test: disconnect primary HSM → backup HSM activates in < 5 minutes
[ ] Runbook: RB-002 documented and fire-drilled

[ ] kron-ctl vault status: prints cluster health and SVID/DEK expiry times
```

---

## Sprint 6 (Weeks 13–15) — GPU Mistral + Full SOAR

**GPU Mistral:**
```
[ ] candle crate (Hugging Face Rust inference)
[ ] CUDA 11.8+ support verified on target GPU (NVIDIA A10G or RTX 4090)
[ ] Mistral 7B model: full precision (F16) for GPU, quantized (q4_k_m) for CPU fallback
[ ] Inference service: separate kron-ai pod with GPU nodeSelector
[ ] GPU inference latency: < 500ms (vs 3–8s CPU)
[ ] Fallback: if GPU pod unavailable → CPU inference (graceful degradation)
[ ] Features enabled with GPU:
    [ ] Real-time alert narrative generation (not batched)
    [ ] NL query via Mistral (complex multi-part queries)
    [ ] AI-assisted playbook generation
    [ ] Root cause chain analysis
```

**Full SOAR engine (`kron-soar`):**
```
[ ] Playbook DSL: JSON-defined step sequences
[ ] Built-in action library:
    [ ] isolate_host: Cilium network policy push
    [ ] block_ip: iptables/pf/NGFW API
    [ ] disable_account: AD/LDAP/Vault revoke
    [ ] revoke_credentials: Vault lease revoke
    [ ] capture_evidence: pcap + memory dump + log snapshot
    [ ] create_ticket: Jira, ServiceNow, GitHub Issues
    [ ] notify: WhatsApp, Slack, PagerDuty, email
    [ ] run_script: custom script on target host (with approval)
[ ] Dry-run mode: simulates all actions, reports what would happen
[ ] Approval gate: destructive actions require second analyst approval
[ ] 4-eyes control: no self-approval (approver ≠ requestor)
[ ] AI playbook generation: describe scenario → Mistral generates playbook JSON
[ ] Playbook library: 20 pre-built playbooks for common scenarios
[ ] Playbook test harness: test against historical alert without executing
[ ] Action audit log: every action appended to Merkle chain
[ ] Rollback: isolation and block actions have corresponding rollback actions
```

---

## Sprint 7 (Week 15–16) — Enterprise Gate

**Additional compliance modules:**
```
[ ] NIS2 module: EU directive controls (for Indian subsidiaries of EU companies)
[ ] DORA module: digital operational resilience for financial entities
[ ] ISO 27001 module
```

**Enterprise gate:**
```bash
./scripts/gate-enterprise.sh

# HA resilience tests:
# Kill ClickHouse node: queries continue < 5s: PASS
# Kill Redpanda broker: no events lost: PASS
# Kill SPIRE server: mTLS continues to TTL: PASS
# Kill Vault active: standby promotes < 30s: PASS
# Disconnect primary HSM: backup activates < 5min: PASS

# Security tests:
# SPIFFE rotation: completes < 60min, zero downtime: PASS
# Cilium: cross-service direct call blocked: PASS
# Vault dynamic creds: DB creds rotate automatically: PASS
# HSM: master key never in plaintext on disk: PASS
# Pentest report: no Critical/High open: PASS

# Performance tests:
# 1M EPS sustained 30 minutes: 0 events lost: PASS
# 1B row query: < 3 seconds: PASS
# GPU Mistral inference: < 500ms: PASS

# ALL must pass → Enterprise is shippable
```

---

## Enterprise Customer Onboarding

Enterprise deployments require hands-on professional services:

**Week 1 (remote):**
- Infrastructure review: servers, network, existing security tools
- Data classification: which sources, which compliance frameworks
- Integration mapping: AD/LDAP, ticketing system, NGFW

**Week 2 (on-site):**
- Hardware provisioning and OS installation
- KRON Enterprise deployment via Terraform + Helm
- Agent deployment across endpoint fleet (Ansible)
- Connector configuration (AD, cloud APIs, NGFW)

**Week 3 (on-site):**
- Detection tuning: suppress known FP rules for this environment
- Alert routing: configure WhatsApp + email + ticketing
- Compliance baseline: CERT-In/RBI/DPDP initial posture report
- SOC team training (half-day)

**Week 4 (remote):**
- Hyper-care monitoring: daily check-ins for first 30 days
- Rule tuning based on real alerts
- Runbook customisation for customer environment

**Included in Enterprise license:**
- 3-day on-site deployment
- 30 days hyper-care
- Annual fire drill facilitation
- 24/7 critical incident support (P1 alerts)
