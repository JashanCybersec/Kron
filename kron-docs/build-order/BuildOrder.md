# BuildOrder.md — KRON Master Build Sequence

**Version:** 1.0  
**Rule:** This file governs what gets built, in what order, and why.  
**Rule:** Do not start a tier until the previous tier's gate passes.  
**Rule:** Do not start a component until its dependencies are marked `[x]` complete.

---

## Why This Order

```
Standard → Nano → Enterprise

NOT: Nano → Standard → Enterprise
NOT: All three in parallel
NOT: Enterprise → Standard → Nano
```

Standard is built first because:
- Its storage (ClickHouse) and bus (Redpanda) are reused in Enterprise — same code
- Its storage abstraction trait enables Nano's DuckDB swap in 2 weeks
- It is the tier that generates revenue fastest (mid-market India)
- It proves the core detection pipeline before adding HA complexity
- Design partners run Standard — they validate the product exists before Enterprise is built

Nano is derived from Standard (not built from scratch):
- Swap `kron-storage` ClickHouse impl → DuckDB impl (2 weeks)
- Swap `kron-bus` Redpanda impl → embedded channel impl (1 week)
- Add USB installer (2 weeks)
- Total: 5 weeks after Standard ships

Enterprise is Standard with upgrades (not a rebuild):
- ClickHouse single node → sharded HA (config + operator, 4 weeks)
- Add SPIFFE/SPIRE identity layer (new crate, 4 weeks)
- Add Cilium network policy (config, 2 weeks)
- Add HSM key management (2 weeks)
- Add GPU Mistral inference (2 weeks)
- Total: 14–16 weeks after Standard ships

---

## Tier Gates

A tier is not "done" until its gate passes. No exceptions.

### Standard Gate (before Nano or Enterprise work starts)
```bash
./scripts/gate-standard.sh
# Must pass:
# 1. Agent installs on Ubuntu 22.04 in < 5 minutes
# 2. Events appear in ClickHouse within 60 seconds of install
# 3. Brute force attack simulation → P1 alert → WhatsApp within 2 minutes
# 4. Cross-tenant isolation test: 0 rows returned
# 5. 50K EPS sustained for 30 minutes: 0 events lost
# 6. 3 design partners confirm it works on their real infrastructure
```

### Nano Gate (before Nano is shipped to customers)
```bash
./scripts/gate-nano.sh
# Must pass:
# 1. Full install on machine with exactly 8 GB RAM completes in < 15 minutes
# 2. USB installer boots and installs on 3 different hardware configs
# 3. All Standard gate tests pass on DuckDB (adapted for single-tier)
# 4. Autopilot mode: attack simulation → auto-blocked → WhatsApp summary
# 5. Machine with 8 GB RAM handles 1K EPS for 60 minutes: stable memory usage
```

### Enterprise Gate (before Enterprise is sold to customers)
```bash
./scripts/gate-enterprise.sh
# Must pass:
# 1. Kill one ClickHouse node: queries continue with < 5s interruption
# 2. Kill one Redpanda broker: no events lost, replication catches up
# 3. Kill one SPIRE server: mTLS continues until SVID TTL, new SVIDs issued on restart
# 4. Full CA rotation (SPIRE): completes in < 60 min with zero downtime
# 5. Pentest report: no Critical or High findings unresolved
# 6. 1M EPS sustained for 30 minutes: 0 events lost
```

---

## Component Build Order Within Standard

The components inside Standard also have a strict build order based on dependencies.

```
Level 0 (no dependencies):
  kron-types

Level 1 (depends only on kron-types):
  kron-storage
  kron-bus
  kron-auth

Level 2 (depends on Level 1):
  kron-agent       (needs kron-types)
  kron-collector   (needs kron-types, kron-bus)
  kron-ai          (needs kron-types)

Level 3 (depends on Level 2):
  kron-normalizer  (needs kron-collector, kron-bus, kron-storage)
  kron-stream      (needs kron-bus, kron-storage, kron-ai)

Level 4 (depends on Level 3):
  kron-alert       (needs kron-stream, kron-storage, kron-ai)
  kron-compliance  (needs kron-storage, kron-alert)

Level 5 (depends on Level 4):
  kron-soar        (needs kron-alert, kron-storage, kron-auth)
  kron-query-api   (needs everything)
```

**Rule:** Never start a Level N component before all Level N-1 components have passing tests.

---

## The Minimum Viable Detection (MVD)

Before building UI, mobile, SOAR, or compliance — prove this works:

```
eBPF agent → kron-collector → kron-normalizer → ClickHouse
                                                      ↓
                                              kron-stream (SIGMA + ONNX)
                                                      ↓
                                              kron-alert → WhatsApp
```

This pipeline — 6 components — is the entire value proposition of KRON.
Everything else (UI, mobile, SOAR, compliance) is built on top of this.
Do not build anything else until this pipeline works end-to-end on real infrastructure.

MVD acceptance test:
```bash
./scripts/mvd-test.sh
# 1. Run on real Ubuntu 22.04 server (not a container)
# 2. Install agent
# 3. Run: for i in {1..100}; do ssh invalid@localhost; done
# 4. Wait 60 seconds
# 5. Assert: WhatsApp message received on configured number
# 6. Assert: Alert in ClickHouse with correct tenant_id
# PASS or FAIL — no partial credit
```

---

## See Also

- `Standard-BuildOrder.md` — detailed week-by-week Standard build
- `Nano-BuildOrder.md` — detailed Nano derivation steps
- `Enterprise-BuildOrder.md` — detailed Enterprise upgrade steps
- `ComponentDependencies.md` — full dependency graph with justifications
- `MilestoneChecklist.md` — go/no-go checklists for each milestone
