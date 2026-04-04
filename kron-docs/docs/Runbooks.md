# KRON — Operational Runbooks

**Version:** 1.0  
**Purpose:** Step-by-step recovery procedures for every major failure scenario.  
**Rule:** Every runbook must be fire-drilled every 6 months. Results appended to this file.

---

## Runbook Index

| ID | Scenario | Severity | RTO |
|---|---|---|---|
| RB-001 | ClickHouse full cluster loss | Critical | <2 hours |
| RB-002 | HSM failure | Critical | <20 min (backup HSM) / <2hr (Shamir) |
| RB-003 | SPIRE trust root compromise | Critical | <60 min |
| RB-004 | Rogue admin action detected | Critical | <5 min containment |
| RB-005 | Redpanda cluster loss | High | <30 min |
| RB-006 | KRON itself compromised | Critical | Immediate isolation |
| RB-007 | Agent mass failure | High | <15 min |
| RB-008 | ClickHouse single node loss (HA) | Medium | Automatic (<5 min) |
| RB-009 | Vault sealed unexpectedly | High | <20 min |
| RB-010 | Schema migration failure | High | <30 min |

---

## RB-001: ClickHouse Full Cluster Loss

**Trigger:** All ClickHouse nodes unresponsive. Prometheus alert: `KRONClickHouseDown`. SOC sees "Storage unavailable" in UI.

### Pre-requisites
- Access to backup object store (MinIO/S3) credentials — stored in Vault at `kron/backup/object-store-key`
- Two-engineer approval required to retrieve backup credentials
- Backup manifest at: `s3://kron-backups/manifests/latest.json`

### Steps

**Step 1 — Declare incident and freeze writes (0–2 min)**
```bash
# Pause Redpanda consumers to prevent data loss
kron-ctl redpanda consumer-group pause --group kron-normalizer
kron-ctl redpanda consumer-group pause --group kron-stream-processor
# Events now queue in Redpanda — not lost
kron-ctl ui banner set "Data temporarily unavailable — pipeline paused"
```

**Step 2 — Diagnose scope (2–10 min)**
```bash
# Check pod status
kubectl get pods -n kron | grep clickhouse
# Check disk health on each node
kubectl exec -n kron clickhouse-0 -- df -h
kubectl exec -n kron clickhouse-0 -- smartctl -a /dev/nvme0

# If partial loss (1 node down) → replica promotion, skip to step 6
# If full loss → continue
```

**Step 3 — Provision fresh ClickHouse nodes (10–20 min)**
```bash
# If nodes are recoverable (software issue):
kubectl delete pod -n kron clickhouse-0 clickhouse-1  # force restart
# If hardware failure — provision new nodes via Terraform:
cd /opt/kron-deploy/terraform && terraform apply -target=module.clickhouse
```

**Step 4 — Restore schema (20–25 min)**
```bash
kubectl exec -n kron clickhouse-0 -- bash -c "
  clickhouse-client < /kron/migrations/001_initial_schema.sql
  clickhouse-client < /kron/migrations/002_indexes.sql
  # Apply all migrations in order
"
# Verify schema
kron-ctl clickhouse schema-check
```

**Step 5 — Restore from Parquet backup (25 min – 2 hours)**
```bash
# Retrieve backup credentials (requires 2-engineer approval)
BACKUP_KEY=$(vault kv get -field=access_key kron/backup/object-store-key)
BACKUP_SECRET=$(vault kv get -field=secret_key kron/backup/object-store-key)

# Download latest Parquet snapshot
kron-ctl backup restore \
  --source s3://kron-backups/snapshots/latest/ \
  --target clickhouse \
  --priority last-7-days  # restore recent data first
# Older data restores in background
```

**Step 6 — Replay Redpanda backlog (parallel with step 5)**
```bash
# Resume consumers — fills gap from last snapshot to now
kron-ctl redpanda consumer-group resume --group kron-normalizer
kron-ctl redpanda consumer-group resume --group kron-stream-processor
```

**Step 7 — Validate before reopening (post-restore)**
```bash
kron-ctl clickhouse integrity-check
# Output: row counts vs backup manifest

kron-ctl test tenant-isolation
# Output: PASSED — 0 cross-tenant rows

kron-ctl test known-queries
# Runs 5 test queries, verifies expected results

kron-ctl ui banner clear
```

**Step 8 — Close incident**
- Notify SOC lead: pipeline restored, lag cleared
- Write incident report within 24h
- Post-mortem within 72h
- Update this runbook if process needs adjustment

**RTO targets:** <2 hours full restore. 7-day hot data priority.  
**RPO target:** <1 minute (Redpanda replay fills the gap).

---

## RB-002: HSM Failure

**Trigger:** Vault reports HSM unreachable. Vault seals itself. Prometheus alert: `KRONVaultSealed`.

### Pre-requisites — Key Escrow Structure
The master KEK is split into 3 Shamir shares:
- Share 1: CTO — offline USB, location: [document location in secure internal system]
- Share 2: Lead SRE — offline USB, location: [document location]
- Share 3: Legal counsel — sealed envelope, location: [document location]
Any 2 of 3 shares reconstruct the KEK.

### Steps

**Step 1 — Confirm failure and assess impact (0–5 min)**
```bash
vault status
# If Status: sealed → HSM failure confirmed
# Services using cached DEKs continue working for ~1 hour (DEK TTL)
# Detection pipeline continues — only secret rotation affected
```

**Step 2 — Try backup HSM first (5–20 min)**
```bash
# Update Vault config to backup HSM
kubectl edit configmap -n kron vault-config
# Change: hsm_lib_path to backup HSM path

kubectl rollout restart deployment/vault -n kron
vault status
# If unsealed → backup HSM working. Continue operations. Alert resolved.
```

**Step 3 — If backup HSM also failed: Shamir reconstruction (20–60 min)**
```bash
# Page both keyholders simultaneously via out-of-band channel
# Both travel to secure location with USB drives

# On air-gapped laptop (never on a networked machine):
vault operator unseal  # Enter share 1
vault operator unseal  # Enter share 2
# → Vault unsealed

# Immediately provision replacement HSM
# Re-seal Vault with new HSM before any other operations
```

**Step 4 — Rotate all DEKs after recovery**
```bash
kron-ctl keys rotate-all-deks
# Rotates per-tenant DEKs
# Re-encrypts any data encrypted under potentially exposed keys
# Writes rotation record to audit log
```

**Step 5 — Replace failed HSM hardware (within 48h)**
- Order replacement hardware
- Sync to backup HSM
- Restore primary + backup redundancy before closing incident

**SLA:** Backup HSM activation <20 min. Full Shamir recovery <2 hours. Detection pipeline stays live throughout.

---

## RB-003: SPIRE Trust Root Compromise

**Trigger:** Suspected or confirmed compromise of SPIRE server. Unauthorized SVID issuance detected.

**CRITICAL: Do NOT revoke old CA before new CA is trusted by all workloads. This causes a cluster-wide mTLS blackout.**

### Safe rotation sequence: ADD new → PROPAGATE → VERIFY → REVOKE old

**Step 1 — Isolate compromised SPIRE node (0–5 min)**
```bash
kubectl label node <compromised-node> kron.security/quarantine=true
kubectl cordon <compromised-node>
# Surviving SPIRE nodes continue issuing SVIDs
# Current SVIDs remain valid for 4-hour TTL — rotation window
```

**Step 2 — Generate new root CA on clean node (5–15 min)**
```bash
kubectl exec -n kron spire-server-1 -- \
  spire-server bundle generate -id spiffe://kron.org/new-root > /tmp/new-ca.pem
# Store in Vault immediately
vault kv put kron/spire/new-root cert=@/tmp/new-ca.pem
# DO NOT deploy yet
```

**Step 3 — Add new CA to trust bundle (dual-trust window) (15–20 min)**
```bash
# Both old CA and new CA are now trusted
kubectl exec -n kron spire-server-1 -- \
  spire-server bundle set --format pem --id spiffe://kron.org < /tmp/combined-bundle.pem
# Workloads trust both CAs — no connections break
```

**Step 4 — Re-issue all SVIDs under new CA (20–40 min)**
```bash
kubectl exec -n kron spire-server-1 -- \
  spire-server entry rotate --all
# Verify new SVIDs being issued
kubectl exec -n kron spire-agent-0 -- \
  spire-agent api fetch x509 | grep -i "subject key"
# Must show new CA thumbprint
```

**Step 5 — Verify 100% migration (40–50 min)**
```bash
kron-ctl spire verify-migration
# Checks all registered SVIDs
# Must report: "0 SVIDs still signed by old CA"
# Do NOT proceed to step 6 until this shows 0
```

**Step 6 — Revoke old CA (50–55 min)**
```bash
kubectl exec -n kron spire-server-1 -- \
  spire-server bundle set --format pem < /tmp/new-ca-only.pem
# Old CA removed from trust bundle
# Old CA added to CRL
```

**Step 7 — Forensics on compromised node (parallel track)**
```bash
# Snapshot disk before any remediation
kubectl debug node/<compromised-node> --image=ubuntu
# Copy /var/lib/spire to investigation storage
# Determine: how was it compromised? Lateral movement?
```

**Step 8 — Rebuild and restore quorum**
```bash
kubectl uncordon <compromised-node>  # or replace hardware
# Join to SPIRE cluster under new CA
kubectl rollout restart daemonset/spire-agent -n kron
```

**Total rotation time target:** <60 minutes. Zero downtime if sequence followed.

---

## RB-004: Rogue Admin Action Detected

**Trigger:** Merkle chain validator reports hash break. Alert: `KRONAuditChainBreak`. Or: automated detection fires on anomalous admin behaviour.

### Containment Track (immediate)

**Step 1 — Revoke session (0–5 min)**
```bash
kron-ctl user revoke-sessions --user-id <suspected_user_id>
kron-ctl spire revoke-svid --workload <service_identity>
# All active tokens invalid immediately
```

**Step 2 — Scope the damage (5–30 min)**
```bash
kron-ctl audit query \
  --actor <user_id> \
  --from "$(date -d '7 days ago' --iso-8601)" \
  --to now \
  --actions "alert_suppress,rule_disable,log_purge,query_export"
# What did this identity do?
```

**Step 3 — Notify affected tenants (within 72h per CERT-In)**
```bash
# Auto-generate CERT-In notification draft
kron-ctl compliance cert-in-notification \
  --incident-id <id> \
  --affected-window "FROM TO" \
  --output /tmp/cert-in-notification.pdf
```

**Step 4 — Rotate all credentials the identity touched**
```bash
kron-ctl vault rotate-secrets --accessed-by <user_id>
# Rotates every API key and DB credential the user had read access to
```

### Forensic Track (parallel)

**F1 — Preserve Merkle chain**
```bash
kron-ctl audit export \
  --from <chain_break_position - 1000> \
  --to now \
  --sign \
  --output /forensics/audit-$(date +%Y%m%d).tar.gz
# This is the primary evidence artifact
```

**F2 — Reconstruct suppressed alerts**
```bash
kron-ctl detection replay \
  --from <incident_start> \
  --to <incident_end> \
  --force  # re-run correlation even if alerts were suppressed
```

**F3 — Determine insider vs external**
```bash
kron-ctl ueba query --user <user_id> --from "30 days ago"
# Login patterns, geo, device fingerprint
# Cross-reference with access logs
```

### Structural Fix (deploy within 48h)
- Enable 4-eyes approval for all destructive admin actions
- Add anomalous admin action detection rule (if not already present)
- Admin session timeout: reduce to 30 minutes
- Admin SOAR action channel: route to out-of-band channel admin cannot suppress

---

## RB-005: Redpanda Cluster Loss

**Trigger:** All Redpanda brokers unreachable. Agents see connection refused. Events queuing in agent local buffer.

```bash
# Step 1: Agents automatically buffer locally (up to configured limit)
# No immediate data loss — agents buffer on disk

# Step 2: Diagnose
kubectl get pods -n kron | grep redpanda
kubectl logs -n kron redpanda-0 --tail=100

# Step 3: If recoverable (software crash):
kubectl rollout restart statefulset/redpanda -n kron
# Raft re-elects leader automatically

# Step 4: If hardware failure on all nodes:
# Provision new Redpanda cluster from Terraform
# Restore topic configs from backup
kron-ctl redpanda restore-config

# Step 5: Agents drain local buffer automatically on reconnection
# Monitor drain:
kron-ctl agents buffer-status
```

**RTO:** <30 min. **RPO:** Zero (agents buffer locally).

---

## RB-006: KRON Itself Compromised

**Trigger:** External breach notification, anomalous network traffic from KRON server, KRON meta-detection fires on own logs.

**Immediate actions (within 5 minutes):**
1. Isolate KRON server from network (remove from any external-facing routing)
2. Notify all tenant admins: "KRON temporarily offline for security maintenance"
3. Preserve disk image before any remediation
4. Page founding engineer and legal counsel simultaneously

**Investigation:**
- Determine entry point (which service? which CVE?)
- Check if any tenant data was accessed or exfiltrated
- Check if any agent was compromised (agent cert revocation)

**Recovery:**
- Deploy KRON to clean hardware from known-good images
- Rotate all certificates and secrets
- Audit all tenant data access logs before bringing service back online
- Mandatory third-party forensic review before re-enabling Enterprise customers

**Legal:** Consult legal counsel on CERT-In breach notification requirements before any public disclosure.

---

## Fire Drill Schedule

| Runbook | Last Drilled | Next Drill | Result |
|---|---|---|---|
| RB-001 ClickHouse recovery | Not yet | Month 6 | — |
| RB-002 HSM recovery | Not yet | Month 6 | — |
| RB-003 SPIRE rotation | Not yet | Month 6 | — |
| RB-004 Rogue admin | Not yet | Month 3 | — |

**Fire drill procedure:**
1. Schedule 3-hour maintenance window
2. Execute runbook on staging environment
3. Record actual time taken vs target RTO
4. Document what failed or was unclear
5. Update runbook based on findings
6. Append results to this table
