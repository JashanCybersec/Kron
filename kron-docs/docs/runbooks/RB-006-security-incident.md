# RB-006 — Security Incident Response

**Severity:** P0 (active breach) / P1 (suspected compromise)
**Owner:** Security lead + on-call engineer
**Last fire-drilled:** (fill on first drill)
**Notification SLA:** CERT-In 6-hour initial report, 24-hour detailed report

---

## Step 0 — Declare the Incident (< 5 minutes)

```
1. Page security lead immediately — do not investigate alone
2. Open incident channel: #incident-YYYY-MM-DD-kron-security
3. Start incident timer
4. Do NOT remediate before gathering evidence — you may destroy forensics
```

---

## Detection Sources

| Source | What to look for |
|---|---|
| KRON alert queue | P1 alerts: privilege escalation, impossible travel, mass download |
| KRON audit log | Unusual admin actions, bulk export, role changes |
| `kron-auth` logs | JWT forgery attempts, brute force from new IP, TOTP failures |
| ClickHouse query log | `SELECT *` without tenant filter, DROP TABLE, unusual query patterns |
| Redpanda ACL audit | Unauthorized topic access attempts |

---

## Triage (< 15 minutes)

```bash
# 1. Identify the affected tenant(s)
kron-ctl events query --type "security_*" --from "1h ago" --limit 100

# 2. Check for active suspicious sessions
kubectl exec -n kron deploy/kron-auth -- \
  cat /var/lib/kron/active-sessions.json | jq '.[] | select(.ip_country != "IN")'

# 3. Check audit log for last 30 minutes
kron-ctl events query --type "audit_*" --from "30m ago" --limit 200

# 4. Check if tenant isolation was breached (critical)
kron-ctl events query \
  --type "cross_tenant_access_attempt" \
  --from "24h ago"
```

---

## Containment

### Isolate a compromised user account

```bash
# Immediately revoke all tokens for the user
kron-ctl user revoke-all-tokens --user-id <user-id>

# Lock the account
kron-ctl user lock --user-id <user-id> --reason "Security incident RB-006"

# Audit what the user accessed in the last 24h
kron-ctl audit trail --user-id <user-id> --from "24h ago"
```

### Isolate a compromised tenant

```bash
# Suspend tenant (preserves all data, blocks all access)
kron-ctl tenant suspend --tenant-id <tenant-id> \
  --reason "Security incident under investigation"

# Verify suspension
kron-ctl tenant get --tenant-id <tenant-id> | jq .status
```

### Block a malicious IP

```bash
# Add to deny list (takes effect within 30 seconds)
kron-ctl deny-list add --ip <ip-address> --reason "Active attack RB-006"

# Verify in Prometheus:
# kron_denied_requests_total{reason="ip_deny_list"} should increment
```

---

## Evidence Preservation

```bash
# Snapshot current state before any remediation
./scripts/forensics-snapshot.sh --incident-id INC-$(date +%Y%m%d-%H%M)

# This captures:
# - All KRON logs for last 24h
# - ClickHouse query log
# - JWT blocklist state
# - Active session list
# - Redpanda consumer group offsets
# - Kubernetes events log
# - Network flow logs (if available)
```

---

## CERT-In Notification (mandatory within 6 hours)

Under CERT-In Directions 2022, reportable incidents include:
- Unauthorised access to IT systems / data
- Data breach / theft
- Identity theft / fraud

**Report to:** incident@cert-in.org.in
**Format:** Use `kron-ctl compliance cert-in report --incident-id <id>`

The generated report follows the prescribed CERT-In format and includes:
- Incident timeline
- Affected systems and data categories
- Estimated number of affected individuals (DPDP requirement)
- Immediate actions taken

---

## Post-Incident

1. Root cause analysis document within 48 hours
2. Update SIGMA rules to detect similar attacks going forward
3. Review and tighten RBAC if privilege was abused
4. Verify all tenant data integrity (canary test)
5. CERT-In detailed report within 24 hours of initial report
6. DPDP breach notification to affected data principals within 72 hours (if personal data involved)
