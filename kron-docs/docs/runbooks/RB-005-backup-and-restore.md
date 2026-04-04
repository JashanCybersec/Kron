# RB-005 — Backup and Restore

**Severity:** P0 (data loss) / P2 (scheduled backup verification)
**Owner:** On-call engineer
**Last fire-drilled:** (fill on first drill)
**RTO Target:** 4 hours (restore from backup to operational)
**RPO Target:** 1 hour (maximum data loss acceptable)

---

## Backup Schedule

| Component | Frequency | Retention | Storage |
|---|---|---|---|
| ClickHouse (incremental) | Every 1 hour | 90 days | MinIO `kron-backups` bucket |
| ClickHouse (full) | Daily at 02:00 IST | 30 days | MinIO `kron-backups` bucket |
| DuckDB (Nano tier) | Every 15 minutes | 7 days | Local disk + MinIO |
| Tenant config JSON | Every 5 minutes | 30 days | MinIO |
| Redis (token blocklist) | Not backed up | Ephemeral | Rebuilt on restart |
| Kubernetes secrets | Daily | 30 days | MinIO (encrypted) |
| SIGMA rules | Git history | Forever | GitHub |

---

## Verify Backups Are Running

```bash
# Check last backup timestamp
./scripts/backup-verify.sh

# Expected output:
# [OK] clickhouse: last backup 00:45 ago (2026-03-26 14:15 IST)
# [OK] duckdb: last backup 00:12 ago
# [OK] tenant-config: last backup 00:03 ago
# [OK] k8s-secrets: last backup 23:55 ago

# List available backups
mc ls minio/kron-backups/ --recursive | sort -k1,2 | tail -20
```

---

## Restore Procedures

### Restore ClickHouse from Backup

```bash
# 1. Identify the backup to restore
mc ls minio/kron-backups/clickhouse/ | sort -k1,2

# 2. Scale down services that write to ClickHouse to avoid conflicts
kubectl scale deploy/kron-normalizer --replicas=0 -n kron
kubectl scale deploy/kron-stream --replicas=0 -n kron
kubectl scale deploy/kron-alert --replicas=0 -n kron

# 3. Restore from specific backup
BACKUP_NAME="clickhouse-2026-03-26-14-00"
clickhouse-client -h clickhouse.kron.internal -q "
  RESTORE TABLE kron.events FROM Disk('backups', '${BACKUP_NAME}/kron/events/')
"
clickhouse-client -h clickhouse.kron.internal -q "
  RESTORE TABLE kron.alerts FROM Disk('backups', '${BACKUP_NAME}/kron/alerts/')
"

# 4. Verify row counts are reasonable
clickhouse-client -h clickhouse.kron.internal -q "
  SELECT tenant_id, count() as events
  FROM kron.events
  GROUP BY tenant_id
  ORDER BY events DESC
"

# 5. Scale services back up
kubectl scale deploy/kron-normalizer --replicas=2 -n kron
kubectl scale deploy/kron-stream --replicas=2 -n kron
kubectl scale deploy/kron-alert --replicas=2 -n kron
```

### Restore Tenant Config

```bash
# If TenantStore JSON is corrupted:
BACKUP_DATE="2026-03-26"
mc cp minio/kron-backups/tenant-config/${BACKUP_DATE}/tenants.json \
  /var/lib/kron/tenants.json.restore

# Verify JSON is valid
jq . /var/lib/kron/tenants.json.restore > /dev/null

# Swap in
cp /var/lib/kron/tenants.json /var/lib/kron/tenants.json.broken
mv /var/lib/kron/tenants.json.restore /var/lib/kron/tenants.json

# Restart API to reload
kubectl rollout restart deploy/kron-query-api -n kron
```

### Restore Kubernetes Secrets

```bash
# Decrypt and apply secrets backup
BACKUP_DATE="2026-03-26"
mc cp minio/kron-backups/k8s-secrets/${BACKUP_DATE}/secrets.enc.yaml .
gpg --decrypt secrets.enc.yaml | kubectl apply -f -
```

---

## Full Disaster Recovery (all data lost)

```bash
# Use the automated DR script — prompts for confirmation at each step
./scripts/restore.sh --from-date 2026-03-26 --confirm
```

See also: `scripts/restore.sh --help`

---

## RTO/RPO Verification Test (Quarterly)

```bash
# Run in staging environment only
./scripts/dr-test.sh --env staging --simulate-failure clickhouse
# Expected: restoration completes within 4 hours
# Expected: maximum event loss = events from last 1 hour
```
