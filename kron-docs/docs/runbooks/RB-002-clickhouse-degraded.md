# RB-002 — ClickHouse Degraded or Unreachable

**Severity:** P1 (query degraded) / P0 (write failure)
**Owner:** On-call engineer
**Last fire-drilled:** (fill on first drill)
**Estimated MTTR:** 20 minutes (degraded) / 2 hours (disk full)

---

## Symptom

- Prometheus alert `ClickHouseWriteErrors` or `ClickHouseQueryLatencyHigh`
- `kron-ctl storage stats` shows error or latency > 5s
- Events arriving in Redpanda but not appearing in ClickHouse after 60s
- Web UI event search returns timeout errors

---

## Triage (< 3 minutes)

```bash
# 1. Ping ClickHouse HTTP interface
curl -sf http://clickhouse.kron.internal:8123/ping

# 2. Check disk usage (most common ClickHouse failure cause)
clickhouse-client -h clickhouse.kron.internal -q "
  SELECT
    formatReadableSize(free_space) AS free,
    formatReadableSize(total_space) AS total,
    round(100 * free_space / total_space, 1) AS free_pct
  FROM system.disks
"

# 3. Check running queries — look for stuck long-running queries
clickhouse-client -h clickhouse.kron.internal -q "
  SELECT query_id, user, elapsed, query
  FROM system.processes
  ORDER BY elapsed DESC
  LIMIT 10
  FORMAT Vertical
"

# 4. Check replica status (if replication is configured)
clickhouse-client -h clickhouse.kron.internal -q "
  SELECT database, table, is_leader, absolute_delay
  FROM system.replicas
  WHERE absolute_delay > 10
"
```

---

## Remediation

### High query latency (> 500ms p99)

```bash
# Kill long-running queries blocking the system
clickhouse-client -h clickhouse.kron.internal -q "
  KILL QUERY WHERE elapsed > 30
"

# Check merge operations — can cause latency spikes
clickhouse-client -h clickhouse.kron.internal -q "
  SELECT database, table, elapsed, progress, num_parts
  FROM system.merges
  ORDER BY elapsed DESC
"
```

### Disk nearly full (< 10% free)

```bash
# 1. Check which tables use the most disk
clickhouse-client -h clickhouse.kron.internal -q "
  SELECT
    database, table,
    formatReadableSize(sum(bytes_on_disk)) AS size
  FROM system.parts
  GROUP BY database, table
  ORDER BY sum(bytes_on_disk) DESC
  LIMIT 20
"

# 2. Run TTL merge to expire old partitions
clickhouse-client -h clickhouse.kron.internal -q "
  OPTIMIZE TABLE kron.events FINAL
"

# 3. Check TTL is configured correctly (should auto-expire per retention policy)
clickhouse-client -h clickhouse.kron.internal -q "
  SHOW CREATE TABLE kron.events
" | grep TTL

# 4. Emergency: drop oldest partitions manually if disk critically low
# WARNING: this is destructive. Confirm with second engineer.
clickhouse-client -h clickhouse.kron.internal -q "
  SELECT partition, formatReadableSize(bytes_on_disk), min_date, max_date
  FROM system.parts
  WHERE table = 'events' AND database = 'kron'
  ORDER BY min_date
  LIMIT 5
"
# If confirmed, drop the oldest:
# clickhouse-client -h clickhouse.kron.internal -q "
#   ALTER TABLE kron.events DROP PARTITION 'YYYYMM'
# "
```

### ClickHouse process crashed

```bash
# Check systemd / pod status
# On bare metal:
systemctl status clickhouse-server
journalctl -u clickhouse-server -n 100

# On Kubernetes:
kubectl rollout restart statefulset/clickhouse -n kron-data
kubectl rollout status statefulset/clickhouse -n kron-data
```

---

## Backup Verification

If data loss is suspected:
```bash
# Verify backup exists for today
./scripts/backup-verify.sh clickhouse

# Restore procedure: see RB-005
```

---

## Escalation

If ClickHouse remains degraded after 20 minutes:
1. Check if Redpanda is buffering events (consumer lag will grow — this is safe)
2. Engage second on-call if disk full scenario
3. Consider emergency scale-up of disk volume (cloud deployment only)
