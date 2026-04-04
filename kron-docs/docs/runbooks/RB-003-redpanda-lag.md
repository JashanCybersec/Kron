# RB-003 — Redpanda Consumer Lag / Throughput Degradation

**Severity:** P2 (rising lag) / P1 (lag > 1M messages or > 30 min behind)
**Owner:** On-call engineer
**Last fire-drilled:** (fill on first drill)
**Estimated MTTR:** 10 minutes (scaling) / 30 minutes (broker failure)

---

## Symptom

- Prometheus alert `KronConsumerLagHigh` firing (lag > 100K messages)
- Events appearing in ClickHouse with timestamp delay > 5 minutes
- Alert latency from event to notification > 5 minutes
- `kron-ctl storage stats` shows processing latency spike

---

## What Is Normal

| Metric | Normal | Warning | Critical |
|---|---|---|---|
| Consumer lag (normalizer) | < 1,000 | 10,000–100,000 | > 100,000 |
| Consumer lag (stream) | < 500 | 5,000–50,000 | > 50,000 |
| Throughput (EPS) | Varies | Drop > 50% | Drop > 80% |
| Broker disk free | > 30% | 10–30% | < 10% |

---

## Triage (< 2 minutes)

```bash
# 1. Check all consumer group lags
rpk group list
rpk group describe kron-normalizer
rpk group describe kron-stream
rpk group describe kron-alert

# 2. Check broker health
rpk cluster health

# 3. Check broker disk
rpk cluster storage

# 4. Check topic throughput (bytes/sec)
rpk topic describe kron.raw --print-configs | grep -E 'retention|segment'
```

---

## Remediation

### Lag is rising but consumer is healthy (burst traffic)

```bash
# Scale up consumer replicas to burn through backlog
kubectl scale deployment/kron-normalizer --replicas=4 -n kron
kubectl scale deployment/kron-stream --replicas=4 -n kron

# Monitor lag draining
watch -n 5 'rpk group describe kron-normalizer | grep LAG'

# Scale back down once lag clears
kubectl scale deployment/kron-normalizer --replicas=2 -n kron
kubectl scale deployment/kron-stream --replicas=2 -n kron
```

### Consumer group is stuck (not making progress)

```bash
# Check for poison messages in DLQ
rpk topic consume kron.dlq --num 10 --format json | jq '.value | fromjson'

# Reset consumer group offset to skip poison message batch
# WARNING: this skips messages — confirm with second engineer
rpk group seek kron-normalizer --to latest --topic kron.raw.<tenant-id>
```

### Broker disk full

```bash
# Check retention settings
rpk topic describe kron.raw --print-configs | grep retention

# Reduce retention temporarily to free disk
# Default: 7 days. Emergency: reduce to 2 days.
rpk topic alter-config kron.raw \
  --set retention.ms=172800000 \
  --set retention.bytes=10737418240

# After disk recovers, restore original retention
rpk topic alter-config kron.raw \
  --set retention.ms=604800000 \
  --delete retention.bytes
```

### Broker node down

```bash
# Check broker status
rpk cluster health

# Redpanda handles broker failure automatically with replication factor 3
# Wait up to 5 minutes for automatic leader election

# If broker does not recover, restart it
kubectl rollout restart statefulset/redpanda -n kron-data
```

---

## Post-Incident

- Calculate maximum lag reached and duration
- Verify all events were eventually processed (no permanent loss)
- If spike was from a specific tenant, consider per-tenant rate limiting review
