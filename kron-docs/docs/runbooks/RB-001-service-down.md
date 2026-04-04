# RB-001 — KRON Service Down

**Severity:** P1
**Owner:** On-call engineer
**Last fire-drilled:** (fill on first drill)
**Estimated MTTR:** 15 minutes

---

## Symptom

One or more KRON services is not responding. Symptoms include:
- Prometheus alert `KronServiceDown` firing
- `kron-ctl health` shows a red service
- Analysts unable to log in or view alerts
- No events arriving in ClickHouse for > 5 minutes

---

## Triage (< 2 minutes)

```bash
# 1. Check which pods are down
kubectl get pods -n kron --field-selector=status.phase!=Running

# 2. Check recent events for crash reason
kubectl describe pod <pod-name> -n kron | tail -30

# 3. Check logs for the last crash
kubectl logs <pod-name> -n kron --previous --tail=100

# 4. Check overall KRON health
kron-ctl health
```

---

## Remediation by Service

### kron-query-api is down
```bash
# Most common cause: OOM kill or config error
kubectl rollout restart deployment/kron-query-api -n kron
kubectl rollout status deployment/kron-query-api -n kron

# Verify recovery
curl -sf https://app.kron.security/api/v1/health | jq .
```

### kron-normalizer is down
```bash
# Events will buffer in Redpanda while normalizer is down (safe for ~1 hour)
kubectl rollout restart deployment/kron-normalizer -n kron

# After restart, verify consumer lag drains
kubectl exec -n kron deploy/kron-normalizer -- \
  rpk group describe kron-normalizer | grep LAG
```

### kron-stream is down
```bash
# Alert detection paused while stream is down
# Events still collected — detection resumes on recovery
kubectl rollout restart deployment/kron-stream -n kron
```

### kron-alert is down
```bash
# No notifications sent while alert engine is down
# Alerts still written to ClickHouse by stream processor
kubectl rollout restart deployment/kron-alert -n kron
```

### kron-auth is down
```bash
# Analysts cannot log in — high urgency
kubectl rollout restart deployment/kron-auth -n kron
kubectl rollout status deployment/kron-auth -n kron --timeout=120s
```

---

## If Restart Does Not Fix

```bash
# Check if it's an image pull failure
kubectl describe pod <pod-name> -n kron | grep -A 5 "Failed to pull"

# Check resource limits — OOM
kubectl top pods -n kron
kubectl describe node | grep -A 10 "Allocated resources"

# Scale up if resource pressure
kubectl scale deployment/<service> --replicas=2 -n kron
```

---

## Escalation

If service remains down after 15 minutes:
1. Page the secondary on-call
2. Check if ClickHouse or Redpanda is also affected (see RB-002, RB-003)
3. Open P1 incident in incident tracker

---

## Post-Incident

- [ ] Document root cause in incident tracker
- [ ] Update this runbook if a new failure mode was discovered
- [ ] Add Prometheus alert tuning if alert was noisy or slow to fire
