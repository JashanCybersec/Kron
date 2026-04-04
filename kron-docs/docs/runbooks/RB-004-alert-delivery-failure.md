# RB-004 — Alert Delivery Failure (WhatsApp / SMS / Email)

**Severity:** P1 (P1/P2 alerts not delivered) / P2 (P3+ delayed)
**Owner:** On-call engineer
**Last fire-drilled:** (fill on first drill)
**Estimated MTTR:** 5 minutes (config) / 30 minutes (provider outage)

---

## Symptom

- Prometheus alert `KronAlertNotificationFailure` firing
- Analyst reports: "I got an email but not a WhatsApp"
- P1 alert created but on-call not paged within 2 minutes
- `kron-alert` logs show repeated notification errors

---

## Notification Fallback Chain

```
WhatsApp (Twilio + Meta API)
    ↓ (failure after 30s)
SMS (Textlocal)
    ↓ (failure after 60s)
Email (SMTP)
```

All P1/P2 alerts bypass rate limiting and always attempt delivery.

---

## Triage (< 2 minutes)

```bash
# 1. Check kron-alert logs for notification errors
kubectl logs deploy/kron-alert -n kron --tail=200 | grep -i "notification\|whatsapp\|sms\|email\|error"

# 2. Check error counters in Prometheus
# Query: kron_notification_errors_total{channel="whatsapp"}

# 3. Verify alert was actually created
kron-ctl events query --tenant <tenant> --type "alert_created" --from "30m ago" --limit 5

# 4. Test notification channel manually
kron-ctl notify test --channel whatsapp --tenant <tenant>
kron-ctl notify test --channel sms --tenant <tenant>
kron-ctl notify test --channel email --tenant <tenant>
```

---

## Remediation by Channel

### WhatsApp failing

```bash
# 1. Check Twilio API status: https://status.twilio.com
# 2. Check Meta API status: https://developers.facebook.com/status

# 3. Verify credentials in config (do NOT log them — check they are set)
kubectl get secret kron-notification-secrets -n kron -o json | \
  jq '.data | keys'

# 4. If Twilio is down — WhatsApp will auto-fallback to SMS
# Confirm SMS is working:
kron-ctl notify test --channel sms --tenant <tenant>
```

### SMS failing (Textlocal)

```bash
# 1. Check Textlocal status: https://www.textlocal.in/status
# 2. Check DLT registration status (TRAI mandate for Indian SMS)
#    — DLT rejection looks like: "Invalid template" or "DLT not registered"

# 3. If DLT template rejected:
#    Log into Textlocal portal → Templates → check approval status
#    New templates take 24-72h for DLT approval

# 4. Emergency: switch SMS provider
#    Update kron config: sms.provider = "twilio" | "msg91" | "textlocal"
kubectl edit configmap kron-config -n kron
# Change sms.provider, then rolling restart:
kubectl rollout restart deploy/kron-alert -n kron
```

### Email failing

```bash
# 1. Check SMTP connectivity
kubectl exec -n kron deploy/kron-alert -- \
  nc -zv smtp.kron.internal 587

# 2. Check SMTP credentials
kubectl get secret kron-notification-secrets -n kron -o json | \
  jq '.data.SMTP_USER | @base64d'

# 3. Check if emails are in spam (check SPF/DKIM/DMARC)
# Query: dig TXT kron.security | grep -E "v=spf|DKIM|DMARC"
```

---

## Manual Alert Retry

If a P1 alert was created but no notification was delivered:

```bash
# Manually trigger notification for a specific alert
kron-ctl alert notify --alert-id <alert-id> --force
```

---

## Post-Incident

- Record which channel failed and duration
- If provider was down > 30 min, consider adding a 4th fallback (Slack webhook)
- Review DLT template registration renewal dates
