# KRON Support Process

**Version:** 1.0
**Owner:** Hardik (support@kron.security)
**Effective date:** v1.0 GA

---

## Support Tiers

| Tier | Included with | Response SLA | Coverage |
|---|---|---|---|
| **Community** | Open-source license | Best effort | GitHub Issues |
| **Standard** | KRON License (≤ 500 EPS) | P1: 4h, P2: 1 business day | Email + GitHub |
| **Professional** | KRON License (≤ 10K EPS) | P1: 1h, P2: 4h, P3: 1 business day | Email + WhatsApp |
| **Enterprise** | KRON License (unlimited EPS) | P1: 30 min, P2: 2h, P3: 4h | Dedicated Slack + phone |

**Support hours:** 09:00–21:00 IST, Monday–Saturday (P1 24×7 for Professional and Enterprise)

---

## Severity Definitions

| Severity | Definition | Examples |
|---|---|---|
| **P1 — Critical** | Production system down or data loss occurring | KRON services not starting, events not being ingested, alerts not delivering |
| **P2 — High** | Major feature impaired, workaround exists | Compliance reports failing, SOAR playbooks not executing |
| **P3 — Medium** | Non-critical feature impaired or degraded | Dashboard slow, mobile app not syncing, specific rule not matching |
| **P4 — Low** | Cosmetic or minor issue | UI display bug, documentation error, feature question |

---

## How to Raise a Support Ticket

### P1 / P2 Incidents (Professional and Enterprise)

1. **WhatsApp Business:** +91-XXXX-XXXXXX (available 24×7 for P1)
2. **Email:** support@kron.security — Subject: `[P1]` or `[P2]` prefix triggers priority routing
3. **Dedicated Slack** (Enterprise only): `#kron-support` channel in your shared workspace

**Include in every P1/P2 report:**
```
- KRON version: (kron-ctl version)
- Deployment type: Kubernetes / Docker Compose / USB installer
- Affected component: (kron-collector / kron-stream / kron-alert / etc.)
- Time incident started (IST):
- Number of tenants affected:
- Error messages from logs: (kron-ctl logs <service> --last 100)
- Health check output: (kron-ctl health)
```

### P3 / P4 Issues (All tiers)

1. **GitHub Issues:** https://github.com/Hardik364/Kron/issues
   - Use the issue template: Bug Report or Feature Request
   - Tag: `support`, `bug`, `enhancement`
2. **Email:** support@kron.security

---

## Incident Response Workflow

```
Customer reports incident
         │
         ▼
  Triage by on-call engineer (SLA clock starts)
         │
         ├─ P1 ──► Immediate acknowledgement → assign engineer → war room (Slack/Meet)
         │
         ├─ P2 ──► Acknowledgement within SLA → assign engineer → status updates every 2h
         │
         └─ P3/P4 ► Acknowledgement within SLA → scheduled resolution

         ▼
  Root cause analysis
         │
         ▼
  Fix deployed to customer (hotfix or next release)
         │
         ▼
  Post-mortem (P1 only) — written within 48h
         │
         ▼
  Ticket closed — customer confirms resolution
```

---

## On-Call Rotation

KRON engineering runs a 24×7 on-call rotation for production incidents.

| Tier | Primary | Escalation | Executive |
|---|---|---|---|
| L1 | On-call engineer (rotating weekly) | Tech lead | Hardik |

**Page the on-call:** Use the on-call endpoint in kron-query-api or the mobile app On-Call screen.

---

## Runbooks

All incident runbooks are in `docs/runbooks/`:

| Runbook | Scenario |
|---|---|
| [RB-001](runbooks/RB-001-service-down.md) | Core KRON service is down |
| [RB-002](runbooks/RB-002-clickhouse-degraded.md) | ClickHouse degraded or unreachable |
| [RB-003](runbooks/RB-003-redpanda-lag.md) | Redpanda consumer lag spiking |
| [RB-004](runbooks/RB-004-alert-delivery-failure.md) | Alerts not delivering (WhatsApp/email) |
| [RB-005](runbooks/RB-005-backup-and-restore.md) | Backup and restore procedures |
| [RB-006](runbooks/RB-006-security-incident.md) | Security incident in KRON itself |

---

## Feature Requests

Feature requests are tracked in GitHub Discussions:
https://github.com/Hardik364/Kron/discussions

Roadmap decisions:
- P0 requests (customer-blocking) reviewed within 1 week
- P1/P2 requests reviewed in monthly roadmap planning
- Community votes influence priority

---

## Data Handling in Support

Support engineers may request:
- Sanitised log excerpts (strip tenant IDs, PII before sharing)
- Health check output (`kron-ctl health`)
- Configuration file (strip credentials: `kron-ctl config export --redact-secrets`)

**Never share:**
- JWT tokens or API keys
- ClickHouse credentials
- Event data containing PII (DPDP compliance)
- Keystore files

---

## SLA Credits

For Professional and Enterprise customers, SLA breaches trigger service credits:

| SLA missed by | Credit |
|---|---|
| 0–2× | 10% of monthly fee |
| 2–4× | 25% of monthly fee |
| 4×+ | 50% of monthly fee |

Credits are applied to the next invoice. To claim: email billing@kron.security within 7 days of the incident.
