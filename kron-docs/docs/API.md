# KRON — API Reference

**Version:** 1.0  
**Base URL:** `https://kron.{org}.internal/api/v1`  
**Auth:** Bearer JWT (all endpoints) + optional mTLS (service-to-service)

---

## Authentication

### POST /auth/login
```json
Request:  { "email": "analyst@org.com", "password": "...", "totp": "123456" }
Response: { "token": "eyJ...", "expires_at": "2026-01-01T00:00:00Z", "tenant_id": "uuid", "role": "analyst" }
```

### POST /auth/refresh
```json
Request:  { "token": "eyJ..." }
Response: { "token": "eyJ...", "expires_at": "..." }
```

### POST /auth/logout
Invalidates the current token. No body.

---

## Events

### GET /events
Query events from ClickHouse/DuckDB.

**Query params:**
| Param | Type | Description |
|---|---|---|
| `from` | ISO8601 | Start time (required) |
| `to` | ISO8601 | End time (default: now) |
| `source_type` | string | Filter by source |
| `host` | string | Filter by hostname or IP |
| `user` | string | Filter by username |
| `event_type` | string | Filter by event type |
| `severity` | string | Filter: critical,high,medium,low,info |
| `ioc_hit` | bool | Only IOC-matched events |
| `limit` | int | Max rows (default: 100, max: 10000) |
| `offset` | int | Pagination offset |
| `sort` | string | Field to sort by (default: ts desc) |

**Response:**
```json
{
  "total": 1523,
  "events": [
    {
      "event_id": "uuid",
      "tenant_id": "uuid",
      "ts": "2026-01-01T00:00:00.000000000Z",
      "source_type": "linux_ebpf",
      "event_type": "network_connect",
      "hostname": "web-server-01",
      "src_ip": "10.0.1.5",
      "dst_ip": "185.220.101.1",
      "dst_port": 443,
      "severity": "high",
      "anomaly_score": 0.87,
      "ioc_hit": true,
      "ioc_type": "ip",
      "mitre_tactic": "command-and-control"
    }
  ],
  "query_ms": 124
}
```

### POST /events/query
Natural language or raw SQL query.

```json
Request:
{
  "query": "show all failed logins from outside India in the last 6 hours",
  "mode": "nl"  // or "sql"
}

Response:
{
  "generated_sql": "SELECT * FROM events WHERE ...",
  "results": [...],
  "query_ms": 89
}
```

### GET /events/{event_id}
Returns single event with full field detail.

### GET /events/stream
WebSocket endpoint. Returns live event stream as newline-delimited JSON.

```
ws://kron.{org}.internal/api/v1/events/stream?severity=critical,high
```

---

## Alerts

### GET /alerts
```
GET /alerts?status=open&severity=P1,P2&from=2026-01-01&limit=50
```

**Response:**
```json
{
  "total": 12,
  "alerts": [
    {
      "alert_id": "uuid",
      "rule_name": "Suspicious Login from New Country",
      "severity": "P1",
      "risk_score": 87,
      "created_at": "2026-01-01T02:15:00Z",
      "affected_assets": ["accounts-server-01"],
      "affected_users": ["finance.user"],
      "mitre_tactic": "initial-access",
      "mitre_technique": "T1078",
      "narrative_en": "User finance.user logged in from Nigeria at 2am — first time seen from this country in 90 days.",
      "narrative_hi": "...",
      "status": "open",
      "whatsapp_sent": true
    }
  ]
}
```

### GET /alerts/{alert_id}
Full alert detail including evidence event IDs, root cause chain, suggested playbook.

### PATCH /alerts/{alert_id}
Update alert status.

```json
Request:
{
  "status": "false_positive",
  "resolution_notes": "Analyst was travelling to Nigeria",
  "assigned_to": "analyst@org.com"
}
```

### POST /alerts/{alert_id}/acknowledge
Marks alert as acknowledged. Logs to audit trail.

### POST /alerts/{alert_id}/escalate
Routes alert to additional recipients.

### GET /alerts/stream
WebSocket — live alert stream.

### GET /alerts/{alert_id}/evidence
Returns all raw events linked to this alert.

---

## Rules

### GET /rules
List all rules for tenant.

```
GET /rules?status=active&source=sigma_oss&severity=high,critical
```

### POST /rules
Create a new rule.

```json
{
  "name": "Unusual Data Export",
  "rule_type": "threshold",
  "severity": "high",
  "mitre_tactic": "exfiltration",
  "mitre_technique": "T1041",
  "config": {
    "field": "bytes_out",
    "threshold": 1073741824,
    "window_seconds": 3600,
    "group_by": "user_name"
  }
}
```

### PUT /rules/{rule_id}
Update rule. Increments version. Previous version retained.

### DELETE /rules/{rule_id}
Soft delete (status = disabled). Never hard deleted.

### POST /rules/{rule_id}/test
Test rule against historical data.

```json
Request:  { "lookback_hours": 24 }
Response: { "matches": 3, "fp_estimate": 0.02, "sample_matches": [...] }
```

### POST /rules/import/sigma
Import SIGMA YAML file.

```json
Request:  { "yaml": "title: ...\nstatus: ...\n..." }
Response: { "rule_id": "uuid", "compiled": true, "fp_estimate": 0.01 }
```

---

## Assets

### GET /assets
```
GET /assets?os_type=linux&criticality=critical&agent_installed=true
```

### GET /assets/{asset_id}
Full asset detail including recent alerts, open risk score, agent status.

### PATCH /assets/{asset_id}
Update criticality, tags, owner, notes.

### GET /assets/{asset_id}/events
Recent events from this asset.

### GET /assets/{asset_id}/alerts
Open alerts on this asset.

---

## SOAR / Playbooks

### GET /playbooks
List available playbooks.

### POST /playbooks
Create playbook.

```json
{
  "name": "Isolate Compromised Host",
  "trigger_severities": ["P1"],
  "steps": [
    { "type": "isolate_host", "target": "{{alert.affected_assets[0]}}", "method": "iptables" },
    { "type": "notify", "channel": "whatsapp", "message": "Host {{target}} isolated" },
    { "type": "ticket", "system": "jira", "priority": "high" }
  ],
  "requires_approval": true,
  "dry_run_mode": false
}
```

### POST /playbooks/{playbook_id}/run
Execute playbook against an alert.

```json
Request:  { "alert_id": "uuid", "dry_run": true }
Response: {
  "run_id": "uuid",
  "dry_run": true,
  "actions": [
    { "step": "isolate_host", "target": "web-server-01", "simulated": true, "would_succeed": true }
  ]
}
```

### POST /playbooks/runs/{run_id}/approve
Approve a pending playbook run (4-eyes).

### POST /playbooks/runs/{run_id}/reject
Reject a pending playbook run.

---

## Compliance

### GET /compliance/status
Current compliance posture across all frameworks.

```json
{
  "cert_in": { "score": 87, "passing": 11, "failing": 2, "controls": [...] },
  "dpdp": { "score": 92, "passing": 13, "failing": 1, "controls": [...] },
  "rbi": { "score": 78, "passing": 9, "failing": 3, "controls": [...] }
}
```

### GET /compliance/{framework}/report
Generate compliance report.

```
GET /compliance/cert_in/report?format=pdf&from=2025-01-01&to=2026-01-01
```

Returns binary PDF or JSON evidence package.

### GET /compliance/cert_in/incidents
List incidents mapped to CERT-In categories for reporting.

---

## Analytics

### GET /analytics/event-volume
Hourly event volume by source type.

```
GET /analytics/event-volume?from=2026-01-01&to=2026-01-07&granularity=hour
```

### GET /analytics/alert-trends
Alert count trends by severity over time.

### GET /analytics/mitre-heatmap
MITRE ATT&CK coverage and hit counts.

```json
{
  "tactics": {
    "initial-access": { "hit_count": 23, "techniques": { "T1078": 15, "T1190": 8 } },
    "lateral-movement": { "hit_count": 4, "techniques": { "T1021": 4 } }
  }
}
```

### GET /analytics/top-assets
Top assets by risk score and alert count.

### GET /analytics/top-users
Top users by anomaly score.

---

## Tenants (MSSP/Admin only)

### GET /tenants
List all tenants (MSSP admin only).

### POST /tenants
Create new tenant.

### GET /tenants/{tenant_id}/summary
High-level security posture for a tenant.

### DELETE /tenants/{tenant_id}
Offboard tenant. Purges all data after confirmation. Irreversible.

---

## System

### GET /health
```json
{ "status": "healthy", "version": "1.0.0", "mode": "standard", "uptime_seconds": 86400 }
```

### GET /health/detailed
Component health: ClickHouse, Redpanda, SPIRE, Vault, agent fleet.

### GET /metrics
Prometheus metrics endpoint. Scraped by Prometheus.

### GET /version
```json
{ "version": "1.0.0", "build": "abc123", "mode": "standard", "schema_version": 1 }
```

---

## WebSocket Endpoints

### /ws/alerts
Live alert stream. JSON newline-delimited.

```
ws://kron.internal/api/v1/ws/alerts?tenant_id=uuid&severity=P1,P2
```

### /ws/events
Live event stream. High-volume — filter required.

```
ws://kron.internal/api/v1/ws/events?source_type=linux_ebpf&host=web-01
```

### /ws/pipeline
Pipeline health stream. EPS, queue depth, ingestion lag.

---

## Error Responses

```json
{
  "error": {
    "code": "INSUFFICIENT_PERMISSION",
    "message": "Role 'viewer' cannot execute SOAR actions",
    "request_id": "uuid"
  }
}
```

| HTTP Code | Error Code | Meaning |
|---|---|---|
| 400 | `INVALID_REQUEST` | Malformed request body or params |
| 401 | `UNAUTHORIZED` | Missing or invalid token |
| 403 | `INSUFFICIENT_PERMISSION` | Valid token, wrong role |
| 404 | `NOT_FOUND` | Resource does not exist |
| 409 | `CONFLICT` | Duplicate resource |
| 422 | `VALIDATION_FAILED` | Request valid but business rule violation |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Server error (request_id for tracing) |
| 503 | `PIPELINE_DEGRADED` | ClickHouse or Redpanda unavailable |

---

## Rate Limits

| Endpoint group | Limit |
|---|---|
| Auth endpoints | 10 req/min per IP |
| Read endpoints (GET) | 1000 req/min per tenant |
| Write endpoints (POST/PATCH) | 100 req/min per tenant |
| Query endpoints | 60 req/min per tenant |
| Report generation | 10 req/hour per tenant |
| WebSocket connections | 10 concurrent per tenant |
