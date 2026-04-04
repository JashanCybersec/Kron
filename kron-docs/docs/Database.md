# KRON — Database Design

**Version:** 1.0

---

## Overview

KRON uses two storage engines depending on tier:
- **DuckDB** (Nano) — embedded, single binary, Parquet-native
- **ClickHouse** (Standard/Enterprise) — columnar OLAP, sharded HA

Both use identical schema. DuckDB DDL and ClickHouse DDL differ in syntax but represent the same logical model. Parquet is the universal interchange format enabling zero-loss tier migration.

---

## Core Schema

### Table: `events`

The primary fact table. Append-only. Every log line, every endpoint event, every network flow is a row here.

**ClickHouse DDL:**
```sql
CREATE TABLE events
(
    -- Identity
    event_id        UUID            DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String)  NOT NULL,
    dedup_hash      UInt64          NOT NULL,

    -- Timing
    ts              DateTime64(9, 'UTC')    NOT NULL,  -- nanosecond precision
    ts_received     DateTime64(9, 'UTC')    NOT NULL,
    ingest_lag_ms   UInt32          DEFAULT 0,

    -- Source
    source_type     LowCardinality(String)  NOT NULL,  -- 'linux_ebpf','windows_etw','syslog','cloudtrail',...
    collector_id    String          NOT NULL,
    raw             String          NOT NULL,  -- original log line, compressed

    -- Asset context
    host_id         String,
    hostname        String,
    host_ip         IPv4,
    host_fqdn       String,
    asset_criticality LowCardinality(String) DEFAULT 'unknown',  -- 'critical','high','medium','low','unknown'
    asset_tags      Array(String)   DEFAULT [],

    -- User context
    user_name       String,
    user_id         String,
    user_domain     String,
    user_type       LowCardinality(String),  -- 'human','service','system'

    -- Event classification
    event_type      LowCardinality(String)  NOT NULL,  -- 'process_create','network_connect','file_access',...
    event_category  LowCardinality(String),  -- 'authentication','network','file','process','registry'
    event_action    LowCardinality(String),

    -- Network fields
    src_ip          IPv4,
    src_ip6         IPv6,
    src_port        UInt16,
    dst_ip          IPv4,
    dst_ip6         IPv6,
    dst_port        UInt16,
    protocol        LowCardinality(String),
    bytes_in        UInt64,
    bytes_out       UInt64,
    packets_in      UInt32,
    packets_out     UInt32,
    direction       LowCardinality(String),  -- 'inbound','outbound','lateral'

    -- Process fields
    process_name    String,
    process_pid     UInt32,
    process_ppid    UInt32,
    process_path    String,
    process_cmdline String,
    process_hash    String,  -- SHA256 of binary
    parent_process  String,

    -- File fields
    file_path       String,
    file_name       String,
    file_hash       String,
    file_size       UInt64,
    file_action     LowCardinality(String),  -- 'read','write','create','delete','rename'

    -- Authentication fields
    auth_result     LowCardinality(String),  -- 'success','failure','unknown'
    auth_method     LowCardinality(String),
    auth_protocol   LowCardinality(String),

    -- Geo enrichment
    src_country     LowCardinality(FixedString(2)),
    src_city        String,
    src_asn         UInt32,
    src_asn_name    String,
    dst_country     LowCardinality(FixedString(2)),

    -- Threat intel
    ioc_hit         Bool            DEFAULT false,
    ioc_type        LowCardinality(String),
    ioc_value       String,
    ioc_feed        String,

    -- MITRE
    mitre_tactic    LowCardinality(String),
    mitre_technique LowCardinality(String),
    mitre_sub_tech  String,

    -- Severity
    severity        LowCardinality(String)  DEFAULT 'info',  -- 'critical','high','medium','low','info'
    severity_score  UInt8           DEFAULT 0,  -- 0-100

    -- AI scores
    anomaly_score   Float32         DEFAULT 0.0,
    ueba_score      Float32         DEFAULT 0.0,
    beacon_score    Float32         DEFAULT 0.0,
    exfil_score     Float32         DEFAULT 0.0,

    -- Enriched fields (flexible)
    fields          Map(String, String)  DEFAULT map(),

    -- Audit
    schema_version  UInt8           DEFAULT 1
)
ENGINE = ReplacingMergeTree(ts_received)
PARTITION BY (tenant_id, toYYYYMM(ts))
ORDER BY (tenant_id, ts, source_type, host_ip, event_type)
TTL ts + INTERVAL 90 DAY TO DISK 'warm',
    ts + INTERVAL 365 DAY TO DISK 'cold'
SETTINGS
    index_granularity = 8192,
    min_compress_block_size = 65536,
    compress_block_size = 1048576;
```

**DuckDB DDL (Nano equivalent):**
```sql
CREATE TABLE events (
    event_id        VARCHAR DEFAULT gen_random_uuid()::VARCHAR,
    tenant_id       VARCHAR NOT NULL,
    dedup_hash      UBIGINT NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    ts_received     TIMESTAMPTZ NOT NULL,
    -- ... same fields, DuckDB types
    PRIMARY KEY (event_id)
);
CREATE INDEX idx_events_tenant_ts ON events(tenant_id, ts);
CREATE INDEX idx_events_host ON events(tenant_id, hostname);
```

---

### Table: `alerts`

Fired detections. One row per unique alert (deduped within 15-minute windows).

```sql
CREATE TABLE alerts
(
    alert_id            UUID        DEFAULT generateUUIDv4(),
    tenant_id           LowCardinality(String)  NOT NULL,

    -- Detection
    rule_id             String      NOT NULL,
    rule_name           String      NOT NULL,
    rule_version        String,
    detection_source    LowCardinality(String),  -- 'sigma','onnx','ueba','ioc','threshold'

    -- Timing
    created_at          DateTime64(3, 'UTC')     NOT NULL,
    first_seen          DateTime64(3, 'UTC')     NOT NULL,
    last_seen           DateTime64(3, 'UTC')     NOT NULL,
    event_count         UInt32      DEFAULT 1,

    -- Risk
    risk_score          UInt8       NOT NULL,  -- 0-100
    severity            LowCardinality(String)  NOT NULL,  -- P1-P5
    confidence          Float32,  -- 0.0-1.0

    -- MITRE
    mitre_tactic        LowCardinality(String),
    mitre_technique     LowCardinality(String),
    mitre_sub_tech      String,
    kill_chain_stage    LowCardinality(String),

    -- Affected assets
    affected_assets     Array(String),
    affected_users      Array(String),
    affected_ips        Array(IPv4),

    -- Evidence
    evidence_event_ids  Array(UUID),  -- foreign keys to events table
    raw_matches         String,  -- JSON of matched event fields

    -- AI enrichment
    narrative_en        String,  -- plain English summary
    narrative_hi        String,  -- Hindi summary
    narrative_ta        String,
    narrative_te        String,
    root_cause_chain    String,  -- JSON array of causal events
    fp_probability      Float32,  -- estimated false positive probability
    suggested_playbook  String,

    -- Lifecycle
    status              LowCardinality(String)  DEFAULT 'open',
    -- 'open','acknowledged','in_progress','resolved','false_positive','suppressed'
    assigned_to         String,
    resolved_at         DateTime64(3, 'UTC'),
    resolved_by         String,
    resolution_notes    String,
    case_id             UUID,

    -- Compliance
    cert_in_category    LowCardinality(String),
    rbi_control         String,
    dpdp_applicable     Bool    DEFAULT false,

    -- Notifications
    whatsapp_sent       Bool    DEFAULT false,
    sms_sent            Bool    DEFAULT false,
    email_sent          Bool    DEFAULT false,
    notification_ts     DateTime64(3, 'UTC'),

    schema_version      UInt8   DEFAULT 1
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(created_at))
ORDER BY (tenant_id, created_at, severity, risk_score)
TTL created_at + INTERVAL 365 DAY TO DISK 'cold';
```

---

### Table: `audit_log`

Tamper-evident audit trail. Every user action, every API call, every SOAR action. Merkle-chained.

```sql
CREATE TABLE audit_log
(
    audit_id        UUID        DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String)  NOT NULL,
    ts              DateTime64(9, 'UTC')    NOT NULL,

    -- Actor
    actor_id        String      NOT NULL,  -- user_id or service identity
    actor_type      LowCardinality(String)  NOT NULL,  -- 'human','service','system'
    actor_ip        IPv4,
    session_id      String,

    -- Action
    action          LowCardinality(String)  NOT NULL,
    resource_type   LowCardinality(String),
    resource_id     String,
    result          LowCardinality(String)  NOT NULL,  -- 'success','failure','denied'

    -- Detail
    request_body    String,  -- sanitized (no secrets)
    response_code   UInt16,
    duration_ms     UInt32,

    -- Merkle chain
    prev_hash       FixedString(64)  NOT NULL,  -- SHA256 of previous row
    row_hash        FixedString(64)  NOT NULL,  -- SHA256 of this row content + prev_hash
    chain_seq       UInt64           NOT NULL   -- monotonically increasing per tenant
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(ts))
ORDER BY (tenant_id, chain_seq)
-- No TTL on audit log — retained indefinitely per compliance requirements
SETTINGS
    parts_to_throw_insert = 0;  -- never reject inserts
```

---

### Table: `assets`

Asset inventory. Updated by collection agents and enrichment pipeline.

```sql
CREATE TABLE assets
(
    asset_id        UUID        DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String)  NOT NULL,
    first_seen      DateTime64(3, 'UTC'),
    last_seen       DateTime64(3, 'UTC'),

    hostname        String,
    fqdn            String,
    ip_addresses    Array(IPv4),
    ip6_addresses   Array(IPv6),
    mac_addresses   Array(String),

    os_type         LowCardinality(String),  -- 'linux','windows','macos','network','ot'
    os_name         String,
    os_version      String,

    asset_type      LowCardinality(String),  -- 'server','workstation','network_device','ot_device','cloud'
    criticality     LowCardinality(String)   DEFAULT 'medium',
    tags            Array(String),
    owner           String,
    department      String,
    location        String,

    -- Agent status
    agent_installed Bool    DEFAULT false,
    agent_version   String,
    agent_last_seen DateTime64(3, 'UTC'),
    collection_mode LowCardinality(String),  -- 'ebpf','etw','agentless','syslog'

    -- Risk
    current_risk_score  UInt8   DEFAULT 0,
    open_alert_count    UInt16  DEFAULT 0,

    -- CMDB
    cmdb_id         String,
    notes           String
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, hostname, ip_addresses);
```

---

### Table: `users`

User inventory and UEBA baselines.

```sql
CREATE TABLE users
(
    user_id         UUID        DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String)  NOT NULL,
    first_seen      DateTime64(3, 'UTC'),
    last_seen       DateTime64(3, 'UTC'),

    username        String      NOT NULL,
    display_name    String,
    email           String,
    department      String,
    manager         String,
    user_type       LowCardinality(String)  DEFAULT 'human',
    is_privileged   Bool        DEFAULT false,
    is_service      Bool        DEFAULT false,

    -- UEBA baselines (rolling 30-day)
    typical_login_hours     Array(UInt8),   -- hours 0-23
    typical_login_geos      Array(FixedString(2)),
    typical_daily_events    Float32,
    typical_data_volume_mb  Float32,
    typical_peer_hosts      Array(String),

    -- Risk
    current_risk_score  UInt8   DEFAULT 0,
    last_risk_update    DateTime64(3, 'UTC'),

    -- AD/LDAP
    ad_dn           String,
    ad_groups       Array(String),
    account_status  LowCardinality(String)  DEFAULT 'active'
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (tenant_id, username);
```

---

### Table: `ioc_hits`

IOC matches logged for threat intel tracking.

```sql
CREATE TABLE ioc_hits
(
    hit_id      UUID    DEFAULT generateUUIDv4(),
    tenant_id   LowCardinality(String)  NOT NULL,
    ts          DateTime64(3, 'UTC')    NOT NULL,
    event_id    UUID    NOT NULL,
    ioc_value   String  NOT NULL,
    ioc_type    LowCardinality(String)  NOT NULL,
    ioc_feed    String,
    confidence  Float32,
    host_id     String,
    user_id     String
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(ts))
ORDER BY (tenant_id, ts, ioc_type);
```

---

### Table: `rules`

Detection rule registry.

```sql
CREATE TABLE rules
(
    rule_id         UUID        DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String)  NOT NULL,  -- 'global' for built-in rules
    created_at      DateTime64(3, 'UTC'),
    updated_at      DateTime64(3, 'UTC'),
    created_by      String,

    name            String      NOT NULL,
    description     String,
    rule_type       LowCardinality(String)  NOT NULL,  -- 'sigma','threshold','sequence','custom'
    status          LowCardinality(String)  DEFAULT 'active',

    sigma_yaml      String,     -- original SIGMA YAML
    compiled_sql    String,     -- compiled ClickHouse/DuckDB SQL
    compiled_hash   FixedString(64),

    severity        LowCardinality(String),
    mitre_tactic    LowCardinality(String),
    mitre_technique String,

    -- Performance
    avg_match_rate_per_day  Float32,
    fp_rate_estimate        Float32,
    last_match              DateTime64(3, 'UTC'),
    total_matches           UInt64  DEFAULT 0,

    tags            Array(String),
    source          LowCardinality(String)  DEFAULT 'custom',  -- 'sigma_oss','india_pack','custom'
    version         String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, rule_id);
```

---

### Table: `playbooks`

SOAR playbook definitions.

```sql
CREATE TABLE playbooks
(
    playbook_id     UUID        DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String)  NOT NULL,
    created_at      DateTime64(3, 'UTC'),
    updated_at      DateTime64(3, 'UTC'),
    created_by      String,

    name            String      NOT NULL,
    description     String,
    trigger_rules   Array(UUID),  -- rule IDs that trigger this playbook
    trigger_severities Array(String),

    steps           String,     -- JSON array of action steps
    dry_run_mode    Bool        DEFAULT true,
    requires_approval Bool      DEFAULT true,
    auto_approve_severity LowCardinality(String),  -- auto-approve for P4/P5 only

    status          LowCardinality(String)  DEFAULT 'active',
    last_run        DateTime64(3, 'UTC'),
    run_count       UInt64      DEFAULT 0,
    success_count   UInt64      DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id, playbook_id);
```

---

### Table: `tenants`

Multi-tenancy registry (Standard/Enterprise only).

```sql
CREATE TABLE tenants
(
    tenant_id       UUID        DEFAULT generateUUIDv4(),
    created_at      DateTime64(3, 'UTC'),
    updated_at      DateTime64(3, 'UTC'),

    name            String      NOT NULL,
    slug            String      NOT NULL,  -- URL-safe identifier
    plan            LowCardinality(String)  NOT NULL,  -- 'nano','standard','enterprise'

    -- Limits
    max_eps         UInt32,
    max_endpoints   UInt32,
    max_retention_days UInt16,

    -- Contact
    admin_email     String,
    whatsapp_number String,
    timezone        String      DEFAULT 'Asia/Kolkata',
    language        LowCardinality(String)  DEFAULT 'en',

    -- Compliance
    cert_in_enabled Bool        DEFAULT true,
    rbi_enabled     Bool        DEFAULT false,
    dpdp_enabled    Bool        DEFAULT true,

    -- Status
    status          LowCardinality(String)  DEFAULT 'active',
    trial_ends      DateTime64(3, 'UTC'),

    -- MSSP
    parent_tenant_id UUID       -- for MSSP sub-tenants
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (tenant_id);
```

---

### Table: `kron_users`

KRON platform users (not monitored users — KRON's own access control).

```sql
CREATE TABLE kron_users
(
    kron_user_id    UUID        DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String)  NOT NULL,
    created_at      DateTime64(3, 'UTC'),

    email           String      NOT NULL,
    display_name    String,
    password_hash   String,     -- argon2id
    totp_secret     String,     -- encrypted

    role            LowCardinality(String)  NOT NULL,
    -- 'viewer','analyst','responder','admin','mssp_admin'

    last_login      DateTime64(3, 'UTC'),
    last_ip         IPv4,
    failed_attempts UInt8       DEFAULT 0,
    locked_until    DateTime64(3, 'UTC'),

    status          LowCardinality(String)  DEFAULT 'active',

    -- Preferences
    language        LowCardinality(String)  DEFAULT 'en',
    notification_prefs String   -- JSON
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (tenant_id, email);
```

---

## Materialized Views

### `mv_alert_counts_hourly`
Pre-aggregated alert counts by hour, severity, and MITRE tactic. Feeds dashboard widgets without scanning the full alerts table.

### `mv_top_assets_by_risk`
Rolling 24h top 20 assets by alert count and risk score. Refreshed every 5 minutes.

### `mv_event_volume_by_source`
Hourly event volume per source type per tenant. Used for EPS monitoring and billing.

### `mv_ueba_daily_baseline`
Daily aggregation of per-user event counts, login hours, data volumes. Input to UEBA baseline model update.

---

## Indexes

All ClickHouse `ORDER BY` keys serve as the primary index (sparse). Additional skip indexes:

```sql
-- Fast lookups by source IP
ALTER TABLE events ADD INDEX idx_src_ip src_ip TYPE minmax GRANULARITY 4;

-- Fast IOC hit lookups
ALTER TABLE events ADD INDEX idx_ioc_hit ioc_hit TYPE set(0) GRANULARITY 4;

-- Fast severity filtering
ALTER TABLE events ADD INDEX idx_severity severity TYPE set(0) GRANULARITY 4;

-- Fast process hash lookups (malware detection)
ALTER TABLE events ADD INDEX idx_proc_hash process_hash TYPE bloom_filter(0.01) GRANULARITY 4;
```

---

## Migrations

Schema migrations tracked in `migrations` table:

```sql
CREATE TABLE kron_migrations
(
    version     UInt32  NOT NULL,
    name        String  NOT NULL,
    applied_at  DateTime64(3, 'UTC')    NOT NULL,
    checksum    FixedString(64)         NOT NULL
)
ENGINE = MergeTree
ORDER BY (version);
```

Migrations are numbered SQL files in `migrations/` directory. Applied in order. Never modified after commit. Reversible migrations preferred but not required.

---

## Retention Policy

| Tier | Hot (NVMe SSD) | Warm (HDD) | Cold (Parquet/MinIO) |
|---|---|---|---|
| Nano | 90 days | — | Unlimited |
| Standard | 90 days | 90–365 days | Unlimited |
| Enterprise | 90 days | 90–365 days | Unlimited |

Audit log: retained indefinitely on all tiers (compliance requirement).

---

## Backup Strategy

| Backup type | Frequency | Method | Retention |
|---|---|---|---|
| Full Parquet snapshot | Nightly | ClickHouse → Parquet → MinIO | 90 days |
| Incremental WAL backup | Every 15 min | ClickHouse backup to MinIO | 7 days |
| Schema + config | On every change | Git | Forever |
| Audit log export | Weekly | Signed Parquet to offline storage | Forever |
