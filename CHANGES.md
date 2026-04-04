# KRON — Changes Log
> Session: 2026-04-04 | Engineer: Claude Sonnet 4.6

---

## 1. Monorepo → Three-Repo Restructure

The old `Kron/Kron/` monorepo was split into five independent git repositories,
each pushable separately to GitHub.

### New Directory Layout

```
Desktop/Kron/
├── kron-core/       ← shared Rust library workspace
├── kron-nano/       ← single-binary SIEM (DuckDB only)
├── kron-standard/   ← Standard-tier crates
├── kron-docs/       ← all documentation
└── kron-mobile/     ← Flutter app (peer directory)
```

---

## 2. kron-core

**What it is:** Shared Rust workspace containing all library and service crates
that both Nano and Standard tiers build on.

**Workspace members (10 crates):**
| Crate | Type | Description |
|---|---|---|
| `kron-types` | lib | Shared domain types, config, errors |
| `kron-storage` | lib | DuckDB + optional ClickHouse (feature-gated) |
| `kron-bus` | lib | Embedded WAL bus + optional Redpanda adapter |
| `kron-auth` | lib | JWT, RBAC, MFA, brute-force protection |
| `kron-ai` | lib | ONNX anomaly/UEBA inference |
| `kron-collector` | lib + bin | gRPC/HTTP/syslog event ingestion |
| `kron-normalizer` | lib + bin | CEF/LEEF/JSON parsing, GeoIP enrichment |
| `kron-stream` | lib + bin | SIGMA engine, IOC filters, risk scoring |
| `kron-alert` | lib + bin | Alert assembly, WhatsApp/SMS/email dispatch |
| `kron-query-api` | lib + bin | Axum REST API, JWT auth, OpenAPI (utoipa) |

**Key changes made:**

### kron-storage — ClickHouse feature gate
```toml
[features]
clickhouse-backend = ["dep:clickhouse"]
```
- `src/lib.rs` — `#[cfg(feature = "clickhouse-backend")] pub mod clickhouse;`
- `src/adaptive.rs` — all ClickHouse types, variants, and match arms gated with
  `#[cfg(feature = "clickhouse-backend")]`
- Fallback error arm for Nano builds that attempt Standard/Enterprise mode

### kron-query-api — standard feature gate
```toml
[features]
standard = ["dep:kron-soar", "dep:kron-compliance"]
```
- `src/handlers/compliance.rs` — `#![cfg(feature = "standard")]`
- `src/handlers/mod.rs` — `#[cfg(feature = "standard")] pub mod compliance;`
- `src/routes.rs` — compliance routes removed from base router

### lib targets added to all service crates
Each service crate (collector, normalizer, stream, alert, query-api) now has:
- `[lib]` with `pub async fn run(config, shutdown) -> anyhow::Result<()>`
- `[[bin]]` as a thin shell that calls `lib::run()`
- This allows kron-nano to embed all five services as tokio tasks

**Shutdown patterns:**
| Crate | Shutdown mechanism |
|---|---|
| kron-collector | Own `tokio::signal` handler |
| kron-normalizer | Own `tokio::signal` handler |
| kron-stream | `Arc<ShutdownHandle>` passed in; master sends broadcast |
| kron-alert | `broadcast::Receiver<()>` passed in from master |
| kron-query-api | `broadcast::Receiver<()>` passed in from master |

---

## 3. kron-nano

**What it is:** Single binary that runs all five KRON services as tokio tasks
in one process. No ClickHouse, no Redpanda — DuckDB + embedded bus only.

**Workspace:** `kron-nano/` — single member `crates/kron-nano`

### kron-nano/crates/kron-nano/src/main.rs
- Spawns collector, normalizer, stream, alert, query-api as concurrent tokio tasks
- Master broadcast channel sends shutdown to alert + query-api
- `await_termination_signal()` handles Ctrl-C / SIGTERM
- Enforces `config.mode == Nano` at startup

### Feature isolation
`kron-nano` **never** activates `clickhouse-backend` or `rdkafka` →
Cargo feature unification guarantees these are never compiled in.

Verified with:
```
cargo tree -p kron-nano | grep -E "clickhouse|rdkafka"
# (no output — confirmed clean)
```

### Deploy files (`deploy/nano/`)
| File | Purpose |
|---|---|
| `Dockerfile` | Multi-stage release image |
| `docker-compose.yml` | Single-service compose |
| `kron-nano.default.toml` | Full default config (all sections) |
| `prometheus.yml` | Prometheus scrape config |
| `install.sh` | Linux/macOS one-liner installer |
| `install.ps1` | Windows zero-interaction installer (PS1) |
| `uninstall.ps1` | Windows clean removal |
| `download-widget.html` | Embeddable website download button |

### Windows installer — kron-nano-setup.exe (new Rust crate)
New crate: `crates/kron-nano-setup/`

| File | Purpose |
|---|---|
| `Cargo.toml` | Deps: rsa, rand, uuid, colored, winreg |
| `setup.manifest` | UAC `requireAdministrator` — prompts before launch |
| `build.rs` | Embeds `kron-nano.exe` via `include_bytes!`, embeds manifest via `winres` |
| `src/main.rs` | Full installer logic (see below) |

**What `kron-nano-setup.exe` does on double-click:**
1. UAC prompt fires automatically (manifest)
2. Extracts embedded `kron-nano.exe` → `C:\Program Files\KronNano\`
3. Creates `C:\ProgramData\KronNano\{data, bus, rules, models, archive, migrations, logs}`
4. Generates RSA-2048 JWT key pair in pure Rust (no openssl.exe needed)
5. Locks private key with `icacls` (SYSTEM + Administrators only)
6. Auto-generates a tenant UUID
7. Writes `C:\ProgramData\KronNano\kron.toml` with all paths pre-filled
8. Opens 6 Windows Firewall inbound rules (8080, 8081, 50051, 514, 6514, 9100)
9. Installs `KronNano` Windows Service (auto-start, restart-on-failure × 3)
10. Writes service environment variables to registry
11. Starts the service
12. Adds `C:\Program Files\KronNano` to system PATH
13. Opens `http://localhost:8080` in default browser

### GitHub Actions — `.github/workflows/release.yml`
On every `v*.*.*` tag push:
1. Checks out `kron-nano` + `kron-core` side-by-side (path deps resolve correctly)
2. Builds `kron-nano.exe` (MSVC, `windows-latest`)
3. Sets `KRON_NANO_BIN` → builds `kron-nano-setup.exe` with binary embedded
4. Smoke-tests PE header (valid `.exe` check)
5. Publishes GitHub Release with:
   - `kron-nano-setup.exe` (self-contained installer)
   - `kron-nano-windows-x86_64.exe` (raw binary)
   - `install.ps1`, `uninstall.ps1`
   - `SHA256SUMS.txt`

---

## 4. kron-standard

**What it is:** Standard-tier Rust workspace. Contains crates exclusive to the
paid/enterprise deployment. Depends on kron-core via relative path.

**Workspace members (4 crates):**
| Crate | Description |
|---|---|
| `kron-agent` | eBPF/ETW endpoint collector, deploys to monitored machines |
| `kron-soar` | SOAR playbook engine, automated response |
| `kron-compliance` | CERT-In, RBI, DPDP Act, SEBI CSCRF reporting |
| `kron-ctl` | CLI management tool (`kron-ctl health`, `kron-ctl query`, etc.) |

**Path deps** point to `../kron-core/crates/...` with `features = ["clickhouse-backend"]`
so Standard builds get ClickHouse support without kron-nano ever seeing it.

**Why separate workspace:** Cargo feature unification — if kron-nano and kron-standard
shared a workspace, `clickhouse-backend` would be unified and compiled into nano.

### Deploy files (`deploy/`)
| Path | Purpose |
|---|---|
| `deploy/standard/docker-compose.yml` | Full Standard stack (ClickHouse, Redpanda, services) |
| `deploy/standard/kron.default.toml` | Standard default config |
| `deploy/standard/prometheus.yml` | Prometheus scrape config |
| `deploy/docker/kron-*.Dockerfile` | Per-service Dockerfiles |
| `deploy/compose/docker-compose.dev.yml` | Dev environment |
| `deploy/compose/docker-compose.qa.yml` | QA environment |

---

## 5. kron-docs

**What it is:** Standalone git repo containing all project documentation.
Consolidated from 3 overlapping locations in the old monorepo.

**Structure:**
```
kron-docs/
├── engineering/       ← DECISIONS (ADR-001..020), CLAUDE, CONTEXT, PHASES,
│                         AntiPatterns, CodeStructure, ErrorHandling, TestingGuide,
│                         WorkspaceSetup
├── docs/              ← PRD, API, Architecture, Database, Deployment, Features,
│   ├── runbooks/         GETTING_STARTED, Roadmap, Security, TechStack, UIUX,
│   ├── releases/         support-process, releases/v1.0.md
│   └── security/         runbooks (RB-001..006), security/ (pentest, soc2)
└── build-order/       ← BuildOrder, ComponentDependencies, DesignPartnerPlaybook,
                          Enterprise/Standard/Nano-BuildOrder, MilestoneChecklist
```

**What was deleted (duplicates):**
- `KRON-docs/` — 13 files, identical to `docs/`
- Root-level `AntiPatterns.md`, `CodeStructure.md`, `ErrorHandling.md`,
  `TestingGuide.md` — identical to `KRON-engineering/`
- Entire old `Kron/Kron/` monorepo scaffold (empty `crates/`, stale workspace)

**What was merged:**
- Root `DECISIONS.md` (220 lines, had ADR-017 + ADR-018..020) was used over
  `KRON-engineering/DECISIONS.md` (180 lines, missing newer ADRs)

---

## 6. kron-mobile

Moved from `Kron/Kron/flutter_app/` to `kron-mobile/` as a peer directory.

Added:
- `README.md` — Flutter app documentation
- `.github/workflows/ci.yml` — lint + test + Android APK build

---

## 7. Git Repositories Initialized

All five directories initialized as independent git repos with initial commits:

| Repo | Commit |
|---|---|
| `kron-core` | `24197c5` — Initial commit: kron-core shared library workspace |
| `kron-nano` | `6519af5` — Initial commit: kron-nano single-binary workspace |
| `kron-standard` | `90a8fc6` — Initial commit: kron-standard tier workspace |
| `kron-docs` | `4ead5f3` — Initial commit: consolidated KRON documentation |

`.gitignore` for kron-core: excludes `/target`, `Cargo.lock`, secrets
`.gitignore` for kron-nano/kron-standard: excludes `/target`, secrets (keeps `Cargo.lock`)

---

## 8. Compile Verification

All three Rust workspaces verified clean:

```
kron-core   →  Finished `dev` profile  (no errors)
kron-nano   →  Finished `dev` profile  (no errors)
kron-standard → Finished `dev` profile (no errors)
```

kron-nano dep tree confirmed free of ClickHouse and rdkafka:
```bash
cargo tree -p kron-nano | grep -E "clickhouse|rdkafka"
# (empty — correct)
```

---

## 9. Pending / Next Steps

- [ ] Push kron-core, kron-nano, kron-standard, kron-docs, kron-mobile to GitHub
- [ ] Decide relationship with existing `Hardik364/Kron` monorepo
- [ ] Add `--version` flag to kron-nano binary (needed for CI smoke test)
- [ ] Set up GitHub Actions secrets for cross-repo checkout in release.yml
- [ ] Configure `GITHUB_ORG` in download-widget.html to `JashanCybersec`
- [ ] Download GeoLite2-City.mmdb and document how to place it
- [ ] Add alert notification credentials via dashboard post-install
