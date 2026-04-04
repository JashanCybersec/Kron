# DECISIONS.md — Architectural Decision Log

**Purpose:** Every significant technical decision is recorded here.
Before adding a new dependency or making an architectural choice, check if it's already decided.
If it's already here, follow it. If you want to change a decision, propose it to the human first.

**Format:** ADR (Architecture Decision Record) — lightweight version.

---

## ADR-001: Rust as primary backend language

**Date:** Project start  
**Status:** Final  
**Decision:** All backend services written in Rust.  
**Rationale:** Memory safety without GC eliminates heap pressure that kills JVM-based SIEMs at scale. eBPF requires Rust (aya framework). Single binary deployment. Performance comparable to C for stream processing.  
**Consequences:** eBPF engineer must know Rust. Steeper learning curve than Go/Python. Larger initial effort pays off at scale.  
**Rejected alternatives:** Go (no eBPF story, GC pauses), Python (too slow for stream processing), Java (JVM overhead is the exact problem we're solving against).

---

## ADR-002: DuckDB for Nano tier storage

**Date:** Project start  
**Status:** Final  
**Decision:** Nano tier uses DuckDB embedded database, not ClickHouse.  
**Rationale:** DuckDB is a 40MB single binary with zero config. Handles 100M rows with <3s queries on 4GB RAM. Native Parquet read/write enables zero-loss migration to ClickHouse when customer grows.  
**Consequences:** Two storage implementations to maintain. Schema must be identical between DuckDB and ClickHouse (same column names, compatible types).  
**Migration path:** DuckDB → export Parquet → ClickHouse import. Seamless.

---

## ADR-003: Redpanda over Kafka

**Date:** Project start  
**Status:** Final  
**Decision:** Redpanda for Standard/Enterprise message bus. Not Kafka.  
**Rationale:** Same Kafka API — zero code change. No JVM — eliminates 6–16GB heap requirement. No ZooKeeper — simpler operations. C++ implementation — no GC pauses. 5x lower memory than equivalent Kafka setup.  
**Consequences:** Must use Kafka-compatible client libraries (rdkafka). Cannot use JVM-specific Kafka features.

---

## ADR-004: Embedded channel for Nano bus

**Date:** Project start  
**Status:** Final  
**Decision:** Nano tier uses a custom disk-backed async Rust channel, not a stripped-down Redpanda.  
**Rationale:** Redpanda minimum resource requirements are too high for Nano tier hardware. A disk-backed channel provides at-least-once delivery with <50MB overhead. The Redpanda API is only needed for multi-node HA which Nano doesn't require.  
**Interface:** Both implement the same `BusProducer` / `BusConsumer` traits. Code above the bus layer is identical.

---

## ADR-005: aya for eBPF

**Date:** Project start  
**Status:** Final  
**Decision:** Use `aya` Rust framework for eBPF programs.  
**Rationale:** Pure Rust eBPF (no C headers required). CO-RE support built-in. Active maintenance. Best documentation. Integrates naturally with tokio async runtime.  
**Consequences:** Requires Rust nightly for eBPF programs (stable for userspace). Build process is more complex — two compilation targets.

---

## ADR-006: OCSF as canonical event schema

**Date:** Project start  
**Status:** Final  
**Decision:** KRON's normalized event schema aligns with OCSF (Open Cybersecurity Schema Framework).  
**Rationale:** Industry standard for SIEM interoperability. Supported by AWS, Splunk, IBM, CrowdStrike. Future connector ecosystem will benefit from standard field names. Easier to import events from OCSF-speaking sources.  
**Consequences:** Schema is larger than a minimal custom schema. Some OCSF fields are not relevant to all event types (acceptable — use NULL).

---

## ADR-007: No raw SQL in application code

**Date:** Project start  
**Status:** Final  
**Decision:** All SQL is defined in `kron-storage`. Application code never constructs SQL strings.  
**Rationale:** Prevents SQL injection. Centralizes query optimization. Makes storage backend swapping possible. Enforces tenant_id in one place.  
**Exception:** SIGMA rule compilation outputs SQL — this SQL is validated, parameterized, and only executed through the storage layer with tenant_id injected.

---

## ADR-008: Self-signed CA for Standard tier mTLS

**Date:** Project start  
**Status:** Final  
**Decision:** Standard tier uses KRON-managed self-signed CA for mTLS, not SPIFFE/SPIRE.  
**Rationale:** SPIFFE/SPIRE requires its own HA deployment, adding operational complexity on a single-server Standard installation. Self-signed CA with auto-rotation provides sufficient security for single-tenant Standard deployments. SPIFFE/SPIRE remains in Enterprise where the operational overhead is justified.  
**Consequences:** Standard tier certs are managed by KRON, not a standard identity platform. Migration to SPIFFE/SPIRE in Enterprise upgrade path requires cert rotation.

---

## ADR-009: JWT with RS256, not HS256

**Date:** Project start  
**Status:** Final  
**Decision:** JWT tokens signed with RS256 (asymmetric), not HS256 (symmetric).  
**Rationale:** In a multi-service architecture, RS256 allows any service to verify tokens using only the public key — no shared secret that could leak. MSSP portal can verify tokens without needing the signing key.  
**Key management:** Private key stored in Vault. Public key published at `/.well-known/jwks.json`.

---

## ADR-010: Parquet as the universal cold storage format

**Date:** Project start  
**Status:** Final  
**Decision:** All cold-tier data stored as Parquet, regardless of hot-tier storage (DuckDB or ClickHouse).  
**Rationale:** DuckDB reads Parquet natively. ClickHouse reads Parquet natively. This is the migration path between tiers — copy Parquet files, no transformation needed. Parquet achieves 3:1 additional compression on top of ClickHouse's columnar compression.  
**Consequences:** Cold storage queries require rehydration (copy Parquet back to hot storage). Acceptable for compliance/forensic use cases where cold queries are infrequent.

---

## ADR-011: SolidJS over React for web UI

**Date:** Project start  
**Status:** Final  
**Decision:** SolidJS for the analyst web UI.  
**Rationale:** No virtual DOM → surgical DOM updates → crucial for alert queue that updates in real-time with 1000+ items. Smaller bundle (~7KB vs ~40KB React). Better TypeScript integration. Reactivity model is simpler for data-heavy dashboards.  
**Consequences:** Smaller ecosystem than React. Harder to hire for. Mitigated by: SolidJS API is intentionally similar to React — React engineers learn it in a week.

---

## ADR-012: SIGMA as the rule format

**Date:** Project start  
**Status:** Final  
**Decision:** SIGMA is the canonical detection rule format. No custom rule format.  
**Rationale:** 3,000+ existing rules available immediately. Community contributions. Analysts who know SIGMA elsewhere can use KRON immediately. Rules are portable — export to Splunk, Elastic, etc. Industry converging on SIGMA.  
**Consequences:** KRON must maintain a SIGMA→ClickHouse SQL compiler. Some SIGMA features map imperfectly to ClickHouse SQL (handled by translator with documented limitations).

---

## ADR-013: Argon2id for password hashing

**Date:** Project start  
**Status:** Final  
**Decision:** Argon2id with memory=64MB, iterations=3, parallelism=4.  
**Rationale:** Winner of Password Hashing Competition. Resistant to GPU and ASIC attacks. Parameters chosen to take ~500ms on reference hardware — slow enough to resist brute force, fast enough for normal login.  
**Do not change parameters** without security review. Do not use bcrypt or scrypt.

---

## ADR-014: No external AI calls

**Date:** Project start  
**Status:** Final — this is a product requirement, not just a preference  
**Decision:** Zero calls to external AI APIs (OpenAI, Anthropic, Azure OpenAI, Google, etc.) from production code. All inference is local.  
**Rationale:** KRON's core value proposition is data sovereignty. A SIEM that sends security telemetry to OpenAI for analysis cannot be marketed as "your data stays on-premise." This is a hard product requirement, not a technical preference.  
**Enforcement:** `cargo-deny` blocks any crate that is an OpenAI/Anthropic/etc. client library. CI will fail if such a dependency is added.  
**Exception:** Development tooling (not production code) may use AI APIs. The kron-ai crate must have a test that verifies no outbound HTTP calls to non-local addresses during inference.

---

## ADR-015: Merkle chain for audit log

**Date:** Project start  
**Status:** Final  
**Decision:** Audit log rows are cryptographically chained using SHA256 Merkle structure.  
**Rationale:** Provides tamper evidence for compliance (CERT-In, RBI require audit trail integrity). Detects insider deletion/modification. Chain break is detectable and precisely locatable. Does not require external blockchain — pure cryptography.  
**Implementation:** See `docs/Database.md` — `audit_log` table schema. Chain validated on demand and on every compliance report generation.

---

## ADR-016: Per-tenant DEK, not per-row encryption

**Date:** Project start  
**Status:** Final  
**Decision:** Encrypt cold-tier Parquet files with a per-tenant DEK. Do not encrypt individual ClickHouse rows.  
**Rationale:** Per-row encryption in ClickHouse kills query performance (every read requires decrypt). Per-file encryption of cold Parquet is sufficient for compliance (data at rest encrypted). ClickHouse data at rest is protected by OS-level disk encryption (LUKS) on the server, not row-level crypto.  
**Consequences:** ClickHouse data on-disk is not encrypted at the row level. Disk encryption (LUKS) is mandatory. This is documented in the security model.

---

## ADR-017: maxminddb for GeoLite2 IP enrichment

**Date:** 2026-03-22
**Status:** Final
**Decision:** Use the `maxminddb` crate (v0.24) to read MaxMind GeoLite2-City MMDB files for IP geolocation enrichment in kron-normalizer.
**Rationale:** MaxMind GeoLite2 is the de-facto standard for offline IP geolocation. The `maxminddb` crate is the only production-quality Rust reader. The MMDB is embedded on disk (no network calls), which satisfies ADR-014 (no external AI/data calls).
**Consequences:** The GeoLite2-City.mmdb file (~65 MB) must be distributed with deployments. Path configured via `normalizer.geoip_db_path`. If absent, enrichment is disabled gracefully (logged warning, no error).

---

## ADR-018: Simple HashMap + Instant for asset TTL cache

**Date:** 2026-03-22
**Status:** Final
**Decision:** Implement the asset enrichment cache in kron-normalizer as `HashMap<String, (Option<AssetInfo>, Instant)>` with manual TTL checks. No additional caching crate (no `moka`, no `lru`).
**Rationale:** The cache in Phase 1.6 is always empty (storage backend not yet wired). A simple HashMap is sufficient infrastructure. Adding a new crate requires human approval; for a feature that is a no-op this phase, it's not justified.
**Consequences:** Cache eviction is manual (`evict_expired()` call from maintenance loop). Max size is enforced by random eviction. Upgrade to `moka` or similar when backend lookup is wired in Phase 2.

---

## ADR-019: totp-rs for TOTP / HOTP implementation

**Date:** 2026-03-23
**Status:** Final
**Decision:** Use `totp-rs` (v0.5) for TOTP MFA in kron-auth.
**Rationale:** Explicitly called out in the PHASES.md spec ("TOTP validation (totp-rs crate)"). Pure Rust, no C bindings, implements RFC 6238. Supports both TOTP and HOTP. `gen_secret` feature used to generate QR-enrollable secrets.
**Consequences:** TOTP secrets stored per-user in the auth store (Phase 3). QR code displayed on first login for authenticator app enrolment.

---

## ADR-020: utoipa for OpenAPI spec generation

**Date:** 2026-03-23
**Status:** Final
**Decision:** Use `utoipa` (v4) + `utoipa-axum` + `utoipa-swagger-ui` for auto-generated OpenAPI 3.1 spec in kron-query-api.
**Rationale:** Explicitly called out in PHASES.md ("OpenAPI spec auto-generated (utoipa)"). Integrates natively with Axum 0.7 via the `utoipa-axum` macro layer. Zero runtime overhead — spec generation is compile-time. Swagger UI served at `/docs`.
**Consequences:** Every handler must carry `#[utoipa::path]` annotations. Return types must implement `ToSchema`. Schema drift is impossible since types are shared.

---

## Open Questions (not yet decided)

| Question | Raised by | Date | Context |
|---|---|---|---|
| — | — | — | — |

*Add new open questions here. They become ADRs once decided.*
