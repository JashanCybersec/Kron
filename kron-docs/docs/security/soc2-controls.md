# KRON SOC 2 Type I — Controls Documentation

**Version:** 1.0
**Classification:** CONFIDENTIAL — Internal
**Owner:** Hardik (security@kron.security)
**Last updated:** 2026-03-28
**Audit target:** SOC 2 Type I — Trust Service Criteria (Security, Availability, Confidentiality)

---

## Overview

This document maps KRON's implemented controls to the AICPA Trust Services Criteria (TSC) required for SOC 2 Type I attestation. Each control entry identifies the criteria reference, the control description, the implementation evidence, and the evidence location.

Controls are collected automatically by Vanta (see `deploy/vanta/` for agent configuration) and supplemented with manual evidence for custom controls.

---

## CC1 — Control Environment

### CC1.1 — COSO Principle 1: Commitment to Integrity and Ethical Values

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC1.1-01 | Security policies documented and accessible to all staff | CLAUDE.md, docs/Security.md, docs/Architecture.md committed to version-controlled repository | GitHub repository — `/docs/Security.md` |
| CC1.1-02 | Code of conduct / ethical standards defined | Onboarding documentation includes security responsibilities | HR onboarding pack |
| CC1.1-03 | Security-by-default coding standards enforced | CLAUDE.md Prime Directives (no unwrap, no hardcoded secrets, tenant_id mandatory) | `CLAUDE.md` lines 1–100 |

### CC1.2 — Board oversight of security

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC1.2-01 | Security incidents escalated to leadership | RB-006 Security Incident runbook defines escalation path | `docs/runbooks/RB-006-security-incident.md` |

---

## CC2 — Communication and Information

### CC2.2 — Internal communication of security information

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC2.2-01 | Security decisions documented in DECISIONS.md | Architectural Decision Records (ADRs) maintained in version control | `DECISIONS.md` |
| CC2.2-02 | Session context log maintained across development sessions | CONTEXT.md updated every session | `CONTEXT.md` |

---

## CC3 — Risk Assessment

### CC3.2 — Risk identification

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC3.2-01 | Threat model documented | Pentest scope covers OWASP Top 10 + tenant isolation threats | `docs/security/pentest-scope.md` |
| CC3.2-02 | Dependency vulnerabilities monitored | `cargo audit` runs on every CI push via `rustsec/audit-check@v1` | `.github/workflows/ci.yml` — `audit` job |
| CC3.2-03 | License and banned dependency policy | `cargo-deny` with approved license list | `.github/workflows/ci.yml` — `deny` job |

---

## CC6 — Logical and Physical Access Controls

### CC6.1 — Logical access security

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC6.1-01 | Authentication requires valid JWT signed with RS256 | `kron-auth` crate: JWT issuance and validation | `crates/kron-auth/src/jwt.rs` |
| CC6.1-02 | Multi-factor authentication (TOTP) enforced for privileged roles | TOTP required for admin and super_admin; login_screen.dart implements TOTP field | `crates/kron-auth/src/totp.rs`; `mobile/lib/features/auth/login_screen.dart` |
| CC6.1-03 | Role-based access control (RBAC) with least privilege | `Resource` and `Action` enums; `can()` function enforces per-role permissions | `crates/kron-auth/src/rbac.rs` |
| CC6.1-04 | Tenant isolation: JWT tenant_id claim is sole authority for data scoping | 4-gate isolation model; tenant_id never accepted from request body or query params | `crates/kron-storage/src/adaptive.rs`; `tests/integration/tenant_isolation.rs` |
| CC6.1-05 | Session termination: token revocation via logout endpoint | `/auth/logout` deletes token from flutter_secure_storage and invalidates server-side | `crates/kron-auth/src/handlers.rs`; `mobile/lib/services/api_service.dart` |
| CC6.1-06 | Biometric confirmation for high-impact actions | SOAR playbook approval requires biometric (Face ID / fingerprint) | `mobile/lib/features/soar/soar_approval_screen.dart` lines 100–140 |

### CC6.2 — Prior access removed for terminated employees

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC6.2-01 | User deactivation endpoint | `DELETE /api/v1/users/:id` implemented in kron-query-api | `crates/kron-query-api/src/handlers/users.rs` |
| CC6.2-02 | Tenant offboarding with data purge | `offboard_tenant()` in TenantStore marks tenant inactive; data purge job scheduled | `crates/kron-storage/src/tenant.rs` — `offboard()` |

### CC6.3 — Access restricted to authorized users only

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC6.3-01 | All API endpoints require valid JWT | Axum middleware extracts and validates JWT on every request | `crates/kron-query-api/src/middleware/auth.rs` |
| CC6.3-02 | Event intake requires agent token | kron-collector validates agent registration token | `crates/kron-collector/src/handlers/intake.rs` |
| CC6.3-03 | mTLS for inter-service communication (staging/prod) | Configured in Helm chart; disabled in dev mode via `KronConfig` | `deploy/helm/kron/values.yaml` |

### CC6.6 — Security measures against threats from outside the boundaries

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC6.6-01 | Rate limiting on authentication endpoints | kron-query-api enforces 5-attempt lockout + per-minute rate limits | `crates/kron-query-api/src/middleware/rate_limit.rs` |
| CC6.6-02 | Input validation on all API endpoints | Axum extractors validate JSON shape; UUIDs validated before reaching storage | All handler files in `crates/kron-query-api/src/handlers/` |
| CC6.6-03 | Network security policy: ClickHouse not externally accessible | `network_security_config.xml` enforces HTTPS; ClickHouse bound to cluster-internal only | `mobile/android/app/src/main/res/xml/network_security_config.xml` |
| CC6.6-04 | Content Security Policy on web UI | SolidJS app served with strict CSP headers | `crates/kron-query-api/src/middleware/security_headers.rs` |

---

## CC7 — System Operations

### CC7.1 — Detection of security events

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC7.1-01 | All authentication events logged with structured fields | `tracing::info!` on login success/failure with tenant_id, user_id | `crates/kron-auth/src/handlers.rs` |
| CC7.1-02 | Prometheus metrics for anomaly detection | Error rate, auth failure rate, alert volume per tenant exported | `deploy/prometheus/alerts.yml` |
| CC7.1-03 | Tenant isolation canary test runs every 5 minutes | Integration test `canary` in tenant_isolation.rs verifies cross-tenant isolation | `tests/integration/tenant_isolation.rs` |

### CC7.2 — Monitoring of system components

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC7.2-01 | Grafana dashboards for all services | Prometheus + Grafana in `deploy/compose/docker-compose.yml` | `deploy/compose/docker-compose.yml` |
| CC7.2-02 | Prometheus alerting rules defined | CPU, memory, disk, error rate, lag alerts | `deploy/prometheus/alerts.yml` |
| CC7.2-03 | Service health endpoints | `GET /health` on all services; `kron-ctl health` aggregates all | `crates/kron-query-api/src/handlers/health.rs` |

### CC7.4 — Security incident response

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC7.4-01 | Incident response runbook documented and rehearsed | RB-006 defines detection → containment → eradication → recovery → post-mortem | `docs/runbooks/RB-006-security-incident.md` |
| CC7.4-02 | SOAR playbooks for automated containment | kron-soar crate executes containment playbooks with analyst approval gate | `crates/kron-soar/` |

---

## CC8 — Change Management

### CC8.1 — Authorized change management

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| CC8.1-01 | All changes via pull request with mandatory review | Branch protection on `main` requires 1 approval + passing CI | GitHub branch protection settings |
| CC8.1-02 | CI pipeline validates all changes before merge | `cargo test`, `cargo clippy`, `cargo fmt`, `cargo audit`, `cargo deny` | `.github/workflows/ci.yml` |
| CC8.1-03 | Architectural decisions recorded before implementation | DECISIONS.md contains all ADRs | `DECISIONS.md` |
| CC8.1-04 | Release artifacts signed and verifiable | cosign + GPG signing in release pipeline | `.github/workflows/release.yml` |
| CC8.1-05 | SBOM generated for every release | CycloneDX JSON + XML via cargo-cyclonedx | `.github/workflows/release.yml` — `sbom` job |

---

## A1 — Availability

### A1.1 — System availability commitments

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| A1.1-01 | ClickHouse backup automated with verified restore | `scripts/backup.sh` (S3 + local), `scripts/restore.sh`, `scripts/backup-verify.sh` | `scripts/backup*.sh` |
| A1.1-02 | Backup RTO < 4 hours documented | RB-005 defines backup/restore procedure and RTO target | `docs/runbooks/RB-005-backup-and-restore.md` |
| A1.1-03 | Redpanda replication factor ≥ 2 in production | Helm values set `replication.factor=2` | `deploy/helm/kron/values.yaml` |
| A1.1-04 | Multi-replica deployment for all stateless services | Helm deployment with `replicas: 2` minimum | `deploy/helm/kron/templates/` |

---

## C1 — Confidentiality

### C1.1 — Confidential information identified and protected

| Control ID | Description | Implementation | Evidence |
|---|---|---|---|
| C1.1-01 | Personal data (DPDP) tracked with access trail | kron-compliance DPDP module records every personal data access | `crates/kron-compliance/src/dpdp.rs` |
| C1.1-02 | Data localisation enforced (RBI) | RBI module verifies all storage within India region | `crates/kron-compliance/src/rbi.rs` |
| C1.1-03 | Secrets never committed to version control | `cargo-deny`, `.gitignore`, pre-commit hooks block secret patterns | `.github/workflows/ci.yml` — `deny` job |
| C1.1-04 | JWT stored in secure storage on mobile | flutter_secure_storage (Keychain on iOS, Keystore on Android) | `mobile/lib/services/api_service.dart` |

---

## Evidence Collection

Vanta agent is installed on all production nodes and collects:
- User access reviews (monthly)
- Vulnerability scan results
- Backup verification logs
- Endpoint configuration snapshots

**Vanta workspace:** `kron-security` (workspace ID in 1Password — `Vanta Workspace ID`)
**Evidence review cadence:** Monthly automated + quarterly manual review
**Next Type I audit window:** Q3 2026

---

## Gap Register

Items identified but not yet fully automated:

| Gap ID | Description | Owner | Target Date |
|---|---|---|---|
| G-001 | Vanta agent not yet deployed to production nodes | Hardik | v1.0 GA |
| G-002 | Penetration test findings not yet remediated (pending first engagement) | Hardik | v1.0 GA |
| G-003 | USB installer hardware test matrix incomplete | Hardik | v1.0 GA |
| G-004 | Formal background check process for new hires not documented | Hardik | v1.1 |
