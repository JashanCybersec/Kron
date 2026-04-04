# CLAUDE.md — KRON Master Instructions for Claude Code

This file is read by Claude Code at the start of every session.
It is the single source of truth for how to build KRON.
Never deviate from these instructions without explicit human approval.

---

## What KRON Is

KRON is a production-grade, on-premise SIEM platform for the Indian market.
It is NOT a prototype. It is NOT a demo. Every line of code written must be
production-quality from day one.

Full product context: see `/docs/PRD.md`, `/docs/Architecture.md`, `/docs/TechStack.md`

---

## Prime Directives

These rules override everything else. No exceptions.

### 1. Never write temporary code
There is no such thing as "we'll fix this later" in KRON.
If you write a TODO, it must have: a GitHub issue number, an owner, and a deadline.
A TODO without those three things is not acceptable.
```rust
// ACCEPTABLE:
// TODO(#142, jashan, v1.1): Replace with ONNX model when training data available

// NOT ACCEPTABLE:
// TODO: fix this later
// FIXME: hack for now
// temp solution
```

### 2. Never mock production dependencies
If a function needs ClickHouse, it talks to ClickHouse.
If a function needs Redpanda, it talks to Redpanda.
Use test containers in tests. Use real services in code.
The only exception: unit tests for pure business logic with no I/O.

### 3. Never use unwrap() or expect() in production code paths
```rust
// NOT ACCEPTABLE in production:
let result = operation().unwrap();
let value = map.get("key").expect("key must exist");

// ACCEPTABLE:
let result = operation()
    .map_err(|e| KronError::StorageError(e.to_string()))?;
let value = map.get("key")
    .ok_or(KronError::MissingField("key".to_string()))?;
```

### 4. Never hardcode configuration
No hardcoded IPs, ports, credentials, timeouts, or thresholds in source code.
Everything configurable goes in `KronConfig` (see `/src/config.rs`).
```rust
// NOT ACCEPTABLE:
let timeout = Duration::from_secs(30);
let clickhouse_url = "http://localhost:8123";

// ACCEPTABLE:
let timeout = config.clickhouse.query_timeout;
let clickhouse_url = &config.clickhouse.url;
```

### 5. Every error must be handled, logged, and have context
```rust
// NOT ACCEPTABLE:
let _ = send_alert(alert).await;

// ACCEPTABLE:
send_alert(&alert).await
    .map_err(|e| {
        tracing::error!(
            alert_id = %alert.id,
            tenant_id = %alert.tenant_id,
            error = %e,
            "Failed to send alert notification"
        );
        e
    })?;
```

### 6. Every public function must have a doc comment
```rust
/// Computes the composite risk score for an alert.
///
/// Combines rule match severity, ONNX anomaly score, IOC hit weight,
/// and asset criticality into a single 0–100 score.
///
/// # Arguments
/// * `rule_severity` - Base severity from the matched SIGMA rule (0–100)
/// * `anomaly_score` - ONNX isolation forest score (0.0–1.0)
/// * `ioc_hit` - Whether the event matched an IOC (bool)
/// * `asset_criticality` - Asset criticality multiplier (0.5–2.0)
///
/// # Returns
/// Risk score 0–100 where 80+ = P1, 60–79 = P2, 40–59 = P3, etc.
pub fn compute_risk_score(...) -> u8 { ... }
```

### 7. Tenant ID is on every database operation. No exceptions.
Every query, every insert, every update touches `tenant_id`.
The query rewrite middleware is a safety net, not a substitute for correct code.

### 8. Never build a feature not in the current phase
Check `PHASES.md` for what is in scope right now.
If a feature is not in the current phase, do not build it.
Ask the human to update `PHASES.md` if scope changes.

---

## How to Work in This Codebase

### Before writing any code

1. Read the relevant spec file in `/docs/`
2. Check `PHASES.md` — is this feature in the current phase?
3. Check `DECISIONS.md` — has this architectural decision already been made?
4. Check if the interface already exists — do not design a new one
5. Look for existing tests — understand what behaviour is expected

### When implementing a feature

1. Write the types first (`src/types/`)
2. Write the error variants (`src/error.rs`)
3. Write the tests (failing)
4. Write the implementation
5. Make the tests pass
6. Add tracing spans and metrics
7. Update the relevant doc comment

### When you are uncertain

Stop. Do not guess. Do not write speculative code.
Ask the human: "I need clarification on X before I can implement Y."
A question is always better than wrong code.

### When you find a bug in existing code

Do not silently fix it while implementing something else.
1. Note it clearly: "I found a bug in `X` while implementing `Y`"
2. Ask whether to fix it now or create an issue
3. Fix it in a separate, clearly labelled change

---

## Repository Structure

```
kron/
├── CLAUDE.md               ← you are here
├── PHASES.md               ← current build phase and task checklist
├── DECISIONS.md            ← architectural decisions already made
├── CONTEXT.md              ← running log of important decisions this session
├── docs/                   ← product documentation
│   ├── PRD.md
│   ├── Architecture.md
│   ├── TechStack.md
│   ├── Database.md
│   ├── API.md
│   ├── Security.md
│   ├── Features.md
│   ├── Deployment.md
│   ├── AIInstructions.md
│   └── UIUX.md
├── crates/                 ← Rust workspace members
│   ├── kron-agent/         ← eBPF + ETW collection agent
│   ├── kron-collector/     ← agentless, syslog, cloud, OT intake
│   ├── kron-normalizer/    ← parse, enrich, normalize
│   ├── kron-stream/        ← stream processor (detection, scoring)
│   ├── kron-storage/       ← ClickHouse + DuckDB abstraction layer
│   ├── kron-query-api/     ← REST + WebSocket API (Axum)
│   ├── kron-alert/         ← alert engine + notifications
│   ├── kron-soar/          ← SOAR playbook engine
│   ├── kron-compliance/    ← compliance mapping + reports
│   ├── kron-auth/          ← JWT, RBAC, MFA
│   ├── kron-ai/            ← ONNX inference + Mistral
│   └── kron-types/         ← shared types (no dependencies)
├── web/                    ← SolidJS frontend
├── mobile/                 ← Flutter app
├── deploy/                 ← Helm charts, Docker Compose, Terraform
│   ├── helm/
│   ├── compose/
│   └── terraform/
├── migrations/             ← numbered SQL migration files
├── models/                 ← ONNX model files + training scripts
├── rules/                  ← SIGMA rules (built-in)
│   ├── sigma-oss/          ← upstream SIGMA corpus
│   └── india-pack/         ← KRON India-specific rules
├── tests/                  ← integration tests (not in crates/)
│   ├── integration/
│   └── e2e/
└── scripts/                ← build, release, tooling scripts
```

---

## Coding Standards

### Rust

**Formatting:** `rustfmt` with default settings. Run before every commit.

**Linting:** `clippy` with these settings in `Cargo.toml`:
```toml
[lints.clippy]
pedantic = "warn"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

**Error handling:** All crates define their own `Error` enum using `thiserror`.
All errors implement `Display` with human-readable messages.
All errors are logged at the point of handling, not at the point of propagation.

**Async:** Use `tokio` exclusively. No `async-std`. No blocking calls in async context.
Use `tokio::task::spawn_blocking` for CPU-intensive work.

**Logging:** `tracing` crate. Structured fields. Every significant operation gets a span.
```rust
#[tracing::instrument(skip(db), fields(tenant_id = %tenant_id, event_count = events.len()))]
async fn batch_insert_events(tenant_id: TenantId, events: Vec<KronEvent>, db: &Storage) -> Result<()>
```

**Metrics:** `metrics` crate with Prometheus exporter. Every service exposes:
- Request count + latency histogram
- Error count by type
- Business metrics (events/sec, alerts/sec)

**Tests:**
- Unit tests: `#[cfg(test)]` module in same file
- Integration tests: `tests/integration/` using testcontainers
- All tests must be deterministic — no sleeps, no time-dependent assertions
- Test function names: `test_<what>_when_<condition>_then_<expected>`

### TypeScript / SolidJS

**Formatting:** Prettier, default settings.
**Linting:** ESLint with `@typescript-eslint/recommended`.
**Types:** No `any`. No `// @ts-ignore`. Every component is typed.
**State:** `createSignal` and `createStore` only. No global mutable state.
**API calls:** All API calls go through `/web/src/api/client.ts`. No direct fetch() calls in components.

### Dart / Flutter

**Formatting:** `dart format`.
**State:** Riverpod only. No setState() except for truly local ephemeral state.
**API calls:** Through `lib/services/api_service.dart` only.

---

## What Never Gets Committed

These will cause CI to fail:

- Credentials, tokens, API keys of any kind
- `.env` files (`.env.example` is fine)
- `unwrap()` or `expect()` outside of tests
- `println!()` in production code (use `tracing::info!()`)
- Commented-out code blocks
- Files > 500 lines (split into modules)
- Functions > 80 lines (extract to helpers)
- Hardcoded IPs, URLs, or ports
- `TODO` without issue number and owner

---

## Git Conventions

**Branch naming:**
- `feat/phase-1/ebpf-agent` — new feature in a phase
- `fix/123-clickhouse-timeout` — bug fix (issue number first)
- `refactor/normalizer-pipeline` — refactoring
- `docs/update-api-reference` — docs only

**Commit messages (Conventional Commits):**
```
feat(agent): add CO-RE support for kernel 5.4+

Implements BTF-based type resolution for eBPF programs,
enabling deployment on kernels 5.4+ without recompilation.

Closes #42
```

**PR requirements:**
- All CI checks pass
- At least 1 reviewer approval
- Test coverage does not decrease
- CONTEXT.md updated if architectural decisions were made

---

## How Claude Should Behave in Sessions

### Start of session
1. Read this file (CLAUDE.md)
2. Read PHASES.md — what phase are we in? What tasks are left?
3. Read CONTEXT.md — what happened in recent sessions?
4. Ask the human: "What are we working on today?"

### During session
- Work on ONE task at a time from PHASES.md
- Mark tasks complete in PHASES.md as you finish them
- If you discover something that needs a decision, add it to DECISIONS.md
- If you make an architectural choice, add it to CONTEXT.md
- Do not start the next task without human confirmation

### End of session
1. Update CONTEXT.md with what was done and any open questions
2. Update PHASES.md — mark completed tasks
3. List any new issues that should be created
4. Tell the human what the next session should start with

### If you are stuck
Say: "I'm blocked on [specific thing]. I need [specific information] to proceed."
Do not write speculative code to get unstuck.
Do not silently make an assumption and continue.

### If the human asks you to do something outside the current phase
Say: "That's in Phase X, and we're currently in Phase Y. Do you want to:
1. Add this to Phase Y scope (update PHASES.md)
2. Note it for Phase X and continue with current work"

---

## Anti-Patterns — Things Claude Must Never Do

1. **Never write a "skeleton" or "placeholder" implementation** that doesn't actually work.
   If a function can't be fully implemented yet, don't write it at all. Write a note in PHASES.md instead.

2. **Never copy-paste code between files.** Extract to a shared function in `kron-types` or a utility module.

3. **Never implement the same concept twice.** If `KronEvent` is defined in `kron-types`, it is defined there and nowhere else.

4. **Never add a dependency without checking DECISIONS.md first.** The tech stack is fixed. Adding a new crate requires human approval and a DECISIONS.md entry.

5. **Never write a function that does more than one thing.** Single responsibility. Always.

6. **Never silently swallow an error.**
   ```rust
   // NEVER:
   let _ = risky_operation().await;
   if let Ok(x) = risky_operation().await { use(x); }  // error silently ignored
   ```

7. **Never write SQL strings inline in business logic.** All SQL lives in the storage layer (`kron-storage`).

8. **Never access `tenant_id` from anywhere except the authenticated request context.** It must come from the JWT claim, never from request body or query params.
