# CONTEXT.md — Running Session Log

**Purpose:** Claude reads this at the start of every session to understand what happened previously.
The human updates this after each session, or Claude updates it at the end of each session.

**Rule:** Never delete entries. Only append. Old entries give context for why current code exists.

---

## How to Write a Session Entry

```markdown
## Session: YYYY-MM-DD — [What was worked on]

### Completed
- List of tasks completed (reference PHASES.md task IDs where possible)

### Decisions Made
- Any architectural decisions (add to DECISIONS.md too)

### Code Written
- Files created or significantly modified

### Known Issues / Tech Debt
- Anything not done perfectly that needs attention

### Open Questions
- Anything unresolved that needs human input

### Next Session Should Start With
- Specific instructions for the next Claude session
```

---

## Session: [Project Start] — Documentation and Architecture

### Completed
- Full product documentation created in `/docs/`
- PRD, Features, Architecture, TechStack, Database, API, Security, Deployment, AIInstructions, UIUX, Runbooks, Roadmap
- Engineering guidance files created
- Architectural decisions logged in DECISIONS.md
- Build phases defined in PHASES.md

### Decisions Made
- All ADR-001 through ADR-016 (see DECISIONS.md)
- Rust workspace with 12 crates
- DuckDB (Nano) / ClickHouse (Standard/Enterprise) tiered storage
- Redpanda / embedded channel tiered bus
- SolidJS web, Flutter mobile
- SIGMA rule engine
- ONNX + Mistral AI architecture
- No external AI calls (ADR-014)

### Code Written
- None yet — documentation phase only

### Known Issues / Tech Debt
- None (project not started)

### Open Questions
- Exact kernel version matrix for eBPF CO-RE support needs research
- Mistral 7B GGUF quantization level for CPU mode (q4_k_m vs q5_k_m) — test on target hardware
- WhatsApp Business API approval timeline in India — apply early

### Next Session Should Start With
1. Read CLAUDE.md
2. Read PHASES.md — start Phase 0
3. Initialize Rust workspace: `cargo new --name kron . --lib`
4. Create all crate directories under `crates/`
5. Set up `rustfmt.toml`, `clippy.toml`, `.cargo/config.toml`
6. First task: Phase 0 — Repository & Tooling

---

*Future sessions append here.*
