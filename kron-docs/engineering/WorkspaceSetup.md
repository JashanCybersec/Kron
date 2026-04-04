# WorkspaceSetup.md — Exact Rust Workspace Configuration

This file contains the exact content of key config files.
Copy these exactly. Do not deviate without updating DECISIONS.md.

---

## `Cargo.toml` (workspace root)

```toml
[workspace]
resolver = "2"
members = [
    "crates/kron-types",
    "crates/kron-storage",
    "crates/kron-bus",
    "crates/kron-agent",
    "crates/kron-collector",
    "crates/kron-normalizer",
    "crates/kron-stream",
    "crates/kron-ai",
    "crates/kron-alert",
    "crates/kron-auth",
    "crates/kron-soar",
    "crates/kron-compliance",
    "crates/kron-query-api",
    "crates/kron-ctl",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.75"
authors = ["Jashan <jashan@kron.security>"]
license = "Apache-2.0"

[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }
tokio-stream = "0.1"

# Web framework
axum = { version = "0.7", features = ["ws", "multipart"] }
tower = { version = "0.4", features = ["full"] }
tower-http = { version = "0.5", features = ["cors", "compression-gzip", "trace"] }
tonic = { version = "0.11", features = ["tls"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
thiserror = "1"
anyhow = "1"  # only in binaries (main.rs), not libraries

# Logging & tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Metrics
metrics = "0.22"
metrics-exporter-prometheus = "0.13"

# Database
clickhouse = { version = "0.11", features = ["tls"] }
duckdb = { version = "0.10", features = ["bundled"] }

# Message bus
rdkafka = { version = "0.36", features = ["cmake-build", "ssl"] }

# eBPF
aya = { version = "0.12" }
aya-log = "0.2"

# Cryptography
argon2 = "0.5"
jsonwebtoken = "9"
rustls = { version = "0.23", features = ["ring"] }
sha2 = "0.10"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
aes-gcm = "0.10"

# AI/ML
ort = { version = "1.18", features = ["load-dynamic"] }
ndarray = "0.15"

# Utilities
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
regex = "1"
serde_yaml = "0.9"
toml = "0.8"
bytes = "1"
futures = "0.3"
async-trait = "0.1"
once_cell = "1"
dashmap = "5"

# Testing
testcontainers = "0.15"
testcontainers-modules = { version = "0.3", features = ["clickhouse"] }

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true

[profile.dev]
opt-level = 0
debug = true

[workspace.lints.rust]
unsafe_code = "forbid"  # no unsafe except kron-agent eBPF interop

[workspace.lints.clippy]
pedantic = "warn"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
missing_docs = "warn"
missing_errors_doc = "warn"
```

---

## `rustfmt.toml`

```toml
edition = "2021"
max_width = 100
tab_spaces = 4
use_small_heuristics = "Default"
imports_granularity = "Module"
group_imports = "StdExternalCrate"
```

---

## `.cargo/config.toml`

```toml
[build]
# Use mold linker for faster builds (install: apt install mold)
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

# eBPF target for kron-agent
[target.bpfel-unknown-none]
rustflags = ["-C", "relocation-model=pic"]
```

---

## `deny.toml` (cargo-deny)

```toml
[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "Unicode-DFS-2016",
    "CC0-1.0",
]
deny = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]

[bans]
# These crates are banned — see DECISIONS.md for rationale
deny = [
    # No JVM-wrapper crates
    { name = "jni" },
    # No external AI API clients
    { name = "async-openai" },
    { name = "openai" },
    # Use rustls, not openssl
    { name = "openssl" },
    { name = "openssl-sys" },
    # No unmaintained crypto
    { name = "md5" },
    { name = "sha1" },  # use sha2
]

[advisories]
# Deny any crate with an unpatched security advisory
deny = ["unmaintained", "unsound", "yanked"]
vulnerability = "deny"
```

---

## `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  check:
    name: Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --workspace --all-targets

  fmt:
    name: Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --all -- --check

  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --workspace --all-targets -- -D warnings

  test:
    name: Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --workspace --lib

  integration:
    name: Integration Tests
    runs-on: ubuntu-latest
    services:
      clickhouse:
        image: clickhouse/clickhouse-server:latest
        ports:
          - 8123:8123
      redpanda:
        image: redpandadata/redpanda:latest
        ports:
          - 9092:9092
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --workspace -- --include-ignored integration

  audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  deny:
    name: License Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v1

  secrets:
    name: No Secrets Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gitleaks/gitleaks-action@v2
```
