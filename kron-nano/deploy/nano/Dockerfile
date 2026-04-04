# kron-nano — Single-binary KRON SIEM
#
# Multi-stage build:
#   Stage 1 (builder): Compiles the kron-nano binary from the Rust workspace.
#   Stage 2 (runtime): Minimal Debian image with only the binary and runtime data.
#
# Build:
#   docker build -f deploy/nano/Dockerfile -t kron-nano:latest .
#
# Run:
#   docker run -d \
#     -v /etc/kron:/etc/kron:ro \
#     -v /var/lib/kron:/var/lib/kron \
#     -p 8080:8080 -p 50051:50051 -p 514:514/udp \
#     kron-nano:latest

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:1.75-slim-bookworm AS builder

# System dependencies for native Rust crates.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p kron-nano

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root service user.
RUN useradd --system --uid 1001 --no-create-home --shell /usr/sbin/nologin kron

# Runtime directories.
RUN mkdir -p /var/lib/kron/data /var/lib/kron/bus /var/lib/kron/rules \
             /var/lib/kron/models /var/lib/kron/archive /etc/kron \
    && chown -R kron:kron /var/lib/kron

WORKDIR /opt/kron

COPY --from=builder /build/target/release/kron-nano /opt/kron/kron-nano

USER kron

# kron-query-api REST / WebSocket
EXPOSE 8080
# kron-collector gRPC (agent intake)
EXPOSE 50051
# kron-collector HTTP intake
EXPOSE 8081
# kron-collector Syslog UDP
EXPOSE 514/udp
# kron-collector Syslog TCP
EXPOSE 6514
# Prometheus metrics
EXPOSE 9101

ENV KRON_CONFIG=/etc/kron/kron.toml
ENV KRON_LOG_LEVEL=info

ENTRYPOINT ["/opt/kron/kron-nano"]
