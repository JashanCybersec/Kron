# kron-collector — Event intake service
#
# Multi-stage build:
#   Stage 1 (builder): Compiles the Rust binary
#   Stage 2 (runtime): Minimal Debian image with only the binary

# Stage 1: Build
FROM rust:1.75-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace manifests — cached until dependencies change
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p kron-collector

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root service user
RUN useradd --system --no-create-home --shell /usr/sbin/nologin kron

WORKDIR /opt/kron

COPY --from=builder /build/target/release/kron-collector /opt/kron/kron-collector

USER kron

# gRPC intake port
EXPOSE 50051
# HTTP intake port
EXPOSE 8080
# Prometheus metrics port
EXPOSE 9101

ENTRYPOINT ["/opt/kron/kron-collector"]
