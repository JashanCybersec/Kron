# kron-query-api — REST + WebSocket API server (Axum)

FROM rust:1.75-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Also copy web frontend assets if they exist (Phase 3+)
COPY web/ web/ 2>/dev/null || true

RUN cargo build --release -p kron-query-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin kron

WORKDIR /opt/kron

COPY --from=builder /build/target/release/kron-query-api /opt/kron/kron-query-api

USER kron

# HTTPS API port
EXPOSE 8443
# HTTP redirect port
EXPOSE 8080
# Prometheus metrics port
EXPOSE 9105

ENTRYPOINT ["/opt/kron/kron-query-api"]
