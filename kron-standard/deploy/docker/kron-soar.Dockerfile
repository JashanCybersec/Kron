# kron-soar — SOAR playbook engine

FROM rust:1.75-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p kron-soar

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin kron

WORKDIR /opt/kron

COPY --from=builder /build/target/release/kron-soar /opt/kron/kron-soar

# Playbook definitions mounted at runtime
VOLUME ["/var/lib/kron/playbooks"]

USER kron

# Prometheus metrics port
EXPOSE 9106

ENTRYPOINT ["/opt/kron/kron-soar"]
