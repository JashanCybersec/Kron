# kron-stream — Detection engine (SIGMA + IOC + ONNX)

FROM rust:1.75-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p kron-stream

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin kron

WORKDIR /opt/kron

COPY --from=builder /build/target/release/kron-stream /opt/kron/kron-stream

# SIGMA rules and ONNX models mounted at runtime
VOLUME ["/var/lib/kron/rules", "/var/lib/kron/models"]

USER kron

# Prometheus metrics port
EXPOSE 9103

ENTRYPOINT ["/opt/kron/kron-stream"]
