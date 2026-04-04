# kron-auth — Authentication service (JWT RS256, Argon2id, TOTP, RBAC)
# NOTE: kron-auth is a library crate, not a binary.
# Auth logic is embedded in kron-query-api. This Dockerfile is reserved
# for a future standalone auth service if needed (e.g., Enterprise SSO).
#
# For now, this builds a minimal health-check binary as a placeholder
# so the CI matrix does not fail on a missing Dockerfile.

FROM rust:1.75-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build query-api which includes auth logic
RUN cargo build --release -p kron-query-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin kron
WORKDIR /opt/kron

COPY --from=builder /build/target/release/kron-query-api /opt/kron/kron-query-api

USER kron
EXPOSE 8080 9105

ENTRYPOINT ["/opt/kron/kron-query-api"]
