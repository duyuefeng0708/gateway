# --- Build stage ---
FROM rust:1.83-bookworm AS builder

WORKDIR /usr/src/gateway

# Copy manifests first (layer cache for dependencies)
COPY Cargo.toml Cargo.lock ./
COPY crates/gateway-common/Cargo.toml crates/gateway-common/Cargo.toml
COPY crates/gateway-anonymizer/Cargo.toml crates/gateway-anonymizer/Cargo.toml
COPY crates/gateway-proxy/Cargo.toml crates/gateway-proxy/Cargo.toml
COPY crates/gateway-cli/Cargo.toml crates/gateway-cli/Cargo.toml

# Create stub lib/main files so cargo can resolve the workspace
RUN mkdir -p crates/gateway-common/src && echo "// stub" > crates/gateway-common/src/lib.rs && \
    mkdir -p crates/gateway-anonymizer/src && echo "// stub" > crates/gateway-anonymizer/src/lib.rs && \
    mkdir -p crates/gateway-proxy/src && echo "fn main() {}" > crates/gateway-proxy/src/main.rs && \
    echo "// stub" > crates/gateway-proxy/src/lib.rs && \
    mkdir -p crates/gateway-cli/src && echo "fn main() {}" > crates/gateway-cli/src/main.rs

# Build dependencies only (cached unless Cargo.toml/lock change)
RUN cargo build --release -p gateway-proxy 2>/dev/null || true

# Copy real source
COPY crates crates
COPY eval eval

# Touch source files so cargo knows they changed
RUN find crates -name "*.rs" -exec touch {} +

# Build the release binary
RUN cargo build --release -p gateway-proxy

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/gateway/target/release/gateway-proxy /usr/local/bin/gateway-proxy

RUN useradd --system --no-create-home gateway
USER gateway

EXPOSE 8443

CMD ["/usr/local/bin/gateway-proxy"]
