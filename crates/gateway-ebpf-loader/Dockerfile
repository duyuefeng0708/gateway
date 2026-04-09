# --- Build stage ---
FROM rust:1.83-bookworm AS builder

WORKDIR /usr/src/gateway

# Copy manifests first (layer cache for dependencies)
COPY Cargo.toml Cargo.lock ./
COPY crates/gateway-common/Cargo.toml crates/gateway-common/Cargo.toml
COPY crates/gateway-anonymizer/Cargo.toml crates/gateway-anonymizer/Cargo.toml
COPY crates/gateway-proxy/Cargo.toml crates/gateway-proxy/Cargo.toml
COPY crates/gateway-cli/Cargo.toml crates/gateway-cli/Cargo.toml
COPY crates/gateway-ebpf-loader/Cargo.toml crates/gateway-ebpf-loader/Cargo.toml

# Create stub lib/main files so cargo can resolve the workspace
RUN mkdir -p crates/gateway-common/src && echo "// stub" > crates/gateway-common/src/lib.rs && \
    mkdir -p crates/gateway-anonymizer/src && echo "// stub" > crates/gateway-anonymizer/src/lib.rs && \
    mkdir -p crates/gateway-proxy/src && echo "fn main() {}" > crates/gateway-proxy/src/main.rs && \
    echo "// stub" > crates/gateway-proxy/src/lib.rs && \
    mkdir -p crates/gateway-cli/src && echo "fn main() {}" > crates/gateway-cli/src/main.rs && \
    mkdir -p crates/gateway-ebpf-loader/src && echo "fn main() {}" > crates/gateway-ebpf-loader/src/main.rs && \
    echo "// stub" > crates/gateway-ebpf-loader/src/lib.rs

# Build dependencies only (cached unless Cargo.toml/lock change)
RUN cargo build --release -p gateway-ebpf-loader 2>/dev/null || true

# Copy real source
COPY crates crates

# Touch source files so cargo knows they changed
RUN find crates -name "*.rs" -exec touch {} +

# Build the release binary
RUN cargo build --release -p gateway-ebpf-loader

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libelf1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/gateway/target/release/gateway-ebpf-loader /usr/local/bin/gateway-ebpf-loader

# The loader needs to run as root to load eBPF programs.
# Capabilities (CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN) are granted via
# docker-compose.yml or the container runtime.

CMD ["gateway-ebpf-loader"]
