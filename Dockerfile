# syntax=docker/dockerfile:1
FROM rust:alpine AS builder

RUN apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static pkgconf perl make

WORKDIR /app
# Disable rust:alpine's broken +crt-static default when linking dynamic C libs (libcrypto3 / SQLCipher)
ENV RUSTFLAGS="-C target-feature=-crt-static"

# 1. Cache deterministic (--locked) dependency compilation separately from app source edits
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src tests && \
    echo "pub fn _cache_anchor() {}" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "#[test] fn _anchor() {}" > tests/security_suite.rs && \
    cargo build --locked --release && \
    cargo test --locked --release --no-run && \
    rm -rf src tests

# 2. Compile and run Sovereign Vault v0.2 unit + security integration tests
COPY src/ ./src/
COPY tests/ ./tests/
RUN touch src/lib.rs src/main.rs tests/security_suite.rs && \
    RUST_BACKTRACE=1 cargo test --locked --release && \
    cargo build --locked --release

# Minimal hardened non-root runtime
FROM alpine:3.24

RUN apk add --no-cache libcrypto3 libgcc ca-certificates && \
    addgroup -S vault && adduser -S vault -G vault -u 10001 && \
    mkdir -p /data && chown -R 10001:10001 /data && chmod 0700 /data

USER 10001:10001

WORKDIR /app
COPY --from=builder /app/target/release/sovereign-vault /usr/local/bin/sovereign-vault

VOLUME ["/data"]
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/sovereign-vault"]
CMD ["daemon", "--data-dir", "/data", "--bind", "0.0.0.0:8443"]
