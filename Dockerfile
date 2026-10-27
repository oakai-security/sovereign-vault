# syntax=docker/dockerfile:1
FROM rust:alpine AS builder

RUN apk add --no-cache build-base musl-dev openssl-dev pkgconf perl make ca-certificates

WORKDIR /app

# 1. Cache deterministic (--locked) dependency compilation separately from app source edits
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src tests && \
    echo "pub fn _cache_anchor() {}" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "#[test] fn _anchor() {}" > tests/security_suite.rs && \
    RUSTFLAGS="-C target-feature=-crt-static" cargo test --locked --release --no-run && \
    RUSTFLAGS="-C target-feature=-crt-static" cargo build --locked --release && \
    rm -rf src tests

# 2. Compile, run unit + security integration tests, and produce stripped binary
COPY src/ ./src/
COPY tests/ ./tests/
RUN touch src/lib.rs src/main.rs tests/security_suite.rs && \
    RUST_BACKTRACE=1 RUSTFLAGS="-C target-feature=-crt-static" cargo test --locked --release && \
    RUSTFLAGS="-C target-feature=-crt-static" cargo build --locked --release && \
    cp target/release/sovereign-vault /app/sovereign-vault && \
    strip --strip-all /app/sovereign-vault

# Hardened minimal Alpine runtime with libcrypto3 for SQLCipher
FROM alpine:3.20

RUN apk add --no-cache ca-certificates libcrypto3 tzdata libgcc && \
    mkdir -p /data /tmp /etc/ssl/certs /usr/local/bin && \
    chmod 0700 /data && \
    chmod 1777 /tmp && \
    addgroup -g 10001 vault && \
    adduser -u 10001 -G vault -h /data -s /sbin/nologin -D vault && \
    chown -R 10001:10001 /data /tmp

COPY --from=builder /app/sovereign-vault /usr/local/bin/sovereign-vault

LABEL org.opencontainers.image.title="Sovereign Vault" \
      org.opencontainers.image.description="Single-binary, zero-account Micro-KMS with memory protection, SQLCipher encryption, and Universal OIDC federation" \
      org.opencontainers.image.url="https://oakai-security.com" \
      org.opencontainers.image.documentation="https://oakai-security.com/docs/quickstart" \
      org.opencontainers.image.source="https://github.com/oakai-security/sovereign-vault" \
      org.opencontainers.image.vendor="Oakai Security" \
      org.opencontainers.image.licenses="Apache-2.0"

USER 10001:10001
WORKDIR /data
ENV PATH="/usr/local/bin" \
    SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"

VOLUME ["/data"]
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/sovereign-vault"]
CMD ["daemon", "--data-dir", "/data", "--bind", "0.0.0.0:8443"]
