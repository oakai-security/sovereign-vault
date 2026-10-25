# syntax=docker/dockerfile:1
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev libc-dev

WORKDIR /app
COPY Cargo.toml ./
COPY src/ ./src/

RUN cargo build --release

# Distroless / minimal runtime
FROM alpine:3.20

# Run as unprivileged UID and pre-create data directory with correct ownership
RUN addgroup -S vault && adduser -S vault -G vault -u 10001 && \
    mkdir -p /data && chown -R 10001:10001 /data

USER 10001:10001

WORKDIR /app
COPY --from=builder /app/target/release/sovereign-vault /usr/local/bin/sovereign-vault

VOLUME ["/data"]
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/sovereign-vault"]
CMD ["daemon", "--db-path", "/data/vault.db", "--bind", "0.0.0.0:8443"]
