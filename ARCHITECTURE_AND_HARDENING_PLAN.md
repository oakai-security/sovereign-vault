# Sovereign Vault v0.2 / v0.3 — Cryptographic & Production Hardening Blueprint

**Status**: Approved Implementation Plan (`TICKET-016` / `TICKET-017` / `ADR-0008`)  
**Branch**: `feature/ticket-016-v02-hardening-plan` (Isolated Git Worktree)  

---

## 1. Purpose

This document translates the findings from the Sovereign Vault Red-Team Audit (`SV-01` through `SV-14`) into a concrete, file-by-file engineering specification for `v0.2.0` (Core Security & Cryptography) and `v0.3.0` (Transport, CLI, Secret-Zero Attestation & Distroless Hardening).

---

## 2. Phase 1 (`v0.2.0` — `TICKET-016`): Core Cryptographic, Auth & Memory Enclave Rewrite

### 2.1 Envelope Encryption & Key Verification (`src/crypto.rs`, `src/storage.rs`, `src/server.rs`)
- **Fixes**: `SV-01` (plaintext master key stored in `meta.salt`) and `SV-03` (unverified `/v1/sys/unseal` clobbering live RAM key).
- **Design**:
  1. `POST /v1/sys/init` generates:
     - `unseal_key` ($32\text{ B}$ CSPRNG) -> hex-encoded into `Zeroizing<String>`, returned once to the caller, **never persisted**.
     - `kdf_salt` ($16\text{ B}$ CSPRNG) -> stored in `meta` (`key = 'kdf_salt'`).
     - `dek` ($32\text{ B}$ CSPRNG) -> held inside `Pin<Box<LockedKey>>` in RAM.
     - Derive `kek = HKDF-SHA256(ikm = unseal_key, salt = kdf_salt, info = b"sovereign-vault:v2:kek")`.
     - Wrap `dek` using `AES-256-GCM(key = kek, nonce = dek_nonce, msg = dek, aad = b"sovereign-vault:v2:dek")`.
     - Persist `(kdf_salt, wrapped_dek, dek_nonce, schema_version = '2', admin_ed25519_pubkey)` atomically in a single SQLite `IMMEDIATE` transaction.
  2. `POST /v1/sys/unseal`:
     - Return `400 Bad Request` if `!is_initialized()`.
     - Return `409 Conflict` if `master_dek` is already `Some(...)` (prevents live DoS / split-brain key overwrite).
     - Re-derive `kek` from supplied `unseal_key` + `meta.kdf_salt` and verify AEAD decryption of `wrapped_dek` (`AAD = b"sovereign-vault:v2:dek"`).
     - Only on AEAD tag success, store `Pin<Box<LockedKey>>` in `AppState`; otherwise return `401 Unauthorized` after rate-limiter accounting.

### 2.2 Pinned Heap Memory (`LockedKey`) & Zeroization (`src/crypto.rs`)
- **Fixes**: `SV-08` (stack-parameter `mlock` bug, unchecked syscall return code, missing `munlock`, unzeroized HTTP strings).
- **Design**:
  - Allocate `LockedKey` directly on the heap via `Box::new([0u8; 32])` wrapped in `Pin<Box<LockedBuffer>>` (or page-aligned `libc::mmap(MAP_PRIVATE | MAP_ANONYMOUS)`), **then** invoke `libc::mlock(ptr, len)` and `libc::madvise(ptr, len, libc::MADV_DONTDUMP)` on the final heap address.
  - Check `mlock() == 0`; log a prominent `ERROR` (or fail startup unless `--allow-unlocked-memory` is explicitly passed for constrained CI containers) if `RLIMIT_MEMLOCK` rejects pinning.
  - Implement `Drop`: run `zeroize::Zeroize::zeroize` via volatile writes **before** calling `libc::munlock(ptr, len)`.
  - Wrap `UnsealRequest.unseal_key`, `PutSecretRequest.value`, `SecretResponse.value`, and `EnrollTokenResponse.token` in `zeroize::Zeroizing<String>`, and enable `features = ["zeroize"]` on `aes-gcm`.

### 2.3 Mandatory Default-Deny Authentication & Hashed Tokens (`src/server.rs`, `src/storage.rs`)
- **Fixes**: `SV-02` (optional `X-Vault-Token` header & unauthenticated `/v1/sys/enroll`) and `SV-04` (unhashed `token_hash` & `trim_start_matches` bug).
- **Design**:
  - Split Axum router into:
    - **Public/Bootstrap routes**: `GET /v1/sys/health`, `POST /v1/sys/init` (constant-time `X-Vault-Bootstrap-Nonce` check; nonce wiped immediately after `init`), `POST /v1/sys/unseal`.
    - **Authenticated routes** (wrapped in mandatory `require_token_auth` middleware):
      - `GET|PUT|DELETE /v1/secret/*path` -> requires valid non-expired token + matching capability (`read` / `write` / `delete`).
      - `POST /v1/sys/enroll`, `DELETE /v1/sys/tokens/:id`, `POST /v1/sys/seal`, `POST /v1/sys/backup` -> requires `admin` capability OR valid `Ed25519` signature from `meta.admin_ed25519_pubkey`.
  - Token format: `sv_live_<token_id_16hex>_<secret_64hex>`.
    - Parse strictly via `strip_prefix("sv_live_")`.
    - Look up row by indexed `token_id`, check `expires_at > now()`, compute `BLAKE3(secret_bytes)`, and compare against stored `token_hash` using `subtle::ConstantTimeEq`.

### 2.4 AEAD Associated Data (AAD), Metadata Protection & Canonical ACLs (`src/acl.rs`, `src/storage.rs`)
- **Fixes**: `SV-05` (ciphertext swap + plaintext SQLite metadata), `SV-06` (`apps/jellyfin/*` matching `apps/jellyfin-prod/*`), `SV-12` (`PRAGMA synchronous = NORMAL` & `0644` permissions).
- **Design**:
  - **Canonical Path Validator**: Normalize and validate paths against `^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$` (max 256 chars; reject leading/trailing `/`, `//`, `.`, `..`, NUL, percent-encoded traversal).
  - **Wildcard Boundary Fix (`src/acl.rs`)**:
    ```rust
    if let Some(dir_prefix) = pattern.strip_suffix("/*") {
        // Require exact directory boundary '/' so "apps/jellyfin/*" never matches "apps/jellyfin-prod/x"
        if requested_path.starts_with(dir_prefix)
            && requested_path.as_bytes().get(dir_prefix.len()) == Some(&b'/')
        {
            return true;
        }
    }
    ```
  - **AEAD AAD Binding**: Pass `format!("sv:v2:{project}:{path}:{version}")` as AES-256-GCM `Payload.aad` on every encrypt and decrypt operation.
  - **Metadata Blinding & Durability**:
    - Key secret rows by `path_hmac = BLAKE3_keyed(dek_index_subkey, canonical_path)` and encrypt `(path, project, metadata_json)` inside an AEAD metadata blob (or enable `rusqlite` `bundled-sqlcipher`).
    - Enforce `umask(0o077)` (`0600` file mode on `vault.db`, `-wal`, `-shm`) and `PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;`.
    - Store immutable versions in `secret_versions (path_hmac, version, ciphertext, nonce, created_at)` so accidental overwrites are recoverable.

### 2.5 Deadlock-Free Concurrency (`src/server.rs`)
- **Fixes**: `SV-07` (AB-BA mutex deadlock between `health_handler` and `secret` handlers) and `SV-11` (slice/mutex `.unwrap()` panics).
- **Design**:
  - Replace `Mutex<Option<LockedKey>>` with `tokio::sync::RwLock<VaultRuntimeState>` and run synchronous SQLite operations via a single-order helper or `tokio::task::spawn_blocking` channel—**never holding two locks simultaneously**.
  - Replace all `copy_from_slice` and `.unwrap()` calls in request paths with ` <[u8; 12]>::try_from(nonce_bytes.as_slice())` returning typed `VaultError` HTTP responses.

---

## 3. Phase 2 (`v0.3.0` — `TICKET-017`): TLS 1.3, Full CLI, Secret-Zero Peer Auth & Distroless Build

1. **Transport Security (`SV-09`)**:
   - Integrate `axum-server` + `rustls` (TLS 1.3 only) with automatic self-signed/internal CA bootstrap or mounted certs, bind `127.0.0.1:8443` by default in `docker-compose.yml` (removing `network_mode: host`), and add optional Unix Domain Socket listener (`/run/sovereign-vault/vault.sock`) using Linux `SO_PEERCRED` for local Secret-Zero container attestation.
2. **CLI & Watcher Completion (`SV-10`, `SV-14`)**:
   - Implement subcommands: `init`, `unseal`, `seal`, `status`, `token enroll|revoke|list`, `secret put|get|delete|versions`, `backup` (`VACUUM INTO`), `run -- <cmd>` (spawns child process with secrets injected into memory environment), and a real `watcher` loop polling `/v1/sys/health` with OS `keyring` integration.
3. **Supply Chain & CI (`SV-13`)**:
   - Remove `Cargo.lock` from `.gitignore`, build static `x86_64-unknown-linux-musl` binary with `cargo build --release --locked`, package into `gcr.io/distroless/static-debian12:nonroot` with `read_only: true` rootfs and `ulimits.memlock`, and add unit + adversarial integration tests (`tests/security_regressions.rs`).
