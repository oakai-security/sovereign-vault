# Security Policy & Development Posture

> **⚠️ Pre-Release Prototype Notice (`v0.1.x`)**: Current `0.1.x` commits represent an early architectural scaffold undergoing active `v0.2.0` cryptographic and authentication hardening (tracked in [`ARCHITECTURE_AND_HARDENING_PLAN.md`](ARCHITECTURE_AND_HARDENING_PLAN.md)). **Do not expose `v0.1.x` builds to untrusted networks or store production credentials until `v0.2.0` (`TICKET-016`) is merged.**

---

## Target Security Guarantees (`v0.2.0+`)

Sovereign Vault is engineered to enforce the following cryptographic and runtime invariants once `v0.2.0` hardening completes:

1. **Storage Compromise Resistance (Envelope AEAD)**:
   - Master unseal keys are never persisted to disk. Volume dataEncryption keys (DEKs) are wrapped via `HKDF-SHA256` / `Argon2id` + `AES-256-GCM`, secret payloads bind `(project, path, version)` into AEAD Associated Data (AAD), and database metadata is blinded/encrypted on `0600` volume files.
2. **Default-Deny Container & Workload Isolation**:
   - Every secret and administrative route requires authenticated, `BLAKE3`-hashed, TTL-bounded machine tokens (`sv_live_*`) or `Ed25519`-signed admin requests, enforcing strict canonical directory-boundary ACLs (`apps/subsystem/*`).
3. **Pinned RAM Enclave**:
   - Heap/anonymous `mmap` key buffers are pinned via verified `mlock()` + `MADV_DONTDUMP`, scrubbed via `zeroize` prior to `munlock()` on drop, and guarded against non-root debugger attachment via `PR_SET_DUMPABLE = 0`.

## Reporting Vulnerabilities

During local pre-release development, track security findings directly in workspace security audits and `TICKET-016` / `TICKET-017`. Prior to public launch, a PGP key fingerprint and `/.well-known/security.txt` will be published for `security@oakai-security.com`.
