# Security Policy & Cryptographic Architecture (`v1.0.0+`)

**Sovereign Vault (`v1.0.0+`)** enforces defense-in-depth across storage, memory, network transport, access control, and auditability.

---

## Enforced Security Invariants

1. **Zero Plaintext Keys at Rest (`HKDF-SHA512` Envelope + `AES-256-GCM`)**:
   - The 256-bit external unseal key is never written to disk. Initialization derives a Key-Encryption Key (KEK) via `HKDF-SHA512` over a 256-bit random salt and wraps a random 256-bit Master DEK under `AES-256-GCM` (`AAD = "sovereign-vault:v2:envelope"`).
   - `/data/vault.envelope` (`0600`) stores only salt, nonce, and wrapped DEK ciphertext. Unseal verifies the AEAD authentication tag *before* opening storage (`401` on invalid key, `409` if already active).
2. **Full-Page Database Encryption (`SQLCipher` + Inner `AAD`)**:
   - All 4 KB SQLite pages, table schemas, secret path indices, token tables, and WAL frames in `/data/vault.db` are encrypted via 256-bit SQLCipher (`PBKDF2_HMAC_SHA512` / `HMAC_SHA512`, `PRAGMA synchronous = FULL`, `0600` permissions).
   - Secret values receive an additional inner `AES-256-GCM` layer bound to canonical Associated Data (`sv:v2:{project}:{path}:{version}`), preventing cross-row ciphertext swapping.
3. **Default-Deny `SHA-512` Machine Authentication & Rate Limiting**:
   - Every secret and administrative route requires a valid `sv_live_<32hex_id>_<64hex_secret>` bearer token hashed at rest with `SHA-512` and verified in constant time (`subtle::ConstantTimeEq`).
   - Sliding-window brute-force rate limiting throttles repeated failed init, unseal, or token guesses (`429 Too Many Requests`).
4. **Canonical Path & Directory-Boundary ACLs**:
   - Rejects `.`, `..`, `//`, and non-canonical characters (`400 Bad Request`) and enforces strict trailing-slash boundaries (`apps/jellyfin/*` never matches sibling `apps/jellyfin-prod/*`).
5. **RAM-Pinned Key Enclave & Core-Dump Suppression**:
   - Active subkeys (`db_key`, `value_aead_key`, `audit_chain_key`) reside in dedicated page-aligned anonymous `mmap` allocations pinned with `mlock()`, marked `MADV_DONTDUMP`, scrubbed with volatile `zeroize` prior to `munlock`/`munmap` on seal/drop, and guarded globally via `PR_SET_DUMPABLE = 0`.
6. **Tamper-Evident `HMAC-SHA512` Audit Chain**:
   - Every administrative and secret event is recorded in an encrypted SQLCipher `audit_log` chained via RFC 2104 `HMAC-SHA512` (`GET /v1/sys/audit` verifies full chain integrity from genesis).
7. **Zero-History CLI & Air-Gapped Default**:
   - Sensitive inputs use hidden `/dev/tty` prompts (`rpassword`) or `--stdin` pipes paired with OS Secret Service (`gnome-keyring`), and `sovereign-vault run` injects secrets directly into child process memory without `.env` files. Standalone containers initiate zero outbound connections.

---

## Reporting Vulnerabilities

Report suspected vulnerabilities privately to `security@oakai-security.com` (PGP fingerprint and `/.well-known/security.txt` published prior to public registry release). Do not open public GitHub issues for undisclosed vulnerabilities.
