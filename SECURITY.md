# Security Policy and Cryptographic Architecture (`v1.0.0+`)

**Sovereign Vault (`v1.0.0+`)** enforces defense-in-depth across storage, memory, network transport, access control, and auditability.

---

## Enforced Security Invariants

1. **Zero Plaintext Keys at Rest (`HKDF-SHA512` Envelope + `AES-256-GCM` + Online KEK Rotation)**:
   - The 256-bit external unseal key is never written to disk. Initialization derives a Key-Encryption Key (KEK) via `HKDF-SHA512` over a 256-bit random salt and wraps a random 256-bit Master DEK under `AES-256-GCM` (`AAD = "sovereign-vault:v2:envelope"`).
   - `/data/vault.envelope` (`0600`) stores only salt, nonce, and wrapped DEK ciphertext. Unseal verifies the AEAD authentication tag *before* opening storage (`401` on invalid key, `409` if already active), and `POST /v1/sys/rotate-unseal-key` rotates the KEK online without downtime.
   - First-boot bootstrap nonces are written exclusively to `/data/.bootstrap_nonce` (`0600`) and deleted upon initialization rather than emitted to container stdout logs.
2. **Full-Page Database Encryption (`SQLCipher` Raw-Key Mode + Inner `AAD`)**:
   - `PRAGMA cipher_memory_security = ON;` is applied prior to `PRAGMA key`. All 4 KB SQLite pages, table schemas, secret path indices, token tables, and WAL frames in `/data/vault.db` are encrypted via 256-bit SQLCipher raw-key mode (`HKDF-SHA512` subkey, `HMAC_SHA512` page authentication, `PRAGMA synchronous = FULL`, `0600` permissions).
   - Secret values receive an additional inner `AES-256-GCM` layer bound to canonical Associated Data (`sv:v2:{project}:{path}:{version}`), preventing cross-row or cross-version ciphertext swapping.
3. **Dual-Mode Authentication, SSRF-Hardened OIDC, and Per-IP Rate Limiting**:
   - Every secret and administrative route requires either a valid `sv_live_<32hex_id>_<64hex_secret>` machine token (hashed at rest with `SHA-512` and verified in constant time with dummy-hash equalization on unknown IDs) or a cryptographically verified OIDC JWT (`RS256`, `ES256`, `EdDSA`) isolated per `binding_id`.
   - OIDC discovery and JWKS fetches enforce `https://`, block cloud metadata (`169.254.169.254`), loopback, and private RFC1918 IPs by default with DNS IP pinning, and disable HTTP redirects.
   - Per-IP sliding-window brute-force rate limiting (`PeerIp` via `ConnectInfo<SocketAddr>`) throttles repeated failed init, unseal, or token guesses (`429 Too Many Requests`) without allowing external IPs to lock out localhost operators.
4. **Canonical Path and Directory-Boundary ACLs**:
   - Rejects `.`, `..`, `//`, and non-canonical characters (`400 Bad Request`) and enforces strict trailing-slash boundaries (`apps/jellyfin/*` never matches sibling `apps/jellyfin-prod/*`).
5. **Targeted RAM-Pinned Key Enclave and Core-Dump Suppression**:
   - Process core dumps and ptrace attachment are disabled via `PR_SET_DUMPABLE = 0`. Active subkeys (`db_key`, `value_aead_key`, `audit_chain_key`) reside in dedicated page-aligned anonymous `mmap` allocations pinned with `mlock()`, marked `MADV_DONTDUMP`, and scrubbed with volatile `zeroize` prior to `munlock`/`munmap` on seal/drop (avoiding `mlockall(MCL_FUTURE)` allocator panics under load).
6. **Tamper-Evident `HMAC-SHA512` Audit Chain with External Rollback Anchor**:
   - Every administrative and secret mutation is committed atomically in the same SQLCipher transaction as its RFC 2104 `HMAC-SHA512` `audit_log` entry, and `secret.get` records audit events fail-closed before returning plaintext.
   - An external HMAC-authenticated `/data/vault.audit_anchor` (`0600`) commits `(latest_seq, latest_entry_mac)` so `GET /v1/sys/audit` detects both internal row tampering and tail-truncation or full table deletion.
7. **Strict TLS 1.3 and Zero-History CLI**:
   - Native Rustls transport negotiates **TLS 1.3 only** (`rustls::version::TLS13`) with CA/B-Forum-compliant (`< 398` days) self-signed or custom certificates.
   - Sensitive CLI inputs use hidden `/dev/tty` prompts (`rpassword`), `--stdin` pipes, or `0600` token files paired with OS Secret Service (`gnome-keyring`). Standalone containers initiate zero outbound connections by default.

---

## Reporting Vulnerabilities

Report suspected vulnerabilities privately to `security@oakai-security.com` (PGP fingerprint and `/.well-known/security.txt` published prior to public registry release). Do not open public GitHub issues for undisclosed vulnerabilities.
