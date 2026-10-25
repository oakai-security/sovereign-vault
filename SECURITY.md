# Security Policy

## Threat Model & Security Guarantees

Sovereign Vault is designed to provide cryptographic confidentiality and integrity under the following assumptions:

1. **Storage Compromise**: If the physical drive or backing storage volume is stolen or cloned, an attacker cannot read the secrets without the 256-bit unseal key.
2. **Container Breach**: If an adjacent microservice container is compromised via RCE, it is barred from accessing secrets unless issued a scoped token. Scoped tokens enforce strict path-prefix boundaries (`apps/subsystem/*`).
3. **RAM Protection**: Memory buffers containing master unseal keys or decrypted secrets are locked in RAM via `mlock()` to prevent kernel swap leakage and zeroed on drop via `zeroize`. Debugger attachment via `ptrace` is rejected (`PR_SET_DUMPABLE = 0`).

## Reporting Vulnerabilities

If you identify a security vulnerability in Sovereign Vault, please send an encrypted report to `security@oakai-security.com`.
