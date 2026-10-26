# Contributing to Sovereign Vault

Thank you for your interest in contributing to Sovereign Vault! As an open-source zero-account Micro-KMS, we place the highest priority on cryptographic correctness, memory protection, operational security, and developer ergonomics.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Security Vulnerabilities

**Do not report security vulnerabilities via public GitHub issues.**  
Please review [SECURITY.md](SECURITY.md) and report security issues privately to `security@oakai-security.com`.

---

## Development Workflow

### 1. Prerequisites
- **Rust**: Latest stable Rust toolchain (`rustup update stable`).
- **Docker & Docker Compose**: Required for containerized daemon testing.
- **Git**: Configured with a verified author email.

### 2. Fork & Clone
1. Fork the repository on GitHub (`https://github.com/oakai-security/sovereign-vault/fork`).
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/sovereign-vault.git
   cd sovereign-vault
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feature/my-improvement
   ```

### 3. Local Verification Gates
Before submitting a pull request, ensure your code passes all local checks:

```bash
# 1. Format check
cargo fmt --check

# 2. Clippy lint (zero warnings allowed)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Test suite
cargo test --verbose
```

### 4. Git Commit Guidelines
We enforce [Conventional Commits](https://www.conventionalcommits.org):
- `feat:` A new feature or capability.
- `fix:` A bug fix.
- `docs:` Documentation-only changes.
- `refactor:` Code change that neither fixes a bug nor adds a feature.
- `test:` Adding missing tests or correcting existing tests.
- `chore:` Tooling, CI, dependencies, or metadata changes.

---

## Submitting a Pull Request (PR)

1. Push your feature branch to your personal fork.
2. Open a Pull Request against `oakai-security/sovereign-vault` (`main` branch).
3. Complete the pull request template checklist:
   - Describe the purpose and motivation of the change.
   - Confirm all tests and linter checks pass.
   - Verify no secrets, credentials, or personal identifiers are committed.
4. Maintainers will review your PR. All PRs require review approval and green CI status checks before merging.
