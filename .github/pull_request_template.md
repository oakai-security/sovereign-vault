## Description
<!-- Provide a brief summary of the changes and the problem solved. -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update
- [ ] Performance or security enhancement

## Verification & Testing
- [ ] `cargo test` passes locally with zero failures.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes with zero warnings.
- [ ] `cargo fmt --check` passes cleanly.
- [ ] Added unit or integration tests covering new functionality.

## Security Checklist
- [ ] No secrets, keys, passwords, or personal tokens are committed.
- [ ] No private IP addresses or internal hostnames are introduced.
- [ ] Memory-zeroing (`zeroize`) and RAM-locking (`mlock`) invariants preserved for sensitive key material.
