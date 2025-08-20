# Contributors Guide

Thank you for contributing to *p2p_password_manager*.
This document formalizes the standards adn expectations for all contributions.

## Workflow

1. Branching

- Create feature branches off of *dev*
- Use descriptive branch names in form: type/short-title (with dashes - as separators)

  **Examples**:
  - feat/quic-handshake
  - fix/crypto-rotate-keys
  - chore/contributors-md

2. Pull Requests

- Every change must be submitted via a PR.
- Each PR **requires at least one code review** before merging.
- Follow the [PR template](.github/PULL_REQUEST_TEMPLATE.md)

## Commit Conventions

We enforce [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification) via CI.

Conventional Commits are in format:

  ```bash
  <type>[optional scope]: <description>
  ```

  **Examples**:

- feat(quic): add handshake retry
- fix(crypto): correct key rotation
- docs: add contributors guide

  Types include:
  feat, fix, docs, style, refactor, perf, test, chore

### Mandatory Commit Signing

All commits pushed to protected branches **must be signed**.

We support both **GPG** and **SSH key signing**. If you have not enabled signing yet, please configure one of these methods and ensure GitHub recognizes your key. Unsigned commit shall be rejected by branch protection rules.

## CI and Quality Gates

Our CI pipeline (.github/workflow/ci.yml) enforces the following:

- Linting -> ```cargo clippy -- -D warnings```
- Formatting -> ```cargo fmt --check```
- Testing -> ```cargo test --all```
- Security audit -> ```cargo audit```
- Conventional commit validation (via [cocogitto](https://github.com/cocogitto/cocogitto))
- Automated version bump and tagging on main merges

PRs will not merge unless all checks pass.

## Documentation

- All public functions, structs, enums, and modules must include **Rustdoc comments**.
- When adding features:
  - Updated relevant **README**, **ADRs**, and other docs.
  - Provide **examples** in Rustdoc where useful.

### ADRs (Architectural Decision Reports)

All ADRs are tracked under docs/architecture/decisions/.

- Review relevant ADRs before making architectural changes.
- New architectural changes must be proposed as ADRs in a PR.

## Security

- Dependencies are regularly checked with **Dependabot** and cargo audit.
- Never commit secrets or credentials.
- Please report security issues privately.

## Best Practices

Follow Rust best practices to keetp the codebase clean and idiomatic:

- Prefer **explicit types** over ```impl Trait``` in public APIs.
- Write **unit tests** for new features.
- Keep functions **small and modular**.
- Follow idiomatic **Rust style guidelines**.
- Use ```?``` for error propagation where possible.
- Document all **unsafe** blocks with justification.

---

By contributing, you agree to follow this guide to maintain a clean, secure, and high-quality codebase.
