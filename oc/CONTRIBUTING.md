# Contributing to ZLAR-OC

Thank you for your interest in contributing to ZLAR-OC.

---

## How to Contribute

### Reporting Issues

If you find a bug, a gap in documentation, or have a suggestion, open an issue. Be specific — include what you expected, what happened, and steps to reproduce if applicable.

### Security Disclosures

If you discover a security vulnerability in ZLAR-OC, **do not open a public issue.** Use [GitHub's private vulnerability reporting](https://github.com/ZLAR-AI/ZLAR-OC/security/advisories) instead. See [SECURITY.md](SECURITY.md) for our full disclosure policy.

### Pull Requests

1. Fork the repository
2. Create a branch from `main` for your change
3. Make focused changes — one concern per PR
4. Run the test suite (`tests/`) and confirm all tests pass
5. Write a clear description of what the change does and why
6. Submit the PR

We review PRs for correctness, security implications, and alignment with the project's architecture. PRs that affect containment behavior (sandbox, firewall, gate, policy, audit trail) receive closer scrutiny — this is expected and intentional.

### Code Standards

ZLAR-OC's codebase is primarily shell scripts, JSON configuration, and macOS system profiles. Contributions should:

- Follow existing patterns and naming conventions
- Include comments explaining *why*, not *what*
- Add or update tests for any behavioral change
- Document containment implications in the commit message if the change touches enforcement layers

### Documentation

Documentation improvements are always welcome. If you found something confusing during installation or setup, a PR that clarifies it helps everyone who comes after you.

---

## What We're Looking For

Areas where contributions are particularly valuable:

- **Test coverage** — more tests for edge cases, failure modes, and adversarial scenarios
- **Platform expansion** — ZLAR-OC currently targets macOS; Linux containment (seccomp, AppArmor, namespaces) is an open area
- **Audit trail tooling** — visualization, analysis, anomaly detection on the audit log
- **Documentation** — install guides for different environments, troubleshooting, architecture explanations

---

## Code of Conduct

Be respectful, be specific, be constructive. Engage with the substance of ideas, not the identity of contributors. If you disagree with an architectural decision, explain what you'd do differently and why — the design docs exist to make those conversations productive.

---

## License

By contributing to ZLAR-OC, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
