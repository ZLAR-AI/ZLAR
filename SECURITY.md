# Security Policy

## Reporting a Vulnerability

**Email:** security@zlar.ai
**GitHub:** [Private vulnerability reporting](https://github.com/ZLAR-AI/ZLAR/security/advisories/new)

Do not open a public issue for security vulnerabilities.

**Response timeline:**
- Acknowledgment: within 48 hours
- Initial assessment: within 5 business days
- Fix or mitigation: depends on severity, communicated in assessment

We credit reporters in the advisory unless they prefer anonymity.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |
| < 1.0   | No        |

## Security Design Principles

1. **Fail closed.** If the gate is down, all actions are denied. There is no `--permissive` flag. ([ADR-003](docs/adr/ADR-003-fail-closed.md))
2. **No intelligence in the enforcement path.** The gate pattern-matches against signed rules. It does not reason, interpret, or form opinions. ([ADR-001](docs/adr/ADR-001-deterministic-enforcement.md))
3. **Policy is a human artifact.** Ed25519-signed. Agents cannot modify the rules that govern them. ([ADR-004](docs/adr/ADR-004-ed25519-signing.md))
4. **Structural independence.** ZLAR does not depend on any agent platform for enforcement. ([ADR-006](docs/adr/ADR-006-structural-independence.md))
5. **Patience over speed.** When in doubt, deny. Silence is not consent.

## Threat Model

ZLAR protects against:

- **Unauthorized agent actions** — tool calls that violate policy are blocked before execution.
- **Policy tampering** — Ed25519 signature verification. Invalid signature = deny all.
- **Audit trail tampering** — hash-chained entries. Modify one and every subsequent hash breaks. Per-entry Ed25519 signing provides non-repudiation.
- **Prompt injection against enforcement** — the gate has no language model. There is no reasoning to attack.
- **Agent self-governance** — R012 blocks agents from modifying gate infrastructure, policy, or signing keys.

ZLAR does not protect against:

- **Compromised signing key** — whoever holds the key can sign permissive policy. Key management is the operator's responsibility. See [token rotation](docs/token-rotation.md).
- **Compromised gate binary** — if the gate itself is replaced, enforcement is lost. Host-level integrity monitoring is the defense layer below the gate.
- **Actions outside tool calls** — direct filesystem access, out-of-band network, side channels that bypass the hook. The gate governs tool calls. OS-level containment governs everything else.
- **Malicious policy author** — if the human who signs the policy is compromised, the policy is compromised. ZLAR enforces policy faithfully; it does not evaluate whether the policy is wise.

## Supply Chain

- Core gate: zero external dependencies (bash, jq, openssl — all system packages).
- MCP gate: zero npm dependencies (Node.js built-ins only).
- CI: ShellCheck, JSON validation, CodeQL scanning.
- Dependabot enabled for GitHub Actions.

## Cryptographic Choices

- **Signing:** Ed25519 (default). ML-DSA-44 and hybrid mode available via crypto abstraction layer.
- **Hashing:** SHA-256.
- **Canonicalization:** `jq -S -c` (sorted keys, compact). Documented limitation: not RFC 8785 (JCS). Cross-gate verifiers must use the same canonical form.
- **Key format:** Standard OpenSSL PEM.
- **Migration path:** Every audit entry records `signature_algorithm` and `hash_algorithm`. When post-quantum migration is required, tooling reads these fields to identify entries needing re-signing.
