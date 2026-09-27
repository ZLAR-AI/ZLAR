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

**Publishing your findings.** Breaking ZLAR is welcome, and so is publishing what
you found, once you've reported it to us privately and it's been fixed or 90 days
have passed, whichever comes first.

## Where ZLAR lives

The only official source is this repository, github.com/ZLAR-AI/ZLAR, with the
website at [zlar.ai](https://zlar.ai). ZLAR has never offered a Windows installer
or a `.exe` file. A repository elsewhere that uses the ZLAR name and asks you to
download and run something is an impersonation and may be malware. Please report
it to security@zlar.ai.

## Supported Versions

The latest version on the main line is supported. Please report against it.

## Security Design Principles

Most of what follows describes ZLAR's first design, the checkpoint that sits next
to the AI. The force field's own properties are in [cyan/README.md](cyan/README.md).

1. **Fail closed on protected paths.** If a routed/intercepted gate invocation cannot be evaluated safely, that invocation is denied. There is no `--permissive` flag. ([ADR-003](docs/adr/ADR-003-fail-closed.md))
2. **No intelligence in the enforcement path.** The gate pattern-matches against signed rules. It does not reason, interpret, or form opinions. ([ADR-001](docs/adr/ADR-001-deterministic-enforcement.md))
3. **Policy is a human artifact.** Ed25519-signed. Agents cannot modify the rules that apply to them. ([ADR-004](docs/adr/ADR-004-ed25519-signing.md))
4. **Structural independence.** ZLAR does not depend on any agent platform for enforcement. ([ADR-006](docs/adr/ADR-006-structural-independence.md))
5. **Patience over speed.** When in doubt, deny. Silence is not consent.

## Threat Model

ZLAR protects against:

- **Unauthorized agent actions on protected paths** — routed/intercepted tool calls that violate policy are blocked before execution.
- **Policy tampering** — Ed25519 signature verification. Invalid signature = deny routed gate invocations.
- **Audit trail tampering** — hash-chained entries. Modify one and every subsequent hash breaks. Per-entry Ed25519 signing provides non-repudiation.
- **Prompt injection against enforcement** — the gate has no language model. There is no reasoning to attack.
- **Agents tampering with ZLAR itself on protected paths** — rules R000A–R000C block routed attempts to reach the signing key, the gate-disabled flag, and sensitive credential paths.

ZLAR protects the human decision-maker:

- **Decision fatigue** — H6 enforces a daily decision cap (default: 80). When the cap is reached, the gate stops routing to the human. The system is under-resourced, not the human.
- **Rubber-stamping / response-pattern drift** — H14 monitors response-time variance in a rolling window and fires a health warning when the pattern suggests review may no longer be meaningful.
- **Rushed approval** — H15 sets a deliberation floor per risk class (critical: 30s, warn: 10s, info: 3s). A critical approval faster than the floor is rejected, and the human must review again. For warn and info, a faster approval goes through and is recorded as a signal for H14, because forced waiting on routine asks trains people to wait and then tap.
- **Automated impersonation** — H17 rejects sub-second responses as possible automation. A human cannot read, comprehend, and decide in under 2 seconds.
- **Queue overload** — H13 tracks pending decisions. When the queue exceeds capacity, the system is under-resourced and logs a warning.

ZLAR does not protect against:

- **Compromised signing key** — whoever holds the key can sign permissive policy. Key management is the operator's responsibility. See [token rotation](docs/token-rotation.md).
- **Compromised gate binary** — if the gate itself is replaced, enforcement is lost. Host-level integrity monitoring is the defense layer below the gate.
- **Actions outside tool calls** — direct filesystem access, out-of-band network, side channels that bypass the hook. The gate covers tool calls. OS-level containment covers everything else.
- **Malicious policy author** — if the human who signs the policy is compromised, the policy is compromised. ZLAR enforces policy faithfully; it does not evaluate whether the policy is wise.

## Supply Chain

- Core gate: zero external dependencies (bash, jq, openssl — all system packages).
- MCP gate: zero npm dependencies (Node.js built-ins only).
- CI: ShellCheck, JSON validation and CodeQL scanning are configured in `.github/workflows/`. Automatic runs are switched off for now.

## Cryptographic Choices

- **Signing:** Ed25519 (default). ML-DSA-44 and hybrid mode available via crypto abstraction layer.
- **Hashing:** SHA-256.
- **Canonicalization:** ZLAR Canonicalization Specification v1.0 — a strict subset of RFC 8785 (JCS) with constrained schema (no floats, ASCII-only property names). Implementation: `jq -S -c` in bash, `JSON.stringify(sortKeysRecursive(obj))` in Node.js. Cross-language verified with 28 test vectors. See `docs/canonicalization-spec.md`.
- **Key format:** Standard OpenSSL PEM.
- **Migration path:** Every audit entry records `signature_algorithm` and `hash_algorithm`. When post-quantum migration is required, tooling reads these fields to identify entries needing re-signing.
