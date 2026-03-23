# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ZLAR, please report it responsibly.

**Email:** security@zlar.ai

Do not open a public issue for security vulnerabilities. We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |

## Security Design

ZLAR is built on five security principles:

1. **Fail closed.** If the gate is down, all actions are denied.
2. **No intelligence in the gate.** The gate classifies and enforces. It does not decide what is safe.
3. **Policy is a human artifact.** Ed25519-signed. Agents cannot modify the rules that govern them.
4. **Every feature is an attack surface.** Only add convenience when the pain of not having it is proven.
5. **Patience over speed.** When in doubt, deny.
