# ADR-004: Ed25519 for Cryptographic Signing

Status: Accepted
Date: 2026-02-10
Author: Vincent Nijjar

## Context

ZLAR signs four things: policy files, standing approvals, audit trail entries, and governed action receipts. The signing algorithm must be fast (gate is synchronous), widely supported (bash + Node.js + any future verifier), and quantum-migration-ready.

Candidates: RSA-2048, ECDSA P-256, Ed25519, ML-DSA-44 (FIPS 204).

## Decision

Ed25519 is the default signing algorithm.

- 64-byte signatures (vs. 256 for RSA-2048). Compact audit entries.
- Sign + verify in under 1ms on commodity hardware.
- Available in OpenSSL 3.x (macOS Homebrew, Linux default) and Node.js crypto (built-in since v15).
- Deterministic signatures — same input always produces same output. No nonce generation required. Simplifies testing.
- 128-bit classical security. Sufficient for current threats.

Post-quantum migration path: ML-DSA-44 (FIPS 204) is supported via the crypto abstraction layer (`lib/crypto.sh`). Hybrid mode (Ed25519 + ML-DSA-44) is implemented. Algorithm selection is configuration, not code — swap via `ZLAR_SIGN_ALGORITHM` or `crypto.json`. Every audit entry records `signature_algorithm` for re-signing during migration.

## Consequences

- macOS ships LibreSSL, which lacks Ed25519 `pkeyutl -rawin` support. The gate auto-resolves to Homebrew OpenSSL 3.x when available. This is documented in the quickstart.
- The signing approach signs SHA-256(canonical_json) as a hex string, not raw bytes. This is non-standard but deterministic and cross-gate compatible. Documented in the receipt spec.
- Cryptographic agility is built in. When NIST mandates ML-DSA migration (expected 2028-2030), ZLAR can switch without code changes. Historical entries record their algorithm for re-verification.
- Key management is the operator's responsibility. ZLAR generates keys but does not manage rotation, distribution, or revocation beyond documenting the process (docs/token-rotation.md).
