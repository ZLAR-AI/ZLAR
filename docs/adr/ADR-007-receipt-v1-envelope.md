# ADR-007: Receipt v1 Envelope Format

## Status

Accepted for receipt v1 (April 6, 2026).

**Superseded for ZLAR Evidence Protocol v2 (August 17, 2026) by
`spec/ZLAR-EVIDENCE-V2-DRAFT.md`, §0.1.**

This is a scoped supersession. The custom JSON envelope, use of “the version IS
the algorithm” to omit a protected algorithm assertion, omission of protected
type metadata, and the prohibition on all extensions do not govern v2. The v2
architecture uses `COSE_Sign1` Signed Statements with a version-fixed mandatory
algorithm profile. Protected `alg` redundantly asserts that required algorithm;
protected `alg`, `kid`, content type, and statement role must match the profile.
A mismatch is rejection, not negotiation. The package cannot negotiate or
downgrade the algorithm.

The April 2026 forecast below that v2 would use composite ML-DSA-65+Ed25519 is
also superseded as a v2 selection. The v2 profile must make and justify its
algorithm-suite and post-quantum transition decision separately.

What remains accepted: receipt v1's historical construction, signing opaque
bytes rather than requiring verifier recanonicalization, strict rejection of
unknown security semantics, and the no-negotiation/no-downgrade objective.
Existing v1 artifacts do not change.

The successor v2 protocol is still marked UNSOUND and is not frozen. This status
change accepts the construction-direction supersession only. It does not accept
a v2 schema, wire encoding, implementation, conformance result, or release.

## Context

The v0 receipt format (0.1.0) stores all governance fields inline and signs the canonical form of the entire structure minus the signature field. This requires verifiers to re-canonicalize the receipt to verify — any canonicalization divergence between signing and verification produces a verification failure.

Research into cryptographic format longevity (items 11 and 13 in the research queue) identified clear patterns:

1. **Formats that sign opaque bytes outlast formats that require canonicalization.** XML Digital Signatures failed because XML canonicalization is computationally complex and semantically ambiguous. JWT succeeded despite security flaws because its three-part structure is conceptually simple. PASETO, DSSE, and COSE all sign payloads as opaque byte sequences.

2. **Versioned protocols beat algorithm negotiation.** JWT's `alg` header has produced CVEs for 11 years. PASETO, age, and WireGuard fix the algorithm to the version. No negotiation, no downgrade attacks.

3. **Extension mechanisms in v1 are where complexity hides.** Start strict. Version bump for changes.

The v0 format also uses a string version field (`"receipt_version": "0.1.0"`), an `alg` field in the signature block, and nested structures that complicate parsing.

## Decision

Introduce receipt v1 with an envelope format that separates the signed payload from the envelope metadata.

**Envelope structure:**
```json
{
  "v": 1,
  "id": "hex-timestamp-random",
  "kid": "key-fingerprint-16chars",
  "iat": 1712412000,
  "type": "governed-action",
  "payload": "<base64url of canonical JSON>",
  "sig": "<base64url of Ed25519 signature>",
  "prev": null
}
```

**Key design decisions:**

- `v` is an integer, not a string. It determines the entire cryptographic construction. v1 = Ed25519 + SHA-256 + ZLAR canonical JSON.
- No `alg` field in the envelope. The version IS the algorithm. This eliminates the JWT vulnerability class.
- `payload` is base64url-encoded (no padding) UTF-8 bytes of the canonical JSON payload. Canonicalization per ZLAR Canonicalization Spec v1.0 happens once at signing time.
- `sig` is base64url-encoded Ed25519 signature over SHA-256(decoded payload bytes) represented as hex string.
- Verifiers decode the payload bytes, hash them, and verify. No re-canonicalization.
- `prev` links receipts into a chain (SHA-256 of the previous receipt's canonical envelope).
- No extension mechanism. Strict schema. Changes require a version bump.

**v0 backward compatibility:** The verifier (`bin/zlar-verify`) accepts both v0 and v1 receipts, dispatching based on whether the receipt has a `v` (integer) or `receipt_version` (string) field.

## Consequences

- Receipts issued before this change (v0) remain verifiable with the existing v0 verification path.
- New receipts (v1) are immune to canonicalization divergence during verification.
- The v1 format is the one that goes external — to auditors, to Forrester, to regulatory filings.
- Post-quantum transition path: v2 will use composite ML-DSA-65+Ed25519. The `v` field makes this clean — old verifiers accept v1, new verifiers accept both, and after a transition window v1 acceptance ends.
- The format is frozen. Changes require ADR amendment and version bump.
