# Governed Action Receipt v1 — Conformance Profile

**Status**: Draft (staging) — ships with the Published v1.0 spec.
**Applies to**: Governed Action Receipt v1 as defined in `governed-action-receipt-v1.md`.
**Audience**: anyone implementing a v1 receipt verifier or producer independent of the ZLAR reference implementation.

---

## 0. Why this document exists

The v1 specification defines the wire format and verification algorithm. This document defines what it means for an independent implementation to **conform**. It names the exact checks a conforming verifier MUST perform, SHOULD perform, and MAY perform, and fixes the test vectors, canonical form, and signature algorithm so that two conforming implementations cannot silently diverge on interpretation.

A specification with no conformance profile drifts. Implementations each pick a slightly different subset to honor, and receipts begin validating under one implementation and failing under another without a single one being wrong per the spec text. This document closes that gap.

A conformance profile is not a compatibility test suite. It describes the invariants an implementation must hold. The test vectors at Annex A of the spec (and the reference verifier at `spec/verify-test-vectors.mjs`) exercise those invariants; passing them is necessary but not sufficient to claim conformance.

---

## 1. Conformance Levels

### 1.1 `MUST` — verifier conformance

A verifier claiming v1 conformance MUST:

1. Parse envelopes per §2 of the spec and reject any envelope containing fields outside the exact set `{v, id, kid, iat, type, payload, sig, prev}`.
2. Reject envelopes with `v !== 1` (exact integer comparison; strings MUST be rejected).
3. Reject envelopes with `type !== "governed-action"` (exact string comparison).
4. Implement the canonicalization rules in §4 per byte. Two conforming implementations applied to the same input MUST produce byte-identical canonical bytes.
5. Sign and verify the UTF-8 bytes of the lowercase hex SHA-256 hash, not the raw 32-byte hash. Implementations that sign the raw bytes are NOT conformant.
6. Reject receipts whose `sig` fails Ed25519 verification against the public key selected by `kid`.
7. Run full semantic validation per §8 of the spec after signature verification succeeds. A receipt with a valid signature but a semantic failure MUST be reported as `invalid`, not `valid-with-warnings`.
8. Enforce the `iat` acceptance window per §3.4. The default bounds (±300s future skew, max age 31 536 000s) MAY be narrowed but MUST NOT be widened silently.
9. Reject receipts where `kid` does not match a key in the verifier's keyring as `unknown-signer`. This state is distinct from `invalid` and a conforming verifier MUST report the two separately.
10. Reject receipts with unknown payload fields. A payload field not listed in §5 (plus §5.2 optional identity fields) MUST cause the receipt to be rejected.

### 1.2 `SHOULD` — verifier recommendations

A verifier SHOULD:

1. Support chain verification per §3.3 (walking `prev` links) as an optional mode. A verifier that cannot traverse chains can still verify individual receipts in isolation, but an archive verifier SHOULD support chain traversal end-to-end.
2. Log the `kid` of any `unknown-signer` rejection for operator action. Silent rejection of unknown-signer receipts is a conformance hazard — a rotated key that silently rejects all prior receipts has the same on-the-wire behavior as a verifier pointed at the wrong keyring.
3. Treat `authorized` (human-authorizer) receipts as stronger evidence than `allow` (policy-authorizer) receipts. This is the load-bearing distinction in §5.1.
4. When the receipt carries agent identity fields (§5.2), expose them to the calling application so higher-level logic can correlate receipts across time by `agent_fingerprint`.

### 1.3 `MAY` — optional features

A verifier MAY:

1. Accept legacy v0 (pre-published) receipts via an explicit opt-in flag. The reference implementation (`bin/zlar-verify`) gates this behind `--allow-v0`. A conformant verifier MUST NOT accept v0 silently — opt-in is required.
2. Cache canonical-form bytes of previously-seen receipts to avoid re-canonicalizing on `prev` traversal.
3. Add deployment-specific deny-only rules beyond the minimum set in §8.3.

### 1.4 Producer conformance

A producer claiming v1 conformance MUST:

1. Emit the exact envelope field set per §2. Adding vendor-specific fields at the envelope level is NOT permitted. Vendor-specific data belongs in a separate side-channel artifact keyed on `id`, not in the envelope.
2. Sign the UTF-8 bytes of the lowercase hex SHA-256 hash of the canonical payload, per §6. Producers that sign the raw 32-byte hash produce receipts that a conforming verifier MUST reject.
3. Never emit outcome/authorizer combinations outside the §5.1 coherence table.
4. Never emit a receipt with a deny-only rule (§8.3) and an approval outcome (`allow`, `authorized`).
5. Populate `ts` in the exact `YYYY-MM-DDTHH:mm:ss.sssZ` form. Variations (e.g., `+00:00` instead of `Z`, nanosecond precision, missing milliseconds) produce non-conformant receipts.

A producer SHOULD:

1. Emit the agent identity fields (§5.2) when a governing configuration artifact is in effect at decision time. Emitting `null` values when no artifact is present is preferred over omitting the fields. This distinguishes "no config hash available" from "field wasn't added by this producer."
2. Use the exact `agent_fingerprint` derivation defined in §5.2 (first 16 hex of SHA-256(`agent_type:config_hash:policy_version`)). Alternative derivations produce fingerprints that do not correlate across implementations.

---

## 2. Canonical Form Requirement

The v1 canonical form is a **frozen subset of RFC 8785 (JCS)** with the additional constraints in §4 of the spec. There is no algorithm negotiation. There is no fallback form. A v1 receipt is either canonicalized per §4 or it is not a v1 receipt.

The reference canonicalization for validation is `jq -S -c '.'` operating on an input that conforms to the §4 constraints. A conforming implementation MUST produce output that matches `jq -S -c '.'` byte-for-byte on every input.

Canonicalization differences to guard against:

- Unicode normalization (NFC, NFD, NFKC, NFKD): receipts MUST pass through UTF-8 bytes as-is. Implementations MUST NOT apply any normalization.
- Escape-sequence preferences (`\u0022` vs `"`): RFC 8785 fixes these. Implementations that diverge produce non-conforming output.
- Trailing-comma tolerance: forbidden. RFC 8785 forbids it. Canonical output MUST NOT contain trailing commas.
- Integer vs float distinction: the spec forbids floats in v1. Any numeric value that would serialize with a decimal point MUST cause canonicalization to fail.

---

## 3. Signature Algorithm

**Ed25519 only.** There is no algorithm negotiation field. There is no fallback to RSA, ECDSA, or HMAC. A v1 receipt is signed with Ed25519 or it is not a v1 receipt.

The signed input is the UTF-8 bytes of the 64-character lowercase hex SHA-256 hash of the canonical payload. It is **not** the 32 raw bytes of the hash. A verifier that treats the raw bytes as the signed input will reject every conforming receipt.

Key format: PEM-encoded Ed25519 public key, as produced by `openssl genpkey -algorithm ed25519`. Key identifier (`kid`) is derived from `shasum -a 256 <key.pub> | awk '{print substr($1,1,16)}'` — the SHA-256 of the **PEM file on disk**, not of the raw key bytes. Two verifiers using different fingerprint constructions will disagree on which key to select from a keyring; the spec pins this construction exactly.

---

## 4. Required Test Vectors

The test vectors in Annex A of the spec are authoritative. A conforming verifier:

- MUST validate every positive vector as `valid`.
- MUST reject every negative vector with the error code named in the vector.
- MUST produce byte-identical canonical form on the stated input for each vector.
- MUST verify each vector's signature successfully against `spec/test-key.pub`.

The reference script at `spec/verify-test-vectors.mjs` implements the §7 verification procedure from scratch with no dependency on the ZLAR codebase and runs each vector end-to-end. An implementation can use this script as a conformance probe on its own generated receipts by substituting its own generator output for the embedded vectors.

### 4.1 Vector catalogue (Published v1.0)

| # | Purpose | Expected outcome |
|---|---------|------------------|
| 1 | Minimal policy-allow receipt | signature valid, semantic valid |
| 2 | Human-authorized receipt with chain link | signature valid, semantic valid |
| 3 | Receipt with delegation chain (depth 2) | signature valid, semantic valid |
| 4 | Negative: deny-only rule with approval outcome (R003 + allow) | signature valid, semantic INVALID (`RULE_OUTCOME_CONTRADICTION`) |
| 5 | Negative: incoherent authorizer/outcome (policy + authorized) | signature valid, semantic INVALID (`AUTHORIZER_OUTCOME_MISMATCH`) |

Additional vectors covering agent identity fields, timeout-then-authorize incoherence, truncation detection, unknown-version rejection, and cross-tier hash collisions will be added as vectors 6–12 once the Published v1.0 spec test-vector signing ceremony is complete.

---

## 5. Agent Identity Fields (§5.2)

Published v1.0 introduces three optional nullable fields in the payload for cryptographic agent identity:

- `agent_config_hash` — SHA-256 of the governing configuration artifact.
- `agent_config_source` — enum indicating which precedence tier produced the hash: `project_claude_md`, `user_claude_md`, `project_soul_md`, `project_should_md`.
- `agent_fingerprint` — first 16 hex chars of SHA-256(`agent_type:agent_config_hash:policy_version`).

### 5.1 Declared vs cryptographic identity

The payload distinguishes two identity layers:

**Declared identity** — `manifest_agent_id` and `manifest_principal` come from a signed capability manifest. The manifest is the agent's claim about what it is and who is accountable for it.

**Cryptographic identity** — `agent_config_hash`, `agent_config_source`, and `agent_fingerprint` are computed at decision time from the governing artifact actually in effect. They are a record of what was loaded, not a claim about what should have been loaded.

A verifier that observes a manifest-declared `claude-code` agent with a `user_claude_md`-sourced config hash that diverges from a known project baseline has evidence of a governance-relevant discrepancy: the declared lineage does not match the cryptographic lineage. The two fields are independent and MUST NOT be collapsed into a single identity claim.

### 5.2 Resolution order

The reference producer resolves the governing artifact in this order (first match wins):

1. `${PROJECT}/CLAUDE.md` → `project_claude_md`
2. `${HOME}/.claude/CLAUDE.md` → `user_claude_md`
3. `${PROJECT}/soul.md` → `project_soul_md`
4. `${PROJECT}/should.md` → `project_should_md`

A conforming producer MAY use this exact order or document its own resolution order. The `agent_config_source` enum MUST accurately report which tier produced the hash. A verifier checking cross-producer consistency MUST rely on `agent_config_source` to disambiguate same-content hashes that originated from different tiers (for example, the same file content in both a project-level and user-level CLAUDE.md would yield identical `agent_config_hash` values; only `agent_config_source` distinguishes them).

### 5.3 Null semantics

When no governing artifact is present in the resolution set, a conforming producer MUST emit all three fields as `null` rather than omitting them. A verifier MUST treat `agent_config_hash: null` and absence of the field identically in all cases except conformance reporting: receipts missing the field entirely were produced by a pre-Published-v1.0 implementation, whereas receipts with explicit `null` were produced by a Published-v1.0-or-later implementation that knew no artifact was available.

---

## 6. Legacy v0 Compatibility

The pre-publication v0 receipt format (identified by `receipt_version: "0.1.0"` and inline signing) is **not** a conformant v1 format. A v1 verifier MUST reject v0 receipts by default. Accepting v0 is gated behind explicit opt-in (`--allow-v0` in the reference CLI; `{ allowV0: true }` in the reference library).

Silent dual-format verification is a conformance hazard. A verifier that accepts both v0 and v1 without opt-in can accidentally validate a v0 receipt under v1 assumptions and vice-versa. The reference implementation's default-reject-v0 posture is what makes the Published v1.0 spec safe to audit against.

---

## 7. Vendor Neutrality

The v1 format contains no vendor-specific fields. The envelope set `{v, id, kid, iat, type, payload, sig, prev}` is fixed. The payload set in §5 is fixed (with §5.2 optional fields). A producer SHOULD NOT add vendor-specific data to the receipt — instead, side-channel artifacts keyed on `id` provide vendor-specific extension without polluting the verifiable payload.

This is a conformance property, not a policy suggestion. A verifier receives a vendor-extended envelope and rejects it because the envelope field set is closed. Vendor-specific extension cannot be introduced without producing non-conformant receipts.

The neutrality property holds at the receipt level. It does not constrain what a producing system does around the receipt (integrating with other tools, exposing richer telemetry, etc.). It constrains only what a receipt is.

---

## 8. Versioning Posture

v1 is frozen (§9 of the spec). Any change to the envelope structure, payload structure, canonicalization rules, signing algorithm, or semantic validation rules MUST be published as a new major version with a different integer in the `v` field.

There is no `v1.1`. There is no `v1.x`. Every semantic change is a major-version change. A relying party holding a v1 receipt issued today can verify it in 2030 with a v1 verifier built in 2030, provided the public key remains available.

A v2 spec MAY declare itself compatible with v1 via explicit opt-in (analogous to the `--allow-v0` pattern for v0 receipts under the v1 verifier). A v2 verifier MUST reject v1 receipts by default.

---

## 9. Claiming Conformance

An implementation claiming v1 conformance SHOULD publish:

1. The implementation's version and commit identifier.
2. The platform and language (for reproducibility of canonicalization).
3. A conformance report documenting which of §1's `MUST` and `SHOULD` items the implementation holds. An implementation claiming `MUST` conformance on a subset of items and not on others is NOT conformant.
4. The output of running the implementation against the Annex A vectors. The output MUST match the expected outcomes per §4.1.
5. The signing and canonicalization fingerprints the implementation commits to (reference: §2–§3 of this document).

A publicly-claimed conformance without the above is unverifiable. This document provides the criteria; the implementation publishes the evidence.

---

*End of v1 Conformance Profile.*
