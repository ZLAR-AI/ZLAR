# ADR-011: Canonical Form Migration — Three Forms in Circulation

## Status

Accepted (April 15, 2026)

## Context

ZLAR's cryptographic chain depends on every signer and verifier agreeing on the exact bytes that are hashed before Ed25519 signing. The ZLAR Canonicalization Specification (docs/canonicalization-spec.md) defines this canonical form precisely. Line 89 of the specification states: "No trailing newline. The output is a single UTF-8 byte sequence with no padding."

An audit of the repository on April 15, 2026, conducted after a red-team review surfaced verification failures in the MCP gate, found that three canonical forms are currently in active use across the project. The spec is the authoritative form; two legacy forms diverge from it and have been in the project since early implementation.

### The three forms

**Form 1: Spec form (authoritative).** Compact, recursively sorted keys, no trailing newline. Produced by `lib/canonicalize.mjs` and matches `jq -S -c` output after stripping the newline that jq appends. Used by the MCP gate end-to-end for receipt and audit signing, and by `bin/zlar-receipt` (the standalone CLI receipt signer — which matches the spec by command-substitution newline-stripping accident).

**Form 2: Bash-pipeline form.** Compact, recursively sorted keys, trailing newline. Produced by any bash pipeline of the shape `jq -S -c '.' | shasum -a 256`: jq emits compact sorted JSON with a trailing newline, the pipeline preserves the newline into shasum's input. Used by `bin/zlar-gate` for internal receipt signing, audit entry signing, and manifest verification. Diverges from the spec by one trailing `\n` byte.

**Form 3: Bash-pretty form.** Plain (unsorted) pretty-printed JSON with 2-space indent, trailing newline. Produced by `jq '.signature.value = ""' file` and hashed as-is. Used by `bin/zlar-policy sign`, `bin/zlar-constitution sign`, and by `bin/zlar-gate` for runtime verification of policy, standing approvals, and constitution files. Diverges from the spec substantially — includes indentation whitespace, does not sort keys.

### Why this was invisible

The cross-gate compatibility tests passed because the one bash tool tested against Node (`bin/zlar-receipt`) happens to match the spec by accident. The bash signer paths that diverge (`zlar-policy sign`, `zlar-constitution sign`, `zlar-gate` receipt and audit pipelines) were never cross-verified against a Node verifier that uses the spec canonicalize. The MCP gate's policy and constitution verification failed silently against production-signed artifacts, but the gate was off during active development, so the failure was not operationally visible until the April 15 red-team exercise forced a cold start.

### Why this matters

Every signed artifact ZLAR produces is meant to stand as evidence for decades. Evidence that cannot be verified is not evidence. A canonicalization inconsistency is not a theoretical problem; it is the single most effective way to destroy the integrity of a cryptographic chain over time. Future verifiers — automated mathematicians, regulators, successor operators, auditors in jurisdictions ZLAR does not yet exist in — must be able to reconstruct the exact bytes that were hashed for any signature they are asked to verify. The spec is the only durable form because it is explicit, minimal, and not dependent on the presence of a specific jq version or tool chain.

## Decision

Adopt a three-phase migration. Each phase is a deliberate, tested transition, not a flag-day rewrite.

### Phase A (now, this commit series)

Accept all three forms in the MCP gate's signature verification paths. The MCP gate's `verifyJsonSignature` (policy, standing approvals) and `verifyEd25519` (constitution, manifest) both invoke `canonicalFormVariants()` and `verifyAnyCanonical()` from `lib/sig-verify.mjs`. When a legacy form is accepted, the gate logs a warning naming the form.

This unblocks the MCP gate against currently-deployed artifacts without any re-signing, preserves the audit chain, and gives operators visible notice that migration is pending. The attack surface is not widened: accepting more canonical forms does not create a forgery primitive — every form still requires a valid Ed25519 signature under the known public key.

### Phase B (separate future project)

Standardize all bash signers on the spec form by stripping trailing newlines before hashing and switching plain `jq` to `jq -S -c`. Specifically:

1. `bin/zlar-policy sign` — pipe canon through `tr -d '\n'` before hashing, use `jq -S -c` instead of plain `jq`.
2. `bin/zlar-constitution sign` — same.
3. `bin/zlar-gate` internal receipt and audit pipelines — pipe through `tr -d '\n'` before hashing.
4. `bin/zlar-gate` runtime verification of policy, standing approvals, constitution — canonicalize the same way.

Verify cross-gate parity before deploying: sign with the new bash tools, verify with MCP (which already supports the spec form). Re-sign deployed policy and constitution under the spec form.

Phase B is an audit-chain-affecting change. Receipts and audit entries signed under Form 2 remain verifiable (the MCP gate still accepts legacy forms); new receipts and audit entries are signed under Form 1. The cutover boundary should be documented in a `chain_transition` event emitted around the switchover.

### Phase C (after Phase B has burned in)

Remove legacy form acceptance from the MCP gate. `canonicalFormVariants()` returns only the spec form. Any signature that does not verify under Form 1 is rejected. This closes the migration.

### Invariants across all phases

- No re-signing of past receipts or audit entries. Their Form 2 signatures remain verifiable forever under the Phase A / Phase B multi-form logic.
- The spec is authoritative from now until forever. `docs/canonicalization-spec.md` does not change because of this ADR — the spec was always correct; the implementation diverged.
- Warnings are not noise; they are migration telemetry. Operators seeing LEGACY canonical form warnings during verification are reading a debt statement.

## Consequences

### Diamond-standard evidence

A future mathematician reviewing this decision should be able to: (a) read the spec and reproduce the canonical bytes for any Form 1 artifact, (b) read ADR-011 and `lib/sig-verify.mjs` and reproduce any Form 2 or Form 3 artifact's hash, (c) verify any Ed25519 signature the project has ever produced given the correct public key. The chain is forensic-grade in both directions.

### Operational noise during migration

The gate will log a legacy-form warning for every policy/SA/constitution/manifest verification until Phase B completes and the deployed artifacts are re-signed. This is acceptable — the noise is the debt signal. Muting it would hide the work that remains.

### Test coverage requirement

`mcp-gate/test-fail-closed.mjs` now includes a regression test that verifies the actually-deployed policy and constitution files against the multi-form verifier. If a future commit breaks legacy acceptance prematurely, this test will fail on any machine where the deployed artifacts are still Form 3.

### Author signature and audit

This ADR is written on April 15, 2026 as part of the red-team remediation work. The author accepts responsibility for naming the inconsistency that existed before this commit and for leaving an explicit migration path rather than a silent fix. No blame attaches to the original implementer — canonicalization inconsistencies are among the most common and subtle bugs in cryptographic systems, and none of the existing cross-gate tests were positioned to catch it.

## Related

- ADR-001: Deterministic enforcement
- ADR-004: Ed25519 signing
- ADR-007: Receipt v1 envelope
- ADR-010: Interception coverage model
- `docs/canonicalization-spec.md` — the authoritative canonical form
- `lib/canonicalize.mjs` — Node implementation of the spec
- `lib/sig-verify.mjs` — multi-form verifier introduced by this ADR
