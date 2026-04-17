# ADR-012: Hash Chain and Non-Repudiation Hardening

## Status

Accepted (April 16, 2026)

## Context

The v3.1.0 mathematician's verification (mathematician-verification-v310.md) records two properties in the "HOLDS WITH GAPS" class:

- Property 5 — Hash Chain Integrity. Tamper-evident within a single unrotated audit file, but with three named sub-gaps: rotation severs cross-file continuity, no `flock` on macOS under concurrent invocations, and no `fsync` after append.
- Property 6 — Receipt Non-Repudiation. All governance-relevant fields bound into the signed payload, with two named sub-gaps: the verifier does not enforce `audit_event_id` match (presentational replay), and tail truncation (deleting the last receipt) is undetectable without an external witness.

The verification document names these gaps because they are real. Silence about them is worse than disclosure — a hostile reviewer reading the spec against the implementation will find each one. This ADR records the disposition of each sub-gap: fix, accept, or document.

## Decision

### Property 5a — Log rotation cross-file anchor

Status: FIX.

`bin/zlar-gate` `rotate_audit_if_needed()` now computes two hashes before moving the audit file:

- `rotated_hash`: SHA-256 of the entire file (aggregate content binding).
- `chain_tail`: SHA-256 of the last line (linear chain tail).

Both are written to a sidecar `var/log/audit.anchors.jsonl` alongside the rotated filename, its byte size, and the rotation timestamp. The sidecar is append-only JSONL, one entry per rotation.

What this buys. With the sidecar present, a verifier can detect:

- Silent deletion of the rotated archive: anchor exists, named file absent.
- Substitution of the rotated archive: named file present but `shasum -a 256` of its contents does not match `rotated_hash`.
- Truncation of the rotated archive: file size on disk does not match `rotated_size`.

What this does NOT close. The anchor format is forward compatible — existing verifiers (`bin/zlar-audit verify-chain`, `bin/zlar-au`) continue to work unchanged because the sidecar is a separate file. A dedicated verifier subcommand that consults the sidecar and reports archive-deletion / archive-substitution findings is tracked as follow-up work; the DATA is captured at rotation time and cannot be fabricated after the fact, so adding the consumer later does not reduce forensic completeness.

### Property 5b — No `flock` on macOS (concurrent invocation chain fork)

Status: DOCUMENT (accepted limitation with explicit mitigation in place).

`bin/zlar-gate` uses `flock` when available (Linux) and logs a warning otherwise (macOS). Two parallel gate invocations on macOS can theoretically produce two audit entries with identical `prev_hash`, forking the chain.

Why this is not being "fixed" with a portable bash replacement:

- A `mkdir`-based lock directory is atomic on POSIX but requires a correct stale-lock reclaim policy. Getting reclaim wrong deadlocks the hook under any ungraceful exit (Ctrl-C, kill -9, OOM). A deadlocked hook turns fail-closed governance into an unusable system. A subtly-wrong lock is worse than a documented gap.
- Claude Code invokes `PreToolUse` hooks synchronously from a single process per session. Concurrent invocations of the hook against the same audit file require *two sessions running simultaneously against the same repo* — an unusual configuration that a user has to deliberately set up. In that configuration, chain forks are detectable at verification time: `verify-chain` in `bin/zlar-audit` reports hash mismatches at the fork point.
- On Linux (and any system where `flock` is available), the existing code is already correct. The gap affects only macOS and only multi-session-on-one-repo use.

Concrete mitigations in place today: the gate logs a WARN when `flock` is unavailable; the chain verifier reports forks at mismatch boundaries; the receipt envelope is signed independently of the audit chain, so receipt non-repudiation is unaffected by audit fork.

### Property 5c — No `fsync` after append (crash mid-write)

Status: DOCUMENT (accepted platform limitation).

Bash has no portable `fsync` primitive. A crash between `echo >> file` completing and the OS flushing the page cache can leave the last audit entry partially written. This is detectable (the partial line is not valid JSON; verifiers reject it), not self-healing (the lost event is lost).

Mitigation in place: the gate writes audit entries synchronously inside the hook execution; macOS and Linux page caches flush on orderly shutdown; the audit chain's hash-linking detects any truncation at verification time. Platforms that need stronger durability guarantees should run ZLAR on a filesystem configured for synchronous writes (e.g., `dirsync` mount option) or route through the MCP gate (Node.js, with `fs.writeFileSync` + `fsync`) instead of the bash gate.

### Property 6a — Presentational replay in verifier

Status: DEFER TO CONFORMANCE.md.

A valid receipt for event X can be presented as evidence for event Y if the verifier does not check that `audit_event_id` matches the event being claimed. `bin/zlar-verify` proves the receipt is authentic, not that it is the correct receipt for the presented context.

This is a verifier-side obligation, not a gate-side defect. The receipt payload already binds `audit_event_id` into the signature — the data is there. Any party presenting a receipt as evidence must also present the event id being claimed, and the verifier must check they match.

The `spec/CONFORMANCE.md` document (Phase 2 of the v1.0 publication plan) defines verifier conformance levels. This requirement is recorded there as a MUST for compliant verifiers. `bin/zlar-verify` will gain a `--match-event-id <id>` flag alongside CONFORMANCE.md's publication.

### Property 6b — Tail truncation of receipt log

Status: DOCUMENT (inherent limitation of local storage).

A single actor with filesystem write access can delete the last N receipts from the receipt log. Each surviving receipt is still authentic; the chain terminates at an earlier point. No local mechanism detects this.

This is a structural limitation of any chain stored on a writable medium without an external witness. Two mitigation paths:

- Append-only medium: WORM storage, S3 Object Lock, or similar. The gate's receipt output can be teed to such a medium by operators who need truncation detection.
- External witness: a second-party observer (auditor's log, independent timestamp service, transparency log) records receipt hashes as they are issued. Tail truncation is detected by divergence between local and witness views.

The `spec/governed-action-receipt-v1.md` receipt specification will note, in the `§10 Threat Model` section, that tail truncation requires external-witness mitigation and is not addressed by the receipt's signature. This is work for Phase 2 alongside CONFORMANCE.md.

## Consequences

### Positive

- Rotation is no longer a silent chain break. The anchor sidecar captures the forensic data needed to detect tampering of rotated archives. A future verifier command can consult the sidecar without changes to the archive format itself.
- Every named sub-gap in Properties 5 and 6 now has an explicit disposition. A hostile reviewer reading the verification document and this ADR side by side sees a gap inventory, not a silence.
- Property 6a and 6b responsibilities move to the correct document (CONFORMANCE.md and the receipt spec respectively). The ADR trail remains an architectural record; the operational obligations live with the spec that imposes them.

### Negative

- The rotation anchor is currently emitted but not consumed by an existing verifier. Adding a dedicated `verify-rotation-anchors` subcommand is tracked as follow-up. The data is captured; full end-to-end verification is not yet shipped.
- Property 5b (macOS flock gap) remains a documented limitation. Users running multiple simultaneous ZLAR sessions against the same repository on macOS retain the risk of chain-fork under rare race conditions.
- Property 5c (fsync gap) remains a documented platform limitation. Users needing strong durability guarantees must select their filesystem and mount options accordingly or use the MCP gate.

### Operational

- No configuration changes required. Rotation anchors are emitted automatically.
- Sidecar file (`var/log/audit.anchors.jsonl`) grows one line per rotation event. At 10MB rotation threshold with an average 2KB audit entry, expect roughly one anchor line per 5,000 events.
- Verifiers that walk the audit chain do not need updates for the sidecar. The sidecar is an additive forensic artifact, not a required input.

## Alternatives considered

**Inline anchor (anchor entry inside the audit file).** Rejected. Would require updating `bin/zlar-au verify`, `bin/zlar-audit verify-chain`, and every downstream consumer simultaneously. The sidecar approach is backward compatible.

**Fix all five sub-gaps in bash.** Rejected for 5b (mkdir-lock deadlock risk higher than the gap) and 5c (no portable bash primitive). Overengineering the bash gate is not the right direction — durability-critical deployments should use the MCP gate, which has `fs.writeFileSync` and Node-native synchronization primitives.

**Defer everything to CONFORMANCE.md.** Rejected. Property 5a was tractable in the gate today; deferring what could be fixed now would leave a cheap rotation-anchor mitigation unshipped. The others are verifier-side (6a) or spec-side (6b) obligations that genuinely belong in the conformance and threat-model documents.

## References

- `mathematician-verification-v310.md` — lines 39–60, Property 5 and Property 6 gap enumeration.
- `bin/zlar-gate` `rotate_audit_if_needed()` — rotation anchor emit.
- `var/log/audit.anchors.jsonl` — sidecar anchor storage (created on first rotation).
- ADR-004 — Ed25519 signing discipline (receipt non-repudiation foundation).
- ADR-007 — Receipt v1 envelope (the payload binding that Property 6 rests on).
- `spec/CONFORMANCE.md` — verifier conformance levels (Phase 2, forthcoming).
- `spec/governed-action-receipt-v1.md` §10 — threat model, including tail-truncation disclosure (Phase 2).
