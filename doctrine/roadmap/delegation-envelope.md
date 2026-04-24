Delegation Envelope
Roadmap note. Design, not yet shipped.

Last updated 2026-04-24. Live roadmap doctrine.

Status: named, shape clear, code not written. This file makes the gap public so no reader believes it is already covered.

—

1. The gap

ZLAR's gate intercepts tool calls made by the local process it is installed in. The gate does not intercept tool calls made by any sub-runtime the local process spawns outside ZLAR's SDK delegation chain.

Concretely: a local Claude Code process with ZLAR installed governs its own tool calls. If that process delegates work to a harness-managed agent running in a separate execution context — any sub-runtime with its own permission model, spawned by the harness rather than by ZLAR's SDK — the sub-runtime's tool calls do not reach the ZLAR hook. The sub-runtime has whatever authority the harness gives it, typically filesystem and network, subject only to the harness's own permission model.

From the operator's point of view, the mental model "ZLAR is on, therefore this machine's agent actions are governed" is wider than the actual enforcement perimeter. The perimeter is the local process. Sub-runtimes that run outside the SDK delegation chain are outside the perimeter.

SCOPE.md names this case under "Out-of-SDK sub-runtimes." This file is the plan for closing it.

—

2. What is already handled

In-SDK delegation (single deployment). Covered by the existing ZLAR SDK delegation chain. When the orchestrator spawns a worker through the SDK, the spawn itself is a governed event at the orchestrator's gate. The worker carries a signed token. The daemon verifies the delegation chain before policy evaluation. The manifest narrows at each level. This is shipped.

Cross-deployment ZLAR↔ZLAR federation. Receipts are portable and verifiable today. The trust-federation protocol that lets deployment B accept deployment A's receipts as pre-authorization at an organizational boundary is designed, not yet shipped. Related but distinct from the gap this note addresses.

—

3. What to build

Delegation-envelope gate.
When the local process hands off work to a sub-runtime ZLAR cannot reach inside of, ZLAR gates the handoff. The envelope is a signed declaration of what the sub-runtime is permitted to touch: which filesystem paths, which network destinations, what duration, what budget, whether it is allowed to spawn further. The operator approves the envelope once through the standard human-authority path. The sub-runtime is trusted within that envelope for its lifetime.

At close, the sub-runtime returns a signed manifest of what it actually did. ZLAR's verifier cross-checks the manifest against the envelope. Deviations are audited. Egregious deviations are policy violations.

This is unilateral-buildable. It does not require the sub-runtime vendor to cooperate beyond returning a parseable manifest. For sub-runtimes that do not return such a manifest, the envelope is still gated at handoff — the operator at least saw and approved the delegation — but post-hoc verification is best-effort.

Session-level decision surface.
An enforcement-layer product should be able to tell its operator what was enforced. Today an operator cannot answer "what did ZLAR decide this session?" without reading audit logs. A session digest surfaced to the operator — N passed silently, M asked, P denied, Q fell outside ZLAR's perimeter — is itself an enforcement property. If the operator cannot tell, the operator cannot catch policy-gap regressions.

The "outside ZLAR's perimeter" bucket is exactly what the delegation envelope makes visible. Until the envelope ships, the digest can only show what the local gate saw.

—

4. Architectural shape

The delegation-envelope gate is the shallow version of federation. A sub-runtime that returns a signed manifest is structurally similar to a deployment that returns receipts. The same primitive — signed handshake artifact at a governance boundary — appears in both.

Build order: delegation envelope first, federation next. The local-handoff case forces the manifest-return discipline. Federation is the same discipline extended to the organizational boundary.

—

5. Distinction from adjacent terms

Delegation envelope is a handoff primitive. It names a scope for a single sub-runtime's lifetime across the boundary ZLAR cannot see into.

Authority Envelope (DNA §10, term under consideration) is a different primitive. It names authority scoping across agent sessions — what prior authority a future session inherits from a past one. Related in shape (both are envelopes) but governing different boundaries.

The delegation envelope is shippable code. The authority envelope is an open doctrine question. Keep them named separately.

—

6. Open questions

- Is "delegation envelope" the right name, or is "handoff boundary," "sub-runtime envelope," or "delegation permit" closer to what the primitive does?

- Does this subsystem sit inside the existing SDK delegation work in the repo, or is it architecturally separate?

- For sub-runtimes that do not return a manifest (the common case today), is envelope-gating at handoff sufficient to claim "governed," or must ZLAR refuse to hand off at all until the sub-runtime implements manifest return?

- Do envelope rules live in operational policy (per-deployment tuning) or in the constitution (hard floor that policy authors cannot soften)?

None of these are blockers for capturing the gap publicly. They are the questions the build session opens with.

—

7. Connection to SCOPE.md

SCOPE.md names "out-of-SDK sub-runtimes" as outside ZLAR's current perimeter. This file is the named plan for pulling that case inside the perimeter. When the delegation envelope ships, SCOPE.md's shipping-status block moves the capability from "design, not shipped" to "shipped," and the out-of-SDK section is rewritten to reflect what the envelope now covers and what still lies outside.

Until then: SCOPE.md's claim stands. The gap is stated, not hidden.
