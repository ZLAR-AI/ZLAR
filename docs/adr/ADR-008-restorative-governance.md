# ADR-008: Restorative Governance (Agent Health)

## Status

Accepted (April 12, 2026)

## Context

ZLAR 2.x provides deterministic enforcement: the gate evaluates each tool call independently against signed policy. This catches individual violations but cannot detect behavioral patterns that emerge across multiple calls within a session. An agent that individually obeys every rule can still drift — escalating after denials, abandoning source-checking, widening its operational scope, or producing contradictory actions.

The gap is not enforcement. The gap is observation.

Monitoring tools (zlar-witness, zlar-digest) already observe the audit trail and report patterns. But they run after the fact. They do not feed back into the gate's decisions in real time.

The question: can observation inform enforcement without putting AI in the enforcement path?

## Decision

Add a restorative governance layer (Agent Health) that sits alongside the gate, not inside it.

Three-layer separation:

1. Action layer (the agent) — produces tool calls.
2. Gate layer (enforcement) — evaluates each call against policy. Deterministic. No reasoning.
3. Healer layer (restore) — observes behavioral patterns across the session. Produces a trust state. Advises the gate.

The healer advises. The gate consults. The human decides.

Key architectural choices:

1. Trust state is monotone. It can only worsen (healthy to degraded to at_risk to suspended). An agent cannot game its way back to trusted by producing favorable-looking actions. Only a human can reset the state, and only with friction (reason, delay, signed event, daily limit).

2. Detectors are pure functions. Each takes a trace (array of audit events) and returns a score, confidence, and evidence. No shared state between detectors. Any detector can be removed without affecting others.

3. The gate integration is error-trapped. If restore fails for any reason, the gate continues with the original policy action. Restore cannot crash the gate. Restore cannot deny an action that policy allows — it can only escalate to ask, bringing the human into the loop.

4. The feature ships disabled. When enabled is false (the default), all restore code paths short-circuit. The gate runs identically to v2.x. This preserves the version boundary: 2.x users get enforcement only, 3.x users opt in to behavioral observation.

5. The background trigger is non-blocking. The gate fires the evaluation engine in a background process after denials and high-risk events. The gate does not wait for the result. The next gate invocation reads whatever trust state exists at that point.

## Alternatives Considered

1. Inline evaluation (run detectors synchronously in the gate). Rejected: adds latency to every tool call, creates a crash risk, and violates the principle that the gate should be fast and deterministic.

2. AI-based behavioral assessment. Rejected: this is the exact pattern ZLAR exists to prevent. Putting AI in the enforcement path means the governance system can be persuaded. Detectors use statistical heuristics (ratios, temporal clustering, domain set expansion), not reasoning.

3. Continuous scoring without monotone constraint. Rejected: allows an adversarial agent to manipulate its score by interspersing "good" actions between "bad" ones. Monotone transitions make this impossible.

4. Automatic reset on session boundary. Rejected: sessions can be restarted strategically. Reset must require human action with friction.

## Consequences

Positive:
- The gate can now respond to behavioral patterns, not just individual violations.
- Human attention is directed to sessions that show drift, reducing the false positive burden from rule-level escalations.
- The architecture is additive. Nothing in 2.x is removed or weakened.

Negative:
- Detector thresholds are conservative defaults. They need tuning with real session data before they produce reliable signals.
- The background trigger adds a Node.js process per deny/novelty/high-risk event. In high-throughput sessions this could be significant.
- Trust state files add a new state surface that must be protected from tampering (not yet addressed — see adversarial review notes).

## References

- docs/RESTORE-INVARIANTS.md — 8 invariants governing the restore subsystem
- docs/architecture-map.md — restore subsystem section
- ZLAR-3.0/build/doctrine-notes-april12.md — Vincent's design doctrine (private)
