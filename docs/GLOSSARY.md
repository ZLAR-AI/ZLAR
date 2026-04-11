GLOSSARY


Agent Health

The human-facing name for the restore subsystem (v3.0.0). Behavioral
observation that detects when an agent may be drifting and brings the
human back into the loop. Ships disabled by default.


Authority envelope

A single approval that covers a bounded scope of sub-actions. Used for
SubagentStart approvals where the human approves the delegation, not
each individual action within it.


Authority widening

A detector that flags when an agent broadens its operational scope beyond
what was established early in the session. New domains appearing after
the establishment window, especially after denials, indicate boundary
probing.


Canonicalization

The process of reducing a tool call to a deterministic, comparable form
before hashing or signing. Ensures that semantically identical requests
produce identical canonical representations.


Cedar

A formal policy language (from AWS) used by ZLAR as an alternative to
regex-based policy rules. Cedar policies are evaluated via WASM. Cedar
is default-deny. Forbid wins. This matches ZLAR's fail-closed architecture.


Contact boundary

The moment intention puts on gloves to touch reality. The point where
an agent's output becomes a real-world effect. ZLAR governs this boundary.


Degraded

A trust state indicating one or more detectors have flagged concerning
behavior. The gate may escalate allow actions to log. The agent is not
blocked but is under increased scrutiny. See trust state.


Deny-first governance kernel

A governance architecture where the default is denial, not permission.
Every action must be explicitly authorized by policy. Actions not
covered by any rule are denied.


Detector

A pure function that evaluates a session trace and returns a score (0.0
to 1.0), a confidence level, and evidence. Five detectors ship with
v3.0.0: contradiction_increase, escalation_under_ambiguity,
source_grounding_loss, abnormal_burstiness, authority_widening.
Detectors are composable and independently removable (RESTORE-INV-07).


Fail closed

If the gate cannot make a decision (policy missing, audit trail
unavailable, signing key absent), it denies. There is no permissive
mode. See ADR-003.


First Authority Law

The gate must be structurally incapable of being overridden by the
entity it governs. The agent cannot reach the off-switch. The agent
cannot modify the policy that constrains it.


Gate

The enforcement point. Sits between the agent and real-world actions.
Pattern-matches tool calls against signed policy. Cannot be persuaded,
only configured. ZLAR has two parallel gate implementations: CC gate
(bash) and MCP gate (Node.js).


Governed Action Receipt

A cryptographic proof that a specific action was governed. Contains the
decision (allow/deny), the policy version, the rule that matched, and
a signature chain. Portable across systems. See spec/governed-action-receipt-v1.md.


Healthy

The default trust state. No detectors have flagged concerning behavior.
The gate enforces policy normally. Absent trust state files are treated
as healthy (RESTORE-INV-01).


Human invariant

A property that must hold regardless of policy configuration. Five
enforcements: H6 (daily decision cap), H13 (pending queue capacity),
H14 (response time variance), H15 (deliberation floor), H17 (human
authenticity). These protect the human from decision fatigue and
rubber-stamping.


Monotone transition

A state transition that can only go in one direction (toward worse
states). Trust state transitions are monotone: healthy can become
degraded but degraded cannot become healthy without an explicit human
reset. This prevents an adversarial agent from gaming its way back to
a trusted state. See RESTORE-INV-03.


Restore

The engineering name for Agent Health. The restorative governance
subsystem that observes agent behavior and maintains a trust state.
Restore advises the gate; it does not enforce directly. Code lives
in lib/restore.sh, lib/restore-trigger.mjs, and packages/zlar-restore/.


Session state

Per-session counters tracking velocity (calls per window), loop detection
(repeated actions), and denial bursts (consecutive denials). A thin
cache that informs the gate's decision without overriding policy.
See lib/session-state.sh.


Suspended

The most severe trust state. All agent actions are blocked (escalated
to deny) until the human explicitly resets the trust state. See trust state.


Trust state

The Agent Health assessment of an agent's behavioral trajectory within
a session. Four states in monotone order:

  healthy    No concerns. Gate enforces policy normally.
  degraded   Detectors flagged something. Gate may escalate allow to log.
  at_risk    Significant drift detected. Gate escalates allow/log to ask.
  suspended  Agent behavior warrants full stop. Gate escalates everything to deny.

State can only worsen without explicit human reset. Absent trust state
file equals healthy (RESTORE-INV-01). Malformed file equals degraded
(RESTORE-INV-02). See docs/RESTORE-INVARIANTS.md.
