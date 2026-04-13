# ADR-009: Second Authority Law

## Status

Accepted (April 13, 2026)

## Context

The First Authority Law says the agent cannot act without human authorization. The gate enforces it. But the gate enforces whatever policy it loads. It cannot distinguish between a policy that protects the human and a policy that harms them. A malicious or negligent policy author could deploy rules that hollow out governance: disable auditing on consequential actions, remove human contestability paths, override the suspended state, or grant agents governance-critical powers.

The gap is not enforcement. The gap is that the enforcer has no authority over the lawmaker.

In constitutional terms: the gate is the judiciary. The policy is the legislation. There was no constitution.

## Decision

Add a constitutional layer above the policy layer. The constitution constrains what operational policies are permitted to contain. It is signed with a separate key from the policy key. The gate validates policy against the constitution at load time.

### Three-layer architecture

Layer 1: Permanent Core (7 clauses, unamendable). These define the identity of governed automation. Removing any of them is regime replacement, not amendment.

- PC-01: Governed consequential power must leave evidence.
- PC-02: Human authority must remain real rather than theatrical.
- PC-03: Human stop must remain sovereign.
- PC-04: There must exist a final degraded state no policy can override.
- PC-05: Agents must be denied six governance-critical powers.
- PC-06: Constitutional and policy keys must be procedurally separated.
- PC-07: The core cannot be amended from inside the regime.

Derived Properties (consequences of the seven clauses):

- DP-01: Irrevocability Theorem. No finite policy sequence removes human sovereignty.
- DP-02: Nonzero Constitutional Delay. Change requires time between proposal and activation.
- DP-03: Outer-Parameter Consistency. Amended parameters validated as a set, not individually.

Layer 2: Observability Obligations (6 clauses). The constitution requires enough visibility that hollow compliance becomes legible.

Layer 3: Amendable Outer Constraints. Constitutional but not identity-defining. Changeable only by ceremony.

### Halt vs Bypass

PC-03 encompasses two distinct human reserve powers, both sovereign:

Halt: the human stops all machine action while governance remains in force. The gate denies everything. Evidence is produced for every denial. Mechanically: suspended state and watchdog lockdown.

Bypass: the human removes the gate from the enforcement path entirely. The machine operates ungoverned. No evidence is produced because the gate is not running. Mechanically: off-flag at a path the agent cannot write to.

Both are human reserve powers. Neither is a policy power. Documentation must specify which power is meant when referencing the off-switch.

### Amendment ceremony

Four-step process: Propose (constitutional key) -> Cooling-off (72h default, 24h floor) -> Ratify (second signing act) -> Activate (DP-03 consistency check before applying).

The cooling-off period is not a security timer. It is a structural assertion that the person who proposes is not yet the person who should decide. The delay protects the proposer from their own urgency.

Amendments targeting permanent core are rejected. That is regime change, not amendment.

The `withdraw` command allows canceling proposals in proposed or ratified state. Abandoned proposals remain in proposed state as the negative space of constitutional evolution: they record what the operator considered and did not do.

The `rollback` command provides emergency restoration of the most recent archived constitution. The decision to return produces its own evidence.

### Deployment-gated validation

The gate only validates against the constitution when a deployment tracker exists. A constitution file without a tracker is ignored. This prevents DoS via a fake unsigned constitution.json.

Four states: file+tracker = validate, file+no tracker = ignore, no file+tracker = deletion attack (hard deny), no file+no tracker = pre-constitutional mode (pass).

### Evidence retention enforcement (OB-02)

The watchdog checks that audit trail retention meets the constitutional minimum. Evidence that vanishes before meaningful review is not evidence. Truncation below the retention floor invalidates the claim of governed operation.

### The Incompleteness

The constitution is a formal system. It cannot verify that genuine intent inhabits its structures. Structure can be satisfied insincerely. Ceremony can be complied with cynically. This is permanent. It is the reason humans must remain in the system.

## Honest Limitations

Three limitations stated for the record:

1. Single-operator ceremony provides procedural discipline, not separation of powers. Phase 2 supports a single constitutional key holder. Multi-party authorization (propose with key A, ratify with key B) is a future phase. The ceremony is mechanical discipline for one operator, not institutional checks and balances.

2. The constitution constrains the policy author but does not yet represent the governed. OB-03 surfaces constitutional changes to the operator. It does not surface them to the people affected by the governance regime. The nurse whose shift scheduling is governed, the farmer whose crop insurance claim is processed: the constitution does not yet hear them. Acknowledging this boundary is part of honest scope.

3. DP-03 coverage is bounded by the validator's known properties. The consistency check validates linear inequality constraints on Layer 3 parameters against Layer 1 and Layer 2 obligations. All current constraints are linear, so the admissible parameter region is convex and single-point checking is sufficient. Unknown inconsistencies and non-linear constraints (if added in future) require human review. DP-03 is a check of known consistency, not a proof of total consistency.

4. Constitutional key compromise has no governed response path. The operator must re-key out of band with no audit trail distinguishing legitimate key rotation from covert regime change. A governed key rotation ceremony is a future phase.

5. Rollback re-runs DP-03 with the current validator code, not the validator that was active when the archive was created. If future versions add new DP-03 checks, a previously valid archive could fail validation and block emergency rollback. When adding new DP-03 constraints, verify that existing archives remain rollback-eligible or document the break explicitly.

## Alternatives Considered

1. AI-based policy review. Rejected: this places intelligence in the enforcement path. The constitution must be checkable by a deterministic validator that cannot be persuaded.

2. Constitutional constraints as natural language only (documentation, not code). Rejected: a constitution that is not mechanically enforced is advisory, not constitutional. The value is in the gate refusing to load a violating policy, not in a document saying it should not.

3. Single-layer constitution (permanent only, nothing amendable). Rejected: governance that cannot adapt to operational reality becomes an obstacle to bypass. The three-layer design channels change through ceremony rather than forcing operators to choose between compliance and competence.

4. Auto-expiration of unratified proposals. Rejected: abandoned proposals in proposed state are meaningful evidence of intent that did not survive reflection. The Mystic Mathematician's insight: the negative space of constitutional evolution is information, not clutter.

## Consequences

Positive:
- Policy authors are now constrained by a higher authority. The gate enforces the constitution before loading the policy.
- Key separation prevents a single compromised key from controlling both the constitution and the policy.
- The amendment ceremony provides a governed path for changing constitutional parameters, avoiding the choice between stasis and ungoverned configuration edits.
- The incompleteness statement prevents the system from claiming more than it delivers.

Negative:
- Additional complexity in the gate's load path. Constitution validation adds ~8ms on first call, ~1ms on cache hit.
- Single-operator ceremony is procedural discipline without institutional checks. The system's constitutional legitimacy is bounded by the operator's good faith until multi-party authorization ships.
- The DP-03 consistency check is bounded by known properties. Adding new Layer 1 obligations requires updating the validator.

## References

- etc/constitution.json.template: three-layer constitution with seven permanent core clauses
- bin/zlar-constitution: CLI for key generation, signing, deployment, amendment ceremony
- bin/zlar-gate validate_constitution(): gate integration (lines 991-1149)
- bin/zlar-watchdog check-retention: evidence retention enforcement (OB-02)
- tests/test-constitution.sh: 35 assertions across 7 categories (A-G)
- ZLAR-2.0/build/second-authority-law-draft.md: original constitutional draft
