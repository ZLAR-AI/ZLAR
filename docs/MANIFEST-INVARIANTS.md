# Manifest v0 Invariants

These invariants govern the design and implementation of the ZLAR capability
manifest. They were earned through multi-agent design review (April 2-3, 2026)
and must not be violated in v0. Any proposed change that breaks an invariant
requires the same level of review that produced these invariants.

## What the manifest IS

The manifest is an **interface** to governance, not governance itself.
The gate is the governance. The manifest makes governance portable,
transparent, and composable.

The manifest declares **ceiling, never floor**. It says what an agent
MAY do. Never what it SHOULD do. Nothing in the manifest can expand
authority. It can only constrain.

## Precedence

```
1. manifest deny   >  policy deny   >  policy ask  >  manifest allow  >  policy allow
2. deny always wins
3. allow never overrides deny
4. manifest narrows policy, never widens it
5. unmatched actions follow the manifest's unmatched_action field (default: escalate)
```

## Failure modes

```
6. expired manifest          = hard deny (silence after expiry means authority withdrawn)
7. unsigned manifest         = reject manifest, fall back to policy-only enforcement
8. tampered manifest (bad sig) = hard deny on everything + log critical security event
9. missing manifest          = fall back to policy-only (backward compatible)
```

## Exclusions (what must NEVER go in the manifest)

These exclusions have constitutional weight. A bad inclusion is permanent
damage. A missing inclusion can grow later.

```
10. No self-modify or override flags (agent cannot raise own ceiling)
11. No capability wildcards (finance.* auto-grants the unknown)
12. No behavioral instructions or prompts (constitution, not job description)
13. No auto-approve or bypass-human flags (judgment cannot be pre-empted)
14. No reputation scores or trust ratings (computed, not declared)
15. No judgment criteria ("approve if < $1000" turns human into rubber stamp)
16. No fail-open flags (crash = deny, always, not configurable)
17. No logging configuration (agent cannot control its own audit trail)
```

## v0 scope

The v0 manifest has exactly five sections:

```
identity          — who is this agent, who is accountable
authority         — what action categories are allowed, denied, or unmatched
escalation        — what conditions route to a human, and how
expires           — hard expiry timestamp
signature         — Ed25519 signature over the manifest
```

Nothing else goes in v0. Not budgets. Not delegation. Not lifecycle
management. Not capability registries. Not profiles. Not ratification
(that is a separate artifact). Not severity gradations.

## Capability namespace (provisional)

v0 uses an internal dot-notation namespace prefixed with `zlar:cap:`.
This is explicitly provisional and will map to a cross-vendor standard
when one exists.

## Design principle

Let the gate be complex. Let the manifest be simple.
