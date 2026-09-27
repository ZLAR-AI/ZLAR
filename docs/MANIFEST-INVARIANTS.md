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
6. expired manifest            = hard deny (silence after expiry means authority withdrawn)
7. unsigned manifest           = reject manifest, fall back to policy-only enforcement
8. tampered manifest (bad sig) = hard deny on everything + log critical security event
9. missing manifest (first run) = fall back to policy-only (no seq file present)
9a. missing manifest (after load) = hard deny + alert (seq file present = manifest existed;
                                    deletion is an attack, not an absence)
10. sequence rollback (seq < last) = hard deny (manifest was rolled back to older version)
11. sequence gap attack (Δ > 100) = log critical + alert + self-heal reset (seq file
                                    poisoning would otherwise permanently DoS all loads)
```

## Exclusions (what must NEVER go in the manifest)

These exclusions have constitutional weight. A bad inclusion is permanent
damage. A missing inclusion can grow later.

```
12. No self-modify or override flags (agent cannot raise own ceiling)
13. No capability wildcards (finance.* auto-grants the unknown)
14. No behavioral instructions or prompts (constitution, not job description)
15. No auto-approve or bypass-human flags (judgment cannot be pre-empted)
16. No reputation scores or trust ratings (computed, not declared)
17. No judgment criteria ("approve if < $1000" turns human into rubber stamp)
18. No fail-open flags (crash = deny, always, not configurable)
19. No logging configuration (agent cannot control its own audit trail)
```

## v0 scope

The v0 manifest has exactly six sections:

```
identity          — who is this agent, who is accountable
authority         — what action categories are allowed, denied, or unmatched
escalation        — what conditions route to a human, and how
sequence          — monotonic counter; enforces replay protection (see failure modes 10–11)
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

## Cross-path invariant

```
20. DWP-01 (Deny Wins Precedence): When two evaluation paths exist
    (v0/v1, JSON/Cedar, locked/unlocked, cached/fresh), the path with
    fewer checks must either be removed or must produce deny on any
    divergence from the stricter path. No weaker path may silently
    override a stricter path's decision.
```

## Design principle

Let the gate be complex. Let the manifest be simple.
