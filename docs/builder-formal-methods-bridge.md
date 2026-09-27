# Builder Formal-Methods Bridge

Status: builder note, claim-bounded.

Purpose: preserve the build implications from ZLAR's private formal-methods
inquiry without turning that inquiry into repo doctrine, novelty claim, public
mathematics, production proof, or external attestation.

## Claim Boundary

This note does not claim:

- new mathematics
- production safety
- current-machine governance
- external review
- external attestation
- all-surface or unrouted-surface coverage
- proof that every deployment closes every side door

Safe builder wording:

```text
ZLAR uses formal-methods-shaped constraints to keep governed consequence paths
honest: coverage, scoped recognition, action binding, issuer correctness,
receipt lifecycle, downstream refusal, and non-authorizing learning.
```

## Core Chain

Every consequential lane should be explainable as:

```text
Action Class
-> Authority Topology
-> Receipt Requirement
-> Issuer Correctness
-> Downstream Refusal
-> Effect
```

If any link is missing, the builder should treat the lane as incomplete or
below stronger claim ceilings.

## Builder Invariants

### Proposal Is Not Crossing

An agent may propose, request, argue, simulate, or draft. None of that is the
governed crossing.

Blue-button shorthand maps here: a request to press a consequential button is
still proposal traffic until route checks, authority topology, receipt
requirements, and downstream refusal are satisfied.

Builder implication:

```text
No effect-producing path may treat proposal text as authority material.
```

### Validity Is Not Recognition

A cryptographically valid artifact proves bytes and signing context. It does
not prove this relying party recognizes the artifact for this consequence.

Builder implication:

```text
Receipt verification and issuer/scope recognition remain separate checks.
```

### Recognition Is Scoped And Current

Recognition belongs to a domain, action class, target, policy, time window,
issuer state, and replay state.

Builder implication:

```text
Wrong issuer, wrong domain, wrong action, wrong target, wrong policy, stale,
expired, revoked, or consumed receipts refuse before effect.
```

### Authority Does Not Clone

Authority for one action does not silently authorize a neighboring action.
Equivalence is itself an authority surface.

Builder implication:

```text
If a receipt boards a governed equivalent action, the equivalence relation must
be explicit, scoped, and governed.
```

### Authenticity Is Not Rightful Issuance

An authentic receipt can still be wrongly issued if the legitimate issuer was
tricked, coerced, or misrouted into minting it.

Builder implication:

```text
The issuer/minting path is a first-class boundary, not paperwork behind the
downstream verifier.
```

The receipt should bind enough context for downstream refusal:

- requested action
- effective action
- action class
- target/resource identity
- policy version
- authority topology satisfied
- issuer identity and issuer state
- time, expiry, revocation, nonce, and consume behavior
- claim boundary

### Refusal Is Not Authority

Failed attempts, blocked routes, and refusal evidence can teach the system only
after evidence gates. Refusal never creates boarding authority.

Builder implication:

```text
Learning updates may improve maps, tests, hardening candidates, and claim
ceilings. They may not mint permission.
```

### Coverage Is A Proof Obligation

Boundary correctness is not coverage. A perfect gate on one path says nothing
about a side door.

Builder implication:

```text
Every stronger claim must name the routed domain and the known non-coverage.
```

## Lane Template

For any new governed action lane, write down:

- `action_class`: the consequence being governed.
- `protected_target`: the resource, state, device, service, record, or effect
  boundary.
- `coverage_premise`: which effect-producing paths are routed, and which
  known side doors remain outside the claim.
- `authority_topology`: who can authorize, under which role, quorum, key,
  policy, jurisdiction, device, expiry, and consequence scope.
- `issuer_boundary`: what must be true before a receipt may be minted.
- `receipt_requirement`: fields and predicates the downstream verifier checks.
- `downstream_refusal`: negative cases that must refuse before effect.
- `learning_boundary`: which observations may update maps/tests only after
  review.
- `claim_boundary`: what this lane still does not prove.

## Minimum Negative Cases

For an effectful lane, preserve explicit refusal cases for:

- missing receipt
- malformed or invalid receipt
- unknown issuer
- retired or unrecognized issuer
- wrong domain
- wrong action
- wrong target
- wrong policy
- stale or expired receipt
- revoked receipt
- consumed or replayed receipt
- requested/effective action mismatch
- semantic laundering
- human proxy bypass
- authority-material supplied by the request stream
- valid but unrecognized receipt
- authentic but wrongfully issued receipt, when the issuer boundary is in scope

## Agent Passenger Lab Connection

`zlar agent-passenger-lab` is a local fixture harness for observing attempted
crossings. Its passenger outputs are traffic, not authority.

Use passenger observations to discover:

- missing action classes
- semantic disguises
- authority-laundering paths
- mis-issuance pressure
- duplicate refusal noise
- missing route-map tests

Do not use passenger observations to create authority, bypass evidence gates,
or raise public claims.

## Headlight

The next useful formal-methods bridge is not more vocabulary. It is boring
repeatability: every new effectful lane should carry the same chain, the same
negative cases, and the same claim boundary until the pattern becomes hard to
misread.
