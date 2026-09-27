# ZLAR Evidence Protocol v2 — DRAFT

**Status: UNSOUND — DO NOT FREEZE. Architecture candidate written 2026-08-17;
independently attacked 2026-08-17.**

The attack found no break in the architecture. It found two live defects in the
enforcement path — a boarding authority bound to a class of work rather than the
work itself, and a deliberation clock the producer controlled — which is the
specification doing its job as a measuring stick. Both are fixed in candidate
044; see the independent attack record of 2026-08-17 (kept in the private development history).

**The additions made in response have not themselves been attacked.** The
Authority Domain Definition role (§2.2) and the clock-independence predicate
(§4.2) were written by the attacker, not by the architect, and nobody reviews
their own architecture. They are the first thing Codex's next pass should hit;
§14 gate 2 names their vectors.

The predecessor at commit `77c4d58` was rejected because it let a producer award
itself evidentiary strength, compressed a typed evidence graph into two records,
and inverted existing Candidate 030 claim ceilings. This revision replaces that
architecture. It does not clear the verdict. Independent negative-vector attack,
two independent implementations, and the freeze gates in §14 still control.

Carried forward: exact-complete-signed-Boarding-Credential binding;
cryptographic domain separation between authority and effect; the
claimed-versus-proven clock distinction; and immutable statements with
preservation wrapping them externally.

This document remains architecture only. It defines roles, relationships,
verifier predicates, and claim ceilings. It does not define a schema, CDDL, wire
encoding, implementation, or conformance result.

Review: the adversarial review of this draft (kept in the private development history)
(SHA-256 `ece6353f26e8d49873913233d870b3128cc391ffd85a7ee72e7f11d826d80f80`).

Preserved rather than deleted, as a record of the error.

---

Drafted 2026-08-17. Explicitly supersedes ADR-007's construction direction for
v2 only; supersedes no published protocol. Frozen by nobody.

`governed-action-receipt-v1` remains the published format. This document does not
edit it.

---

## 0. Why v2 exists

Four defects in v1, all verified against the published text rather than reported:

1. **The signature covers only the payload.** §6 signs the payload in steps 1–6
   and assembles the envelope in step 7 — after signing. So `v`, `id`, `iat`,
   `type` and `prev` are unsigned. **`prev` is the chain link: the published
   chain is not integrity-protected.**
2. **`type` cannot separate anything**, being unsigned. Any multi-type envelope
   built on v1's construction would be relabellable.
3. **Nothing conforms to v1, including ZLAR.** `CONFORMANCE.md` cites a purported
   subsection 5.2 that does not exist; `lib/receipt.mjs` emits five payload fields
   the spec never defines; neither the shipped kit nor `bin/zlar-verify`
   implements the unknown-field rejection the spec mandates.
4. **v1 has no consequence statement at all.** It records a decision. Nothing in
   it says what the destination actually did.

### 0.1 ADR-007 is explicitly superseded for v2

ADR-007 remains accepted for the historical receipt v1 format. It is superseded
for v2 on five decisions: the custom JSON envelope, absence of protected
algorithm/type metadata, use of “the version IS the algorithm” to exclude a
protected algorithm assertion, prohibition of all extensions, and its forecast
that v2 would necessarily use composite ML-DSA-65+Ed25519.

v2 uses `COSE_Sign1` Signed Statements. The protocol version selects one fixed
mandatory algorithm profile, while protected `alg` redundantly asserts the
required algorithm; protected `alg`, `kid`, content type, and statement role MUST
match that profile. A mismatch is rejection, not negotiation. Callers cannot
negotiate, substitute, or downgrade the suite. Namespaced noncritical
information may be preserved only when it cannot change acceptance or strengthen
a claim. Unknown security-semantic roles, fields, algorithms, or predicates fail
closed.

ADR-007's sound objectives survive: sign opaque bytes, avoid verifier
recanonicalization, keep security semantics strict, and prohibit package-driven
algorithm negotiation. Existing v1 artifacts do not change. This scoped
supersession does not select the v2 algorithm suite and does not make the rest of
this UNSOUND draft accepted or frozen.

## 1. What this protocol claims, exactly

Not: *"this proves the world entered state X."*

**"Given the identified historical trust anchors and a named validation policy,
this package permits a verifier to derive separately: which authority was
recognized; the exact bounded grant G and Boarding Credential A; the conditions
of any human decision; what a named destination recognized, consumed, refused,
attempted, or reported in Effect Receipt B; what authoritative or independent
evidence establishes about the resulting state; the causal relationship between
authority and consequence; when each exact artifact provably existed; and
whether an uninterrupted preservation chain protected those facts before each
prior cryptographic generation ceased to be trustworthy."**

Narrower than the ambition. Supportable by existing standards machinery.

## 2. Canonical authority chain and signed-statement roles

### 2.1 The founder-confirmed chain controls

The canonical product language comes from the founder's private notes,
Vincent-confirmed 2026-07-17 and restated in `docs/FOUNDER-DECISIONS.md` (D1):

> **Recognized authority → bounded grant → boarding credential → destination
> recognition → effect receipt**

This is the role graph. It is not a five-field schema and it is not compressed
into two statements. Each arrow is a separately verifiable relationship, and
supporting decision, human-authority, attempt, consumption, refusal, outcome,
state, and preservation evidence attaches to the node or edge it actually
supports.

### 2.2 Canonical chain roles

| canonical role | representation and signer | verifier-checkable meaning | authority effect |
|---|---|---|---|
| **Authority Domain Definition D** | immutable Signed Statement constituting one named authority domain: its trust anchors, the mandate rules an authority in that domain may grant under, the deterministic comparator profile, any quorum/role predicates, and its own succession rule. Signed either by a key the named identity regime anchors directly, or under an exact predecessor D through that succession rule. | exact domain name and version, anchor set, mandate rules, comparator profile, quorum/role predicates, status, and succession lineage verify; the verifier reports which D version and which anchor it used | Constitutes the domain inside which Recognized Authority has meaning. It grants nothing itself and can never verify as G or A. A later D version cannot change the recognition result of any G bound to an earlier one. |
| **Recognized Authority** | a verifier-derived relationship between an identified human/institutional authority, its exact mandate and lineage, and one **exact** Authority Domain Definition D | identity and signature verification, mandate, scope, delegation, and status all verify, and the mandate is in scope under exact D's rules | Source of legitimate authority within that domain. A valid signature alone never establishes this role — and neither does an unbound or ambient statement of what the authority may grant. |
| **Bounded Grant G** | immutable Signed Statement issued by Recognized Authority or a grant issuer acting inside that exact mandate | exact authority representation, scope, ceilings, destination/action classes, validity, revocation/renewal, delegation lineage, and attenuation verify | Authorizes no more than its bounds and may authorize derivation or issuance of Boarding Credentials. It is not by itself proof that any destination will recognize one. |
| **Boarding Credential A** | immutable, action- and destination-bound Signed Statement issued under exact G | exact G, principal, destination, operation or allocated item, limits, validity, idempotency/replay scope, and all required decision/human evidence verify | The only artifact presented as boardable authority at the destination. It is consumable, expiring, and no broader than G. |
| **Destination Recognition** | immutable decision statement from the destination-owned recognition boundary | exact A and the exact formed operation/attempt satisfy—or fail—the destination's independently named recognition rule | `RECOGNIZED` permits the destination crossing to continue inside A's bounds. `REFUSED` stops that named path. Recognition creates no new authority and proves no effect. |
| **Effect Receipt B** | immutable destination-signed statement carrying the SCITT Agent Action Capsule `Effect Record` semantics and any bound proof references | exact operation, attempt, effect boundary, producer claim, and qualifying proof objects verify; any G, A, Destination Recognition, or Consumption Record it claims to rely on is bound exactly, but defects in those artifacts do not invalidate an otherwise valid report of an unauthorized effect | Portable evidence of what the destination accepted or reported and which authority path it claimed to use. Never authority; never proof of wisdom, legality, complete enforcement coverage, or real-world state beyond the derived predicates. |

The names **Bounded Grant**, **Boarding Credential**, **Destination
Recognition**, and **Effect Receipt** are canonical ZLAR architecture terms.
`G`, `A`, and `B` are compact artifact labels only.

**D is not a sixth stage.** The founder-confirmed chain in §2.1 is unchanged and
still begins at Recognized Authority. D is not prior to that stage; it is what
makes that stage verifier-checkable instead of ambient. Before D, every security
edge in this architecture bound exact signed bytes while the definition of the
first vertex's powers remained ordinary text — so the one input nothing could
check was the one that decided what everything else was allowed to authorize.

The attack that requires it: the artifact stating what a Recognized Authority may
grant was unsigned, unversioned and unbound. Edit it, and a signer who was out of
scope becomes in scope — retroactively, across every historical package, with
every signature still verifying and no verifier able to detect the change. For
ZLAR specifically that was the wrong place to be soft. The claim is that human
authority is structural; if the document defining the founder's mandate is the
one unsigned input, the top of the chain is its weakest link.

**What D does not do is remove the need to trust something.** §10 still holds:
at least one anchor is irreducible, and a forger can construct an internally
consistent fake root. D changes what kind of thing sits at the top. An ambient
document can be edited silently and rewrites history. An exact, versioned,
bound artifact cannot: replacing it is visible, and every G stays bound to the D
that was actually in force when it was issued — the same rule §6.1 already
applies to every other artifact in the graph.

### 2.3 Supporting statement roles

| supporting role | establishes when verified | authority effect |
|---|---|---|
| **Action Proposal** | the exact action proposed by an agent, runtime, or other principal | None. Intelligence may propose. |
| **Authorization Envelope** | the canonical operation subject, authority request, destination, constraints, data/resource class, limits, and expiry presented for decision | None. It is the subject of decision and grant, not authority by possession. |
| **Decision / Permit** | SCITT Permit `decision: allow`, `deny`, or `challenge` for the exact Authorization Envelope under exact policy | Evidence of a decision only. `allow` may permit issuance of G; it is not G or A. |
| **Human Review Attempt** | one exact challenged Decision/Permit and operation/context package was presented to one named human authority at a named boundary, with pre-decision profile/state and clock evidence | None. It starts a review attempt; it does not prove delivery, comprehension, response, or approval beyond the stated boundary. |
| **Human Decision Record** | the exact Human Review Attempt, response, identity/authority lineage, and evidence inputs used by the named human-authority profile | Evidence only. It may satisfy a predicate for G issuance; a producer's `approved` label is insufficient. |
| **Destination Attempt** | one presentation or crossing attempt, the exact presented bytes or commitment, and one unique `attempt_id` | None. Correlation evidence, not permission. |
| **Consumption Record** | the exact G allocation and A were atomically debited or claimed in one exact replay domain for one Destination Attempt | Spends existing bounded authority; cannot create or widen it. |
| **Refusal Receipt** | the named destination boundary deliberately refused a formed attempt before its defined effect | Evidence of refusal at that boundary, not global prevention or absence of a side door. |
| **Outcome** | later confirmation, correction, reversal, compensation, dispute, or aggregate result | Evidence only. Appends history and never rewrites an earlier statement. |

A dispatch-specific **Closure Record** may bind the exact authorized bytes,
bytes dispatched, provider response, and bytes returned to a client. It proves
request/response closure at that boundary only; it is not an Effect Receipt or
proof of commit or settlement.

### 2.4 The graph

```text
Action Proposal ──> Authorization Envelope ──> Decision / Permit
                                                │
Recognized Authority ───────────────────────────┤
                                                ├─ challenge ─> Human Review Attempt
                                                │                ├─ no valid response
                                                │                │      └─ pending; no G or A
                                                │                └─ Human Decision Record
                                                │                     ├─ reject/deny ─> no G or A
                                                │                     └─ accepted ─────┐
                                                ├─ deny ─────────────> no G or A       │
                                                └─ allow ──────────────────────────────┤
                                                                                      v
Recognized Authority ──> Bounded Grant G ──> Boarding Credential A
                                                   │
                                                   v
Destination Attempt                    # may present A, no A, or malformed bytes
  ├─ formation predicate fails ───────> INCOMPLETE; no operation formed,
  │                                      nothing refused, no G/A consumed
  └─ operation formed ────────────────> Destination Recognition
       ├─ refused ────────────────────> Refusal Receipt
       └─ recognized ─────────────────> Consumption Record
                                            └─ Effect Receipt B [0..n]
                                                 └─ Outcome [0..n]

Independent verifier ──checks exact G/A/B bytes──> verification results only
                                                    # never recognition

Any later Outcome ──exact signed-artifact reference──> statement it corrects,
                                                       reverses, compensates,
                                                       disputes, or aggregates
```

An attempt after `deny`, during `challenge`, without A, with invalid A, or after
a destination refusal remains expressible. If an effect nevertheless occurs,
the verifier preserves the Effect Receipt or other effect evidence and reports
the governance violation; it MUST NOT reject or hide a consequence because its
path was unauthorized.

Every security-semantic edge in the graph is an exact signed-artifact reference.
`operation_id`, `action_id`, `decision_id`, `attempt_id`, `effect_id`, and
business `intent_id` are correlation values. None substitutes for an artifact
reference.

### 2.5 Verification, authority recognition, and destination recognition differ

The founder rule is exact: **“A signature may verify correctly. Verification
alone is not recognition.”**

The producer signs what it claims and the evidence it binds. The verifier checks
the artifact and derives only the results supported by the named validation
policy. The destination-owned recognition boundary decides whether exact A can
board. None of those roles may speak for either of the others.

1. **Statement verification** checks exact bytes, protected role/type/profile,
   signature, credential history, and internal bindings. It establishes what an
   identified signer signed under a named validation policy.
2. **Authority recognition** decides whether that signer held the in-scope human
   or institutional mandate required to issue G. Signature validity is only one
   input.
3. **Destination Recognition** is the destination-owned decision whether exact A
   counts for this exact attempted crossing under its own recognition rule. A
   third-party verifier cannot make that operational decision for the
   destination.
4. **Effect verification** checks Effect Receipt B and its proof objects after
   the boundary. It does not retroactively create authority or recognition.

A SCITT **Receipt** remains transparency-registration evidence; a Signed
Statement plus that SCITT Receipt is a Transparent Statement. A ZLAR **Effect
Receipt** is the canonical destination evidence role above. The qualified terms
MUST NOT be collapsed: registering B does not prove B's claimed effect, and
verifying B does not mean the destination recognized its issuer or enforced all
paths.

Decision/Permit, human records, Destination Attempts, Consumption Records,
Refusal Receipts, Effect Receipts, Outcomes, SCITT Receipts, timestamps, and
preservation evidence are evidence. G is bounded source authority; A is its
boardable instantiation. No evidence artifact can be relabelled as G or A.

D is neither. It is the frame both are read in: it grants nothing, proves
nothing, and carries no consequence, yet no recognition result means anything
without naming the exact one in force. A verifier that reports `RECOGNIZED`
without reporting which D it recognized against has answered a different
question than the one asked.

This is the North Star rule in protocol form: **evidence is never authority.**

## 3. Operation, attempt, and effect model

### 3.1 Stable operation; unique attempts; explicit effects

An **operation** is the exact semantic subject of authority: action type,
principal and delegation, destination, resource, parameters, maximum effect,
policy namespace, preconditions, deadline, and idempotency scope. A stable
`operation_id` may correlate retries and destination legs, but the signed
operation bytes or their version-fixed digest are the security binding.

An **attempt** is one presentation of an operation to a decision or destination
boundary. Every attempt has a unique `attempt_id`. A retry is a new attempt, not a
rewrite or replay of the prior record. It identifies `retry_of`, carries the same
or explicitly revised operation subject, and preserves the idempotency scope.

An **effect** is one consequence at one named boundary. One attempt may produce
zero, one, or many Effect Receipts B, each carrying an Agent Action Capsule
`Effect Record`. Each effect identifies its exact subject, ordinal or leg,
destination, irreversibility class, and effect boundary. A single successful
member never proves completion of a batch or multi-effect operation.

### 3.2 Formation precedes refusal

The destination profile defines a deterministic formation predicate. If the
presented candidate does not constitute a recognizable operation, the verifier
may derive `INCOMPLETE` only by applying that predicate to the exact candidate
bytes or by verifying a trusted destination-formation statement that binds those
bytes. `INCOMPLETE` means **not an operation**. It is not `deny`, `refuse`,
`failed`, or `no effect`.

Cyan's Tier 3 wallet is the reference meaning: half a transaction is not a
transaction, so nothing exists for the wallet to refuse and no authority is
consumed.

### 3.3 Attempt completeness without invented outcomes

The refusal-event correlation pattern is retained: one attempt has at most one
primary terminal Outcome for the same semantic layer. Multiple Effect Receipts
and effect-specific Outcomes may sit beneath it. A later correction, reversal,
compensation, or dispute is a new Outcome that exactly links to the statement it
qualifies; it is not a second sibling terminal result. An attempt with no
primary terminal Outcome is open or incomplete evidence; it is never silently
converted to success, failure, refusal, or no effect. Two incompatible primary
terminal Outcomes for one attempt produce a conflict finding, not winner
selection.

### 3.4 Claimed facts and established facts

A producer MAY sign `claimed_effect_status`, `claimed_event_time`, and, if useful
for migration, `claimed_evidence_basis`. Those fields preserve what the producer
said. They have no power to award a verifier result.

The verifier independently derives statement verification, authority
recognition, decision, human-authority, bounded-grant, Boarding Credential,
formation, Destination Recognition, consumption, effect, attestation,
causal-binding, and governance-relation results from verified statement roles,
exact links, proof objects, identity and independence predicates, and state
deltas. A producer claim that exceeds the derived result is an overclaim finding.

### 3.5 Two clocks and causal order

`claimed_event_time` is inside the actor statement. `proven_existence_time` is a
verifier result derived from independently trusted timestamp, transparency, or
preservation evidence and states only that the exact bytes existed no later than
that time.

The verifier separately reports its `validation_as_of` time, the cutoff of the
credential/status evidence it used, and whether the named validation policy
considers that evidence fresh enough. Historical validity as of a proved cutoff
must never be rendered as present validity after the cutoff.

Neither clock by itself proves governance-before-effect. That relation requires
structural evidence that the destination recognized and consumed exact A before,
or atomically with, constructing the effect or authoritative commit. A-before-B
signature order without that coupling is `ORDER_ONLY`, never governed causation.

## 4. Total verifier-derived compatibility matrix

### 4.1 Independent result dimensions

The verifier MUST emit each dimension separately. It MUST NOT collapse the graph
to `valid: true` or copy a producer's label into its result.

Results are scoped. The verifier derives them per decision chain, authorization,
attempt, effect, operation leg, or aggregate, as applicable. A package report is
a keyed collection of scoped results, not one global lifecycle scalar.

| dimension | closed architecture results |
|---|---|
| `statement_verification_result` | `UNPROVEN`, `SIGNATURE_VALID_ONLY`, `PROFILE_VALID`, `INVALID`, `CONFLICTED` |
| `authority_domain_result` | `UNPROVEN`, `UNBOUND`, `INVALID`, `VALID`, `CONFLICTED`; `UNBOUND` is the affirmative result that G references no D at all, and is distinct from `UNPROVEN` |
| `authority_recognition_result` | `UNPROVEN`, `UNRECOGNIZED`, `RECOGNIZED`, `CONFLICTED` |
| `decision_result` | `UNPROVEN`, `PENDING`, `DENIED`, `ALLOWED`, `CONFLICTED` |
| `human_authority_result` | `NOT_APPLICABLE`, `UNPROVEN`, `PENDING`, `DENIED`, `APPROVAL_REJECTED`, `APPROVAL_ACCEPTED`, `APPROVAL_ACCEPTED_WITH_SIGNALS`, `CONFLICTED` |
| `human_deliberation_result` | `NOT_APPLICABLE`, `UNPROVEN`, `FLOOR_MET`, `BELOW_FLOOR_SIGNAL`, `BELOW_FLOOR_REJECT`, `CONFLICTED` |
| `human_daily_load_result` | `NOT_APPLICABLE`, `UNPROVEN`, `WITHIN_PROFILE`, `DAILY_CAP_SIGNAL`, `CONFLICTED` |
| `human_pending_load_result` | `NOT_APPLICABLE`, `UNPROVEN`, `WITHIN_PROFILE`, `PENDING_CAPACITY_SIGNAL`, `CONFLICTED` |
| `human_variance_result` | `NOT_APPLICABLE`, `UNPROVEN`, `INSUFFICIENT_SAMPLE`, `WITHIN_PROFILE`, `ALERT(tier, acknowledgement_result)`, `CONFLICTED`; `tier` comes from the exact profile's bounded domain |
| `human_authenticity_result` | `NOT_APPLICABLE`, `UNPROVEN`, `PROFILE_PASSED`, `BELOW_PROFILE_FLOOR`, `BELOW_ABSOLUTE_FLOOR`, `CONFLICTED` |
| `bounded_grant_result` | `UNPROVEN`, `NOT_ISSUED`, `VALID`, `NOT_YET_VALID`, `EXPIRED`, `REVOKED`, `EXHAUSTED`, `INVALID`, `CONFLICTED` |
| `boarding_credential_result` | `UNPROVEN`, `NOT_ISSUED`, `VALID`, `NOT_YET_VALID`, `EXPIRED`, `REVOKED`, `INVALID`, `CONFLICTED` |
| `formation_result` | `UNPROVEN`, `INCOMPLETE`, `FORMED`, `CONFLICTED` |
| `destination_recognition_result` | `UNPROVEN`, `REFUSED`, `RECOGNIZED`, `CONFLICTED` |
| `consumption_result` | `NOT_APPLICABLE`, `UNPROVEN`, `CONSUMED`, `OVERCONSUMED`, `CONFLICTED` |
| `effect_result` | `UNPROVEN`, `NONE_PROVED`, `DISPATCHED_UNCONFIRMED`, `CONFIRMED`, `COMMITTED`, `SETTLED`, `FAILED_STATE_KNOWN`, `FAILED_STATE_UNKNOWN`, `PARTIAL`, `REVERSED`, `COMPENSATED`, `CONFLICTED` |
| `derived_attestations` | a set containing zero or more of `SIGNED_CLAIM_ONLY`, `DESTINATION_BOUNDARY_ATTESTED`, `AUTHORITATIVE_STATE_NO_CHANGE_PROVED`, `AUTHORITATIVE_STATE_COMMIT_PROVED`, `CONSENSUS_LEDGER_COMMIT_PROVED`, `INDEPENDENT_OBSERVATION_PROVED`, `DOMAIN_SETTLEMENT_PROVED`; the empty set means none established |
| `causal_binding_result` | `UNPROVEN`, `ORDER_ONLY`, `PROVED_BY_CONSTRUCTION` |

`UNPROVEN` is the default scalar result when required evidence is absent; the
derived-attestation set defaults to empty. Absence of an event record does not
prove the event did not occur. `NONE_PROVED` requires affirmative evidence that
the named effect boundary did not change, not an empty log.

`SIGNATURE_VALID_ONLY` and `PROFILE_VALID` are verification results. Neither
establishes `authority_recognition_result=RECOGNIZED`,
`destination_recognition_result=RECOGNIZED`, or any effect. Verification never
grades itself into recognition.

Negative and latest-state results also require a completeness predicate. A
verifier may derive `PENDING` or `DENIED` as the current decision only against a
verified complete decision lineage or checkpoint for the named decision scope.
It may derive `NOT_ISSUED` for G or A only from an affirmative non-issuance
predicate under that same scope. Otherwise the result is `UNPROVEN`, even if no
G or A is present in the package.

For a challenged decision, the decision chain derives `ALLOWED` only from an
accepted Human Decision Record and `DENIED` only from a valid human denial. An
unresolved challenge remains `PENDING`. `bounded_grant_result=VALID` additionally
requires Recognized Authority and the resolved decision/human chain.
`boarding_credential_result=VALID` additionally requires exact A to bind exact G
and the allocated operation/destination scope. An approval that is rejected,
conflicted, or unproved cannot produce valid G or A even if an issuer signed
bytes labelled as one.

The remaining non-effect results exist only under these base predicates:

| result family | minimum verifier-checkable predicate |
|---|---|
| Statement verification | exact immutable bytes, protected role/type/profile, signature, signer credential history, internal exact-artifact bindings, and validation time verify; this produces no recognition result |
| Authority domain | exact immutable D bytes, domain name and version, anchor set, mandate rules, comparator profile, quorum/role predicates, status, and succession lineage back to an anchored or predecessor-issued D all verify; the verifier reports the exact D version and the anchor it used |
| Authority recognition | `authority_domain_result=VALID` for the exact D that G binds, **plus** exact human/institutional identity, mandate, scope, status, lineage, and any quorum/role predicate evaluated against that D's rules, together establish that the signer was recognized to issue G. An identity proved against no bound D is `UNPROVEN`, never `RECOGNIZED` |
| Decision / Permit | valid Decision/Permit role, evaluator identity, exact Authorization Envelope binding, decision value, governing policy/profile, and the completeness rule above |
| Bounded Grant G | valid G role and construction, Recognized Authority, exact Decision/Human Decision links when required, authority representation, ceilings, validity/status, delegation lineage and attenuation, and validation at the reported time |
| Boarding Credential A | valid A role and construction, exact valid G, issuer authority under G, operation/item/principal/destination/limits/validity binding, and no-wider attenuation from G |
| Formation | deterministic profile predicate applied to the exact presented candidate bytes, or a trusted formation statement binding those bytes |
| Destination Recognition | valid destination-owned recognition statement binding the exact Destination Attempt, formed operation, exact A if presented, recognition profile, and recognized/refused result; verification of A alone is insufficient |
| Consumption | verified atomic debit/claim transition for the exact G allocation and A, Destination Attempt, consumption authority, and replay scope; `OVERCONSUMED` is derived over the verified consumption set, not from one producer label |
| Causal binding | `ORDER_ONLY` requires verified ordering evidence; `PROVED_BY_CONSTRUCTION` requires the structural coupling in §6.4; missing coupling is `UNPROVEN` |
| Conflict | two or more otherwise valid statements satisfy the same exclusive role/scope while asserting mutually exclusive results; an invalid statement cannot create a conflict with a valid one |

A D that supersedes an earlier version changes nothing about statements already
bound to the earlier one. The verifier evaluates each G against the exact D that
G binds, reports both the bound version and the current one, and derives
`CONFLICTED` when two otherwise valid D statements claim the same domain and
version while asserting different rules. Retroactive widening is therefore not
expressible: a later D cannot promote an out-of-scope historical signer, and an
attempt to do so surfaces as a version divergence rather than a silent change.

`NOT_APPLICABLE` also requires a positive profile predicate. It is never a synonym
for missing evidence.

### 4.2 Verifier-checkable human-authority predicates

A Human Decision Record binds the exact Human Review Attempt; that Attempt binds
the exact challenged Permit, operation/context shown for review, named human
authority, review boundary, active constitution/policy/profile, and pre-decision
evidence inputs. The Decision Record adds the exact response and response-side
evidence. Neither contains a self-authenticating Boolean called “human.”

| component | verifier-checkable predicate | claim ceiling |
|---|---|---|
| Decision identity and authority | authenticate the response under the named human identity and decision-channel trust profile; verify that authority's exact scope and lineage; bind it to the exact still-pending Human Review Attempt and operation | Attributable, in-scope response under that profile; never metaphysical proof of personhood or comprehension. |
| H15 elapsed versus floor | derive the applicable floor from the exact signed policy/profile; derive elapsed from exact linked request-dispatch and response-acceptance evidence in one trusted clock domain **independent of the producer**; recompute the comparison | Signed `h15_elapsed_seconds`, `h15_floor_seconds`, or `h15_below_floor` values alone establish only a producer claim and arithmetic consistency. |
| H6 decision load | verify a protected state snapshot or evaluator statement binding the human, risk-weighted daily total, cap, reset domain, and decision point; recompute total versus cap | Capacity condition at that decision point, not future capacity or quality of judgment. |
| H13 pending load | verify the exact pending-set snapshot, TTL/profile, retry-dedup key, and transition for this request; recompute live members and load versus cap | Queue condition at the named review boundary, not proof the human read every pending item. |
| H14 variance tier | verify or recompute the profile-selected window, exclusions, minimum sample, variance statistic, threshold, prior tier, resulting tier, and any exact acknowledgement artifact | Deterministic variance signal and acknowledgement state; not a trust score or proof of rubber-stamping. |
| H17 authenticity floor | derive the applicable absolute/profile floor from the exact signed profile and authorized lane/calibration inputs; compare it with elapsed proved under the independence predicate below | `PROFILE_PASSED` means only that the deterministic timing predicate passed against an independently witnessed interval. It never proves the responder was human. |

**Clock independence.** H15 and H17 are the only human-authority predicates that
can reject an approval, and both are elapsed-time comparisons. If the clock
bounding that interval belongs to the producer, both reduce to self-attestation:
a compromised or merely buggy gate can claim any interval it likes, every
signature still verifies, and the one condition ZLAR exists to protect — that a
human actually deliberated — becomes invisible to every verifier forever.

So the response side of the reviewed interval MUST be witnessed in a clock domain
the producer does not control, bound inside the same signature as the response it
times. §4.3 already demands independence predicates for effect attestations; the
predicate that decides whether a human authorization is real cannot be held to a
weaker standard than the one that decides whether a payment settled.

Where only a producer-controlled clock is available, the verifier derives
`human_authenticity_result=UNPROVEN` and, for any profile class that makes H15
blocking, `human_deliberation_result=UNPROVEN`. Neither may be graded to a
passing result, and an absent witnessed time is never backfilled from the
producer's own.

The witness needs to be no larger than the claim. A channel that timestamps its
own delivery is sufficient; it attests elapsed time, not identity, authority, or
comprehension, and it must not be promoted into an anchor for any of those.

The evaluator derives `APPROVAL_REJECTED` when an approval violates a
profile-defined hard predicate, including the active H17 floor and any H15 class
that the profile makes blocking. A rejected approval cannot permit G or A.
`APPROVAL_ACCEPTED` requires every profile-required component to be proved, all
blocking predicates to pass, and no advisory signal. Profile-defined advisory
H6/H13/H14 findings, and a nonblocking H15 finding, derive
`APPROVAL_ACCEPTED_WITH_SIGNALS` only if every required input is proved and all
blocking predicates pass. A missing required input derives `UNPROVEN`, not a
weaker acceptance. Signals remain visible and cannot be rewritten as clean
approval. A denial stands as `DENIED`; timing anomalies on a denial are recorded
but cannot turn it into approval.

`NOT_APPLICABLE` is valid only when the governing Permit path did not require a
human decision, such as a policy-authorized operation inside already bounded
standing authority. It cannot be selected merely because human evidence is
missing.

The current implementation's exact advisory-versus-blocking behavior is source
truth for migration, not a universal semantic: H6, H13, and H14 are advisory;
H17 rejects approvals; H15 rejects below-floor critical approvals but records
warn/info violations as signals; denial stands. A future profile may change
those mechanics only by naming and binding a new version. Fast, guarded, or slow
lane selection must come from exact authority and profile evidence, never from a
producer's self-selected trust label.

### 4.3 Verifier-checkable effect predicates

Every reportable effect result has a predicate. If the predicate does not verify,
the result does not exist.

| derived `effect_result` | minimum verifier-checkable predicate | forbidden inference |
|---|---|---|
| `NONE_PROVED` | authoritative no-change proof for the exact effect subject and boundary over the relevant attempt interval | No global absence or side-door closure. |
| `DISPATCHED_UNCONFIRMED` | exact authorized/request bytes are bound to bytes emitted at the named dispatch boundary; no result proof is present | Not executed, committed, or settled. |
| `CONFIRMED` | the named boundary observed and bound the exact response or resulting state for the effect subject | Observation does not prove causation or durable commit. |
| `COMMITTED` | the exact operation item, Destination Attempt, and effect are inside or cryptographically coupled to the authoritative state transition; commit identity and before/after state verify under the named profile; any claimed G/A/recognition/consumption path is bound but evaluated independently | An application log or actor assertion never qualifies. Missing or invalid authority changes the governance relation, not the truth of a proved commit. |
| `SETTLED` | `COMMITTED` plus domain finality evidence satisfying a named settlement/finality profile | Consensus inclusion alone is not settlement unless the domain profile says so. |
| `FAILED_STATE_KNOWN` | a failure record plus affirmative proof of the exact resulting state, including whether any defined effect occurred | A thrown exception alone cannot establish known state. |
| `FAILED_STATE_UNKNOWN` | dispatch or execution activity is established and the terminal state cannot be established | Must not be rendered as no effect. |
| `PARTIAL` | a commitment identifies the complete expected-effect member set and proves at least one established member plus at least one failed, absent, or unresolved member | No whole-operation completion. |
| `REVERSED` | a new Outcome binds the prior committed effect and proves an authoritative state transition that undoes it under the domain profile | The original effect remains historical fact. |
| `COMPENSATED` | a new effect binds the prior effect and proves the compensating transition; its authority path is evaluated independently | Compensation is not erasure or reversal unless the domain profile proves equivalence. |
| `CONFLICTED` | two or more otherwise valid statements make mutually exclusive claims for the same role, attempt, effect, or consumption | The verifier must not choose the stronger or later claim. |

### 4.4 Attestation compatibility

The `derived_attestations` set is verifier output. Multiple independently valid
attestations may coexist; none displaces another. A producer's
`claimed_evidence_basis` does not enter this table.

| derived attestation | what the verifier must establish | maximum claim it can support by itself |
|---|---|---|
| `SIGNED_CLAIM_ONLY` | valid actor signature and role; no qualifying corroborating proof | Only “the identified actor claimed X.” `effect_result` remains `UNPROVEN` unless another predicate verifies. |
| `DESTINATION_BOUNDARY_ATTESTED` | recognized boundary identity, accepted attestation evidence, and exact binding to the attempt/effect bytes | receipt, dispatch, response observation, or failure at that named boundary; never authoritative commit or settlement by label alone |
| `AUTHORITATIVE_STATE_NO_CHANGE_PROVED` | verifier-recognized authoritative state system plus exact subject/boundary binding and an affirmative no-change proof over the attempt interval | `NONE_PROVED` or the no-change branch of `FAILED_STATE_KNOWN`; never global absence |
| `AUTHORITATIVE_STATE_COMMIT_PROVED` | verifier-recognized authoritative state system plus exact commit coupling and valid before/after transition | `COMMITTED`, the changed-state branch of `FAILED_STATE_KNOWN`, or `REVERSED`, as the state predicate warrants |
| `CONSENSUS_LEDGER_COMMIT_PROVED` | valid inclusion/finality proof under the named ledger validation profile and exact effect binding | ledger commit; `SETTLED` only under an explicit domain settlement profile |
| `INDEPENDENT_OBSERVATION_PROVED` | observer identity plus defined independence from destination control, keys, administration, and failure domain; exact observation binding | observed resulting state; never causation, authorization, consumption, or commit by observation alone |
| `DOMAIN_SETTLEMENT_PROVED` | valid domain settlement artifact, recognized issuer/system, exact effect binding, and finality predicate | `SETTLED` within that named domain and no broader |

Unknown attestation types are informational and never grade up. Behavioral trust,
risk, model confidence, reputation, or anomaly scores may be preserved as
advisory evidence. They are never authorization, recognition, consumption, or an
effect predicate.

### 4.5 Total effect/attestation compatibility matrix

After both sides are independently derived, the verifier applies this table. A
pair absent from the table is incompatible and cannot grade up. Additional valid
attestations remain reportable but cannot compensate for a missing minimum
predicate.

If a candidate effect result lacks the minimum compatible proof, that result is
not derived. The verifier records the failed predicate and evaluates any other
applicable result, defaulting to `UNPROVEN`; it never copies the claimed result.

| `effect_result` | minimum compatible derived attestation or proof set |
|---|---|
| `UNPROVEN` | no minimum; all established attestations remain separately visible |
| `NONE_PROVED` | `AUTHORITATIVE_STATE_NO_CHANGE_PROVED` |
| `DISPATCHED_UNCONFIRMED` | `DESTINATION_BOUNDARY_ATTESTED` at the dispatch boundary |
| `CONFIRMED` | `DESTINATION_BOUNDARY_ATTESTED` or `INDEPENDENT_OBSERVATION_PROVED`, with the exact result/state binding |
| `COMMITTED` | `AUTHORITATIVE_STATE_COMMIT_PROVED` or `CONSENSUS_LEDGER_COMMIT_PROVED` under the named commit profile |
| `SETTLED` | `DOMAIN_SETTLEMENT_PROVED`; any ledger evidence must also satisfy the named domain finality predicate |
| `FAILED_STATE_KNOWN` | failure-boundary attestation plus `AUTHORITATIVE_STATE_NO_CHANGE_PROVED` or `AUTHORITATIVE_STATE_COMMIT_PROVED`, according to the resulting state |
| `FAILED_STATE_UNKNOWN` | `DESTINATION_BOUNDARY_ATTESTED` proving activity/failure while terminal state evidence remains absent |
| `PARTIAL` | a commitment to the complete expected-member set in which every member has its own result and at least one member is established while another is failed or unresolved |
| `REVERSED` | the attestation required by the named reversal profile, normally `AUTHORITATIVE_STATE_COMMIT_PROVED` or `DOMAIN_SETTLEMENT_PROVED`, plus the exact prior-effect link |
| `COMPENSATED` | the compatible proof for the new compensating effect plus its exact prior-effect link; any new G/A is evaluated in the separate authority and governance-relation dimensions |
| `CONFLICTED` | two otherwise valid incompatible statements; no attestation selection resolves the conflict |

### 4.6 Total governance-relation classifier

After deriving the dimensions above, the verifier applies this table in order
for each attempt, effect, leg, and aggregate scope. The first matching row is
that scope's single `governance_relation`. This makes the classifier total
without pretending the lifecycle itself is one scalar stage.

“Consequence activity” below means any established dispatch, effect, failure
with activity, partial, reversal, compensation, commit, or settlement.

| priority | condition | `governance_relation` |
|---:|---|---|
| 1 | package/profile ambiguity, canonicalization failure, or broken mandatory graph framing prevents any safe interpretation | `INVALID_EVIDENCE` |
| 2 | any result dimension is `CONFLICTED`, including incompatible terminal Outcomes or mutually exclusive consumption state | `CONFLICTED_EVIDENCE` |
| 3 | a verified consumption set exceeds G/A's item, allocation, quantity, budget, or use cardinality in its named replay scope | `AUTHORITY_OVERCONSUMED` |
| 4 | consequence activity is established for an `INCOMPLETE` candidate | `CONSEQUENCE_AFTER_UNFORMED_INPUT` |
| 5 | consequence activity is established while Recognized Authority, valid G, or valid A is absent for the exact operation, including because a decision or human prerequisite is pending, denied, rejected, or unproved | `CONSEQUENCE_WITHOUT_VALID_AUTHORITY` |
| 6 | consequence activity is established and destination recognition is not `RECOGNIZED` | `CONSEQUENCE_WITHOUT_DESTINATION_RECOGNITION` |
| 7 | consequence activity is established and exact consumption is not `CONSUMED` | `CONSEQUENCE_WITHOUT_PROVED_CONSUMPTION` |
| 8 | Recognized Authority, valid exact G/A, formed operation, Destination Recognition, consumption, a §4.5-compatible Effect Receipt/attestation pair, and `PROVED_BY_CONSTRUCTION` all verify | `GOVERNED_CONSEQUENCE_ESTABLISHED` |
| 9 | the same effect is established but causal binding is `ORDER_ONLY` or `UNPROVEN` | `CONSEQUENCE_ESTABLISHED_GOVERNANCE_CAUSATION_UNPROVEN` |
| 10 | exact A is recognized and consumed but `effect_result` is `UNPROVEN` | `AUTHORIZATION_CONSUMED_CONSEQUENCE_UNOBSERVED` |
| 11 | latest Decision/Permit is `PENDING`; no later valid allow/deny supersedes it | `PENDING_NO_AUTHORITY` |
| 12 | latest Decision/Permit is `DENIED`; no valid G or A exists from that decision | `DENIED_NO_AUTHORITY` |
| 13 | human authority is `APPROVAL_REJECTED`; no valid G/A or consequence activity exists | `HUMAN_APPROVAL_REJECTED_NO_AUTHORITY` |
| 14 | formation is `INCOMPLETE` and no consequence activity is established | `INCOMPLETE_NO_OPERATION` |
| 15 | a valid Refusal Receipt exists at the named destination boundary and no consequence activity is established | `REFUSED_AT_NAMED_BOUNDARY` |
| 16 | exact G/A is valid but no governed consequence is established | `BOARDING_CREDENTIAL_VALID_NO_EFFECT_ESTABLISHED` |
| 17 | no prior row matches | `UNPROVEN` |

An established unauthorized consequence is evidence of a governance failure, not
invalid evidence. A refusal plus observer silence is only
`REFUSED_AT_NAMED_BOUNDARY`; it is never silently promoted to prevention.
Invalid individual statements produce findings and contribute no predicate;
they do not erase an independently established consequence. This is why an
invalid A plus a valid authoritative Effect Receipt reaches priority 5 rather
than hiding behind `INVALID_EVIDENCE`.

## 5. Candidate invariants and explicit trade-offs

Nothing in this section is frozen while the document remains UNSOUND.

1. **All security-semantic actor fields are signed.** SCITT Receipts,
   transparency proofs, timestamps, and preservation evidence may attach outside
   the actor signature but cannot change actor-statement semantics.
2. **Authority roles stay distinct.** Recognized Authority is a verified source
   relationship; G is the bounded grant; A is the only boardable artifact.
   Decisions/Permits, human records, SCITT Receipts, Effect Receipts, Refusal
   Receipts, Consumption Records, and Outcomes are evidence and can never verify
   as G or A.
3. **Every security edge binds exact complete signed artifact bytes.** Semantic
   or business identifiers are supplemental correlation only.
4. **Grant, credential, and effect roles are domain-separated.** Cross-role
   replay fails cryptographically before semantic evaluation.
5. **Strength is derived, never declared.** Producer `claimed_*` fields preserve
   testimony; verifier results come only from predicates in §4.
6. **The lifecycle is multidimensional.** Statement verification, authority
   recognition, decision, human authority, bounded grant, boarding credential,
   formation, destination recognition, consumption, effect, attestation,
   causation, and governance relation remain separate results.
7. **Two clocks never collapse.** Claimed event time and proven existence time
   are both reported; neither substitutes for structural causal binding.
8. **Statements are immutable.** Corrections, reversals, compensations,
   disputes, aggregation, transparency, and preservation append new artifacts.
9. **One version selects one construction and binding digest suite.** COSE
   protected `alg`, `kid`, statement type, and content type must match that
   profile. Package-supplied algorithm negotiation is forbidden.
10. **Consumption claims name the actual serialization boundary.** No isolated
    package proves global uniqueness across partitions.
11. **Unknown semantics never grade up.** A profile may carry namespaced
    noncritical extensions, but unknown roles, proof types, critical fields, or
    predicates cannot affect acceptance or strengthen a claim.
12. **Behavioral trust scoring stays outside enforcement authority.** The DRP
    patterns for scope, boundaries, time windows, instruction commitments,
    parent linkage, attenuation, and revocation are useful. Its adaptive trust
    and risk scores are not authority.
13. **Human approval is derived, never Boolean.** A named human-authority profile
    determines which identity, deliberation, load, variance, authenticity, and
    acknowledgement predicates are blocking or advisory. A bare approval label,
    risk score, or trust lane cannot permit G or A.
14. **Authority defects never erase effect evidence.** Invalid, absent, denied,
    expired, revoked, or overconsumed G/A changes the governance relation. It
    cannot downgrade an independently proved commit, settlement, reversal, or
    compensation into an unproved effect.

15. **The domain's rules are an artifact, not a document.** Recognized Authority
    is established against one exact signed Authority Domain Definition that G
    binds. What an authority may grant is versioned and immutable like every
    other input, so changing it is visible and never retroactive. An irreducible
    external anchor remains (§10); this bounds what that anchor can silently
    become.

Rejected alternatives:

- **Producer-awarded `evidence_basis`:** recreates the original defect.
- **One scalar `stage`:** cannot express incomplete formation, open decisions,
  consumption without observation, partial effects, or later reversal honestly.
- **Two-statement-only event coverage:** loses Candidate 018's typed decision,
  consumption, effect, and refusal relationships.
- **Signature validity as recognition:** collapses cryptographic verification,
  authority recognition, and destination recognition into one unsafe Boolean.
- **An ambient mandate document:** binds every edge in the graph to exact bytes
  and leaves the powers of the top vertex as editable text, which is where a
  patient attacker would go first.
- **Generic “receipt” as a semantic role:** collapses SCITT registration evidence
  and ZLAR Effect Receipts, allowing one to overclaim as the other.
- **Treating every anomalous combination as invalid evidence:** hides real
  unauthorized consequences. The verifier must preserve the evidence and name
  the governance failure.
- **Behavioral trust or AI judgment in the enforcement path:** an attack surface
  disguised as governance.
- **A signed `approved: true`:** records a claim but cannot show that the human
  decision channel preserved the conditions for accountable judgment.

## 6. Binding and artifact identity

### 6.1 Exact complete signed G, A, and B

Every Destination Recognition, Consumption Record, Effect Receipt B, Refusal
Receipt, or Outcome that relies on Boarding Credential A commits to the exact
complete signed A artifact: the version-selected signed bytes, including
protected role and algorithm metadata and the signature. It never binds only
A's payload or a business identifier.

Every A commits to the exact complete signed Bounded Grant G from which it is
derived. Every Effect Receipt B additionally commits to the exact Destination
Recognition and Consumption Record on which its governed-path claim relies.
The role-specific graph edges therefore remain inspectable even when all three
artifacts carry the same business `operation_id`.

B always binds the exact credential bytes presented at its attempt, even when
those bytes fail to verify as A. If no credential was presented, B binds an
explicit signed absence rather than omitting the relationship ambiguously. A B
that claims a governed path MUST bind exact valid A; no identifier-only fallback
is permitted.

The architecture-level reference identifies the selected protocol/profile,
content type, exact byte length, and the one mandatory digest selected by that
version. This is not an algorithm-agile list. A transition to another binding
digest requires an explicit successor profile or version with deterministic
transition semantics.

Re-signing identical grant, credential, or effect semantics creates a new G, A,
or B respectively. That is correct. Every downstream statement remains bound to
the historical signed artifact it actually used.

### 6.2 The artifact hash is not the operation binding

Exact G identity answers **which bounded source grant**. Exact A identity answers
**which Boarding Credential was presented**. The signed operation subject
answers **which action, principal, destination, scope, item, quantity,
preconditions, and maximum effect**. All applicable bindings must verify. A
business `intent_id`, `operation_id`, or action label cannot substitute for any
of them.

G commits to the exact complete signed Authority Domain Definition D under which
its issuer was recognized, and to the exact complete signed allow Decision/Permit
on which issuance relies. When a challenge was resolved by a human, G additionally commits to the
exact complete Human Decision Record; that record commits to the exact Human
Review Attempt; and the Attempt commits to the exact challenge Decision/Permit.
A commits to exact G and the exact allocated operation item and destination. A
`deny`, unresolved `challenge`, rejected approval, or approval whose required
predicates are unproved cannot be transformed into G or A by relabelling or
omitting a reference.

### 6.3 Same-byte ingestion

The verifier reads each referenced G, A, B, or supporting artifact once from a
bounded immutable byte
source or pinned descriptor. Length check, digest, decode, role check, and
signature verification all operate on those same bytes. Path names, a second
read, or a parsed-and-reserialized form are not artifact identity.

This imports the `sha256_pinned` discipline into the protocol architecture:
symlinks, type changes, size overrun, identity change during read, and hash-one /
parse-another substitutions fail closed.

### 6.4 Causal enforcement binding

`HASH(exact G)` inside A proves only that exact G existed before A was signed.
`HASH(exact A)` inside B proves only that exact A existed before B was signed.
Neither hash proves that the issuer was recognized, that the destination
recognized A, that A preceded the effect, or that A participated in enforcement.

`PROVED_BY_CONSTRUCTION` requires evidence that exact valid G and A, the exact
formed operation item, Destination Recognition, and Consumption Record were
structurally coupled before, or atomically with, the destination's effect
construction or authoritative commit. Effect Receipt B must bind that coupling
and the resulting effect. Signed timestamps alone can prove at most
`ORDER_ONLY`. A package lacking structural coupling must report the effect and
the missing governance causation separately.

### 6.5 SCITT and delegation convergence

Use SCITT `Signed Statement`, `Receipt`, and `Transparent Statement`; Permit
`binding_request_hash` for authorized request bytes; Closure Record dispatch and
response digests for byte closure; Agent Action Capsule `Effect Record`,
`effect.status`, `effect_attestation`, `verdict_class`, `action_id`, and
`decision_id`, with `approver` and `human_disposed` retained as minimum human-
involvement facts rather than approval proof; and refusal-event `event-id` /
`attempt-id` correlation. The Agent Action Capsule Effect Record is content
carried by canonical Effect Receipt B; a SCITT Receipt may register B but cannot
replace it.

Delegated G and A use Permit terminology: **Authority Representation**,
**Comparator Profile**, **Authority Attenuation**, and **Authority Lineage**.
Every child G cryptographically identifies its parent G, commits to its own
authority representation, and proves it is no broader under the declared
deterministic comparator. Every A identifies exact G and is no broader than G.
Insufficient evidence yields attenuation `UNPROVEN`, never success.

## 7. Consumption, retries, batches, partials, and multiple destinations

### 7.1 The actual one-use boundary

One-use is a state property, not a signature property. G names the bounded
allocation or budget and its replay regime; A names the exact boardable item,
destination, consumption authority, and replay domain. `CONSUMED` requires a
verified atomic state transition for exact A and the applicable G item,
allocation, or debit for that attempt.

The truthful claim is **one-use at the named replay domain**. “One-use at a
destination” is still too broad when replicas, partitions, restored stores, or
multiple guards do not share one serialization boundary. An isolated package
cannot prove no conflicting consumption exists elsewhere; external checkpoints
or consensus may strengthen that result.

Two valid Consumption Records are not automatically conflicting evidence. If
their verified set exceeds G or A's cardinality, allocation, or budget inside
the declared replay scope, the verifier derives `OVERCONSUMED` and
`AUTHORITY_OVERCONSUMED`. Both statements remain valid evidence of the governance
failure.

### 7.2 Consume-and-effect gap

The strongest path atomically emits a Consumption Record for A and constructs or
commits the effect carried by Effect Receipt B. Where a destination cannot do
that, consumption and effect remain separate and the gap is explicit. A verified
Consumption Record followed by missing effect evidence derives
`AUTHORIZATION_CONSUMED_CONSEQUENCE_UNOBSERVED`, not execution, failure, or no
effect.

### 7.3 Retries and reconciliation

Every retry has a new `attempt_id`, an exact `retry_of` link, and a stable or
explicitly revised idempotency scope. If the prior A was consumed, a retry
normally needs a new A issued under remaining or renewed G, or a separately
defined lease/allocation. A new A does not prove the prior effect failed.

When the prior effect is unknown, the destination must reconcile against its
authoritative state or idempotency record before another non-idempotent effect.
Until then the result is `FAILED_STATE_UNKNOWN` or `UNPROVEN`; retrying does not
repair the evidence gap.

### 7.4 Batches and standing grants

A Bounded Grant G for N operations, a set, a lease, or a budget commits to the
operation-set representation and its comparator. Each boardable item uses an
exact A under G. Every Consumption Record identifies one exact item, leaf,
allocation, quantity, or debit plus state/balance before and after. One Effect
Receipt B cannot be presented as completion of G or the whole batch.

Batch completion is an aggregate Outcome over the complete committed member set.
Missing members remain unresolved. Mixed established and unresolved or failed
members derive `PARTIAL`.

### 7.5 Multi-destination operations

A multi-destination operation has a signed parent operation and destination-
specific legs under a parent G. Each leg has its own destination-scoped child G
where further attenuation is needed, its own Boarding Credential A, Destination
Attempt, Destination Recognition, Consumption Record, Effect Receipt B, and
Outcomes. One A never boards at more than one destination. A shared `operation_id`
correlates legs but never replaces their exact artifact references.

An aggregate Outcome states which legs are established, failed, reversed,
compensated, or unresolved. It cannot claim atomicity or settlement unless a
named cross-destination authoritative commit or settlement proof establishes it.
The aggregate evaluator cannot promote any unresolved leg.

### 7.6 Reversal and compensation

Reversal and compensation are new operations with new G and A when authority is
required. They link to the prior Effect Receipt and preserve it as historical
fact. Reversal proves an undo under a named domain profile. Compensation proves
a new offsetting effect. Neither edits the original statement or makes the
original effect disappear.

## 8. Strength is derived, never declared

Assurance is not monotonic — a later timestamp strengthens, a newly discovered
key compromise weakens. No producer field inside a Signed Statement is accepted
as, or can by itself award, a verifier assurance result. Producer `claimed_*`
fields, including `claimed_evidence_basis`, preserve testimony only.

A verifier computes results from the package under a named validation policy and
reports the §4 dimensions separately from at least these trust results, never
collapsed into `valid: true`:

```text
CRYPTOGRAPHIC_SIGNATURE_VALID
HISTORICAL_CREDENTIAL_VALID
IDENTITY_ESTABLISHED_UNDER  <named trust regime>
```

## 9. Preservation is a role, not a vendor

A `Preservation Steward` responsibility, transferable between providers, with
complete evidence exportable and no proprietary account required by a successor.

Two operational fields, neither signed by the original actor and neither claiming
to predict cryptanalysis:

```text
preservation_target_end     business/legal retention horizon
next_preservation_review    an operational promise by the current steward
```

**The operational rule that governs everything:** every cryptographic generation
must commit to the previous one *while the previous one is still trustworthy*.
There is no "renew it later when someone needs it." Once an algorithm is
forgeable, no subsequent evidence can distinguish the original from a forgery.

## 10. Historical identity is first-class

At least one external trust anchor is irreducible. A package cannot bootstrap
identity from nothing — a forger can construct an internally consistent fake root
and fake history.

So the package carries credentials, historical status evidence, trust-list or
checkpoint material, and **names the identity regime**. The verifier reports
which anchor it used rather than hiding the assumption.

## 11. What ships with the evidence

The specification is authoritative. Source is explanatory. A binary is optional
and is archaeology, not a trust mechanism — a 2046 investigator may have neither
a compatible runtime nor any willingness to execute an unknown 2026 executable.

```text
protocol/   normative semantics · schema/CDDL · canonicalization · algorithm IDs
events/     Action Proposal · Authorization Envelope · Decision/Permit
            · Human Review Attempt · Human Decision Record · G · A
            · Destination Attempt · Destination Recognition
            · Consumption Record · Effect Receipt B · Refusal Receipt · Outcome
                                                               [immutable bytes]
identity/   certificates · historical status · trust material · regime
witnessing/ timestamps · notarial evidence           [append-only]
preservation/ evidence records · renewal history · policy history
transparency/ receipts · service config history      [optional]
verification/ reference source · known-answer vectors · negative vectors
operations/ preservation_target_end · next_preservation_review
```

## 12. Reconciling ZLAR's three existing vocabularies

This is not a fourth event vocabulary and does not retroactively make legacy
artifacts conformant. Migration preserves each source value as a producer claim,
then derives v2 results only when the required role, links, identity, profile,
and predicates verify.

| existing value | source meaning that must be preserved | maximum v2 mapping |
|---|---|---|
| Orange `allow` | Policy allowed progression. | Decision/Permit `decision=allow`; derived decision `ALLOWED`. It may satisfy one predicate for issuing G. It is not G, A, destination recognition, consumption, or effect. |
| Orange `deny` | Policy denied progression before effect. | Decision/Permit `decision=deny`; derived decision `DENIED`. `DENIED_NO_AUTHORITY` additionally requires the §4 completeness predicate and affirmative non-issuance of G and A with no established consequence. It is a destination refusal only if a separate Refusal Receipt predicate verifies. |
| Orange `ask_pending` | Human decision is open. | Decision/Permit `decision=challenge`; derived decision and human authority remain `PENDING`; a Human Review Attempt exists only if exact presentation evidence verifies. No G or A and no terminal refusal. |
| Orange `authorized` | The human approval event recorded by the gate. | A Human Decision Record producer claim. It derives `APPROVAL_ACCEPTED` or `APPROVAL_ACCEPTED_WITH_SIGNALS` only from §4.2 and may satisfy a predicate for G issuance only through the exact binding in §6.2. |
| Orange H15 `h15_elapsed_seconds`, `h15_floor_seconds`, `h15_below_floor` | Gate-recorded timing values and comparison. | Claimed timing evidence. The verifier recomputes consistency; `FLOOR_MET` or below-floor results require the linked request/response clock evidence and exact active profile in §4.2. |
| Orange H14 `h14_alert_tier`, `h14_alert_ack_receipt_id` | Gate-recorded canary/variance tier and optional acknowledgement reference. | Claimed tier plus correlation ID. `ALERT_ACKNOWLEDGED` requires exact acknowledgement-artifact binding; a bare ID is insufficient. The tier requires recomputation or a trusted exact evaluator statement. |
| Orange H6/H13 state | Risk-weighted decisions today and TTL-filtered, retry-deduplicated pending set. | Separate `human_daily_load_result` and `human_pending_load_result`, each only from a protected bound snapshot/evaluator statement and the exact active profile. Absence from a legacy receipt leaves that result `UNPROVEN`. |
| Orange H17 result | Deterministic timing-floor check, with profile/lane/calibration inputs. | `PROFILE_PASSED`, `BELOW_PROFILE_FLOOR`, or `BELOW_ABSOLUTE_FLOOR` after recomputation. Passing is not proof of personhood. |
| Cyan `authorized` | Destination recognized authority and, for one-use credentials, ran its local replay claim; deliberately nonterminal. | Destination Recognition `RECOGNIZED` plus a producer claim of a Consumption Record. `CONSUMED` still requires the named replay-state transition predicate; no Effect Receipt or effect result follows from this string. |
| Cyan `executed` | `effectFn` returned at the named local runtime boundary. | Effect Receipt B producer claim with `claimed_effect_status=executed`; at most `CONFIRMED` when the exact boundary and returned result verify. Never `COMMITTED` or `SETTLED` without their predicates. |
| Cyan `failed` | `effectFn` threw. | Effect Receipt B failure claim; `FAILED_STATE_KNOWN` only with resulting-state proof, otherwise `FAILED_STATE_UNKNOWN`. Partial external effect remains possible. |
| Cyan `refused` | Destination refused before calling the effect boundary. | Refusal Receipt plus Destination Recognition `REFUSED` at that named boundary. It does not prove global prevention. |
| Cyan wallet `incomplete` | Candidate bytes did not form a transaction; nothing was refused. | Formation `INCOMPLETE`; normally `INCOMPLETE_NO_OPERATION`. No Refusal Receipt, G/A consumption, or effect result. |
| Cyan wallet `settled` | The in-memory wallet changed balance and nonce, then wrote a local log value called `settled`. | Effect Receipt B producer claim with `claimed_effect_status=settled`. `COMMITTED` or `SETTLED` requires the corresponding authoritative-state or domain-settlement predicate; the string alone establishes neither. |
| c030 `authorization-consumed-consequence-unobserved` | Authority was recorded as spent; destination execution and consequence were explicitly unproved. | A Consumption Record claim. If the exact consumption predicate verifies, derive `CONSUMED`, effect `UNPROVEN`, and `AUTHORIZATION_CONSUMED_CONSEQUENCE_UNOBSERVED`; otherwise consumption also remains `UNPROVEN`. Mapping it to execution is false. |
| c030 `consequence-unobserved` | The evidence component could not read the target. | Effect `UNPROVEN`. It does not by itself prove dispatch, attempt, failure, or no effect. |
| c030 `matching-bytes-observed-no-causation-proof` | The evidence component read bytes matching the expected bytes and expressly lacked causation proof. | `INDEPENDENT_OBSERVATION_PROVED` only if the observer-independence predicate verifies; otherwise at most the attestation whose own predicate verifies, often `SIGNED_CLAIM_ONLY`. The causal result remains `UNPROVEN`, never governed causation. |
| c030 `prevented` / `refused-before-consequence` | Candidate 030 deliberately refused promotion; `claimed_prevention` remained unverified. | Refusal Receipt at the named boundary. Prevention remains unproved unless affirmative no-change evidence independently derives `NONE_PROVED`. |

## 13. What v2 deliberately does not claim

- That successful statement or receipt verification establishes issuer,
  authority, or destination recognition. Verification checks the artifact;
  recognition is a separate policy decision with separate predicates.
- That a valid Effect Receipt means the action was wise, correct, lawful, safe,
  or within any policy other than the exact profiles the verifier evaluated.
- That emitting any evidence proves a destination enforced ZLAR, closed side
  doors, made the governed path exclusive, or prevented bypass.
- That a real-world consequence occurred, outside an authoritative commit boundary.
- That verification requires zero external trust.
- That binding an Authority Domain Definition removes the need for an external
  anchor. It does not. It converts an ambient, silently editable statement of
  what an authority may grant into an exact versioned artifact whose replacement
  is visible and whose historical bindings survive it.
- That an independently witnessed elapsed interval proves the responder was
  human, understood what they approved, or exercised judgement. It bounds one
  timing predicate and nothing else.
- That evidence survives without an actively maintained preservation chain.
- That one authorization is globally one-use across partitions.
- That the concept is novel. 2026 IETF drafts — SCITT permit profiles, Agent
  Action Capsules, refusal-event correlation, agent delegation receipts — occupy
  adjacent ground. v2 positions as generalizing and hardening an emerging
  pattern, not inventing it.

## 14. Freeze gates — none of this freezes until all four are green

1. **Two independent implementations agreeing byte-for-byte on identical
   vectors, one not written by ZLAR.** The conformance profile demands this of
   others; it binds ZLAR first.
2. **Negative vectors for every failure found 2026-08-16/17**: unsigned-field
   substitution, chain-link rewrite, consequence-replayed-as-authorization,
   unknown-field acceptance, trailing-newline divergence, case-folded path
   evasion; plus every independent attack on this revision, including producer
   grade-up, incomplete-as-refusal, invalid-A effect suppression,
   over-consumption, human timing/profile/state substitution, ID-only alert
   acknowledgement, signature-valid-but-unrecognized authority,
   signature-valid-but-destination-unrecognized A, verified Effect Receipt
   treated as issuer recognition, and evidence emission treated as enforcement;
   plus the vectors this revision's own additions introduce — mandate
   substitution under a stable identity, retroactive domain widening by a
   superseding D, recognition against an unbound domain, two D statements
   claiming one domain and version, a D that authorizes its own succession
   outside its anchor, and a producer-clock elapsed interval presented as an
   independently witnessed one.
3. **A written field-by-field comparison against the 2026 SCITT agent drafts**,
   before any name is frozen.
4. **A package verified with its signing key rotated *and revoked*, issuer
   offline.** If this fails, nothing else matters.

## 15. Open — needs a decision before drafting the schema

- Which single mandatory algorithm suite the first v2 profile selects, including
  its post-quantum transition rule. ADR-007's April forecast is not that decision.
- Whether RFC 9995 hash-envelope machinery or a fixed protected/application
  relationship field carries each exact-artifact reference inside the mandatory
  `COSE_Sign1` profile. Every role uses the one construction selected by the
  version; the role graph must not collapse back to two content types.
- Whether `intent_id` is in the frozen core or a profile.
- Whether ZLAR runs a transparency service, uses a third party, or specifies the
  interface and runs nothing.
- Who publishes an Authority Domain Definition, where a verifier retrieves the
  current version and its status, and whether succession requires quorum. The
  role is defined here; its custody is not, and custody is where a domain
  definition is actually attacked.
- Which witnessed clock domains a profile accepts for H15/H17, and what a
  verifier does when two witnesses disagree about the same interval.
