# Cyan — the consequence layer

Orange decides. **Cyan makes the decision binding.**

A decision with no enforcement is a dashboard. Enforcement with no decision is a
firewall. ZLAR is the pair.

## Exact Demo 1 profile — current source route

The founder-accepted Demo 1 contract does not reuse the earlier generic
grant-or-credential mechanism. It requires both exact founder-originated Grant
G and a non-expanding Boarding Credential A, with one grant-level allocation
consumed in the same SQLite transaction as the protected release transition,
PromotionCommit P, and terminal receipt R.

| file | current Demo 1 role |
|---|---|
| `demo1-protocol.mjs` | strict canonical schemas, domains, signatures, recognition policy, exact G-to-A linkage |
| `demo1-store.mjs` | one SQLite durability and serialization domain |
| `demo1-destination.mjs` | destination reconstruction, independent G/A verification, effect/P/R transaction |
| `test-demo1-protocol.mjs` | strict bytes, signature roles, non-expansion, type confusion |
| `test-demo1-destination.mjs` | refusal, exact effect, allocation, concurrency, replay, restart, fault rollback, abrupt pre/post-commit process loss |
| `test-demo1-receipts.mjs` | offline P/R verification, canonical signature identity, chain integrity, evidence-is-not-authority |

Caution first: the end-to-end test,
`demos/zlar-destination-gate/test-demo1-e2e.mjs`, is withheld from the commands
below because its host isolation remains unresolved (issue 12). Its last check
runs the installed Demo 1 client in a health subprocess, and as UID 501 that
subprocess attempts the host's fixed socket, including from a disposable
checkout on the same computer. The
[Demo 1 README](../demos/zlar-destination-gate/README.md#source-verification)
has the detail. Withholding this one test doesn't certify the others as safe on
every computer.

Run the software-key profile from the repository root:

```sh
node cyan/test-demo1-protocol.mjs
node cyan/test-demo1-destination.mjs
node cyan/test-demo1-receipts.mjs
```

Prerequisite: the exact Node runtime must expose `node:sqlite`; the current
verified build runtime is Node `v22.22.1`. The API is experimental in that Node
line, so candidate identity must bind the runtime version. Do not fall back to
separate grant, replay, effect, and receipt files.

This profile uses disposable software keys. Its claim stops at protocol and
transaction behavior. It does not establish YubiKey C custody, fresh human
authorization, actual Claude isolation, installed destination separation, or
Demo 1 PASS.

## Earlier Cyan slices — preserved semantic provenance

These generic slices remain useful research and regression evidence. They do
not route the exact Demo 1 profile: `issueGrant()` lets the issuer originate a
grant, `Guard.perform()` accepts grant or credential rather than both, and the
file stores cannot atomically bind debit, effect, P, and R.

| file | what it is |
|---|---|
| `canonical.mjs` | byte-identical serialization — no signature is meaningful without it |
| `envelope.mjs` | the exact action, typed by enduring consequence class, and its digest |
| `credential.mjs` | bounded authority: bound to one digest, principal, destination, window |
| `replay-store.mjs` | what a guard holds to refuse a credential it already honoured |
| `guard.mjs` | the destination-owned verifier. Refusal is the default |
| `lattice.mjs` | the consequence lattice — join, elevations, constitutional prohibitions |
| `grant.mjs` | standing authority and the delegation helper |
| `grant-store.mjs` | destination-side running debit and the composition window |
| `receipt.mjs` | what the destination signs, and how a third party checks it |
| `receipt-log.mjs` | the destination's own chain — where omission becomes visible |
| `test-cyan.mjs` | slice one checks — single-credential authorization and replay |
| `test-cyan-composition.mjs` | slice two propositions — composition and cumulative effect |
| `test-cyan-receipts.mjs` | slice three propositions — proof after the fact |

    node test-cyan.mjs && node test-cyan-composition.mjs && node test-cyan-receipts.mjs

## Design commitments

**The guard recomputes the digest.** It never trusts the credential's own account
of what it authorizes. Change the action after authorization and the credential
matches nothing. This is the defence against semantic escape.

**Recognition is local.** The guard never calls home at execution time. A guard
that must reach a server to decide is a guard that fails in a partition — on a
severed link, at the edge, on Mars.

**One claim per credential within one replay store.**
[`replay-store.mjs`](replay-store.mjs) uses exclusive file creation (`O_EXCL`)
to claim a single-use credential. The two-guard check in
[`test-cyan.mjs`](test-cyan.mjs) calls `authorize()` twice sequentially and
asserts one authorization. It does not demonstrate a concurrent execution.
[`Guard.perform()`](guard.mjs) consumes authority before calling a separate
effect function; these generic files do not commit consumption, effect and
receipt in one transaction. Two guards for the same destination with separate
replay stores can each accept the same credential:
`node test-cyan-negative-vectors.mjs` reports that known break on purpose.

The exact Demo 1 profile above uses a different mechanism. Its destination
issues and stores a signed challenge, and every grant binds that challenge.
A database that doesn't
hold the challenge refuses with `challenge_unrecognized`, and debit,
consumption, effect, P and R commit in one SQLite transaction
(`demo1-destination.mjs`, `demo1-store.mjs`). So Demo 1 prevents reuse within
its authoritative destination database. Rollback by an excluded administrator
is outside Demo 1's claim, and copied databases, replicas, backups and failover
haven't been shown safe.

**Authority expires by default.** Every credential must carry an expiry —
issuance refuses without one. Revocation is a renewal withheld, not a cancel
message that has to arrive.

**Measure, not flag.** Budget is an integer in smallest units. For each
configured grant ceiling, the guard checks the requested action together with
that grant's spending history in one store over its configured window.
This bounds cumulative authorization within that accounting scope; it does
not share spending between parent and child grants or across independent
stores. A credential's own `budget` caps a single action, and a `lease`
credential repeats its one exact action until it expires.

**Receipts are destination-signed.** A refusal is provable later without trusting
the AI, the ledger, or ZLAR.

## Tier 3 — cryptographic necessity

    node demo-theft.mjs

`wallet.mjs` is a reference destination that owns its acceptance rule: a
transfer requires two signatures, the owner's and the cosigner's. `cosigner.mjs`
holds the cosigner's key and will not sign anything the guard has not
authorized — and it builds the transaction body itself from the authorized
action rather than signing a body handed to it, so nothing can be substituted
between approval and signature.

In a real house the cosigning key belongs to whoever runs that house's force
field. ZLAR can be one option, never the requirement: a design where every
payment everywhere needs ZLAR Inc.'s signature would be the master key that
[PRINCIPLES.md](../PRINCIPLES.md) rules out.

The wallet has **three** outcomes, and the third is the product:

| outcome | meaning |
|---|---|
| `settled` | accepted, balance moved |
| `refused` | a whole transaction the wallet declined — something said no |
| `incomplete` | **not a transaction.** Nothing to refuse. Half a cheque |

A stolen owner key produces `incomplete`. Not blocked, not rejected — never
formed. There is no rule to argue with and no guard to route around, because
the wallet is not asking whether the transfer is permitted. It is observing that
what arrived is not a transaction.

Tier 2 is included in `test-cyan-theft.mjs` for contrast, and it is shown
failing: a destination protected by a single exclusively-held secret drains the
moment that secret is stolen. That is exactly why Tier 3 exists.

## Slice two — composition and cumulative effect

**Standing authority, because one-use is the atom and not the prison.** Routine
action moves at machine speed inside a bounded grant with no human touched. Only
the exceptional stops for a person.

**The join, not the maximum.** A set of steps has a combined consequence that can
exceed any part of it. Per class the measures sum; declared elevation rules add
what the combination produces that no single step declared. Read access to PII
plus disclosure of PII elevates to an irreversible effect neither step admitted.

**Composition uses recorded authorizations.** For one grant in one spending
store, the guard joins the requested action with the recent authorization
history over that grant's window. These entries are recorded before the
separate effect function runs; they do not establish completed effects.

**Delegation is meant to be a meet.** A child grant should be the greatest lower
bound of what the parent held and what was asked for. `delegate()` applies that
to these fields: ceilings take the minimum, allow-lists intersect, prohibitions
and elevations union, expiry takes the earlier. A child that asks for 999,999
against a parent ceiling of 10,000 receives 10,000. The meet is not yet
complete, so no enlargement is the target, not a proven property. Three gaps
remain:

- `delegate()` takes the *shorter* composition window. Ceilings are summed over
  the window, so a child's allowance can refill faster than its parent's.
- Parent and child keep separate spending histories in `grant-store.mjs`.
- The guard doesn't verify the delegation chain. A recognized issuer can sign a
  wider "child" directly, and the guard accepts it.

**Constitutional prohibitions.** Combinations no ordinary grant can permit,
regardless of available budget. Deploy code, then activate the machine it drives:
refused with ceilings to spare.

**The grant store records spending with the decision.** The ceiling check and
spending-record update run under the same per-grant lock in
[`grant-store.mjs`](grant-store.mjs). This records an authorization before the
separate effect function runs; it is not an atomic commit of the protected effect.

## Slice three — receipts, and what proof after the fact actually requires

**Attributable.** A receipt names the destination key that signed it and
verifies offline from that public key alone. Nothing is asked of ZLAR at
verification time. A receipt that can only be checked by calling the system that
issued it is that system's word, restated in a different font.

**Evidence is never authority — as arithmetic, not as a rule.** Receipt
signatures are domain-separated, so a receipt can never be presented as a
credential and a credential can never be presented as a receipt. A destination
that signs a million receipts has not thereby minted a million authorizations.
The invariant used to depend on everyone remembering it. Now it depends on the
bytes.

**Gap-evident.** Every receipt carries its position and the hash of the receipt
before it. One signed receipt proves one event. It says nothing about what is
missing, and a history that can be quietly pruned will be pruned exactly where
it matters. Deleting from the middle breaks the sequence; altering in place
breaks the successor's link even when the altered entry is re-signed with the
real key; reordering breaks both.

**Refusals share the chain with executions.** Otherwise a destination could drop
its refusals and present an unblemished record of successes.

**The receipt states the outcome, never the intent.** `authorize()` receipts an
*authorization*; the terminal receipt is minted after the effect happened or
failed. An authorization with no terminal successor is a dangling pair, visible
to anyone reading the chain — which is the honest way to surface "the guard said
yes and no one ever recorded what happened next."

**Which rules were in force.** A receipt names the issuer that authorized and
carries a digest of the guard's recognition rules. "Authorized" is meaningless
without "under what": change which issuers a destination accepts and you change
what authority means there, silently, while every existing receipt still
verifies. The digest makes that change visible — receipts from either side of it
are visibly not comparable.

**Published heads close the truncation gap.** The chain catches deletion from the
middle, and cannot catch removal of the tail: lop off the newest entries and what
remains is internally consistent. Nothing inside a chain can fix that, because
the evidence that something is missing was the thing removed. So the destination
periodically signs a small statement — *at this moment my chain was N entries
long and ended with this hash* — and gives it to someone. Once one copy is
outside the destination's control, a shortened history contradicts the
destination's own signature. A head is a floor, not a claim of finality: a longer
history is fine, a shorter one is a finding.

### The bound, stated plainly

The chain makes **removal** from a written history detectable, and a published
head extends that to the tail. Neither can make a destination write a receipt it
never wrote, and no cryptography can. A destination that records nothing produces
nothing to catch. Anchoring narrows the gap to exactly that, and the honest claim
stops there.

## Not done

Renewal protocol for leases. Multi-destination grants and cross-guard debit.
Quorum and separation of duties. A transport for published heads — the mechanism
exists, where the heads go is a deployment question and is unanswered. Tier 2
exclusive custody and Tier 3 cryptographic necessity beyond the reference wallet.
One-use across separately recorded guards in these generic slices (issue 1).
Delegation that keeps the parent's window, shares its spending, and is verified
at the guard.
