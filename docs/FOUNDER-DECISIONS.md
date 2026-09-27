# Founder decisions that bind engineering

**Extracted 2026-08-17 from Vincent Nijjar's private working space. Restated
here, not copied.**

## Why this document exists

There is a private space where the founder thinks — vision, rough language,
things that are not true yet. It exists deliberately: a builder that only
accepts what evidence already supports cannot help anyone see something novel,
because every novel thing is unevidenced right up until it works.

That space is **private and stays private.** It holds personal material and
contacts. It is not in this repository, will not be, and should never be
requested.

But decisions were made there that bind what gets built here — and with no door
between the two rooms, they bound silently. On 2026-08-17 an evidence protocol
was drafted that compressed a founder-confirmed five-stage chain into two
statements. An independent review objected that two were too few. **The decision
saying five was a month old and neither reviewer knew.**

This document is the door. The thinking stays free; the decisions become binding
here, dated, and available to anyone who clones this repository.

## The promotion rule

**A private note is not authority. A decision recorded here is.**

The private space *"can orient, map, classify, and synthesize inside its
authority. It does not authorize ZLAR changes."* Nothing there governs this
repository until it appears in this file.

So: when something stops being speculation, it gets restated here with its date.
Until then a builder must not treat it as binding — and equally, must not
contradict it once it is.

---

## D1 — The authorization chain has five stages

**Source: founder vision on the universal authorization protocol, confirmed
2026-07-17.**

> Recognized authority → bounded grant → boarding credential → destination
> recognition → effect receipt

Binding consequence: **an evidence model with only "authorization" and
"consequence" is incomplete.** Independent adversarial review reached the same
conclusion on 2026-08-17 from a different direction — that two statements cannot
express pending decisions, denials with no authorization, consumption, partial
effects, retries, reversals or multi-destination legs.

**Canonical name: the destination's signed statement of what it did is an
`effect receipt`.** Do not invent another term for it.

## D2 — Verification is not recognition

**Source: same document, line 99.**

> A signature may verify correctly. Verification alone is not recognition.

Verification checks the receipt. **Recognition decides whether it can board.**
These are different roles with different predicates, and collapsing them is a
forbidden claim (see D4).

This is the same distinction an adversarial review independently demanded:
*what the producer claimed ≠ what the verifier established ≠ what the destination
actually enforced.*

## D3 — The layer ladder: crossing one layer does not cross the next

**Source: boundary-collapse guard.**

1. repo code
2. release/tag
3. website/public claim
4. install/config
5. live hook crossing
6. receipt emission
7. downstream recognition/refusal
8. side-door map
9. current-machine governance claim

Before any status, proof, or authority claim, state: highest crossed layer,
evidence, next uncrossed layer, forbidden claim, private/public surface,
authority needed.

This is the discipline behind every honest claim ZLAR has made. It is also the
one that catches a builder saying "installed" and meaning "governing."

## D4 — Forbidden claim classes

**Source: claim ceilings and language lanes.** Do not write or imply these
unless current evidence explicitly supports them. Reproduced because several bear
directly on live protocol work.

- ZLAR governs all AI; or governs thought, model reasoning, memory, planning or
  final text.
- ZLAR governs all of Codex, Claude Code, Cursor, Windsurf, browsers, files,
  networks, apps, shells or MCP.
- A client install proves a governed path.
- Gate state `on` proves current-machine governance.
- Live hook execution has happened, unless a live hook-crossing proof exists.
- Live receipt emission has happened, unless a live receipt proof exists.
- **A valid receipt means the action was wise, harmless, legal, complete, or
  globally authorized.**
- **Receipt verification is the same as issuer recognition.**
- Static proof-pack artifacts prove production deployment.
- A private verifier interaction is public external attestation.
- Private core release means public website release.
- Public website language is proof evidence.
- Draft strategy is product doctrine.
- Meristem proof-chain progress is ZLAR production authority.
- ZLAR operates as sovereign infrastructure outside a recognized authority domain.
- Side doors are closed unless the deployment actually blocks or routes them.

## D5 — Language decisions

- Receipts are **never** described as NFTs or tokens.
- `ZLARed`, `ZLARing`, `ZLARs` are forbidden inflections (founder decision,
  2026-08-08).
- ZLAR is always **ZLAR**, in every document, commit, comment and reply.

## D6 — Demo 1 meaning

**Status: FOUNDER-ACCEPTED, amended 2026-08-18.**

Preserve Candidate 005’s narrow deployment.promote consequence proof as the
technical starting point. Repair or replace implementation details where
required by the accepted propositions and decisive tests. The outward Demo 1
must show an AI with ordinary execution capability visibly unable to cross the
protected consequence boundary until separately originated authority is
supplied. This does not make Candidate 005’s current code, UI, state mechanism,
database, or deployment.promote use case permanent.

## D7 — Authority semantics

**Status: FOUNDER-ACCEPTED 2026-08-18.**

Vincent originates bounded authority in exact Grant G, including its maximum
protected-effect allocation. An authorized issuer may derive one or more
Boarding Credentials A under G, but derivation may neither broaden G nor
increase its remaining authority allocation. The agent may propose an action
and transport A but may not originate, enlarge, recognize, restore, or multiply
authority. The destination independently verifies recognized authority on G,
issuer authorization, exact G-to-A linkage, non-expansion, consequence binding,
and remaining grant-level allocation before permitting the protected effect.
These are semantic and evidentiary roles and do not require separate software
services.

## D8 — Human-authority threshold

**Status: FOUNDER-ACCEPTED 2026-08-18.**

Demo 1 requires a fresh custody-bound authorization act for exact G through an
authority mechanism the acting AI cannot complete, automate, replay, reuse from
a prior human-presence event, or obtain unattended within the declared Demo 1
threat model. The agent may prepare a candidate G and initiate the ceremony, but
the proposal has no authority until the recognized authority act is bound to
exact G and the fresh authorization instance.

The Demo 1 claim is custody-bound fresh authorization. It does not claim that
ZLAR cryptographically proved Vincent read, understood, or knowingly approved
every material term. Informed authorization remains a later
consequence-specific profile.

---

## What is deliberately not here

The private space also holds founder voice, rough language, unresolved tensions,
competitive intelligence, contacts and personal material. **None of it belongs in
this repository**, and its absence is not an oversight.

A colleague joining ZLAR needs the decisions, not the notebook. Publishing the
notebook would also destroy the thing that makes it work: a space where nobody is
watching is only useful while nobody is watching.

## Related, and already in this repository

- `lib/human-invariants.sh` — H6, H13, H14, H15, H17
- [`PRINCIPLES.md`](../PRINCIPLES.md) — the properties every ZLAR key follows
