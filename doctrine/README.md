# ZLAR Doctrine Suite

This directory contains the canonical doctrine files for ZLAR.

These files are used to keep public writing, internal reasoning, code comments, and implementation naming aligned with the live system.

## Authority order

When these sources disagree, use this order:

1. **Live signed artifacts and live runtime truth**
   - `etc/policies/active.policy.json`
   - `etc/constitution.json`
   - the live manifest in use by the gate
   - the live receipt chain
   - `var/gate-uptime.json`
2. **`doctrine/ZLAR-DNA.md`**
   - the architectural and doctrinal canon of ZLAR
3. **`doctrine/SCOPE.md`**
   - the public boundary of ZLAR's governance claim — what is governed, what is not, and the rules for any claim made about it
4. **`doctrine/FRAMINGS.md`**
   - conceptual vocabulary, superseded terms, framing discipline, copy doctrine
5. **`doctrine/IMPLEMENTATION-TERMS.md`**
   - engineering-near vocabulary and live mechanism names
6. **Maintainer session-entry notes (not shipped in this repo)** route to canon above and update themselves on conflict.

## File roles

### ZLAR-DNA.md

Use for:
- what ZLAR is
- what is load-bearing
- what is current doctrine
- what must remain consistent across public and internal surfaces

DNA decides canon.

### SCOPE.md

Use for:
- what ZLAR governs and what it does not
- how any public claim about ZLAR must be framed
- the deployment owner's responsibility for interception completeness
- the shipping status of scope-related capabilities

SCOPE elaborates DNA §11. It does not overrule DNA; it operationalizes it for public claims.

### FRAMINGS.md

Use for:
- conceptual vocabulary around the canon
- superseded but historically relevant terms
- framing choices in public and internal writing
- structural voice guidance

FRAMINGS explains and sharpens language. It does not overrule DNA.

### IMPLEMENTATION-TERMS.md

Use for:
- code-near vocabulary
- mechanism names
- implementation shorthand
- terms used in comments, tests, logs, and engineering discussion

IMPLEMENTATION-TERMS explains how doctrine becomes code. It does not overrule the live repo.

## Usage rules

- For **website, README, essays, positioning, and public-facing writing**:
  1. check live truth if the claim is operational
  2. check DNA
  3. check FRAMINGS if wording or conceptual framing is in question
- For **code comments, tests, implementation prose, and engineering notes**:
  1. check the live repo
  2. check IMPLEMENTATION-TERMS for names
  3. check DNA when explaining why a structure exists
- For **naming disputes**:
  - DNA first
  - then FRAMINGS
  - then IMPLEMENTATION-TERMS

## The roadmap/ subdirectory

`doctrine/roadmap/` holds design-not-shipped doctrine: the named plans for capabilities that have an approved architectural shape but no running code. A roadmap file states:

- the gap being addressed
- the architectural shape of the fix
- how the capability, once shipped, will change what DNA and SCOPE describe

Roadmap files are doctrine, not capability claims. They make unshipped work public so readers do not mistake absence-of-claim for absence-of-gap. A roadmap file is retired to canon (DNA or SCOPE) when the capability it describes ships.

The roadmap/ directory ranks below live canon in authority order — if a roadmap file and DNA (or SCOPE, or the live signed artifacts) disagree about present-day truth, the canon wins and the roadmap file must be corrected or retired.

## What these files are not

- DNA is not a scratchpad
- SCOPE is not a place to soften claims DNA already states
- FRAMINGS is not a place to casually invent new doctrine
- IMPLEMENTATION-TERMS is not the source of truth over the code
- roadmap/ is not a capability claim — it is a plan made public

## Code-comment split

When writing code comments:
- use **DNA** for explaining **why** a structure exists
- use **IMPLEMENTATION-TERMS** for explaining **what** a mechanism is called
- use the live code and signed artifacts for claims about runtime behavior

## Maintenance rule

If a doctrine file and live signed artifacts disagree, the artifacts win.

If a file becomes a warehouse, split it.
