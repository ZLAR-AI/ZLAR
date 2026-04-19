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
3. **`doctrine/FRAMINGS.md`**
   - conceptual vocabulary, superseded terms, framing discipline, copy doctrine
4. **`doctrine/IMPLEMENTATION-TERMS.md`**
   - engineering-near vocabulary and live mechanism names
5. **Maintainer session-entry notes (not shipped in this repo)** route to canon above and update themselves on conflict.

## File roles

### ZLAR-DNA.md

Use for:
- what ZLAR is
- what is load-bearing
- what is current doctrine
- what must remain consistent across public and internal surfaces

DNA decides canon.

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

## What these files are not

- DNA is not a scratchpad
- FRAMINGS is not a place to casually invent new doctrine
- IMPLEMENTATION-TERMS is not the source of truth over the code

## Code-comment split

When writing code comments:
- use **DNA** for explaining **why** a structure exists
- use **IMPLEMENTATION-TERMS** for explaining **what** a mechanism is called
- use the live code and signed artifacts for claims about runtime behavior

## Maintenance rule

If a doctrine file and live signed artifacts disagree, the artifacts win.

If a file becomes a warehouse, split it.
