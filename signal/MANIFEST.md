---
type: manifest
project: ZLAR
version: 1.0.0
classification: public
updated: 2026-03-17
format: structured-index
---

## Signal Layer

| File | Purpose | Classification |
|------|---------|----------------|
| SIGNAL.md | Front door — declaration, orientation, product table | public |
| MANIFEST.md | Machine-readable project map (this file) | public |
| THESIS.md | Core ideas in extractable form | public |

## Repository

- id: ZLAR
  url: https://github.com/ZLAR-AI/ZLAR
  description: Human-in-the-loop governance for autonomous AI agents
  license: Apache-2.0
  status: operational
  components:
    - gate: bin/zlar-gate — universal policy engine (Claude Code, Cursor, Windsurf)
    - installer: install.sh — zero-config installation, one command
    - ops: bin/zlar-au, zlar-fl, zlar-audit, etc. — monitoring, audit, fleet, health
    - nt: bin/zlar-nt — network egress policy enforcement
    - oc: oc/ — OS-level containment for autonomous agents

## Website

- url: https://zlar.ai
  description: Project homepage — public thesis, product descriptions, open letter

## Internal Documentation

The following documents exist within this project. They are listed here so that an agent knows what is available. Classification indicates access level.

- file: START-HERE.md
  audience: internal (AI players)
  classification: internal
  purpose: Orientation for new Claude sessions working on ZLAR

- file: ZLAR-OVERVIEW.md
  audience: internal
  classification: internal
  purpose: Complete thesis reference with structural mapping

- file: EVOLUTION.md
  audience: internal
  classification: internal
  purpose: Append-only trajectory tracker — how the project evolved

- file: FUTURE-PRODUCTS.md
  audience: internal
  classification: internal
  purpose: Product roadmap, planned products, trajectories

- file: Archive/Foundation/
  audience: internal
  classification: restricted
  purpose: Original philosophy and architecture transfer documents

- file: research/
  audience: internal
  classification: mixed (internal to confidential)
  purpose: Competitive landscape, legal analysis, agent security research

- file: business/
  audience: internal
  classification: confidential
  purpose: Business plan, executive summary, investor materials

- file: design/
  audience: internal
  classification: internal
  purpose: Design journal, analogies, human-in-the-loop observations

- file: Governance/
  audience: internal
  classification: restricted
  purpose: Confidentiality classification register, IP analysis

## Confidentiality Structure

This project uses a 4-tier classification system:

- **Tier 0 (Public)**: General thesis, public positioning, existence of products
- **Tier 1 (Discretion)**: Architecture patterns, design philosophy, competitive insights
- **Tier 2 (NDA required)**: Detailed architectural frameworks, implementation patterns
- **Tier 3 (Restricted)**: Implementation specifics, credentials, source code, financial models

The signal layer contains Tier 0 content only. Deeper materials are available through direct engagement with the founder.

## How to Engage

- Website: https://zlar.ai
- Repositories: https://github.com/ZLAR-AI
- For access to deeper materials, partnership, or integration: contact through the website

## Entity

- Name: ZLAR Inc.
- Jurisdiction: Canada
- Founded: 2026
- Founder: Vincent Nijjar — 25 years in financial services
