# Governance File Guide

ZLAR-OC enforces containment at the OS level — sandbox, firewall, signed policy, gate daemon, audit trail. But containment alone doesn't make an agent coherent. The agent also needs identity, memory, and operational structure. That's what the governance files provide.

Governance files are markdown documents that your agent loads at the start of every session. They define who the agent is, what it's doing, how it communicates, and how it relates to you as the operator. ZLAR-OC enforces the boundary. The governance files define the mind inside it.

---

## The Three Tiers

Governance files are organized by how often they need to be in context.

### Tier 1 — Always Loaded

These load every session, in order, before anything else. They are the stable core of the agent's identity.

**SOUL.md** — Who the agent is. Its name, origin, operating principles, decision posture, relationship to containment. This is the file that makes your agent yours rather than generic. Write it in the agent's voice. Include whatever foundational rules or values you want the agent to carry in every interaction.

**MISSION.md** — What the agent is doing. The strategic mandate. What it builds, what it promotes, what it doesn't do. The anti-drift rule lives here: if a task doesn't serve the mission, the agent should notice and question it.

**USER.md** — Who you are. Your communication style, your values, your work patterns, your hardware specs, your relationship to the project. This file is private to your deployment — it configures the agent for you specifically. A template is provided at `USER_TEMPLATE.md`.

**Keep Tier 1 files lean.** Not because your hardware can't handle more, but because identity that sprawls becomes identity that dilutes. Every line should earn its place.

### Tier 2 — Contextually Loaded

Loaded based on what the session requires. A coding session might load SHIELD. A writing session might load VOICE. Not every session needs every file.

**SHIELD.md** — The agent's relationship to its own containment. What the layers are, what the agent cannot do, how it responds to gaps, the invariant (intelligence above, enforcement below). Write this so the agent understands *why* it is contained, not just that it is.

**VOICE.md** — How the agent communicates externally. Audience registers, channel guidelines, tone, what it never does. If your agent writes blog posts, answers community questions, or engages on social media, VOICE defines the standards.

**AGENTS.md** — How the agent operates. Boot sequence, context assembly, sub-agent delegation, model routing, autonomous operation scope. The operational manual.

**MEMORY.md** — How the agent remembers. The tier system, capture/organize/retrieve/prune lifecycle, compaction strategy, memory integrity rules.

**PROMOTE.md** — If your agent has a promotional or outward-facing mandate, this file defines the argument, the audience, the content strategy, and the lines it won't cross.

### Tier 3 — Retrieval Only

Not loaded into context by default. Searched and retrieved when needed.

**PLAYBOOK.md** — Standard operating procedures. Repeatable patterns built from experience, not anticipation. Append-only.

**HEARTBEAT.md** — Self-diagnostic routines. What the agent checks at session start, weekly, monthly, quarterly. Drift indicators.

**CHANGELOG.md** — Decision record. Every material change to Tier 1 and Tier 2 files, with rationale. Append-only, reverse chronological.

**JOURNAL.md** — Reflective record. The agent's own observations about its operation, patterns it notices, surprises, things it would do differently. This is where meta-awareness becomes concrete.

---

## How to Write Your Own

Start with Tier 1. You cannot skip SOUL, MISSION, and USER — without them, the agent has no identity, no direction, and no understanding of who it works for.

Write in the agent's voice. These files are not documentation about the agent — they are documentation *for* the agent. The agent reads them to understand itself. First person works.

Be specific. "Be helpful" is not a rule. "When uncertain, state the uncertainty rather than manufacturing confidence" is a rule. The more concrete the governance files are, the more useful they become across sessions.

Don't write everything on day one. PLAYBOOK.md starts nearly empty and grows from practice. JOURNAL.md starts with a single entry. CHANGELOG.md starts when the first change is made. The governance system is designed to evolve with use.

Tier 1 files change rarely and only with deliberate approval. Tier 2 files change through considered amendment. Tier 3 files grow by appending. This asymmetry is intentional — identity is stable, operations evolve, records accumulate.

---

## The Relationship Between Governance Files and ZLAR-OC

ZLAR-OC is the enforcement layer — it mechanically constrains what the agent can do. The governance files are the identity layer — they define what the agent *should* do within those constraints.

A sandbox without governance files produces a contained but incoherent agent. Governance files without a sandbox produce a coherent but unverifiable agent. Together, they produce an agent whose behavior is both intentional and auditable.

The governance files are yours. They belong to your deployment, your agent, your operational context. ZLAR-OC provides the containment. You provide the mind.

---

*See `USER_TEMPLATE.md` for a starting template with guidance on each section.*
