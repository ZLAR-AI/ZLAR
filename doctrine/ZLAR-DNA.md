ZLAR DNA
The architectural and doctrinal canon of ZLAR

If this file and the live signed artifacts disagree, the artifacts win.

Last updated 2026-04-18. Live doctrine.

Scope: what ZLAR is, what it protects, how it works, and why it is architected this way. Implementation shorthand and build lore live elsewhere (see IMPLEMENTATION-TERMS.md and FRAMINGS.md). Every capability described here is labeled by shipping status when ambiguity is possible; overstating is not allowed.

—

1. Purpose

ZLAR is human-in-the-loop governance infrastructure for autonomous AI agents. It evaluates agent actions against signed policy, routes decisions to a human when policy calls for it, and produces signed receipts of what happened.

Denials are positive outcomes — they are what governance looks like when it is working.

The thesis: governance is only real when the architecture, not the operator's intent, makes non-compliance impossible.

—

2. The Three Authority Laws

The First Authority Law
Humans must remain sovereign over the actions of AI systems that can produce consequential, irreversible effects. Within the governed path, no consequential action crosses the contact boundary without either a signed policy allowing it or a signed human approval. Structural, not policy-level. The protection holds even when the agent is adversarial or misaligned.

The Second Authority Law
Humans must remain sovereign over the policy that governs agents. Operational policy is constrained by a meta-policy (the constitution), signed by a separate authority. The gate refuses to load operational policy that violates the constitution. This protects humans from policy authors, including policy authors who are themselves governance vendors.

The Third Authority Law
Humans must remain sovereign over operators of governance infrastructure, including ZLAR itself. Governance must remain independently auditable: no vendor should control its own accountability.

Ordering rule (Rechtsstaat precedent): the Second Authority Law must ship and prove in production before the Third is implemented.

—

3. The Contact Boundary

The contact boundary is the point at which agent intention puts on gloves to touch reality. It is the only structurally governable moment — before it, an agent has intentions; after it, the world has changed. Everything in ZLAR sits on that line: the gate, the receipt, the policy evaluation, the human ask.

Governing upstream (the model, the prompt, the reasoning trace) is governance theater. Governing downstream (monitoring, logging, dashboards) is forensics. Governance happens at the contact.

Execution Boundary — superseded. Earlier ZLAR writing used "execution boundary" for this concept. Contact Boundary is current because it is closer to what actually happens: the instant before the agent touches the world. Retained here for historical continuity.

—

4. The Invariant and the Five Inviolable Principles

The Invariant
Within the governed path, no consequential action reaches the world without either a signed policy allowing it or a signed human approval. Everything else in ZLAR is infrastructure for keeping this true under adversarial conditions.

The Five Inviolable Principles
One. Structural enforcement over intent. The architecture, not the operator, makes non-compliance impossible.
Two. Fail closed. When any component cannot verify its own state, deny.
Three. Deterministic evaluation. Policy decisions must be reproducible from signed inputs alone. No AI in the enforcement path.
Four. Human authority at the contact boundary. The human is not an auditor or reviewer; the human is the source of consent that unblocks consequential action.
Five. Cryptographic continuity. Every decision produces a signed receipt that chains to the prior receipt, so history cannot be silently rewritten.

These five are invariants in the literal sense: they hold across all versions, all deployments, all downstream changes. Any feature that breaks one of them is rejected, not refactored.

—

5. Core Architecture

The Gate
The gate is ZLAR's enforcement core. Everything else exists to make that core trustworthy, legible, and durable. Two implementations share state: zlar-gate (bash, Claude Code PreToolUse hook) and gate.mjs (MCP gate). Both evaluate the same signed policy and write to the same state store.

The Policy
Policy is a signed Cedar-based rule set loaded at gate startup. Rules are declarative and ordered by specificity: narrower allows before broader denies, narrower denies before broader allows. Policy is verified against the constitution before load; a policy that violates the constitution fails closed.

The Constitution
The constitution is the meta-policy: rules about what operational policy is allowed to be. Signed by a separate key (the constitution key) from operational policy (the policy key). This is the machinery of the Second Authority Law.

The Manifest
The manifest is the signed declaration of the agent identity crossing the gate: who, what runtime, what invariants, what version. Checked before the first tool call and pinned to the session receipt chain. A drifted or unsigned manifest fails closed.

The Receipt
Every gate decision produces a Governed Action Receipt (GAR v1): a signed, structured record of the intent, the evaluation, the outcome, and the prior receipt hash. Receipts chain. A broken chain is detectable and fails closed.

Dual-Layer Receipt Architecture
Receipts have an inner layer (decision detail, potentially personal data) and an outer layer (chain link, no personal data). This allows public verifiability of the chain without exposing sensitive content — the structural basis for GDPR compatibility without breaking auditability.

—

6. Defense in Depth

The Chokepoint Stack
Six layers, each fail-closed: manifest verification, constitution verification, policy verification, Cedar evaluation, human ask where policy routes it, receipt seal. No layer trusts the layers above it. Each can refuse independently.

Cassandra's Gap
The distance between a system being able to detect a problem and a system being authorized to act on it. ZLAR closes the gap by coupling detection and routing: the gate does not report to a dashboard and wait; it blocks and asks a human.

Five-Layer Validation Pipeline
Syntactic, structural, semantic, referential, rule-outcome consistency. A receipt that fails any layer is rejected, not soft-logged. Semantic validation — does the rule that fired match the decision rendered — is the layer most governance systems skip.

The Deny-First Governance Kernel
ZLAR's default is deny. Every allow is explicit, narrow, signed, and traceable. Rule ordering (narrower-allow-before-broader-deny) is the operational expression. Rule-ordering audits are first-class maintenance work, not cleanup.

—

7. Human Authority in Practice

Policy-Routed Human Authority
The gate does not show every action to a human. Policy decides. For actions below the consequential threshold, the gate evaluates deterministically and proceeds. For actions above it, the gate routes to a human via Telegram and blocks until the human answers. The threshold is policy, not model judgment.

Approval is not rubber-stamping
Sustained very-high approval rates are a warning sign that the system may be rubber-stamping rather than governing. Either policy is routing too much to humans (noise) or the human is no longer reading (capture). Both are operational failures, detectable from the receipt chain.

Silence is not consent
If the human does not answer, the action does not proceed. Deny-by-timeout is the only safe default. Anything else lets the absence of a human become an implicit yes, which is the precise failure mode governance exists to prevent.

Zero-Terminal
The human's only interface is approve or deny on a phone. No terminal, no dashboard, no console, no policy knob surfaced at decision time. The human decides whether the action happens; the human does not configure the governance system at the moment of governance.

—

8. Evidence and Verification

Governed Action Receipt (GAR v1)
Structured, signed record of a single gate decision. Contains intent, evaluated policy, outcome (allow, deny, human-approved, human-denied, timeout), and the hash of the prior receipt. Verifiable standalone (bin/zlar-verify) and as a chain.

Hash Chain Continuity
Each receipt includes the SHA-256 hash of the prior receipt. A rewritten, missing, or reordered receipt breaks the chain. Detectable by anyone with access to the receipt stream, without needing access to ZLAR internals.

Independent Verifiability
Receipts are verifiable using only the public keys (policy signing, constitution signing) and the schema. No call to a ZLAR server is required. A direct expression of the Third Authority Law: the governed must be able to audit the governor.

Ed25519 and SHA-256
Ed25519 for signing (policy, constitution, receipts, manifest). SHA-256 for hashing (chain links, content addresses). Both standard. The choice is the absence of custom cryptography.

—

9. Anti-Patterns

The Smart Gate Trap
Putting an LLM in the enforcement path. Creates an attack surface (prompt injection against the gate itself), removes determinism, and makes the governance system non-auditable. Any system whose enforcement depends on model judgment is not governance; it is a recommendation engine with a nicer word attached.

The Inside-the-Model Trap
Trying to govern an agent by training, fine-tuning, or prompt-engineering the agent itself. Fails on alignment, fails on adversarial models, fails on drift. The agent cannot govern itself, and the vendor of the agent cannot be trusted to govern it. Governance must sit outside the model, at the contact boundary.

The Trust Quantification Category Mistake
Assigning numeric trust scores to agents, actions, or outputs. Scores become a vector: the system that decides what score to assign is the system that decides what is allowed, which collapses governance into a ranking problem. ZLAR has no trust scores. Actions are allowed or denied on signed policy.

The Trust Farming Attack
When a system adjusts trust based on observed behavior, an adversary with patience produces benign behavior for long enough to raise the trust level, then uses the raised trust to execute the real action. Any system that grants trust via behavior is farmable. ZLAR is not.

The Verified Liar
A receipt is proof that a decision was signed. It is not proof that the decision was correct. A perfectly signed chain of bad decisions is a perfectly signed chain of bad decisions. Evidence is necessary but not sufficient; the policy must be constrained by the constitution, and the constitution must be public.

Voluntary Compliance Error
Assuming that the actors the system is designed to constrain will volunteer to be constrained. The Syria CWC declaration is the canonical counterexample: a treaty with a voluntary declaration step produced an inaccurate declaration, which is the outcome voluntary compliance always produces under adversarial conditions. Governance must constrain without relying on the constrained party's cooperation.

—

10. Cumulative Irreversibility and Restorative Governance

Cumulative Irreversibility Detection (design, not yet shipped)
Individual actions below the consequential threshold can, in aggregate, produce irreversible outcomes. A single write to a config file is reversible; a sustained pattern of writes that collectively reshape the system may not be. The detection: track consequence vectors across actions, raise the threshold as cumulative effect approaches an irreversible boundary. Planned for ZLAR 3.0.

Restorative Governance (design, not yet shipped)
When the gate denies, the agent is not just blocked — it is routed to a restorative path: what would have to be true for this action to be allowed. The human can grant a narrow exception (signed, receipt-producing), adjust policy (signed, constitution-checked), or refuse. Planned for ZLAR 3.0 (Restore / Agent Health subsystem).

Authority Branching, Authority Envelope, Future Authority Writes (terms under consideration)
Candidates for formalizing authority scoping across agent sessions. Not yet canon; surfaced here so the terminology can be evaluated before it ships.

The Semantic-Gap Frontier (named, not solved)
ZLAR governs routed execution. It does not yet govern meaning across sequences, reformulations, and indirect effect. A chain of individually low-risk actions can produce a consequential result without any single decision crossing the threshold. A technically accurate ask can be cognitively misleading to the human. An effect can be reached through paths the rule set does not recognize. Digest and witness detect; they do not enforce. Sequence-aware enforcement is the next maturity layer, not a shipped capability. The layer is named here so it is not absorbed silently into the constitutional or policy layers, which are structurally different problems.

—

11. Category Definition

What ZLAR is
A deterministic governance layer that sits on the contact boundary between autonomous agents and the world, enforces signed policy with human authority routed when policy calls for it, produces verifiable receipts, and refuses to load policy that violates its signed constitution. Infrastructure, not a platform. Apache 2.0.

What ZLAR is not
Not monitoring. Not trust scoring. Not AI safety research. Not an agent platform. Not orchestration. Not a compliance dashboard. Not a policy-authoring IDE. Not a product that tries to make agents safer by making them smarter.

Category vocabulary
Governance: the structural constraint on what the agent can do. Monitoring: the observation of what the agent did. Orchestration: the decision of what the agent should do next. ZLAR is governance. Monitoring and orchestration are legitimate but separate categories. Conflating them is the central confusion in the current market.

Governance is not compliance
Compliance is the checkbox that the system met a standard on the day it was audited. Governance is the continuous structural property that the system cannot violate the standard. A system that is compliant today but can be silently non-compliant tomorrow was never governed.

Scope boundary
ZLAR governs actions that cross the contact boundary through the gate. It does not claim software alone can make governance complete. Interception completeness is a deployment property, not a code property: the guarantees attach to routed execution, and the deployment owner is responsible for making the governed surfaces authoritative with sandbox, OS, and network controls. Bypass is not eliminated by declaration; it is made visible as a deployment responsibility. Any vendor in this category that implies otherwise is selling something smaller than what the word governance should mean.

—

12. Strategic Positioning

The compressed position
ZLAR is strongest where the deployment owner can make the governed surfaces authoritative. Within that boundary, it gives deterministic, signed, fail-closed governance of routed execution plus independently verifiable evidence. The unsolved frontier is not signatures or deny logic; it is the semantic gap across sequences, framing, and indirect effect. The position is honest about what it is not as a way of being credible about what it is.

The doctrine is the moat
ZLAR's position is not the codebase — any vendor can write a gate in a quarter. The position is the doctrine: the Three Authority Laws, the Contact Boundary, the deny-first kernel, the refusal to put AI in the enforcement path. The doctrine is what makes the codebase structurally correct. Copying the code without the doctrine produces a system that looks like ZLAR but fails under adversarial conditions.

The combination defines the category ZLAR is trying to make legible
Structural enforcement, routed human authority, cryptographic proof. Each exists in the market separately. The combination is what ZLAR names.

Voice
ZLAR copy is structural, not performative. It describes the governed event, not the agent's intent. It names architectural failures plainly. It does not soften language to avoid making competitors uncomfortable. The mission is to protect human beings; the language serves the mission.

—

13. Governance Literary Canon

Compressed reference to the traditions that inform ZLAR's architecture — named so that future readers can place ZLAR in context. No invariant is credited to any specific tradition; the architecture carries the ideas.

Nuclear command and control: the two-person rule, the permissive action link, the distinction between authority to launch and capability to launch. ZLAR's human-at-the-contact-boundary maps to the launch authority pattern.

Aviation safety: sterile cockpit, checklist, FAA/NASA ASRS dual-track (mandatory reporting of serious events plus voluntary reporting of near-misses with enforcement immunity). ZLAR's receipt chain is the aviation black box applied to agent actions.

Chemical Weapons Convention: the General Purpose Criterion, the schedules, the OCPF inspection regime. Three-layer defense-in-depth mirrors ZLAR's chokepoint stack. The Syria declaration trap is the canonical Voluntary Compliance Error.

Toyota production system (jidoka): the drop wire at the loom, authority asymmetry (wide stop, narrow go), the Andon. ZLAR's deny-first default is jidoka applied to AI.

Nunn-Lugar / Cooperative Threat Reduction: the institutional pattern for dismantling dangerous capability without stopping beneficial capability. Precedent for governance infrastructure adopted across adversarial actors without unilateral disarmament.

—

14. External Standards and Category Context

Anderson's Reference Monitor and Complete Mediation (Saltzer and Schroeder, 1975)
The foundational computer security principle: whatever touches an action first is sovereign over it. If the mediator is not consulted on every access, it is not a reference monitor. ZLAR's gate is the reference monitor for agent actions; whatever-touches-action-first-is-sovereign is complete mediation applied at the contact boundary.

WHO Surgical Safety Checklist analog
The checklist reduced surgical mortality by creating a structural pause: certain things must be verified before the knife touches the patient. ZLAR creates the same structural pause before the agent touches the world. Preparation as enforcement — the sterile field is not a reminder, it is a precondition.

Cedar (AWS policy language)
The policy language ZLAR uses. Chosen for formal verification support, deterministic evaluation, and the absence of procedural constructs that would make policy un-auditable. ZLAR does not extend Cedar; ZLAR compiles to it.

Ed25519, SHA-256, Apache 2.0
Cryptographic and licensing standards ZLAR adopts without modification.

GDPR compatibility
The dual-layer receipt architecture (chain-linkable outer, personal-data-bearing inner) reconciles auditability with the right to erasure. The outer chain is preserved; the inner payload can be redacted on lawful request without breaking chain verifiability.

Category adjacencies (pointers, not equivalences)
Forrester three-plane model (Build / Orchestration / Control): ZLAR sits in Control.
Gartner Guardian Agent category (Feb 2026): ZLAR fits, with the caveat that Gartner's definition admits AI-in-enforcement systems that ZLAR rejects on architectural grounds.
Portable Agent Identity Descriptor (Forrester agent control plane research): maps to the ZLAR manifest.

—

15. Maintenance and Evolution

This file is canon, not history. It is revised when doctrine changes, not when implementation changes. Implementation detail lives in IMPLEMENTATION-TERMS.md. Build lore, historical working names, and superseded framings live in FRAMINGS.md.

Change discipline
A change here is a change to doctrine. It requires explicit justification, review against the Three Authority Laws for consistency, and a dated entry in the revision log. Silent edits are forbidden.

Provenance discipline
No public attribution of any invariant or architectural pattern to a specific philosophical, religious, spiritual, or cultural tradition. The ideas speak for themselves. Labels stay off.

Shipping-status discipline
Every capability is labeled by status when ambiguity is possible. Shipped means live in the gate on origin main. Design, not yet shipped means approved direction without running code. Under consideration means not yet decided. If this file ever reads as though a capability exists when it does not, the file is wrong, not the reader.

Authority over this file
If this file and the live signed artifacts disagree, the artifacts win. Not a hedge — the structural expression of the Third Authority Law applied to ZLAR's own documentation.

—

End of ZLAR DNA. Last updated 2026-04-18.
