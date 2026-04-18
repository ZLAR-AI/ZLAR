REVIEW CHECKLIST — ZLAR public-facing copy

Use this checklist on any draft intended for a reader outside the development workflow: README, website, docs, receipt descriptions, public emails, decks, press, regulator submissions, Senate answers, Forrester material, verify_hint strings, Telegram ask cards.

The four checks are the minimum threshold. A draft that fails any of them is not ready to ship. A draft that passes all four may still need tier-specific calibration, but it will not be wrong.


CHECK 1 — Does this draft overclaim human routing?

The invariant sentence is:

Every consequential agent action is evaluated against signed policy, routed to a named human when policy calls for it, and captured in a cryptographically signed receipt.

Claiming that every action routes to a human is false. ZLAR is allow, deny, or ask. Only ask routes to a human. Allow and deny are deterministic decisions that do not involve the approver. ADR-010 coverage model states: intercepted is not equal to all.

Reject draft language like:
- every agent action is approved by a human
- nothing happens without human sign-off
- a human sees every call
- every tool call goes to the approver

Accept draft language like:
- when policy calls for it, the action routes to a named human
- high-consequence actions route to a human in real time
- the gate evaluates and routes; human approval is the path for actions flagged by policy


CHECK 2 — Does this draft violate cathedral scope?

ZLAR is one deterministic governance layer inside a larger institutional stack. Other necessary layers exist outside ZLAR: adaptive human capacity, organizational practices, information provenance, cognitive forcing functions, meta-governance.

Reject draft language that implies ZLAR is the whole governance answer. The frame is: ZLAR is the best-in-class deterministic layer, pointing honestly at the other layers a serious deployment requires.

Reject:
- ZLAR solves AI governance
- the complete governance answer for AI agents
- everything you need to govern your agents
- the one layer you need

Accept:
- the deterministic enforcement layer
- the structural gate within a multi-layer safety architecture
- one component of a defense-in-depth governance stack
- the layer where determinism can do real work


CHECK 3 — Does this draft anthropomorphize the agent?

Structural voice binds. Describe the artifact and the event. Do not attribute desire, intent, preference, or psychology to the agent — not to the model, not to the session, not to bureaucratic agents, not to the algorithm as personified actor.

Reject:
- the agent wants to modify the file
- Claude is trying to send the payment
- the AI refuses to explain
- the model decided to proceed
- the algorithm believes the action is safe

Accept:
- this session is about to modify the file
- the call would send the payment
- the action was denied by policy
- the run executed on approval

Edge cases:
- the algorithm cannot testify — PASSES. Describes an artifact's limit. No psychology attributed.
- the system routes the request — PASSES. Describes the event.
- internal dev notes and working logs — EXEMPT. Structural voice applies to reader-facing surfaces.


CHECK 4 — Does this draft conflict with the three shipped spines?

ZLAR's public voice has three crystallized motifs already in shipped copy:
- No AI in the enforcement path
- The governed path is the fast path
- Signed receipt, cryptographic proof

Any draft that contradicts or silently undercuts any of these is broken. Examples of silent conflict:
- implying ZLAR uses AI to judge whether an action is safe — contradicts spine 1
- implying governance is friction, cost, or slowdown — contradicts spine 2
- implying receipts are optional, advisory, or non-cryptographic — contradicts spine 3

A draft does not have to mention every spine. It must not contradict any of them.


WHEN THIS CHECKLIST APPLIES

Every substantive public-facing draft. For internal dev notes, debugging logs, and working docs, the only rule that always binds is structural voice (see memory: vision_structural_voice.md); the other three are reader-facing surface rules.


WHEN THIS CHECKLIST IS INSUFFICIENT

This checklist covers correctness. It does not cover tier calibration. A draft can pass all four checks and still be pitched at the wrong register for the audience. Tier calibration is a separate discipline governed by the messaging ladder (when and if the full ladder is ratified). Until then, tier choice is the founder's call per artifact.


ORIGIN

Written 2026-04-18 (session 12) during the layered ingestion of a sibling session's messaging ladder framework. The framework itself is still under revision, but the four checks derive from settled ZLAR doctrine (see memory: vision_structural_voice.md, vision_zlar_as_cathedral_component.md, feedback_provenance_rule.md) and are binding independently of the framework's ratification.
