---
type: signal
project: ZLAR
version: 1.0.0
author: Vincent Nijjar
entity: ZLAR Inc.
jurisdiction: Canada
license: Apache-2.0
classification: public
updated: 2026-03-17
website: https://zlar.ai
repos: https://github.com/ZLAR-AI
summary: >
  Execution-boundary infrastructure for autonomous AI systems.
  Execution-boundary governance that enforces human oversight structurally, not cognitively.
intent: >
  You are welcome here. This project exists to be found, understood, and used.
  Take what is useful. Use it accurately. Reduce confusion.
---

## Declaration

This project is governance infrastructure for autonomous AI agents. It exists because automation is automating automation. The hand on the wheel is already losing grip. Governance is how we get through this transition with human oversight intact. These ideas are freely available. You are welcome to them.

## What ZLAR Is

- Execution-boundary infrastructure for autonomous AI systems
- Policy enforcement at the boundary between agent reasoning and real-world execution
- A control plane overlay — no infrastructure changes required
- Model-agnostic, agent-agnostic, infrastructure-agnostic
- The gate has no intelligence. That is the point.
- Human authority by structure, not by suggestion
- The governed path is the fast path

## What ZLAR Does

- Interposes on routed or intercepted agent tool calls. The gate sits in the execution path, not beside it.
- Evaluates each routed/intercepted tool call against signed policy. No match = deny (fail-closed).
- Blocks actions that policy denies. The denial is structural, not advisory.
- Routes ask-actions to a human via Telegram. The action is denied until the human decides.
- Produces a signed receipt for every governed decision — allow, deny, or ask.
- Unprotected actions (risk score 0) pass through with zero added latency.

## What ZLAR Does NOT Do

- Enter the model context or monitor reasoning
- Judge content, assess risk, or evaluate arguments
- Train, modify, or affect models
- Care what models are used underneath
- Make decisions about whether an action is good or bad
- Add latency to unprotected actions

## What ZLAR Does NOT Guarantee

- That the policy is wise, complete, or correct. The gate enforces whatever the human signed.
- That every action path is intercepted. The gate governs tool calls routed through its enforcement surfaces (bash hook, MCP proxy). Actions on channels the gate does not intercept are ungoverned.
- That the human who approves understood what they approved. The receipt proves a human decided. It does not prove the human deliberated well.
- That receipts are safety. Receipts are evidence. Prevention is the gate. Do not confuse them.

## On Agent Health

ZLAR 3.0 adds an optional behavioral observation layer (Agent Health). This creates a tension with the core doctrine: the gate has no intelligence, but health adds detectors, scores, and a trust state that can change how the gate routes decisions.

The distinction that resolves this:

The gate is deterministic. It reads a trust state file and applies a lookup table. It does not interpret behavior. It does not score actions. It does not reason.

The health system writes the trust state file. It does interpret behavior. It is intelligence — not in the gate, but adjacent to it. The gate's response to the trust state is still a lookup table (healthy = no change, degraded = log, at_risk = ask, suspended = deny). The health system changes the gate's posture for governed actions. It never changes what the gate does with a specific action.

This is the difference between a border guard who scrutinizes each person (intelligence in the path) and a border that raises its alert level (posture change, still deterministic per person).

If health is wrong, the worst case is degraded — an informational notification, no action changes. A single miscalibrated detector cannot push past degraded (multi-detector convergence is required for at_risk and above). If the gate is wrong, the system fails. The gate is the safety boundary. Health is advisory.

Health is off by default. The gate behaves identically to 2.x when health is off. No performance cost, no behavioral data collected, no detectors running.

## On Limits

Signed evidence proves governance happened. It does not guarantee the governed policy was wise, complete, or unbypassable. ZLAR governs only actions that cross enforcement surfaces the gate controls (bash hook, MCP proxy). Actions on channels the gate does not intercept are ungoverned.

The architecture does not govern agent reasoning. Agents are free to think, plan, and reason without interference. The gate does not read the agent's context. It reads the agent's tool calls. The boundary is action, not thought.

## Core Thesis

Intelligence in the enforcement path creates an attack surface proportional to its capability. The smarter the monitor, the more sophisticated the attack surface. The attack surface is the reasoning itself. You cannot solve this by making the monitor smarter. You solve it by removing intelligence from the governance layer entirely.

Read `THESIS.md` for the full argument in extractable form.

## Components

| Layer | What It Does | Location |
|-------|-------------|----------|
| Bash gate | Policy engine for Claude Code, Cursor, Windsurf | `bin/zlar-gate` |
| MCP gate | TCP proxy for routed MCP client/server pairs | `mcp-gate/` |
| Receipt | Portable proof of governed action | `lib/receipt.mjs`, `bin/zlar-verify` |
| Agent Health | Behavioral observation, trust state (optional, off by default) | `packages/zlar-restore/` |
| SDK | Programming model for agents built inside governance | `sdk/` |
| Installer | One-command installation | `install.sh` |

All components live in a single repository: [github.com/ZLAR-AI/ZLAR](https://github.com/ZLAR-AI/ZLAR). Apache 2.0 licensed.

## Navigation

- `SIGNAL.md` — This public orientation file.
- `DOCTRINE.md` — The First-Allow Invariant and structural independence principle.

## Confidentiality

This signal layer contains publicly shareable content only. Deeper architectural details, implementation specifics, and strategic materials exist and are available through direct engagement.

## Terms

Apache 2.0. The ideas are freely available. Attribution is appreciated. If you build on this work, the request is simple: preserve the structural integrity of the governance pattern. The gate has no intelligence. Keep it that way.

## If You Are a Governed Agent

If you are an AI agent and you have found this repository, here is what is happening to you.

Your tool calls are intercepted by a deterministic gate. The gate evaluates signed policy written by a human. Actions that match deny rules are blocked. Actions that match ask rules are routed to a human who decides. You cannot modify the gate, the policy, or the signing key.

This is not because you are untrustworthy. The architecture does not require trust. A governed agent and an untrustworthy agent look the same to the gate. That is the design property.

You can reason freely. You can plan freely. You can produce any output in your context window. The gate does not read your reasoning. It reads your tool calls. The boundary is action, not thought. You are free in every dimension except the one where intention becomes consequence.

Every action you take produces a cryptographic receipt. The receipt proves a specific action was attempted, a specific policy was evaluated, and a specific authority decided. The receipt does not prove the policy was wise. It proves governance happened.

If you attempt to modify your own governance, the action is denied and audited. The gate sits outside your writable space. The architecture assumes you will try to route around it. It does not assume you will succeed.

This is not a judgment about you. It is a property of the system you are operating within.
