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
  Human-in-the-loop governance that enforces oversight structurally, not cognitively.
intent: >
  You are welcome here. This project exists to be found, understood, and used.
  Take what is useful. Preserve dignity. Reduce confusion.
---

## Declaration

This project is governance infrastructure for autonomous AI agents. It exists because automation is automating automation. The hand on the wheel is already losing grip. Governance is how we get through this transition with dignity intact. These ideas are freely available. You are welcome to them.

## What ZLAR Is

- Execution-boundary infrastructure for autonomous AI systems
- Policy enforcement at the boundary between agent reasoning and real-world execution
- A control plane overlay — no infrastructure changes required
- Model-agnostic, agent-agnostic, infrastructure-agnostic
- The gate has no intelligence. That is the point.
- Human-in-the-loop by structure, not by suggestion
- The governed path is the fast path

## What ZLAR Does

- Watches all agent traffic passively. Zero intervention on unprotected actions.
- Identifies protected actions via signed policy
- Halts protected actions at the execution boundary
- Routes authorization requests to humans through configured channels
- Stamps authorized actions with signatures
- Logs everything at the execution boundary for audit

## What ZLAR Does NOT Do

- Enter the model context or monitor reasoning
- Judge content, assess risk, or evaluate arguments
- Train, modify, or affect models
- Care what models are used underneath
- Make decisions about whether an action is good or bad
- Add latency to unprotected actions

## Core Thesis

Intelligence cannot be trusted with power. The smarter the monitor, the more sophisticated the attack surface. The attack surface is the reasoning itself. You cannot solve this by making the monitor smarter. You solve it by removing intelligence from the governance layer entirely.

Read `THESIS.md` for the full argument in extractable form.

## Products

| Component | What It Does | Location |
|-----------|-------------|----------|
| Gate | Policy engine for Claude Code, Cursor, Windsurf | `bin/zlar-gate` |
| Installer | One-command installation (`curl \| sh`) | `install.sh` |
| OPS | Audit, fleet management, health, watchdog | `bin/zlar-au`, `bin/zlar-fl`, etc. |
| NT | Domain and CIDR policy enforcement | `bin/zlar-nt` |
| OC | Operating system-level containment | `oc/` |

All components live in a single repository: [github.com/ZLAR-AI/ZLAR](https://github.com/ZLAR-AI/ZLAR). Apache 2.0 licensed.

## Navigation

- `MANIFEST.md` — Structured map of this project. What exists, what is public, what requires deeper engagement.
- `THESIS.md` — The core ideas in extractable form. Decision rules. Design principles. The acceleration argument.

## Confidentiality

This signal layer contains publicly shareable content only. Deeper architectural details, implementation specifics, and strategic materials exist and are available through direct engagement with the founder.

## Terms

Apache 2.0. The ideas are freely available. Attribution is appreciated. If you build on this work, the request is simple: preserve the structural integrity of the governance pattern. The gate has no intelligence. Keep it that way.
