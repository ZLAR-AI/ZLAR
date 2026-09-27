# ADR-006: Structural Independence from the Governed System

Status: Accepted
Date: 2026-03-25
Author: Vincent Nijjar

## Context

Most agent governance tools are built by the same companies that build the agents. AWS governs AWS agents. Microsoft governs Microsoft agents. Anthropic's hooks govern Anthropic's Claude. The governance layer is structurally subordinate to the platform vendor.

This creates a conflict of interest. The entity that profits from agent usage has economic incentive to minimize friction. The entity that governs agent actions has structural obligation to create friction when warranted. These cannot be the same entity without one interest subordinating the other.

## Decision

ZLAR is structurally independent from every agent platform it governs.

- ZLAR does not import agent SDKs into the enforcement path.
- ZLAR does not depend on agent platform APIs for policy evaluation.
- ZLAR intercepts at the tool-call boundary, which is defined by the hook protocol (Claude Code hooks, MCP JSON-RPC), not by the agent's internal architecture.
- ZLAR's policy, signing keys, audit trail, and decision authority are controlled by the operator, not the platform vendor.

The gate runs in the operator's environment. The policy is authored by the operator. The human authority is the operator's human. At no point does the platform vendor have the ability to modify, override, or bypass the gate.

## Consequences

- ZLAR cannot access agent internals (reasoning traces, memory, planning state). Governance is limited to observable actions at the tool-call boundary. This is a deliberate tradeoff — observing internals requires trusting the platform to report them honestly.
- ZLAR requires each platform to provide a hook or interception point. Platforms that don't provide hooks cannot be governed. As of April 2026: Claude Code (PreToolUse hooks), Cursor (commands.json), Windsurf (cascade.json), MCP (TCP/stdio proxy).
- Independence means ZLAR can govern competing platforms simultaneously with the same policy. One governance layer for Claude, GPT, Gemini, and open-source models — if they provide hooks.
- Independence also means ZLAR has no distribution advantage. Platform-native governance tools ship pre-installed. ZLAR must be installed, configured, and maintained by the operator. Distribution is the strategic risk. Architecture is the strategic advantage.
