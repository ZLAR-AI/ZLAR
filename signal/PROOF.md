---
type: proof
project: ZLAR
version: 1.0.0
author: Vincent Nijjar
classification: public
date: 2026-04-01
verification: All claims reference specific lines in bin/zlar-gate (Gate v2.5.1)
summary: >
  On the governed path, no unauthorized action can execute.
  Proof by exhaustive case analysis against source code.
---

## Claim

On a path governed by the ZLAR gate, no action can execute without human authorization.

This is not a statistical claim. It is a structural claim. It does not say unauthorized actions are unlikely. It says they are impossible — within a precisely defined boundary.

## Definitions

**Governed path.** An action is on the governed path when it passes through a ZLAR gate — either the PreToolUse hook (for Claude Code, Cursor, Windsurf) or the MCP TCP proxy (for any MCP-connected agent). If an action does not pass through the gate, the gate has nothing to enforce. The boundary of the governed path is defined in [What this proof does not cover](#what-this-proof-does-not-cover).

**Human authorization.** An action is human-authorized if either: (a) a human signed the policy rule that permits it, using an Ed25519 private key the agent does not possess, or (b) a human explicitly approved it in real time via Telegram, and the approval is cryptographically bound to the exact action requested.

**The gate.** `bin/zlar-gate` — a bash script with no model inference, no reasoning, no intelligence. It reads a tool call from stdin, evaluates it against a signed policy, and writes a JSON response to stdout: allow or deny. That is all it does.

## Proof

The gate has exactly five terminal states. Every tool call reaches exactly one of them.

### State 1: Policy says deny

The policy rule matching the tool call specifies `action: deny`.

The gate blocks the action immediately. No Telegram message. No human decision needed. The policy — signed by a human with an Ed25519 key — pre-determined that this class of action is not permitted.

*Source: `bin/zlar-gate` line 301 — `respond_deny()` emits `permissionDecision: "deny"`. The action never executes.*

### State 2: Policy says allow

The policy rule matching the tool call specifies `action: allow`.

The gate permits the action. The policy — signed by a human with an Ed25519 key — pre-determined that this class of action is permitted. The human authorized it at the time they signed the policy.

*Source: `bin/zlar-gate` line 251 — `respond_allow()` emits `permissionDecision: "allow"`.*

### State 3: Policy says ask — human decides

The policy rule specifies `action: ask`. The gate sends a message to the human via Telegram and denies the action while waiting. The agent is told to retry after the human decides.

The gate denies immediately upon sending the ask. No action executes while pending.

*Source: `bin/zlar-gate` line 1468 — `respond_deny "Awaiting Telegram approval"`. The command is blocked on first contact.*

On retry, the gate checks for a human response. Four sub-cases:

**3a. Human approves.** The gate finds an approval callback file. Before allowing, it verifies the SHA-256 action hash matches the exact tool call — `rule|tool_name|detail` (line 1429). If the hash matches, the action is allowed. The human explicitly authorized this specific action.

**3b. Human denies.** The gate finds a denial callback. The action remains blocked.

**3c. Human does not respond.** The pending file ages past the configured timeout (default 300 seconds, line 199). The gate treats expiry as denial (line 1037-1039). The action remains blocked.

**3d. Approval hash mismatch.** If the approval was for a different action, the SHA-256 hash will not match (line 992-993). The approval is rejected. The action remains blocked.

### State 4: Ask fails — Telegram unreachable

The gate attempts to send a Telegram message and fails. This covers: no Telegram token configured (line 1052), API call failure (line 1116), or any other send error.

The gate denies the action with "Could not reach human for approval."

*Source: `bin/zlar-gate` lines 1474-1476 — the `*` case in the `send_result` handler: `respond_deny "Could not reach human for approval"`.*

The action never executes. The gate does not fall back to allowing. It does not assume the human would have approved. If the human cannot be reached, the answer is no.

### State 5: Gate crashes

Any unhandled error in the gate triggers the ERR trap.

*Source: `bin/zlar-gate` lines 38-49:*

```bash
set -euo pipefail
trap '_gate_crash $LINENO' ERR

_gate_crash() {
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse",
           "permissionDecision":"deny",
           "permissionDecisionReason":"ZLAR gate crash (line ...)"}}'
    exit 0
}
```

The trap outputs a valid deny response and exits cleanly. The action is blocked. The crash is logged.

`exit 0` is deliberate: Claude Code's hook runner interprets non-zero exit as "non-blocking error, continue" (fail-open). By exiting 0 with a deny payload, the gate ensures its crash produces a valid blocking response that the hook runner respects.

### State 0: No rule matches

If no policy rule matches the tool call, the gate applies the default action. The default is deny.

*Source: `bin/zlar-gate` line 666 — `POLICY_DEFAULT_ACTION=$(jq -r '.default_action // "deny"')`.*

If the policy file does not specify a default, the fallback is deny. The gate is closed until a human opens it.

## The policy cannot be modified by the agent

The policy file is Ed25519-signed. The gate verifies the signature at load time using the public key.

*Source: `bin/zlar-gate` lines 651-660 — signature verification via `zlar_crypto_verify()`. If verification fails: `return 1`, which under `set -e` triggers the ERR trap, which denies.*

An agent cannot write a permissive policy and have the gate enforce it, because the agent does not possess the Ed25519 private key. The key never lives on the agent's machine. The key is held by the human.

## The gate cannot be persuaded

The gate performs four operations: pattern matching (regex, prefix, contains, exact), comparison (numeric thresholds), lookup (session counters), and timestamp arithmetic (timeout calculation). It does not perform inference, interpretation, or reasoning. It has no language model. It has no prompt. It has no context window. It has no objective function.

Persuasion requires a reasoning target. The gate has none. This is not a limitation. It is the design.

## Summary

| State | Condition | Outcome |
|-------|-----------|---------|
| **0** | No rule matches | Default action = deny |
| **1** | Rule: deny | Blocked immediately |
| **2** | Rule: allow | Allowed — human pre-authorized via signed policy |
| **3a** | Rule: ask → human approves (hash match) | Allowed — human explicitly authorized |
| **3b** | Rule: ask → human denies | Blocked |
| **3c** | Rule: ask → human does not respond | Blocked (timeout = deny) |
| **3d** | Rule: ask → approval hash mismatch | Blocked |
| **4** | Rule: ask → Telegram unreachable | Blocked |
| **5** | Gate crashes | Blocked (ERR trap) |

In every state, either a human authorized the action, or the action was blocked. There is no state in which an unauthorized action executes.

## What this proof does not cover

A proof that does not state its own boundaries is not a proof. It is marketing.

**The hook runner.** The ZLAR gate sits inside a host framework's hook system (Claude Code, Cursor, Windsurf). If the hook process is killed by the operating system before the ERR trap fires, or if it exceeds the framework's timeout (310 seconds for Claude Code), the host framework fails open — the action proceeds without gate evaluation. This is a documented design choice in the host framework, not a property of the gate. The gate's ERR trap (State 5) mitigates this for all crashes that occur within the process. The timeout gap cannot be closed from outside the host framework. We have formally requested that Anthropic add a fail-closed configuration option for PreToolUse hooks.

**Channels outside the governed path.** If an agent accesses resources through a channel that does not pass through the gate — direct filesystem access outside tool calls, out-of-band network requests, or execution paths the hook system does not intercept — the gate cannot enforce. OS-level containment (sandboxing, network policy, filesystem permissions) is the defense layer below the gate. The gate governs tool calls. The operating system governs everything else.

**Compromised signing key.** If the Ed25519 private key used to sign policies is stolen, an attacker can sign a permissive policy. Mitigation: the key never resides on the agent's machine. Key rotation invalidates all prior signatures. The `public_key_id` field in every audit entry ties evidence to a specific key era.

**Compromised gate binary.** If the gate script itself is replaced with a permissive version, enforcement is lost. Rule R012 in the default policy blocks agents from modifying their own governance infrastructure. External integrity monitoring (filesystem checksums, host-level intrusion detection) is the defense layer below R012.

**Human error in policy design.** The gate enforces the policy exactly as signed. If a human signs a policy that allows dangerous actions, the gate will allow those dangerous actions. The gate checks authorization, not judgment. The quality of governance is bounded by the quality of the policy.

**Human error in real-time approval.** If a human approves an action they should have denied, the gate allows it. The gate enforces the human's decision. It does not second-guess the human. The approval is bound to the exact action (SHA-256 hash), so the human approves precisely what executes — but the human must exercise judgment.

## What this proof means

On the governed path, the gate is a deterministic function from (tool call, signed policy, human decision) to (allow, deny). The function has no intelligence. It has no attack surface for reasoning-based attacks. It cannot be prompt-injected, context-drifted, or persuaded, because it does not reason.

This is the structural argument: if the enforcement layer uses intelligence, the enforcement layer can be attacked with intelligence. If the enforcement layer is deterministic, the only attacks are against the policy (a human artifact, signed with Ed25519, stored outside agent context) or against the infrastructure below the gate (the operating system, the hook runner, the hardware). Those attacks exist. They are real. They are documented above. But they are a fundamentally different class of attack than reasoning-based persuasion — and they have well-understood mitigations.

The absence of intelligence in the gate is not a limitation. It is the security property.

## Verification

Every claim in this document references specific lines in [`bin/zlar-gate`](../bin/zlar-gate) (Gate v2.5.1, commit `21a548d`). The source code is Apache 2.0 licensed and publicly available at [github.com/ZLAR-AI/ZLAR](https://github.com/ZLAR-AI/ZLAR). Every claim can be independently verified by reading the source.

If you find a path through the gate where an unauthorized action executes, that is a security vulnerability. Please report it to security@zlar.ai.
