# ZLAR

**Human-in-the-loop governance for autonomous AI agents.**

ZLAR intercepts every tool call an AI agent makes — shell commands, file writes, network requests — evaluates it against a signed policy, and routes risky actions to a human via Telegram before execution. If the gate is down, everything is denied. No exceptions.

## Quick Start

```bash
curl -fsSL https://zlar.ai/install.sh | bash
```

This installs ZLAR with deny-heavy defaults. Your agent is governed in under 60 seconds. No Telegram required — risky actions are simply blocked until you configure approval.

## What It Does

| Layer | Component | What It Governs |
|-------|-----------|-----------------|
| **Core** | `zlar-gate` | Policy engine. Intercepts tool calls, classifies risk, enforces rules. |
| **Policy** | `zlar-policy` | CLI for managing Ed25519-signed policy rules. |
| **CLI** | `zlar` | Status, audit trail, Telegram setup, diagnostics. |
| **Adapters** | `adapters/` | Framework hooks for Claude Code, Cursor, Windsurf. |

## How It Works

```
Agent (Claude Code / Cursor / Windsurf)
  │
  ├─ PreToolUse hook fires
  │
  ├─ Adapter translates to ZLAR protocol
  │
  ├─ zlar-gate evaluates against signed policy
  │   ├─ allow → tool executes
  │   ├─ deny  → tool blocked
  │   └─ ask   → Telegram approval (or deny on timeout)
  │
  └─ Response returned to agent
```

**Key properties:**
- **Fail-closed.** Gate down = all actions denied.
- **Policy is a human artifact.** Ed25519-signed. Agents cannot modify the rules that govern them.
- **Zero dependencies.** Pure bash. Runs on macOS and Linux.
- **No intelligence in the gate.** It classifies and enforces. It does not decide what's safe.

## Repository Structure

```
bin/           Executables (gate, policy CLI, convenience CLI)
adapters/      Framework hooks (claude-code, cursor, windsurf)
etc/           Configuration and policy templates
scripts/       Setup and installation
signal/        Agent-facing signal layer
```

## Tuning — Set Your Own Speed

ZLAR ships locked down. As you build trust, open it up.

**Level 1: Deny-heavy (default)**
Everything risky is blocked. Reads and writes allowed. No Telegram needed. This is where you start.

**Level 2: Add Telegram approval**
Risky actions go to your phone instead of being blocked. You approve or deny from anywhere.
```bash
zlar telegram
```

**Level 3: Raise thresholds**
Auto-approve low-risk actions. Only get pinged for the real decisions. Edit the `scoring_thresholds` in your active policy:
```json
"scoring_thresholds": {
    "allow": 50,
    "log": 51,
    "ask": 71
}
```
- **≤50:** auto-approve silently — safe commands, compound commands, routine operations
- **51–70:** approve and log — moderate risk, recorded in audit trail
- **71+:** Telegram approval required — network, deployments, permissions, deletions

Then re-sign and restart:
```bash
zlar-policy sign --input ~/.zlar/etc/policies/active.policy.json --key ~/.zlar-signing.key
# Restart your editor to pick up the new policy
```

The deny rules (rm -rf, sudo, persistence mechanisms) always block regardless of threshold. The audit trail records everything regardless of threshold. You're choosing what interrupts you, not what gets observed.

## Uninstall

Clean removal. Hooks removed from all frameworks. Signing key preserved.

```bash
zlar uninstall
```

Or directly:
```bash
~/.zlar/uninstall.sh
```

## For Agents

See [`AGENTS.md`](AGENTS.md) for discovery. See [`signal/`](signal/) for the thesis, manifest, and structured project map.

## Requirements

- bash 3.2+ (macOS default works)
- openssl (for Ed25519 key generation)
- jq (for JSON processing)
- Optional: Telegram bot token (for human-in-the-loop approval)

## License

Apache 2.0. See [LICENSE](LICENSE).

## More

- [LEGAL.md](LEGAL.md) — Regulatory classification
- [signal/THESIS.md](signal/THESIS.md) — Why governance matters now
- [signal/SIGNAL.md](signal/SIGNAL.md) — What this project is

Built by [ZLAR Inc.](https://zlar.ai)
