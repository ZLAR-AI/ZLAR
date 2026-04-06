# ZLAR

[![CI](https://github.com/ZLAR-AI/ZLAR/actions/workflows/ci.yml/badge.svg)](https://github.com/ZLAR-AI/ZLAR/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CodeQL](https://github.com/ZLAR-AI/ZLAR/actions/workflows/codeql.yml/badge.svg)](https://github.com/ZLAR-AI/ZLAR/actions/workflows/codeql.yml)

**ZLAR is a deterministic execution governance layer for AI agents.**

It intercepts agent tool calls, evaluates them against signed policy, routes decisions to humans when required, and produces cryptographic proof that governance happened. No AI in the enforcement path. The gate pattern-matches. It cannot be persuaded.

## What ZLAR Is

- A gate that sits between the agent and real-world actions
- Deterministic policy enforcement — regex matching, not reasoning
- Human-in-the-loop escalation via Telegram (approve/deny from your phone)
- Hash-chained, Ed25519-signed audit trail on every decision
- Governed Action Receipts — portable proof that an action was governed
- Framework-agnostic: Claude Code, Cursor, Windsurf, any MCP client

## What ZLAR Is Not

- Not a monitoring dashboard that watches after the fact
- Not an AI that judges whether an action "seems safe"
- Not a trust scoring system that builds a reputation for agents
- Not a sandbox — it governs the decision, not the execution environment
- Not tied to any model provider — the entity that sells agents cannot credibly govern them

## Quick Start

```bash
git clone https://github.com/ZLAR-AI/ZLAR.git
cd ZLAR && bash install.sh
```

Installs with deny-heavy defaults. Your agent is governed in under 60 seconds.

```bash
~/.zlar/bin/zlar doctor    # verify everything works
~/.zlar/bin/zlar status    # see what's governed
```

Add human approval via Telegram: `~/.zlar/bin/zlar telegram`

Something not working? See [Troubleshooting](docs/troubleshooting.md) or run `zlar doctor`.

## How It Works

```
Agent issues tool call (shell command, file write, API request)
  |
  +-- Gate intercepts at execution boundary
  |
  +-- Loads Ed25519-signed policy (agents cannot modify their own rules)
  |
  +-- Evaluates: which rule matches?
  |   +-- allow  -> tool executes, audit entry + receipt written
  |   +-- deny   -> tool blocked, audit entry + receipt written
  |   +-- ask    -> human notified via Telegram, agent waits
  |               +-- human approves -> executes, receipt records "authorized by human"
  |               +-- human denies   -> blocked, receipt records "denied by human"
  |               +-- timeout        -> blocked (fail-closed, silence is not consent)
  |
  +-- Hash-chained audit entry records the decision
  +-- Governed Action Receipt provides portable proof
```

Two enforcement surfaces share the same policy and audit trail:

- **Bash gate** (`bin/zlar-gate`) — hooks into Claude Code, Cursor, Windsurf. Pure bash. Zero dependencies beyond jq and openssl.
- **MCP gate** (`mcp-gate/gate.mjs`) — TCP proxy between any MCP client and server. Intercepts `tools/call` JSON-RPC messages. Per-entry Ed25519 signing, policy signature verification, standing approvals.

The agent does not volunteer to be governed. It is governed by architecture.

## The Governed Action Receipt

The receipt is the portable proof that a governed action was evaluated by deterministic policy and decided by the stated authority.

```bash
# Generate a receipt from an audit event
bin/zlar-receipt --last --key ~/.zlar-signing.key --pubkey ~/.zlar-signing.pub

# Verify it — anyone with the public key can do this
bin/zlar-verify receipt.json --pubkey key.pub
```

```
VALID

Signature valid. Action "Bash" in domain "file" was deny by policy at 2026-04-05T21:00:00.000Z.
```

A receipt proves:
1. A specific action was attempted by an AI agent
2. Deterministic policy was evaluated against that action
3. The decision was made by the stated authority (policy rule or human)
4. The record has not been tampered with since creation
5. The receipt is anchored to the audit hash chain

Receipts are cross-gate compatible — a bash-gate receipt verifies with the Node.js verifier and vice versa. The detail is hashed, not exposed — you can share a receipt with an auditor without revealing the command.

## The Audit Trail

Every gate decision writes a hash-chained, Ed25519-signed audit entry:

```json
{
  "ts": "2026-04-05T09:14:22Z",
  "agent_id": "claude-code",
  "domain": "file",
  "action": "git push origin main",
  "outcome": "denied",
  "rule": "R014",
  "authorizer": "human:7662799203",
  "prev_hash": "a1b2c3...",
  "signature_algorithm": "Ed25519",
  "signature": "mOiZF8E3MKFeyuRw..."
}
```

- **`authorizer: "human:7662799203"`** — a specific human made this decision. Non-repudiable.
- **`prev_hash`** — SHA-256 of the previous entry. Tamper with any record and every subsequent hash breaks.
- **`signature`** — Ed25519 over SHA-256 of the canonical entry. Every entry is individually signed.

This is not the agent's account of what it did. This is the infrastructure's record of what happened.

## Why Deterministic

If the enforcement layer uses intelligence, the enforcement layer can be attacked with intelligence. If the enforcement layer is deterministic, the only attack is against the policy itself — which is a human artifact, signed with Ed25519, stored outside agent context. The absence of intelligence in the gate is the security property.

An enforcement layer that uses reasoning to evaluate actions can be subverted by reasoning-based attacks. The enforcement layer's capability becomes its vulnerability.

## What the Gate Does Not Protect Against

- **Compromised signing key** — an attacker with the key can sign a permissive policy. Mitigation: key never lives on the agent's machine. Rotation invalidates prior signatures.
- **Compromised gate binary** — if replaced, all enforcement is lost. Mitigation: R012 blocks agents from modifying their own governance. Host-level IDS is the defense layer below the gate.
- **Actions the gate cannot see** — channels that bypass the hook or proxy. The gate governs tool calls. OS-level containment governs everything else.

A security tool should state its own boundaries, not just its competitors' failures.

## Architecture

| Layer | Component | What it does |
|-------|-----------|-------------|
| **Enforcement** | `zlar-gate` | Policy engine. Intercepts tool calls, classifies, evaluates signed rules, writes audit trail and receipts. |
| **Enforcement** | `mcp-gate` | TCP proxy for MCP. Same policy, same audit format, per-entry signing, standing approvals. |
| **Evidence** | `lib/receipt.mjs` | Governed Action Receipt generation and verification. Cross-gate compatible. |
| **Evidence** | `bin/zlar-verify` | Standalone receipt verifier. Anyone can verify with just the public key. |
| **Observation** | `zlar-witness` | Sequence detection from audit trail. Detected, not enforced. |
| **Observation** | `zlar-digest` | Governance summary. Decisions, latency, sequences, novelty. |
| **Identity** | `zlar-agents` | Per-agent policy bindings, standing approvals, delegation depth limits. |
| **Identity** | Agent manifest | Capability boundary per agent. Narrows policy, never widens. ([Invariants](docs/MANIFEST-INVARIANTS.md)) |
| **Policy** | `zlar-policy` | CLI for Ed25519-signed policy rules. Keygen, sign, verify. |
| **Session** | `lib/session-state.sh` | Velocity, loop detection, denial bursts. Thin counters, not reasoning. |
| **Human** | `lib/human-invariants.sh` | Protects the human: decision cap (H6), deliberation floor (H15), approval rate monitoring (H14), capacity tracking (H13), authenticity checks (H17). |
| **Adapters** | `adapters/` | Framework hooks for Claude Code, Cursor, Windsurf. |

## Running Tests

```bash
# Core governance
bash tests/test-receipt.sh             # Receipt generation and cross-gate verification
bash tests/test-manifest.sh            # Manifest CLI and schema invariants
bash tests/test-agent-identity.sh      # Agent identity, risk tiers, authorization levels
bash tests/test-human-invariants.sh    # Human invariant enforcement (H6, H13, H14, H15, H17)
bash tests/test-perimeter-closure.sh   # Policy rules, sandbox, path sanitization
bash tests/test-crypto.sh              # Cryptographic abstraction layer
bash tests/test-session-state.sh       # Session counters
bash tests/test-standing-approvals.sh  # Standing approval matching
bash tests/test-approval-binding.sh    # Approval binding (action fingerprint)
bash tests/test-inbox-hmac.sh          # Inbox HMAC verification
bash tests/test-doctor.sh              # Installation health checks

# Canonicalization (cross-language verification)
node tests/test-canonicalization.mjs   # 28 test vectors + validation + edge cases
python3 tests/verify-canonicalization.py  # Python cross-language verification

# MCP gate, receipts, and Cedar (200+ assertions)
node mcp-gate/test-hardened.mjs        # Policy verification, signing, fail-closed, standing approvals
node mcp-gate/test-receipt.mjs         # Receipt generation, verification, delegation chains
node mcp-gate/test-cedar.mjs           # Cedar P1/P2 rules, gate action mapping, cross-engine regression

# Cedar policy verification
node cedar-poc/test.mjs                # Cedar base rules
node cedar-poc/test-e23.mjs            # Cedar E-23 risk-tiered governance
```

## Requirements

- bash 3.2+ (macOS default)
- jq (JSON processing)
- openssl 3.x (Ed25519 signing — Homebrew on macOS)
- Optional: Telegram bot token (human approval)
- Optional: Node.js 18+ (MCP gate, receipt verification)

## Repository Structure

```
bin/           Gate, receipt tools, witness, digest, registry, policy CLI
lib/           Shared libraries (crypto, session state, agent identity, receipt, human invariants)
adapters/      Framework hooks (claude-code, cursor, windsurf)
mcp-gate/      MCP TCP proxy gate (Node.js)
etc/           Policy, manifests, signing keys, standing approvals, receipt schema
tests/         Test suites (10 bash + 5 Node.js, 470+ assertions)
docs/          Architecture decisions, manifest invariants, operations
docs/adr/      Architecture Decision Records
signal/        Agent-facing signal layer (thesis, origin, proof)
cedar-poc/     Cedar formal policy verification
```

## Design Decisions

Architectural choices are documented as ADRs:

| ADR | Decision |
|-----|----------|
| [001](docs/adr/ADR-001-deterministic-enforcement.md) | Deterministic enforcement, not AI |
| [002](docs/adr/ADR-002-bash-implementation.md) | Bash as implementation language |
| [003](docs/adr/ADR-003-fail-closed.md) | Fail-closed as default |
| [004](docs/adr/ADR-004-ed25519-signing.md) | Ed25519 for signing |
| [005](docs/adr/ADR-005-manifest-narrows-policy.md) | Manifest narrows policy, never widens |
| [006](docs/adr/ADR-006-structural-independence.md) | Structural independence from governed system |

## Further Reading

- [docs/troubleshooting.md](docs/troubleshooting.md) — Common issues and fixes
- [GOVERNANCE.md](GOVERNANCE.md) — How decisions are made, how invariants are amended
- [SECURITY.md](SECURITY.md) — Vulnerability disclosure, security principles
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
- [ADOPTERS.md](ADOPTERS.md) — Who is using ZLAR
- [LEGAL.md](LEGAL.md) — Regulatory classification, liability, data processing
- [signal/THESIS.md](signal/THESIS.md) — Why intelligence in the monitor fails
- [signal/ORIGIN.md](signal/ORIGIN.md) — Why ZLAR exists
- [signal/PROOF.md](signal/PROOF.md) — No unauthorized action can execute on the governed path

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [ZLAR Inc.](https://zlar.ai)
