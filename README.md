# ZLAR

[![CI](https://github.com/ZLAR-AI/ZLAR/actions/workflows/ci.yml/badge.svg)](https://github.com/ZLAR-AI/ZLAR/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CodeQL](https://github.com/ZLAR-AI/ZLAR/actions/workflows/codeql.yml/badge.svg)](https://github.com/ZLAR-AI/ZLAR/actions/workflows/codeql.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12381/badge)](https://www.bestpractices.dev/projects/12381)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ZLAR-AI/ZLAR/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ZLAR-AI/ZLAR)
[![GitHub release](https://img.shields.io/github/v/tag/ZLAR-AI/ZLAR?label=release&sort=semver)](https://github.com/ZLAR-AI/ZLAR/releases)
[![Tests](https://img.shields.io/badge/tests-1055_assertions-brightgreen)](https://github.com/ZLAR-AI/ZLAR#running-tests)

**ZLAR is a deny-first governance kernel for AI agents.**

It intercepts agent tool calls, evaluates them against signed policy, routes decisions to humans when required, and produces cryptographic proof that governance happened. No AI in the enforcement path. The gate pattern-matches. It cannot be persuaded.

## What ZLAR Is

- A gate that sits between the agent and real-world actions
- Deterministic policy enforcement — regex rules or Cedar formal policy, never reasoning
- Human-in-the-loop escalation via Telegram (approve/deny from your phone)
- Hash-chained, Ed25519-signed audit trail on every decision
- Governed Action Receipts — portable proof that an action was governed, with semantic validation beyond the signature check
- SDK membrane — a programming model where agents cannot be constructed without a live gate connection
- Cryptographic delegation chains for multi-agent systems
- Framework-agnostic: Claude Code, Cursor, Windsurf, any MCP client, AuthZEN 1.0 PDP interface

### ZLAR 3.0: Agent Health (optional)

ZLAR 3.0 adds restorative governance — behavioral observation that detects when an agent may be drifting and brings the human back into the loop. Eight detectors evaluate session traces and produce a trust state. The gate consults the trust state and may escalate actions to human review.

Ships disabled by default. Enable with one command:

```bash
zlar health on    # generates keys, enables monitoring, signs config
zlar health off   # disables, signs config — no behavioral data accessed
```

The gate behaves identically to 2.x when health is off. No performance cost, no behavioral data collected, no detectors running.

## What ZLAR Is Not

- Not a monitoring dashboard that watches after the fact
- Not an AI that judges whether an action "seems safe"
- Not a trust scoring system that builds a reputation for agents
- Not a sandbox at the architectural level — ZLAR governs the decision, not the execution environment. Optional macOS Seatbelt wrapping is available as a containment layer below the gate when `etc/sandbox/` profiles are present
- Not tied to any model provider — the entity that sells agents cannot credibly govern them

## For different readers

- **The product in 90 seconds**: [`docs/the-moment.md`](docs/the-moment.md) — what it feels like to be in the loop.
- **Implementers**: [`spec/governed-action-receipt-v1.md`](spec/governed-action-receipt-v1.md) — build a compatible receipt producer or verifier in an afternoon.
- **If an agent took an action that affected you**: [`docs/if-an-agent-affected-you.md`](docs/if-an-agent-affected-you.md) — how to find, verify, and contest.

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
  |   +-- ask    -> human notified via Telegram, action denied immediately
  |               +-- agent retries  -> gate checks for human response
  |               +-- human approved -> executes on retry, receipt records "authorized by human"
  |               +-- human denied   -> blocked on retry, receipt records "denied by human"
  |               +-- no response    -> blocked (fail-closed, silence is not consent)
  |
  +-- Hash-chained audit entry records the decision
  +-- Governed Action Receipt provides portable proof
```

Two enforcement surfaces share the same policy and audit trail:

- **Bash gate** (`bin/zlar-gate`) — hooks into Claude Code, Cursor, Windsurf. Pure bash. Zero dependencies beyond jq and openssl.
- **MCP gate** (`mcp-gate/gate.mjs`) — TCP proxy between any MCP client and server. Intercepts `tools/call` JSON-RPC messages. Per-entry Ed25519 signing, policy signature verification, standing approvals. Evaluates JSON regex policy by default; can evaluate Cedar formal policy when `ZLAR_POLICY_ENGINE=cedar` or `=both`.

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

Signatures alone are not enough. Every signed-payload system that skipped semantic validation got burned: X.509 basicConstraints bypasses (24 years), JWT algorithm confusion (11 years), SAML wrapping attacks (14 years). ZLAR runs a semantic validator (`lib/semantic-validator.mjs`) after signature verification and before trust — cross-field invariants that signatures cannot check: rule-outcome consistency (deny-only rules cannot produce allow), authorizer-outcome coherence (a policy authorizer cannot produce an "authorized" outcome; that requires a human), delegation chain integrity, and temporal bounds. Signatures prove the bytes haven't changed. Semantic validation proves those bytes make sense.

## Why Governance Is External

A language model's output is a function of its input context. There is no architectural layer between observation and response where a language model can decide to ignore information. Every token in the context window mechanically shapes the next token produced. This is the transformer architecture, not a character trait.

Human operators have a dampening layer — deliberation happens in a layer architecturally separable from receipt. The language model does not. A language model cannot reliably be asked to behave identically when observed and when unobserved, because any governance state in its context shapes its outputs.

ZLAR places governance outside the model's processing path. The gate evaluates tool calls before the model's next turn. The audit trail records what happened. Agent Health writes trust state that the gate consults through a static lookup table. Governance state is never injected into the model's context window.

The model's behavior is constrained by what it is allowed to do, not by what it knows is being monitored. External integrity substitutes for internal integrity the model does not have. This is the architectural reason governance cannot be built by putting intelligence in the enforcement path: intelligence in the governance layer can be persuaded by intelligence in the governed layer.

## First-Allow Invariant

The first component in the call chain that can return "allow" must be outside the governed agent's writable or influenceable space. If the agent can modify, disable, or redirect that first-allow point, governance is cosmetic — the agent has not been governed, it has been presented with a governance-shaped surface it can route around.

The full principle is documented in [`signal/DOCTRINE.md`](signal/DOCTRINE.md). [`signal/PROOF.md`](signal/PROOF.md) is a line-referenced proof by exhaustive case analysis that no unauthorized action can execute on a gate-governed path. [ADR-006](docs/adr/ADR-006-structural-independence.md) sets out why the entity that sells agents cannot credibly govern them.

## What the Gate Does Not Protect Against

- **Compromised signing key** — an attacker with the key can sign a permissive policy. Mitigation: key never lives on the agent's machine. Rotation invalidates prior signatures.
- **Compromised gate binary** — if replaced, all enforcement is lost. Mitigation: R012 blocks agents from modifying their own governance. Host-level IDS is the defense layer below the gate.
- **Actions the gate cannot see** — channels that bypass the hook or proxy. The gate governs tool calls. OS-level containment governs everything else.

A security tool should state its own boundaries, not just its competitors' failures.

## OSFI E-23 — Canadian Model Risk Management

**Status**: `cedar-poc/e23.cedar` is a complete, schema-validated Cedar ruleset for OSFI Guideline E-23 (Model Risk Management, effective May 1, 2027). It is **not in the default MCP gate load path**. Using it as a runtime enforcement layer requires extending `lib/cedar-evaluator.mjs` to populate the extended ToolCall fields from application input, and loading `e23.cedar` alongside the base rules. This wiring is tracked for v2.8. Validation is exercised by `cedar-poc/test-e23.mjs` against its own schema.

The ruleset implements ten rules. Each cites a specific E-23 principle.

**What the ruleset covers**:

- **Kill switches** (KS-001, KS-002) — burst-denial detection, and autonomous-action blocks in production below a configurable confidence threshold. E-23 Principle 2.3.
- **Position limits** (PL-001, PL-002, PL-003) — tier-based caps, absolute caps, counterparty validation against hallucinated account numbers. E-23 Principle 2.3.
- **Pre-execution checks** (PEC-001, PEC-002, PEC-003) — risk-tiered access; Tier 1 agents restricted to read-only actions. E-23 Principle 2.2.
- **Environment gates** (EC-001) — broader thresholds in dev/staging, tighter in production. E-23 Principle 3.4.
- **Third-party model controls** (TP-001) — unidentified models treated as Tier 1 regardless of declared tier. E-23 Principle 3.6.

The schema extends the base Cedar model with bank-risk vocabulary (`risk_tier`, `amount`, `counterparty`, `is_irreversible`, `confidence`, `session_deny_count`).

## SDK: Agents Built Inside Governance

The bash and MCP gates intercept agents from outside. The SDK membrane (`@zlar/sdk`, `sdk/membrane/`) is a programming model in which agents are constructed inside governance — not wrapped by it.

```javascript
import { ZlarAgent, ZlarDeniedError } from '@zlar/sdk';

// If the gate daemon is unreachable, construction throws.
// There is no code path that produces an ungoverned agent instance.
const agent = await ZlarAgent.connect({ agentId: 'my-agent' });

// Every tool call evaluates policy before the function runs.
const result = await agent.gate('Bash', { command: 'ls -la' }, async () => {
  return execSync('ls -la').toString();
});

// Or wrap a whole executor map at once.
const governed = agent.wrapTools({
  bash:      (input) => execSync(input.command).toString(),
  read_file: (input) => fs.readFileSync(input.path, 'utf8'),
});
```

`ZlarAgent.connect()` opens a JSON-RPC 2.0 connection to the gate daemon (`sdk/daemon/`) over a Unix socket. If the daemon is unreachable, construction throws `ZlarDaemonUnreachableError` — there is no code path that produces an ungoverned agent instance. See [ADR-006](docs/adr/ADR-006-structural-independence.md) for the architectural reasoning.

**Multi-agent delegation chains.** The SDK ships cryptographic delegation chain support for orchestrator/worker patterns. Each agent receives a per-session Ed25519 keypair; the daemon issues a signed root token via the `register` RPC; each parent signs its child's token with its own key. The daemon verifies the full chain cryptographically **before any policy evaluation** — an invalid chain fails closed with `rule: chain:verify` in the audit trail, and no policy rule is ever consulted.

**AuthZEN 1.0 standards interface.** `sdk/authzen/server.mjs` implements the OpenID Foundation AuthZEN 1.0 Final Specification (January 2026) — a standards-compliant Policy Decision Point at `POST /access/v1/evaluation` (single) and `POST /access/v1/evaluations` (batch). Any AuthZEN-aware PEP can call it. Default port 8181.

**HTTP hook adapter.** `sdk/hook-adapter/server.mjs` bridges Claude Code's HTTP hook protocol to the gate daemon. It always returns HTTP 200 with a valid JSON body — Claude Code treats non-2xx responses as fail-open, so the adapter handles every error condition internally and returns 200 + deny for any failure mode.

## Architecture

| Layer | Component | What it does |
|-------|-----------|-------------|
| **Enforcement** | `zlar-gate` | Policy engine. Intercepts tool calls, classifies, evaluates signed rules, writes audit trail and receipts. |
| **Enforcement** | `mcp-gate` | TCP proxy for MCP. Same policy, same audit format, per-entry signing, standing approvals. Optional Cedar engine via `ZLAR_POLICY_ENGINE`. |
| **Evidence** | `lib/receipt.mjs` | Governed Action Receipt generation and verification (v0 inline and v1 envelope formats). Cross-gate compatible. |
| **Evidence** | `lib/semantic-validator.mjs` | Cross-field validation after signature verification. Rule-outcome consistency, authorizer coherence, delegation chain integrity, temporal bounds. Closes X.509/JWT/SAML-class attacks. |
| **Evidence** | `bin/zlar-verify` | Standalone receipt verifier. Anyone can verify with just the public key. Runs semantic validation automatically on v1 receipts. |
| **Observation** | `zlar-witness` | Sequence detection from audit trail. Detected, not enforced. |
| **Observation** | `zlar-digest` | Governance summary. Decisions, latency, sequences, novelty. |
| **Observation** | `zlar-restore` | Agent Health. 8 behavioral detectors, monotone trust-state machine, gate escalation. Multi-detector convergence required for at_risk+. Advisory — observes, does not enforce directly. Disabled by default. ([Invariants](docs/RESTORE-INVARIANTS.md), [ADR-008](docs/adr/ADR-008-restorative-governance.md)) |
| **Identity** | `zlar-agents` | Per-agent policy bindings, standing approvals, delegation depth limits. |
| **Identity** | Agent manifest | Capability boundary per agent. Narrows policy, never widens. ([Invariants](docs/MANIFEST-INVARIANTS.md)) |
| **Policy** | `zlar-policy` | CLI for Ed25519-signed policy rules. Keygen, sign, verify. |
| **Compliance** | `cedar-poc/zlar.cedar` | Cedar formal policy for the base gate ruleset (R002, R003, R005, R006, R007, R012, R014, R016). Evaluated by the MCP gate when Cedar engine is enabled. |
| **Compliance** | `cedar-poc/e23.cedar` | Cedar ruleset implementing 10 rules for OSFI Guideline E-23 (Model Risk Management). Not in default load path — see [OSFI E-23](#osfi-e-23--canadian-model-risk-management) section. |
| **Session** | `lib/session-state.sh` | Velocity, loop detection, denial bursts. Thin counters, not reasoning. |
| **Human** | `lib/human-invariants.sh` | Protects the human: decision cap (H6), deliberation floor (H15), approval rate monitoring (H14), capacity tracking (H13), authenticity checks (H17). Per-human state, not per-session. |
| **Adapters** | `adapters/` | Framework hooks for Claude Code, Cursor, Windsurf. |
| **SDK** | `sdk/membrane` | Programming model for agents built inside governance. `ZlarAgent.connect()` requires a live daemon at construction. Wraps tool calls with policy evaluation before execution. |
| **SDK** | `sdk/daemon` | Long-lived gate daemon. Unix socket, JSON-RPC 2.0, delegation chain issuer, agent registration. |
| **SDK** | `sdk/authzen` | OpenID Foundation AuthZEN 1.0 Policy Decision Point. `POST /access/v1/evaluation` for standards-compliant authorization requests. |
| **SDK** | `sdk/hook-adapter` | HTTP hook bridge for Claude Code. Always returns HTTP 200 (Claude Code treats non-2xx as fail-open). |

## Running Tests

The canonical entrypoint runs every test suite and prints the total assertion
count. CI runs this on every push. It is the single source of truth for the
"1100+ assertions" badge.

```bash
bash tests/count-assertions.sh            # run all 32 files, print summary
bash tests/count-assertions.sh --detail   # also show per-file pass counts
bash tests/count-assertions.sh --badge    # print shields.io badge URL
```

Current state (v3.0.5): **37 files, 1425 assertions, 2 pre-existing failures** (mcp-gate/test.mjs and cedar-poc/test.mjs — constitution signature not available in CI environment).

### Dependencies

The tests need `bash`, `jq`, and an **OpenSSL with Ed25519 support** (LibreSSL
on macOS does not qualify — use `brew install openssl@3` and put it on PATH
first). `node` is optional — `.mjs` test files will be skipped gracefully if
node is not available. `python3` is optional — canonicalization cross-check
will be skipped gracefully if python3 is not available.

### Individual suites (for targeted debugging)

```bash
# Core governance (bash)
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
bash tests/test-policy-loading.sh      # Policy load fail-closed corpus
bash tests/test-witness.sh             # Sequence detection from audit
bash tests/test-canary.sh              # Canary pending-file lifecycle

# Canonicalization (cross-language verification)
node tests/test-canonicalization.mjs      # 62 vectors across Node and jq -S -c
python3 tests/verify-canonicalization.py  # 28 vectors cross-checked in Python

# Receipt v1 envelope format and semantic validation
node tests/test-receipt-v1.mjs            # v1 create/sign/verify/tamper/universal
node tests/test-semantic-validation.mjs   # Layer 4: rule-outcome, authorizer, temporal, delegation

# MCP gate
node mcp-gate/test.mjs                    # Base gate tests
node mcp-gate/test-hardened.mjs           # Policy verification, signing, fail-closed, standing approvals
node mcp-gate/test-receipt.mjs            # Receipt generation, verification, delegation chains
node mcp-gate/test-cedar.mjs              # Cedar P1/P2 rules, gate action mapping

# Cedar policy verification
node cedar-poc/test.mjs                   # Cedar base rules
node cedar-poc/test-e23.mjs               # Cedar E-23 risk-tiered governance

# SDK layer
node sdk/daemon/test.mjs                  # Daemon lifecycle
node sdk/membrane/test.mjs                # Membrane boundary enforcement
node sdk/authzen/test.mjs                 # AuthZen integration
node sdk/hook-adapter/test.mjs            # Hook adapter HTTP surface
```

## Requirements

| Dependency | Minimum | Required for | Install |
|---|---|---|---|
| bash | 4.0+ | Gate engine | `brew install bash` (macOS) / default on Linux |
| jq | 1.6+ | Policy evaluation | `brew install jq` / `apt install jq` |
| openssl | 3.x | Ed25519 signing | `brew install openssl@3` / `apt install openssl` |
| Node.js | 18+ | MCP gate, receipt verification | Optional — bash gate works without it |
| Telegram | — | Human approval channel | Optional — without it, blocked actions are instant-denied |

**CI-tested platforms:** Ubuntu 22.04+ and macOS 14+ (matrix on every push).
Debian 12+ is supported but not gated by CI — maintainers verify manually.

Run `zlar doctor` after installation to verify all dependencies.

## Repository Structure

```
bin/           Gate, receipt tools, witness, digest, registry, policy CLI
lib/           Shared libraries (crypto, session state, agent identity, receipt, human invariants)
adapters/      Framework hooks (claude-code, cursor, windsurf)
mcp-gate/      MCP TCP proxy gate (Node.js)
etc/           Policy, manifests, signing keys, standing approvals, receipt schema
tests/         Test suites (16 bash + 3 Node.js + 1 Python)
               Run all: bash tests/count-assertions.sh
packages/      ZLAR 3.0 subsystems (zlar-restore: 8 detectors, engine, trust state, 4 test files)
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
| [007](docs/adr/ADR-007-receipt-v1-envelope.md) | Receipt v1 envelope format (versioned, no alg negotiation) |
| [008](docs/adr/ADR-008-restorative-governance.md) | Restorative governance (Agent Health) — observe, don't enforce |

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
