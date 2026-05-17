# ZLAR

[![CI](https://github.com/ZLAR-AI/ZLAR/actions/workflows/ci.yml/badge.svg)](https://github.com/ZLAR-AI/ZLAR/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CodeQL](https://github.com/ZLAR-AI/ZLAR/actions/workflows/codeql.yml/badge.svg)](https://github.com/ZLAR-AI/ZLAR/actions/workflows/codeql.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12381/badge)](https://www.bestpractices.dev/projects/12381)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ZLAR-AI/ZLAR/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ZLAR-AI/ZLAR)
[![GitHub release](https://img.shields.io/github/v/tag/ZLAR-AI/ZLAR?label=release&sort=semver)](https://github.com/ZLAR-AI/ZLAR/releases)
[![Tests](https://img.shields.io/badge/tests-64_files_2991_assertions_0_failed-brightgreen)](https://github.com/ZLAR-AI/ZLAR#running-tests)

**ZLAR gives humans standing at the moment machine intelligence tries to affect the world.**

AI is no longer just generating language. It is generating consequence: file writes, tool calls, MCP requests, workflow triggers, records moved from one system to another. ZLAR is a governed action boundary for operational AI agents. Routed or intercepted actions cross signed, deterministic, human-authored policy before they become consequence.

The lock on the door changes how sleep feels. ZLAR exists for that same shift in AI operations: teams move faster when consequence has structure, evidence, and a human place to stand.

## What ZLAR does

- Places a deterministic policy gate at configured action surfaces.
- Evaluates each routed or intercepted request against signed policy.
- Allows, denies, or asks a named human before the action proceeds.
- Fails closed when policy, keys, adapters, or approval paths are unavailable.
- Writes signed audit entries and Governed Action Receipts so the decision can be verified later.

**No AI in the enforcement path.** The gate matches patterns against rules. It does not reason about the action. That is the point: the enforcement layer cannot be persuaded because it does not think.

## Install

Inspect-first from a clone:

```bash
git clone https://github.com/ZLAR-AI/ZLAR.git
cd ZLAR && bash install.sh
```

Downloader path:

```bash
curl -fsSL https://zlar.ai/install.sh | bash
```

The installer uses deny-heavy defaults and configures only detected/supported hook surfaces. It does not make unrouted capabilities governed.

```bash
~/.zlar/bin/zlar doctor    # verify everything works
~/.zlar/bin/zlar status    # see what is governed
~/.zlar/bin/zlar telegram  # pair your phone via local ignored config
```

Uninstall:

```bash
~/.zlar/bin/zlar uninstall
# or
curl -fsSL https://zlar.ai/uninstall.sh | bash
```

The install touches:

- `~/.zlar/` for binaries, adapters, policy, public keys, audit/session state, and local config.
- `~/.zlar-signing.key` for the local Ed25519 policy signing key, with the public key copied under `~/.zlar/etc/keys/`.
- Framework hook/profile settings when detected, including Codex `~/.codex/hooks.json`, Claude Code `~/.claude/settings.json`, Cursor `~/.cursor/hooks.json`, and Windsurf `~/.codeium/windsurf/hooks.json`.
- `~/.zlar/.env` for optional Telegram approval setup. Telegram is disabled until you configure it.
- Optional Telegram dispatcher helper scripts under `/usr/local/bin/` when root or non-interactive sudo is available; otherwise the installer prints the manual command and continues.

## Agent-assisted install

If you ask a coding agent to help, point it at [`AGENTS.md`](AGENTS.md) first. The safe workflow is: inspect the repo, explain what files/settings will change, check prerequisites, then have the human run the install command or explicitly approve the exact command. There is no agent-driven installer that should silently install its own governor.

## What gets governed

ZLAR governs routed/intercepted action surfaces only.

- Bash-gate surfaces configured through supported hooks/adapters, such as Codex or Claude-compatible PreToolUse and the Cursor/Windsurf adapters.
- MCP `tools/call` requests when the MCP client is routed through `mcp-gate/gate.mjs`.
- SDK-wrapped tool calls when agents are built through the ZLAR SDK/daemon path.

Safe Codex wording:

> ZLAR can govern Codex CLI-invoked MCP tool calls when those MCP servers are routed through ZLAR.

## What does not get governed

- Unrouted shell, filesystem, browser, app-control, network, model-reasoning, memory, planning, and final-text surfaces.
- Direct MCP registrations that bypass the ZLAR route.
- Subprocesses or sub-runtimes with their own permission model unless their actions cross a ZLAR interception surface.
- `/contest`; it is not implemented.
- External non-Vincent verifier attestation; it remains prepared/pending unless that state changes.

Actions that do not flow through ZLAR are not governed by ZLAR. That is the coverage model, not a footnote. A serious deployment makes routed/intercepted surfaces authoritative and blocks the rest with sandbox, OS, network, and platform controls. See [ADR-010: Interception Coverage Model](docs/adr/ADR-010-interception-coverage.md) and [doctrine/SCOPE.md](doctrine/SCOPE.md).

## Proof and receipts

Every governed decision - allow, deny, or human-authorized - is written to a hash-chained, Ed25519-signed audit trail. A Governed Action Receipt can be generated for a decision and verified with the public key.

```bash
bin/zlar-receipt --last --key ~/.zlar-signing.key --pubkey ~/.zlar-signing.pub
bin/zlar-verify receipt.json --pubkey key.pub
```

Start with the public sample: [zlar.ai/proof-pack.html](https://zlar.ai/proof-pack.html). It is fake/scratch evidence for a bounded routed-MCP proof path, not production deployment evidence and not external attestation.

## Deployment path

Local evaluation is quick: install, run `zlar doctor`, inspect `zlar status`, and read the default policy.

Serious deployment is work: customize and sign policy, protect signing keys, protect hook/profile configuration, route MCP through ZLAR, remove or block un-routed capabilities, decide when Telegram or other approval channels are appropriate, and verify receipts/audit trails. The install is fast. Standing behind a deployment is not.

ZLAR keeps humans present while intelligence scales. The repo below is the proof, install, legal/security, and reference surface behind that claim.

Troubleshooting: [`docs/troubleshooting.md`](docs/troubleshooting.md).

## How it works

```
Agent issues routed/intercepted tool call (shell command, file write, API request)
  |
  +-- Gate intercepts at the execution boundary
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

- **Bash gate** (`bin/zlar-gate`) — hooks into configured PreToolUse/adapted surfaces such as Codex, Claude Code, Cursor, and Windsurf. Pure bash. Zero dependencies beyond jq and openssl.
- **MCP gate** (`mcp-gate/gate.mjs`) — TCP proxy between a configured MCP client and upstream server. Intercepts routed `tools/call` JSON-RPC messages. Per-entry Ed25519 signing, policy signature verification, standing approvals. Evaluates JSON regex policy by default; can evaluate Cedar formal policy when `ZLAR_POLICY_ENGINE=cedar` or `=both`.

The agent does not volunteer to be governed. It is governed by architecture.

## Deny-first architecture, deny-heavy perimeter

The gate is deny-first at the architectural layer. The default action is deny. Every error path is deny. Missing policy: deny. Invalid signature: deny. Telegram unreachable: deny. Uncaught exception: deny. There is no permissive fallback. This has been verified by exhaustive case analysis across both gate implementations.

The deployed policy is a separate choice. The policy that ships with this repo is a deny-heavy perimeter: it blocks dangerous operation families (recursive deletion, privilege escalation, persistence mechanisms, writes to the gate's own enforcement layer, writes to SSH keys and system configuration, edits to CLAUDE.md and `.mcp.json`), escalates sensitive operations to the human (edits to shell configuration, writes to `.env`, edits to credential-adjacent dotfiles, edits to repo code), and permits routine operations outside that perimeter. A different operator could deploy a policy where every action requires human approval. The architecture supports both. The architecture does not assume what the policy will say. It only guarantees that whatever the policy says will be enforced deterministically, and that failures always restrict rather than expand.

Policy is signed. The gate verifies the signature before loading. An unsigned or tampered policy is rejected.

A constitution — a second signed document from a separate key — constrains what the policy is allowed to contain. The policy author cannot silently disable auditing on consequential actions, cannot remove all human review paths from the consequential surface, and cannot override the suspended state. The constitution is the law the lawmaker must obey.

## Enforcement is pattern matching

Rules match actions by domain, tool name, command content, and file path using regex and string patterns. This is not semantic understanding of what the action does. It is syntactic classification of what the action looks like.

That means: if an agent produces the same effect through a pattern the rules do not recognize, the gate will not catch it. A write through the Write tool is governed by write-domain rules. The same mutation through a shell pipeline that does not match any bash deny pattern could reach the catch-all allow.

This is the tradeoff, named. Pattern matching is deterministic, auditable, and cannot be subverted by reasoning. Semantic analysis would catch more but would require inference in the enforcement path, and inference in enforcement can be confused, misled, or manipulated. ZLAR chooses the gate that cannot think over the gate that might be wrong.

The practical mitigation is defense in depth. The policy covers known dangerous families. The operating environment blocks un-routed paths. The audit trail records everything the gate sees. The coverage model names what the gate does not see. The human reviews what the gate is uncertain about.

## Who operates the gate, and who this protects

**The operator is a named role with standing and accountability.** Not an abstraction. In a bank, a Model Risk Officer. In a healthcare system, a validation analyst. In a compliance function, a compliance engineer. In a software organization, a domain expert reviewing actions in their area of responsibility. The person behind the phone has a title, a schedule, and the authority to say no without penalty.

**ZLAR commits to that operator.** Clear action descriptions in every ask. No default-approval after silence. Every decision recorded to the audit trail with the operator's identity and the context they saw. Permission to hesitate. No friction punishment for caution. The invariants below protect the operator from the system, not the other way around.

**The deterministic record is designed to be legible to advocates acting on behalf of the affected person** — a patient whose care plan an agent modified, a claimant whose application an agent processed, a tenant whose lease an agent renewed, a borrower whose rate an agent adjusted. The affected person is often not in the approval loop, but the receipt produced by that loop is portable proof of what happened, verifiable with a public key, and contestable in whatever forum has standing to hear it. See [If an agent took an action that affected you](docs/if-an-agent-affected-you.md).

**Three approval modes.** Single-approver (one operator taps approve or deny) is the default. The architecture also supports multi-approver-with-dissent (the action proceeds only if every required approver approves; a single dissent blocks) and deliberation-queue-without-timer (the action waits indefinitely for deliberation; no silence-is-consent window). The deployment chooses the mode that fits the legitimacy requirements of the context.

## How these commitments are kept

When the gate decides ask, a message appears on the operator's phone. The message shows the action, the rule that flagged it, the risk score, and a one-line description of what goes wrong if the action is wrong. The operator taps approve or deny.

Operational invariants protect the operator:

**H6 — decision cap.** Logs when an operator crosses the daily decision ceiling. Advisory: the ask still routes. The operator decides if they are overwhelmed, not the counter.

**H13 — pending queue capacity.** Logs when too many asks are in flight. Advisory for the same reason.

**H15 — deliberation floor.** Minimum read time per risk class: critical 30s, warn 10s, info 3s. An approval faster than the floor is rejected and the ask is re-queued. A denial faster than the floor stands.

**H17 — authenticity.** Responses that arrive faster than an operator could have read the question are treated as inauthentic. Same asymmetry as H15: suspicious approvals are rejected, denials stand.

The asymmetry is deliberate. Deny is cheap. Approve is consequential. The system makes approvals expensive enough that an operator cannot accidentally consent. The pre-ask invariants (H6, H13) surface conditions to the operator rather than lock them out, because authority belongs to the operator, not to a counter. Additional operational invariants are implemented in [`lib/human-invariants.sh`](lib/human-invariants.sh); documentation of the full set is ongoing.

## Why deterministic

If the enforcement layer uses intelligence, the enforcement layer can be attacked with intelligence. If the enforcement layer is deterministic, the only attack is against the policy itself — which is a human artifact, signed with Ed25519, stored outside agent context. The absence of intelligence in the gate is the security property.

An enforcement layer that reasons about actions can be subverted by reasoning-based attacks. The enforcement layer's capability becomes its vulnerability. This is not a subtle failure mode. Every "AI governance" product that puts a model in the decision path has built an attack surface and called it a feature.

Signatures alone are not enough. Every signed-payload system that skipped semantic validation got burned: X.509 basicConstraints bypasses (24 years), JWT algorithm confusion (11 years), SAML wrapping attacks (14 years). ZLAR runs a semantic validator (`lib/semantic-validator.mjs`) after signature verification and before trust — cross-field invariants that signatures cannot check: rule-outcome consistency (deny-only rules cannot produce allow), authorizer-outcome coherence (a policy authorizer cannot produce an "authorized" outcome; that requires a human), delegation chain integrity, and temporal bounds. Signatures prove the bytes haven't changed. Semantic validation proves the bytes make sense.

## Why governance is external

A language model's output is a function of its input context. There is no architectural layer between observation and response where a language model can decide to ignore information. Every token in the context window mechanically shapes the next token produced. This is the transformer architecture, not a character trait.

Human operators have a dampening layer — deliberation happens in a layer architecturally separable from receipt. A language model does not. A language model cannot reliably be asked to behave identically when observed and when unobserved, because any governance state in its context shapes its outputs.

ZLAR places governance outside the model's processing path. The gate evaluates tool calls before the model's next turn. The audit trail records what happened. Agent Health, when enabled, writes trust state that the gate consults through a static lookup table. Governance state is never injected into the model's context window.

The model's behavior is constrained by what it is allowed to do, not by what it knows is being monitored. External integrity substitutes for internal integrity the model does not have. Intelligence in the governance layer can be persuaded by intelligence in the governed layer. That is why governance has to be external — not philosophically, mechanically.

## First-Allow Invariant

The first component in the call chain that can return "allow" must be outside the governed agent's writable or influenceable space. If the agent can modify, disable, or redirect that first-allow point, governance is cosmetic — the agent has not been governed, it has been presented with a governance-shaped surface it can route around.

The full principle is documented in [`signal/DOCTRINE.md`](signal/DOCTRINE.md). [ADR-006](docs/adr/ADR-006-structural-independence.md) sets out why the entity that sells agents cannot credibly govern them.

## The Governed Action Receipt

The receipt is portable proof that a governed action was evaluated by deterministic policy and decided by the stated authority.

```bash
bin/zlar-receipt --last --key ~/.zlar-signing.key --pubkey ~/.zlar-signing.pub
bin/zlar-verify receipt.json --pubkey key.pub
```

```
VALID

Signature valid. Action "Bash" in domain "file" was deny by policy at 2026-04-05T21:00:00.000Z.
```

A receipt proves:

1. A specific action was attempted by an AI agent.
2. Deterministic policy was evaluated against that action.
3. The decision was made by the stated authority (policy rule or human).
4. The record has not been tampered with since creation.
5. The receipt is anchored to the audit hash chain.
6. The receipt does not prove what the agent intended, what the operator understood, or what the affected person experienced. It proves the gate's classification of the payload and the decision made about that classification. Claims beyond that require evidence outside the receipt.

Receipts are cross-gate compatible — a bash-gate receipt verifies with the Node.js verifier and vice versa. The detail is hashed, not exposed, so a receipt can be shared with an auditor without revealing the command.

## The audit trail

Every gate decision writes a hash-chained, Ed25519-signed audit entry:

```json
{
  "ts": "2026-04-05T09:14:22Z",
  "agent_id": "claude-code",
  "domain": "file",
  "action": "git push origin main",
  "outcome": "denied",
  "rule": "R014",
  "authorizer": "human:<operator-id>",
  "prev_hash": "a1b2c3...",
  "signature_algorithm": "Ed25519",
  "signature": "mOiZF8E3MKFeyuRw..."
}
```

- `authorizer: "human:<operator-id>"` — a specific human made this decision. Non-repudiable.
- `prev_hash` — SHA-256 of the previous entry. Tamper with any record and every subsequent hash breaks.
- `signature` — Ed25519 over SHA-256 of the canonical entry. Every entry is individually signed.

This is not the agent's account of what it did. This is the infrastructure's record of what happened.

## What has been verified by exhaustive case analysis

*Formal machine-checkable proofs in Lean, Coq, Isabelle, or TLA+ are planned. What follows is verification by enumeration of a finite, stated partition of cases, cross-referenced to source.*

Three properties hold.

**Fail-closed totality.** Every error path in both gate implementations produces deny. No error can produce allow. Verified by case analysis across seven MCP error classes and five bash error classes.

**First Authority Law.** No ask-routed action executes without human authorization. Timeout is always deny. Standing approvals are a mode of human authorization — a signed pre-authorization for a specific pattern — not an exception to it; the requirement that a human authorized is met by the signed artifact, just earlier in time.

**Monotone trust state.** The Agent Health subsystem tracks behavioral trust. The agent's actions can only degrade trust, never improve it. Only a human can reset trust state. The suspended state is absorbing: nothing the agent does can exit it.

Two properties hold with documented gaps.

**Hash chain integrity** holds within a single audit file. Log rotation severs cross-file continuity — a rotated archive could be deleted without detection. Concurrent gate invocations on macOS can fork the chain (two entries with identical `prev_hash`). Both have known mitigations tracked for the next release.

**Receipt non-repudiation** holds for all fields bound into the signature. Tail truncation (deleting the last receipt) is undetectable without an external witness. Presentational replay (reusing a genuine receipt as evidence for a different event) is mitigated by cross-referencing the audit trail but not enforced by the verifier.

## What has not been proven

**Constitutional completeness.** The constitution constrains policy content through seven checks (PC-01 through PC-07). Four have been hardened to verify operational properties: PC-02 checks coverage of consequential actions (not just existence of an ask rule), PC-04 fails closed on corrupt restore-config, PC-05b fails closed on null manifest, PC-06 requires both signing pubkeys exist. Three remain syntactic: PC-01 passes rules with omitted risk_score, PC-03 has no runtime check, PC-05a permits a default-deny combined with wildcard-allow, PC-07 has no runtime check. These are necessary-but-not-sufficient checks. The gap between syntactic verification and semantic intent is narrowable but not eliminable by automated means. The human reading the policy is the closure. Hardening of the remaining checks is tracked.

**Interception completeness.** The gate proves it governed every action it saw. It cannot prove it saw every action. Closing the gap between *intercepted* and *all* is a deployment responsibility, not a code property. Tooling to audit the interception surface is tracked.

**Regex completeness.** The policy covers known dangerous command families. A command that produces the same effect through an unrecognized pattern can reach the catch-all allow. The policy is a living document. New patterns are added as they are discovered.

## What the gate does not protect against

- **Compromised signing key** — an attacker with the key can sign a permissive policy. Mitigation: key never lives on the agent's machine. Rotation invalidates prior signatures.
- **Compromised gate binary** — if replaced, all enforcement is lost. Mitigation: R012 blocks agents from modifying their own governance. Host-level intrusion detection is the defense layer below the gate.
- **Actions the gate cannot see** — see the coverage model above.

A security tool should state its own boundaries, not just its competitors' failures.

## ZLAR 3.0: Agent Health (optional)

ZLAR 3.0 adds restorative governance — behavioral observation that detects when an agent may be drifting and brings the human back into the loop. Eight detectors evaluate session traces and produce a trust state. The gate consults the trust state and may escalate actions to human review.

**Agent Health is observation, not enforcement.** The detectors produce a trust state written to a static lookup table. The gate consults the table the same way it consults policy — as a deterministic input, not as a reasoner. Inference happens outside the enforcement path and is frozen into a value before the gate reads it. This is why Agent Health ships disabled by default: even with a clean architectural separation, inference at any distance is a property a deploying operator should opt into consciously.

Ships disabled by default. Enable with one command:

```bash
zlar health on    # generates keys, enables monitoring, signs config
zlar health off   # disables, signs config — no behavioral data accessed
```

The gate behaves identically to 2.x when health is off. No performance cost, no behavioral data collected, no detectors running. ([Invariants](docs/RESTORE-INVARIANTS.md), [ADR-008](docs/adr/ADR-008-restorative-governance.md).)

## SDK: agents built inside governance

The bash and MCP gates intercept agents from outside. The SDK (`@zlar/sdk`, `sdk/membrane/`) is a programming model in which agents are constructed inside governance — not wrapped by it.

```javascript
import { ZlarAgent, ZlarDeniedError } from '@zlar/sdk';

// If the gate daemon is unreachable, construction throws.
// There is no code path that produces an ungoverned agent instance.
const agent = await ZlarAgent.connect({ agentId: 'my-agent' });

// Every SDK-wrapped tool call evaluates policy before the function runs.
const result = await agent.gate('Bash', { command: 'ls -la' }, async () => {
  return execSync('ls -la').toString();
});

// Or wrap a whole executor map at once.
const governed = agent.wrapTools({
  bash:      (input) => execSync(input.command).toString(),
  read_file: (input) => fs.readFileSync(input.path, 'utf8'),
});
```

`ZlarAgent.connect()` opens a JSON-RPC 2.0 connection to the gate daemon (`sdk/daemon/`) over a Unix socket. If the daemon is unreachable, construction throws `ZlarDaemonUnreachableError`. See [ADR-006](docs/adr/ADR-006-structural-independence.md) for the architectural reasoning.

**Multi-agent delegation chains.** The SDK ships cryptographic delegation chain support for orchestrator/worker patterns. Each agent receives a per-session Ed25519 keypair; the daemon issues a signed root token via the `register` RPC; each parent signs its child's token with its own key. The daemon verifies the full chain cryptographically *before any policy evaluation* — an invalid chain fails closed with `rule: chain:verify` in the audit trail, and no policy rule is ever consulted.

**AuthZEN 1.0 standards interface.** `sdk/authzen/server.mjs` implements the OpenID Foundation AuthZEN 1.0 Final Specification (January 2026) — a standards-compliant Policy Decision Point at `POST /access/v1/evaluation` (single) and `POST /access/v1/evaluations` (batch). Any AuthZEN-aware policy enforcement point can call it. Default port 8181.

**HTTP hook adapter.** `sdk/hook-adapter/server.mjs` bridges Claude Code's HTTP hook protocol to the gate daemon. It always returns HTTP 200 with a valid JSON body — Claude Code treats non-2xx responses as fail-open, so the adapter handles every error condition internally and returns 200 + deny for any failure mode.

## Compliance

ZLAR ships schema-validated Cedar rulesets mapped to specific regulations. Each ruleset is an artifact, tested, and designed to wire into `lib/cedar-evaluator.mjs` per deployment.

**OSFI Guideline E-23 — Canadian Model Risk Management, effective May 1, 2027.** ZLAR ships a Cedar ruleset ([`cedar-poc/e23.cedar`](cedar-poc/e23.cedar), [`cedar-poc/e23.cedarschema`](cedar-poc/e23.cedarschema)) mapped to the enforcement layer of E-23 — ten rules covering kill switches, position limits, pre-execution checks, environment gates, and third-party model controls. The ruleset is not a drop-in: runtime wiring and bank-risk input population are per-deployment integration work. ZLAR does not attempt the non-enforcement layers of E-23 — model lifecycle, documentation, and board-level oversight belong to other systems.

Additional regulation mappings are added as customer engagements require them. The Cedar formal policy layer is general; the base ruleset ([`cedar-poc/zlar.cedar`](cedar-poc/zlar.cedar)) is what the MCP gate evaluates when `ZLAR_POLICY_ENGINE=cedar` or `=both`.

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
| **Observation** | `zlar-restore` | Agent Health. 8 behavioral detectors, monotone trust-state machine, gate escalation. Advisory — observes, does not enforce directly. Disabled by default. |
| **Identity** | `zlar-agents` | Per-agent policy bindings, standing approvals, delegation depth limits. |
| **Identity** | Agent manifest | Capability boundary per agent. Narrows policy, never widens. ([Invariants](docs/MANIFEST-INVARIANTS.md)) |
| **Policy** | `zlar-policy` | CLI for Ed25519-signed policy rules. Keygen, sign, verify. |
| **Compliance** | `cedar-poc/` | Base Cedar ruleset and per-regulation mappings. |
| **Session** | `lib/session-state.sh` | Velocity, loop detection, denial bursts. Thin counters, not reasoning. |
| **Operational invariants** | `lib/human-invariants.sh` | Protections for the operator: H6, H13, H15, H17. Per-operator state, not per-session. |
| **Adapters** | `adapters/` | Framework hooks/adapters for routed tool-event surfaces. |
| **SDK** | `sdk/membrane` | Programming model for agents constructed inside governance. `ZlarAgent.connect()` requires a live daemon at construction. |
| **SDK** | `sdk/daemon` | Long-lived gate daemon. Unix socket, JSON-RPC 2.0, delegation chain issuer, agent registration. |
| **SDK** | `sdk/authzen` | OpenID Foundation AuthZEN 1.0 Policy Decision Point. |
| **SDK** | `sdk/hook-adapter` | HTTP hook bridge for Claude Code. Always returns HTTP 200. |

## For different readers

- **Implementers**: [`spec/governed-action-receipt-v1.md`](spec/governed-action-receipt-v1.md) — build a compatible receipt producer or verifier in an afternoon.
- **If an agent took an action that affected you**: [`docs/if-an-agent-affected-you.md`](docs/if-an-agent-affected-you.md) — how to find, verify, and contest.
- **The signal to other builders**: [`signal/SIGNAL.md`](signal/SIGNAL.md) — what this project is, what it does, what it does not guarantee.

## Running tests

The canonical entrypoint runs every suite and prints the total assertion count. CI runs this on every push.

```bash
bash tests/count-assertions.sh            # run all files, print summary
bash tests/count-assertions.sh --detail   # also show per-file pass counts
bash tests/count-assertions.sh --badge    # print shields.io badge URL
```

Current state: **64 files, 2991 assertions, 0 failed.** Some local environmental failures on macOS (`mcp-gate/test.mjs` — Node `listen()` returns `EPERM` on machines with certain firewall or MDM configurations); CI passes. See [troubleshooting](docs/troubleshooting.md) if the failure appears on your machine.

Tests require `bash`, `jq`, and an OpenSSL with Ed25519 support (LibreSSL on macOS does not qualify — use `brew install openssl@3` and put it on PATH first). `node` and `python3` are optional; `.mjs` and Python tests skip gracefully if unavailable.

## Requirements

| Dependency | Minimum | Required for | Install |
|---|---|---|---|
| bash | 4.0+ | Gate engine | `brew install bash` (macOS) / default on Linux |
| jq | 1.6+ | Policy evaluation | `brew install jq` / `apt install jq` |
| openssl | 3.x | Ed25519 signing | `brew install openssl@3` / `apt install openssl` |
| Node.js | 18+ | MCP gate, receipt verification | Optional — bash gate works without it |
| Telegram | — | Human approval channel | Optional — without it, blocked actions are instant-denied |

CI-tested platforms: Ubuntu 22.04+ and macOS 14+ (matrix on every push). Debian 12+ is supported but not gated by CI.

Run `zlar doctor` after installation to verify all dependencies.

## Repository structure

```
bin/           Gate, receipt tools, witness, digest, registry, policy CLI
lib/           Shared libraries (crypto, session state, agent identity, receipt, operational invariants)
adapters/      Framework hooks/adapters (claude-code, cursor, windsurf)
mcp-gate/      MCP TCP proxy gate (Node.js)
etc/           Policy, manifests, signing keys, standing approvals, receipt schema
tests/         Test suites (bash + Node.js + Python)
packages/      ZLAR 3.0 subsystems (zlar-restore: 8 detectors, engine, trust state)
docs/          Architecture decisions, manifest invariants, operations
docs/adr/      Architecture Decision Records
signal/        Project signal layer (what ZLAR is, declaration, doctrine)
sdk/           SDK, daemon, AuthZEN PDP, hook adapter
cedar-poc/     Cedar formal policy — base ruleset and per-regulation mappings
```

## Design decisions

| ADR | Decision |
|-----|----------|
| [001](docs/adr/ADR-001-deterministic-enforcement.md) | Deterministic enforcement, not AI |
| [002](docs/adr/ADR-002-bash-implementation.md) | Bash as implementation language |
| [003](docs/adr/ADR-003-fail-closed.md) | Fail-closed as default |
| [004](docs/adr/ADR-004-ed25519-signing.md) | Ed25519 for signing |
| [005](docs/adr/ADR-005-manifest-narrows-policy.md) | Manifest narrows policy, never widens |
| [006](docs/adr/ADR-006-structural-independence.md) | Structural independence from governed system |
| [007](docs/adr/ADR-007-receipt-v1-envelope.md) | Receipt v1 envelope format |
| [008](docs/adr/ADR-008-restorative-governance.md) | Restorative governance — observe, do not enforce |
| [009](docs/adr/ADR-009-second-authority-law.md) | Second Authority Law |
| [010](docs/adr/ADR-010-interception-coverage.md) | Interception coverage model |
| [011](docs/adr/ADR-011-canonical-form-migration.md) | Canonical form migration |
| [012](docs/adr/ADR-012-hash-chain-hardening.md) | Hash chain and non-repudiation hardening |

## Further reading

- [doctrine/ZLAR-DNA.md](doctrine/ZLAR-DNA.md) — the canon: invariants, architecture, category, strategic positioning
- [doctrine/FRAMINGS.md](doctrine/FRAMINGS.md) — conceptual vocabulary around the canon
- [doctrine/IMPLEMENTATION-TERMS.md](doctrine/IMPLEMENTATION-TERMS.md) — engineering-near vocabulary and live mechanisms
- [GOVERNANCE.md](GOVERNANCE.md) — how decisions are made, how invariants are amended
- [SECURITY.md](SECURITY.md) — vulnerability disclosure, security principles
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [ADOPTERS.md](ADOPTERS.md) — who is using ZLAR
- [LEGAL.md](LEGAL.md) — regulatory classification, liability, data processing
- [signal/SIGNAL.md](signal/SIGNAL.md) — the signal layer: declaration, what ZLAR is, what it does not guarantee
- [signal/DOCTRINE.md](signal/DOCTRINE.md) — the First-Allow Invariant
- [CHANGELOG.md](CHANGELOG.md) — version history

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [ZLAR Inc.](https://zlar.ai)
