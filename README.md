# ZLAR

## Automation, Abundance and Authority: The Governed Path Is the Fast Path

### The problem

AI agents are starting to do real things. They can read files, write files, send things over the internet, run commands, change systems, and spawn other agents.

Most people try to solve this in one of three ways: let the machine act then check what it did, use another AI to judge whether it seems safe, or lock it down and hope that is enough.

That is too late, and not strong enough. Once the act has happened, the harm may already be done. And if you ask one intelligence to judge another intelligence, both can be fooled.

The real question is: how do we stop it before it crosses the line? How do we let it work, while keeping it inside what a human actually allowed?

### The solution

**Give the agent a permission card.** Every agent gets a simple manifest that says who it belongs to, what it may do, what it may never do, what happens when it reaches something unclear, and when its permission runs out. Not a brain. Not a personality. Just the boundary.

**Put a gate in front of every real act.** The agent can think all it wants. It cannot act without crossing the gate. The gate checks: is this allowed? Is this forbidden? Does a human need to be asked? If the answer is no, it does not happen.

**Keep a record that cannot be quietly changed.** Every important attempt is written down in a tamper-evident, cryptographically signed record. So later you can prove what the agent tried, what was allowed, what was blocked, and who approved it.

**Keep human judgment where it belongs.** Inside its boundary, the machine moves fast. At the edge, it must ask a human. The human is called only when judgment is truly needed. The machine handles the routine. The human handles the point of consequence.

### My view

Do not ask if the machine seems good. Ask if this act was allowed.

Most people focus on behavior: does this look safe? Does this seem risky? Do we trust this model?

ZLAR focuses on authority: was this allowed? By whom? Within what boundary? What happens if it goes past that boundary?

That is not the language of vibes. That is the language of law, finance, access, and rule.

---

For platform teams and security engineers deploying AI agents with real-world tool access.

## The structural failure this addresses

Current approaches to AI governance put intelligence in the monitor — systems that watch what agents do and try to decide whether the action is acceptable. This fails for a reason that cannot be patched: the Intelligence Persuading Intelligence Error. Prompt injection, context drift, reasoning that convinces the monitor the same way it convinced the agent. The attack surface is the reasoning itself.

You cannot solve this by making the monitor smarter. A smarter monitor is a larger attack surface.

ZLAR separates the defense surface from the attack surface. The reasoning layer is where intelligence lives — and where attacks happen. The execution boundary is where actions become real — and where governance belongs. The gate checks whether an action has authorization. It checks paperwork, not quality. It has no opinions. This is why it cannot be persuaded.

## The convergence

Autonomous vehicles, financial transaction authorization, content provenance (C2PA), and agent commerce (Visa TAP, Mastercard Agent Pay) all independently arrived at the same pattern: a deterministic gate at the execution boundary, cryptographic evidence of authorization, and a human authority that is structurally separate from the system being governed. ZLAR did not invent this pattern. It recognized that the pattern already existed across domains and implemented it for AI agents.

## How it works

```
Agent issues tool call (shell command, file write, API request)
  │
  ├─ Gate intercepts at execution boundary
  │
  ├─ Loads Ed25519-signed policy (agents cannot modify the rules that govern them)
  │
  ├─ Evaluates: which rule matches? what is the action?
  │   ├─ allow  → tool executes, audit entry written
  │   ├─ deny   → tool blocked, audit entry written
  │   └─ ask    → human notified via Telegram, agent waits
  │               ├─ human approves → tool executes, audit entry written
  │               ├─ human denies   → tool blocked, audit entry written
  │               └─ timeout        → tool blocked (fail-closed)
  │
  └─ Hash-chained audit entry records the decision
```

The gate runs synchronously on every tool call. No daemon. No server. No database. The process is the pending state. Unprotected actions experience zero added latency. Delay happens only where delay is the point.

Two enforcement surfaces share the same policy and the same audit trail:

- **Bash gate** — hooks into Claude Code, Cursor, Windsurf via PreToolUse. Pure bash. Zero dependencies beyond `jq` and `openssl`.
- **MCP gate** — TCP proxy that sits between any MCP client and any MCP server. Intercepts `tools/call` JSON-RPC messages. Same policy engine, same evidence format.

The agent does not volunteer to be governed. It is governed by architecture.

## What the audit trail produces

Every gate decision writes a hash-chained, algorithm-labeled audit entry. Two entries for a human decision — the request and the resolution:

```json
{
  "ts": "2026-03-21T09:14:22Z",
  "agent_id": "claude-code",
  "domain": "bash",
  "action": "git push origin main",
  "outcome": "pending",
  "risk_score": 75,
  "rule": "R014",
  "authorizer": "gate",
  "prev_hash": "a1b2c3...",
  "signature_algorithm": "Ed25519",
  "hash_algorithm": "SHA-256",
  "public_key_id": "88aaeeaca05eba4d",
  "signature": "mOiZF8E3MKFeyuRw..."
}
```
```json
{
  "ts": "2026-03-21T09:14:31Z",
  "outcome": "denied",
  "authorizer": "human:7662799203",
  "prev_hash": "d4e5f6...",
  "signature": "Kp7xR2vNcW4bQm3j..."
}
```

What this proves:

- **`authorizer: "human:7662799203"`** — a specific human, identified by Telegram ID, made this decision. Not "system denied." Non-repudiable.
- **`prev_hash`** — SHA-256 of the previous entry. Tamper with any record and every subsequent hash breaks. Chain integrity without consensus overhead.
- **`signature_algorithm` / `hash_algorithm`** — every entry labels its own cryptographic assumptions. When NIST deprecates Ed25519 post-2030, migration tooling reads these fields and knows exactly which entries need re-signing under ML-DSA. Designed for this today.
- **`signature`** — Ed25519 signature over the SHA-256 hash of the entry. Every individual audit entry is cryptographically signed at write time. Satisfies SP 800-53 AU-10 (Non-Repudiation). If the signing key is unavailable, the field reads `"unsigned"` — evidence is never lost, only unsigned.

This is not the agent's account of what it did. This is the infrastructure's record of what happened.

## Why deterministic

The gate does not evaluate whether an action *should* proceed. It checks whether the action *has authorization*. It pattern-matches against signed policy rules. It counts. It compares. It looks up. It never reasons, interprets, or forms an opinion.

This is the architectural argument in three sentences: If the enforcement layer uses intelligence, the enforcement layer can be attacked with intelligence. If the enforcement layer is deterministic, the only attack is against the policy itself — which is a human artifact, signed with Ed25519, stored outside agent context. The absence of intelligence in the gate is the security property.

## What the gate does not protect against

A security tool should state its own boundaries, not just its competitors' failures.

- **Compromised signing key.** If the Ed25519 private key is stolen, an attacker can sign a permissive policy. Mitigation: the key never lives on the agent's machine. Key rotation invalidates all prior signatures. The `public_key_id` in every audit entry ties evidence to a specific key era.
- **Compromised gate process.** If the gate binary itself is replaced, all enforcement is lost. Mitigation: the gate's self-protection rules (R012) block agents from modifying their own governance infrastructure. External integrity observation (filesystem checksums, host-level IDS) is the defense layer below the gate.
- **Hash chain limitations.** The chain detects post-hoc tampering by external actors — alter any entry and subsequent hashes break. It does not prevent a compromised gate from writing valid-looking entries with correct hashes. The chain is evidence integrity, not execution integrity. Execution integrity is the gate's job; evidence integrity is the chain's job.
- **Risk profile is rule-derived.** The `risk_score` in each audit entry is the maximum of three policy-defined values (irreversibility, consequence, blast radius) from the matching rule. It is deterministic, not heuristic. No model evaluates risk.
- **Actions the gate cannot see.** If an agent has a channel that bypasses the hook or proxy — direct filesystem access outside tool calls, out-of-band network requests — the gate cannot intercept it. The gate governs tool calls. OS-level containment (sandboxing, network policy) governs everything else.

## Session state

The gate is stateless by design — each tool call evaluated independently. But some governance failures are only visible across multiple calls:

- **Velocity tracking** — too many calls per window escalates to human
- **Loop detection** — same action repeated N times escalates to human
- **Denial burst detection** — consecutive denials signal something adversarial

The counters inform the gate. The human decides. The counter never overrides policy.

## Quick start

```bash
git clone https://github.com/ZLAR-AI/ZLAR.git
cd ZLAR && bash install.sh
```

Or if you've already reviewed the install script:
```bash
curl -fsSL https://raw.githubusercontent.com/ZLAR-AI/ZLAR/main/install.sh | bash
```

Installs with deny-heavy defaults. Your agent is governed in under 60 seconds. No Telegram required — risky actions are blocked until you configure approval.

**Add human approval via Telegram:**
```bash
~/.zlar/bin/zlar telegram
```

**Tune thresholds** — defaults are `20/50/80` (deny-heavy). To widen the allow window:
```json
"scoring_thresholds": {
  "allow": 50,
  "log": 51,
  "ask": 71
}
```
Then re-sign: `zlar-policy sign --input ~/.zlar/etc/policies/active.policy.json --key ~/.zlar-signing.key`

The deny rules (rm -rf, sudo, persistence mechanisms) always block regardless of threshold. The audit trail records everything regardless of threshold.

## Architecture

| Layer | Component | What it does |
|-------|-----------|-------------|
| **Enforcement** | `zlar-gate` | Policy engine. Intercepts tool calls, classifies, evaluates signed rules, writes audit trail. |
| **Enforcement** | `mcp-gate` | TCP proxy for MCP. Same policy, same audit format, any MCP-connected agent. |
| **Observation** | `zlar-witness` | Sequence detection. Reads the audit trail, finds multi-step patterns (credential read followed by network egress, denial followed by schedule creation). Detected, not enforced. |
| **Observation** | `zlar-digest` | Governance summary. Decisions, latency, sequences, novelty. |
| **Observation** | `zlar-standing` | Standing authority view. What the agent can do right now without asking. |
| **Observation** | `zlar-registry` | Agent inventory. Every agent the gate has seen, derived from the audit trail. No registration required. |
| **Identity** | `zlar-agents` | Per-agent policy bindings. Standing approval scoping, aggregate budgets, delegation depth limits per agent. |
| **Identity** | `zlar-agents-export` | Generate signable agent inventory from audit trail. Raw + production views (filters test agents). |
| **Identity** | `lib/agent-identity.sh` | Risk tier classification, authorization levels, test agent filtering, pattern detection. |
| **Dashboard** | `zlar-status` | Governance health dashboard. Gate status, policy state, agent inventory, recent approvals/denials. |
| **Policy** | `zlar-policy` | CLI for Ed25519-signed policy rules. Keygen, sign, verify. |
| **Session** | `lib/session-state.sh` | Velocity, loop detection, denial bursts, aggregate action budgets. Thin counters, not reasoning. |
| **Adapters** | `adapters/` | Framework hooks for Claude Code, Cursor, Windsurf. Thin wrappers — the gate is the gate. |

## The witness layer

The witness reads the gate's audit trail. It does not intercept, block, or modify agent actions. The gate remains the sole enforcement point.

```
Gate (enforces) → audit.jsonl → Witness (observes) → Brief (surfaces) → Human (ratifies) → Policy (gate enforces)
```

Candidate sequence patterns — detected, not blocked:

| Pattern | What it detects |
|---------|----------------|
| `credential-adjacent-egress` | Sensitive file read followed by outbound network request |
| `denied-then-scheduled` | Denied request followed by cron/schedule creation |
| `rapid-approval-drift` | Human approval latency decreasing within a session |
| `repeated-denial-burst` | Same rule denying 5+ times in one session |

The witness can be smart. The gate must remain simple. The witness does not become sovereign.

## Design tests

If a proposed feature fails any of these, it does not belong:

- If it requires the gate to form an opinion about whether an action should be allowed, it does not belong.
- If it requires access to the content of an agent's reasoning, it does not belong.
- If it adds latency to actions that are not protected, it violates the performance contract.
- If it creates dependency on a specific model, agent framework, or infrastructure provider, it breaks portability.

## Repository structure

```
bin/           Gate, witness, digest, standing, registry, agents, status, policy CLI
lib/           Shared libraries (audit reader, session state, agent identity, crypto)
adapters/      Framework hooks (claude-code, cursor, windsurf)
mcp-gate/      MCP TCP proxy gate (Node.js)
sdk/           Phase 2 SDK: daemon, membrane (delegation chains), AuthZEN, hook adapter
etc/           Configuration, policy templates, agent bindings, signing keys, sandbox profiles
scripts/       Setup, installation, Telegram bootstrap
tests/         Test suites (9 bash + 4 Node.js)
docs/          Architecture and design
signal/        Agent-facing signal layer (thesis, manifest)
cedar-poc/     Cedar formal policy verification: base rules + E-23 risk-tiered governance
oc/            OS-level containment (OpenClaw integration)
```

## Running tests

```bash
# Gate and governance tests (266 assertions across 9 suites)
bash tests/test-perimeter-closure.sh  # Perimeter closure: 85 assertions (policy rules + sandbox + path sanitization)
bash tests/test-crypto.sh             # Cryptographic abstraction: 46 assertions
bash tests/test-agent-identity.sh     # Agent identity, registry, bindings: 35 assertions
bash tests/test-canary.sh             # Governance health probes: 25 assertions
bash tests/test-witness.sh            # Observation layer: 23 assertions
bash tests/test-session-state.sh      # Session counters: 16 assertions
bash tests/test-standing-approvals.sh # Standing approvals: 15 assertions
bash tests/test-approval-binding.sh   # Approval binding (action fingerprint): 11 assertions
bash tests/test-inbox-hmac.sh         # Inbox HMAC verification: 10 assertions

# Cedar, MCP gate, and SDK
node cedar-poc/test.mjs               # Cedar base rules: 14 assertions
node cedar-poc/test-e23.mjs           # Cedar E-23 risk-tiered: 25 assertions
node mcp-gate/test.mjs                # MCP proxy gate: 7 assertions
```

All tests pass on macOS (arm64).

## Requirements

- bash 3.2+ (macOS default works)
- jq (JSON processing)
- openssl (Ed25519 key generation)
- Optional: Telegram bot token (for human approval via Telegram)
- Optional: Node.js 18+ (for MCP gate)

## Uninstall

```bash
~/.zlar/bin/zlar uninstall
```

Clean removal. Hooks removed from all frameworks. Signing key preserved.

## Further reading

- [signal/PROOF.md](signal/PROOF.md) — Proof: on the governed path, no unauthorized action can execute. Exhaustive case analysis against source code.
- [signal/FAIL-OPEN.md](signal/FAIL-OPEN.md) — On the Anthropic source code leak, the fail-open hook architecture, and why deterministic enforcement exists.
- [signal/ORIGIN.md](signal/ORIGIN.md) — Why ZLAR exists. The personal failure that produced the architecture.
- [signal/THESIS.md](signal/THESIS.md) — Why intelligence in the monitor fails. Why the governed path is the fast path.
- [signal/SIGNAL.md](signal/SIGNAL.md) — Project declaration and structured overview.
- [AGENTS.md](AGENTS.md) — Agent discovery layer.
- [LEGAL.md](LEGAL.md) — Regulatory classification.
- [SECURITY.md](SECURITY.md) — Security policy.

## License

Apache 2.0. See [LICENSE](LICENSE).

Built by [ZLAR Inc.](https://zlar.ai)
