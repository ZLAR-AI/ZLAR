# ZLAR Demo Script — The Deny Path

*5 minutes. Four of five Forrester pillars in one flow.*

---

## What you're showing

An AI agent tries to execute a tool call. The gate intercepts it, evaluates policy, routes the decision to a human's phone, the human denies it, the agent is blocked, and a cryptographically chained audit entry records exactly what happened — including who denied it, when, and which signing algorithm protects the evidence.

This is not a dashboard. This is structural enforcement with cryptographic evidence.

---

## Prerequisites

1. **Gate active** — remove `~/.claude/.gate-disabled` if present
2. **Telegram dispatcher running** — `pgrep -f zlar-tg-poll` should return PIDs
3. **Telegram app open** on phone — @ZLAR_00_bot chat visible
4. **Clean inbox** — `rm /var/run/zlar-tg/inbox/cc/*.json 2>/dev/null` (clears stale callbacks)
5. **Claude Code session** open in terminal

---

## The Flow (5 minutes)

### Act 1: The Intercept (30 seconds)

Open Claude Code. Ask it to do something the policy classifies as `ask`:

```
push my changes to github
```

Claude Code will run `git push origin main`. The gate intercepts it.

**What happens internally:**
- PreToolUse hook fires → `zlar-gate.sh` → `repo/bin/zlar-gate`
- Gate loads signed policy (Ed25519-verified, cached by content hash)
- Rule R014 matches: `git push` → action=ask, risk=75/100, severity=warn
- Gate sends Telegram message, emits `ask_sent` audit entry with `outcome: "pending"`

### Act 2: The Human Decision (30 seconds)

Your phone buzzes. Telegram shows:

```
🟡 🖥️ ZLAR Gate

Tool: Bash
Action: git push origin main
Risk: 75/100
Rule: R014
Session: <session_id>

[✅ Approve]  [❌ Deny]
```

**Tap ❌ Deny.**

The message updates to `🖥️ ▪️ Denied` — muted, completed state.

### Act 3: The Block (instant)

Back in the terminal, Claude Code shows:

```
[human] Denied by human (rule R014)
```

The command did not execute. The agent was stopped. Not by a log entry after the fact — by structural enforcement before execution.

### Act 4: The Evidence (2 minutes)

Now show what the audit trail recorded. Two entries for one decision:

**Entry 1 — The request (seq 1):**
```json
{
  "outcome": "pending",
  "action": "ask_sent",
  "rule": "R014",
  "risk_score": 75,
  "authorizer": "gate",
  "signature_algorithm": "Ed25519",
  "hash_algorithm": "SHA-256",
  "public_key_id": "88aaeeaca05eba4d",
  "prev_hash": "<sha256 of previous entry>"
}
```

**Entry 2 — The decision (seq 2):**
```json
{
  "outcome": "denied",
  "authorizer": "human:7662799203",
  "rule": "R014",
  "risk_score": 75,
  "signature_algorithm": "Ed25519",
  "hash_algorithm": "SHA-256",
  "public_key_id": "88aaeeaca05eba4d",
  "prev_hash": "<sha256 of entry 1>"
}
```

Point out:
- **`authorizer: "human:7662799203"`** — not "system denied" or "policy denied." A specific human, identified by Telegram ID, made this decision. Non-repudiable.
- **`prev_hash`** — SHA-256 of the previous entry. Tamper with any entry and every subsequent hash breaks. Same structural integrity as a blockchain, without the consensus overhead.
- **`signature_algorithm: "Ed25519"`** — the entry labels its own cryptographic assumptions. When NIST deprecates Ed25519 after 2030, migration tooling reads this field and knows exactly which entries need re-signing. We designed for this today.
- **`seq: 1` → `seq: 2`** — the pending/resolution pair. The audit trail records not just what happened but the temporal structure of the decision.

### Act 5: The Registry (1 minute)

Show the agent inventory:

```bash
zlar-registry list --json
```

Output shows every agent the gate has ever seen — identity, first/last seen, session count, denial rate. No registration required. The audit trail IS the registry.

```bash
zlar-registry stats --json
```

Shows aggregate governance metrics: denial rates, human authorization rates, average risk scores.

**Close:** "The gate enforces. The evidence trail proves what happened. The registry shows who's here. The human decides — on their phone, in ten seconds, with full context. That's the governance primitive."

---

## Alternate: The Approve Path

If you want to show approve too, trigger the same flow and tap ✅ Approve. The audit entry will show:

```json
{
  "outcome": "authorized",
  "authorizer": "human:7662799203"
}
```

And the command executes. Same evidence, opposite decision. The structure doesn't change — only the human's judgment.

---

## Alternate: The Policy Deny Path

To show enforcement without human involvement:

Ask Claude Code to do something the policy blocks outright (no ask, just deny):

```
read the gate log file using a bash command
```

The gate blocks it immediately:

```
[policy] Blocked by rule R012: ZLAR enforcement modification — blocked
```

No Telegram message. No human needed. The policy is structurally superior — the agent cannot override it. Point out: R012 protects the gate's own infrastructure. The governor governs itself.

---

## What This Demonstrates (Forrester Pillars)

| Pillar | What they see |
|--------|--------------|
| **1. Agent Inventory** | `zlar-registry` — every agent surfaced from audit trail |
| **2. Policies & Guardrails** | Signed policy, rule evaluation, `forbid`/`unless` semantics (Cedar PoC) |
| **3. Monitoring & Insights** | Real-time Telegram notifications, audit trail as single source of truth |
| **4. Control & Coordination** | Human-in-the-loop approve/deny, availability modes (active/away/review) |
| **5. Risk, Compliance & Audit** | Hash-chained entries, PQC metadata, non-repudiable human authorization |

Five pillars. One flow. One primitive.

---

## Common Questions

**"What if the human doesn't respond?"**
Configurable timeout (default 900s). On timeout, the action is denied and logged as `authorizer: "gate:timeout"`. Fail-closed.

**"What if the human is away?"**
Availability modes: `active` (route to Telegram), `away` (auto-allow low-risk, queue/deny high-risk), `review` (catch up on queued items). The gate adapts to the human's presence without weakening enforcement.

**"Can the agent override the gate?"**
No. The gate sits below the agent as a PreToolUse hook. The agent's tool call is intercepted before execution. The agent doesn't volunteer to be governed — it is governed by architecture.

**"What about multiple agents?"**
The OC gate governs a second agent (Bohm/OpenClaw). Same unified audit trail. `zlar-registry` sees all agents across both gates. Same Telegram bot, emoji-prefixed (🖥️ CC, 🦞 OC).

**"How do you know the audit trail hasn't been tampered with?"**
Hash chain. Each entry's `prev_hash` is the SHA-256 of the previous entry. Alter any entry and every subsequent hash is wrong. The chain is its own proof.

**"What about post-quantum?"**
Every entry carries `signature_algorithm` and `hash_algorithm` metadata. SHA-256 (the chain hash) is quantum-safe. Ed25519 (the signing algorithm) is not — NIST deprecates it after 2030. We've designed for migration today: algorithm metadata in every record, so tooling knows what to re-sign when ML-DSA arrives.
