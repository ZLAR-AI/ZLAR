# ZLAR Architecture Map

**Purpose:** Load-bearing, non-obvious facts about ZLAR's structure that aren't visible from reading any single file. Read this before making architectural changes — especially changes that remove, replace, or modify enforcement components — to avoid the failure mode where one component is changed and a parallel one silently breaks.

This document is the answer to "what does this change actually touch?" — the cross-file dependencies that grep alone is slow to surface. It is updated alongside any architectural change.

**Last updated:** v3.0.0 — April 12, 2026

---

## Two parallel gate implementations

ZLAR has TWO gates that enforce the same five human invariants on agent activity:

| Gate | Implementation | Hooks into | Library sourced |
|---|---|---|---|
| **CC gate** | `bin/zlar-gate` (bash) | Claude Code, via `~/.claude/settings.json` PreToolUse | `lib/human-invariants.sh` |
| **MCP gate** | `mcp-gate/gate.mjs` (Node.js) | MCP server stack | `lib/human-invariants.mjs` |

**Both implementations share the same state directory: `repo/var/human-state/`.** Per-human JSON files named `<telegram_chat_id>.json`. Both implementations agree on schema. Both update the same files concurrently.

**Implication for changes:** any schema change to the state files MUST be applied to both `lib/human-invariants.sh` AND `lib/human-invariants.mjs` simultaneously, plus migration logic for old-format files, plus updates to test fixtures in `tests/test-human-invariants.sh` (which hardcode schema fields in test setup, currently at lines 109, 120, 145, 226).

---

## The First Authority chain (v2.7.0 overlap period)

The order in which a Claude Code tool call passes through enforcement layers:

1. **Claude Code reads `~/.claude/settings.json`** — points the PreToolUse hook at `~/.claude/zlar-gate.sh` (the wrapper).
2. **Wrapper checks `~/.claude/.gate-disabled`** — if present, returns allow immediately. *This is the legacy off-switch path. v2.6.0 had this as the only off-switch.*
3. **Wrapper does `.env` parsing** for `TELEGRAM_BOT_TOKEN` (also done in step 6; redundant but harmless).
4. **Wrapper exec's `bin/zlar-gate`** — the real gate binary.
5. **bin/zlar-gate checks `/etc/zlar/off-flag`** — if present, returns allow immediately. **This is the v2.7.0 structural off-switch** — root-owned, sudoers-NOPASSWD-toggleable, agent cannot reach.
6. **Policy load and signature verification** — `etc/policies/active.policy.json`, verified against `etc/keys/policy-signing.pub`.
7. **Policy evaluation** — apply rules to the tool call. Rules can return allow / deny / ask.
8. **Human invariants** — H6 (daily decision cap), H13 (pending queue), H14 (response time variance), H15 (deliberation floor), H17 (authenticity).
9. **Session state escalation** — velocity, loop, and denial burst detection (step 9). Novelty detection for first-use domains (step 9b).
9c. **Restore / Agent Health check (v3.0.0)** — if `etc/restore-config.json` is enabled and a trust state file exists, may escalate allow/log to ask or deny based on trust state (healthy / degraded / at_risk / suspended). Error-trapped: cannot crash the gate (RESTORE-INV-04). Reads `lib/restore.sh`.
10. **Telegram approval (if needed)** — route to @ZLAR_00_bot for the human to decide.
11. **Audit log entry** — written to `var/log/audit.jsonl` with signature.
12. **Restore background trigger (v3.0.0)** — on deny, novelty, or high-risk (70+) outcomes, fires `lib/restore-trigger.mjs` in the background. Reads the audit trail, runs 5 detectors, updates trust state monotonically, sends Telegram notification on state change. Non-blocking.

The first allow in this chain is THE SOVEREIGN. v2.6.0 had its sovereign at `~/.claude/.gate-disabled` — agent-writable. v2.7.0 adds a second sovereign at `/etc/zlar/off-flag` — agent-unreachable. During the overlap period, both check independently; either being present means the gate is off.

---

## Off-switch architecture (v2.7.0)

The structural off-switch lives at `/etc/zlar/off-flag`. Properties:

- **Filesystem permissions:** root-owned, mode 644. Agent cannot write `/etc/` without sudo.
- **Sudo policy:** `/etc/sudoers.d/zlar` grants the user NOPASSWD on EXACTLY two commands: `/usr/bin/touch /etc/zlar/off-flag` and `/bin/rm -f /etc/zlar/off-flag`. No other commands.
- **Agent reach:** R003 in the policy denies any bash command containing `sudo` (regex `\b(sudo|visudo|dscl)\b`). Combined with filesystem permissions, the agent has no path to write the flag.
- **CLI entry points:** `repo/bin/zlar off|on` and `tools/zlar off|on`. Both write BOTH the wrapper flag (`~/.claude/.gate-disabled`) AND the structural flag (`/etc/zlar/off-flag`) during the overlap period.
- **Direct invocation:** `sudo -n touch /etc/zlar/off-flag` from any shell (relies on the sudoers entry).

**The sudoers entry is a TCB component.** If `/etc/sudoers.d/zlar` is removed or modified, the CLI can no longer toggle the structural flag (the wrapper path still works as fallback). Any installation or migration procedure must preserve it.

**Known gap (v2.7.0):** `repo/bin/zlar` and `tools/zlar` are NOT in R032's path-protection regex. An agent could theoretically overwrite the CLI to lie about gate state. This is a UX-deception attack, not a security bypass — the actual gate still runs. v2.8 backlog item: extend R032 to cover the CLI scripts.

---

## Restore subsystem (v3.0.0 — Agent Health)

ZLAR 3.0 adds a behavioral observation layer that runs alongside the enforcement gate.

| Component | File | Purpose |
|---|---|---|
| Shell layer | `lib/restore.sh` | Sourced by `bin/zlar-gate`. Reads trust state file, advises on escalation. Error-trapped. |
| Config | `etc/restore-config.json` | Feature gate (`enabled: false` by default). Escalation mappings, reset constraints. |
| Trust state | `var/restore/trust-state.json` | Monotone state machine: healthy / degraded / at_risk / suspended. Written by trigger, read by shell layer. |
| Trigger | `lib/restore-trigger.mjs` | Backgrounded by gate on deny/novelty/high-risk. Reads audit trail, runs detectors, updates trust state, sends Telegram. |
| Engine | `packages/zlar-restore/restore-engine.mjs` | Loads and runs detectors, aggregates scores, produces recommendation. |
| Trust machine | `packages/zlar-restore/trust-state.mjs` | Monotone transition logic. Reset with friction (reason, delay, count). |
| Detectors | `packages/zlar-restore/detectors/` | 5 files: contradiction, escalation, grounding loss, burstiness, authority widening. |
| CLI | `bin/zlar-restore` | Operator interface: evaluate, status, reset, history, detectors. |
| Invariants | `docs/RESTORE-INVARIANTS.md` | 8 invariants (RESTORE-INV-01 through -08). |

**Key architectural fact:** when `enabled: false` (the default), ALL restore code paths short-circuit. The gate runs identically to v2.x. No trust state files are created, no detectors run, no background triggers fire. This is the version boundary: 2.x = enforcement only, 3.x = enforcement + behavioral observation.

**Implication for changes:** the shell layer (`lib/restore.sh`) and the Node.js engine (`packages/zlar-restore/`) are NOT parallel implementations of the same logic (unlike the two gates). They have different responsibilities. The shell layer reads state and advises. The Node.js engine writes state. Changing one does not require changing the other — but the trust state file format must stay consistent between them.

---

## Pre-existing files in `/etc/zlar/`

| File | Purpose | Owner | Origin |
|---|---|---|---|
| `admin-user` | tg-poll daemon config: persistent admin username for boot-time user resolution. 14 bytes. **Do not modify.** | root:wheel | April 6, 2026 (tg-poll daemon fix session) |
| `off-flag` | v2.7.0 structural off-switch. Created/removed by CLI via sudoers NOPASSWD. Presence means gate is off. | root:wheel | v2.7.0 (April 7, 2026) |

---

## State directory

`repo/var/human-state/` contains per-human state files. File naming: `<telegram_chat_id>.json`. The Telegram chat ID is the human's identity within the gate.

**Schema (v2.7.0):**
```json
{
  "human_id": "<telegram_chat_id>",
  "date": "YYYY-MM-DD",
  "decisions_today": <int>,
  "approvals_recent": [<bool>, ...],
  "pending_count": <int>,
  "last_ask_epoch": <unix_seconds>
}
```

**Field semantics:**
- `decisions_today` — H6 daily decision counter. Resets at midnight UTC via `_hi_ensure_state` date-rollover logic.
- `pending_count` — H13 pending queue counter. **As of v2.7.0, also resets at midnight UTC** alongside `decisions_today` (belt fix for the leak documented below). Full TTL fix is in the v2.8.0 backlog.
- `approvals_recent` — H14 rolling window of recent approve/deny decisions.
- `last_ask_epoch` — H15/H17 timing reference for deliberation and authenticity checks.

**Created by:** `_hi_ensure_state` in `lib/human-invariants.sh` (and equivalent in `.mjs`). Lazily created on first reference.

**Reset path:** `ZLAR reset` (added v2.7.0). Backs up to `/tmp/zlar-state-backup-<timestamp>/` before deleting the .json file. Next gate invocation auto-recreates with zero values.

**Known issue:** `pending_count` can leak intra-day if asks increment without responses (crash, timeout, session end). v2.7.0 fixes this at midnight rollover and via the manual reset CLI. v2.8.0 will add per-ask TTL for continuous self-healing.

---

## Policy signing — root of trust

| File | Role |
|---|---|
| `etc/policies/active.policy.json` | The signed policy. Loaded by both gates at startup. |
| `etc/keys/policy-signing.pub` | Public key. Used for verification. Committed. |
| `~/.zlar-signing.key` | Private key. Used for signing. **Never committed.** Root of trust. |
| `bin/zlar-policy` | The signing/verification CLI. |

**Procedure for changing a policy rule:**
1. Edit `etc/policies/active.policy.json` (this invalidates the existing signature)
2. Re-sign: `bin/zlar-policy sign --input etc/policies/active.policy.json --key ~/.zlar-signing.key --output etc/policies/active.policy.json`
3. Verify: `bin/zlar-policy verify --input etc/policies/active.policy.json`

The gate refuses to load a policy with an invalid signature.

---

## Wrapper status (v2.7.0 overlap)

The wrapper at `~/.claude/zlar-gate.sh` is still in the chain in v2.7.0. It performs four functions:

1. **Kill-switch check on `~/.claude/.gate-disabled`** — **load-bearing** (legacy off-switch path)
2. `.env` parsing for `TELEGRAM_BOT_TOKEN` — duplicated in `bin/zlar-gate` line ~138, removable
3. macOS `osascript` startup notification — UX-only, removable
4. `exec "${REAL_HOOK}"` — delegation to `bin/zlar-gate`

**Removal plan:** the wrapper is scheduled for removal in a future release (v2.8 or v2.9), only after the v2.7.0 structural off-switch has been verified in production for at least one release cycle. **Do not delete the wrapper without first verifying the new sovereign at `/etc/zlar/off-flag` is the only path the user uses to toggle.** The kill-switch in step 1 must be relocated, not just deleted.

---

## Why this document exists

This document was created in response to an architectural change attempted in early v2.7.0 that nearly removed a load-bearing function (the wrapper's kill-switch, which is also the human's only off-switch in v2.6.0) without realizing it was load-bearing. The kill-switch looked like part of an indirection layer that could be removed for cleanup. It wasn't. Removing it meant removing the human override entirely.

The lesson: **before removing or modifying enforcement code, enumerate every function it performs and verify each one is either (a) duplicated elsewhere, (b) explicitly out of scope and the regression accepted, or (c) replaced before removal.** The grep step that would have caught the kill-switch issue was simple. It wasn't done before committing to the plan.

This document is the place where future contributors (human or AI) can find the load-bearing facts that aren't obvious from any single file. If you're about to make an architectural change to ZLAR's gate, sources, policy, or state schema:

1. **Read this document first.**
2. Then grep for the specific symbols you're touching, across all files.
3. Then propose.
4. Then verify.
5. Then execute.

---

## Document maintenance

When you change ZLAR's architecture, update this document in the same commit. Specifically:

- Adding a new gate or runtime → add a row to "Two parallel gate implementations"
- Adding to the first authority chain → update the numbered list
- Adding files to `/etc/zlar/` → update that table
- Changing state schema → update the schema block and field semantics
- Removing the wrapper → rewrite the wrapper section to "removed in vX.Y" with a brief note about how the kill-switch was relocated

This document is the architecture truth. If the document and the code disagree, fix one of them — don't leave them in disagreement.
