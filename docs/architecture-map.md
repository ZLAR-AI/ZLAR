# ZLAR Architecture Map

**Purpose:** Load-bearing, non-obvious facts about ZLAR's structure that aren't visible from reading any single file. Read this before making architectural changes — especially changes that remove, replace, or modify enforcement components — to avoid the failure mode where one component is changed and a parallel one silently breaks.

This document is the answer to "what does this change actually touch?" — the cross-file dependencies that grep alone is slow to surface. It is updated alongside any architectural change.

**Last updated:** v3.3.17-dev — May 17, 2026

---

## Two parallel gate implementations

ZLAR has TWO gate implementations that enforce the same human-invariant machinery
on action surfaces that are actually routed or intercepted:

| Gate | Implementation | Hooks into | Library sourced |
|---|---|---|---|
| **Bash / hook gate** | `bin/zlar-gate` (bash) | PreToolUse- or adapter-routed tool events, including Codex/Claude-compatible hook surfaces when configured | `lib/human-invariants.sh` |
| **MCP gate** | `mcp-gate/gate.mjs` (Node.js) | MCP `tools/call` requests only when the MCP client is routed through the ZLAR proxy | `lib/human-invariants.mjs` |

Installing a client is not governance. A surface is governed only when the
action crosses one of these gates before effect.

**Both implementations share the same state directory: `repo/var/human-state/`.** Per-human JSON files named `<telegram_chat_id>.json`. Both implementations agree on schema. Both update the same files concurrently.

**Implication for changes:** any schema change to the state files MUST be applied to both `lib/human-invariants.sh` AND `lib/human-invariants.mjs` simultaneously, plus migration logic for old-format files, plus updates to test fixtures in `tests/test-human-invariants.sh` (which hardcode schema fields in test setup, currently at lines 109, 120, 145, 226).

---

## The First Authority chain

The order in which a hook-routed tool call passes through enforcement layers:

1. **The client reads its hook/profile configuration** — for example Codex
   `~/.codex/hooks.json` or Claude Code `~/.claude/settings.json` — and points
   the PreToolUse surface at a ZLAR wrapper.
2. **Wrapper checks `~/.claude/.gate-disabled`** — if present, returns allow immediately. *This is the legacy off-switch path. v2.6.0 had this as the only off-switch.*
3. **Wrapper does `.env` parsing** for `TELEGRAM_BOT_TOKEN` (also done in step 6; redundant but harmless).
4. **Wrapper exec's `bin/zlar-gate`** — the real gate binary.
5. **bin/zlar-gate checks `/etc/zlar/off-flag`** — if present, returns allow immediately. **This is the structural off-switch** — root-owned, sudoers-NOPASSWD-toggleable, agent cannot reach.
6. **Policy load and signature verification** — `etc/policies/active.policy.json`, verified against `etc/keys/policy-signing.pub`.
7. **Policy evaluation** — apply rules to the tool call. Rules can return allow / deny / ask.
8. **Human invariants** — H6 (daily decision cap), H13 (pending queue), H14 (response time variance), H15 (deliberation floor), H17 (authenticity).
9. **Session state escalation** — velocity, loop, and denial burst detection (step 9). Novelty detection for first-use domains (step 9b).
9c. **Restore / Agent Health check (v3.0.0)** — if `etc/restore-config.json` is enabled and a trust state file exists, may escalate allow/log to ask or deny based on trust state (healthy / degraded / at_risk / suspended). Error-trapped: cannot crash the gate (RESTORE-INV-04). Reads `lib/restore.sh`.
10. **Telegram approval (if needed)** — route to @ZLAR_00_bot for the human to decide.
11. **Audit log entry** — written to `var/log/audit.jsonl` with signature.
12. **Restore background trigger (v3.0.0)** — on deny, novelty, or high-risk (70+) outcomes, fires `lib/restore-trigger.mjs` in the background. Reads the audit trail, runs 7 detectors, updates trust state monotonically, sends Telegram notification on state change. Non-blocking.

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
| Detectors | `packages/zlar-restore/detectors/` | 8 files: contradiction_increase, escalation_under_ambiguity, source_grounding_loss, abnormal_burstiness, authority_widening, entropy_shift, action_silence, governance_vacuum. |
| Config integrity | `packages/zlar-restore/config-integrity.mjs` | HMAC sign/verify for restore-config.json. Sidecar file (.hmac). |
| CLI | `bin/zlar-restore` | Operator interface: evaluate, status, reset, history, detectors, sign-config. |
| Invariants | `docs/RESTORE-INVARIANTS.md` | 14 invariants (RESTORE-INV-01 through -14). |

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

**Schema (v3.3.6, current):**
```json
{
  "human_id": "<telegram_chat_id>",
  "date": "YYYY-MM-DD",
  "decisions_today": <int>,
  "response_times": [{"elapsed": <int>, "severity": "<class>"}, ...],
  "pending": [{"action_hash": "<sha256>", "ts": <unix_seconds>}, ...],
  "last_ask_epoch": <unix_seconds>,
  "trust_lane": "fast" | "guarded" | "slow",
  "trust_lane_grant": { "source": "authority", "granted_at": <epoch>, "reason": "<str>" },
  "clean_run_count": <int>,
  "clean_run_started_epoch": <unix_seconds>,
  "canary_approvals_since_last": <int>,
  "canary_last_epoch": <unix_seconds>,
  "canary_pending_id": "<canary_id_or_empty>",
  "canary_pending_session_id": "<session_id_or_empty>",
  "canary_pending_started_epoch": <unix_seconds>
}
```

**Field semantics:**
- `decisions_today` — H6 daily decision counter. Resets at midnight UTC via `_hi_ensure_state` date-rollover logic.
- `pending` — H13 pending array (v2.8.0 rewrite). Each entry is `{action_hash, ts}`. On every increment, stale entries (older than `HI_PENDING_TTL`, default 1800s) are filtered before counting; a retry with the same `action_hash` does not re-append. Replaces the v2.7.x scalar `pending_count` which leaked under orphaned increments and retries.
- `response_times` — H14 rolling window of `{elapsed, severity}` pairs, last 20 decisions. Replaces the v2.7.x `approvals_recent` approval-rate tracking. H14 now measures response-time variance on warn/info decisions; low variance fires `canary_pattern_check` (advisory). Critical decisions are excluded from variance (H15's 30s floor creates artificial uniformity that would falsely fire H14). When H14 fires, `response_times` is cleared so the window starts fresh.
- `last_ask_epoch` — H15/H17 timing reference for deliberation and authenticity checks.
- `trust_lane` — v3.3.0 lane state. `fast` (H14 bypassed; H15/H17 floors at 500ms minimum), `guarded` (default; full floors), `slow` (reserved). Survives UTC rollover.
- `trust_lane_grant` — v3.3.0 manual authority grant (terminal-only, TTY-gated, HMAC-sealed). Bootstraps lane=fast at grant time. v3.3.4: grant does not shortcut auto-promotion and does not shield from demotion.
- `clean_run_count` — v3.3.4 consecutive healthy canary outcomes. Five consecutive promote one lane (slow→guarded, guarded→fast). Reset to 0 on promotion, demotion, or canary failure/miss. Capped at threshold when `auto_promotion_enabled=false`. ZLAR does not score the human. It watches the run.
- `clean_run_started_epoch` — v3.3.4 telemetry; epoch when the current run began (count went 0→1). Cleared on demotion or promotion. Persists across UTC rollover (a run is logical, not calendar-bound).
- `canary_approvals_since_last` — v3.3.6 per-human trigger counter. Increments on each human-approved ask. Reset to 0 by `canary_send`. Replaces the per-session counter that lived in `var/canary/{session_id}.canary.json`.
- `canary_last_epoch` — v3.3.6 cooldown anchor. Set by `canary_send` to the moment the canary fired. `canary_should_trigger` requires `now - canary_last_epoch >= cooldown_s` before allowing a new probe.
- `canary_pending_id` — v3.3.6 per-human pending lock. The canary id of the outstanding probe, or empty string. While non-empty, no new canary fires for this human (across any session). Cleared on resolution (passed/failed/missed/pending_lost).
- `canary_pending_session_id` — v3.3.6 routing pointer. The session that issued the outstanding canary. Used by `canary_check_result` to locate the per-session `.pending` artifact regardless of which session is currently running. Empty when nothing is pending.
- `canary_pending_started_epoch` — v3.3.6 staleness reference. Epoch when the canary was sent. Used to distinguish in-flight probes from genuinely stale ones in the missing-artifact branch of `canary_check_result`.

All five v3.3.6 canary fields persist across UTC rollover. The canary lifecycle is event-driven, not calendar-bound — a probe in flight at midnight UTC must still resolve correctly.

**v3.3.6 canary trigger architecture:**

Trigger eligibility (counter, cooldown, pending lock) is **per-human**, not per-session. A clean run earns future canary opportunity across sessions; the human is what the system is calibrating, not the Claude session. Pre-v3.3.6 these counters lived in `var/canary/{session_id}.canary.json` and reset on every new session, making recovery accidentally harder across short sessions.

The `.pending` file at `var/canary/{session_id}.canary.pending` stays as a routing artifact for the inbox handler, but authoritative state is the per-human record. `canary_check_result` is keyed on `human_id` and reads `canary_pending_session_id` to find the artifact — a canary fired in session A is resolvable by any later gate invocation under the same human, in any session.

**Demotion requires evidence, not absence of evidence.**
- `canary_failed` (callback approve) — evidence of fatigue → demote.
- `canary_missed` (artifact present, age > timeout, no callback) — evidence the human ignored a real prompt → demote.
- `canary_pending_lost` (state says pending, but routing artifact is missing) — bookkeeping fault, not human behavior → clear pending state, emit `canary_pending_lost` warn audit event, **do not touch trust lane**. Distinguishes a safety system from a superstition machine.

**Created by:** `_hi_ensure_state` in `lib/human-invariants.sh` (and equivalent in `.mjs`). Lazily created on first reference. Includes v2.8.0 schema migration that drops any lingering `pending_count` / `approvals_recent` scalars.

**Reset path:** `ZLAR reset` (added v2.7.0). Backs up to `/tmp/zlar-state-backup-<timestamp>/` before deleting the .json file. Next gate invocation auto-recreates with zero values.

**Known issues resolved:** the v2.7.x `pending_count` scalar leak under orphaned increments is fixed in v2.8.0 via the TTL+dedup array. H14 self-sealing resolved: when H14 fires, `response_times` is cleared so the min-sample check fails and H14 returns ok on the next pre-ask. Gate advisory semantics ensure asks still route during detection, so new decisions accumulate naturally.

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
