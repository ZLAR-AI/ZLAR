# ZLAR CLI Reference

The `zlar` command is the operator's interface to the ZLAR governance system. It exposes the controls a human needs to administer the gate, inspect state, and respond to runtime issues.

This document is the reference for **what each command does**. For symptom-based problem-solving, see [`troubleshooting.md`](troubleshooting.md). For architectural context, see [`architecture-map.md`](architecture-map.md). For the doctrine, see [`../signal/DOCTRINE.md`](../signal/DOCTRINE.md).

**Last updated:** v2.7.0 — April 7, 2026

---

## Notation

Throughout this document:

- `${PROJECT_DIR}` refers to your ZLAR install root. For users running an installed copy, this is typically `~/.zlar`. For developers working in the repo, it is the repo path (e.g., `~/Desktop/ZLAR/repo`). The `zlar` script computes it automatically from its own location.
- `~` refers to the current user's home directory.
- Examples that show file paths use absolute paths so you can copy-paste them.

---

## Quick reference

| Command | Purpose | Side effects |
|---|---|---|
| `zlar status` | Show gate state, human invariant state, frameworks, policy, telegram, audit | None (read-only) |
| `zlar on` | Enable enforcement (remove off-flags) | Modifies `~/.claude/.gate-disabled` and `/etc/zlar/off-flag` |
| `zlar off` | Disable enforcement (write off-flags) | Modifies `~/.claude/.gate-disabled` and `/etc/zlar/off-flag` |
| `zlar reset` | Clear human invariant state (escape hatch for stuck H13) | Backs up + deletes state files in `${PROJECT_DIR}/var/human-state/` |
| `zlar doctor` | Run installation health check | None (read-only) |
| `zlar audit [N]` | Show last N audit entries (default 20) | None (read-only) |
| `zlar policy` | Show current policy rules summary | None (read-only) |
| `zlar version` | Show ZLAR version and install path | None (read-only) |
| `zlar telegram` | Configure Telegram approval (interactive) | Modifies `${PROJECT_DIR}/.env` and `${PROJECT_DIR}/etc/gate.json` |
| `zlar uninstall` | Remove the ZLAR installation (interactive) | Destructive — see the command for exact behavior |
| `zlar help` | Show command list | None |

---

## Setup (one-time, v2.7.0 and later)

ZLAR v2.7.0 introduced a structural off-switch at `/etc/zlar/off-flag`. This requires a one-time sudoers entry that grants the user passwordless `touch` and `rm` on EXACTLY that file path — nothing else.

```bash
sudo mkdir -p /etc/zlar
sudo chmod 755 /etc/zlar
echo "$USER ALL=(root) NOPASSWD: /usr/bin/touch /etc/zlar/off-flag, /bin/rm -f /etc/zlar/off-flag" | sudo tee /etc/sudoers.d/zlar >/dev/null
sudo chmod 440 /etc/sudoers.d/zlar
sudo visudo -c
```

The last command should print:
```
/etc/sudoers: parsed OK
/etc/sudoers.d/zlar: parsed OK
```

Verify the NOPASSWD entry works without prompting:
```bash
sudo -n touch /etc/zlar/off-flag
sudo -n rm -f /etc/zlar/off-flag
```

If sudoers is not configured, `zlar off` and `zlar on` still work via the wrapper-flag fallback (`~/.claude/.gate-disabled`), but the structural off-switch will not be exercised. You will see a one-line warning on `zlar off`:

```
  (warn: /etc/zlar/off-flag not writable; wrapper path still active)
```

The wrapper-flag fallback is the v2.6.0 behavior. The structural off-switch is the v2.7.0 architectural improvement that puts the kill-switch in a path the agent cannot reach. **Both are checked**; either being present means the gate is off.

For the architectural rationale, see [`architecture-map.md`](architecture-map.md) — the "First Authority chain" section.

---

## Daily-use commands

### `zlar status`

Shows current gate state, human invariant state, governed frameworks, policy summary, telegram status, and audit count. The most useful command when something seems wrong.

```bash
zlar status
```

Example output:

```
ZLAR Status

  Version:  2.7.0
  Install:  ${PROJECT_DIR}

  Gate State:
    Wrapper flag (~/.claude/.gate-disabled):    present (2026-04-07 08:58)
    Structural flag (/etc/zlar/off-flag):       absent
    Resolved gate state:                         OFF (wrapper flag)
    Hook target (PreToolUse):                    /Users/yourname/.claude/zlar-gate.sh

  Human Invariant State:
    Human ID:                                    7***9203
    State date:                                  2026-04-07
    decisions_today:                             0 / 80
    pending_count:                               0 / 5
    approvals_recent:                            0 entries
    last_ask_epoch:                              never
    State file:                                  ${PROJECT_DIR}/var/human-state/7***9203.json

  Frameworks: [...]
  Policy: [...]
  Telegram: [...]
  Audit: [...]
```

**Read this when:**
- Tool calls are unexpectedly being blocked or allowed
- You want to confirm the gate is in the state you think it is
- Diagnosing whether `pending_count` has hit the H13 cap (it will show as `⚠ OVER CAP` in red)
- Checking the hook target to verify it points where you expect

The Human ID is partially masked for privacy when the output is shared (e.g., screenshots, support requests).

### `zlar off`

Disable enforcement. The gate short-circuits to allow on every invocation. No policy evaluation, no human invariant checks, no telegram routing.

```bash
zlar off
```

Output:
```
Gate OFF — Claude unblocked
```

What it does:
- Touches `~/.claude/.gate-disabled` (wrapper kill-switch path, legacy)
- Touches `/etc/zlar/off-flag` via passwordless sudo (structural kill-switch path, v2.7.0+)
- If sudoers isn't configured, prints a warning and the structural path is skipped (wrapper path still works)

**Use when:**
- You are actively building or modifying ZLAR itself and don't want to be governed by it
- Running tests or experiments where the gate would interfere
- You have explicit human authority to suspend enforcement temporarily

The First Authority Law says the human is the sovereign. `zlar off` is the human exercising that sovereignty. It is structurally distinct from an agent disabling enforcement — which is impossible by design, because the agent cannot reach `/etc/zlar/` without sudo, and policy rule R003 denies all sudo from the bash domain.

### `zlar on`

Enable enforcement. Removes both off-flags.

```bash
zlar on
```

Output:
```
Gate ON — policy enforced
```

After running, the next tool call from a governed framework will hit the gate and be evaluated against policy + invariants.

**Important:** if `pending_count` is currently > the cap (H13 stuck state), turning the gate on will cause every subsequent tool call to be blocked. Run `zlar status` first to check, and `zlar reset` if the state is stuck.

### `zlar reset`

Clear human invariant state. The escape hatch when H13 (or any other invariant) gets stuck due to a leak from a previous session.

```bash
zlar reset
```

Output:
```
Human state reset — backed up to /tmp/zlar-state-backup-20260407-092133
  state files will recreate on next gate invocation
```

What it does:
- Finds all `.json` files in `${PROJECT_DIR}/var/human-state/`
- Copies them to `/tmp/zlar-state-backup-<timestamp>/` (preserves timestamps with `cp -p`)
- Deletes the originals
- The next invocation of the gate that calls `_hi_ensure_state` will recreate the file with zeroed counters

**Use when:**
- `zlar status` shows `pending_count: N ⚠ OVER CAP` and you can't figure out why
- A previous Claude Code session crashed mid-ask and left orphaned pending counters
- You want a clean slate for testing

**Recovery:** the backup at `/tmp/zlar-state-backup-<timestamp>/` is one `cp` away from restoring the pre-reset state. It is not auto-deleted.

---

## Diagnostic commands

### `zlar doctor`

Run a 7-section diagnostic that checks dependencies, keys, policy, hooks, gate, audit, and telegram. The first thing to run when something is wrong.

```bash
zlar doctor
```

Output groups (each section either ✓ or ✗):

- Dependencies (jq, openssl, bash version)
- Cryptographic keys (signing key permissions and presence)
- Policy (file present, signature valid)
- Hooks (settings.json wired correctly for each governed framework)
- Gate (binary exists, executable, version matches)
- Audit (log file present, recent entries)
- Telegram (token present, dispatcher running, HMAC secret readable)

If `doctor` is green and you're still seeing weird behavior, escalate to `zlar status` for runtime state, then [`troubleshooting.md`](troubleshooting.md) for symptom-based fixes.

### `zlar audit [N]`

Show the last N audit log entries (default 20). Each entry is one line per decision.

```bash
zlar audit          # last 20
zlar audit 100      # last 100
```

Each line shows: timestamp, decision (allow/deny/ask), tool name, rule ID. Color-coded: allow green, deny red, ask yellow.

For raw JSON access:
```bash
tail -100 ${PROJECT_DIR}/var/log/audit.jsonl
```

### `zlar policy`

Show the current policy file's rules in summary form: rule ID, action, description.

```bash
zlar policy
```

For full rule details:
```bash
cat ${PROJECT_DIR}/etc/policies/active.policy.json | jq .
```

### `zlar version`

Show the version string and the installation path.

```bash
zlar version
```

The version string is read from `${PROJECT_DIR}/VERSION`. If that file is missing, version reports as "unknown".

### `zlar help`

Show the command list with one-line descriptions. Useful when you've forgotten a command name.

---

## Configuration commands

### `zlar telegram`

Interactive setup for Telegram approval. Prompts for bot token and chat ID, writes them to `.env` and `gate.json`.

```bash
zlar telegram
```

Prerequisites (set up via the Telegram client first):
1. Create a bot via @BotFather, get the token
2. Get your chat ID via @userinfobot

The command writes:
- Bot token → `${PROJECT_DIR}/.env` (mode 600)
- Chat ID + `telegram.enabled = true` → `${PROJECT_DIR}/etc/gate.json`

After this, denied actions get routed to your Telegram for approval/denial instead of instantly blocked.

---

## Maintenance commands

### `zlar uninstall`

Remove the ZLAR installation. Interactive — prompts for confirmation before doing anything destructive.

```bash
zlar uninstall
```

Run the command to see its current behavior. As of v2.7.0, the v2.7.0 sudoers entry, the `/etc/zlar/` directory, and the wrapper kill-switch flag may need to be cleaned up manually depending on how thorough you want the removal to be — check the command output for what it touches.

---

## The two CLI binaries

ZLAR ships with **two** `zlar` scripts that share behavior on `off`/`on`/`reset`:

| Script | Path | Purpose |
|---|---|---|
| Main CLI | `${PROJECT_DIR}/bin/zlar` | Full-featured: status, doctor, audit, policy, telegram, uninstall, version, off, on, reset, help |
| Simple utility | `${PROJECT_DIR}/../tools/zlar` (developer-only) | Minimal: off, on, status (basic), reset |

Both scripts manipulate the same flag files (`~/.claude/.gate-disabled` and `/etc/zlar/off-flag`). They are interchangeable for `off`, `on`, and `reset`. The main CLI has all the diagnostic commands; the simple utility is a 30-line script that exists for quick toggles when you don't want the full CLI overhead.

**In day-to-day use, the main CLI is the one you want.** The simple utility exists for debugging the toggling logic and as a fallback when the main CLI is being modified.

---

## State files

### Human invariant state

Location: `${PROJECT_DIR}/var/human-state/<telegram_chat_id>.json`

One file per human. Each file is JSON with fields:

- `human_id`: the telegram chat ID (string)
- `date`: YYYY-MM-DD (UTC), used for date-rollover reset
- `decisions_today`: H6 daily decision counter (resets at midnight UTC)
- `approvals_recent`: H14 rolling window of recent decisions (booleans)
- `pending_count`: H13 pending queue counter (resets at midnight UTC since v2.7.0; see [`architecture-map.md`](architecture-map.md) for the v2.8 TTL fix plan)
- `last_ask_epoch`: unix seconds, used by H15 (deliberation) and H17 (authenticity)

To inspect manually:
```bash
cat ${PROJECT_DIR}/var/human-state/*.json | jq .
```

To reset (use `zlar reset` for the supported path):
```bash
zlar reset
```

### Off-flags

| Flag | Path | Owner | Set by |
|---|---|---|---|
| Wrapper flag | `~/.claude/.gate-disabled` | user | `touch` (via `zlar off`) |
| Structural flag | `/etc/zlar/off-flag` | root | `sudo touch` (via `zlar off` + sudoers NOPASSWD) |

Either being present means the gate is off. Both check independently. See [`architecture-map.md`](architecture-map.md) for the doctrinal reason both exist during the v2.7.0 overlap period.

---

## Common workflows

### "I want to build ZLAR itself without being governed by it"

```bash
zlar off              # Disable
# ... do your work ...
zlar on               # Re-enable
zlar status           # Verify
```

### "Tool calls are being blocked unexpectedly"

```bash
zlar status           # Check gate state and human invariant state
zlar doctor           # Check installation health
zlar audit 50         # Look at recent decisions
```

If `zlar status` shows `pending_count: N ⚠ OVER CAP`:
```bash
zlar reset            # Clear stuck state
zlar status           # Verify cleared
```

### "I just rebooted my Mac and want to confirm ZLAR is healthy"

```bash
zlar doctor
zlar status
```

If either shows red, see [`troubleshooting.md`](troubleshooting.md).

### "I want to set up a fresh install on a new machine"

1. Clone the repo
2. Run the install procedure (see install instructions)
3. Run the v2.7.0 setup block from the [Setup](#setup-one-time-v270-and-later) section above
4. `zlar telegram` to wire up approval routing
5. `zlar doctor` to verify

---

## See also

- [`architecture-map.md`](architecture-map.md) — load-bearing facts about ZLAR's structure (parallel gate implementations, first authority chain, off-switch architecture)
- [`troubleshooting.md`](troubleshooting.md) — symptom-based problem-solving guide
- [`../signal/DOCTRINE.md`](../signal/DOCTRINE.md) — the First Authority Law (the doctrine v2.7.0 ships)
- [`adr/`](adr/) — architecture decision records
