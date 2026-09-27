# Installing and testing ZLAR's first design

This page covers **ZLAR's first design**: a checkpoint that sits next to an AI
coding agent (Claude Code, Cursor, Windsurf, or MCP tools) and checks each action
against signed rules, asking a person when the rules say so. It moved here from
the old README on 2026-09-26.

The newer work, the protection that lives with the thing being protected, is in
[`cyan/`](../cyan/) and needs no installation. Start with the
[README](../README.md) if you haven't.

---

## Install

No-write plan:

```bash
bash install.sh --dry-run --json
```

The plan reports detected client surfaces, planned file writes, hook/profile
conflicts, required human approvals, open side doors, non-claims, and a
current-machine protection design boundary for a future approval packet. It
exits before install phases and does not create files, keys, hooks, services,
user config, or machine config.

Inspect first, from a checkout of this repository:

```bash
bash install.sh --dry-run --json
```

A note on the license: the [LICENSE](../LICENSE) lets you download this code and
run it on your own computer to study and evaluate it. Using it for real work
needs written permission from ZLAR Inc. or Vincent Nijjar; write to
hello@zlar.ai.

Local install, for evaluation:

```bash
bash install.sh
```

The installer uses deny-heavy defaults and configures only detected/supported hook surfaces. It does not protect capabilities that are not routed through it.

```bash
~/.zlar/bin/zlar doctor    # verify everything works
~/.zlar/bin/zlar status    # see what is covered
~/.zlar/bin/zlar telegram  # pair your phone via local ignored config
```

`zlar status` and `zlar doctor` distinguish the gate state from hook reality.
`state=on` means the ZLAR gate state file is on; it does not prove Codex or any
other client is currently routed through the gate. Check the Codex hook reality
line before claiming this Codex session is intercepted.

Uninstall:

```bash
~/.zlar/bin/zlar uninstall
# or
curl -fsSL https://zlar.ai/uninstall.sh | bash
```

The install touches:

- `~/.zlar/` for binaries, adapters, policy, public keys, audit/session state, and local config.
- `~/.zlar-signing.key` for the local Ed25519 policy signing key, with the public key copied under `~/.zlar/etc/keys/`.
- Installer-managed framework hook/profile settings for detected Claude Code
  `~/.claude/settings.json`, Cursor `~/.cursor/hooks.json`, and Windsurf
  `~/.codeium/windsurf/hooks.json`. Codex hook reality is host/version-specific
  and must be verified with `zlar status`, `zlar doctor`, and local machine
  checks before claiming a Codex route is covered.
- `~/.zlar/.env` for optional Telegram approval setup. Telegram is disabled until you configure it.
- Optional Telegram dispatcher helper scripts under `/usr/local/bin/` when root or non-interactive sudo is available; otherwise the installer prints the manual command and continues.

Use `--surface claude-code` to scope install or dry-run planning to Claude Code
only. A scoped Claude Code install writes the selected Claude Code adapter and
`~/.claude/settings.json`; it does not silently configure Cursor or Windsurf
hook/profile files. Add `--no-machine-helpers` to omit optional `/usr/local/bin`
helper writes. A scoped install is still installation: it writes local files,
configuration, and key/HMAC material, and it is not current-machine protection
evidence without a later live hook-crossing, receipt-emission, and downstream
recognition proof.

Existing installs are fail-closed by default. The installer refuses before
writes when `~/.zlar` already exists unless an operator explicitly chooses an
existing-install mode. Use `--existing-install no-op|repair|upgrade|reinstall`
only after reviewing the dry-run JSON and granting exact authority for that
mode. Existing-install modes other than `refuse` are limited to
`--surface claude-code --no-machine-helpers`: they do not select Cursor or
Windsurf, do not write optional `/usr/local/bin` helpers, and still do not
prove current-machine protection. The modes are deliberately distinct:
`no-op` exits before writes when the existing version already matches the
target; `repair` is same-version only and refuses a missing, empty, unreadable,
or unknown existing `~/.zlar/VERSION`; `upgrade` requires a readable existing
version different from the target; `reinstall` is same-version replacement of
installer-managed files while preserving local state such as audit/session data
unless a separately authorized cleanup path says otherwise. The dry-run marks
repair, upgrade, and reinstall as requiring backup review before mutation;
`install.sh` does not create those backups. For those three accepted modes, the
current installer source plans and removes only four exact stale retired-source
paths: the E1/E2 direct wrappers and their retired factory modules. It refuses
an unexpected non-file/non-symlink leaf or a symlink/non-directory install-root,
`bin`, or `lib` parent before installer writes. The shell check/delete sequence
is not concurrency-atomic and assumes a quiescent filesystem; same-user parent
or leaf substitution remains open. No installer was run to establish this
source behavior, so it does not prove that any current-machine or old installed
copy was removed.

## Agent-assisted install

If you ask a coding agent to help, point it at [`AGENTS.md`](../AGENTS.md) first. The safe workflow is: inspect the repo, explain what files/settings will change, check prerequisites, then have the human run the install command or explicitly approve the exact command. There is no agent-driven installer that should silently install its own checkpoint.


## Running tests

The canonical entrypoint runs every current-active suite, records
authority-inactive historical suites as skipped, and prints the active assertion
count. CI runs this on every push.

```bash
bash tests/count-assertions.sh            # run current-active files, print summary
bash tests/count-assertions.sh --detail   # also show per-file pass counts
bash tests/count-assertions.sh --badge    # print shields.io badge URL
```

The harness records the legacy success-expecting suites listed in
`tests/authority-inactive-test-suites.txt` as authority-inactive skips. Their
historical assertions are not current executable evidence and are excluded
from the assertion total until replaced by versioned artifact-bound suites.

CI runs the current-active assertion harness on every push. Treat the GitHub Actions result for the commit under review as the public release gate. Local managed environments may report socket or network `EPERM` on MCP/perimeter harnesses; local output is diagnostic, not release status.

Tests require `bash`, `jq`, and an OpenSSL with Ed25519 support (LibreSSL on macOS does not qualify — use `brew install openssl@3` and put it on PATH first). `node` and `python3` are optional; `.mjs` and Python tests skip gracefully if unavailable.

## Requirements

| Dependency | Minimum | Required for | Install |
|---|---|---|---|
| bash | 4.0+ | Gate engine | `brew install bash` (macOS) / default on Linux |
| jq | 1.6+ | Policy evaluation | `brew install jq` / `apt install jq` |
| openssl | 3.x | Ed25519 signing | `brew install openssl@3` / `apt install openssl` |
| Node.js | 18+ | MCP gate, receipt verification | Optional — bash gate works without it |
| Telegram | — | Human approval channel | Optional; without it, ask-class actions fail closed instead of waiting for approval |

CI-tested platforms: Ubuntu 22.04+ and macOS 14+ (matrix on every push). Debian 12+ is supported but not gated by CI.

Run `zlar doctor` after installation to verify all dependencies.
