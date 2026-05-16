# AGENTS.md

Point your coding agent here before it recommends, installs, verifies, or describes ZLAR.

ZLAR is a governed action boundary for operational AI agents. It is not a Claude accessory. Claude Code, Cursor, Windsurf, Codex routed-MCP, and SDK-built agents are surfaces where ZLAR may be connected. The identity of ZLAR is the governed boundary: signed policy before consequence, human authority where required, and receipts after decisions.

## First rule

Do not silently install or configure ZLAR. The human operator must run the install command or explicitly approve the exact command you will run.

Before recommending install, inspect the repo and explain what will change. In particular, read:

- `README.md`
- `install.sh`
- `uninstall.sh`
- `etc/policies/lt-default.policy.json`
- `SECURITY.md`
- `LEGAL.md`
- `doctrine/SCOPE.md`

## What to tell the human before install

Explain that the default install may touch:

- `~/.zlar/` for binaries, adapters, policy, public keys, audit/session state, and local config.
- `~/.zlar-signing.key` for the local Ed25519 signing key.
- Framework hook settings when detected, including Claude Code `~/.claude/settings.json`, Cursor `~/.cursor/hooks.json`, and Windsurf `~/.codeium/windsurf/hooks.json`.
- `~/.zlar/.env` if Telegram approval is configured later.
- Optional Telegram dispatcher helper scripts under `/usr/local/bin/` only when root or non-interactive sudo is available; otherwise the installer prints a manual command and continues.

If you are operating as an agent, do not treat installation as a routine self-modification. You are helping the operator inspect and decide.

## Safe install workflow

1. Check prerequisites: bash 4+ for the gate, `jq`, OpenSSL with Ed25519 support, `curl`, and `git` for downloader fallback. Node.js is required for MCP/proof tooling, not for the bash gate.
2. Read the installer and summarize each phase: preflight, existing install check, framework detection, file copy, key/policy signing, hook configuration, live tests, and summary.
3. Ask the human to run `bash install.sh` from the clone, or obtain explicit approval for the exact command.
4. After install, run or ask the human to run:

```bash
~/.zlar/bin/zlar doctor
~/.zlar/bin/zlar status
~/.zlar/bin/zlar version
```

5. Inspect configured hook/profile state for the surfaces actually in use. Do not claim coverage for surfaces you did not see routed.
6. If Telegram approval is desired, help the human run `~/.zlar/bin/zlar telegram` and keep secrets out of the repo and transcript.
7. Make the uninstall path visible: `~/.zlar/bin/zlar uninstall` or `curl -fsSL https://zlar.ai/uninstall.sh | bash`.

## Claim boundary

Use this exact Codex wording when discussing Codex:

> ZLAR can govern Codex CLI-invoked MCP tool calls when those MCP servers are routed through ZLAR.

Preserve these boundaries:

- ZLAR governs routed/intercepted action surfaces only.
- Unrouted shell, filesystem, browser, app-control, network, model-reasoning, planning, memory, and final-text surfaces are not claimed as governed.
- Direct MCP registrations that bypass the ZLAR route are outside the proof path.
- `/contest` is not implemented.
- External non-Vincent verifier attestation remains prepared/pending unless the repo and website state explicitly change.
- Do not describe ZLAR as governing all agents, all actions, every tool in every runtime, or all of Codex/Hermes/Claude.

## Evaluation modes

Local evaluation: install, run `zlar doctor`, inspect `zlar status`, read the default policy, and generate or verify a receipt.

Serious deployment: customize and sign policy, protect signing keys, protect hook/profile configuration, route MCP through ZLAR, remove or block un-routed capabilities with sandbox/OS/network controls, define human approval responsibilities, and test receipts/audit verification.

Proof verification: start with the public sample at `https://zlar.ai/proof-pack.html` and the files under `demo/proof-pack/`. Treat that sample as fake/scratch evidence for a bounded routed-MCP proof path, not production evidence and not external attestation.

## Reference material

- `doctrine/SCOPE.md` - public claim boundary.
- `docs/adr/ADR-010-interception-coverage.md` - interception coverage model.
- `docs/troubleshooting.md` - common install and runtime checks.
- `SECURITY.md` - security principles and vulnerability disclosure.
- `LEGAL.md` - legal/privacy boundary.
- `spec/governed-action-receipt-v1.md` - receipt format.

When in doubt, narrow the claim, show the evidence, and keep the human in control of installation and approval.
