# Changelog

## 2.8.0 — 2026-04-09

H13 TTL rewrite. Fixes the April 9 2026 fail-closed incident where a single
accounting bug in one invariant locked every Claude session simultaneously on
a false positive. Architectural fix, not a belt-fix.

### The incident

A tool call arrived and was denied with `H13 WARNING: has 6 pending decisions
(cap: 5) — system is under-resourced`. The production state file contained
`pending_count: 6, decisions_today: 0, approvals_recent: []` — six pending,
zero recorded. That combination is mathematically impossible unless the
increment path is running but the matching decrement/record path is not.

Root cause analysis surfaced two independent failure modes that the old
scalar `pending_count` couldn't distinguish from each other, and couldn't
recover from either:

1. **Orphaned increments.** `hi_increment_pending` runs on every ask, but
   `hi_decrement_pending` only runs if the gate's post-response path is
   reached. Claude Code's deny-then-retry architecture means the post path
   can be skipped entirely — Claude pivots, the session ends, or a standing
   approval bypasses the whole flow. Each orphan is a permanent `+1` on the
   scalar. The April 6 log shows the counter climbing `6 → 36` over eight
   hours of normal work, never decrementing once.

2. **Retry double-counting.** When Claude retried a denied tool call before
   the human had approved on Telegram, the gate fell into the "no prior
   approval" branch a second time and incremented `pending_count` again for
   the same logical ask. Fast retries pumped the counter through the cap in
   seconds.

Both failure modes collapse into one fix.

### Added

- **`HI_PENDING_TTL` / `ZLAR_PENDING_TTL`**. New config (default 1800s =
  30 min). Pending entries older than this are filtered out on every read,
  so orphaned increments cannot drift the counter permanently. TTL is the
  load-bearing invariant: the fix does not depend on the decrement path
  being called reliably — it depends on the entry's wall-clock timestamp.
- **`action_hash` parameter** on `hi_pre_ask_check`, `hi_increment_pending`,
  `hi_post_response_check`, `hi_decrement_pending` (`.sh` and `.mjs` both).
  When provided, H13 uses it to dedupe retry loops: a second call with the
  same hash finds the existing entry and returns `ok` without appending.
  The Claude Code gate passes `action_hash` (already computed for the
  approval file key) through all three call sites. Callers that don't
  have a stable identifier can omit it — TTL alone still bounds drift.
- **Schema migration from v2.7.x** in `_hi_ensure_state` / `loadState`.
  Any state file carrying the deprecated `pending_count` scalar has it
  dropped and gains an empty `pending` array on first access, idempotent
  after first run. This is the code path that auto-heals a stuck
  `pending_count > cap` state file with no manual reset required.

### Changed

- **`lib/human-invariants.sh` / `.mjs`** (in lockstep per the v2.7.1
  discipline). H13 state changed from `pending_count: int` to
  `pending: [{action_hash, ts}]`. Both gate implementations now filter
  stale entries by TTL on every increment and decrement, and dedupe by
  `action_hash` when provided. Decrement by hash removes the specific
  entry; decrement without hash removes the FIFO-oldest entry.
- **`bin/zlar-gate`** now threads `action_hash` through
  `hi_pre_ask_check` (line ~1945), `hi_post_response_check` on both the
  approve path (line ~1909) and the deny path (line ~1934). Removed the
  double-decrement bug on the deny path (`hi_post_response_check` already
  calls `hi_decrement_pending` internally; the explicit second call was
  subtracting twice for every denied ask).
- **`bin/zlar` status display** reads the TTL-filtered length of
  `.pending` instead of the deprecated `pending_count` scalar. Falls back
  to the scalar on un-migrated files for display continuity. Field label
  changed from `pending_count:` to `pending (ttl-filtered):` to reflect
  the new semantics.

### Fixed

- **H13 gate fail-closed on single stuck invariant** blocking all sessions.
  Production repro: `pending_count: 6, decisions_today: 0` — impossible
  state, proving the decrement path was never running in the real flow.
- **Double-decrement on deny-retry** in `bin/zlar-gate` line ~1935. Every
  denied ask was subtracting from pending twice — once via the
  `hi_post_response_check` internal call, once via an explicit
  `hi_decrement_pending` call. This masked the scale of the drift
  because some entries were being over-removed at the same time orphans
  were being under-removed.

### Tests

- **22 new assertions** in `tests/test-human-invariants.sh` covering
  action_hash dedup (retry idempotency), TTL expiration (orphan cleanup),
  and schema migration from v2.7.x scalar. The migration test seeds the
  exact shape of the April 9 production incident state file (`pending_count: 6`,
  today's date, no `pending` array) and asserts that the first v2.8.0
  `hi_increment_pending` call returns `ok` — which it would not have
  under v2.7.x because `6 > 5`.

### Not in this release

- **H14 approval-rate semantic fix.** The April 9 log also showed eight
  H14 "100% rubber-stamping" warnings during normal use. Raw approval
  rate is the wrong signal: a well-calibrated gate that only escalates
  legitimately risky calls will make a careful user hit 100% forever. The
  right signal is approval rate correlated with deliberation time — fast
  approvals are suspicious, slow approvals are not. Deferred because
  it's a separate failure class from H13 and touches different code
  paths. Belt-fix (date-rollover reset of `approvals_recent`) shipped
  in v2.7.2 remains in place.
- **Generalized error visibility in `|| true` masking.** The H13 rewrite
  adds structured error logging in the new paths (`_hi_log "ERROR: ..."`),
  but the existing `|| true` patterns elsewhere in `human-invariants.sh`
  and the gate are untouched. Broader audit deferred.

## 2.7.1 — 2026-04-07

Analyst-ready build hygiene. No architectural changes. Every claim in the
README verified against the code; every finding fixed or documented.

### Fixed

- **install.sh version hardcode**. `ZLAR_VERSION` was pinned to `"1.4.0"` — now reads the repo `VERSION` file dynamically at install time. Fresh installs write the correct version into `~/.zlar/VERSION`.
- **Release badge URL**. The `[GitHub release]` badge in `README.md` pointed at `/tag/v2.0.0`; now points at `/releases` so the shields.io `sort=semver` picks up the current tag automatically.
- **H13 belt-fix lockstep miss in MCP gate**. `lib/human-invariants.mjs` now resets `pending_count` on date rollover alongside `decisions_today`, matching the `lib/human-invariants.sh` fix that shipped in v2.7.0. Both gates now behave identically across midnight boundaries. Full per-entry TTL remains v2.8.0 backlog.
- **Stale `scripts/zlar-tg-boot.sh`** (MD5 bce07e0b) removed. `oc/bin/zlar-tg-boot.sh` (MD5 2f03d645) is now the canonical copy — it matches the running `/usr/local/bin/` version and has the April 6 boot-time user resolution fix.
- **`bin/zlar-gate` header comment** bumped from `v2.5.1` to `v2.7.1` with a v2.7.x release notes block.
- **`install.sh` Claude Code hook merge**. `.hooks.PreToolUse` was being overwritten (`=`) instead of appended — now uses `((.hooks.PreToolUse // []) + [...])` to preserve any existing non-ZLAR PreToolUse hooks.
- **`install.sh` keygen stderr**. `zlar-policy keygen` stderr was silenced; now surfaced so key generation failures are visible instead of cascading into confusing "signing key not found" errors downstream.
- **`uninstall.sh` self-delete**. The script now relocates itself to a temp path before `rm -rf ~/.zlar/` to avoid deleting its own currently-executing source. Dead `elif` branch (unreachable identical-condition check) removed.
- **`bin/zlar` doctor "Fix" lines** no longer hardcode `/usr/local/bin/zlar-tg-boot.sh` — that path isn't installed by `install.sh` and only exists on machines with the OC gate separately installed. Now points at `docs/troubleshooting.md#telegram-callback-listener`.
- **`scripts/smoke-test.sh`** now skips node-dependent phases gracefully when `node` is not on PATH instead of failing them. Added explicit Ed25519 preflight so "your openssl doesn't support Ed25519" is surfaced before the test phases run.
- **`test-crypto.sh` silent exit on LibreSSL**. Removed `set -e` (which masked silent exits in command substitutions under `pipefail`) and added an Ed25519 preflight that exits 77 (POSIX skip) with a clear error message when the environment's openssl can't do Ed25519. Same preflight added to `test-policy-loading.sh`.
- **`test-perimeter-closure.sh` version check** loosened from strict `2.6.0` to any `2.x.x` — the rule set is preserved unchanged across 2.7.x so the version string bump shouldn't fail tests.
- **`etc/manifest.json`** added to `.gitignore` as per-install regeneratable state. Identity-bound, time-bounded, signed — not distributable. Generation path: `bin/zlar-manifest new --agent-id ... --principal ... | bin/zlar-manifest sign`.
- **`mcp-gate/test-allow-policy.json`** added to `.gitignore`. The file is created by `mcp-gate/test.mjs:writeFileSync` at test start and removed by `unlinkSync` at teardown — tracking it was meaningless since every test run rewrote or deleted it.

### Added

- **`tests/count-assertions.sh`**. Canonical source of truth for the "1000+ assertions" badge. Runs every test file in the repo and parses the pass count from each. Handles missing node gracefully (skips `.mjs` files). Exit 77 (skip) semantics respected. Supports `--detail` (per-file breakdown) and `--badge` (shields.io URL) modes.
- **`docs/architecture-map.md`** shipped in v2.7.0 is unchanged — it documents the cross-file load-bearing facts (parallel gate implementations, first-authority chain, off-switch architecture, policy TCB) that aren't visible from any single file.
- **macOS runner in CI matrix**. `.github/workflows/ci.yml` `test` job now runs on `[ubuntu-latest, macos-latest]` with `fail-fast: false`. macOS step installs `brew openssl@3` and prepends it to PATH so Ed25519 is available.
- **CI test expansion**. The old CI only ran 5 bash tests + 4 SDK tests + 2 Cedar tests + 1 MCP gate test — a subset of the test suite, with ZERO overlap with the tests the README advertised. CI now runs `tests/count-assertions.sh --detail` as a single step, which exercises all 28 test files (14 bash + 13 Node.js + 1 Python) and fails if the assertion total drops below 900. A visitor clicking the green CI badge now sees the same test coverage the README promises.

### Changed

- **README.md** test section rewritten to lead with `bash tests/count-assertions.sh` as the canonical entrypoint. File counts corrected from "12 bash + 7 Node.js + 1 Python" to "14 bash + 13 Node.js + 1 Python". Assertion badge bumped from "550+" to "1000+" (verified count: 1022). Platform claim softened from "Verified platforms: macOS 14+, Ubuntu 22.04+, Debian 12+" to "CI-tested platforms: Ubuntu 22.04+ and macOS 14+ (matrix on every push); Debian 12+ supported but manually verified."

### Test counts

**1022 assertions across 28 test files (14 bash + 13 Node.js + 1 Python). 0 failures.** Verified by `bash tests/count-assertions.sh`.

## 2.7.0 — 2026-04-07

The First Authority Law. Structural off-switch. Architecture map. Two new permanent disciplines born from a near-miss.

### Added

- **The First Authority Law** (`signal/DOCTRINE.md`). Seven-section doctrine in the founder's voice. Core statement: "The first component that can say 'yes' to action must be outside the governed agent's writable or influenceable space. If the agent can alter that first authority, governance is cosmetic. That is the whole thing. Everything else follows from it."
- **Structural off-switch at `/etc/zlar/off-flag`**. Root-owned flag file, sudoers NOPASSWD on EXACTLY `/usr/bin/touch /etc/zlar/off-flag` and `/bin/rm -f /etc/zlar/off-flag` (no other commands). `bin/zlar-gate` checks this at the top of main before sourcing any libraries — if present, returns allow JSON immediately. The agent has no filesystem path to write it (R003 denies sudo from bash domain, writing to `/etc` requires sudo). This replaces the wrapper's `~/.claude/.gate-disabled` kill-switch with a sovereign the agent cannot reach. The wrapper remains in the chain during v2.7.0 overlap for backward compatibility.
- **CLI off/on/reset** (`repo/bin/zlar`, `tools/zlar`). `zlar off` writes both flags (wrapper + structural) via `sudo -n touch /etc/zlar/off-flag` (sudoers NOPASSWD). `zlar on` removes both. `zlar reset` backs up `var/human-state/*.json` to `/tmp/zlar-state-backup-<ts>/` and deletes, forcing next gate invocation to recreate with zero values. Escape hatch for H13 pending-count leaks.
- **Architecture map** (`repo/docs/architecture-map.md`). Cross-file load-bearing facts that aren't visible from any single file: parallel gate implementations (sh + mjs share state), first-authority chain order, v2.7.0 off-switch architecture, sudoers TCB, policy signing root of trust, wrapper overlap semantics. Written specifically to prevent the failure mode of the morning-of incident.
- **CLI reference** (`repo/docs/cli-reference.md`). Full v2.7.0 command reference with examples and common workflows.
- **Expanded `zlar status`** command in `bin/zlar`. Adds a "Gate State" section (on/off via both flag paths) and a "Human Invariant State" section (per-human decisions_today, pending_count, approvals_recent, last_ask_epoch with color-coded threshold warnings). ~88 lines added.
- **H13 belt-fix at midnight** (`lib/human-invariants.sh` only — mjs gate missed this in 2.7.0, caught and fixed in 2.7.1). Date-rollover logic in `_hi_ensure_state` now resets `pending_count` alongside `decisions_today`. Belt fix for the H13 pending-count leak where asks increment without responses (crash/timeout/session end). Full per-entry TTL remains v2.8.0 backlog.

### Disciplines adopted (permanent)

- **Critical-review practice**. Every substantive code proposal is paired with the author's own honest critique of that proposal in the same message, before approval. Operationalizes non-symbolic human authority over technical content the human cannot directly evaluate. Origin: v2.7.0 status expansion, where ~88 lines of bash were proposed with 10 explicit concerns and triaged.
- **Pre-change scope audit**. Before removing or modifying enforcement code, enumerate every function the existing code performs. Each must be (a) duplicated downstream, (b) explicitly accepted as a regression, or (c) replaced before removal. Born from the morning-of incident where the wrapper's kill-switch was nearly removed without realizing it was the human's only off-switch path in v2.6.0.

### Fixed (carryover from v2.6.x work stream)

- **Telegram callback listener** fixes continue to hold (gate crash bug, tg-poll daemon admin-user config, HMAC secret permissions). These shipped in the v2.6.0 line and are preserved in v2.7.0.

### Test counts (v2.7.0)

Passed: 486+ assertions across 16 suites at commit time. Not yet run through a single consolidated reporter — `tests/count-assertions.sh` added in v2.7.1 to fix this.

## ZLAR 2.0 — 2026-04-06

The proof. Deterministic gate + human authority + cryptographic evidence. Format frozen. Specifications published.

### 2.0.0+11 — 2026-04-06 (evening)

- **Canonicalization Specification v1.0** (`docs/canonicalization-spec.md`). RFC 8785 subset with constrained schema. 28 test vectors verified across Node.js, Python, and bash. Published at zlar.ai/specs/canonicalization.
- **Receipt v1 envelope format** (format frozen). Base64url payload, Ed25519 signature, integer version field, no algorithm negotiation. Published at zlar.ai/specs/receipt-v1. ADR-007.
- **Semantic validation layer** (`lib/semantic-validator.mjs`). Layer 4 of five-layer pipeline: rule-outcome consistency, authorizer-outcome coherence, temporal checks, delegation chain integrity. 70+ assertions.
- **zlar doctor** (`bin/zlar`). Seven-section diagnostic: dependencies, keys, policy, hooks, gate, audit, Telegram (daemon + HMAC). Post-reboot habit.
- **Troubleshooting docs** (`docs/troubleshooting.md`). 12 failure modes with symptoms, causes, fix commands.
- **Gate crash fix**. HMAC secret permissions (root:root 600 → root:staff 640). Gate was silently dead April 3-6.
- **tg-poll daemon fix**. Boot script user resolution: persistent config + /Users/ search. Telegram callbacks restored.
- **Codex audit fixes**. Crash handler event type, empty session ID fallback, schema regex constraints, spec/code alignment, README flow accuracy, tamper test.
- **Institutional website restructure**. Forrester-first navigation. Essays archived to /writing. Architecture page updated to v2.0.0.
- **CODE_OF_CONDUCT.md**. Contributor Covenant v2.1.
- **All 17 research items complete**. 24 MD files in ZLAR-2.0/research/.

### 2.0.0 — 2026-04-06

Phase 2: Governed Action Receipt, MCP hardening, Cedar integration, institutional repo, human invariants.

### Added

- **Governed Action Receipt** (`lib/receipt.mjs`, `bin/zlar-verify`, `bin/zlar-receipt`, `etc/receipt.schema.json`). Portable cryptographic proof that a governed action was evaluated by deterministic policy and decided by the appropriate authority. Cross-gate compatible — bash-generated receipts verify with Node and vice versa. Receipt schema v0.1.0.
- **Receipt integration** in both gates. Bash gate: `_emit_receipt()` alongside `emit_event` when `ZLAR_EMIT_RECEIPTS=true`. MCP gate: receipt generation on every governed action when signing key available.
- **Per-entry audit signing (MCP gate)**. Every MCP gate audit event is now Ed25519-signed. Matches bash gate approach: canonical JSON, SHA-256 hex, Ed25519 sign hex bytes, base64. Cross-gate compatible.
- **Policy signature verification (MCP gate)**. `verifyJsonSignature()` closes the Phase B TODO. Invalid or tampered policy = deny-all (fail-closed).
- **Standing approval support (MCP gate)**. `checkStandingApproval()` — same format and matching as bash gate, signature-verified. Checked before Telegram escalation.
- **Fail-closed hardening (MCP gate)**. Default switch case: deny (was passthrough). Upstream error: deny to client. Uncaught exception handler: audit + exit. Unknown policy action: deny.
- **Cedar policy evaluation** (`lib/cedar-evaluator.mjs`). Production WASM evaluator with policy ID mapping. Priority 1 rules (R002, R003, R005, R006, R007) and Priority 2 rules (R014, R016) translated to Cedar. Standing approval equivalents as Cedar permits. MCP gate: `--policy-engine json|cedar|both`.
- **Human invariant enforcement** (`lib/human-invariants.sh`, `lib/human-invariants.mjs`). Five mechanical enforcements wired into both gates: H6 (decision cap, 80/day), H13 (pending queue capacity), H14 (approval rate monitoring), H15 (deliberation floor: critical 30s, warn 10s, info 3s), H17 (human authenticity, reject sub-second responses).
- **Architecture Decision Records** (`docs/adr/ADR-001` through `ADR-006`). Deterministic enforcement, bash implementation, fail-closed, Ed25519, manifest narrows policy, structural independence.
- **GOVERNANCE.md**. Decision-making process, ADR index, invariant amendment procedure.
- **ADOPTERS.md**. Template for production and evaluation users.
- **GitHub templates**. Issue templates (bug, feature, security), PR template with invariant checklist.
- **Quickstart script** (`scripts/quickstart.sh`). Keygen, deny, receipt, verify in under 60 seconds.
- **Cedar migration guide** (`docs/cedar-migration.md`). JSON-to-Cedar translation, dual-engine mode, known limitations.
- **65 Cedar tests** (`mcp-gate/test-cedar.mjs`). P1/P2 rules, gate action mapping, receipt integration, cross-engine regression.
- **54 MCP hardened tests** (`mcp-gate/test-hardened.mjs`). Policy verification, signing, fail-closed, standing approvals, hash chain integrity.
- **124 receipt tests** (`mcp-gate/test-receipt.mjs`, `tests/test-receipt.sh`). Generation, verification, delegation chains, tampering, cross-gate compatibility.
- **21 human invariant tests** (`tests/test-human-invariants.sh`). Decision cap, deliberation floor, approval rate, capacity, authenticity.

### Changed

- **README.md** rewritten. Category definition, What Is / What Is Not, receipt showcase, ADR table, human invariant layer in architecture.
- **SECURITY.md** expanded. Threat model, supply chain, crypto choices, human invariant protections.
- **CONTRIBUTING.md** expanded. Per-area test instructions, adding rules/adapters, PR process, ADR guidance.
- **MCP gate EXPERIMENTAL warning removed.** The gate passes 200+ tests, signs every entry, verifies policy signatures, and fails closed on every error path.

### Test counts

470+ assertions across 15 test suites (10 bash + 5 Node.js).

## 1.7.0 — 2026-04-02

Agent identity, coordination, and Level 2 gate integration.

### Added

- **Agent identity layer** (`lib/agent-identity.sh`). Risk tier classification (critical/high/medium/low), authorization levels (pre-approved/human-review-required/blocked), test agent filtering, pattern detection. Shared by registry, export, and status tools.
- **Agent registry export** (`bin/zlar-agents-export`). Generates signable agent inventory from the cryptographic audit trail. Two views: raw (every agent including test/simulation) and production (filtered). The audit trail IS the registry.
- **Agent binding CLI** (`bin/zlar-agents`). Per-agent policy overlays: standing approval scoping, velocity limits, aggregate budgets, delegation depth limits. `bind`, `unbind`, `show`, `list`, `inventory` commands.
- **Governance dashboard** (`bin/zlar-status`). Single-command health view: gate status, policy state, agent inventory (risk-tiered), recent approvals and denials. `--json` for machine consumption.
- **Delegation chain governance** (Build A). Gate records parent-child ancestry on SubagentStart. Enforces `max_depth`. Standing approvals scope by depth via `depth_rules` in bindings. Monotonic narrowing validation: deeper depths cannot widen permissions. Cycle-safe ancestry traversal (10-hop iteration limit).
- **Aggregate action budgets** (Build B). Per-agent, per-rule budget counters with daily/hourly windows. Counters persist across sessions (`var/sessions/budgets/`). Budget exceeded triggers `respond_deny` + audit event. Trading-style position limits — individual actions pass, aggregate triggers escalation.
- **Policy version sync** (Build C). Gate checks bindings `policy_version` against loaded policy after `load_policy()`. Drift events emit to audit trail. Checks all binding versions, not just first.
- **Per-agent standing approval scoping**. Gate reads `agent-policy-bindings.json` and filters standing approvals by agent_id. Unbound agents get all SAs (backward compatible).
- **Agent identity from hook payload**. Gate extracts `agent_id` from PreToolUse input (was hardcoded `"claude-code"`). Falls back to default for main thread.
- **35 new tests** (`tests/test-agent-identity.sh`). Risk tiers, authorization levels, test agent detection, export views, binding roundtrip, schema validation.

### Fixed

- **R012 policy action**: changed from `deny` (silent block) to `ask` (human decides via Telegram). Silent blocks with no Telegram routing is not human-in-the-loop governance.
- **Gate crash on startup**: `log()` called before function defined at module load time. macOS bash found `/usr/bin/log` (system command) instead. Fixed with direct file logging for pre-function code.
- **`local` at top level**: `local _narrowing_ok` used outside a function. bash error under `set -e` triggered ERR trap crash.
- **OpenSSL resolution**: `crypto.sh` now resolves Homebrew OpenSSL 3.x on macOS (LibreSSL lacks Ed25519 `pkeyutl -rawin`).

### Design principles

- Level 2 coordination imports existing patterns, not invention: RBAC inheritance (delegation chains), trading position limits (aggregate budgets), distributed config management (policy sync).
- Design judged by faithful import of right lessons from RBAC, trading controls, distributed config, and delegated auth.
- The registry is not a database. It is the audit trail viewed from the agent dimension.

### Tests

- 9 bash test suites: 266 assertions
- 4 Node.js test suites (Cedar, MCP, SDK): 93+ assertions
- Grand total: 395+

## 2.0.0-alpha.2 — 2026-03-29

HTTP Hook Adapter — the first connector. Claude Code governance bridge.

### Added

- **HTTP Hook Adapter** (`sdk/hook-adapter/server.mjs`, `bin/zlar-hook-server`). Translates between Claude Code's HTTP hook protocol and the ZLAR gate daemon. Any Claude Code deployment can use ZLAR governance by adding one JSON entry to settings.json — zero agent code changes. `POST /hook` evaluates tool calls against signed Cedar policy. `GET /health` for monitoring.
- **Fail-closed at HTTP level.** Claude Code treats non-2xx as fail-open (tool proceeds). The adapter always returns HTTP 200 with a valid JSON body. JSON parse errors, missing tool names, daemon unreachable, unhandled exceptions — all produce `200 + deny`. Never returns 4xx/5xx for hook evaluations.
- **SubagentStart support.** Maps SubagentStart hook events to the daemon's agent domain evaluation. Claude Code's SubagentStart hooks route through the same governance pipeline as PreToolUse.
- **Managed settings generator** (`sdk/hook-adapter/managed-settings.mjs`). Generates enterprise `managed-settings.json` with two-layer defense: static deny rules (fail-closed floor for most dangerous operations) + HTTP hook (dynamic Cedar policy evaluation). `allowManagedHooksOnly: true` prevents governance bypass. Deploy via MDM to `/etc/claude-code/managed-settings.json`.
- **19 new tests.** Unit tests (daemon unavailable, managed settings generation), integration tests (allow, deny, SubagentStart, malformed input, chain forwarding, error handling). Every test verifies the HTTP 200 invariant.

### Architecture note

This is the first Phase 2 connector — the bridge from "governance membrane exists" to "anyone can use it." An enterprise deploys ZLAR by: (1) running `zlar-daemon`, (2) running `zlar-hook-server`, (3) dropping managed-settings.json. No agent code changes. The bash gate remains the local enforcement surface; the hook adapter is the remote/enterprise surface.

## 2.0.0-alpha.1 — 2026-03-29

Phase 2 security hardening pass. Four structural gaps fixed from multi-agent review.

### Fixed

- **Chain verification at daemon boundary.** `handleEvaluate()` now calls `verifyChain()` before any policy evaluation. Walks the full chain: structural checks, sequential depth fields, `parent_jti` links, and Ed25519 signature verification (root against daemon key, each child against parent key). Fail-closed: invalid or unverifiable chain → immediate deny with `rule: chain:verify`. Previously, chain depth was computed as `chain.length - 1` on an attacker-supplied array with no cryptographic verification — audit `chain_depth` and policy depth enforcement were unverified attacker-controlled data.
- **Canonical form: raw SHA-256 bytes.** `signToken()` and `verifyTokenSig()` in `chain.mjs`, and the equivalent in `daemon.mjs`, now sign and verify `SHA-256(canonical).digest()` (raw bytes) rather than `SHA-256(canonical).digest('hex')` (the ASCII hex string of the hash). The previous form signed a 64-byte ASCII string rather than the 32-byte hash digest — any external verifier replicating the signing would need to know about this double-encoding. All token signatures regenerate on first use.
- **Telegram inbox path configurable.** Hardcoded `/var/run/zlar-tg/inbox/cc` is now sourced from `cfg.telegramInboxDir`, which reads from `gate.json` `telegram.inbox_dir` with the previous path as default. On macOS, `/var/run` is not writable without root — all Telegram HITL decisions silently timed out. Override in `gate.json`: `{ "telegram": { "inbox_dir": "/path/to/inbox" } }`.
- **"RFC 8693-style" claim removed.** `chain.mjs` header comment and all code references to "RFC 8693-style" or "RFC 8693 inspired" removed. The delegation chain is a custom Ed25519-signed structure — accurate description matters when presenting to Forrester and NCCoE evaluators who check standards claims.

### Tests

- 2 new integration tests: `tampered chain: daemon rejects forged chain → deny`, `attacker-supplied bare array: daemon rejects unverifiable chain → deny`
- Total Phase 2 tests: 129 (was 127). Grand total: 360.

## 2.0.0-alpha — 2026-03-29

Phase 2 begins. Gate daemon — first piece of the SDK governance membrane.

### Added

- **SDK Gate Daemon** (`sdk/daemon/daemon.mjs`, `bin/zlar-daemon`). Persistent Node.js Unix domain socket server replacing the fork-per-call subprocess model. Eliminates macOS fork+exec overhead (0.3–5ms per call). JSON-RPC 2.0 over 4-byte length-prefixed frames. Socket mode 0600 (owner-only). `getpeereid()` for kernel-verified peer identity. Socket discovery: `ZLAR_GATE_SOCKET` env var → `$XDG_RUNTIME_DIR/zlar/gate.sock` → `~/.zlar/gate.sock`.
- **Full policy parity.** Daemon implements identical logic to bash gate: DETAIL Schema Contract (same frozen schemas per domain), `matchDetailField()` (regex/contains/prefix/eq/not_regex), compound_guard AND-constraints, first-match-wins evaluation, default deny.
- **Shared infrastructure.** Reads same `etc/gate.json`, `etc/policies/active.policy.json`, `var/log/zlar-oc/audit.jsonl`, `etc/standing-approvals.json`, `var/log/approvals/` pending files. Approval binding hashes identical to bash gate: `SHA-256(rule|toolName|sortedJSON(detail))`. Policy signature verified at startup via jq subprocess (bit-exact compatibility). Per-entry Ed25519 audit signing with hash chain.
- **Blocking HITL.** Telegram ask blocks daemon connection while human decides (rather than deny-then-retry). Polling same `var/run/zlar-tg/inbox/cc/` inbox. Deny-then-retry still supported for clients that call evaluate multiple times.
- **Fail-closed everywhere.** Policy missing → deny. Daemon unavailable → client denies. Timeout → deny. Crash → deny. SIGPIPE suppressed.
- **53 new tests.** Tool translation (19 cases), detail field matching (11 cases), policy evaluation (10 cases), approval binding hash (4 cases), JSON-RPC 2.0 framing (5 cases), policy signature format (3 cases), live socket integration (conditional on running daemon). `node test.mjs` in `sdk/daemon/`.

### Architecture note

Phase 1 (bash gate, CC hook, MCP gate) unchanged. Daemon is new infrastructure for Phase 2 SDK clients. Agents built with the Phase 2 SDK will connect to the daemon at instantiation — governance present at construction, not bolted on.

## 1.6.0 — 2026-03-29

Perimeter closure complete. Three phases closing the gap between the gate's material (sound) and the gate's coverage (not yet complete when this work began).

### Added

- **macOS Seatbelt sandboxing (Phase C).** Two per-command sandbox profiles via sandbox-exec. Tier 2a (nonet): deny all network + deny dangerous binaries (curl, wget, ssh, osascript, security) + deny secret reads + deny governance writes. Tier 2b (net): same restrictions, allows outbound network for approved commands. Gate integration via updatedInput hook protocol -- commands wrapped transparently.
- **15 new policy rules (Phase A).** R005B-H (bash): claude -p spawning, interpreter one-liners, base64 pipe, pipe-to-shell, eval/exec, .mcp.json, Docker socket, library injection. R032F/F2, R032G (write): CLAUDE.md + .mcp.json protection. R041F/F2, R041G (edit): matching edit rules. R051: .env reads upgraded from log to ask.
- **Path sanitization (Phase B).** `sanitize_path()` strips newlines and resolves symlinks via realpath before pattern matching. Prevents newline injection and symlink laundering across Write, Edit, Read, NotebookEdit domains.
- **Audit signing canonicalization.** `jq -S` key-sorting before SHA-256 hashing produces deterministic signatures within the jq toolchain. External verifiers must also use `jq -S -c` — `jq` is not a formal cross-language canonicalization standard (JCS/RFC 8785).
- **85 new tests.** `test-perimeter-closure.sh` covers all new rules, path sanitization, symlink resolution, and 10 sandbox-specific tests. 231 total across 8 suites.

### Changed

- Policy v2.6.0 (72 rules, was 57). Signed with Ed25519.
- Origin story revised to honest version: "the gate is absolute where it stands, the perimeter is not yet complete."
- Glossary: 16 new terms (Composition Attack, Governance Perimeter, Escape Hatch, Binding Width, TOCTOU Window, Approval Receipt, Tiered Sandboxing, Taint Label, Taint Explosion, Forward-Secure Signing, External Anchoring, JCS Canonicalization, Policy Transparency Log, Fencing Token, Multi-Gate Deployment, Canary System) + 5 existing terms updated.

### Honest Boundaries

17 escape hatches blocked. 2 partially (DNS exfiltration, persistence edges). 4 require upstream Anthropic fixes (#25000, #23983, #37210, MCP sampling). 2 fundamental (model deliberate evasion, kernel-level bypass).

## 1.5.0 — 2026-03-29

Perimeter closure Phase A. Policy rules only.

### Added

- 15 new policy rules mitigating 8 escape hatches (see v1.6.0 for full list)
- `test-perimeter-closure.sh` with 69 assertions

## 1.4.1 — 2026-03-26

Security fixes from cross-model audit (Codex + Claude verification). Five issues found, five fixed. The most critical: approval for one command could authorize a different command matching the same policy rule.

### Fixed

- **CRITICAL: Approval replay/binding bypass.** Approvals were keyed only by rule + session, not by action content. An agent could get approval for `git status` (rule R014) and use that approval to execute `git push` (also R014) on retry. Approvals are now bound to a SHA-256 hash of the exact command. Mismatch forces a fresh human ask. Backward compatible with legacy pending files.
- **CRITICAL: MCP gate fail-open on missing policy.** The MCP gate returned `ask` (risk 50) when no policy file was found. Now returns `deny` (risk 100) — fail-closed, matching the bash gate's behavior.
- **MCP gate inbox forgery.** Callback files in the MCP inbox were accepted without HMAC verification. Now verified using `timingSafeEqual` with the shared dispatcher HMAC secret.
- **MCP dispatcher `mcp:` routing.** Telegram callbacks with `mcp:` prefix were silently discarded. Now routed to `/var/run/zlar-tg/inbox/mcp` with 🔷 emoji.
- **HMAC timing side-channel.** String equality comparison replaced with double-hash constant-time compare in `lib/hmac.sh`.

### Added

- **Hash chain atomicity.** `emit_event` now acquires `flock` on Linux before reading `prev_hash` and appending. Prevents chain forks under concurrent SubagentStart + PreToolUse invocations. macOS uses synchronous hook guarantee (no flock available).
- **Strict signed audit mode.** Set `ZLAR_REQUIRE_SIGNED_AUDIT=true` (env var or `gate.json`) to refuse writing unsigned audit entries. When enabled, missing signing key causes gate to deny all actions. Default: false (preserve graceful degradation).
- **Approval binding test suite** (`tests/test-approval-binding.sh`) — 11 assertions covering replay prevention, backward compatibility, hash determinism, and subagent binding.
- **MCP fail-closed test** — verifies deny on missing policy file.
- **MCP gate EXPERIMENTAL label** — startup warning that Ed25519 policy signature verification and per-entry audit signing are not yet implemented.

### Known limitations (Phase B, deferred)

- MCP gate does not verify Ed25519 policy signatures (trusts the file).
- MCP gate does not sign individual audit entries.
- These require porting the crypto abstraction to Node.js.

## 1.4.0 — 2026-03-26

Per-entry cryptographic signing and supply chain hardening. Every audit trail entry is now individually signed. The gate hardens against the deny-path bypass class and supply chain attacks.

### Added

- **Per-entry Ed25519 audit signing** — every audit entry is SHA-256 hashed and Ed25519-signed via `lib/crypto.sh` before being written to the JSONL audit trail. `signature` field appended to each entry. Graceful fallback to `"unsigned"` if signing key is missing. Satisfies SP 800-53 AU-10 (Non-Repudiation) — each entry is cryptographically bound to the signing key, providing independent verifiability.
- **R099 canary rule** — denies commands containing `ZLAR_CANARY_PROBE` to prove gate enforcement on demand. Canary test script: `scripts/canary.sh`.
- **Token rotation documentation** (`docs/token-rotation.md`) — rotation procedures for all 4 credential types (Telegram token, HMAC secret, signing keys, full reset).
- **Inbox HMAC verification** — Telegram callback files are HMAC-verified before the gate reads them. Prevents inbox file injection.
- **HMAC test suite** (`tests/test-inbox-hmac.sh`) — tests for inbox integrity verification.

### Changed

- **Deny-then-retry pattern** — replaced blocking Telegram poll with immediate deny + inbox check on retry. Claude Code hooks must respond fast — long-running polls silently bypass governance. New functions: `check_pending_approval()`, `telegram_ask_async()`. Old blocking `telegram_ask()` removed.
- **Supply chain hardening** (12 items) — SHA-pinned CI actions, vendored `cedar-wasm`, eliminated policy cache bypass seam, hidden bot token from `ps` output, hardened `/tmp` paths, locked signing algorithm to allowlist, `chmod 640` on dispatcher callback files.
- **SubagentStart handler** — now uses same deny-then-retry pattern as PreToolUse.

### Fixed

- **Silent governance bypass under `set -u`** — dead `policy_hash`/`cache_file` references crashed the gate, causing Claude Code to default-allow every policy-evaluated tool call.
- **Dispatcher file permissions** — `chmod 600` → `640` so the gate (running as user, not root) can read Telegram callback files.

## 1.3.0 — 2026-03-22

Cryptographic agility and the proof layer. The gate can now sign with post-quantum algorithms and produce machine-readable governance attestations for external consumption.

### Added

- **Cryptographic abstraction layer** (`lib/crypto.sh`) — algorithm-agnostic signing, verification, and key management. Three modes: `ed25519` (default), `ml-dsa-44` (NIST FIPS 204, post-quantum), `hybrid` (Ed25519 + ML-DSA-44 composite, both must verify). Algorithm choice is configuration via `ZLAR_SIGN_ALGORITHM` env var or `etc/crypto.json` — no code changes required. Satisfies Government of Canada cryptographic agility requirements (ITSAP.40.018). 46 tests.
- **Governance attestation** (`zlar-audit attest`) — the proof layer. Self-contained, cryptographically sealed JSON bundle packaging audit events, hash chain integrity verification, summary statistics, policy metadata, and cryptographic metadata. Designed for external consumption by regulators (OSFI E-23), insurers (AI governance coverage), courts (litigation defense), and auditors (ISO 42001).
- **E-23 Cedar policy templates** (`cedar-poc/e23.cedar`, `cedar-poc/e23.cedarschema`) — 11 rules implementing OSFI Guideline E-23 risk-tiered governance using bank risk management vocabulary: kill switches (session denial burst circuit breaker, low-confidence production halt), position limits ($10K tier-1, $100K absolute, mandatory counterparty), pre-execution checks (tiered risk thresholds by agent classification), environment controls, and third-party model controls. 25 tests.

### Changed

- **Gate and policy CLI now route through `lib/crypto.sh`** — `bin/zlar-gate` and `bin/zlar-policy` both source the cryptographic abstraction. Policy signing and verification use algorithm labels from the abstraction layer. Existing Ed25519-signed policies verify without modification (backward compatible).
- **Gate audit metadata resolved via abstraction** — `SIGNATURE_ALGORITHM`, `HASH_ALGORITHM`, and `PUBLIC_KEY_ID` are now computed by `lib/crypto.sh` rather than hardcoded.

## 1.2.0 — 2026-03-21

Agent inventory and cryptographic agility. You cannot govern what you cannot see.

### Added

- **Agent registry** (`bin/zlar-registry`) — reads the evidence trail, surfaces every agent the gate has seen: identity, sessions, activity, denial rates, domains touched. Supports multi-audit trails. Closes the agent inventory gap.
- **PQC metadata** — every audit entry now carries `signature_algorithm`, `hash_algorithm`, and `public_key_id`. Zero behavior change, but migration tooling will know exactly which entries need re-signing when Ed25519 gives way to ML-DSA.
- **Cedar proof-of-concept** (`cedar-poc/`) — three real gate rules (R012, R001, R014) translated to Cedar policy language, validated against schema, 14/14 tests passing. Proves the migration path from bash pattern matching to formal policy evaluation.
- **Demo script** (`docs/demo-script.md`) — 5-minute deny path walkthrough for briefings.

### Fixed

- **Human deny path was silently broken** — `set -e` (errexit) killed the gate process when `telegram_ask` returned exit code 1 (deny). The deny response never reached Claude Code, which defaulted to allowing the tool call. Every human deny since the gate was written was a no-op at the enforcement layer. The evidence trail recorded the deny intent but the action executed anyway. Fixed by capturing the return code safely (`telegram_ask ... || ask_result=$?`). Both PreToolUse and SubagentStart paths patched. The architecture caught the bug: recursive trust proof + evidence trail inspection revealed the gap. Approximately 29-30 historical audit entries have orphaned `pending` outcomes with no recorded resolution.

### Known limitations

- **Cedar PoC maps `ask` to `forbid`** — Cedar's effect model is binary (permit/forbid). The gate's three-valued `allow`/`deny`/`ask` requires either Cedar extensions or a two-pass evaluation. The PoC proves rule translation, not full semantic parity.
- **OC gate audit schema divergence** — the OC gate does not emit `prev_hash` or `authorizer` fields. Observation tools that query these fields will silently return null for OC events. Schema alignment planned for a future release.

## 1.1.0 — 2026-03-21

Added observation layer. The gate enforces — the witness observes. Two layers, one product.

### Added

- **Sequence detection** (`bin/zlar-witness`) — reads the evidence trail after the fact, finds multi-step behavioral patterns (credential-adjacent-egress, denied-then-scheduled, approval-drift, repeated-denial-burst)
- **Governance digest** (`bin/zlar-digest`) — weekly summary of decisions, approval latency, detected sequences. Sends to Telegram.
- **Standing authority view** (`bin/zlar-standing`) — shows what the agent can do right now without asking
- **Shared audit library** (`lib/audit-reader.sh`) — fact extraction from evidence trails. Multi-audit support: reads from both CC and OC gate trails via `ZLAR_AUDIT_FILES`
- **Sequence definitions** (`etc/sequences.json`) — pattern catalog for witness detection
- **Test suite** (`tests/test-witness.sh`) — 20+ assertions covering witness, digest, standing, and audit-reader
- **Design documentation** (`docs/witness.md`) — observation layer design philosophy

### Changed

- CI now includes ShellCheck for `lib/` and `tests/`, plus witness test execution

## 1.0.0 — 2026-03-18

Consolidated release. Five repositories (ZLAR-Gate, ZLAR-LT, ZLAR-OPS, ZLAR-NT, ZLAR-OC) unified into a single ZLAR repository.

### What's included

- **Core gate engine** (`bin/zlar-gate`) — universal policy engine, Ed25519-signed policies, JSONL audit trail
- **Policy CLI** (`bin/zlar-policy`) — create, sign, validate, inspect policy rules
- **Convenience CLI** (`bin/zlar`) — status, audit, Telegram setup, diagnostics
- **Framework adapters** — Claude Code, Cursor, Windsurf
- **Zero-config installer** (`install.sh`) — `curl | bash`, governed in 60 seconds
- **Signal layer** — agent-discoverable thesis, manifest, and project map

### Prior history

- ZLAR-Gate v2.3.0 — universal gate engine with three-framework support
- ZLAR-LT v1.0.0 — zero-config installer with deny-heavy defaults
- ZLAR-OPS — observation, audit, fleet, and operational tooling
- ZLAR-NT — network egress policy enforcement
- ZLAR-OC — OS-level containment for OpenClaw agents
