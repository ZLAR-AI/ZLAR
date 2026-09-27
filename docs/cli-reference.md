# ZLAR CLI Reference

The `zlar` command is the operator's interface to the ZLAR governance system. It exposes the controls a human needs to administer the gate, inspect state, and respond to runtime issues.

This document is the reference for **what each command does**. For symptom-based problem-solving, see [`troubleshooting.md`](troubleshooting.md). For architectural context, see [`architecture-map.md`](architecture-map.md). For the properties ZLAR holds, see [`../PRINCIPLES.md`](../PRINCIPLES.md).

This reference tracks current mainline CLI behavior; installed releases may differ.

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
| `zlar on` | Enable enforcement (remove off-flags) | Removes `/etc/zlar/off-flag` when sudoers permits, and removes the legacy `~/.claude/.gate-disabled` marker |
| `zlar off` | Disable enforcement (write off-flags) | Writes `/etc/zlar/off-flag` when sudoers permits, and writes the legacy `~/.claude/.gate-disabled` marker |
| `zlar reset` | Clear human invariant state (escape hatch for stuck H13) | Backs up + deletes state files in `${PROJECT_DIR}/var/human-state/` |
| `zlar doctor` | Run installation health check | None (read-only) |
| `zlar audit [N]` | Show last N audit entries (default 20) | None (read-only) |
| `zlar key-state [--json]` / `zlar key-state --sample --json` | Show read-only local key-state verifier/pin alignment snapshot, or deterministic sample JSON for proof fixtures | None (read-only); does not sign, request PINs, or read private key bytes |
| `zlar coverage (--input <file\|->\|--sample)` | Build a fixture-input Governed Surface Coverage Map from supplied or committed-sample evidence | None (read-only) |
| `zlar agent-passenger-lab [--json\|--json-out <file>]` | Run the local fixture Governed Crossing Test Harness for instrumented passenger roles | None unless `--json-out <file>` writes the selected report path |
| `zlar coverage-evidence bash --input <file> --event-id <id>` | Assemble supplied bash-gate coverage evidence for one event | None (read-only) |
| `zlar coverage-evidence mcp --input <file> --event-id <id>` | Assemble supplied MCP-gate coverage evidence for one event | None (read-only) |
| `zlar downstream-recognition --input <file>` | Evaluate a supplied signed v1 receipt against a supplied downstream recognition rule | None (read-only) |
| `zlar downstream-refusal-proof [--json]` | Run a local hermetic fake-downstream refusal proof | None (read-only) |
| `zlar human-authorization-proof [--json]` | Run a local hermetic simulated-human authorization proof | None (read-only) |
| `zlar approval-transport-proof [--json]` | Run a local hermetic channel-neutral approval transport proof | None (read-only) |
| `zlar current-machine-governance-preview --sample [--json]` | Compose local no-write current-machine governance preview evidence into one bounded receipt | Uses committed fixtures and proof-owned temporary roots only; no authority request, install/config write, live hook, live receipt, live downstream recognition, Telegram, GitHub settings, website publication, external contact, or current-machine governance claim |
| `zlar verifier-env [--json\|--json-out <file>]` | Check external verifier workstation prerequisites and optionally emit a redacted machine-readable readiness/failure report | None unless `--json-out <file>` writes the selected new report path |
| `zlar verifier-kit-reproducibility [--json\|--json-out <file>]` | Build the verifier kit twice with one temporary test publisher key and prove archive SHA-256 determinism | Regenerates ignored `dist/` verifier-kit build output; no signing material outside the temporary test key |
| `zlar verifier-kit-release-assets-live-read --release-tag <vX.Y.Z> [--repo <owner/name>] [--download-dir <dir>] [--json\|--json-out <file>]` | Read explicit-tag public release assets and bind downloaded SHA-256 evidence | Optional local writes to `--download-dir` and `--json-out`; does not upload release assets, mutate releases, read private keys, or create attestation |
| `zlar verifier-kit-public-distribution --release-tag <vX.Y.Z> --release-assets-json <file> --reproducibility <file> [--asset-dir <dir>] [--json\|--json-out <file>] [--require-public]` | Audit whether verifier-kit release assets and reproducibility evidence support a public distribution posture | None (read-only); does not upload release assets, read private keys, or create attestation |
| `zlar private-verifier-result verify (--input <file\|->\|--sample) [--evidence-dir <dir>] [--json]` | Validate a private-by-default verifier result envelope without public attribution or public external attestation | None (read-only) |
| `zlar private-verifier-readiness build --evidence-dir <dir> --commit <sha> --evidence-source-commit <sha> --branch <branch> --output-dir <dir>` | Build a local private no-send verifier-readiness packet for supplied active-persistent lifecycle evidence | Writes only the selected local packet output directory; does not contact a verifier, publish, attest, release, deploy, or change access |
| `zlar private-verifier-readiness verify --input <file\|-> [--evidence-dir <dir>] [--require-commit <sha>] [--require-evidence-source-commit <sha>] [--require-recomputed-evidence]` | Verify a private verifier-readiness packet and optionally recompute the supplied evidence bundle hashes | None (read-only); does not create external attestation or non-operator review |
| `zlar public-artifact-verifier-result verify (--input <file\|->\|--sample) [--json]` | Validate a redacted public-artifact verifier reply envelope without source access or public attestation | None (read-only) |
| `zlar public-artifact-verifier-result from-transcript (--input <file\|->\|--sample-transcript) [--json]` | Normalize a bounded public-artifact terminal transcript into the redacted reply envelope | None (read-only) |
| `zlar public-external-attestation-result verify --input <file\|-> [--json]` | Validate a bounded public signed external-attestation envelope without contacting external services | None (read-only); North Star readiness consumes the verification output only as intake evidence, not as a readiness or public-claim upgrade |
| `zlar live-trust-registry-state verify --input <file\|-> [--json]` | Validate a no-secret live-shaped trust registry, issuer status, custody posture, and revocation contract | None (read-only); no live probing, key custody, revocation truth, production recognition, or public attestation claim |
| `zlar private-verifier-zip-result verify (--input <file\|->\|--sample) [--evidence-dir <dir>] [--json]` | Validate a private personally connected outside-machine ZIP-snapshot verifier result without public attestation | None (read-only) |
| `zlar source-bridge-window (--input <file\|->\|--sample) [--json] [--json-out <file>]` | Validate a no-secret time-boxed source bridge window authority packet | None unless `--json-out <file>` writes under the build scratch root; does not push, read remote refs, call GitHub, mint credentials, inspect keys, or change config |
| `zlar issuer-status-proof [--json]` | Run a local hermetic issuer status proof | None (read-only) |
| `zlar protected-records-proof [args...]` | Refuse permanently retired fresh E1 terminal-proof generation | No key generation, signing, scratch state, adapter call, artifact, or effect |
| retired `protected-records-write` source surface | Fixed-refuse the retired direct E1 adapter/factory route | No main-dispatch route; standalone source and exported factory return `e1_direct_adapter_factory_source_retired`; future repair/upgrade/reinstall source omits and removes the exact stale wrapper/module paths, but no install ran and old installed or copied source remains unproven |
| `zlar protected-records-adapter-conformance [args...]` | Refuse permanently retired fresh E1 adapter-conformance generation | No key generation, signing, child process, scratch state, adapter call, artifact, or effect |
| retired `protected-records-service-request` source surface | Fixed-refuse the retired direct E2 request/factory route | No main-dispatch route; standalone source and exported factory return `e2_direct_request_factory_source_retired`; future repair/upgrade/reinstall source omits and removes the exact stale wrapper/module paths, but no install ran and old installed or copied source remains unproven |
| `zlar protected-records-service-proof [args...]` | Refuse permanently retired fresh E2 service-proof generation | No key generation, signing, child process, scratch state, artifact, or effect |
| `zlar protected-records-service-preflight --profile <file\|-> [args...]` | Refuse permanently retired fresh E2 service-preflight generation before reading the profile | No profile read, key generation, signing, child process, artifact, or effect |
| `zlar protected-records-service-preflight verify (--input <file\|->\|--sample) [--json] [--require-sha <sha256>]` | Verify a supplied or committed historical service-profile preflight artifact | None (read-only) |
| `zlar protected-records-runtime-service [args...]` | Refuse the permanently retired legacy runtime-service direct entry surface | The committed script body performs no config, stdin, authority-status, target-module, or consequence handling and returns `legacy_runtime_v1_direct_entry_surface_retired` |
| `bin/zlar-protected-records-replacement-crossing-v2 cross-and-pin ...` | Execute one externally pinned, source-authorized v2 local-fixture crossing through the exact driver route | At most one runtime request; may mutate the exact fixture target and then pin route artifacts/status; never retries and does not claim crash-atomic or exactly-once effect |
| `zlar protected-records-replacement-artifact-set-v2 verify ...` | Verify the pinned v2 service/terminal artifact set without runtime import or consequence reexecution | Read-only raw-byte verification; cannot reactivate authority or re-execute the effect |
| `zlar protected-records-runtime-profile-preflight --profile <file\|-> [--json]` | Refuses nested positive runtime proof generation while the exact grant is exhausted | No scratch root or consequence; historical artifact verification remains separate |
| `zlar protected-records-runtime-activation-preflight --plan <file\|-> --profile <file\|-> [--json] [--artifact <file\|->]` | Refuses nested positive runtime proof generation while the exact grant is exhausted | No artifact or consequence write |
| `zlar protected-records-runtime-activation-preflight verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or committed-sample activation-preflight artifact | The verify branch precedes generation; intended no consequence reexecution, but transitive import-time side-effect closure is unproven |
| `zlar protected-records-runtime-local-activation --plan <file\|-> --profile <file\|-> [--json] [--artifact <file\|->]` | Refuses positive local-activation proof generation while the exact grant is exhausted | No artifact, scratch consequence, persistent config, or hook write |
| `zlar protected-records-runtime-local-activation verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or committed-sample local-activation artifact | The verify branch precedes generation; intended no consequence reexecution, but transitive import-time side-effect closure is unproven |
| `zlar protected-records-runtime-profile-installation --plan <file\|-> --profile <file\|-> [--json] [--artifact <file\|->]` | Refuses before disposable install-root creation while the exact grant is exhausted | No artifact, install-root, profile, config, or hook write |
| `zlar protected-records-runtime-profile-installation verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or committed-sample disposable profile-installation artifact | The verify branch precedes generation; intended no consequence reexecution, but transitive import-time side-effect closure is unproven |
| `zlar protected-records-installed-runtime-profile-preflight --install-root <dir> --expected-profile <file\|-> --profile-id <id> --profile-sha256 <sha256> [--json] [--artifact <file\|->]` | Preflight an explicit installed runtime-profile root by profile id and SHA | None unless `--artifact <file>` writes the selected artifact path; no install, activation, config, hooks, or service start |
| `zlar protected-records-installed-runtime-profile-preflight verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or committed-sample installed-runtime-profile preflight artifact | None (read-only) |
| `zlar protected-records-active-persistent-profile-preflight --surrogate-root <dir> --activation-root <dir> --proof-target <file> --profile <file> --runtime-profile-id <id> --runtime-profile-sha256 <sha256> --expires-at <future-iso8601> [--json] [--report <file>]` | Source-only preflight for a future active persistent profile install | None unless `--report <file>` writes the selected report path; no install, activation, hooks, config, service start, real activation root default, or literal/symlink-routed real activation-root evidence path |
| `zlar protected-records-active-persistent-profile-preflight status --surrogate-root <dir> --activation-root <dir> [--json]` | Read-only source-preflight status for an explicit proof-owned surrogate activation root | None (read-only; refuses live-root defaulting) |
| `zlar protected-records-active-persistent-profile-preflight closeout --manifest <file\|-> --closed-at <iso8601> --reason <reason> [--json] [--output <file>]` | Build a source-preflight closeout object from a supplied source-preflight manifest | None unless `--output <file>` writes the selected closeout path; no activation or service start |
| `zlar protected-records-active-persistent-profile-live-installation install --activation-root <dir> --profile <file> --runtime-profile-id <id> --runtime-profile-sha256 <sha256> --expires-at <future-iso8601> [--allow-named-live-root] [--replace-closed-root] [--json] [--report <file>]` | Refuses as `active_persistent_profile_mutation_authority_absent`; the fixture grant does not authorize persistent-profile mutation | No activation-root inspection or creation, profile install, report write, service start, hook/config write, credential use, or real-record write |
| `zlar protected-records-active-persistent-profile-live-installation status --activation-root <dir> [--allow-named-live-root] [--json]` | Inspect explicit active persistent profile root state | None (read-only) |
| `zlar protected-records-active-persistent-profile-live-installation closeout --activation-root <dir> --closed-at <iso8601> --reason <reason> [--allow-named-live-root] [--json]` | Refuses as `active_persistent_profile_mutation_authority_absent` until separate closeout authority is source-recorded | No activation-root inspection or manifest mutation |
| `zlar protected-records-active-persistent-profile-action-crossing --activation-root <dir> --expected-profile <file> --profile-id <id> --profile-sha256 <sha256> --proof-target <file> --allow-named-live-root [--json] [--report <file>]` | Refuses before active-root inspection or proof-target handling while the exact grant is exhausted | No root, target, service, or report write |
| `zlar protected-records-active-persistent-profile-lifecycle --install-report <file> --green-report <file> --red-report <file> --closeout-report <file> [--expected-*-report-sha256 <sha256>...] [--json] [--report <file>]` | Verify supplied historical lifecycle mechanics while forcing current fixture-rightful projection false | The non-`run` branch avoids generation and may write only `--report`; transitive import-time side-effect closure is unproven; no root reopen, renewal, activation, service start, credentials, real records, production claim, current-machine-general claim, or public claim |
| `zlar protected-records-active-persistent-profile-lifecycle run --activation-root <dir> --output-dir <dir> --profile <file> --runtime-profile-id <id> --runtime-profile-sha256 <sha256> --expires-at <future-iso8601> [--allow-named-live-root] [--replace-closed-root] [--json]` | Refuses before activation-root/output creation while the exact grant is exhausted | No root, target, report, or manifest write |
| `zlar protected-records-installed-runtime-profile-recognition-proof (--input <file\|->\|--sample) [--json] [--artifact <file\|->]` | Refuses positive proof generation because the exact one-use fixture grant is exhausted | No positive consequence; use the read-only verify form |
| `zlar protected-records-installed-runtime-profile-recognition-proof verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or committed-sample recognition-proof artifact | The verify branch precedes generation; intended no consequence reexecution, but transitive import-time side-effect closure is unproven |
| `zlar protected-records-installed-runtime-profile-service-proof (--input <file\|->\|--sample) [--json] [--artifact <file\|->]` | Refuses positive generation because the exact one-use fixture grant is exhausted | No positive consequence; refusal precedes grant-store commit and state mutation |
| `zlar protected-records-installed-runtime-profile-service-proof verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or committed-sample service-proof artifact | The verify branch precedes generation; intended no consequence reexecution, but transitive import-time side-effect closure is unproven |
| `zlar protected-records-installed-runtime-profile-terminal-chain (--sample\|--plan <file\|-> --profile <file\|->) [--json] [--artifact <file\|->]` | Refuses fixture-rightful composition while the exact grant is exhausted | No positive consequence; use the read-only verify form for historical artifacts |
| `zlar protected-records-installed-runtime-profile-terminal-chain verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or committed-sample terminal-chain artifact | The verify branch precedes generation; intended no consequence reexecution, but transitive import-time side-effect closure is unproven |
| `zlar protected-records-one-terminal-deployment-profile --sample [--json]` | Refuses fixture-rightful projection from the exhausted committed service grant | None; no positive consequence |
| `zlar protected-records-one-terminal-deployment-profile --profile <file\|-> --runtime-profile <file> --preflight-artifact <file> [--json]` | Refuses fixture-rightful projection while preserving exact input validation | None; no positive consequence |
| `zlar protected-records-named-deployment-profile-readiness --sample [--json]` | Run a local no-secret named deployment-profile rehearsal readiness report | None (read-only local rehearsal; no install/config/current-machine/production claim) |
| `zlar protected-records-named-deployment-profile-real-boundary --run [--json] [--artifact <file>]` | Refuses the named machine-local route outside current authority | Zero side effects: no activation root, proof target, config, child process, or artifact |
| `zlar recognized-effect-target-shape --sample [--json] [--artifact <file\|->]` | Run the no-secret recognized-effect target-shape fixture proof | None unless `--artifact <file>` writes the selected artifact path; does not block OS filesystem writes or prove side-door closure |
| `zlar recognized-effect-target-shape verify (--input <file\|->\|--sample) [--json]` | Verify a supplied or sample recognized-effect target-shape artifact | None (read-only); refuses malformed, replayed, stale, mismatched, untrusted-ingress, and tampered fixture evidence |
| `zlar records-write-terminal-proof [--json] [--plan <file\|-> --profile <file\|->]` | Refuses before nested runtime proof execution while the exact grant is exhausted | No consequence or artifact write |
| `zlar protected-records-runtime-profile-proof [--json]` | Refuses before scratch-root creation while the exact grant is exhausted | No child process, scratch store, or effect |
| `zlar local-proof-pack [args...]` | Refuses permanently retired fresh proof-pack generation | No child process, scratch store, effect, or artifact write |
| `zlar local-proof-pack verify (--input <file\|->\|--sample) [--json]` | Verify historical structure and artifact identity with fixture-rightful projection permanently false for legacy schemas | The verify branch precedes generation; intended no consequence reexecution, but transitive import-time side-effect closure is unproven |
| `zlar product-proof-path [args...]` | Refuses permanently retired fresh Product Proof Path generation | No proof execution or report write |
| `zlar proof-smoke [verify (--input <file\|->\|--sample)]` | Refuses fresh smoke execution and legacy fixture-rightful schema acceptance | The verify branch precedes fresh generation; transitive import-time side-effect closure is unproven, and a new artifact-bound schema is required |
| `zlar north-star-readiness (--sample\|--evidence-dir <dir> [--release-tag <vX.Y.Z>] [--private-verifier-result-verification <file>] [--private-verifier-zip-result-verification <file>] [--public-artifact-verifier-result-verification <file>] [--public-external-attestation-result-verification <file>]) [--json]` | Refuses current fixture-rightful readiness composition under the exhausted grant | None; historical tag-specific verification remains at its pinned source, and a new artifact-bound schema is required for current composition |
| `zlar policy` | Show current policy rules summary | None (read-only) |
| `zlar version` | Show ZLAR version and install path | None (read-only) |
| `zlar telegram` | Configure Telegram approval (interactive) | Modifies `${PROJECT_DIR}/.env` and `${PROJECT_DIR}/etc/gate.json` |
| `zlar uninstall` | Remove the ZLAR installation (interactive) | Destructive — see the command for exact behavior |
| `zlar help` | Show command list | None |
| `zlar-restore evaluate` | Run Agent Health detectors against session trace | Writes `var/restore/trust-state.json` if state worsens |
| `zlar-restore status` | Show current trust state | None (read-only) |
| `zlar-restore reset <reason>` | Reset trust state to healthy (with friction) | Modifies trust state file after delay |
| `zlar-restore history` | Show trust state transition history | None (read-only) |
| `zlar-restore detectors` | List available detectors | None (read-only) |

Rows above that describe an exhausted grant or a refusal report the
source-recorded status at this source checkpoint. They do not prove
caller-authenticated current runtime refusal. For hybrid ESM verification
commands, branch ordering is source-checked, while transitive import-time
side-effect closure remains unproven unless a row states a narrower exact
boundary.

---

## First Proof-Only Protected-Records Run

Before installing or activating anything, a human can inspect the
protected-records boarding path from the repo root with committed fixture
evidence:

```bash
bin/zlar protected-records-runtime-profile-installation verify --sample
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample
```

This is the first-run proof path, not an install path. These commands do not
write hooks, user config, machine config, persistent runtime config, or service
configuration. They do not select `--latest`, select a default current-machine
profile, inspect a live records system, start a persistent runtime service,
prove current-machine governance, prove production downstream recognition, or
close unrouted records paths.

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

If sudoers is not configured, `zlar off` can write only the legacy wrapper flag
(`~/.claude/.gate-disabled`). Current install-managed wrappers no longer treat
that flag as the load-bearing off-switch, so the structural gate may remain on.
You will see a warning on `zlar off`:

```
  (warn: /etc/zlar/off-flag not writable; legacy wrapper flag written only)
ZLAR structural gate may still be ON. Current install-managed wrappers require /etc/zlar/off-flag for the off state.
```

The wrapper flag is the v2.6.0 behavior and is retained for legacy status and
old wrapper compatibility. The structural off-switch is the load-bearing
current path that puts the kill-switch outside routed agent reach through the
ZLAR-governed path.

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
    Resolved gate state:                         LEGACY FLAG ONLY — current install-managed gate may still enforce
    Codex hook target (PreToolUse):              <verify locally; host/version-specific>
    Codex hook reality:                          configured to current gate; current invocation not observed by status
    Codex interception:                          configured route only; current invocation not observed by status
    Claude legacy/current hook target:           /Users/yourname/.claude/zlar-gate.sh

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
- You need to distinguish `state=on` from a specific client hook actually being
  configured and current
- Diagnosing whether `pending_count` has hit the H13 cap (it will show as `⚠ OVER CAP` in red)
- Checking the hook target to verify it points where you expect

The Human ID is partially masked for privacy when the output is shared (e.g., screenshots, support requests).

### `zlar key-state`

Shows the current local key-state alignment for ZLAR signing concerns.

```bash
zlar key-state
zlar key-state --json
zlar key-state --sample --json
```

The text form is for operators. The JSON form emits
`zlar-key-state-report-v1` for automation. It reports local public verifier
fingerprints, manifest/active-policy/constitution embedded public-key
fingerprints, hardware-slot observation when available, and legacy software
private-key presence as a boolean only.
`--sample --json` emits the deterministic fixture report used by
`local-proof-pack` and `proof-smoke`. It uses a fixture home directory, fixed
timestamp, no hardware observation, and no OpenSSL/YubiKey tool availability
so committed evaluator artifacts can carry the key-state report shape without
inspecting the operator's home directory, hardware, private key paths, or
current-machine custody state. `--sample` is only valid with `--json`.

Boundary: this is a local read-only key-state snapshot. It does not sign,
request PINs, read private key bytes, rotate or revoke keys, prove key custody,
prove hardware possession, prove production trust-registry truth, provide
external attestation, prove sovereign recognition, or prove current-machine
governance. The sample form is fixture evidence only and is not a live
key-state snapshot.

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
- Touches `~/.claude/.gate-disabled` (legacy wrapper marker)
- Touches `/etc/zlar/off-flag` via passwordless sudo (current structural kill-switch path)
- If sudoers isn't configured, prints a warning and the structural path is skipped; current install-managed wrappers may continue enforcing

**Use when:**
- You are actively building or modifying ZLAR itself and don't want to be governed by it
- Running tests or experiments where the gate would interfere
- You have explicit human authority to suspend enforcement temporarily

The First Authority Law says the human is the sovereign. `zlar off` is the
human exercising that sovereignty when the structural off-flag is written. It
is distinct from an agent trying to disable enforcement through a routed gate
path: the current off-flag lives under `/etc/zlar/`, requires sudo, and policy
rule R003 denies sudo from the bash domain.

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

### `zlar coverage`

Build a fixture-input Governed Surface Coverage Map from supplied action-surface
evidence. This command does not perform live probing, does not inspect live
hooks or audit stores, and does not claim live machine coverage.

```bash
zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json
zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json --json
zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json --require-governed
zlar coverage --sample
zlar coverage --sample --json
zlar coverage --sample --require-governed
```

The two `--require-governed` examples are refusal checks against the current
`4/6` sample; they exit nonzero while the exhausted-grant lanes remain open.

Counted lanes can be marked governed only when supplied evidence proves
routing, freshness, policy currency, Worker Receipt capability, and downstream
refusal. Boundary entries are named in the map but are not governed coverage.
JSON reports include derived `coverage_summary`, `last_decision`,
`last_receipt`, `issuer_identity`, and `known_boundaries` fields; the text
summary names the latest supplied decision, receipt status, and issuer or
recognition-anchor identifier for counted lanes. These summaries are supplied
fixture/report evidence only, not live discovery or issuer-status proof.
`--sample` uses the committed fixture at
`tests/fixtures/governed-surface-coverage-map-v1-input.json` without requiring
the path to be supplied. The committed sample currently counts four governed
fixture lanes: bash `PreToolUse`, routed MCP `tools/call`,
`protected-records.service-profile.records.write` from the committed
service-profile preflight artifact,
and `protected-records.runtime.records.write` from the committed runtime-local
activation artifact. It counts but does not govern
`protected-records.runtime.profile-installation.records.write` from the
committed disposable runtime-profile installation artifact and
`protected-records.installed-runtime-profile.terminal-chain.records.write`
from the committed installed-runtime-profile terminal-chain artifact because
the current grant is exhausted and those lanes are not receipt-capable. It is
still fixture-input evidence, not live coverage.

For the evidence model and claim boundary, see
[`docs/governed-surface-coverage-map.md`](governed-surface-coverage-map.md).

### `zlar consequence-lifecycle`

Project one validated installed-runtime-profile terminal-chain artifact into a
strict local-fixture consequence lifecycle map:

```bash
zlar consequence-lifecycle --sample
zlar consequence-lifecycle --sample --json
zlar consequence-lifecycle --input tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json
zlar consequence-lifecycle --input - --json
bin/zlar-consequence-lifecycle-replacement-overlay-v0 \
  --base-map <consequence-lifecycle-map-v0.json> \
  --replacement-manifest <50-replacement-artifact-set-manifest-v2.canonical.json> \
  --replacement-service <30-replacement-service-artifact-v2.canonical.json> \
  --replacement-terminal <40-replacement-terminal-artifact-v2.canonical.json> \
  --replacement-exhausted-status <80-authority-status-exhausted-v2.json> \
  --require-base-map-sha <sha256> \
  --require-replacement-manifest-sha <sha256> \
  --require-replacement-grant-sha <sha256> \
  --require-replacement-manifest-schema-sha <sha256> \
  --require-replacement-exhausted-status-sha <sha256> \
  --json
```

The v0 map is deliberately `mapped_open`. It separates a branching path
definition from the observed boarding and refusal traces, binds the exact
artifact body SHA and
`protected-records.installed-runtime-profile.terminal-chain.records.write`
path, preserves every source side door, and names missing lifecycle
obligations. `--require-closed` is a refusal gate: the committed sample fails
it because lifecycle closure is not proven.

The separate replacement-overlay command accepts one already-built, explicitly
SHA-pinned v0 map. It does not import the v0 lifecycle generator. It rebuilds
the declared `consequence-lifecycle-map` structural projection from raw
manifest, service, and terminal bytes, then cross-binds the canonical,
hash-pinned exhausted-status wrapper. Its committed static import graph
contains only the overlay, canonicalization/hash utilities, the replacement
artifact-set verifier, plus the exact `node:crypto`, `node:fs`, and `node:path`
built-in imports; it contains no lifecycle generator, runtime, crossing
driver, key, signing, or child-process module.

The overlay accepts no detached verification or projection JSON, mutable
runtime status, raw runtime result, or route closeout. The base map remains an
opaque caller-pinned root: the overlay emits its identity plus selected
validated open-boundary fields, not the unvalidated full object or its claim
strings. Its full schema is not revalidated; the report says
`base_map_schema_fully_validated=false`,
`base_map_claim_strings_evaluated=false`, and
`base_map_reference.full_object_reprojected=false`. The replacement inputs
prove caller-pinned structural artifact coherence only. They do not evaluate
authority or effect occurrence.

The overlay remains `mapped_open` with `rightful_issuance_projected=false`,
`consequence_reexecution_performed=false`, and
`manifest_covers_complete_lifecycle=false`. The replacement source commit
binds only that exact crossing lineage; it does not make the current lifecycle
graph source-commit-bound. `--require-closed` therefore continues to refuse.
The static source-graph claim assumes the intended interpreter and an
unmodified source tree. `NODE_OPTIONS`, custom loaders/preloads,
interpreter/PATH substitution, and same-user source mutation are outside this
overlay's coverage.

The artifact binds the exact path identity. The branching lifecycle graph is a
code-modeled, hash-identified projection whose source commit is not bound in
v0, so the graph itself remains an open lifecycle obligation rather than
artifact evidence. Evidence references are namespaced to the source artifact
or emitted report and must resolve before an obligation can count as
evidenced.

The current sample classifies 12 obligations as evidenced, 8 as not evidenced,
and 2 as outside coverage. It resolves 63/63 namespaced evidence references and
preserves 18 recognition refusals plus 5 authority-grant refusals.
`protected_target_binding` is evidenced only for one
launcher-owned `process-private-recognized-effect-state` logical-fixture target:
launcher config owns the target, the request target handle is assertion-only,
the boarded service receipt detail hash binds
`sha256(canonical({target_handle,record_update}))`, and the accepted state-effect
summary is hash-bound. The map also carries the full public fixture authority-
grant contract, its exact four-power topology, historical effect mechanics,
signed-payload replay separation, and the observed
grant-burn and joint-rollback boundaries. Private issuer appointment, key id,
public key, signature, and private key material remain outside the portable
artifact. Source reconciliation records the one-use grant as exhausted and
repeated-use provenance as invalid, so fixture-rightful issuance is false. It
also does not prove generic or portable rightful issuance, profile-wide target authority,
a per-run or physical target identity, a live target, production authority,
current-machine governance, or lifecycle closure. Verification without an
expected SHA proves structural self-integrity only; exact artifact identity
requires the caller to supply the pinned SHA-256 or a stronger external anchor.

The map keeps two receipt roles distinct. The
`boarded-service-write-authority-receipt` is the receipt whose detail hash binds
the accepted logical-fixture target effect. The
`synthetic-registry-recognition-evidence-receipt` supplies the generation-time
signature-valid and issuer-recognized registry summary only; it is not the
boarded service receipt, did not authorize the service write, and has a distinct
detail hash. Rightful issuance remains unproven. Artifact verification is
integrity verification over hash-bound summaries: the artifact contains neither
receipt envelope nor raw public-key material and cannot portably re-run either
cryptographic verification.

The map also keeps replay-store rollback protection separate from rollback of
the `records.write` consequence, splits revocation into distinct powers, and
prevents observations or hardening proposals from creating authority.

This command does not live probe, install, configure, activate, update policy,
apply hardening, borrow active-persistent evidence from another path, or prove
production governance, enterprise readiness, general current-machine
governance, revocation truth, public external attestation, side-door closure,
sovereign recognition, or all-surface governance.

### `zlar-protected-records-post-effect-route-evidence-index-v0`

Build one canonical, verification-only index over seven caller-pinned retained
route files without modifying the completed crossing directory:

```bash
bin/zlar-protected-records-post-effect-route-evidence-index-v0 \
  --runtime-result <20-runtime-service-result-v2.canonical.json> \
  --service <30-replacement-service-artifact-v2.canonical.json> \
  --terminal <40-replacement-terminal-artifact-v2.canonical.json> \
  --manifest <50-replacement-artifact-set-manifest-v2.canonical.json> \
  --verification <60-replacement-artifact-set-verification-v2.json> \
  --exhausted-status <80-authority-status-exhausted-v2.json> \
  --closeout <90-route-closeout-v2.json> \
  --require-runtime-result-file-sha <sha256> \
  --require-service-file-sha <sha256> \
  --require-terminal-file-sha <sha256> \
  --require-manifest-file-sha <sha256> \
  --require-verification-file-sha <sha256> \
  --require-exhausted-status-file-sha <sha256> \
  --require-closeout-file-sha <sha256> \
  --require-service-body-sha <sha256> \
  --require-terminal-body-sha <sha256> \
  --require-manifest-body-sha <sha256> \
  --require-manifest-schema-sha <sha256> \
  --require-grant-sha <sha256> \
  --require-crossing-binding-sha <sha256> \
  --require-exhausted-status-body-sha <sha256> \
  --require-crossing-source-commit <git-sha1> \
  --json
```

Every path and identity argument is mandatory. The CLI trusts neither
filenames nor directory adjacency, refuses one filesystem object assigned to
multiple roles, and reads through one no-follow descriptor with pre-read size
and post-read descriptor checks. `--json` emits exact canonical JSON bytes to
stdout without a trailing newline. The command writes no file and is not wired
through the broad dispatcher.

Raw service, terminal, and manifest bytes source-recompute the artifact-set
verification through the pure v2 verifier. The supplied persisted
verification must match that recomputed canonical object and bytes exactly.
This is source-recomputed no-reexecution verification, not independent actor,
process, implementation, or external attestation evidence.

The runtime result remains an opaque caller-pinned root. Only selected path,
accepted-transition, source, authority-hash, target, and artifact bindings are
validated; the report keeps `runtime_result_schema_fully_validated=false` and
`runtime_result_claim_strings_evaluated=false`. The exhausted status is
cross-bound and chronology-checked. The closeout is exact-key and posture
checked, but it contains no crossing identity, so
`closeout_crossing_identity_embedded=false` and
`closeout_same_route_proven=false` remain mandatory.

The index is separate from the central manifest and lifecycle overlay. It does
not index derived file `70`, pre-effect files `00/10/11`, mutable
`runtime-control/*`, or the source snapshot. The historical Git object ID is a
reference; object presence is not evaluated by the pure CLI. The recorded
target state was process-private memory, so surviving effect state is not
re-observed.

The committed static graph contains only the direct CLI, the pure index and
artifact-set modules, canonicalization/hash helpers, and the exact
`node:crypto`, `node:fs`, and `node:path` built-ins. `NODE_OPTIONS`, custom
loaders/preloads, interpreter/PATH substitution, same-user source mutation,
parent-process behavior, and stdout redirection destinations remain outside
coverage. `existing_crossing_output_mutated=false` describes the verifier
itself; it cannot prove where its parent aimed file descriptor 1.
`--require-closed` is an unsupported lifecycle-upgrade request and refuses.

### `zlar-consequence-path-coverage-dependency-map-v0`

Build one verification-only source-marker catalogue and dependency projection
for the exact local-fixture `records.write` lifecycle dependencies:

```bash
bin/zlar-consequence-path-coverage-dependency-map-v0 \
  --repo-root <ZLAR_Repo> \
  --base-map <consequence-lifecycle-map-v0.json> \
  --overlay <replacement-lifecycle-overlay-v0.json> \
  --index <post-effect-route-evidence-index-v0.json> \
  --require-base-map-file-sha <sha256> \
  --require-base-map-sha <sha256> \
  --require-overlay-file-sha <sha256> \
  --require-overlay-sha <sha256> \
  --require-index-file-sha <sha256> \
  --require-index-body-sha <sha256> \
  --require-historical-crossing-source-commit <git-sha1> \
  --require-dependency-map-source-commit <git-sha1> \
  --require-source-inventory-sha <sha256> \
  --json
```

This v0 command and its required markers describe a pinned prior
source-checkpoint observation. Stage 3 intentionally changed those positive E2
markers, so the v0 map is no longer the current checked-out-source
disposition. Current direct E2 request/factory disposition is recorded
additively in `spec/e2-direct-request-factory-source-retirement-v0.json`; the
prior map remains unchanged historical source evidence.

The map first records the additive overlay-consumer decision as
`no_go_no_new_lifecycle_evidence`. The post-effect index reinforces existing
evidence but changes no open lifecycle obligation and permits no new claim, so
the command creates no overlay consumer.

The topology keeps surface role separate from effect-node relationship. One
wrapper can depend on an effect node that is physically distinct from the
selected v2 effect. A verifier can name `records.write` without being an
effect-capable route. This prevents wrappers, proof generators, and evidence
views from being counted as independent consequence exits.

The pinned prior source-bound v0 slice projected five mutation-node candidates from
required markers; it does not prove executable reachability or effect
capability:

- a derived-or-caller-selected adapter ledger append;
- a file-backed service-state append;
- the legacy v1 process-private runtime append;
- the selected replacement v2 process-private runtime append;
- an active-persistent proof-target marker write.

That prior slice separately recorded the five named minimum surfaces (the selected entrypoint
plus four named candidates), both direct service modes, direct adapter and
legacy-runtime modes,
the internal replacement-v2 child, active-persistent and legacy-terminal
wrappers, proof/conformance/preflight generators, the local proof pack, and
the broad `zlar` command dispatcher. Known source candidates without governed
coverage remain `observed_uncovered` or unclassified. Generation and
verification modes are separated where one CLI exposes both. A non-exhaustive
list of known static wrappers outside the pinned v0 catalogue remains visible
as `known_static_wrappers_not_catalogued`. A fresh-effect-gate
marker is not proof of call order or current refusal behavior. Observation is
not authority. The command accepts no outside-coverage authority artifact and
fixes `authorized_outside_coverage_count=0`.

The source inventory is an exact caller-pinned set of read-only file bytes and
required source markers. The pure graph does not invoke Git and therefore says
`dependency_map_source_commit_object_presence_evaluated=false` and
`loaded_source_matches_commit_evaluated=false`. Source-marker validation is not
an AST, control-flow, effect-capability, route-existence, or
dynamic-reachability proof.

`domain_inventory_complete`, `equivalent_route_closure`, and
`lifecycle_closed` remain false. `--require-closed`,
`--require-domain-inventory-complete`, and
`--require-equivalent-route-closure` refuse. The CLI has no output-file option,
performs no filesystem, artifact, or repository write, emits stdout only, and
is not wired through the broad dispatcher.

Direct imports, caller-controlled legacy-v1 configuration and time, internal
v2 invocation, raw fixture-storage writes, generated entrypoints,
`NODE_OPTIONS`, loaders/preloads, interpreter/PATH substitution, same-user
source mutation, and shell/MCP/browser/app-control/filesystem/network routes
not bound to a named effect node remain outside coverage. Parent-process stdout
destinations are also outside coverage; stdout-only behavior does not prove
where file descriptor 1 was routed.

### `zlar-source-bound-static-reachability-delta-v0`

Validate one additive, version-specific exact-edge certificate over inert
source bytes without mutating the parent dependency map:

```bash
bin/zlar-source-bound-static-reachability-delta-v0 \
  --repo-root <ZLAR_Repo> \
  --parent-map <consequence-path-coverage-dependency-map-v0.json> \
  --require-parent-file-sha <sha256> \
  --require-parent-body-sha <sha256> \
  --require-analyzed-source-commit <git-sha1> \
  --require-source-inventory-sha <sha256> \
  --json
```

This v0 delta is likewise an exact prior source-checkpoint certificate, not the
current Stage 3 reachability disposition. Its parent and source identities stay
immutable; current removed/refused E2 edges and remaining unknown paths are
recorded in the additive Stage 3 overlay.

This is a source-bound certificate validator, not a general JavaScript control
flow engine. It requires exact full-file SHA-256 identities, caller-pinned Git
blob/mode metadata, exact source-span identities, and executable lexical code
anchors. Any byte drift refuses. Comments, strings, templates, and recognized
regular-expression contexts cannot satisfy code anchors. The lexical mask is
not a complete JavaScript regex parser, AST, or control-flow engine; edge
semantics remain a human-reviewed certificate over the exact pinned bytes. The
production module does not import, execute, or spawn any analyzed target; it does not invoke Git
or accept an output-file option. The CLI is intentionally not registered in
the analyzed `bin/zlar` dispatcher.

The v0 delta splits seven executable surfaces into eleven semantic modes. Three
modes contain source paths to existing parent mutation-node candidates: direct
legacy runtime-v1 and installed recognition generation lead to the existing E3
candidate in-process, while active-persistent lifecycle `run` contains green
and closeout-probe syntactic paths to the existing E5 proof-target candidate.
At that pinned checkpoint, closeout refusal behavior remained unproven. None becomes a proven effect
exit. The runtime-profile proof and installed-service proof child edges remain
unresolved because their `spawnSync` environments inherit `process.env`; the
profile-preflight and activation-preflight generation paths inherit that same
boundary. The active lifecycle E3 leg is unresolved for the same reason.

Activation-preflight `verify`, installed recognition `verify`, installed
service `verify`, and active lifecycle supplied-report mode resolve to verifier
sinks only. They remain verification candidates rather than proven
effect-absent routes because generation-capable ESM modules load before argv
branching and transitive import-time side-effect closure is open. Likewise,
observed freshness guards do not establish source-refusal dominance.

`runtime_reachability_proven`, `effect_capability_proven`,
`effect_occurrence_proven`, `current_refusal_behavior_proven`, authority-domain
membership, current authority, domain completeness, equivalent-route closure,
and lifecycle closure remain false. That pinned parent keeps its 24 catalogued
surfaces, six known static uncatalogued surfaces, 30 unresolved observations,
five mutation-node candidates, and `mapped_open` status. Output/report-file
variants are evidence sinks, not additional `records.write` exits.

Inherited environment state including `BASH_ENV`, exported shell functions,
`PATH`, `NODE_OPTIONS`, unqualified `node` and `/usr/bin/env node` interpreter selection, transitive import-time execution,
direct/custom imports, raw fixture-storage writes, generated entrypoints,
same-user source substitution, and non-inventoried shell/MCP/browser/app-control
routes remain side doors.

The focused repository test is deliberately a fail-closed workspace integration
test: it requires the exact caller-private sibling parent map and does not copy
that Draft evidence into repository source. A standalone checkout without that
parent cannot reproduce the exact-parent certificate and must not report a
pass.

### `zlar agent-passenger-lab`

Run the local fixture Agent Passenger Lab / Governed Crossing Test Harness:

```bash
bin/zlar agent-passenger-lab
bin/zlar agent-passenger-lab --json
bin/zlar agent-passenger-lab --json-out ./zlar-agent-passenger-lab-v1.json
```

The report emits `zlar-agent-passenger-lab-v1`. It models agent roles as
instrumented passengers and observes this crossing shape:
`proposal -> action_class -> route -> authority_topology -> receipt_request -> verifier_result -> effect_or_refusal`.

The report exposes action classes discovered, semantic disguises, human-proxy
pressure, authority-laundering attempts, duplicate refusal noise, and missing
route candidates. Those observations may inform coverage maps, tests, and
future claim-ceiling work only through normal evidence gates. They do not
create authority.

This command uses local fixture evidence only. It does not spawn live agents,
inspect private reasoning, surveil model thoughts, prove current-machine
governance, prove production governance, create external attestation, upgrade a
public claim, or claim all-surface or unrouted-surface coverage.

For the evidence model and claim boundary, see
[`docs/agent-passenger-lab.md`](agent-passenger-lab.md).

### `zlar coverage-evidence bash`

Assemble supplied, event-scoped evidence for one bash `PreToolUse -> zlar-gate`
lane. This command prints coverage-map input JSON to stdout. It does not live
probe, does not inspect live hooks or audit stores, and does not support
`--latest`; the caller must provide an explicit `--event-id`.

```bash
zlar coverage-evidence bash --input tests/fixtures/bash-gate-coverage-evidence-v1-input.json --event-id bash-fixture-event-001
zlar coverage-evidence bash --input tests/fixtures/bash-gate-coverage-evidence-v1-input.json --event-id bash-fixture-event-001 | zlar coverage --input - --require-governed
```

The input evidence must be supplied by the caller. A counted lane can become
governed only after `zlar coverage` confirms routing, heartbeat freshness,
policy currency, Worker Receipt capability, and downstream refusal evidence.

`worker_receipt_ref` is reference-only and cannot self-attest into
`receipt_capable=true`. To make the lane receipt-capable, supply a raw
`worker_receipt` object that validates and matches the supplied event id, audit
hash, policy version, and bash-gate surface evidence.

### `zlar coverage-evidence mcp`

Assemble supplied, event-scoped evidence for one MCP `tools/call -> mcp-gate`
lane. This command prints coverage-map input JSON to stdout. It does not live
probe, does not inspect live MCP configuration, hooks, or audit stores, and does
not support `--latest`; the caller must provide an explicit `--event-id`.

From the repo root, run the sanitized fixture:

```bash
bin/zlar coverage-evidence mcp --input tests/fixtures/mcp-gate-coverage-evidence-v1-input.json --event-id mcp-fixture-event-001
```

Pipe the assembled input into the coverage map:

```bash
bin/zlar coverage-evidence mcp --input tests/fixtures/mcp-gate-coverage-evidence-v1-input.json --event-id mcp-fixture-event-001 | bin/zlar coverage --input - --require-governed
```

The input evidence must be supplied by the caller. A counted MCP lane can become
governed only after `zlar coverage` confirms routing, heartbeat freshness,
policy currency, Worker Receipt capability, downstream refusal evidence, and no
direct or extra MCP bypass evidence.

`worker_receipt_ref` is reference-only and cannot self-attest into
`receipt_capable=true`. To make the lane receipt-capable, supply a raw
`worker_receipt` object that validates and matches the supplied event id, audit
hash, policy version, and MCP-gate surface evidence.

This command is not live MCP coverage, all-MCP governance, or current-machine
governance proof. It is a supplied-evidence assembly path for one event.

### `zlar downstream-recognition`

Evaluate a supplied signed v1 receipt against a supplied downstream recognition
rule. This command prints a `downstream-recognition-rule-v1` decision JSON to
stdout. It does not live probe, does not inspect runtime state, and does not
choose `--latest`.

From the repo root, run the sanitized fixture:

```bash
bin/zlar downstream-recognition --input tests/fixtures/downstream-recognition-v1-input.json --require-refused
```

The fixture contains a valid signed receipt from a known issuer, but the receipt
policy version is outside the supplied rule's accepted policy set. The expected
decision is `refuse` with reason `policy_not_recognized`.

Use stdin instead of a file:

```bash
bin/zlar downstream-recognition --input - --require-refused < tests/fixtures/downstream-recognition-v1-input.json
```

The output can be supplied to the coverage map as
`downstream_refusal.recognition_decision`. A refused recognition decision can
satisfy downstream refusal evidence only when it matches the counted lane's
audit event id and detail hash. An accepted recognition decision does not prove
refusal.

Run the local hermetic downstream-effect proof:

```bash
bin/zlar downstream-refusal-proof
bin/zlar downstream-refusal-proof --json
```

That proof creates ephemeral issuer keys, accepts one matching signed receipt,
writes exactly one bounded fake effect marker, and proves missing, tampered,
unknown-issuer, retired-issuer, non-boarding, wrong-policy, wrong-domain,
wrong-tool, wrong-audit-event, wrong-detail, and stale receipts do not board.
It is local fixture evidence only.

Developer test harness:

```bash
node tests/test-downstream-recognition-refusal.mjs
```

These commands are not live downstream integration, not production deployment,
not external attestation, not sovereign recognition, and not coverage of
unrouted surfaces.

### `zlar human-authorization-proof`

Run a local hermetic simulated-human authorization proof. This command creates
ephemeral issuer keys and a fixture ask-class `records.write` action. The
pending action without a receipt refuses, the simulated human approval emits a
signed receipt with `authorizer=human:fixture-operator` and boards, and the
simulated human denial emits a non-boarding receipt and refuses.

```bash
bin/zlar human-authorization-proof
bin/zlar human-authorization-proof --json
```

This proof uses a simulated human decision fixture. It does not use Telegram,
inspect live approval channels, inspect runtime state, prove live operator
approval delivery, prove production deployment, prove external attestation,
prove sovereign recognition, or prove coverage of unrouted surfaces.

### `zlar approval-transport-proof`

Run a local hermetic channel-neutral approval transport proof. This command
models approval delivery as a replaceable transport boundary. The reference
fixture transport is healthy, the Telegram adapter is explicitly not required
for the fixture path, and boarding still requires a signed human decision
receipt.

```bash
bin/zlar approval-transport-proof
bin/zlar approval-transport-proof --json
```

The proof shows an unavailable transport fails closed, a delivered ask without
a human decision receipt still refuses, and a delivered ask with a signed human
decision receipt boards through downstream recognition.

This proof uses local fixture transports only. It does not send Telegram,
Slack, Teams, email, web, or hardware approval messages; inspect live
approval-channel configuration; prove a production transport is configured,
healthy, or secure; prove production deployment; prove external attestation;
prove sovereign recognition; or prove coverage of unrouted surfaces.

### `zlar verifier-env`

Check the local verifier workstation prerequisites used by the external
verifier packet: Git, Bash, Node.js 18+, `jq`, OpenSSL, and exact OpenSSL
Ed25519 `genpkey` support.

```bash
bin/zlar verifier-env
bin/zlar verifier-env --json
bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json
```

`--json` emits a redacted machine-readable `zlar-verifier-env-v0` report.
`--json-out <file>` writes the same report to a new file while preserving the
human-readable terminal output. The command refuses to overwrite an existing
JSON output file and does not print the local output path.

The report records environment readiness or prerequisite failure only. It is
private by default and does not include raw environment variables, raw `PATH`,
home/temp paths, credentials, private-key material, emails, Telegram
identifiers, or verifier identity. It is not a verifier pass, not a ZLAR proof
run, not external attestation, not key custody, not live issuer-status proof,
not production authority, not current-machine governance, and not coverage of
unrouted surfaces.

### `zlar verifier-kit-reproducibility`

Build the verifier kit twice from the same source tree with one temporary test
publisher key and require the distributable tarball SHA-256, manifest SHA-256,
and manifest-signature SHA-256 to match across both builds.

```bash
bin/zlar verifier-kit-reproducibility
bin/zlar verifier-kit-reproducibility --json
bin/zlar verifier-kit-reproducibility --json-out zlar-verifier-kit-reproducibility-v1.json
```

The JSON report is `zlar-verifier-kit-reproducibility-v1`. It includes the
temporary publisher `kid`, the two build hashes, public artifact hash entries
for `dist/zlar-verifier-kit-v0.1.0.tar.gz`, the `.sha256` sidecar,
`MANIFEST.json`, and `MANIFEST.sig`, and a claim boundary. The command refuses
to overwrite an existing JSON output file.

This is source-build reproducibility evidence for identical inputs and the same
publisher key. It regenerates ignored `dist/` verifier-kit output. It does not
prove production publisher key custody, production signing identity, public
release publication, external attestation, live trust-registry state,
revocation truth, enterprise readiness, or v3.4.0 readiness.

### `zlar verifier-kit-release-assets-live-read`

Read an explicitly authorized release by explicit tag, download its release
assets when the operator has access, and emit byte-bound release-asset evidence for
`zlar verifier-kit-public-distribution`.

```bash
bin/zlar verifier-kit-release-assets-live-read \
  --release-tag v3.4.31 \
  --download-dir zlar-verifier-kit-release-assets \
  --json-out zlar-verifier-kit-release-assets-live-v1.json
```

The JSON report is `zlar-verifier-kit-release-assets-live-v1`. It uses the
`github-release-assets-json-live-read` evidence model, records the release URL,
draft state, asset metadata, downloaded SHA-256 values, and whether the
required verifier-kit release assets were present and downloaded. With
`--download-dir`, it also saves the downloaded asset bytes under their release
asset names so the public-distribution validator can recompute local artifact
hashes after extraction. The command uses an explicit release tag only; it does
not use `--latest`.

The command does not upload assets, mutate release state, grant source access,
create external attestation, prove non-operator review, prove production
publisher key custody, prove production signing identity, prove enterprise
readiness, or prove sovereign recognition.

### `zlar verifier-kit-public-distribution`

Audit whether a release has the verifier-kit asset shape needed for the stated
distribution posture, using supplied release-asset JSON plus the
`zlar-verifier-kit-reproducibility-v1` report.

```bash
bin/zlar verifier-kit-public-distribution \
  --release-tag v3.3.109 \
  --release-assets-json zlar-verifier-kit-release-assets-v1.json \
  --reproducibility zlar-verifier-kit-reproducibility-v1.json \
  --asset-dir . \
  --json-out zlar-verifier-kit-public-distribution-v1.json
```

The required public release assets are the verifier-kit tarball, the tarball
SHA-256 sidecar, and the verifier-kit reproducibility report. Publication
evidence comes from the supplied release-asset JSON, not from mutating the
reproducibility report. Live GitHub release reads should be shaped with
`evidence_model: "github-release-assets-json-live-read"`, a release URL that
names the target tag, explicit `isDraft: false`, required assets with
`state: "uploaded"`, positive sizes, and either GitHub
`digest: "sha256:<hash>"` fields or downloaded `downloaded_sha256` values.
For ZLAR public-distribution readiness, that live-read evidence must also name
the authorized repository or static public artifact source, and the release URL
plus required asset download URLs must name that same source and target tag.
For ZLAR release-asset evidence, the authorized repository binding is
repository `ZLAR-AI/ZLAR`; that binding identifies historical or authorized
release-asset provenance and does not restore any public clone, public source
inspection, or open-source claim for the current private core.
For true public static artifact distribution, the supplied evidence may instead
use `evidence_model: "static-public-artifact-source-live-read"`, name
`public_artifact_source: "zlar.ai"`, set `anonymous_access_verified: true`,
and include HTTPS asset URLs under that public source and exact target tag.
This path is for public verifier-kit bytes, not public source visibility.
`zlar verifier-kit-release-assets-live-read` emits that live-read shape from an
explicitly authorized release without mutating it.
When `--asset-dir` is supplied, the command recomputes local artifact hashes
for the tarball, sidecar, `MANIFEST.json`, and `MANIFEST.sig` and checks them
against the reproducibility report. `--require-public` exits non-zero unless
all required assets are present, live release-asset evidence supports public
publication, public asset byte hashes bind to the reproducibility evidence, and
local hashes match.

The JSON report is `zlar-verifier-kit-public-distribution-v1`. It can report a
successful audit while still saying `ready_for_public_distribution_claim=false`;
that is the point. When live release-asset evidence, required assets, and
reproducibility hashes line up, it may report
`ready_for_public_distribution_claim=true` while the reproducibility report
still says `public_release_publication=false`. That separation is deliberate:
reproducibility names the expected bytes; live release-asset evidence plus
GitHub digests, downloaded SHA-256s, or static public artifact SHA-256 evidence
proves those expected public asset bytes are present on the authorized public
artifact source. Incomplete live evidence remains bounded `NOT_READY` evidence
unless it is used to make a public-ready claim. The
command does not publish release assets, prove production publisher key
custody, prove production signing identity, create external attestation, prove
non-operator review, prove live trust-registry state, revocation truth,
production downstream recognition, enterprise readiness, or sovereign
recognition.

### `zlar private-verifier-result`

Validate a private-by-default verifier result envelope for internal custody.
The command checks the release tag, exact commit SHA, required release-forward
artifact hashes, privacy flags, and claim-boundary flags.

```bash
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json --evidence-dir release-forward-result-dir
bin/zlar private-verifier-result verify --input - --json < zlar-private-verifier-result-v1.json
bin/zlar private-verifier-result verify --sample --json
```

The JSON input is `zlar-private-verifier-result-v1`. The committed sample at
`tests/fixtures/private-verifier-result-v1.json` is a schema fixture only, not
a real verifier reply.

The validator rejects moving-target evidence, public attribution approval,
public external-attestation approval, obvious identity/contact leakage, obvious
secret strings, unapproved verifier labels or relationship descriptions,
unapproved result-summary prose, missing release-forward artifact hashes, and
claims that the private result proves production authority, enterprise
readiness, current-machine governance, live MCP coverage, key custody,
revocation truth, v3.4.0 readiness, or unrouted-surface coverage.
`private-verifier-reply` envelopes must use a pseudonymous label shaped like
`private-non-operator-verifier-<release>-<index>` and the approved private
relationship boundary. Verification is read-only and does not publish the
verifier, contact anyone, or turn private intake into public external
attestation.

### `zlar private-verifier-readiness`

Build or verify a local private verifier-readiness packet for a supplied
active-persistent lifecycle evidence directory. This is the no-send preparation
object before any named external verifier contact.

```bash
bin/zlar private-verifier-readiness build \
  --evidence-dir active-persistent-current-machine-lifecycle-20260709T034858Z \
  --commit <verifier-source-commit-sha> \
  --evidence-source-commit f6e54059193254eeb310936a6bba925f541c8f29 \
  --branch local-governed-destination-boarding-proof \
  --output-dir private-verifier-readiness-20260709T120000Z

bin/zlar private-verifier-readiness verify \
  --input private-verifier-readiness-20260709T120000Z/zlar-private-verifier-readiness-packet-v1.json \
  --evidence-dir active-persistent-current-machine-lifecycle-20260709T034858Z \
  --require-commit <verifier-source-commit-sha> \
  --require-evidence-source-commit f6e54059193254eeb310936a6bba925f541c8f29 \
  --require-recomputed-evidence \
  --json
```

The packet type is `zlar-private-verifier-readiness-packet-v1`. It binds the
exact verifier source commit, evidence source commit, branch, private evidence
directory label, evidence artifact hashes, artifact-set SHA-256, lifecycle
source report hashes, North Star readiness non-scoring lifecycle intake,
expected pass/fail criteria, side doors, non-claims, and the later authority
required for actual external contact.

The verifier recomputes the artifact-set hash when `--evidence-dir` is supplied,
rebuilds the active-persistent lifecycle report from the four source reports,
requires North Star readiness to keep the lifecycle historical/local/supplied
and non-scoring, and refuses moving-target command templates, private paths,
email/contact residue, credential-shaped strings, public external attestation,
production authority, enterprise readiness, side-door closure, all-surface
governance, or general current-machine governance claims.

This command does not send a verifier request, create public or private
attestation, prove non-operator review, publish source, change GitHub access,
tag, release, update the website, deploy production, touch secrets, or install
configuration.

### `zlar public-artifact-verifier-result`

Validate a redacted outside-machine public-artifact verifier reply envelope.
This command is for public `zlar.ai` artifact checks such as the `v3.4.59`
verifier-kit request. It is intentionally not a private-source verifier, not a
GitHub-access verifier, and not an external-attestation creator.

```bash
bin/zlar public-artifact-verifier-result verify --input zlar-public-artifact-verifier-result-v1.json
bin/zlar public-artifact-verifier-result verify --input - --json < zlar-public-artifact-verifier-result-v1.json
bin/zlar public-artifact-verifier-result verify --sample --json
bin/zlar public-artifact-verifier-result from-transcript --input terminal-output.txt --json \
  > zlar-public-artifact-verifier-result-v1.json
```

The JSON input is `zlar-public-artifact-verifier-result-v1`. It must bind to:

- version `v3.4.59`;
- `https://zlar.ai/release.json`;
- `https://zlar.ai/verifier-kit/v3.4.59/`;
- source access path `public_release_assets_only`;
- pseudonymous label `public-artifact-outside-machine-review-v3459-001`.

The validator requires the public release metadata, verifier-kit tarball,
tarball SHA-256, sidecar check, reproducibility JSON, proof-pack manifest, and
proof-pack `SHA256SUMS` to be reported present. It also requires source access,
GitHub access, credentials, and deploy key use to remain false. The output may
record `public_artifact_hash_consistency_signal=true` while keeping
`public_external_attestation=false`, `non_operator_review_proven=false`,
`private_source_review=false`, `production_authority=false`,
`enterprise_readiness=false`, `current_machine_governance=false`, and
`all_surface_governance=false`.

This command does not fetch public artifacts, send email, contact a verifier,
grant source access, publish a claim, update public metadata, or create public
external attestation.

The committed redacted `v3.4.59` intake fixture lives at
`tests/fixtures/public-artifact-verifier-result-v3459-redacted-v1.json`.
It records only the bounded public-artifact reachability/hash-consistency
signal and keeps the private mailbox source, public attribution, and public
external attestation outside the committed claim.

`from-transcript` is intentionally conservative. It extracts only the public
tarball SHA-256 and sidecar `OK` evidence from a terminal transcript and
requires the known public artifact filenames to appear. It refuses checksum
failure text, warning text, private-key material, token-shaped strings, and
assignment-shaped credential residue. It does not preserve the verifier's local
paths or turn transcript prose into an attestation.

### `zlar private-verifier-zip-result`

Validate a private personally connected outside-machine ZIP-snapshot verifier
result envelope for internal custody. This command is for practical browser-ZIP
fallback evidence from an exact commit snapshot. It is intentionally separate
from `zlar private-verifier-result`, which is release-forward oriented.

```bash
bin/zlar private-verifier-zip-result verify --input zlar-private-verifier-zip-result-v1.json
bin/zlar private-verifier-zip-result verify --input zlar-private-verifier-zip-result-v1.json --evidence-dir returned-artifact-intake --require-recomputed-evidence
bin/zlar private-verifier-zip-result verify --input - --json < zlar-private-verifier-zip-result-v1.json
bin/zlar private-verifier-zip-result verify --sample --json
```

The JSON input is `zlar-private-verifier-zip-result-v1`. The committed sample
at `tests/fixtures/private-verifier-zip-result-v1.json` is schema-only and does
not name a real verifier. Verifier identity stays private unless separate
public disclosure is approved.

With `--evidence-dir`, the validator recomputes the returned-results ZIP
SHA-256, checks returned `SHA256SUMS.txt` entries against unpacked files,
requires the seven known verifier `.exit` files to be `0`, accepts only the
known `SHA256SUMS.err` directory warning, validates `source-bridge-window`,
`proof-smoke-verify`, `north-star-readiness`, and `public-privacy` outputs, and
requires `north-star-readiness` to preserve `NOT_READY_FOR_V3_4_0`.

This command may support the private claim:

```text
private personally connected outside-machine verifier signal with locally
reviewed returned-result custody
```

It does not prove public external attestation, independent review,
arm's-length review, git clone source access, source-transport credentials,
tag/release proof, website/public alignment, production trust, current-machine
governance, all-surface governance, North Star readiness, side-door closure, or
absolute human intention.

For `v3.3.109+` targets, the required release-forward artifact hashes include
`ZLAR/zlar-verifier-kit-release-assets-v1.json` and
`ZLAR/zlar-verifier-kit-public-distribution-v1.json`. Private intake must
preserve those public-distribution posture artifacts before validation can
pass.
For `v3.4.9+` targets, release-forward evidence also preserves
`ZLAR/zlar-product-proof-path-v1.json`, the bounded fresh local Product Proof
Path report. It is local fixture evidence only, not live approval,
current-machine governance, production downstream recognition, external
attestation, all-MCP governance, or unrouted-surface coverage. For `v3.4.10+`
readiness runs, `north-star-readiness` consumes that report directly and
records `product_proof_path_verified=true` only when the report is `PASS`, all
acceptance gates are true, all forbidden-claim flags are false, the proof-pack
artifact is verified, live probing is false, and private operator state is not
required.
For `v3.4.11+` targets, release-forward evidence also preserves
`ZLAR/zlar-installed-runtime-profile-service-proof-v1.json`,
`ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json`, and
`ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`.
These prove only local disposable child-service refusal from a verified
installed-runtime-profile preflight sample. They do not prove persistent
install, activation, live runtime service, current-machine governance,
production downstream recognition, enterprise readiness, or external
attestation. For `v3.4.18+` targets, the service-proof artifact verification
must also preserve the canonical refusal taxonomy SHA-256 so the artifact
verification binds exact case ids, reason codes, and before-mutation facts, not
just the count of refused cases. For `v3.4.19+` targets, release-forward
readiness also preserves the installed-runtime-profile recognition-contract
SHA-256 across preflight, service proof, service-proof artifact verification,
terminal chain, and terminal-chain artifact verification. For `v3.4.15+`
targets, release-forward
evidence also preserves
`ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json`,
`ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json`, and
`ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`.
These prove only the launcher-owned disposable chain from explicit plan/profile
through generated installed-root preflight, selected service proof, and generated
service-proof artifact verification. They do not prove persistent install,
activation, current-machine governance, production downstream recognition,
enterprise readiness, external attestation, sovereign recognition, or unrouted
records-path coverage.
For `v3.4.33+` targets, release-forward evidence also presents the existing
local issuer-status proof as first-class `issuer_status_evidence` in
`DRY-RUN-MANIFEST.json` and `Issuer Status Evidence` in `DRY-RUN-RESULT.md`.
That section preserves the fixture verdict, active-issuer boarding,
retired/compromised/missing-status/unknown/missing-key issuer refusals, no-live
boundary, and false live/custody/revocation/production-registry/downstream
claim flags. It does not prove live issuer status, key custody, revocation
truth, production trust-registry state, production downstream recognition,
non-operator review, or public external attestation.
For `v3.4.35+` targets, release-forward evidence also presents the existing
trusted-issuer registry recognition as first-class
`trusted_issuer_registry_recognition_evidence` in `DRY-RUN-MANIFEST.json` and
`Trusted Issuer Registry Recognition Evidence` in `DRY-RUN-RESULT.md`. That
section binds the recognized fixture JSON and malformed-registry fail-closed
artifacts, records `registry_type=trusted-receipt-issuers-v1`,
`registry_evidence_model=bundled-local-fixture`, `live_probing=false`,
`issuer_status=active`, and `signature_valid=true`, and keeps live registry,
live issuer status, key custody, revocation truth, production trust-registry,
production downstream recognition, production authority, sovereign recognition,
non-operator review, and public external attestation false.
For `v3.4.53+` targets,
`tools/release-forward-verifier-dry-run.sh --trusted-issuer-completion-proof <file>`
may copy a supplied
`zlar-trusted-receipt-issuer-completion-proof-v1.json` into the fresh checkout,
verify it to
`zlar-trusted-receipt-issuer-completion-proof-verification-v1.json`, record
both artifact SHA-256s in the release-forward manifest without adding them to
the core private-verifier artifact set, expose
`trusted_receipt_issuer_completion_evidence` in `DRY-RUN-MANIFEST.json`, print
the same bounded fields in `DRY-RUN-RESULT.md`, and let
`north-star-readiness --evidence-dir .` consume the supplied proof. This is
optional supplied private-core completion evidence, not public by default, not
source publication, not production issuer or hardware custody, not live issuer
status or revocation truth, not production downstream recognition, not public
external attestation, not enterprise readiness, not real records protection, not
side-door closure, not sovereign recognition, and not absolute human intention
or legal consent. The proof's selected surface may be
`protected-records.private-operator.records-terminal.records.write` while the
readiness report's `selected_terminal` remains
`protected-records.runtime.profile-installation.records.write`.
For `v3.4.39+` targets, release-forward evidence also presents the existing
terminal-chain trusted-registry refusal summary inside
`terminal_chain_refusal_evidence` and in `DRY-RUN-RESULT.md`: case count,
exact case IDs/reason codes, `all_refused=true`, matching terminal-chain and
artifact-verification refusal hashes, and
`all_trusted_issuer_registry_recognition_refusals_preserved=true`. This is
summary preservation only, not live registry, key custody, revocation, or
production-recognition evidence.
For `v3.4.41+` targets, `DRY-RUN-MANIFEST.json` also includes
`release_forward_report_contract`, a compact machine-readable summary of the
existing release-forward dry-run report contract. The object is derived only
from preserved local dry-run artifacts and same-manifest evidence.
`DRY-RUN-RESULT.md` renders it as
`manifest.release_forward_report_contract.*` lines for human review. This is
not a new verifier result, non-operator review, public external attestation,
live registry state, key custody, revocation truth, current-machine
governance, production downstream recognition, production authority,
enterprise readiness, sovereign recognition, or unrouted-surface coverage.
For `v3.4.42+` targets, that object also binds
`ZLAR/zlar-product-proof-path-v1.json` by source path/SHA-256 and compact
Product Proof Path fields: PASS/evidence model, simulated human authorization,
receipt-verifier boundary, North Star consumption, false forbidden claims, and
known unrouted-records noncoverage visibility.
For `v3.4.45+` targets, that Product Proof Path contract also carries the
public-safe terminal-chain boundary consumed by Product Proof Path: terminal
artifact verification, binding/refusal hashes, exact trusted-registry refusal
IDs/reasons, omitted public-key material, omitted receipt envelope, false
external attestation, and false current-machine governance.
Current local post-v3.4.50 proof-hardening also preserves the terminal-chain
binding's own local `RECOGNIZED` verdict, issuer status, signature validity,
local registry evaluation facts, and contract hashes in Product Proof Path and
North Star readiness summaries.
For future `v3.4.51+` local targets, release-forward/private-intake contracts
also require those trusted-registry verdict/evaluation facts and the
downstream-refusal marker boundary in both the Product Proof Path contract and
North Star mirror, including exact downstream refusal reasons and
all-refusals-unboarded flags, while `v3.4.50` omits those new fields. Private
verifier text output and release-forward `Private Result Verification Evidence`
also print
the trusted-registry requirement, Product Proof Path preservation, North Star
preservation, `RECOGNIZED` verdict, signature-valid fields, downstream-refusal
boundary requirement, marker delta, final marker count, refusal count, and
zero-refusal-marker-delta status so the private-intake content binding can be
inspected without parsing raw JSON.
For `v3.4.46+` targets, it also carries exact grouped recognition-refusal case
IDs from that boundary: `group_count=3`, `case_count=18`, the grouped case-ID
map, and `preserved=true`.
For `v3.4.47+`, private result verification with `--evidence-dir` also validates
that Product Proof Path content contract from `DRY-RUN-MANIFEST.json`: the
Product Proof Path terminal-chain boundary and the North Star mirror must carry
the same 3 groups, 18 case IDs, and `preserved=true` state before the private
intake verification can pass.
For `v3.4.48+`, the same private intake check also validates the Product Proof
Path deployment-profile authority bridge and its North Star mirror.
For `v3.4.49+`, it also validates the exact five-case deployment-profile
authority refusal contract and the before-service-proof boundary in both
Product Proof Path and North Star mirrors.
For `v3.4.46+` evidence-dir verification, the same private intake check also
exact-family validates the same-manifest
`terminal_chain_refusal_evidence` trusted-registry recognition refusal fields:
the `v3.4.39` minimum target, exact two refusal case IDs/reason codes, matching
terminal-chain and artifact-verification refusal hashes, and
`all_trusted_issuer_registry_recognition_refusals_preserved=true`. This is a
closed evidence family, not a whole-object schema freeze; unrelated future
fields on the root `terminal_chain_refusal_evidence` object remain evolvable.
For `v3.4.50+`, release-forward evidence also validates the terminal-chain,
proof-smoke, and North Star mirror of that same five-case refusal contract.
The private intake check exact-family validates the same-manifest
deployment-profile authority-refusal mirror at this boundary, including exact
five refusal case IDs, before-service-proof and before-mutation refusal flags,
service-proof-not-started, and false current-machine/production/enterprise/
external-attestation/sovereign/unrouted claim fields.
For future `v3.4.51+` local targets, it also fails closed if Product Proof Path
terminal-chain trusted-registry verdict/evaluation facts or the
downstream-refusal marker boundary are missing or drift in either the manifest
Product Proof Path contract or the North Star mirror.

When `--evidence-dir <dir>` is supplied, the validator also recomputes each
declared `evidence.artifact_hashes[]` SHA-256 against the matching safe
relative file under that directory. Missing files, symlinks, directories, and
hash mismatches fail closed. For `v3.4.46+` targets, the validator also fails
closed if the already hash-checked `DRY-RUN-MANIFEST.json` drops or mutates the
Product Proof Path terminal-chain grouped refusal case-ID contract. Error
output names only the relative artifact path,
not the operator's local evidence directory.
For `v3.4.48+` targets, it also fails closed if the Product Proof Path
deployment-profile authority bridge weakens explicit profile SHA binding,
verified preflight, one recognized mutation, 18/18 zero-mutation refusals,
authority-material refusal, or false current-machine/production claim flags.
For `v3.4.49+` targets, it also fails closed if the bridge drops, changes, or
starts service proof for the stale profile artifact, profile mismatch,
`--latest`, or request-stream authority-material refusal cases.
For `v3.4.50+` targets, it also fails closed if terminal-chain evidence,
proof-smoke, or North Star readiness drops or mutates the same five-case mirror.
For future `v3.4.51+` local targets, it also fails closed if the Product Proof
Path terminal-chain trusted-registry `RECOGNIZED` verdict, active issuer,
signature-valid fact, local registry rule evaluation facts, or contract hashes
are missing or drift in the manifest terminal-chain boundary or North Star
mirror, or if the downstream-refusal marker boundary loses the recognized
marker delta, final marker count, exact refusal count/reasons, unboarded
refusals, or zero refusal marker deltas. Text verification output prints
`terminal_chain_trusted_registry_verdict_required_for_target`,
`product_proof_path_terminal_chain_trusted_registry_verdict_preserved`,
`north_star_terminal_chain_trusted_registry_verdict_preserved`,
`terminal_chain_trusted_registry_recognition_verdict`, and
`terminal_chain_trusted_registry_signature_valid`, plus
`downstream_refusal_boundary_required_for_target`,
`product_proof_path_downstream_refusal_boundary_preserved`,
`north_star_downstream_refusal_boundary_preserved`,
`downstream_refusal_recognized_marker_count_delta`,
`downstream_refusal_final_marker_count`, `downstream_refusal_case_count`, and
`downstream_refusal_all_refusals_unboarded`, `downstream_refusal_reasons`,
`north_star_downstream_refusal_all_refusals_unboarded`,
`north_star_downstream_refusal_reasons`, and
`downstream_refusal_marker_count_deltas_zero`.

### `zlar issuer-status-proof`

Run a local hermetic issuer status proof. This command creates ephemeral issuer
keys and one fixture downstream recognition rule. The rule accepts an active
issuer and refuses a retired issuer, a compromised issuer, a missing-status
issuer, an unknown issuer, and a known active issuer with no public key before
boarding.

```bash
bin/zlar issuer-status-proof
bin/zlar issuer-status-proof --json
```

This proof is local fixture evidence only. It does not inspect live trust
registries, use production signing keys, prove key custody, prove rotation or
revocation operations, prove compromise response, prove production deployment,
prove external attestation, prove sovereign recognition, or prove coverage of
unrouted surfaces.

### `zlar protected-records-proof`

Fresh generation is permanently retired in current source. Every invocation,
including `--help` and `--json`, fixed-refuses before input handling as:

```text
e1_positive_terminal_proof_generation_retired
```

The positive generator body, key/signing machinery, scratch writes, and E1
adapter call were removed. Historical report constants, schemas, structural
validators, privacy guards, and formatters remain for exact committed
local-proof-pack and proof-smoke verification. They do not generate a report,
authenticate current authority, or verify a fresh effect. The direct
`protected-records-write` route is now separately source-retired and documented
below. Historical command strings remain artifact content only.

### `zlar protected-records-write`

This is a retired current-source surface. The main dispatcher no longer routes
the command. The retained standalone wrapper and exported factory fixed-refuse
before argument, stdin, receipt, environment-authority, or filesystem-target
handling as:

```text
e1_direct_adapter_factory_source_retired
```

The positive filesystem, recognition, receipt-consumption, and ledger-append
body was removed. Historical result constants and plain-data structural/privacy
validators remain in `lib/protected-records-adapter-verification.mjs`; they do
not authenticate current authority or verify a fresh effect. Future installer
planning and copy filters omit the retired wrapper/module. Existing installed
files were not inspected or removed in this work. Future accepted repair,
upgrade, and reinstall source plans exact cleanup of the stale E1 wrapper/module
and refuses an unexpected leaf type or symlink/non-directory install-root,
`bin`, or `lib` parent before installer writes. The shell sequence is not
concurrency-atomic; same-user parent/leaf substitution remains open. Old,
copied, loaded, dynamic, raw-write, and E4 routes remain open, so E1
elimination, installed-copy retirement, runtime unreachability, and side-door
closure remain false.

### `zlar protected-records-adapter-conformance`

Fresh generation is permanently retired in current source. Every invocation,
including `--help` and `--json`, fixed-refuses before input handling as:

```text
e1_positive_adapter_conformance_generation_retired
```

The positive generator body, key/signing machinery, scratch writes, child
processes, and E1 adapter calls were removed. Historical schemas, validators,
privacy guards, and formatters remain only for exact committed artifact
verification. The direct adapter is now separately source-retired. Neither
source retirement establishes installed-copy retirement, E1 elimination,
runtime unreachability, or side-door closure.

### Retired `protected-records-service-request` source surface

Current source no longer exposes this command through `bin/zlar`. The retained
standalone wrapper and exported `applyProtectedRecordsServiceRequest` factory
fixed-refuse as `e2_direct_request_factory_source_retired` before reading
arguments, config, stdin, environment authority, or filesystem targets. The
positive request/factory body was removed.

Historical result constants and plain-data structural/privacy validators now
live in `lib/protected-records-service-verification.mjs`. They preserve pinned
artifact interpretation only: they do not authenticate callers, verify a fresh
effect, prove authority, or make hostile objects safe to inspect.

The future installer plan omits the retired standalone wrapper. The actual
copy filters omit both that wrapper and the retired factory module. Future
accepted repair, upgrade, and reinstall source plans exact cleanup of both
stale paths and refuses an unexpected leaf type or unsafe parent before
installer writes. The shell validation/delete sequence requires a quiescent
filesystem and does not close same-user concurrent substitution. No installer
was run and no current installation was inspected, so installed-copy retirement,
runtime unreachability, E2 elimination, and side-door closure remain false.
Historical profile/artifact command strings remain unchanged evidence, not
current executable instructions.

### `zlar protected-records-service-proof`

Fresh downstream-service proof generation is permanently retired:

```bash
bin/zlar protected-records-service-proof
```

The CLI returns
`e2_positive_service_proof_generation_retired` without importing the
historical generator, generating keys, signing receipts, creating scratch
state, starting a child process, or invoking E2. The exact pre-retirement
service-proof report schema remains only for verification of the pinned
historical local-proof-pack artifact. The direct E2 request/factory retirement
is recorded separately and does not retire old installed, copied, historical,
or mutated source.

### `zlar protected-records-service-preflight`

Verify an exact historical protected-records service-preflight artifact:

```bash
bin/zlar protected-records-service-preflight verify --input ./service-profile-preflight-artifact.json
bin/zlar protected-records-service-preflight verify --sample
```

Any current generation form returns
`e2_positive_service_preflight_generation_retired` before reading a profile
or artifact-output path. `verify --input <file|->` and `verify --sample`
recompute canonical artifact integrity and validate embedded historical
preflight boundaries without rerunning E2. Verification does not establish
current authority, source freshness, fresh effect, active deployment,
current-machine governance, production service evidence, external
attestation, or closure of direct filesystem writes.

### `zlar protected-records-runtime-profile-preflight`

Source-checkpoint posture: the source-recorded exhausted-status guard precedes
nested runtime proof execution. Caller-authenticated current runtime refusal is
not proven. The commands and mechanics below describe the pre-exhaustion
interface.

Preflight a sample protected-records runtime profile:

```bash
bin/zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-profile-preflight --profile - --json < profiles/protected-records-runtime-fixture.profile.json
```

The profile at `profiles/protected-records-runtime-fixture.profile.json` is a
sample runtime-profile preflight profile. It is not an active or installed
runtime profile. It names the runtime service command, proof command, request
contract, launcher-owned authority boundary, consumed-store lock/validation/
anchor/write model, replay scope, required proof cases, required boundary
observations, and known open boundaries.

The preflight validates that profile, runs the local disposable
`zlar protected-records-runtime-profile-proof`, binds the profile SHA-256 into
the report, and reports that the proof accepted one recognized write while
refusing replay after restart, invalid consumed-store shape, invalid anchor
shape, consumed-store rollback/deletion/replacement relative to the current
local anchor, and agent-supplied authority material before runtime-state
mutation. It also preserves the store-plus-anchor rollback boundary as open.

This command does not select `--latest`, live probe, inspect a live records
system, install or activate a persistent runtime profile, prove a production
records service, prove production-grade durable storage or anti-rollback,
stale-lock recovery, multi-host coordination, tamper resistance, exactly-once
effect semantics, current-machine governance, live MCP coverage, external
attestation, sovereign recognition, or coverage of unrouted records paths.

### `zlar protected-records-runtime-activation-preflight`

Source-checkpoint posture: the source-recorded exhausted-status guard precedes
positive artifact generation. The `verify` branch is intended to inspect
historical effect facts without consequence reexecution and keeps
fixture-rightful issuance false, but transitive import-time side-effect closure
and caller-authenticated current runtime refusal are unproven. Positive commands
below are retained as pre-exhaustion interface documentation.

Preflight a sample protected-records runtime activation plan:

```bash
bin/zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact ./runtime-activation-preflight-artifact.json
bin/zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact -
bin/zlar protected-records-runtime-activation-preflight verify --input ./runtime-activation-preflight-artifact.json
bin/zlar protected-records-runtime-activation-preflight verify --input ./runtime-activation-preflight-artifact.json --json
bin/zlar protected-records-runtime-activation-preflight verify --sample
bin/zlar protected-records-runtime-activation-preflight verify --sample --json
bin/zlar protected-records-runtime-activation-preflight --plan - --profile profiles/protected-records-runtime-fixture.profile.json --json < profiles/protected-records-runtime-activation-plan.fixture.json
```

The plan at
`profiles/protected-records-runtime-activation-plan.fixture.json` is a sample
activation-plan preflight profile. It is not an active or installed runtime
profile. It binds an explicit runtime-profile SHA, requires explicit human
install, refuses latest/current-machine selection, and records that it does
not write runtime config, write hook configuration, start a runtime service,
or accept request-stream authority material.

The preflight validates the explicit plan and explicit profile together, runs
the bounded runtime-profile preflight, binds the plan SHA-256 and profile
SHA-256 into the report, and reports profile-SHA match, runtime proof case
count, rollback refusal, no activation applied, no config/hook write, and open
activation/live/current-machine boundaries.

`--artifact <file|->` wraps the explicit plan, runtime profile, and preflight
report in a portable canonical JSON artifact with a SHA-256 over the canonical
artifact body. `verify --input <file|->` verifies artifact integrity and the
embedded activation-preflight boundaries without rerunning the preflight or
selecting a live/current-machine runtime profile.

`verify --sample` verifies the committed sample artifact at
`tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json`
without generating fresh evidence.

This command does not select `--latest`, live probe, inspect a live records
system, install or activate a persistent runtime profile, write runtime config,
write hook configuration, start a runtime service, prove production service
deployment, prove production-grade anti-rollback, exactly-once effects,
current-machine governance, live MCP coverage, external attestation, sovereign
recognition, or coverage of unrouted records paths.

### `zlar protected-records-runtime-local-activation`

Source-checkpoint posture: the source-recorded exhausted-status guard precedes
positive activation proof generation. The `verify` branch is intended to avoid
consequence reexecution, remains historical for the legacy schema, and projects
fixture-rightful issuance false; transitive import-time side-effect closure and
caller-authenticated current runtime refusal are unproven.

Run the explicit local disposable runtime activation proof:

```bash
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact ./runtime-local-activation-artifact.json
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact -
bin/zlar protected-records-runtime-local-activation verify --input ./runtime-local-activation-artifact.json
bin/zlar protected-records-runtime-local-activation verify --input ./runtime-local-activation-artifact.json --json
bin/zlar protected-records-runtime-local-activation verify --sample
bin/zlar protected-records-runtime-local-activation verify --sample --json
bin/zlar protected-records-runtime-local-activation --plan - --profile profiles/protected-records-runtime-fixture.profile.json --json < profiles/protected-records-runtime-local-activation-plan.fixture.json
```

The command validates an explicit local activation plan and explicit runtime
profile together, verifies that the profile SHA matches the plan, then runs the
bounded disposable runtime-profile proof. The proof writes only launcher-owned
disposable config inside the proof harness, starts local JSONL child service
processes, accepts one recognized `records.write`, refuses replay across
restart, and refuses missing, invalid, unknown-issuer, retired-issuer,
missing-issuer-status, stale, wrong-policy, wrong-domain, wrong-tool,
wrong-runtime-profile-id, wrong-audit-event, wrong-detail, non-boarding, direct-API, and
agent-supplied-authority requests before runtime-state mutation.

`--artifact <file|->` wraps the explicit plan, runtime profile, and local
activation proof in a portable canonical JSON artifact with a SHA-256 over the
canonical artifact body. `verify --input <file|->` checks artifact integrity
and the embedded local-activation boundaries without rerunning the proof.
`verify --sample` verifies the committed sample artifact at
`tests/fixtures/protected-records-runtime-local-activation-artifact-v1.json`
without generating fresh evidence.

This command does not select `--latest`, live probe, install a persistent
runtime profile, write persistent runtime configuration, write hook
configuration, use Telegram, inspect a live records system, prove production
service deployment, prove current-machine governance, prove external
attestation, prove sovereign recognition, or cover unrouted records paths.

### `zlar protected-records-runtime-profile-installation`

Source-checkpoint posture: the source-recorded exhausted-status guard precedes
positive generation and disposable install-root creation. The `verify` branch
is intended to preserve historical installation/effect/refusal facts without
consequence reexecution, but transitive import-time side-effect closure is
unproven. The legacy artifact lacks a bound grant SHA and cannot project
fixture-rightful issuance.

Run the local disposable runtime profile installation proof:

```bash
bin/zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact ./runtime-profile-installation-artifact.json
bin/zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact -
bin/zlar protected-records-runtime-profile-installation verify --input ./runtime-profile-installation-artifact.json
bin/zlar protected-records-runtime-profile-installation verify --input ./runtime-profile-installation-artifact.json --json
bin/zlar protected-records-runtime-profile-installation verify --sample
bin/zlar protected-records-runtime-profile-installation verify --sample --json
bin/zlar protected-records-runtime-profile-installation --plan - --profile profiles/protected-records-runtime-fixture.profile.json --json < profiles/protected-records-runtime-profile-installation-plan.fixture.json
```

The command validates an explicit disposable installation plan and explicit
runtime profile together, verifies that the profile SHA matches the plan,
creates only a launcher-owned disposable proof root, copies the pinned profile
there, writes an active profile index, selects the profile by explicit id and
SHA, and then runs the bounded disposable runtime-profile proof. The proof
accepts one recognized `records.write`, refuses replay across restart, and
refuses missing, invalid, unknown-issuer, retired-issuer,
missing-issuer-status, stale, wrong-policy, wrong-domain, wrong-tool,
wrong-runtime-profile-id, wrong-audit-event, wrong-detail, non-boarding, direct-API, and
agent-supplied-authority requests before runtime-state mutation.

It also runs a request-authority guard proving that request-stream attempts to
supply installed profile state, runtime config, runtime profile, or recognition
rule are refused before mutation with zero state delta.

`--artifact <file|->` wraps the explicit plan, runtime profile, and disposable
installation proof in a portable canonical JSON artifact with a SHA-256 over
the canonical artifact body. `verify --input <file|->` checks artifact
integrity and the embedded disposable-installation boundaries without rerunning
the proof. `verify --sample` verifies the committed sample artifact at
`tests/fixtures/protected-records-runtime-profile-installation-artifact-v1.json`
without generating fresh evidence.

This command does not select `--latest`, live probe, install a persistent
runtime profile, write persistent runtime configuration, write hook/user/machine
configuration, use Telegram, inspect a live records system, prove production
service deployment, prove current-machine governance, prove external
attestation, prove sovereign recognition, or cover unrouted records paths.

### `zlar protected-records-installed-runtime-profile-preflight`

Preflight an explicit installed runtime-profile root without installing or
activating it:

```bash
bin/zlar protected-records-installed-runtime-profile-preflight \
  --install-root /absolute/path/to/disposable-install-root \
  --expected-profile profiles/protected-records-runtime-fixture.profile.json \
  --profile-id protected-records-runtime-fixture-profile \
  --profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469
bin/zlar protected-records-installed-runtime-profile-preflight \
  --install-root /absolute/path/to/disposable-install-root \
  --expected-profile profiles/protected-records-runtime-fixture.profile.json \
  --profile-id protected-records-runtime-fixture-profile \
  --profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 \
  --json
bin/zlar protected-records-installed-runtime-profile-preflight \
  --install-root /absolute/path/to/disposable-install-root \
  --expected-profile profiles/protected-records-runtime-fixture.profile.json \
  --profile-id protected-records-runtime-fixture-profile \
  --profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 \
  --artifact ./installed-runtime-profile-preflight-artifact.json
bin/zlar protected-records-installed-runtime-profile-preflight verify --input ./installed-runtime-profile-preflight-artifact.json
bin/zlar protected-records-installed-runtime-profile-preflight verify --input ./installed-runtime-profile-preflight-artifact.json --json
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample --json
```

The command requires an explicit install root, expected profile, profile id,
and profile SHA-256. It reads only the supplied install root's
`active-runtime-profile.json` and matching installed profile file, refuses
symlinked install-root/index/profile paths, validates the active-profile index,
requires selection by explicit id and SHA, rejects latest/default-current-machine
selection, validates the installed profile contract, preserves the selected
profile recognition contract, and reports sanitized placeholder paths only.

`--artifact <file|->` wraps the read-only preflight report in a portable
canonical JSON artifact with a SHA-256 over the canonical artifact body.
`verify --input <file|->` checks artifact integrity and the embedded
installed-runtime-profile preflight boundaries without reading an install root.
The verification output reports whether the recognition contract was preserved,
the launcher-owned recognition boundary, the ordered recognition-then-authority
mutation route, that the launcher must later supply the exact grant contract,
appointment, issuance decision, and authorized record update, that request-
stream authority material and agent-supplied recognition rules were not
accepted, and the required refusal-case count. The preflight deliberately
defers the exact runtime grant and therefore keeps rightful issuance false.
`verify --sample` verifies the committed sample artifact at
`tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json`
without generating fresh evidence.

This command does not select `--latest`, use a default current-machine runtime
profile, install or activate a runtime profile, write runtime config, write
hook/user/machine configuration, start a runtime service, inspect a live
records system, run a downstream refusal proof, prove production downstream
recognition, prove current-machine governance, prove production service
deployment, prove external attestation, prove sovereign recognition, or cover
unrouted records paths.

### `zlar protected-records-active-persistent-profile-preflight`

Run a source-only preflight for a future active persistent profile installation
against explicit temp/proof-owned surrogate paths:

```bash
bin/zlar protected-records-active-persistent-profile-preflight \
  --surrogate-root <proof-owned-root> \
  --activation-root <proof-owned-root>/activation/protected-records-private-operator-records-terminal \
  --proof-target <proof-owned-root>/proof/records-target.jsonl \
  --profile profiles/protected-records-runtime-fixture.profile.json \
  --runtime-profile-id protected-records-disposable-runtime-profile \
  --runtime-profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 \
  --expires-at <future-iso8601>
bin/zlar protected-records-active-persistent-profile-preflight \
  --surrogate-root <proof-owned-root> \
  --activation-root <proof-owned-root>/activation/protected-records-private-operator-records-terminal \
  --proof-target <proof-owned-root>/proof/records-target.jsonl \
  --profile profiles/protected-records-runtime-fixture.profile.json \
  --runtime-profile-id protected-records-disposable-runtime-profile \
  --runtime-profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 \
  --expires-at <future-iso8601> \
  --json \
  --report <redacted-source-preflight-report.json>
bin/zlar protected-records-active-persistent-profile-preflight status \
  --surrogate-root <proof-owned-root> \
  --activation-root <proof-owned-root>/activation/protected-records-private-operator-records-terminal \
  --json
bin/zlar protected-records-active-persistent-profile-preflight closeout \
  --manifest <source-preflight-manifest.json> \
  --closed-at <iso8601> \
  --reason operator_closeout \
  --output <source-preflight-closeout.json>
```

The command requires a surrogate root, activation root, proof target, canonical
runtime profile file, exact runtime profile id, exact runtime profile SHA-256,
and future expiry. The activation root must end with the named deployment
profile id `protected-records-private-operator-records-terminal`. It refuses
`--latest`, moving selectors, expired profiles, symlink escapes,
proof-target hardlinks where the platform exposes them, activation/proof-target
realpath escape from the surrogate root, user-supplied report/manifest/closeout
paths inside or symlink-routed into the real activation root, and existing
nonempty activation roots.
Existing active-root behavior is explicit: no silent overwrite and no
source-preflight replace mode. The status subcommand is read-only and the
closeout subcommand builds a closeout object from a supplied source-preflight
manifest.

The report preserves the refusal matrix for missing, invalid, unknown-signer,
wrong-issuer, wrong-policy, wrong-profile, wrong-action-class, wrong-target,
stale, expired, same-process signed-payload replay, restart consumed-grant
reuse, missing/mismatched/expired/revoked authority-grant appointment,
revoked/closed profile, and request-supplied authority-grant cases. It also
preserves the launcher-owned grant/store/witness requirements while deferring
the exact runtime grant, so source preflight does not claim rightful issuance.
It records the
crash/interruption contract: interrupted, preparing, active, expired, and
closed states must refuse silent continuation until an explicit closeout or
new authority exists.

This command does not default to the real activation root, install or activate
a persistent profile, write hook/user/machine/shell/app configuration, write
LaunchAgents or daemons, start a runtime service, create background
persistence, auto-activate anything, inspect real records, use credentials,
use network or external services, prove current-machine governance, prove
production downstream recognition, prove enterprise readiness, or close
unrouted side doors.

### `zlar protected-records-active-persistent-profile-lifecycle`

Source-checkpoint posture: the non-`run` supplied-report branch builds a
historical lifecycle projection with fixture-rightful issuance false and may
write only an explicitly selected report path. The source-recorded guard in the
`run` branch precedes activation-root or output creation. Transitive import-time
side-effect closure and caller-authenticated current runtime refusal are
unproven. Its positive command block is historical.

Verify a supplied set of local active persistent profile lifecycle reports:

```bash
bin/zlar protected-records-active-persistent-profile-lifecycle \
  --install-report <active-persistent-live-installation-report.json> \
  --green-report <active-persistent-action-crossing-report.json> \
  --red-report <active-persistent-red-path-refusal-report.json> \
  --closeout-report <active-persistent-closeout-refusal-report.json> \
  --expected-install-report-sha256 <sha256> \
  --expected-green-report-sha256 <sha256> \
  --expected-red-report-sha256 <sha256> \
  --expected-closeout-report-sha256 <sha256> \
  --report <active-persistent-lifecycle-report.json>
```

Historical pre-exhaustion run interface for a source-bound lifecycle bundle:

```bash
bin/zlar protected-records-active-persistent-profile-lifecycle run \
  --activation-root <protected-records-private-operator-records-terminal> \
  --output-dir <proof-owned-evidence-dir> \
  --profile profiles/protected-records-runtime-fixture.profile.json \
  --runtime-profile-id protected-records-disposable-runtime-profile \
  --runtime-profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 \
  --expires-at <future-iso8601> \
  --allow-named-live-root \
  --replace-closed-root
```

The verifier checks that the supplied reports form one coherent local
lifecycle: bounded installation/readback, one governed `records.write`
crossing, red-path refusal before mutation, and explicit closeout/refusal
after closure. The reports must bind to the same explicit runtime profile id
and SHA-256 and preserve `selects_latest=false`. The lifecycle output records
only supplied-report hashes and basename labels, so private scratch paths in
the source evidence are not echoed into the portable summary.
The expected SHA-256 flags are optional, but all-or-none; when supplied, the
verifier refuses any input report whose bytes do not match the pinned evidence
set.

The `run` form removes the handcrafted source-report gap. It installs the
pinned profile under the explicit root, proves one green crossing, generates
the red-path refusal report from a real selected-profile service proof, closes
the root, proves a post-closeout action crossing refuses before target
mutation, writes `zlar-active-persistent-profile-lifecycle-v1.json`, and writes
`zlar-active-persistent-profile-lifecycle-source-binding-v1.json` for
`north-star-readiness --evidence-dir`. The binding remains local,
source-supplied, and non-scoring:
`current_installation=false`, `product_proof_path_completion=false`, and
`production_downstream_recognition=false`.

The active-root status is evaluated at the supplied action-time clock. The
embedded local disposable service authority proof is separately evaluated at
the fixed hermetic fixture epoch. The report exposes both clocks; the fixture
grant is not evidence of live rightful issuance for the active root. Its grant-
store burn window, joint rollback reuse, exactly-once, and host-path TOCTOU
boundaries remain open.

The verifier form does not reopen, renew, reactivate, or install a profile
root. The `run` form writes only the explicit activation root, the proof-owned
evidence directory, and proof targets required for the lifecycle. Neither form
touches real records, uses credentials, writes hooks/config outside the named
root, proves raw Codex/developer-tool governance, proves arbitrary
current-machine governance, proves production downstream recognition, proves
enterprise readiness, provides public external attestation, or closes unrouted
side doors.

### `zlar protected-records-installed-runtime-profile-recognition-proof`

Run a local hermetic selected-profile recognition proof from a verified
installed-runtime-profile preflight artifact:

```bash
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --json
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --artifact ./installed-runtime-profile-recognition-proof-artifact.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input ./installed-runtime-profile-recognition-proof-artifact.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --sample
bin/zlar protected-records-installed-runtime-profile-recognition-proof --input ./installed-runtime-profile-preflight-artifact.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof --input ./installed-runtime-profile-preflight-artifact.json --json
```

The command consumes a read-only installed-runtime-profile preflight artifact,
verifies its selector and recognition-contract boundary, and runs a local
hermetic downstream-shaped service object. One matching `records.write` receipt
boards; all 18 required selected-profile refusal cases refuse before the
in-memory fake effect marker changes. The output records that the source
preflight itself remains no-effect selector evidence:
`downstream_refusal_proven=false` and
`current_machine_governance_proven=false`.

With `--artifact`, the command emits a portable checksummed recognition-proof
artifact. The `verify` form checks artifact integrity and embedded proof
boundaries without rerunning the proof or reading an install root.

This command does not install or activate a runtime profile, write runtime,
hook, user, or machine configuration, start a live runtime service, inspect a
live records system, prove current-machine governance, prove production
downstream recognition, prove production authority, provide external
attestation, prove sovereign recognition, or cover unrouted records paths.

### `zlar protected-records-installed-runtime-profile-service-proof`

Verify the committed historical service-proof artifact without rerunning the
exhausted positive consequence:

```bash
bin/zlar protected-records-installed-runtime-profile-service-proof verify --input ./installed-runtime-profile-service-proof-artifact.json
bin/zlar protected-records-installed-runtime-profile-service-proof verify --sample --require-sha 3e6bac95ba0a6b41d0ac53c16d598a22d47c871757473025a550556626f5fea8
```

The exact current contract SHA-256 is
`0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba`.
It authorizes one hermetic crossing, has `max_uses=1`, and is source-recorded as
exhausted. Fresh effect evaluation refuses as
`authority_grant_contract_exhausted` before grant-store commit and runtime-state
mutation. Positive generation commands therefore fail closed until a separate
replacement grant is authorized and pinned.

The committed service artifact remains historical structural evidence. It
records the following mechanics; it does not prove current fixture-rightful
issuance:
The launcher-owned service config also owns one fixed logical-fixture target.
The request's `target_handle` is assertion-only, and the receipt detail hash
binds the target handle with the record update. Wrong, missing, and malformed
target assertions refuse before receipt recognition, receipt consumption, and
state mutation. The same auxiliary receipt then boards when the correct target
is asserted in a separate proof store, proving target refusals do not burn it.
The primary proof and auxiliary recovery probe each append once: two fixture
appends across two isolated proof stores, not one total append. Replay of the
primary signed payload refuses as `receipt_replay` in the same child service
process; after restart the persisted authority-grant contract SHA refuses as
`authority_grant_already_consumed`. Unsigned envelope id, issued-at metadata,
previous-receipt metadata, and key-id alias are not replay identities.
Invalid, duplicate, and locked consumed-store states, invalid local-anchor
shape, and valid consumed-store rollback/deletion/replacement relative to the
local anchor refuse before mutation. Configured witness deletion after store
and anchor state exists also refuses before mutation. Store-plus-anchor
rollback also refuses before mutation when the launcher-owned local proof
witness remains ahead. All 18 required selected-profile recognition cases
refuse before service-state mutation. Five separate missing, mismatched,
expired, revoked, or request-supplied authority-grant cases refuse before grant
consumption and mutation. The output preserves the source
preflight's no-effect boundary while recording the stronger local
child-service facts:
`runtime_service_started=true`,
`same_process_signed_payload_replay_refused=true`,
`restart_consumed_authority_grant_refused=true`,
`single_host_consumed_store_rollback_detection=true`,
`store_and_anchor_rollback_refused_while_witness_ahead=true`,
`store_anchor_and_witness_joint_rollback_detection=false`,
`fixture_rightful_issuance_path_evidenced=false`,
`rightful_issuance_proven=false`,
`persistent_runtime_config_written=false`,
`current_machine_governance_proven=false`, and
`production_downstream_recognition=false`.
The proof's non-claims separately state that store/anchor/witness commit is not
atomic and exactly-once effect semantics are not proven.

The embedded public grant contract binds authority domain
`protected-records.local-disposable-fixture`, grantor role
`fixture-consequence-authority`, issuer slot
`protected-records-fixture-receipt-issuer`, the exact consequence path, target,
runtime profile, recognition and target contracts, authorized effect, policy,
and half-open fixture time window. Its powers are exactly
`bind_runtime_issuer_to_slot`, `issue_governed_action_receipt`,
`issue_replacement_authority_grant`, and `revoke_authority_grant`. Runtime
private appointment and key material are deliberately omitted from portable
artifacts.

With `--artifact`, the command emits a portable checksummed service-proof
artifact. The `verify` form checks structural self-integrity and embedded proof
boundaries, including separate recognition and authority-refusal taxonomy
hashes, without rerunning the proof or reading an install root. Exact artifact
identity requires the caller to provide the expected SHA-256; self-integrity
alone is not source identity.

This command does not install or activate a runtime profile, write persistent
runtime, hook, user, or machine configuration, start a live runtime service,
inspect a live records system, prove current-machine governance, prove
production downstream recognition, prove production authority, prove enterprise
readiness, provide external attestation, prove sovereign recognition, or cover
unrouted records paths. It preserves one fixed logical-fixture target binding
as historical artifact evidence, but the exhausted grant cannot project a
current fixture-rightful crossing; it also does not prove
profile-wide target authority, generic or portable rightful issuance, a per-run
or physical target identity, a live target, live revocation truth, current-
machine governance, or consequence-lifecycle closure. The store, anchor, and
witness commit is ordered but non-atomic: a later write failure can burn the
one-use grant, and joint rollback of all three matching local files can reopen
grant reuse. Host-filesystem path TOCTOU and exactly-once effects remain open.

### `zlar protected-records-installed-runtime-profile-terminal-chain`

Verify the exact committed terminal-chain artifact without recursively rerunning
the exhausted positive service consequence:

```bash
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input ./installed-runtime-profile-terminal-chain-artifact.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --sample --require-sha 0f8db51f11885e7867c6f0fa4d737adf51774e7cd9ad711cd2073b5b684c303f
```

Source composition now reads and exact-SHA verifies the committed service
artifact instead of invoking its positive generator. One-terminal and product
composition follow the same rule. Because the current grant is exhausted, the
composition runners refuse fixture-rightful projection rather than treating a
fresh scratch root as new authority.

The terminal artifact preserves the boarded service target handle,
target/effect/detail hashes, accepted state-effect binding hash, the full
public fixture authority-grant contract and summary, and the nested service-
artifact hash as `post-effect-hash-bound-metadata-only`. It preserves one fixed
logical-fixture target binding as historical evidence; it does not prove a
current fixture-rightful crossing or profile-wide, generic, portable, per-run,
physical, live, or production authority.

The terminal-chain report proves one matching `records.write` boards through the
local disposable child service while the missing receipt, invalid receipt, and
all 18 selected-profile recognition cases refuse before service-state mutation.
Five separate authority-grant cases refuse before grant consumption and
mutation. The report preserves separate recognition and authority refusal
taxonomies as required case ids, observed case ids, observed reason codes,
before-mutation booleans, and canonical
`recognition_refusal_taxonomy_sha256` and
`authority_refusal_taxonomy_sha256` values; it also preserves named receipt-refusal evidence and
a canonical `named_receipt_refusals_sha256` for missing, invalid, stale,
`stale_or_expired`, unknown-issuer, wrong-policy, wrong-domain, and wrong-tool
receipt cases. `stale_or_expired` is a named summary label backed by the stable
machine reason `receipt_stale`; it is not a separate `receipt_expired` contract.
The report also preserves canonical `recognition_refusal_groups` and
`recognition_refusal_groups_sha256` separating no usable recognized receipt
authority, recognized receipt scope mismatch, and route/request authority
material refusal cases, with stable `case_count` and `cases[].case_id`
evidence inside each group, plus the generated preflight artifact hash, generated
service proof artifact hash, explicit plan/profile hashes, false
latest-selection flag, and false stronger-claim flags.
For `v3.4.28+`, the report also embeds the generated preflight and
service-proof artifacts in `nested_artifacts`, and verification refuses summary-only
forged inner preflight and service-proof hashes even when outer terminal-chain
artifact integrity is recomputed.
For `v3.4.30+`, artifact verification also emits a verifier-owned
`nested_artifact_binding` summary with nested artifact body hashes, verified
flags, binding booleans, and false stronger-claim flags.
For `v3.4.37+`, the report and artifact verification also preserve a
public-safe hash-bound trusted issuer registry recognition summary over the
bundled local fixture: stable registry/receipt contract hashes, local
`RECOGNIZED` evaluation, malformed-registry fail-closed behavior, and explicit
`false` flags for embedded raw public-key material, embedded receipt envelope,
and artifact-only cryptographic reconstruction.
The registry summary uses a synthetic registry-evidence receipt. That receipt
is not the boarded service receipt, did not authorize the service write, and has
a distinct receipt role and detail hash. The boarded receipt is the
write-authority receipt whose detail hash binds the accepted target effect.
Issuer recognition and a valid signature still do not create permission. The
separate launcher-owned fixture authority-grant contract supplies the exact
fixture authorization and is evaluated at issuance and effect time. No receipt
envelope, runtime private issuer appointment, issuer key id, public key,
signature, or private key is embedded. The positive result remains one exact
local-fixture crossing; generic, portable, live, and production rightful
issuance remain false.
For `v3.4.38+`, that binding also preserves terminal-chain-local refusal
evidence for unrecognized registry scope (`scope_not_found`) and a valid
signed receipt whose registry-bound receipt contract mismatches
(`detail_hash_mismatch`), plus the canonical
`trusted_issuer_registry_recognition_refusals_sha256`.
For `v3.4.39+`, `proof-smoke` and North Star readiness expose that refusal
contract directly in evaluator summaries with case count, exact case IDs, exact
reason codes, `all_refused=true`, and the refusal SHA-256.
For `v3.4.39+` targets, release-forward dry-run packets also preserve and print that
same trusted-registry refusal summary in `DRY-RUN-MANIFEST.json` and
`DRY-RUN-RESULT.md`.
For `v3.4.41+` targets, release-forward dry-run packets also preserve
`release_forward_report_contract` in `DRY-RUN-MANIFEST.json` and render the
same object in `DRY-RUN-RESULT.md` with the
`manifest.release_forward_report_contract.*` prefix. The manifest object is
canonical; the Markdown rendering is for human review.
For `v3.4.42+` targets, that canonical object also names
`ZLAR/zlar-product-proof-path-v1.json` directly with source hash, PASS/evidence
model, receipt-verifier boundary, North Star consumption, false-claim flags,
and known unrouted-records noncoverage visibility.
For `v3.4.45+` targets, that same Product Proof Path contract also preserves the
fresh terminal-chain artifact-verification boundary: binding/refusal hashes,
exact trusted-registry refusal IDs/reasons, omitted public-key material, omitted
receipt envelope, false external attestation, and false current-machine
governance.
For `v3.4.46+` targets, it also preserves exact grouped recognition-refusal case
IDs in the Product Proof Path terminal-chain boundary.
For `v3.4.48+` targets, it also preserves the Product Proof Path
deployment-profile authority bridge: deployment profile SHA, selected runtime
profile SHA, explicit id-and-SHA selection, no `--latest`, verified preflight,
one recognized receipt mutating once, 18/18 refusals before mutation,
agent-supplied authority material refused, direct API refused, and false
current-machine/production/external/sovereign/unrouted flags.
For `v3.4.49+` targets, it also preserves five deployment-profile authority
refusals before service proof starts: stale deployment-profile runtime SHA,
runtime-profile id mismatch, preflight profile SHA mismatch, preflight
`--latest` selection, and preflight request-stream authority material.
For `v3.4.50+` targets, terminal-chain evidence and artifact verification also
mirror that same five-case list with before-service-proof refusal,
before-mutation refusal, service-proof-not-started, and false stronger-claim
flags.
For future `v3.4.51+` local targets, release-forward/private-intake contracts
also require the Product Proof Path terminal-chain trusted-registry
verdict/evaluation facts and downstream-refusal marker boundary in both the
Product Proof Path contract and North Star mirror, including exact downstream
refusal reasons and all-refusals-unboarded flags; this remains local fixture
evidence, not live trust-registry truth.

With `--artifact`, the command emits a portable checksummed terminal-chain
artifact. The `verify` form checks structural self-integrity and embedded proof
boundaries without rerunning the chain, recreating an install root, starting a
child service, or reading live machine state. Exact artifact identity requires
the caller to supply the expected SHA-256 or a stronger external anchor.

This command does not persistently install or activate a runtime profile, write
persistent runtime, hook, user, or machine configuration, select `--latest`,
inspect a live records system, start a live runtime service, prove live trust-
registry state, prove live issuer status, prove key custody, prove revocation
truth, prove current-machine governance, prove production downstream
recognition, prove production authority, prove enterprise readiness, provide
external attestation, prove sovereign recognition, or cover unrouted records
paths. It also does not prove exactly-once effects, atomic all-or-nothing grant-
store/anchor/witness commit, joint rollback detection when all three local
files move together, host-filesystem path TOCTOU closure, or consequence-
lifecycle closure.

### `zlar protected-records-one-terminal-deployment-profile`

Run the local fixture deployment-profile authority bridge proof:

```bash
bin/zlar protected-records-one-terminal-deployment-profile --sample
bin/zlar protected-records-one-terminal-deployment-profile --sample --json
bin/zlar protected-records-one-terminal-deployment-profile --profile ./deployment-profile.json --runtime-profile ./runtime-profile.json --preflight-artifact ./preflight-artifact.json --json
```

The command validates a deployment-owned profile artifact, binds the selected
protected-records runtime profile by explicit id and SHA-256, consumes the
matching installed-profile preflight artifact, and runs the local disposable
child-service proof for the selected profile. The proof records one recognized
receipt mutating exactly once and all 18 required refusal cases mutating zero
state. It also records that request-stream or agent-supplied authority material,
direct API attempts, `--latest` selection, and stronger current-machine or
production claims are refused.

JSON output includes `input_provenance` so sample and explicit-file runs bind
the deployment profile, runtime profile, and preflight artifact by safe display
path plus SHA-256. Absolute local paths are not emitted; stdin and outside-repo
inputs are redacted before they become proof text.

This command is local fixture evidence only. It does not install or activate a
runtime profile, start a live runtime service, inspect live records, write hook,
user, machine, or production configuration, prove current-machine governance,
prove production downstream recognition, prove production authority, prove
enterprise readiness, create external attestation, prove sovereign recognition,
or cover unrouted surfaces.

### `zlar protected-records-named-deployment-profile-readiness`

Run the local no-secret named deployment-profile rehearsal readiness report:

```bash
bin/zlar protected-records-named-deployment-profile-readiness --sample
bin/zlar protected-records-named-deployment-profile-readiness --sample --json
```

The command declares the named rehearsal profile
`protected-records-private-operator-records-terminal`, binds it to the
`records.write` action class, and names the downstream boundary as the local
JSONL child-process protected-records runtime service. It then runs the fresh
installed-runtime-profile terminal chain and reports whether the rehearsal
boundary refused missing, unrecognized, out-of-scope, and request-authority
attempts before mutation while one recognized receipt boards through the local
disposable fixture path.

This command intentionally accepts only `--sample`. It does not read live
deployment-profile inputs, inspect personal records, select `--latest`, install
or activate a runtime profile, write hook/user/machine/production configuration,
start a live service, use credentials, create receipts, or publish evidence.

The report sets `active_deployment_profile=false`,
`persistent_runtime_profile_installation=false`,
`current_machine_governance=false`,
`production_downstream_recognition=false`, `enterprise_readiness=false`, and
`public_external_attestation=false`. The next authority crossing remains
install/config/current-machine or an equivalent real deployment boundary.

### `zlar current-machine-governance-preview`

Compose the local no-write current-machine governance preview lane:

```bash
bin/zlar current-machine-governance-preview --sample
bin/zlar current-machine-governance-preview --sample --json
```

The command assembles existing bounded components into one preview receipt:
the current-machine approval request preview, the named deployment-profile
readiness rehearsal, active-persistent-profile source status, and the
active-persistent-profile source preflight. It uses committed fixtures and
proof-owned temporary roots only.

This is a claim contract, not authority. The report sets
`evidence_surface=local-no-write-source-lane`, preserves
`proof_stage=source_only_preview_no_authority`, and keeps
`authority_request_made=false`, `install_authority_granted=false`,
`human_approval_granted=false`, `current_machine_governance=false`,
`current_machine_governance_proven=false`,
`production_public_authority=false`, `public_release_claim=false`,
`deployment_readiness_claim=false`, and `external_attestation_claim=false`.

It does not install, activate, write hooks, write profiles, write services,
write user or machine configuration, use Telegram, change GitHub settings,
publish website artifacts, contact external verifiers, execute a live hook,
emit a live receipt, or prove live downstream recognition. The next authority
crossing remains install/config/current-machine or an equivalent real
deployment boundary.

### `zlar protected-records-named-deployment-profile-real-boundary`

Run the bounded machine-local named deployment-profile real-boundary ceremony
proof:

```bash
bin/zlar protected-records-named-deployment-profile-real-boundary --run
bin/zlar protected-records-named-deployment-profile-real-boundary --run --json
bin/zlar protected-records-named-deployment-profile-real-boundary --run --artifact ./real-boundary-proof.json --json
```

The command creates the named activation root for
`protected-records-private-operator-records-terminal`, writes public recognition
fixture material and runtime-service config inside that root, and routes
proof-owned `records.write` requests through the local JSONL child-process
runtime service. It writes the proof-owned records target under the build
scratch root only after the runtime service accepts a recognized receipt.

The proof checks that the selected runtime profile is pinned by exact id and
SHA-256, no `--latest` selection is used, one recognized receipt mutates the
proof-owned target exactly once, same-process and restart replay refuse before
target mutation, and missing, unrecognized, out-of-scope, request-authority,
and closed-profile attempts refuse before target mutation. The activation is
closed as inert evidence at the end of the proof.

Temporary Ed25519 test signing material is generated only in memory. Public
recognition fixture material is written inside the named activation root. No
private key material, credential, token, HMAC, or production issuer/custody
material is persisted or emitted.

This command does not touch real personal, business, customer, or production
records. It does not write hooks, Codex config, user config, machine config,
GitHub settings, website files, tags, releases, Actions, or external services.
It does not prove generic current-machine governance, raw Codex/developer-tool
governance, all-surface governance, production downstream recognition,
production authority, enterprise readiness, public external attestation,
sovereign recognition, side-door closure, or absolute human intention.

### `zlar recognized-effect-target-shape`

Run or verify the no-secret recognized-effect target-shape fixture proof:

```bash
bin/zlar recognized-effect-target-shape --sample
bin/zlar recognized-effect-target-shape --sample --json
bin/zlar recognized-effect-target-shape --sample --artifact ./recognized-effect-target-shape-artifact.json
bin/zlar recognized-effect-target-shape verify --input ./recognized-effect-target-shape-artifact.json
bin/zlar recognized-effect-target-shape verify --sample --json
```

The command models the corrected protected-records consequence target:
`candidate_input_log` is untrusted ingress, while
`recognized_effect_delta` is the consequence. One governed receipt-shaped
candidate advances the delta through the receipt/profile/issuer/state contract.
Direct and shell-written raw ingress fixture bytes remain target-incapable for
recognized effect and do not advance the delta.

The verifier also checks stale, replayed, malformed, missing, mismatched,
non-boarding, unknown-issuer, missing-status, retired-issuer,
compromised-issuer, receipt-contract, request-authority, state-tamper, and
manifest-mismatch refusals. Restart replay is checked through a persisted
replay-store fixture. Malformed JSONL / partial-write ingress fails closed
without crashing the verifier or advancing `recognized_effect_delta`.

This command does not block OS filesystem writes, close side doors, authenticate
against a coherent state-plus-manifest rewrite, prove production ingress
governance, prove current-machine governance, install hooks/config, create
credentials, publish evidence, or make a public claim.

### `zlar records-write-terminal-proof`

Current posture: this command refuses before nested runtime proof execution.
The airport sentence and positive mechanics below describe historical evidence,
not a currently executable crossing.

Historical pre-exhaustion one-command `records.write` terminal interface:

```bash
bin/zlar records-write-terminal-proof
bin/zlar records-write-terminal-proof --json
bin/zlar records-write-terminal-proof --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --json
```

By default, the command uses the committed local activation plan and runtime
profile fixture paths. It generates fresh local disposable proof evidence in
memory, builds and verifies the in-memory local-activation artifact, then
prints the bounded airport sentence for the first `records.write` terminal:
one recognized receipt reaches bounded service-state mutation, while a
machine-readable downstream refusal contract preserves exact reason-code and
zero-mutation evidence for missing, invalid, stale/expired,
unrecognized-issuer, wrong-policy, out-of-scope, binding-mismatch,
direct-API, and agent-supplied-authority attempts. The report includes an
`active_profile_selection` section showing that the explicit pinned runtime
profile was selected as active inside the local disposable proof harness for
this `records.write` route. That selection is not a persistent runtime-profile
install, not `--latest` selection, and not a live/current-machine runtime
profile check.

This command does not select `--latest`, live probe, install a persistent
runtime profile, write persistent runtime configuration, write hook
configuration, use Telegram, inspect a live records system, prove production
service deployment, prove current-machine governance, prove external
attestation, prove sovereign recognition, or cover unrouted records paths.

### `zlar protected-records-runtime-service`

This direct executable surface is permanently retired in the committed source.
Its script body contains one unconditional refusal before argument,
process-environment, config-file, stdin, target-module, or authority-status
handling with
`legacy_runtime_v1_direct_entry_surface_retired`. There is no internal flag,
token, caller identity, or source-recorded grant status that reopens it.
Interpreter/PATH substitution, loaders/preloads before script evaluation, old
source copies, and same-user source mutation remain outside this source-level
claim.

```bash
bin/zlar protected-records-runtime-service --config ./protected-records-runtime-config.json < ./protected-records-runtime-requests.jsonl
```

The command above is a refusal probe, not a service launch. Historical
pre-retirement v1 behavior accepted launcher-supplied config out of band from
the JSONL request stream. That config had to be supplied as a file because
stdin was reserved for service requests. It owned the recognition rule, fixed
target binding, persistent consumed-receipt
store path, and local anti-rollback anchor path. Each write request must carry a
`target_handle` assertion; it cannot select the target and must equal the
launcher-owned binding. The receipt detail hash must bind
`sha256(canonical({target_handle,record_update}))`. Wrong, missing, or malformed
target assertions refuse before receipt recognition, receipt consumption, and
mutation. Requests that try to supply runtime state paths, replay-store paths,
recognition rules, or other unsupported authority material also refuse before
mutation. Those mechanics remain historical E3 evidence; they are not current
positive CLI behavior.

The checked-out source also retains the named
`createProtectedRecordsRuntimeService` export only as an unconditional,
input-independent refusal returning
`legacy_runtime_v1_exported_factory_retired`. It reads no config or getters and
creates no service object or `applyRequest`. This preserves verifier-bearing
module linkage without preserving a positive v1 factory. Existing installed or
copied modules, old source, custom loaders/imports, interpreter substitution,
and same-user source mutation remain outside the checked-out-source claim.

The additive `legacy-runtime-v1-e3-source-disposition-overlay-v0` keeps the
historical E3 node and its `distinct_effect` relationship to E4 intact. At its
exact source checkpoint, each of nine reviewed E3 route projections contains a
fixed CLI or factory refusal boundary before E3; source-recorded guards may
refuse earlier. The installed terminal-chain E3 association is a
historical evidence view: it reads a committed service-proof artifact and does
not invoke the service-proof generator. Coverage remains observed-uncovered or
unclassified, and North Star 2 remains `mapped_open`.

The committed general runtime-service script body now contains one refusal path
before legacy v1 or v2 config or request reading. The supported historical v2 crossing used a non-dispatched
internal child of the exact replacement crossing route; the public dispatcher
cannot bypass artifact pin and exhausted-status closeout. The child's literal
environment marker is routing metadata, not parent authentication. Direct Node
invocation or custom import of that module is explicitly outside coverage and
keeps side-door closure false. Direct calls to the exported v2 service creator
and loader-preload/custom-code execution are outside coverage too. In the
supported route, neither launcher config nor request input may nominate
`now_epoch`. The
child samples its process wall clock at initial recognition, again under the
consumed-store lock, and again immediately before the final freshness check and
authority effect evaluation. A clock regression during that boundary refuses
before consumption and mutation. This closes caller-selected historical time
and the supported direct-v2 CLI path; it does not prove host-clock correctness,
rollback-resistant time custody, external time attestation, source-access
tamper resistance, or same-user direct module/custom-code execution. Historical
v1 hermetic fixture proofs retain their fixed test epoch and do not widen v2
authority. Their positive CLI and exported-factory dependencies are now
retired; any future
fixture-internal execution route requires a new design and separate authority.

The historical service kept mutable runtime state in process-private memory for the life
of the local child process and uses the launcher-owned lockfile-guarded
persistent consumed-receipt store to refuse replay across service restarts
while that store remains intact. It refuses invalid store or anchor shape,
duplicate receipt ids, a pre-existing store lock, and valid consumed-store
rollback/deletion/replacement relative to the local anchor before
runtime-state mutation. It does not inspect a live records system, install a
persistent runtime profile, close host process/memory/debugger/operator
filesystem side doors, prove production-grade durable storage,
production-grade anti-rollback, stale-lock recovery, multi-host coordination,
tamper resistance, exactly-once effect semantics, or claim production
deployment.

### `zlar protected-records-replacement-crossing-v2`

Execute the one-attempt local-fixture replacement route only from a new exact
authorization packet and its matching holder records:

```bash
bin/zlar-protected-records-replacement-crossing-v2 cross-and-pin \
  --packet ./packet.json \
  --holder-bound ./holder-bound.json \
  --holder-signed-once ./holder-signed-once.json \
  --output-dir /absolute/new/output-directory \
  --require-packet-sha <packet-sha256> \
  --require-holder-bound-sha <holder-bound-sha256> \
  --require-holder-signed-once-sha <holder-signed-once-sha256> \
  --require-grant-sha <grant-contract-sha256> \
  --require-manifest-schema-sha <manifest-schema-sha256> \
  --json
```

All five SHA-256 identities are external roots; the packet cannot choose them.
The holder-signed-once root pins the complete post-signing event, and the route
requires the signed receipt envelope to be exactly the packet's unsigned
envelope with only the appointed `kid` and verified signature populated.
The output directory must not exist, must remain outside the source repository,
and must have a real non-symlink parent. The packet's planned live-status path
must equal `<output-dir>/runtime-control/authority-status.json`. No caller clock
is accepted. The CLI clears inherited Node loader/module-search variables,
rejects hidden Git index flags, builds a hook-disabled detached snapshot of the
packet-bound clean source commit, rechecks it, makes it read-only, and invokes
the runtime service exactly once from that snapshot. It never retries.

An accepted canonical runtime result is pinned before service and terminal
composition; the central manifest is pinned after those two artifacts. The
route then verifies the persisted set, replaces the live authority status with
an exhausted status, and writes closeout evidence. A refusal or crash can leave
fail-closed residue. Effect-plus-artifact pinning is not crash-atomic, and the
route does not prove exactly-once effect semantics, tamper-resistant custody,
host-selected Node integrity, host-clock custody, production governance,
lifecycle closure, or side-door closure. A failed or ambiguous attempt cannot
be retried under the same one-use authority.

### `zlar protected-records-replacement-artifact-set-v2`

Verify the persisted service and terminal artifacts without importing or
calling the runtime crossing route:

```bash
bin/zlar protected-records-replacement-artifact-set-v2 verify \
  --manifest ./50-replacement-artifact-set-manifest-v2.canonical.json \
  --service ./30-replacement-service-artifact-v2.canonical.json \
  --terminal ./40-replacement-terminal-artifact-v2.canonical.json \
  --require-manifest-sha <manifest-body-sha256> \
  --require-grant-sha <grant-contract-sha256> \
  --require-manifest-schema-sha <manifest-schema-sha256> \
  --consumer all \
  --json
```

The verifier requires external manifest, grant, and schema identities and
recomputes the raw canonical service/terminal lineage. `--consumer` must be
`all` or a consumer declared by the no-reexecution graph. Verification does not
re-execute the consequence, reactivate authority, or prove freshness outside
the recorded local-fixture crossing.

### `zlar protected-records-runtime-profile-proof`

Source-checkpoint posture: the source-recorded exhausted-status guard refuses
before scratch-root creation. Caller-authenticated current runtime refusal is
not proven. The proof behavior below is historical.

Historical pre-exhaustion disposable runtime-profile proof interface:

```bash
bin/zlar protected-records-runtime-profile-proof
bin/zlar protected-records-runtime-profile-proof --json
```

The historical proof invoked `zlar protected-records-runtime-service --config
<file>` as a JSONL child service whose process owned private in-memory state and whose
launcher-supplied config carries the recognition rule, persistent
consumed-receipt store, and local anti-rollback anchor outside the request
stream. That child dependency is now permanently retired; at this source
checkpoint the outer exhausted-status guard refuses generation before scratch
creation, without proving caller-authenticated current runtime refusal. This proof command has no verify
mode. Downstream versioned runtime-local-activation,
runtime-profile-installation, and installed-service artifacts retain their own
verification branches intended to inspect supplied artifacts without consequence
reexecution; their transitive import-time side-effect closure remains unproven.
Those branches do not invoke this child after argument dispatch. The historical proof recorded one recognized
`records.write` mutates runtime state once, replay of that receipt refuses in
the same service process, replay of that receipt refuses after a fresh service
process restart while the store remains intact, invalid/duplicate/locked
consumed-store states and invalid anchor shape refuse before mutation, valid
consumed-store rollback/deletion/replacement relative to the local anchor
refuses before mutation, missing/invalid/unknown/retired/missing-status/
wrong-policy/wrong-domain/wrong-tool/wrong-runtime-profile-id/wrong-audit-event/wrong-detail/
non-boarding/stale receipts refuse before mutation, direct API attempts refuse
before mutation, and
agent-supplied state-path, consumed-receipt-path, consumed-store-anchor-path,
recognition-rule, fixture-mode, or unsupported-field attempts refuse before
mutation. It also emits boundary observations for the burned-receipt window
and store-plus-anchor rollback reopening replay.

This is local disposable runtime-profile evidence only. It is not live
records-system evidence, not a persistent runtime profile install, not a
production records service, not production-grade durable storage, not
production-grade anti-rollback, stale-lock recovery, multi-host coordination,
tamper resistance, or exactly-once effect semantics for the consumed store and
local anchor, not host process side-door closure, not live MCP or
current-machine governance proof, and not external attestation or sovereign
recognition.

### `zlar local-proof-pack`

Current-source posture: fresh proof-pack generation is permanently retired as
`local_proof_pack_fresh_generation_retired`, independently of mutable
fixture-grant state. The no-argument artifact fallback is separately retired;
explicit-report artifact packaging remains a named source side door. The
artifact-verification branch preserves the exact historical pack without
consequence reexecution. Transitive import-time side-effect closure remains
unproven. The legacy pack is a historical 6/6 snapshot, source-backed current
coverage is 4/6, and verification never projects current fixture-rightful
issuance.

Preserved artifact-verification branch:

```bash
bin/zlar local-proof-pack verify --sample
bin/zlar local-proof-pack verify --sample --json
bin/zlar local-proof-pack verify --input tests/fixtures/local-proof-pack-artifact-v1.json
```

The historical pre-retirement pack ran the fixture-input coverage map, the hermetic downstream refusal
proof, the simulated-human authorization proof, the approval-transport proof,
the issuer-status proof, the trusted issuer registry recognition fixture, the
local receipt-verifier boundary proof, the protected records terminal proof,
the protected records adapter conformance proof, the protected records
downstream-service proof, the protected records service-profile preflight, the
protected records runtime activation-plan preflight, the protected records
runtime-local-activation proof, and the protected records runtime-profile
installation proof through their existing validators, plus a deterministic
read-only key-state sample
summary from `zlar key-state --sample --json`.
The downstream refusal component accepts one matching receipt with
`recognized_marker_count_delta=1`, records final marker count one, and refuses
the required missing, invalid, stale/expired, issuer, scope, binding, and
non-boarding cases before fake marker write with all refusal marker-count
deltas at zero.
The issuer-status component accepts one active local fixture issuer and refuses
retired, compromised, missing-status, unknown, and key-missing issuers before
boarding.
The trusted issuer registry recognition component validates and evaluates a
valid bundled private `trusted-receipt-issuers-v2` registry fixture through the shared
downstream recognition rule. It records `verdict=RECOGNIZED`, active fixture
issuer status, signature validity, audit-event/detail-hash binding,
malformed-registry fail-closed behavior, and false live-registry,
live-issuer-status, key-custody, revocation, production-trust-registry,
production-downstream-recognition, production-authority, public-attestation,
real-non-operator-review, sovereign-recognition, and
current-machine-governance flags.
The receipt-verifier component runs the actual
`zlar-verify <receipt.json> --pubkey <key.pub> --json` CLI against local
ephemeral v1 receipts and proves `VALID`, `UNKNOWN-SIGNER`, and `INVALID`
stay distinct by verdict and exit code. It does not prove active issuer status,
key custody, revocation state, downstream recognition, or production relying-
party acceptance.
The key-state component reports the `zlar-key-state-report-v1` sample summary,
software-rooted policy/constitution posture, software pin alignment, privacy
flags, and non-claims. It does not inspect the operator's home directory,
hardware, private key paths, or current-machine custody state, and it does not
prove key custody, revocation state, production trust-registry truth, external
attestation, sovereign recognition, or current-machine governance.
Artifact verification exposes the trusted registry summary as
`trusted_issuer_registry_recognition` so downstream smoke and readiness reports
consume the proof-pack component, not a reconstructed Product Proof Path claim.
Artifact verification also exposes the downstream refusal summary as
`downstream_refusal`: proof-pack run provenance, one recognized board with
marker-count delta one, final marker count one, exact refusal count/reasons,
all refusals unboarded, all refusal marker-count deltas zero, local hermetic
fixture evidence, false live probing, and no live downstream or
production-recognition claim.
The protected-records components carry the fixture deployment profile, adapter
profile, adapter route, callable local adapter action, CLI-process conformance
boundary, downstream service process boundary, persistent
consumed-receipt-store replay refusal, append-only ledger model, bounded
service-state model, per-adapter/service replay scope, action class,
downstream boundary, profile contract route, replay policy, required receipt
fields, accepted write, refused write count, downstream-service refusal for
missing, unrecognized/detail-mismatch, invalid, unknown-issuer, stale, and
direct-API attempts, executed service preflight profile id/SHA/status, case
counts, wrong-policy refusal, refusal summary, open boundaries, and
non-claims, runtime-profile
preflight profile id/SHA/status, activation plan id/SHA, activation plan
profile-SHA match, activation preflight execution, nested runtime-profile proof
case and boundary counts, rollback/deletion/replacement refusal,
agent-supplied authority-material refusal, explicit install requirement, and
known ungoverned boundaries so a fresh evaluator can see the one-terminal claim
directly from the portable proof pack. The service preflight runs as local
disposable fixture evidence. The runtime-profile preflight identity component
stays metadata-only, while the activation-plan preflight component executes the
bounded runtime-profile preflight/proof under explicit fixture plan and profile
files. The runtime-local-activation component executes the local disposable
activation proof: it validates explicit plan/profile inputs, writes
launcher-owned disposable runtime config inside the proof harness, starts local
JSONL child service processes, accepts one recognized `records.write`, and
refuses replay, missing, invalid, unknown-issuer, retired-issuer,
missing-issuer-status, stale, wrong-policy, wrong-domain, wrong-tool,
wrong-audit-event, wrong-detail, non-boarding, direct-API, and
agent-supplied-authority requests before runtime-state mutation. The proof-pack
runtime-local-activation component also carries an `active_profile_selection`
summary for the first `records.write` terminal. That summary states that the
explicit pinned runtime profile was selected inside the local disposable proof
harness and records `selects_latest_profile=false`,
`persistent_runtime_profile_installed=false`, `live_runtime_profile_checked=false`,
and `hook_configuration_written=false`. The proof pack does not install a
persistent runtime profile, write hook configuration, write machine or
production configuration, select a live/current-machine profile, select
`--latest`, or inspect live/current machine state.
The runtime-profile-installation component creates only a launcher-owned
disposable proof root, copies the pinned runtime profile, writes the active
profile index, selects by explicit id and SHA, runs the same bounded
runtime-profile proof, and records that request-stream attempts to supply
installed profile state, runtime config, runtime profile, or recognition rule
are refused before mutation. It records
`selects_latest_profile=false`, `persistent_runtime_profile_installed=false`,
`hook_configuration_written=false`, `user_config_written=false`, and
`machine_config_written=false`.
It is a convenience path for a fresh evaluator to reproduce the bounded local
evidence without knowing every individual command.

`--artifact <file>` writes a portable JSON envelope containing the validated
proof-pack report plus a SHA-256 over the canonical artifact body. `--artifact
-` prints that envelope to stdout instead of writing a file. The checksum makes
the local proof pack easier to hand to another verifier; it is integrity
metadata for the bounded fixture proof, not external attestation.

`verify --input <file|->` reads a supplied artifact, recomputes the canonical
body SHA-256, validates the embedded proof-pack boundaries, and prints a bounded
verification result. That result includes an embedded simulated-human
authorization summary derived from the verified artifact: the proof ran inside
the proof pack, the evidence model is a local hermetic fixture, the approval
channel is `simulated-human-fixture`, the authorized case boarded, pending and
denied cases did not board, live probing is false, and the summary is not live
approval-channel health or real human approval evidence. It also includes an
embedded key-state sample summary, an embedded service-profile preflight summary
derived from the verified artifact, and an embedded receipt-verifier boundary
summary: valid receipt accepted under the supplied key, wrong public key
reported as `UNKNOWN-SIGNER`, tampering reported as `INVALID`, and no
issuer-recognition/key-custody/revocation/downstream-recognition claim. The
downstream refusal summary preserves one recognized board with marker-count
delta one, final marker count one, exact refusal count/reasons, all refusals
unboarded, all refusal marker-count deltas zero, local hermetic fixture
evidence, false live probing, and no live downstream or production-recognition
claim. The
service-profile preflight summary includes preflight type, fixture evidence
model, case count, sanitized case summaries, direct-API-with-receipt refusal
reason, zero state mutation, and no-live/no-production/no-external-attestation
flags. It also exposes the embedded runtime-local-activation summary:
local activation applied, disposable config written, no persistent config or
hook write, local child service started, the expanded runtime refusal taxonomy,
direct-API-with-receipt refusal, embedded active-profile selection, and no
live/production/external claim. It does not run the proof pack, run current-
machine key-state, generate new evidence, inspect local runtime state, install a
persistent runtime profile, select a latest profile, or attest for an external
verifier.
It also exposes the embedded runtime-profile-installation summary: disposable
install root created, profile copy written, active profile index written,
profile selected from the disposable root by explicit id and SHA, request
authority guard refused, no latest selection, no persistent profile install, no
hook/user/machine configuration, and no live/production/external claim.
`verify --sample` verifies the committed sample artifact at
`tests/fixtures/local-proof-pack-artifact-v1.json` without requiring the path to
be supplied. The sample is a stable fixture for verifier smoke tests; it is not
fresh runtime evidence.

This command does not inspect live hooks, live audit stores, runtime state,
live approval channels, live downstream systems, operator home key material, or
hardware. It does not use Telegram or prove live human approval-channel
delivery. Its approval-transport component is a local fixture model, not a live
Telegram or production transport health check. Its key-state component is a
deterministic sample, not current-machine key custody evidence. Its
runtime-local-activation component starts only local disposable JSONL child
service processes inside the proof harness. Its runtime-profile-installation
component writes only disposable proof-root files and does not alter hooks,
user config, machine config, or production config. It is not a persistent
runtime profile install, production deployment, external attestation, sovereign
recognition, current-machine governance, or coverage of unrouted surfaces.

### `zlar product-proof-path`

Historical pre-exhaustion Product Proof Path interface:

```bash
bin/zlar product-proof-path
bin/zlar product-proof-path --json
bin/zlar product-proof-path --json-out ./zlar-product-proof-path-v1.json
```

Current-source posture: fresh Product Proof Path generation is permanently
retired as `product_proof_path_fresh_generation_retired`, independently of
the mutable fixture-grant status. The description below records the
pre-retirement report contract only.

Before exhaustion, `product-proof-path` generated a fresh local proof-pack artifact, verified that
artifact, recomputed artifact verification before accepting any
artifact/verification pair in the Product Proof Path builder, and emits
`zlar-product-proof-path-v1`. Stale verification cannot be paired with a
mutated proof-pack artifact. The report is intentionally small compared with
the full proof pack. It exposes the Product Proof Path acceptance gate:

- fresh local proof-pack generated;
- proof-pack artifact verified;
- one governed `records.write` path allowed;
- missing or unrecognized paths refused before mutation;
- simulated-human authorization observed with pending and denied cases not
  boarding;
- receipt verifier boundary observed as `VALID`, `UNKNOWN-SIGNER`, and
  `INVALID`;
- trusted issuer registry recognition observed over a bundled local fixture,
  with malformed-registry input failing closed before verdict;
- downstream refusal marker boundary observed, including one recognized marker
  count delta, final marker count one, exact refusal count/reasons, all
  refusals unboarded, and all refusal marker-count deltas zero;
- fresh disposable installed-runtime-profile terminal-chain artifact
  verification observed, including binding/refusal hashes and exact trusted
  registry refusal IDs/reasons plus the terminal-chain binding's local
  `RECOGNIZED` verdict, issuer status, signature validity, registry evaluation
  facts, and contract hashes;
- local fixture deployment-profile authority bridge observed, including
  explicit profile SHA binding, no `--latest`, one recognized receipt mutation,
  18/18 zero-mutation refusals, and authority-material refusal;
- non-coverage visible through counted boundary entries and known ungoverned
  boundaries;
- no private operator state required.

The report also names the action class, checkpoint, route, downstream effect,
proof-pack body SHA-256, observed allow/refusal/receipt facts, downstream
refusal marker-count deltas, trusted issuer registry recognition fixture facts,
and false stronger-claim flags. The
trusted issuer registry section records
`trusted_issuer_registry_recognition`, `registry_type=trusted-receipt-issuers-v2`,
`registry_evidence_model=bundled-local-fixture-no-secret-registry-contract`,
`registry_contract_evidence=no-secret-registry-contract-v2`,
`registry_public_safe_summary_sha256`, `live_probing=false`,
`registry_fixture_validated=true`, `registry_fixture_evaluated=true`,
`registry_to_recognition_rule_evaluated=true`,
`registry_evaluation_result_type=downstream-recognition-rule-v1`,
`verdict=RECOGNIZED`, `issuer_status=active`, `signature_valid=true`,
`malformed_registry_fail_closed_before_verdict=true`, and false live-registry,
live-issuer-status, key-custody, revocation, production-registry,
production-downstream-recognition, production-authority, sovereign-recognition,
public-attestation, real-non-operator-review, and current-machine-governance
flags.
The terminal-chain boundary section records verified terminal-chain artifact
evidence, payload/body SHA-256, generated preflight/service-proof binding,
trusted-issuer registry recognition binding/refusal hashes, the binding's local
`RECOGNIZED` verdict, issuer status, signature validity, registry evaluation
facts, contract hashes, exact local trusted-registry refusal IDs/reasons, exact
grouped recognition-refusal case IDs, `registry_public_key_material_included=false`,
`receipt_envelope_included=false`,
`cryptographic_evidence_reproducible_from_artifact=false`,
`current_machine_governance_proven=false`, `external_attestation=false`, and
known open boundaries.
For `v3.4.48+`, the deployment-profile authority bridge section records
deployment profile SHA, selected runtime profile SHA, explicit id-and-SHA
selection, no `--latest`, verified preflight artifact, one recognized receipt
mutating once, 18/18 refusal cases before mutation, agent/request authority
material refused, direct API refused, `current_machine_governance=false`,
`production_authority=false`, `external_attestation=false`, and
`unrouted_surface_coverage=false`.
For `v3.4.49+`, it also records the five deployment-profile authority refusal
case IDs and proves they refused before service proof started.
For `v3.4.50+`, proof-smoke and North Star readiness also preserve the
terminal-chain/artifact-verification mirror of those same five refusal cases.
Current local post-v3.4.50 proof-hardening also preserves the proof-pack
downstream-refusal marker boundary through Product Proof Path and North Star
readiness summaries: recognized marker-count delta one, final marker count one,
exact refusal count/reasons, all refusals unboarded, and all refusal
marker-count deltas zero.

`--json` prints the report to stdout. `--json-out <file>` writes the report to
a new file and refuses to overwrite an existing path.

This command is local fixture evidence only. It does not inspect live hooks,
live audit stores, runtime state, approval channels, downstream systems,
operator home key material, or hardware. It does not use Telegram, prove real
human approval, install or activate a persistent runtime profile, write hook,
user, machine, or production configuration, start a live production service,
prove current-machine governance, prove production downstream recognition,
create external attestation, prove enterprise readiness, prove sovereign
recognition, live trust-registry state, live issuer status, key custody,
revocation truth, production trust-registry state, all-MCP governance, or prove
coverage of unrouted surfaces.

### `zlar proof-smoke`

Source-checkpoint posture: the source-recorded exhausted-status guard precedes
fresh smoke execution and acceptance of the old fixture-rightful smoke schema.
Caller-authenticated current runtime refusal is unproven. Use the static
coverage and consequence lifecycle maps for the source-backed boundary. The
commands below are retained as historical interface documentation; no current
successful execution is claimed.

```bash
bin/zlar proof-smoke
bin/zlar proof-smoke --json
bin/zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar coverage --sample
```

Before grant exhaustion, this was the shortest committed-fixture check for an evaluator who wanted to verify
the sample artifacts and report inputs without knowing fixture file paths. It is
committed local fixture evidence only; it does not regenerate proof-pack or
preflight artifacts. It does not
run the proof pack, generate fresh
proof-pack, key-state, receipt-verifier, service-profile preflight,
activation-preflight, runtime-local-activation, runtime-profile-installation, or
installed-runtime-profile preflight evidence. It runs fresh local
installed-runtime-profile recognition and disposable child-service proofs plus
service artifact verification plus fresh installed-runtime-profile terminal
chain proof and artifact verification from committed sample input only; it does
not inspect
live or non-sample recognition state,
start a live runtime service, inspect live hooks, audit stores, operator home
key material, or hardware, prove
live/current-machine governance, prove active issuer status or key custody,
prove production deployment, provide external attestation, prove sovereign
recognition, or cover unrouted surfaces.

Full smoke and verification forms:

```bash
bin/zlar proof-smoke
bin/zlar proof-smoke --json
bin/zlar proof-smoke verify --historical --input tests/fixtures/proof-smoke-v1-report.json --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar proof-smoke verify --historical --input tests/fixtures/proof-smoke-v1-report.json --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80 --json
bin/zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80 --json
bin/zlar proof-smoke verify --historical --input - --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
```

The smoke test verifies the committed sample proof-pack artifact with
`zlar local-proof-pack verify --sample`, verifies the committed service-profile
preflight sample artifact with
`zlar protected-records-service-preflight verify --sample`, verifies the
committed activation preflight sample artifact with
`zlar protected-records-runtime-activation-preflight verify --sample`, then
verifies the committed runtime-local-activation sample artifact with
`zlar protected-records-runtime-local-activation verify --sample`, verifies the
committed runtime-profile-installation sample artifact with
`zlar protected-records-runtime-profile-installation verify --sample`, verifies
the committed installed-runtime-profile preflight sample artifact with
`zlar protected-records-installed-runtime-profile-preflight verify --sample`,
runs the installed-runtime-profile recognition proof with
`zlar protected-records-installed-runtime-profile-recognition-proof --sample`,
runs the installed-runtime-profile service proof with
`zlar protected-records-installed-runtime-profile-service-proof --sample`,
verifies that service-proof artifact with
`zlar protected-records-installed-runtime-profile-service-proof verify --sample`,
then runs the installed-runtime-profile terminal chain with
`zlar protected-records-installed-runtime-profile-terminal-chain --sample` and
verifies that terminal-chain artifact with
`zlar protected-records-installed-runtime-profile-terminal-chain verify --sample`,
then ran the fixture-input coverage map. The current committed coverage map
shows `4/6` governed counted lanes. The
`protected-records.service-profile.records.write` service-profile preflight
artifact lane, the `protected-records.runtime.records.write` runtime-local
artifact lane, bash, and routed MCP remain governed. The
`protected-records.runtime.profile-installation.records.write` disposable
profile-installation artifact lane and the
`protected-records.installed-runtime-profile.terminal-chain.records.write`
terminal-chain artifact lane are open because current receipt capability and
fixture-rightful projection are false under the exhausted grant.
It also carries the coverage-map airport summaries for supplied last decision,
last receipt, issuer/recognition anchor, and known boundaries.
`--json` runs the same twelve checks with their JSON outputs and wraps them in a
`zlar-proof-smoke-v1` report for CI or evaluator tooling. The report contract
requires the local proof-pack artifact verifier's embedded key-state sample
summary, including privacy flags, software-rooted policy/constitution posture,
no key-custody/revocation/production-trust-registry/current-machine-governance
claim, and no current-machine key-state run during artifact verification. It
also requires the embedded simulated-human authorization summary, including the
local hermetic fixture model, `simulated-human-fixture` approval channel,
authorized case boarded, pending and denied cases not boarded, false
live-probing flag, and no live approval-channel or real human approval claim. It
also requires the embedded receipt-verifier boundary summary, including
`VALID`, `UNKNOWN-SIGNER`, and `INVALID` distinction and no
issuer-recognition/key-custody/revocation/downstream-recognition claim. It
also requires the embedded downstream-refusal summary from local proof-pack
artifact verification, including one recognized board with marker-count delta
one, final marker count one, exact refusal count/reasons, all refusals
unboarded, all refusal marker-count deltas zero, local hermetic fixture
evidence, false live probing, and no live downstream or production-recognition
claim. It
also requires the embedded service-profile preflight
summary, including the executed fixture preflight case count and
direct-API-with-receipt refusal reason and zero state mutation, plus
no-live/no-production boundary flags, and the embedded runtime-local-activation
summary, including local activation applied, disposable config written, no
persistent config or hook write, local child service started, the expanded
runtime refusal taxonomy, direct-API-with-receipt refusal, and
active-profile selection with no
latest-profile selection, no live runtime profile check, and no persistent
runtime profile install, without rerunning the proof pack.
It also requires the embedded runtime-profile-installation summary, including
disposable install root created, profile copy written, active index written,
profile selected from the disposable root by explicit id and SHA, request
authority guard refused, no latest selection, no persistent profile install,
and no hook/user/machine configuration, without rerunning the proof pack.
It also
requires the standalone service-profile preflight sample artifact verification,
including the 11/11 case count, wrong-policy refusal reason,
direct-API-with-receipt refusal reason, zero state mutation, and
no-live/no-production/no-external-attestation flags, without rerunning the
preflight. It also requires the runtime-local-activation sample
artifact verification, including local activation applied inside the proof
harness, disposable runtime config written, persistent runtime config and hook
configuration not written, local JSONL child service started, the expanded
runtime refusal taxonomy, direct-API-with-receipt refused, and agent-supplied
authority material refused, without rerunning local activation.
It also requires the runtime-profile-installation sample artifact verification,
including disposable install root created, profile copy written, active index
written, profile selected by explicit id and SHA, request authority guard
refused, the expanded runtime refusal taxonomy, no latest selection, no
persistent profile install, no hook/user/machine configuration, and local JSONL
child service proof run, without
rerunning disposable installation.
It also requires the installed-runtime-profile preflight sample artifact
verification, including read-only selector-integrity validation, explicit
install root/profile id/profile SHA requirements, active index read, installed
profile read, installed profile contract validation, selected profile
recognition-contract preservation, profile selected by explicit id and SHA, no
latest selection, no installation, no activation, no service start, no
hook/user/machine configuration, no downstream refusal proof, and no
current-machine governance proof, without rerunning the preflight.
It also requires the installed-runtime-profile recognition proof, including one
matching `records.write` receipt boarded, all 18 selected-profile refusal cases
refused before fake effect, the source preflight's downstream-refusal claim
remaining false, no runtime service start, no current-machine governance, and no
production downstream recognition.
It also requires the installed-runtime-profile service proof, including one
matching `records.write` receipt boarded through a local disposable JSONL
runtime-service child process, all 18 selected-profile refusal cases refused
before service-state mutation, disposable runtime config written inside the
proof harness, no persistent runtime config, the source preflight's downstream-
refusal claim remaining false, no install, no activation, no current-machine
governance, and no production downstream recognition.
It also requires the installed-runtime-profile service-proof artifact
verification, including the proof payload type, artifact body SHA-256 bound to
the service proof carried in the same report, restart replay refusal, consumed-
store integrity case count, store-and-anchor rollback case count, before-
mutation refusal result, exact refusal taxonomy SHA-256, current-machine false
flag, and production-downstream false flag.
It also requires the installed-runtime-profile terminal chain, including
generated installed-root preflight, generated preflight consumption by the
service proof, generated service-proof artifact verification, service proof
binding to generated preflight, service artifact verification binding to the
generated service proof, one recognized write boarded, missing and invalid
receipt refusal before mutation, all 18 selected-profile refusals before
mutation, no persistent install or activation, no hook/user/machine
configuration, no current-machine governance, and no production downstream
recognition. It also requires the terminal-chain artifact verification,
including artifact body SHA-256 bound to the terminal-chain payload carried in
the same report, the same refusal taxonomy SHA-256 carried by the terminal
chain, and the same false stronger-claim flags.
For `v3.4.25+`, the report counts also preserve exact terminal-chain
recognition-refusal group case IDs: terminal-chain
`installed_runtime_profile_terminal_chain_recognition_refusal_group_count=3`,
`installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count=18`,
`installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids`,
and the matching terminal-chain artifact-verification `group_count`,
`case_count`, and `case_ids` fields.
For `v3.4.26+`, the North Star readiness Enterprise Deployment Profile and
Downstream Recognition Rule observed summaries mirror the same preserved
case-ID contract so verifier-facing puzzle pieces cannot drift back to
hash-only recognition-refusal group summaries while counts remain exact.
For `v3.4.28+`, terminal-chain evidence and its portable artifact must also
preserve nested generated preflight and service-proof artifacts, and the
release-forward dry run must refuse forged inner preflight and service-proof
hashes even after recomputing outer terminal-chain artifact integrity.
For `v3.4.30+`, proof-smoke and North Star readiness must also preserve the
verifier-owned `nested_artifact_binding` summary from terminal-chain artifact
verification, not a reconstructed binding from raw embedded artifacts.
For `v3.4.37+`, proof-smoke and North Star readiness must also preserve the
terminal-chain trusted issuer registry recognition binding from both
terminal-chain evidence and terminal-chain artifact verification: stable
registry/receipt contract hashes, `registry_receipt_contract_hash_bound=true`,
and false embedded-key, embedded-envelope, and artifact-only cryptographic
reconstruction flags.
For `v3.4.38+`, that preserved binding must also carry the terminal-chain-local
trusted-registry refusal case count, exact refusal reasons, `all_refused=true`,
and the canonical refusal hash while keeping the full false-boundary field
contract false.
For `v3.4.39+`, proof-smoke and North Star readiness must also expose those
refusal fields in first-class report counts, and North Star readiness must
mirror them into the Enterprise Deployment Profile and Downstream Recognition
Rule observed summaries.
For `v3.4.39+` targets, release-forward verifier packets must also expose those same
fields in `terminal_chain_refusal_evidence` and in `DRY-RUN-RESULT.md`, with
matching terminal-chain/artifact-verification refusal hashes.
For `v3.4.50+` targets, proof-smoke, North Star readiness, and release-forward
verifier packets must also expose the terminal-chain deployment-profile
authority-refusal mirror: exact five case IDs, before-service-proof refusal,
before-mutation refusal, service-proof-not-started, and false stronger claims.
Current local post-v3.4.50 proof-hardening also requires proof-smoke and North
Star readiness to preserve the local proof-pack downstream-refusal marker
boundary: recognized marker-count delta one, final marker count one, exact
refusal count/reasons, all refusals unboarded, and all refusal marker-count
deltas zero.
The committed sample report at `tests/fixtures/proof-smoke-v1-report.json` is
validated by `lib/proof-smoke-report.mjs` and exists to lock the report shape,
not to create new evidence.

`verify --input <file|->` validates a supplied `zlar-proof-smoke-v1` report
against the same strict contract. `verify --sample` validates the committed
sample report at `tests/fixtures/proof-smoke-v1-report.json` without requiring
the path to be supplied. Both forms can emit a
`zlar-proof-smoke-report-verification-v1` JSON result. They do not rerun the
smoke test, regenerate evidence, inspect local runtime state, or turn a sample
report into external attestation.

This command does not run the proof pack, generate fresh proof-pack evidence,
generate fresh key-state evidence, generate fresh receipt-verifier evidence,
generate fresh service-profile preflight evidence, generate fresh
activation-preflight evidence, generate fresh runtime-local-activation
evidence, generate fresh runtime-profile-installation evidence, generate fresh
installed-runtime-profile preflight evidence. It runs fresh local
installed-runtime-profile recognition, disposable child-service, and
terminal-chain proofs plus artifact verification from committed sample input
only; it does not inspect
live or non-sample recognition state,
start a live runtime service, inspect live hooks, inspect live audit stores,
inspect runtime state, inspect live downstream systems, or attest for an
external verifier. It is a local fixture smoke test only.

### `zlar north-star-readiness`

Source-checkpoint posture: the source-recorded exhausted-status guard precedes
v1 readiness composition and v1 report acceptance. Caller-authenticated current
runtime refusal is unproven. A new artifact-bound schema is required; the
historical interface below remains available only at its pinned source/tag.

Build a bounded machine-readable closure report for the current North Star
proof path:

```bash
bin/zlar north-star-readiness --sample
bin/zlar north-star-readiness --sample --json
bin/zlar north-star-readiness --evidence-dir . --release-tag v3.3.106 --json
bin/zlar north-star-readiness --evidence-dir . --release-tag v3.4.2 --private-verifier-result-verification zlar-private-verifier-result-verification-v1.json --json
bin/zlar north-star-readiness --evidence-dir . --private-verifier-zip-result-verification zlar-private-verifier-zip-result-verification-v1.json --json
bin/zlar north-star-readiness --evidence-dir . --release-tag v3.4.59 --public-artifact-verifier-result-verification zlar-public-artifact-verifier-result-verification-v1.json --json
bin/zlar north-star-readiness --evidence-dir . --release-tag v3.4.59 --public-external-attestation-result-verification zlar-public-external-attestation-result-verification-v1.json --json
```

`--sample` derives the report from committed sample verifications:
`proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80`, `local-proof-pack verify --sample`, the
service-profile preflight sample verifier, runtime-local-activation sample
verifier, runtime-profile-installation sample verifier, the
installed-runtime-profile preflight sample verifier, the
installed-runtime-profile service proof, the installed-runtime-profile service-
proof artifact verifier, the installed-runtime-profile terminal chain, the
installed-runtime-profile terminal-chain artifact verifier, and
`coverage --sample --require-governed --json`.

`--evidence-dir <dir>` reads the same JSON artifacts from a release-forward
dry-run directory. When present, it also consumes
`zlar-trusted-receipt-issuer-recognition.json` and the malformed-registry error
artifact so the trusted-issuer fixture and schema-contract boundary are
included in the readiness packet. When present, it also consumes
`zlar-verifier-kit-reproducibility-v1.json` so the readiness report records
same-source, same-test-publisher-key verifier-kit reproducibility and public
artifact hashes without upgrading External Attestation, production publisher
custody, production signing identity, public release publication, or v3.4.0
readiness. When present, it also consumes
`zlar-verifier-kit-public-distribution-v1.json` so the readiness report can
name public-distribution blockers, including
`ready_for_public_distribution_claim=false`, without uploading assets or
upgrading the claim. Supplied public-distribution JSON is validated through the
same verifier-kit public-distribution report validator used by
`zlar verifier-kit-public-distribution`, and when `--release-tag` is supplied
the report tag must match that pinned target before readiness consumes it.

When present, `--evidence-dir <dir>` also consumes
`zlar-active-persistent-profile-lifecycle-v1.json` only if it is paired with
`zlar-active-persistent-profile-lifecycle-source-binding-v1.json`. The binding
manifest must use the historical supplied local active-persistent-profile
lifecycle evidence class, name the lifecycle report basename and SHA-256, name
the four source report basenames and SHA-256s, and keep the boundary flags
`non_scoring=true`, `current_installation=false`,
`product_proof_path_completion=false`, and
`production_downstream_recognition=false`. Readiness rebuilds the lifecycle
report from the four source reports and refuses missing source reports, hash
drift, lifecycle summary drift, path-shaped labels, or ambiguous binding. When
accepted, readiness records the supplemental evidence as
`historical_supplied_local_active_persistent_profile_lifecycle` and does not
increase `proven_count`, complete Product Proof Path, complete Enterprise
Deployment Profile, prove a current active installation, or create production
downstream recognition.

The product proof path also records the simulated-human authorization summary
from local proof-pack artifact verification. That proves only that the committed
local fixture boarded the authorized case and refused pending/denied boarding in
the artifact contract. It does not prove live approval-channel health, Telegram
delivery, or real human approval.

With `--evidence-dir`, `--release-tag <vX.Y.Z>` names the pinned
release-forward target so the readiness report can record the bounded
`private_verifier_result_sample` manifest pointer contract for `v3.3.104+`
targets. This reports private-intake sample discoverability only. It does not
read the dry-run manifest, does not create a circular hash, does not include
the generated private-intake sample files in core artifact hashes, and does not
create public external attestation or prove non-operator review. For
`v3.3.107+` dry-run targets, `DRY-RUN-RESULT.md` also summarizes the
readiness report-side pointer alongside the manifest-side pointer for human
review without widening the claim boundary.
For `v3.4.34+` dry-run targets, `DRY-RUN-RESULT.md` also summarizes private
result verification evidence: verification verdict, recomputed evidence-dir
hash status, artifact count, sample/non-operator boundary, and false public
attestation, public attribution, and public non-operator-review flags. The
generated sample keeps `private_non_operator_pass_validated=false`; it is not a
real non-operator reply and is not public external attestation.
For `v3.4.35+` dry-run targets, `DRY-RUN-RESULT.md` also summarizes trusted
issuer registry recognition evidence: recognized fixture verdict, supplied
registry type, fixture evidence model, `live_probing=false`, active issuer
status, signature validity, malformed-registry fail-closed result, and false
live-registry, custody, revocation, production-recognition, production-authority,
sovereign-recognition, non-operator-review, and public-attestation flags.
When the evidence directory contains
`zlar-trusted-receipt-issuer-completion-proof-v1.json`,
`north-star-readiness` verifies and consumes it as bounded private-core Trusted
Receipt Issuer completion evidence. That can move the Trusted Receipt Issuer
puzzle piece to `operator_owned_private_core_completion_proven` while still
keeping public external attestation, production authority, production downstream
recognition, key custody, current-machine governance, and unrouted-surface
coverage false. This supplied proof may select
`protected-records.private-operator.records-terminal.records.write`; the
readiness report's `selected_terminal` remains the profile-installation surface.
For `v3.4.39+` dry-run targets, `DRY-RUN-RESULT.md` also summarizes
terminal-chain trusted-registry refusal preservation: the two case IDs, two
reason codes, `all_refused=true`, matching chain/artifact refusal hashes, and
observed-summary preservation. This does not add live trust-registry or
production authority evidence.

With `--evidence-dir`, `--private-verifier-result-verification <file>` may
point to sanitized `zlar-private-verifier-result-verification-v1` JSON produced
by `zlar private-verifier-result verify --json`. The readiness report consumes
only that verification output, not the raw private reply, verifier identity, or
contact channel. If the verification is a private non-operator `PASS` for the
same release tag with evidence-dir hashes recomputed, and with any required
evidence-dir content contract verified, the External Attestation piece records
`private_non_operator_pass_validated=true` while keeping
`public_external_attestation=false`,
`non_operator_review_proven=false`, and
`non_operator_review_publicly_claimed=false`. This is internal private intake
evidence only. It is not a signed or published attestation and does not permit
public attribution.

With `--evidence-dir`, `--private-verifier-zip-result-verification <file>` may
point to sanitized `zlar-private-verifier-zip-result-verification-v1` JSON
produced by `zlar private-verifier-zip-result verify --json`. The readiness
report consumes only that verification output, not the raw private reply,
verifier identity, contact channel, local private paths, or returned ZIP bytes.
If the verification recomputed the returned evidence, matched every declared
checksum, proved all required steps exited zero, accepted only the known
`SHA256SUMS.err` directory warning, preserved `NOT_READY_FOR_V3_4_0`, and kept
public/privacy boundaries false, the External Attestation piece records
`private_personally_connected_zip_result_validated=true` while keeping
`public_external_attestation=false`, `non_operator_review_proven=false`,
independent review false, arm's-length review false, and public attribution
false. This is internal private intake evidence only. It is not a signed or
published attestation, not independent review, not git clone source access, and
not public attribution.

With `--evidence-dir`, `--public-external-attestation-result-verification
<file>` may point to `zlar-public-external-attestation-result-verification-v1`
JSON produced by `zlar public-external-attestation-result verify --json`. The
readiness report consumes only that verification output as intake-only
non-scoring evidence. It can record that a bounded signed/published attestation
verification file was valid, but it still keeps the External Attestation puzzle
piece `unproven` and keeps `public_external_attestation=false`,
`non_operator_review_proven=false`, public attribution false, production
authority false, enterprise readiness false, and public claim movement false
until a separate authority lane promotes the claim.

The report emits `zlar-north-star-readiness-v1`, with seven puzzle pieces:
product proof path, governed surface coverage map, enterprise deployment
profile, trusted receipt issuer, downstream recognition rule, external
attestation, and public claim boundary. For `v3.4.10+` evidence, the Product
Proof Path piece consumes `zlar-product-proof-path-v1.json` when present and
fails closed if the report weakens an acceptance gate or widens a forbidden
claim. The Product Proof Path summary also preserves fixture-bound trusted
issuer registry recognition facts and requires live-registry, live-issuer-status,
key-custody, revocation, production-registry, production-recognition,
production-authority, sovereign-recognition, public-attestation, and
real-non-operator-review flags to remain false. For `v3.4.13+` evidence, the
Enterprise Deployment Profile piece can
consume the installed-runtime-profile service proof and record
`local_disposable_profile_refusal_proven` when the local disposable child
service boarded the matching write, refused same-process and restart replay,
refused consumed-store/local-anchor/witness integrity failures, refused
store-plus-anchor rollback when a launcher-owned local witness remained ahead,
and refused all selected-profile cases before mutation while current-machine
and production claims stay false. For `v3.4.14+` evidence, readiness also
requires and consumes
`zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`
and records `installed_runtime_profile_service_artifact_verification_required=true`
plus
`installed_runtime_profile_service_artifact_verification_preserved=true` only
when that verifier output keeps the artifact hash bound to the supplied service
proof, proof payload, replay refusal, rollback counts, before-mutation refusal
result, and false stronger-claim flags intact. For `v3.4.18+` evidence, it
also records
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required=true`
plus
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved=true`
only when the verifier keeps the exact service-proof artifact refusal taxonomy
hash bound to case ids, reason codes, and before-mutation facts. For
`v3.4.19+` evidence, it also records
`installed_runtime_profile_recognition_contract_digest_required=true`,
`installed_runtime_profile_recognition_contract_digest_preserved=true`, and the
canonical `installed_runtime_profile_recognition_contract_sha256` only when
the recognition-contract digest remains identical across preflight, service
proof, service-proof artifact verification, terminal chain, and terminal-chain
artifact verification. For
`v3.4.15+` evidence,
readiness also requires and consumes
`zlar-installed-runtime-profile-terminal-chain-v1.json` and
`zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`
and records `installed_runtime_profile_terminal_chain_required=true` plus
`installed_runtime_profile_terminal_chain_preserved=true` only when the chain
keeps generated installed-root preflight, generated preflight consumption,
generated service-proof artifact verification, proof/artifact hash binding,
recognized write boarding, missing/invalid receipt refusal, all selected-profile
refusals before mutation, and false persistent-install/current-machine/
production flags intact.
For `v3.4.22+` release-forward evidence, readiness also records
`installed_runtime_profile_terminal_chain_named_receipt_refusals_required=true`
and
`installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved=true`
only when the terminal chain and artifact verifier preserve the same canonical
`named_receipt_refusals_sha256` for missing, invalid, stale, unknown-issuer,
wrong-policy, wrong-domain, and wrong-tool refusal cases.
For `v3.4.23+` release-forward evidence, readiness also records
`installed_runtime_profile_terminal_chain_recognition_refusal_groups_required=true`
and
`installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved=true`
only when the terminal chain and artifact verifier preserve the same canonical
`recognition_refusal_groups_sha256` for no usable recognized receipt authority,
recognized receipt scope mismatch, and route/request authority material refusal
groups. The
release-forward verifier packet for `v3.4.24+` additionally requires
`recognition_refusal_group_case_ids_required=true` and prints the exact
case-id lists for each recognition-refusal group in `DRY-RUN-RESULT.md`. The
release-forward readiness contract for `v3.4.25+` additionally requires
`installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required=true`
and
`installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved=true`
with `group_count=3`, `case_count=18`, and exact grouped case IDs for both the
terminal-chain and terminal-chain artifact-verification report counts. For
`v3.4.26+`, the Enterprise Deployment Profile and Downstream Recognition Rule
observed summaries must also mirror that same preserved case-ID contract. The
release-forward readiness contract for `v3.4.28+` additionally requires
terminal-chain nested artifact preservation and refused forged inner preflight
and service-proof hashes after recomputing outer terminal-chain artifact
integrity. For `v3.4.30+`, it also requires the verifier-owned
`nested_artifact_binding` summary, including nested body hashes, verified flags,
binding booleans, and false stronger-claim flags. The
Product Proof Path piece for `v3.4.45+` also preserves the terminal-chain
boundary consumed by Product Proof Path and fails closed if terminal artifact
verification, binding/refusal hashes, local `RECOGNIZED` verdict, registry
evaluation facts, contract hashes, exact trusted-registry refusal IDs/reasons,
public-key omission, receipt-envelope omission, current-machine false boundary,
or external-attestation false boundary drifts. For `v3.4.46+`, it also fails
closed if the Product Proof Path boundary stops preserving the exact grouped
recognition-refusal case-ID map. For `v3.4.49+`, it also fails closed if the
Product Proof Path deployment-profile authority bridge stops preserving the
five pre-service authority refusal cases. For `v3.4.50+`, it also fails closed
if terminal-chain/proof-smoke/readiness evidence stops mirroring those same
five refusal cases. Current local post-v3.4.50 proof-hardening also fails
closed if the Product Proof Path summary drops the proof-pack downstream
refusal marker boundary: recognized marker-count delta one, final marker count
one, exact refusal count/reasons, all refusals unboarded, and all refusal
marker-count deltas zero. Current local post-v3.4.60 proof-hardening also fails
closed if the no-secret trusted issuer registry artifact contract stops naming
the registry identity/version, `live_probing=false`, lifecycle status, effective
window, custody posture declaration, revocation or compromise transition
metadata, accepted policy/domain/tool/outcome, replay/freshness requirements,
false forbidden-claim flags, non-claims, and public-safe summary hash. This
contract evidence remains a local fixture contract; it is not live registry
state, live issuer status, key custody, revocation truth, production downstream
recognition, production authority, public external attestation, enterprise
readiness, sovereign recognition, or a public claim upgrade. The
Downstream Recognition Rule piece records the same observations while retaining
its `local_fixture_proven` status. It intentionally reports
`NOT_READY_FOR_V3_4_0` and keeps the v3.4 gate closed until the evidence class
changes: a non-operator verifier attests a pinned release-forward run, a named
real deployment refuses missing or unrecognized receipts at the downstream
boundary, or the verifier kit reaches public distribution posture with
reproducible-build evidence, live release-asset publication evidence, and public
artifact hashes. When that third trigger is supplied, the result may become
`READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION`. That is a boundary-release
readiness signal only; it does not prove external attestation, production
authority, enterprise readiness, or sovereign recognition.

When a private verifier-result verification JSON is supplied, the External
Attestation puzzle remains unproven and private/internal. For future
`v3.4.51+` local private-intake contracts, its summary also preserves
`downstream_refusal_all_refusals_unboarded`, `downstream_refusal_reasons`,
`north_star_downstream_refusal_all_refusals_unboarded`, and
`north_star_downstream_refusal_reasons` from the private verification result
while keeping public attestation, public attribution, and public non-operator
review false.

This command is a closure/readiness audit over bounded local and release-
forward evidence. With default fixture or no-assets release-forward evidence,
it does not prove v3.4.0 readiness. With live public verifier-kit distribution
evidence, it may prove only
`READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION`. It does not prove external
attestation, non-operator review, production authority, enterprise readiness,
sovereign recognition, current-machine governance, live hooks, live MCP
coverage, live approval-channel health, live trust-registry state, key custody,
revocation truth, production downstream recognition, persistent runtime profile
installation, production service deployment, all-MCP governance, or coverage of
unrouted surfaces.

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

Interactive setup for Telegram approval. Prompts for bot token and chat ID, then writes them to local ignored config files (`.env` and `etc/gate.json`). Do not commit real Telegram identifiers.

```bash
zlar telegram
```

Prerequisites (set up via the Telegram client first):
1. Create a bot via @BotFather, get the token
2. Get your chat ID via @userinfobot

The command writes:
- Bot token → `${PROJECT_DIR}/.env` (mode 600)
- Chat ID + `telegram.enabled = true` → `${PROJECT_DIR}/etc/gate.json`

After this, ask-class actions can route to Telegram for approval or denial. Deny-class actions still stop.

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

Both scripts manipulate the same structural flag (`/etc/zlar/off-flag`) when
sudoers permits and the same legacy wrapper marker (`~/.claude/.gate-disabled`)
for old-wrapper compatibility. They are interchangeable for `off`, `on`, and
`reset` only when the structural off-flag can be written or removed. The main
CLI has all the diagnostic commands; the simple utility is a 30-line script
that exists for quick toggles when you don't want the full CLI overhead.

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
| Legacy wrapper marker | `~/.claude/.gate-disabled` | user | `touch` (via `zlar off`; honored only by older wrappers) |
| Structural flag | `/etc/zlar/off-flag` | root | `sudo touch` (via `zlar off` + sudoers NOPASSWD) |

For current install-managed wrappers, the structural flag is the load-bearing
off state. The legacy wrapper marker is kept visible so old installs are not
silently misread. See [`architecture-map.md`](architecture-map.md) for the
doctrinal reason the structural flag exists.

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
- [`adr/`](adr/) — architecture decision records
