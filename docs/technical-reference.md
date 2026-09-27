# ZLAR technical reference (first design)

This is the detailed technical manual for **ZLAR's first design**, the
checkpoint that sits next to the AI, together with its proof, receipt and
verifier tooling. It was moved here from the old README on 2026-09-26 so the
README could speak to people first. The words "governance" and "governed" below
are the older vocabulary; read them as "protected by ZLAR."

For the idea and the current direction, start with the [README](../README.md).
To install and test this design, see [first-design-install.md](first-design-install.md).

---

## Proof-only first look

Before installing or asking an agent to install anything, you can inspect the
protected-records boarding path with committed fixture evidence:

```bash
bin/zlar current-machine-approval-packet verify --sample
bin/zlar current-machine-approval-intake --packet tests/fixtures/current-machine-approval-packet-claude-code-v1.json
bin/zlar current-machine-approval-intake --packet tests/fixtures/current-machine-approval-packet-claude-code-v1.json --json | bin/zlar current-machine-approval-request-preview --intake -
bin/zlar protected-records-runtime-profile-installation verify --sample
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample
```

These commands are proof-only. The approval-packet verifier checks that a
selected Claude Code packet names the selected surface, hook target,
issuer/policy, receipt path, downstream refusal matrix, and explicit
non-claims before install/config authority is requested. These commands do not
install or activate ZLAR, write hooks or user/machine configuration, start a
persistent service, inspect a live records system, mint recognized receipts, or
prove current-machine governance. The approval-packet intake command runs the
verifier on an explicit packet and refuses install/config authority request
preparation unless that packet verifies as complete; it does not request or
grant install/config authority. The authority-request preview command consumes
an intake report and refuses unless `authority_request_allowed=true`,
`authority_request_made=false`, packet verification is complete, and no
install/config/live/current-machine governance claim is present. The preview
is not install authority, not an approval, and not current-machine governance
evidence.

For `v3.4.54`, the committed current-machine approval packet fixture names
`accepted_policy_version=3.4.54`. That field binds the pre-authority packet
contract for this release candidate; it is not live policy signature
verification, live issuer status, key custody, revocation truth, install
authority, or current-machine governance evidence.

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
- Public external verifier attestation; a private-by-default non-Vincent
  verifier request has been sent for `v3.3.49`, but no public external
  attestation is claimed in this repo. Any private reply or later result
  remains bounded by verifier relationship, disclosure permission, and exact
  evidence returned.

Actions that do not flow through ZLAR are not governed by ZLAR. That is the coverage model, not a footnote. A serious deployment makes routed/intercepted surfaces authoritative and blocks the rest with sandbox, OS, network, and platform controls. See [ADR-010: Interception Coverage Model](adr/ADR-010-interception-coverage.md).

## Proof and receipts

Every governed decision - allow, deny, or human-authorized - is written to a hash-chained, Ed25519-signed audit trail. The bash gate emits Worker Receipts when the helper is available. A Governed Action Receipt can be generated for a decision and verified with the public key; bash-gate v1 receipt emission is configured with `emit_receipts` / `ZLAR_EMIT_RECEIPTS=true`.

A log records what happened. A receipt records what counted as authorized
effect. The receipt is not a reconstruction of the agent's full history,
intent, context, or reasoning. It is the signed authority artifact for the
moment a routed action tried to become consequence.

Verification proves the receipt bytes match a signature under a supplied public
key and pass the receipt checks. It does not prove active issuer status, key
custody, revocation state, downstream acceptance, production deployment, or
coverage of unrouted paths. Recognition of a receipt for boarding is a separate
deployment rule. See [Trusted Receipt Issuer Boundary](trusted-receipt-issuer.md).
For v1 receipts, `bin/zlar-verify` reports `UNKNOWN-SIGNER` with exit code `3`
when the receipt `kid` does not match the supplied public key; that is distinct
from `INVALID`.

`bin/zlar key-state --json` emits a read-only local key-state report for
verifier pins and embedded signing public keys. It does not sign, request PINs,
read private key bytes, rotate or revoke keys, prove key custody, prove hardware
possession, prove production trust-registry truth, provide external
attestation, or prove current-machine governance. `bin/zlar key-state --sample
--json` emits the deterministic fixture form used by proof-pack and smoke
artifacts without inspecting operator home key material or hardware.

```bash
bin/zlar-receipt --last --key ~/.zlar-signing.key --pubkey ~/.zlar-signing.pub
bin/zlar-verify receipt.json --pubkey key.pub
```

Start with the public sample: [zlar.ai/proof-pack.html](https://zlar.ai/proof-pack.html). It is fake/scratch evidence for a bounded routed-MCP proof path, not production deployment evidence and not external attestation.

Current refusal probes from the repo root. Product Proof Path generation is
permanently retired; the one-terminal profile remains a separate
exhausted-grant refusal:

```bash
bin/zlar product-proof-path
bin/zlar protected-records-one-terminal-deployment-profile --sample
```

Local agent passenger lab from the repo root:

```bash
bin/zlar agent-passenger-lab
bin/zlar agent-passenger-lab --json
bin/zlar agent-passenger-lab --json-out ./zlar-agent-passenger-lab-v1.json
```

`agent-passenger-lab` runs a fixture-only Governed Crossing Test Harness. It
models agent roles as instrumented passengers, observes
`proposal -> action_class -> route -> authority_topology -> receipt_request -> verifier_result -> effect_or_refusal`,
and reports learning signals for coverage maps and tests. It does not spawn
live agents, inspect private reasoning, create authority, prove
current-machine or production governance, create external attestation, or
upgrade a public claim.

For the builder-facing formal-methods bridge behind those observations, see
[Builder Formal-Methods Bridge](builder-formal-methods-bridge.md).

Historical pre-exhaustion behavior: `product-proof-path` generated and verified
a fresh local proof-pack artifact, then reported the Product Proof Path
acceptance gate in one bounded JSON result:
allowed `records.write`, refused missing or unrecognized paths,
simulated-human authorization, receipt verification, trusted issuer registry
recognition over a bundled local fixture, malformed-registry fail-closed
behavior, downstream refusal marker-delta preservation, and visible
non-coverage. The Product Proof Path builder recomputes
proof-pack artifact verification before accepting an artifact/verification
pair, so stale verification cannot be paired with a mutated proof-pack artifact.
It also generated a fresh disposable installed-runtime-profile terminal chain,
verified the terminal-chain artifact, and preserved a compact public-safe
`terminal_chain_boundary` with binding/refusal hashes, exact registry refusal
IDs/reasons, the binding's local `RECOGNIZED` verdict, issuer status, signature
validity, registry evaluation facts, exact grouped recognition-refusal case IDs,
named receipt-refusal evidence including `stale_or_expired`, and false
stronger-claim flags.
For `v3.4.48+`, it also observes a local fixture deployment-profile authority
bridge: deployment profile SHA, selected runtime profile SHA, explicit
id-and-SHA selection, no `--latest`, verified preflight artifact, one
recognized receipt mutating once, 18/18 refusals before mutation,
agent-supplied authority material refused, direct API refused, and false
current-machine, production, enterprise, external, sovereign, and unrouted
flags.
For `v3.4.49+`, that bridge also records five deployment-profile authority
refusals before service proof starts: stale deployment-profile runtime SHA,
runtime-profile id mismatch, preflight profile SHA mismatch, preflight
`--latest` selection, and preflight request-stream authority material.
For `v3.4.50+`, terminal-chain evidence, terminal-chain artifact verification,
`proof-smoke`, North Star readiness, and release-forward dry-run evidence mirror
that same five-case authority-refusal list with before-service-proof refusal,
before-mutation refusal, service-proof-not-started, and false stronger-claim
flags. Current local post-v3.4.50 proof-hardening also preserves the
proof-pack downstream-refusal marker boundary through Product Proof Path,
proof-smoke, and North Star readiness summaries: recognized marker-count delta
one, final marker count one, exact refusal count/reasons, all refusals
unboarded, and all refusal marker-count deltas zero.
It is local fixture evidence only, not live approval-channel health, real human
approval, live trust-registry state, live issuer status, key custody,
revocation truth, current-machine governance, production trust-registry state,
production downstream recognition, external attestation, enterprise readiness,
sovereign recognition, all-MCP governance, or unrouted-surface coverage.

Current committed-fixture refusal and static-coverage checks from the repo root:

```bash
bin/zlar proof-smoke
bin/zlar proof-smoke --json
bin/zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample
bin/zlar protected-records-installed-runtime-profile-service-proof --sample
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample
bin/zlar coverage --sample
bin/zlar north-star-readiness --sample --json
```

These commands are fixture-bound. The positive and aggregate commands now
refuse with `authority_grant_contract_exhausted` before consequence execution;
`coverage --sample` remains a static current-state read. The coverage sample
currently records `4/6` governed counted lanes: bash
`PreToolUse`, routed MCP `tools/call`,
`protected-records.service-profile.records.write` from the committed
service-profile preflight artifact,
and `protected-records.runtime.records.write` from the committed runtime-local
activation artifact. It counts but does not govern
`protected-records.runtime.profile-installation.records.write` from the
committed disposable runtime-profile installation artifact or
`protected-records.installed-runtime-profile.terminal-chain.records.write`
from the committed installed-runtime-profile terminal-chain artifact.
Its JSON map includes supplied-evidence summaries for route/freshness/policy
status, latest decision, latest receipt, issuer or recognition anchor, and
known boundaries.
For `v3.3.76+` evaluator runs, preserve the smoke counts
`active_profile_selection_verified=true`, `active_profile_selected=true`,
`active_profile_selects_latest=false`,
`active_profile_live_runtime_profile_checked=false`, and
`active_profile_persistent_runtime_profile_installed=false`, plus the
proof-pack verifier's embedded `active_profile_selection` summary. That is
fixture-contained selection evidence only; it is not persistent runtime profile
installation, hook activation, live/current-machine profile state, production
authority, or external attestation.
For `v3.3.81+` evaluator runs, also preserve the disposable installed-profile
counts: `runtime_profile_installation_applied=true`,
`runtime_profile_installation_request_authority_guard_refused=true`,
`runtime_profile_installation_selects_latest=false`,
`runtime_profile_installation_persistent_profile_installed=false`, and
`runtime_profile_installation_hook_configuration_written=false`. These are
fixture-contained installed-state selection fields only; they do not prove a
persistent install, hook activation, live/current-machine profile state,
production authority, or external attestation.
For `v3.4.5+` evaluator runs, also preserve the read-only installed-runtime
profile preflight counts:
`installed_runtime_profile_preflight_sample_artifact_verified=true`,
`installed_runtime_profile_preflight_read_only=true`,
`installed_runtime_profile_preflight_selected=true`,
`installed_runtime_profile_preflight_selects_latest=false`,
`installed_runtime_profile_preflight_installation_performed=false`,
`installed_runtime_profile_preflight_activation_performed=false`,
`installed_runtime_profile_preflight_downstream_refusal_proven=false`, and
`installed_runtime_profile_preflight_current_machine_governance_proven=false`.
For `v3.4.6+` evaluator runs, also preserve
`installed_runtime_profile_preflight_recognition_contract_preserved=true`.
These are explicit selector-integrity fields only; they do not prove a
persistent install, runtime activation, service start, downstream refusal,
production downstream recognition, current-machine governance, production
authority, or external attestation.
For `v3.4.7+` evaluator runs, also preserve
`installed_runtime_profile_recognition_proof_verified=true`,
`installed_runtime_profile_recognition_recognized_write_boarded=true`,
`installed_runtime_profile_recognition_refusal_case_count=18`,
`installed_runtime_profile_recognition_all_refusals_before_mutation=true`,
`installed_runtime_profile_recognition_runtime_service_started=false`,
`installed_runtime_profile_recognition_current_machine_governance_proven=false`,
and
`installed_runtime_profile_recognition_production_downstream_recognition=false`.
This is local hermetic selected-profile recognition evidence only; it does not
start a live runtime service, prove current-machine governance, or prove
production downstream recognition.
For `v3.4.8+` evaluator runs, also preserve
`zlar-installed-runtime-profile-recognition-proof-artifact-v1.json` and
`zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json`.
This verifies a portable checksummed wrapper for the same local hermetic proof
without rerunning the proof or widening it into install, activation, live
governance, production downstream recognition, external attestation, enterprise
readiness, or sovereign recognition.
For `v3.4.9+` evaluator runs, also preserve
`zlar-product-proof-path-v1.json`. At those historical release targets this was
a fresh local Product Proof Path report over local fixture evidence only; it
does not prove live approval, live
trust-registry state, live issuer status, key custody, revocation truth,
current-machine governance, production trust-registry state, production
downstream recognition, external attestation, all-MCP governance, or
unrouted-surface coverage. For `v3.4.10+`
readiness runs, `north-star-readiness` consumes that report directly and
records `product_proof_path_verified=true` only when the report is `PASS`, all
acceptance gates are true, all forbidden-claim flags are false, the proof-pack
artifact is verified, live probing is false, and private operator state is not
required.
For `v3.4.11+` evaluator runs, also preserve
`zlar-installed-runtime-profile-service-proof-v1.json`,
`zlar-installed-runtime-profile-service-proof-artifact-v1.json`, and
`zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`.
This consumes the verified installed-runtime-profile preflight sample, starts a
local disposable JSONL runtime-service child process from the selected-profile
boundary, boards one matching `records.write`, and proves all 18
selected-profile refusal cases refuse before service-state mutation. It is not a
persistent install, activation, live runtime service, current-machine
governance, production downstream recognition, external attestation, enterprise
readiness, or side-door closure.
For `v3.4.14+` readiness runs, `north-star-readiness` consumes the service-proof
artifact verification directly, records
`installed_runtime_profile_service_artifact_verification_required=true`, and records
`installed_runtime_profile_service_artifact_verification_preserved=true` only
when the verifier hash matches the supplied service proof's artifact body hash
and the verifier keeps the proof payload, replay refusal, rollback-refusal
counts, before-mutation refusal result, and false current-machine/production
flags intact.
For `v3.4.18+` readiness runs, the service-proof artifact verification must
also preserve the exact selected-profile refusal taxonomy. Readiness records
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required=true`
and
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved=true`
only when the verifier's canonical `refusal_taxonomy_sha256` stays bound to
the supplied service-proof artifact verification, so case ids, reason codes,
and before-mutation facts cannot be replaced by a matching refusal count.
For `v3.4.19+` readiness runs, the installed-runtime-profile recognition
contract must also stay digest-bound from preflight through service proof,
service-proof artifact verification, terminal chain, terminal-chain artifact
verification, proof-smoke, and readiness. Readiness records
`installed_runtime_profile_recognition_contract_digest_required=true`,
`installed_runtime_profile_recognition_contract_digest_preserved=true`, and the
canonical `installed_runtime_profile_recognition_contract_sha256` only when all
supplied layers carry the same digest; missing or drifted object digests fail
closed.
For `v3.4.21+` release-forward/evaluator runs, also preserve
`zlar-verifier-kit-external-runner-diagnostics-v1.json`. Here
`external-runner` means the bundled verifier-kit helper file, not a human
external verifier. The report proves the `v3.4.20` external-runner diagnostic
hardening is present in the source-built verifier packet: the built helper hash
matches the kit manifest entry and source helper, the last-output check uses
the pipefail-safe Bash substring form instead of `grep -q`, and the
issuer-status JSON artifact is verified. It is not live probing, external
attestation, non-operator review, production authority, or proof that repo-side
regression tests are inside the built kit.
For `v3.4.15+` release-forward/evaluator runs, also preserve
`zlar-installed-runtime-profile-terminal-chain-v1.json`,
`zlar-installed-runtime-profile-terminal-chain-artifact-v1.json`, and
`zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`.
`north-star-readiness` consumes and requires the terminal-chain JSON and
artifact-verification JSON
directly, records `installed_runtime_profile_terminal_chain_required=true`, and
records `installed_runtime_profile_terminal_chain_preserved=true` only when
generated installed-root preflight, generated preflight consumption, generated
service-proof artifact verification, proof/artifact binding, recognized write
boarding, missing/invalid receipt refusal, all 18 selected-profile refusals
before mutation, refusal taxonomy SHA-256 binding, and false persistent-install/
current-machine/production flags remain intact. For `v3.4.28+`,
terminal-chain preservation also requires nested generated preflight and
service-proof artifacts and dry-run forged inner preflight and service-proof
hash refusals
even after recomputing outer terminal-chain artifact integrity. For
`v3.4.30+`, proof-smoke, North Star readiness, and release-forward evidence also
preserve the verifier-owned `nested_artifact_binding` summary from
terminal-chain artifact verification, including nested artifact body hashes,
verified flags, binding booleans, and false stronger-claim flags.
For `v3.4.39+`, proof-smoke and North Star readiness also surface the
terminal-chain trusted-registry refusal contract directly in evaluator report
summaries: case count, exact case IDs, exact reason codes, `all_refused=true`,
and refusal SHA-256 for both terminal-chain evidence and artifact verification.
North Star readiness mirrors the same fields into Enterprise Deployment Profile
and Downstream Recognition Rule observed summaries.
For `v3.4.39+` targets, release-forward verifier packets also copy that same
trusted-registry refusal summary into `DRY-RUN-MANIFEST.json` and print it in
`DRY-RUN-RESULT.md`, including the two exact case IDs/reason codes,
`all_refused=true`, matching terminal-chain/artifact-verification refusal
hashes, and observed-summary preservation.
For `v3.4.41+` targets, `DRY-RUN-MANIFEST.json` also includes
`release_forward_report_contract`, a compact machine-readable summary of the
existing release-forward dry-run report contract. `DRY-RUN-RESULT.md` renders
that manifest object as `manifest.release_forward_report_contract.*` lines for
human review; the manifest remains canonical.
For `v3.4.42+` targets, that contract also names the Product Proof Path artifact
directly: source path, SHA-256, PASS/evidence-model fields, receipt-verifier
boundary, North Star consumption, false forbidden-claim flags, and known
unrouted-records noncoverage visibility.
For `v3.4.45+` targets, that contract also carries the Product Proof Path
terminal-chain boundary: terminal artifact verification, binding/refusal hashes,
exact trusted-registry refusal IDs/reasons, omitted raw public-key material,
omitted receipt envelope, false external attestation, and false current-machine
governance.
For `v3.4.46+` targets, it also carries exact grouped recognition-refusal case
IDs from that terminal-chain boundary: `group_count=3`, `case_count=18`, the
grouped case-ID map, and `preserved=true`.
For `v3.4.48+` targets, it also carries the Product Proof Path
deployment-profile authority bridge: explicit deployment profile and runtime
profile SHA binding, no `--latest`, verified preflight, one recognized receipt
mutation, 18/18 zero-mutation refusals, request/agent authority-material
refusal, direct API refusal, and false current-machine, production, external,
sovereign, and unrouted flags.
For `v3.4.49+` targets, it also carries the deployment-profile authority
refusal case list and before-service-proof booleans so stale profile artifacts,
profile recognition mismatches, `--latest` selection, and request-stream
authority material cannot be compressed into the older bridge summary.
For `v3.4.50+` targets, it also carries the terminal-chain/proof-smoke/North
Star mirror of that five-case authority-refusal list, including exact IDs,
before-service-proof refusal, before-mutation refusal, service-proof-not-started,
and false current-machine/production/external/sovereign/unrouted flags.
For `v3.4.53+` targets, release-forward verifier packets can preserve an
optional supplied
`zlar-trusted-receipt-issuer-completion-proof-v1.json` with
`--trusted-issuer-completion-proof <file>`, verify it locally, include the proof
and verification JSON SHA-256s in the release-forward manifest without adding
them to the core private-verifier artifact set, and expose
`trusted_receipt_issuer_completion_evidence` for readiness intake. This remains
private-core completion evidence, not public by default, not source publication,
not production issuer or hardware custody, not production downstream
recognition, not public external attestation, not enterprise readiness, not real
records protection, not side-door closure, and not absolute human intention or
legal consent. The supplied proof may select
`protected-records.private-operator.records-terminal.records.write` while
`north-star-readiness` still reports the selected terminal as
`protected-records.runtime.profile-installation.records.write`.
Historical pre-exhaustion evaluator sequence: the explicit
`zlar-product-proof-path-v1.json` step was the fresh proof-pack generation path.
The remaining historical checks did not run the
proof pack, generate fresh proof-pack, key-state, receipt-verifier,
service-profile preflight, activation-preflight, runtime-local-activation,
runtime-profile-installation, or installed-runtime-profile preflight evidence.
They ran fresh local installed-runtime-profile recognition, disposable
child-service, and terminal-chain proofs from committed sample input only; they
do not inspect live or non-sample recognition state, start a live runtime service, inspect live
hooks, audit stores, operator home key material, or hardware, prove
live/current-machine governance, prove active issuer status or key custody,
prove production deployment, provide external attestation, prove sovereign
recognition, or cover unrouted surfaces.

Historical schema note: `north-star-readiness` emitted
`zlar-north-star-readiness-v1`, a bounded closure
report over committed fixture or supplied release-forward evidence. It records
which North Star puzzle pieces are locally proven, partial, or unproven. The
product proof path consumed the fresh `zlar-product-proof-path-v1` report when
present and still records the simulated-human authorization summary from local
proof-pack artifact verification. Supplied verifier-kit public-distribution
evidence is validated through the verifier-kit public-distribution validator and
tag-bound to `--release-tag` before readiness consumes it. The
default fixture/no-assets path reports `NOT_READY_FOR_V3_4_0`; live
public verifier-kit distribution evidence can report
`READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION`. That is only boundary-
release readiness. The simulated-human authorization summary is local fixture
evidence only. It is not external attestation, real human approval, live
approval-channel health, production authority, enterprise readiness,
current-machine governance, live MCP coverage, key custody, or unrouted-surface
coverage.

Historical positive command inventory from the repo root. The commands tied to
the exact protected-records runtime grant now refuse with
`authority_grant_contract_exhausted`; do not use this block as a current runbook.
Current safe paths are `bin/zlar coverage --sample`,
`bin/zlar consequence-lifecycle --sample`, and the read-only artifact verifier
forms documented below.

```bash
bin/zlar issuer-status-proof
bin/zlar issuer-status-proof --json
bin/zlar approval-transport-proof
bin/zlar approval-transport-proof --json
bin/zlar current-machine-approval-packet verify --sample
bin/zlar current-machine-approval-packet verify --sample --json
bin/zlar current-machine-approval-intake --packet tests/fixtures/current-machine-approval-packet-claude-code-v1.json
bin/zlar current-machine-approval-intake --packet tests/fixtures/current-machine-approval-packet-claude-code-v1.json --json
bin/zlar current-machine-approval-intake --packet tests/fixtures/current-machine-approval-packet-claude-code-v1.json --json | bin/zlar current-machine-approval-request-preview --intake -
bin/zlar current-machine-approval-intake --packet tests/fixtures/current-machine-approval-packet-claude-code-v1.json --json | bin/zlar current-machine-approval-request-preview --intake - --json
bin/zlar protected-records-proof
bin/zlar protected-records-proof --json
bin/zlar protected-records-adapter-conformance
bin/zlar protected-records-adapter-conformance --json
bin/zlar protected-records-service-preflight verify --input ./service-profile-preflight-artifact.json
bin/zlar protected-records-service-preflight verify --sample
bin/zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact ./runtime-activation-preflight-artifact.json
bin/zlar protected-records-runtime-activation-preflight verify --input ./runtime-activation-preflight-artifact.json
bin/zlar protected-records-runtime-activation-preflight verify --sample
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact ./runtime-local-activation-artifact.json
bin/zlar protected-records-runtime-local-activation verify --input ./runtime-local-activation-artifact.json
bin/zlar protected-records-runtime-local-activation verify --sample
bin/zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json
bin/zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --json
bin/zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact ./runtime-profile-installation-artifact.json
bin/zlar protected-records-runtime-profile-installation verify --input ./runtime-profile-installation-artifact.json
bin/zlar protected-records-runtime-profile-installation verify --sample
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample
bin/zlar protected-records-installed-runtime-profile-service-proof --sample
bin/zlar records-write-terminal-proof
bin/zlar records-write-terminal-proof --json
bin/zlar protected-records-runtime-profile-proof
bin/zlar protected-records-runtime-profile-proof --json
bin/zlar key-state --sample --json
bin/zlar local-proof-pack verify --sample --require-sha e24adc1735216e20dfb321db473cd58f6ca1b817c93d75e8b83ccf02a9622186
```

Read-only historical artifact checks remain available. Local proof-pack
verification always projects fixture-rightful issuance false. Proof-smoke v1
uses the explicit historical v2 verification output and never becomes current
authority or fresh effect evidence:

```bash
bin/zlar proof-smoke
bin/zlar proof-smoke --json
bin/zlar proof-smoke verify --historical --input tests/fixtures/proof-smoke-v1-report.json --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar proof-smoke verify --historical --input tests/fixtures/proof-smoke-v1-report.json --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80 --json
bin/zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80 --json
bin/zlar local-proof-pack verify --sample
bin/zlar local-proof-pack verify --sample --json
bin/zlar local-proof-pack verify --input tests/fixtures/local-proof-pack-artifact-v1.json
bin/zlar local-proof-pack verify --input tests/fixtures/local-proof-pack-artifact-v1.json --json
```

`issuer-status-proof` creates ephemeral local fixture issuer keys and proves one recognition rule accepts an active issuer while refusing retired, compromised, missing-status, unknown, and key-missing issuers before boarding. It is not live key custody, production trust registry, revocation infrastructure, compromise-response, or external attestation evidence.

`approval-transport-proof` models approval delivery as a replaceable local fixture transport boundary. It proves unavailable transport and delivered-without-decision cases fail closed, Telegram is not required by the fixture path, and boarding still requires a signed human decision receipt. It is not live Telegram health, production approval-channel delivery, runtime configuration, or external attestation evidence.

`current-machine-approval-packet verify --sample` verifies a committed selected-surface Claude Code approval packet without probing the live machine. The packet must name the selected surface, hook target, delegation target, source target, installer identity, command posture, dry-run plan identity, authority request identity, backup/rollback requirements, issuer/policy, receipt path, downstream refusal matrix, and explicit non-claims; the verifier refuses missing sections, request-stream authority material cases, summary-only authority material, verifier-minted boarding credentials, install/activation claims, false boundary flips, source/installer/plan mismatches, missing backup/rollback requirements, and current-machine governance claims. It is not installation, activation, hook execution proof, live receipt emission, live downstream recognition, production authority, external attestation, release identity evidence, or current-machine governance evidence.

`current-machine-approval-intake --packet <file|->` runs `current-machine-approval-packet verify --input <file|-> --json` on an explicit packet and reports whether a future human install/config authority request may be prepared. Incomplete, invalid, mutating, under-bound, or overclaiming packets return `authority_request_allowed=false` and `authority_request_made=false`. A complete packet returns `authority_request_allowed=true` only for request preparation and preserves the packet binding for source target, installer identity, command posture, dry-run plan identity, authority request identity, backup/rollback requirements, selected surface, hook target, delegation target, issuer/policy, receipt path, refusal matrix, and non-claims; it still does not install, activate, write hook/profile/user/service/machine configuration, touch secrets or signing material, use Telegram, execute a live hook, mint a receipt, prove downstream recognition, or prove current-machine governance.

`current-machine-approval-request-preview --intake <file|->` consumes a current-machine approval intake report and verifies that a future human install/config authority request preview may be prepared. It refuses unless the intake report has `authority_request_allowed=true`, `authority_request_made=false`, complete packet verification, preserved source target, installer identity, command posture, dry-run plan identity, authority request identity, backup/rollback requirements, selected surface, hook target, delegation target, issuer/policy, receipt path, downstream refusal matrix, and non-claims, with all install/config/live/current-machine governance claim flags false. A successful preview keeps `authority_request_made=false`, `install_authority_granted=false`, and `human_approval_granted=false`. It is not install authority, not an approval, not an actual human authority request, not release identity evidence, not current-machine governance evidence, not live hook execution, not live receipt emission, and not live downstream recognition.

`protected-records-write` and the exported `applyProtectedRecordsWrite` factory
are permanently retired in current source as
`e1_direct_adapter_factory_source_retired`. The positive body was removed; the
standalone wrapper fixed-refuses before argument, stdin, receipt, or target-path
access; the main dispatcher no longer routes the command; and future installer
copies omit the wrapper and retired module. Historical result constants and
plain-data validators remain in the inert verification module. A future
authorized repair, upgrade, or reinstall is source-defined to remove the exact
stale installed wrapper/module paths before replacement copies; no installer
was run here. Current-machine, copied, loaded, historical, or mutated source
therefore remains open, so this is not installed-copy retirement, E1
elimination, or runtime unreachability.

`protected-records-proof` fresh terminal-proof generation is permanently retired
in current source as `e1_positive_terminal_proof_generation_retired`. The
positive body and positive adapter call were removed. Its historical schema,
privacy guard, formatter, and exact embedded evidence remain available only to
the pinned local-proof-pack and proof-smoke historical verifiers. That retained
evidence is not current authority, a fresh proof, or a fresh effect.

`protected-records-adapter-conformance` fresh CLI-process proof generation is
permanently retired in current source as
`e1_positive_adapter_conformance_generation_retired`. Its wrapper no longer
imports a generator or invokes `protected-records-write`; the positive body was
removed while the historical schema and formatter remain. The direct adapter
is now separately source-retired as described above, but installed, old,
loaded, dynamic, raw-write, and E4 routes remain open.

`protected-records-service-proof` fresh generation is permanently retired in
current source as `e2_positive_service_proof_generation_retired`. Exact
historical downstream-service evidence remains embedded in the pinned local
proof-pack artifact and is available only through its verifier. The direct E2
request CLI and exported factory now fixed-refuse in current source as
`e2_direct_request_factory_source_retired`; the main dispatcher no longer
routes that command, and future installer copies omit the retired wrapper and
module. A future authorized repair, upgrade, or reinstall is source-defined to
remove the exact stale installed wrapper/module paths; no installer was run or
current installation inspected. Old installed, copied, historical, or mutated
source remains open and prevents any installed-copy-retirement,
runtime-unreachability, or E2-elimination claim.

`protected-records-service-preflight` fresh profile execution and CLI artifact
generation are permanently retired as
`e2_positive_service_preflight_generation_retired`. `verify --input
<file|->` and `verify --sample` remain read-only historical artifact
verification paths. They validate canonical integrity and embedded historical
preflight boundaries without running E2, selecting a live/latest profile, or
projecting current authority, fresh effect, production service evidence, or
closure of direct filesystem writes.

The next four runtime proof descriptions are pre-exhaustion mechanics. Their
positive forms now refuse before nested proof or install-root creation. Their
committed artifact verifiers are historical-only and force current
fixture-rightful issuance false.

`protected-records-runtime-profile-preflight --profile profiles/protected-records-runtime-fixture.profile.json` preflights a sample protected-records runtime profile without installing or activating it. The profile names the runtime service command, proof command, launcher-owned authority boundary, consumed-store lock/validation/anchor/write model, replay scope, required proof cases, required boundary observations, and known open boundaries. The preflight validates that profile, runs the local disposable runtime-profile proof, binds the profile SHA-256 into the report, and reports recognized write acceptance, replay-after-restart refusal, invalid consumed-store and invalid-anchor refusal, consumed-store rollback/deletion/replacement refusal relative to the current local anchor, agent-supplied authority-material refusal, and the residual store-plus-anchor rollback boundary. It is not a persistent runtime profile install, not live records-system evidence, not production service evidence, not production-grade anti-rollback, and not closure of host side doors or unrouted records paths.

`protected-records-runtime-activation-preflight --plan profiles/protected-records-runtime-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json` preflights a sample runtime activation plan without installing or activating it. The plan binds an explicit runtime-profile SHA, requires explicit human install, refuses latest/current-machine selection, and records that it does not write runtime config, write hook config, start a runtime service, or accept request-stream authority material. The preflight validates the plan and profile together, runs the bounded runtime-profile preflight, and reports plan SHA, profile SHA match, runtime proof case count, rollback refusal, no activation applied, and open activation/live/current-machine boundaries. `--artifact <file|->` emits a portable canonical JSON artifact containing the explicit plan, runtime profile, and preflight report with a SHA-256 over the canonical artifact body. `verify --input <file|->` checks artifact integrity and the embedded preflight boundaries without rerunning the preflight or selecting a live/current-machine runtime profile. `verify --sample` checks the committed sample artifact at `tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json` without generating fresh evidence. It is not a persistent runtime profile install, not current-machine governance evidence, not live records-system evidence, not production service evidence, not external attestation, and not sovereign recognition.

`protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json` runs an explicit local disposable runtime activation proof. It validates the plan and profile SHA, writes only launcher-owned disposable runtime config inside the proof harness, starts local JSONL child service processes through the runtime-profile proof, proves one recognized `records.write` mutates once, and proves replayed, missing, invalid, unknown-issuer, retired-issuer, missing-issuer-status, stale, wrong-policy, wrong-domain, wrong-tool, wrong-runtime-profile-id, wrong-audit-event, wrong-detail, non-boarding, direct-API, and agent-supplied-authority requests refuse before runtime-state mutation. `--artifact <file|->` emits a portable canonical JSON artifact; `verify --input <file|->` and `verify --sample` check artifact integrity and embedded local-activation boundaries without rerunning the proof. It is not a persistent runtime profile install, not hook configuration, not current-machine governance evidence, not live records-system evidence, not production service evidence, not external attestation, and not sovereign recognition.

`protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json` runs a local disposable runtime-profile installation proof. It validates the plan and profile SHA, creates only a launcher-owned disposable proof root, copies the pinned runtime profile there, writes an active-profile index, selects the profile by explicit id and SHA, then runs the bounded runtime-profile proof. It proves one recognized `records.write` is accepted and replayed, missing, invalid, unknown-issuer, retired-issuer, missing-issuer-status, stale, wrong-policy, wrong-domain, wrong-tool, wrong-runtime-profile-id, wrong-audit-event, wrong-detail, non-boarding, direct-API, and agent-supplied authority-material attempts refuse before runtime-state mutation. It also proves request-stream attempts to supply installed profile state, runtime config, runtime profile, or recognition rule are refused before mutation. `--artifact <file|->` emits a portable canonical JSON artifact; `verify --input <file|->` and `verify --sample` check artifact integrity and embedded disposable-installation boundaries without rerunning the proof. It is not a persistent runtime profile install, not hook/user/machine configuration, not current-machine governance evidence, not live records-system evidence, not production service evidence, not external attestation, and not sovereign recognition.

`protected-records-installed-runtime-profile-preflight --install-root <dir> --expected-profile <file|-> --profile-id <id> --profile-sha256 <sha256>` reads an explicit installed runtime-profile root without installing or activating anything. It validates the active-profile index, refuses latest/default-current-machine selection, verifies that the installed profile matches the supplied expected profile and SHA, preserves the selected profile recognition contract, and reports only sanitized placeholder paths. `verify --input <file|->` and `verify --sample` check artifact integrity, embedded selector-integrity boundaries, the launcher-owned recognition boundary, the mutation-authoritative route, and the required refusal-case count without reading an install root. It is not a persistent install, not runtime activation, not service start, not hook/user/machine configuration, not downstream refusal evidence, not current-machine governance evidence, not live records-system evidence, not production service evidence, not external attestation, and not sovereign recognition.

`protected-records-active-persistent-profile-preflight --surrogate-root <dir> --activation-root <dir> --proof-target <file> --profile profiles/protected-records-runtime-fixture.profile.json --runtime-profile-id protected-records-disposable-runtime-profile --runtime-profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 --expires-at <future-iso8601>` runs a source-only preflight for a future active persistent profile path. It requires explicit temp/proof-owned surrogate paths, exact profile id/SHA/source, and refuses moving selectors, expired profiles, path aliases, real-root evidence paths, and nonempty roots. It preserves the launcher-owned grant/store/witness requirements and the recognition/authority refusal matrix but defers the exact runtime grant, so rightful issuance remains false. It does not default to, install, activate, or write the real root, hooks, user/machine config, persistence, credentials, network, or records.

`protected-records-active-persistent-profile-live-installation status` remains read-only. Current `install` and `closeout` calls refuse as `active_persistent_profile_mutation_authority_absent` before activation-root inspection, creation, report output, or manifest mutation. The original installation/readback contract remains historical source only: it described one bounded explicit-root profile installation, but the disposable fixture grant never authorized that persistent-profile mutation and a replacement fixture grant cannot reactivate it.

`protected-records-active-persistent-profile-action-crossing --activation-root <dir> --expected-profile profiles/protected-records-runtime-fixture.profile.json --profile-id protected-records-runtime-fixture-profile --profile-sha256 e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469 --proof-target <file> [--allow-named-live-root]` currently refuses as `authority_grant_contract_exhausted` before active-root inspection or proof-target handling. Its retained historical contract read one explicit active root at action time and placed the proof-owned marker only after the recognized fixture effect. That history does not make the fixture grant live authority for an active root or prove generic, portable, production, or current-machine rightful issuance.

`protected-records-active-persistent-profile-lifecycle --install-report <file> --green-report <file> --red-report <file> --closeout-report <file>` verifies one supplied historical local active-persistent evidence set without reopening the root and forces current fixture-rightful projection false. The `run` form currently refuses before activation-root or output creation. Its former report-generation sequence is historical only; it does not upgrade the selected disposable North Star 2 path, prove live rightful issuance, current-machine governance, production recognition, external attestation, enterprise readiness, or side-door closure.

`north-star-readiness --evidence-dir <dir>` can also consume a historical
active-persistent-profile lifecycle evidence bundle when the directory contains
both `zlar-active-persistent-profile-lifecycle-v1.json` and
`zlar-active-persistent-profile-lifecycle-source-binding-v1.json`. The binding
manifest must name the lifecycle report, bind its SHA-256, name the four source
report basenames and SHA-256s, and keep `non_scoring=true`,
`current_installation=false`, `product_proof_path_completion=false`, and
`production_downstream_recognition=false`. Readiness rebuilds the lifecycle
report from the four source reports and refuses missing, drifted, or ambiguous
evidence. When accepted, this is recorded only as
`historical_supplied_local_active_persistent_profile_lifecycle`; it does not
increase `proven_count`, complete Product Proof Path, complete Enterprise
Deployment Profile, prove a current active installation, or create production
downstream recognition.

The current `protected-records-installed-runtime-profile-recognition-proof` positive generator is intentionally unavailable: its exact one-use fixture grant is source-recorded as exhausted. `verify --input <file|->` and `verify --sample --require-sha <sha256>` may inspect the committed historical artifact without rerunning the consequence. Structural or exact-SHA artifact identity does not restore fixture-rightful issuance. Recognition and refusal mechanics remain historical fixture evidence only; no live runtime, current-machine, production, or lifecycle claim follows.

The current `protected-records-installed-runtime-profile-service-proof` positive generator is intentionally fail-closed. Contract `0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba` authorizes one hermetic crossing, has `max_uses=1`, and is source-recorded as exhausted; a fresh store now refuses as `authority_grant_contract_exhausted` before grant-store commit or state mutation. The committed artifact preserves historical target/effect binding, 18 recognition refusals, 5 authority refusals, replay separation, burn windows, and the joint-rollback side door. `verify --sample --require-sha <sha256>` can bind its exact identity without rerunning the consequence, but neither self-integrity nor an exact SHA restores fixture-rightful issuance.

The terminal-chain composition path no longer reruns the positive child-service generator. It reads and exact-SHA verifies the committed service artifact; the one-terminal and product wrappers likewise consume pinned historical artifacts instead of recursively spending the grant. Because the current grant is exhausted, these paths refuse any fixture-rightful projection. The committed terminal artifact remains structural history for nested preflight/service binding, the exact logical target, 18 recognition refusals, 5 authority refusals, replay separation, burn windows, and the joint-rollback side door. `verify` without a caller pin proves only self-integrity; even an exact pin proves identity, not renewed consequence authority.

The exhaustion guard now also covers the direct runtime-profile proof,
runtime-profile preflight, activation preflight, runtime-local activation,
runtime-profile installation, records-write terminal, local proof-pack, Product
Proof Path, proof-smoke, and North Star readiness entrypoints. Positive calls
refuse before scratch/install/output creation. Legacy runtime and proof-pack
artifact verifiers preserve historical effect/refusal fields but force current
fixture-rightful issuance false; schemas without an artifact-bound exact grant
SHA can never be revived by a future replacement grant. Product Proof Path v7,
proof-smoke v1, and North Star readiness v1 require a schema revision before
any future positive composition.

The command descriptions below record pre-exhaustion behavior and retained
historical interfaces; they do not override the current refusal boundary.

`records-write-terminal-proof` is the one-command view of the first boarded
terminal. It uses the committed local disposable activation plan and runtime
profile, generates fresh local proof evidence in memory, verifies the in-memory
artifact, and prints the bounded airport sentence for `records.write`: one
recognized receipt mutates the local fixture state, while a machine-readable
downstream refusal contract preserves exact reason-code and zero-mutation
evidence for missing, invalid, stale/expired, unrecognized-issuer,
wrong-policy, out-of-scope, binding-mismatch, direct-API, and
agent-supplied-authority attempts. It does not install a persistent runtime
profile, write hooks or machine configuration, use Telegram, inspect a live
records system, prove current-machine governance, prove production authority,
provide external attestation, or cover unrouted records paths.

Historical `protected-records-runtime-profile-proof` generation ran the local disposable runtime profile through `protected-records-runtime-service --config <file>`. The committed direct runtime-service script body is now permanently retired and contains one refusal before config or request reading. The named `createProtectedRecordsRuntimeService` export is also retained only as an unconditional, input-independent refusal: it reads no config or getters and creates no service object or `applyRequest`. Verification-bearing modules remain import-linkable, but their old positive generators cannot create the v1 service. This proof command itself has no artifact-verification mode; downstream versioned runtime-local-activation, runtime-profile-installation, and installed-service artifacts retain separate verification branches intended to inspect supplied artifacts without consequence reexecution. Their transitive import-time side-effect closure remains unproven. The historical launcher config owned the recognition rule, exact authority-grant material, authorized record update, state path, consumed-grant store, local anchor, and local witness; the request stream could not replace them. The historical route was receipt recognition, authority-grant evaluation, persistent store/anchor/witness writes, then process-private state mutation under one ordered lock. That remains North Star 1 boarding/effect evidence, not current authority or a reusable positive route. Any future fixture-internal E3 execution needs a new versioned design and separate authority. Interpreter/PATH substitution, loaders/preloads, custom imports of old or mutated source, old installed copies, and same-user source mutation remain open side doors, so this retirement does not prove current-machine refusal, E3 elimination, runtime unreachability, lifecycle closure, exactly-once semantics, atomic multi-file commit, host-path TOCTOU closure, production durability, live records protection, external attestation, or sovereign recognition.

The additive `legacy-runtime-v1-e3-source-disposition-overlay-v0` preserves E3 as a historical distinct-effect node while recording the exact current-source disposition: each of nine reviewed E3 route projections contains a fixed direct-CLI or exported-factory refusal boundary before E3, with source-recorded guards permitted to refuse earlier; the installed terminal-chain association is a historical evidence view that does not invoke the service-proof generator. This does not change observed-uncovered or unclassified coverage, prove runtime unreachability or E3 elimination, cover old installed copies, or move North Star 2 beyond `mapped_open`.

Historical pre-exhaustion `local-proof-pack` generation ran the fixture-input coverage map, downstream refusal proof, simulated-human authorization proof, approval-transport proof, issuer-status proof, trusted issuer registry recognition fixture, local receipt-verifier boundary proof, protected-records terminal proof, protected-records adapter conformance proof, protected-records downstream-service proof, protected-records service-profile preflight, protected-records runtime activation-plan preflight, protected-records runtime-local-activation proof, and protected-records runtime-profile-installation proof through their validators, and carried separate runtime-profile preflight identity metadata. The downstream refusal component proved one local hermetic rule accepted one matching receipt with `recognized_marker_count_delta=1` and refused missing, invalid, stale, unknown-issuer, retired-issuer, wrong-policy, out-of-scope, wrong-audit-event, wrong-detail, and non-boarding receipts before a fake marker write with every refusal marker-count delta at zero. The issuer-status component proved one local fixture recognition rule accepted an active issuer and refused retired, compromised, missing-status, unknown, and key-missing issuers before boarding. The trusted issuer registry recognition component validated and evaluated a valid bundled `trusted-receipt-issuers-v2` private registry fixture through the shared downstream recognition rule, recorded audit-event/detail-hash binding and malformed-registry fail-closed behavior, and kept live-registry/live-issuer-status/key-custody/revocation/production/current-machine/external-attestation flags false. The receipt-verifier component ran the actual `zlar-verify <receipt.json> --pubkey <key.pub> --json` CLI against local ephemeral v1 receipts and proved `VALID`, `UNKNOWN-SIGNER`, and `INVALID` stayed distinct by verdict and exit code. The protected-records components named the fixture deployment profile, adapter profile, adapter route, callable local adapter action, CLI-process conformance boundary, downstream service process boundary, persistent consumed-receipt-store replay refusal, append-only ledger model, bounded service-state model, per-adapter/service replay scope, action class, downstream boundary, profile contract route, replay policy, required receipt fields, accepted write, refused write count, downstream-service refusal for missing, unrecognized/detail-mismatch, invalid, unknown-issuer, stale, and direct-API attempts, executed launcher-owned-config service preflight profile id/SHA/status, case counts, wrong-policy refusal, request-stream authority-material refusal, direct-API refusal summary, open boundaries and non-claims, runtime-profile preflight profile id/SHA/status, activation plan id/SHA, activation plan profile-SHA match, activation preflight execution, nested runtime-profile proof case and boundary counts, rollback/deletion/replacement refusal, agent-supplied authority-material refusal, explicit install requirement, and known ungoverned boundaries. It also recorded local disposable runtime activation and runtime-profile installation components: explicit local activation/install commands, plan/profile SHA match, launcher-owned disposable runtime config and disposable install-root evidence inside the proof harness, active profile selected by explicit id and SHA, local JSONL child service processes started, recognized write accepted, replay/missing/invalid/unknown-issuer/retired-issuer/missing-issuer-status/stale/wrong-policy/wrong-domain/wrong-tool/wrong-runtime-profile-id/wrong-audit-event/wrong-detail/non-boarding/direct-API refusal, and agent-supplied authority-material refusal before runtime-state mutation. It generated local fixture evidence only; it did not prove active live issuer status, key custody, revocation state, live downstream recognition, install a persistent runtime profile, write hooks or machine configuration, write production configuration, use Telegram, inspect live hooks or audit stores, close direct filesystem writes to fixture paths, prove live/current-machine governance, or attest production/external governance.
`local-proof-pack` artifact verification exposes the embedded downstream refusal proof as a machine-readable summary: proof-pack run provenance, one recognized board with marker-count delta one, final marker count one, exact refusal count/reasons, all refusals unboarded, all refusal marker-count deltas zero, local hermetic fixture evidence, false live probing, and no live downstream or production-recognition claim.
`local-proof-pack` artifact verification exposes the embedded simulated-human authorization proof as a machine-readable summary: local hermetic fixture evidence, `simulated-human-fixture` approval channel, authorized case boarded, pending and denied cases not boarded, false live-probing flag, and no live approval-channel or real human approval claim.
`local-proof-pack` artifact verification also exposes the embedded trusted issuer registry recognition summary: validated and evaluated bundled local registry fixture, `RECOGNIZED` verdict, active fixture issuer status, signature validity, audit-event/detail-hash binding, malformed-registry fail-closed behavior, and false live-registry, live-issuer-status, key-custody, revocation, production, current-machine, sovereign-recognition, public-attestation, and real-non-operator-review flags.
Historical proof-pack artifacts also embed a deterministic `zlar key-state --sample --json` summary so those artifacts carry verifier/pin posture and privacy flags without inspecting operator home key material, hardware, key custody, revocation truth, production trust registry state, or current-machine governance.

Historical pre-exhaustion `product-proof-path` was the evaluator-facing wrapper over that proof pack.
It ran the local proof-pack, verified the generated artifact, and emitted
`zlar-product-proof-path-v1`: a compact Product Proof Path report that names
the action class, checkpoint, route, downstream effect, proof-pack hash,
acceptance gates, observed allow/refusal/simulated-human/receipt-verifier
facts, trusted issuer registry recognition fixture facts, known ungoverned
boundaries, terminal-chain trusted-registry binding verdict/evaluation facts,
and false stronger-claim flags. It was a single-command local proof path, not a
live registry, key custody, revocation, production deployment, or external
attestation claim.

Source-checkpoint fixture status: the exact one-use grant is source-recorded as
exhausted; this is not caller-authenticated current runtime authority status.
At this source checkpoint, `proof-smoke`, Product Proof Path, and North Star
readiness are guarded before fresh consequence execution or fixture-rightful
projection. The next paragraph
describes the pre-exhaustion smoke contract and is retained as historical
evidence only; it is not the current executable or claim posture. Current
static coverage is `4/6`, with runtime profile-installation and installed
terminal-chain lanes open.

Current verification-only path: `proof-smoke verify --historical` accepts only
the caller-pinned exact v1 sample bytes and emits a v2 historical verification
with no current counts projection. Fresh execution, source freshness, current
coverage, current authority, current fixture-rightful issuance, current effect,
and lifecycle closure remain false.

`proof-smoke` verifies the committed local proof-pack sample artifact, verifies the committed service-profile preflight sample artifact, verifies the committed activation-preflight sample artifact, verifies the committed runtime-local-activation sample artifact, verifies the committed runtime-profile-installation sample artifact, verifies the committed installed-runtime-profile preflight sample artifact, runs the committed installed-runtime-profile recognition proof, runs the committed installed-runtime-profile disposable service proof, verifies that service-proof artifact, runs the installed-runtime-profile terminal chain, verifies that terminal-chain artifact, and runs the committed fixture-input coverage map with `coverage --sample --require-governed`; `--json` emits the same bounded smoke result as a parseable `zlar-proof-smoke-v1` report. `proof-smoke verify --input <file|->` validates a supplied smoke report against that strict contract without regenerating evidence. `proof-smoke verify --sample` validates the committed sample report at `tests/fixtures/proof-smoke-v1-report.json` without requiring the path to be supplied. A committed sample report lives at that path, and `lib/proof-smoke-report.mjs` validates the report shape. The local proof-pack sample check verifies the sample artifact's canonical body SHA-256 and embedded local fixture proof-pack boundaries, including downstream refusal, simulated-human authorization, approval transport, issuer-status refusal for retired, compromised, missing-status, unknown, and key-missing issuers, key-state sample summary, receipt-verifier `VALID`/`UNKNOWN-SIGNER`/`INVALID` separation, protected-records terminal refusal/replay behavior, protected-records adapter CLI-process conformance, protected-records downstream-service refusal before mutation, service-profile preflight evidence, runtime-profile preflight identity metadata, runtime activation-plan preflight execution evidence, runtime-local-activation execution evidence, and runtime-profile-installation disposable installed-state evidence. Its verifier summary exposes the embedded simulated-human authorization summary: local hermetic fixture evidence, `simulated-human-fixture` approval channel, authorized case boarded, pending and denied cases not boarded, false live-probing flag, and no live approval-channel or real human approval claim. It also exposes the embedded key-state sample privacy and non-claim flags, including no key custody, revocation, production trust registry, current-machine governance, external attestation, or sovereign recognition claim. It also exposes the embedded receipt-verifier boundary summary: valid receipt accepted under the supplied key, wrong public key reported as `UNKNOWN-SIGNER`, tampering reported as `INVALID`, and no issuer-recognition/key-custody/revocation/downstream-recognition claim. It also exposes the embedded service-profile preflight type, fixture evidence model, case count, sanitized case summaries, wrong-policy refusal reason, direct-API-with-receipt refusal reason, zero state mutation, and no-live/no-production/no-external-attestation flags, plus the embedded runtime-local-activation and runtime-profile-installation summaries: local activation applied, disposable config written, disposable profile install-root/index/selection applied, no persistent config/profile install or hook write, local child service started, replay/missing/invalid/unknown-issuer/retired-issuer/missing-issuer-status/stale/wrong-policy/wrong-domain/wrong-tool/wrong-runtime-profile-id/wrong-audit-event/wrong-detail/non-boarding/direct-API refusal, request authority guard refusal, and no live/production/external claim. The coverage-map step exposes supplied-evidence summaries for counted lanes: route/freshness/policy status, latest decision, latest receipt, issuer or recognition anchor, and known boundaries. The standalone service-profile preflight sample check verifies canonical artifact integrity, the 11/11 case count, wrong-policy refusal reason, direct-API-with-receipt refusal reason, zero state mutation, and no-live/no-production/no-external-attestation flags without rerunning the preflight. The activation-preflight sample check verifies canonical artifact integrity and embedded activation-preflight boundaries without rerunning the preflight. The runtime-local-activation sample check verifies canonical artifact integrity and embedded local disposable runtime activation boundaries, including local activation applied inside the proof harness, disposable runtime config written, no persistent runtime config or hook configuration written, local JSONL child service started, recognized write accepted, replay-after-restart refused, the expanded refusal taxonomy including wrong-runtime-profile-id, direct-API-with-receipt refused, and agent-supplied authority material refused. The runtime-profile-installation sample check verifies canonical artifact integrity and embedded disposable installation boundaries, including disposable install root created, profile copy written, active index written, profile selected from the install root by explicit id and SHA, no latest selection, no persistent profile install, no hook/user/machine config, the expanded refusal taxonomy including wrong-runtime-profile-id, request-stream authority material refused, and local JSONL child service proof run. The installed-runtime-profile preflight sample check verifies canonical artifact integrity and embedded read-only selector-integrity boundaries, including explicit install-root/profile-id/profile-SHA requirements, active index read, installed profile read, installed profile contract validation, profile selected by explicit id and SHA, no latest selection, no installation, no activation, no service start, no hook/user/machine config, no downstream refusal proof, and no current-machine governance proof. The installed-runtime-profile recognition proof consumes that verified preflight sample, boards one matching `records.write` receipt, and refuses all 18 selected-profile recognition cases before fake effect without starting a live runtime service. The installed-runtime-profile service proof consumes the same verified preflight sample, writes only disposable proof config, starts local disposable JSONL runtime-service child processes, boards one matching `records.write`, refuses same-process and restart replay, refuses consumed-store/local-anchor/witness integrity failures, proves store-plus-anchor rollback refusal when the local witness remains ahead, and refuses all 18 selected-profile refusal cases before service-state mutation. The service-proof artifact verifier then preserves that proof's payload type, artifact body SHA-256, replay refusal, rollback-refusal counts, before-mutation refusal result, current-machine false flag, and production-downstream false flag; the report rejects the verifier if its artifact body SHA-256 is not the hash of the service proof carried in the same report. The installed-runtime-profile terminal chain creates only a launcher-owned disposable installed root from explicit plan/profile input, preflights that generated root by explicit id and SHA, runs the selected-profile service proof from the generated preflight artifact, verifies the generated service-proof artifact, boards one matching `records.write`, refuses missing/invalid receipts and all 18 selected-profile refusal cases before mutation, and preserves false persistent-install/current-machine/production flags. The terminal-chain artifact verifier then preserves the terminal-chain payload type, artifact body SHA-256, generated-root/preflight/service-proof binding, refusal-before-mutation facts, and false stronger-claim flags; the report rejects the verifier if its artifact body SHA-256 is not the hash of the terminal chain carried in the same report. These smoke commands do not run the proof pack, generate fresh proof-pack, key-state, receipt-verifier, service-profile preflight, activation-preflight, runtime-local-activation, runtime-profile-installation, or installed-runtime-profile preflight evidence. They run fresh local installed-runtime-profile recognition, disposable child-service, and terminal-chain proofs plus artifact verification from committed sample input only; they do not inspect live or non-sample recognition state, use Telegram, inspect live hooks or audit stores, operator home key material, or hardware, or attest production/external governance.

For `v3.4.18+`, the service-proof artifact verifier also carries the exact
refusal taxonomy SHA-256, and proof-smoke rejects reports where the verifier's
taxonomy identity is replaced even if the refusal count still says 18.

For `v3.4.19+`, the installed-runtime-profile recognition contract also carries
a canonical `recognition_contract_sha256`, and proof-smoke rejects reports where
preflight, service proof, service-proof artifact verification, terminal chain,
or terminal-chain artifact verification stop carrying the same contract digest.

For `v3.4.6+`, the installed-runtime-profile preflight sample check also preserves the selected profile recognition contract, launcher-owned recognition boundary, mutation-authoritative route, and required refusal-case count without proving production downstream recognition.

For `v3.4.7+`, the installed-runtime-profile recognition proof records one boarded matching write and all 18 selected-profile refusal cases refusing before fake effect. It remains local hermetic fixture evidence, not live service start, current-machine governance, or production downstream recognition.

For `v3.4.13+`, the installed-runtime-profile service proof records one boarded matching write through a local disposable runtime-service child process, same-process and restart replay refusal, consumed-store/local-anchor/witness integrity refusal, store-plus-anchor rollback refusal when a launcher-owned local witness remains ahead, and all 18 selected-profile refusal cases refusing before service-state mutation. It also records that rollback detection is not proven if the consumed store, local anchor, and local witness move together. For `v3.4.14+`, proof-smoke and North Star readiness also preserve the service-proof artifact verification result. For `v3.4.18+`, they preserve the service-proof artifact-verification refusal taxonomy SHA-256 so artifact verification binds exact case ids, reason codes, and before-mutation facts, not just refusal counts. For `v3.4.19+`, they preserve the installed-runtime-profile recognition-contract SHA-256 across preflight, service proof, service-proof artifact verification, terminal chain, and terminal-chain artifact verification so the proof path cannot swap the recognized contract behind matching profile/taxonomy counts. For `v3.4.15+`, proof-smoke and North Star readiness also preserve the installed-runtime-profile terminal chain and terminal-chain artifact verification result: generated installed-root preflight, generated preflight consumption, generated service-proof artifact verification, service-proof/preflight binding, artifact/service-proof binding, recognized write boarding, missing/invalid receipt refusal, all 18 selected-profile refusals before mutation, and false stronger-claim flags. For `v3.4.17+`, they also preserve the terminal-chain refusal taxonomy SHA-256 so the receipt binds exact case ids, reason codes, and before-mutation facts, not just refusal counts. For `v3.4.22+`, they preserve named receipt-refusal evidence for missing, invalid, stale, unknown-issuer, wrong-policy, wrong-domain, and wrong-tool cases. For `v3.4.23+`, they preserve recognition refusal groups so no usable receipt authority, recognized receipt scope mismatch, and route/request authority-material refusals remain distinct. For `v3.4.24+`, release-forward verifier packets also require and print the exact terminal-chain recognition-refusal group case IDs so grouped evidence cannot degrade into only hashes and booleans. For `v3.4.25+`, proof-smoke and North Star readiness preserve the same report contract directly: `group_count=3`, `case_count=18`, and exact grouped case IDs for both terminal-chain evidence and terminal-chain artifact verification. For `v3.4.26+`, North Star readiness also mirrors that same case-ID contract into the Enterprise Deployment Profile and Downstream Recognition Rule observed summaries, so verifier-facing puzzle pieces cannot fall back to hash-only summaries while counts remain exact. For `v3.4.28+`, terminal-chain artifacts embed nested generated preflight and service-proof artifacts, and verification refuses summary-only forged inner preflight and service-proof artifact hashes even when the outer terminal-chain artifact integrity is recomputed. For `v3.4.30+`, proof-smoke, North Star readiness, and release-forward evidence preserve the verifier-owned `nested_artifact_binding` summary from terminal-chain artifact verification instead of reconstructing binding authority from raw embedded artifacts. For `v3.4.37+`, terminal-chain evidence and artifact verification preserve a public-safe hash-bound trusted issuer registry recognition summary over the bundled local fixture, including stable registry/receipt contract hashes and no embedded raw public-key material or receipt envelope. For `v3.4.38+`, that binding also preserves terminal-chain-local refusal evidence for unrecognized registry scope and registry/receipt contract mismatch, plus the full false-boundary field contract used by readiness. For `v3.4.39+`, proof-smoke and North Star readiness expose that refusal evidence directly as report summary fields, including case count, exact case IDs/reasons, `all_refused=true`, and refusal SHA-256 in top-level counts and readiness observed summaries. For `v3.4.41+`, release-forward verifier packets expose a compact `release_forward_report_contract` object in `DRY-RUN-MANIFEST.json` so tooling can verify the existing report contract without scraping Markdown. For `v3.4.42+`, that object also binds Product Proof Path by source path/SHA-256, PASS/evidence-model fields, false forbidden claims, receipt-verifier boundary, North Star consumption, and known unrouted-records noncoverage visibility. For `v3.4.45+`, Product Proof Path also consumes a fresh terminal-chain artifact verification and the release-forward contract carries the same compact terminal-chain boundary with binding/refusal hashes, exact trusted-registry refusal IDs/reasons, omitted raw public-key material, omitted receipt envelope, false external attestation, and false current-machine governance. For `v3.4.46+`, the Product Proof Path terminal-chain boundary also preserves `group_count=3`, `case_count=18`, exact grouped recognition-refusal case IDs, and `preserved=true`, so already-existing terminal-chain grouped refusal evidence cannot degrade into hash-only Product Proof Path proof. For `v3.4.48+`, Product Proof Path also carries the local fixture deployment-profile authority bridge, including explicit deployment/runtime profile SHA binding, no `--latest`, verified preflight, one recognized receipt mutation, 18/18 zero-mutation refusals, agent/request authority-material refusal, direct API refusal, and false current-machine, production, enterprise, external, sovereign, and unrouted flags. For `v3.4.49+`, that bridge preserves the exact five-case deployment-profile authority refusal contract before service proof starts. Current local post-v3.4.50 proof-hardening also preserves the proof-pack downstream-refusal marker boundary through Product Proof Path, proof-smoke, and North Star readiness summaries so marker evidence cannot degrade into only boarded/refused booleans. For future `v3.4.51+` local targets, release-forward/private-intake contracts also require the Product Proof Path terminal-chain trusted-registry `RECOGNIZED` verdict, active issuer status, signature-valid fact, local registry rule evaluation facts, registry/receipt contract hashes, and downstream-refusal marker boundary in both the terminal-chain/Product Proof Path contract and North Star mirror; `v3.4.50` omits those new fields. It remains local disposable child-service, launcher-owned disposable terminal-chain, and fresh-local Product Proof Path evidence, not persistent install, activation, live runtime service, live trust-registry state, live issuer status, key custody, revocation truth, current-machine governance, production downstream recognition, enterprise readiness, sovereign recognition, unrouted-surface coverage, or external attestation.

For future `v3.4.51+` local targets, those downstream-refusal summaries must
preserve exact downstream refusal reasons and all-refusals-unboarded flags in
both Product Proof Path and North Star mirrors; marker counts alone are not
enough.

Current local post-v3.4.60 proof-hardening also upgrades the trusted issuer
registry fixture into a no-secret registry artifact contract. The contract
names registry identity/version, `live_probing=false`, deployment scope, issuer
lifecycle status, effective window, custody posture declaration, revocation or
compromise transition metadata, accepted policy/domain/tool/outcome, replay and
freshness requirements, false forbidden-claim flags, and non-claims. Product
Proof Path and North Star readiness consume the public-safe hash-bound summary
as contract evidence only. This is still not live trust-registry state, live
issuer status, key custody, revocation truth, production downstream recognition,
production authority, enterprise readiness, public external attestation,
sovereign recognition, or a public claim upgrade.

For `v3.4.50+`, the installed-runtime-profile terminal chain, terminal-chain
artifact verification, proof-smoke, North Star readiness, and release-forward
report contract also mirror that same five-case deployment-profile
authority-refusal contract with exact IDs, before-service-proof refusal,
before-mutation refusal, service-proof-not-started, and false stronger-claim
flags.

For a fixture-input map of governed action surfaces, see the [Governed Surface Coverage Map](governed-surface-coverage-map.md):

```bash
bin/zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json
bin/zlar coverage --sample
```

This validates supplied fixture/report evidence only. Historical artifacts can
still prove route shape, exact plan/profile binding, refusal behavior, and
artifact identity. The exhausted one-use grant cannot make a lane currently
governed or restore fixture-rightful issuance merely because a committed
artifact recorded a mechanically accepted write. The map names the supplied latest
decision, latest receipt, issuer or recognition anchor, and known boundaries
for evaluator tooling. It performs no live probing, does not inspect local
hooks or audit stores, and is not a live machine coverage claim.

`bin/zlar consequence-lifecycle --sample` projects the SHA-pinned terminal-
chain fixture into `consequence-lifecycle-map-v0`. The committed sample resolves
63/63 evidence references and classifies 12 obligations as evidenced, 8 open,
and 2 outside coverage. It carries the exact target binding, full public
authority-grant topology, historical effect mechanics, 18
recognition refusals, 5 authority refusals, replay separation, and the observed
burn/joint-rollback side doors. The result remains `mapped_open` with lifecycle
closure false. The current fixture grant is exhausted and repeated-use
provenance is invalid, so fixture-rightful issuance is also false; generic,
portable, live, production, and current-machine rightful issuance remain false.

## Deployment path

Local evaluation is quick: install, run `zlar doctor`, inspect `zlar status`, and read the default policy.

Serious deployment is work: customize and sign policy, protect signing keys, protect hook/profile configuration, route MCP through ZLAR, remove or block un-routed capabilities, decide when Telegram or other approval channels are appropriate, and verify receipts/audit trails. The install is fast. Standing behind a deployment is not.

ZLAR keeps humans present while intelligence scales. The repo below is the proof, install, legal/security, and reference surface behind that claim.

Troubleshooting: [`docs/troubleshooting.md`](troubleshooting.md).

## How it works

```
Agent issues routed/intercepted tool call (shell command, file write, API request)
  |
  +-- Gate intercepts at the execution boundary
  |
  +-- Loads Ed25519-signed policy (unsigned or tampered policy is rejected)
  |
  +-- Evaluates: which rule matches?
  |   +-- allow  -> tool executes, audit entry written; Worker Receipt emitted when available
  |   +-- deny   -> tool blocked, audit entry written; Worker Receipt emitted when available
  |   +-- ask    -> configured approval channel notified when available, action denied immediately
  |               +-- agent retries  -> gate checks for human response
  |               +-- human approved -> executes on retry, audit/receipt evidence records "authorized by human"
  |               +-- human denied   -> blocked on retry, audit/receipt evidence records "denied by human"
  |               +-- no response    -> blocked (fail-closed, silence is not consent)
  |
  +-- Hash-chained audit entry records the decision
  +-- Governed Action Receipt can provide portable proof when generated
```

Two enforcement surfaces share the same policy and audit trail:

- **Bash gate** (`bin/zlar-gate`) — hooks into configured PreToolUse/adapted surfaces such as Codex, Claude Code, Cursor, and Windsurf. Pure bash. Zero dependencies beyond jq and openssl.
- **MCP gate** (`mcp-gate/gate.mjs`) — TCP proxy between a configured MCP client and upstream server. Intercepts routed `tools/call` JSON-RPC messages. Per-entry Ed25519 signing, policy signature verification, standing approvals. Evaluates JSON regex policy by default; can evaluate Cedar formal policy when `ZLAR_POLICY_ENGINE=cedar` or `=both`.

The agent does not volunteer to be governed. It is governed by architecture.

## Deny-first architecture, deny-heavy perimeter

The gate is deny-first at the architectural layer. The default action is deny. Every error path is deny. Missing policy: deny. Invalid signature: deny. Approval channel unavailable: deny. Uncaught exception: deny. There is no permissive fallback. This has been verified by exhaustive case analysis across both gate implementations.

The deployed policy is a separate choice. The policy that ships with this repo is a deny-heavy perimeter: it blocks dangerous operation families (recursive deletion, privilege escalation, persistence mechanisms, writes to the gate's own enforcement layer, writes to SSH keys and system configuration, edits to CLAUDE.md and `.mcp.json`), escalates sensitive operations to the human (edits to shell configuration, writes to `.env`, edits to credential-adjacent dotfiles, edits to repo code), and permits routine operations outside that perimeter. A different operator could deploy a policy where every action requires human approval. The architecture supports both. The architecture does not assume what the policy will say. It only guarantees that whatever the policy says will be enforced deterministically, and that failures always restrict rather than expand.

Policy is signed. The gate verifies the signature before loading. An unsigned or tampered policy is rejected.

A constitution — a second signed document from a separate key — constrains what the policy is allowed to contain. The policy author cannot silently disable auditing on consequential actions, cannot remove all human review paths from the consequential surface, and cannot override the suspended state. The constitution is the law the lawmaker must obey.

## Enforcement is pattern matching

Rules match actions by domain, tool name, command content, and file path using regex and string patterns. This is not semantic understanding of what the action does. It is syntactic classification of what the action looks like.

That means: if an agent produces the same effect through a pattern the rules do not recognize, the gate will not catch it. A write through the Write tool is governed by write-domain rules. The same mutation through a shell pipeline that does not match any bash deny pattern could reach the catch-all allow.

This is the tradeoff, named. Pattern matching is deterministic, auditable, and cannot be subverted by reasoning. Semantic analysis would catch more but would require inference in the enforcement path, and inference in enforcement can be confused, misled, or manipulated. ZLAR chooses the gate that cannot think over the gate that might be wrong.

The practical mitigation is defense in depth. The policy covers known dangerous families. The operating environment blocks un-routed paths. The audit trail records everything the gate sees. The coverage model names what the gate does not see. The human reviews what the gate is uncertain about.

## Who operates the gate, and who this protects

**The operator is a named role with standing and accountability.** Not an abstraction. In a bank, a Model Risk Officer. In a healthcare system, a validation analyst. In a compliance function, a compliance engineer. In a software organization, a domain expert reviewing actions in their area of responsibility. The person behind the configured approval channel has a title, a schedule, and the authority to say no without penalty.

**ZLAR commits to that operator.** Clear action descriptions in every ask. No default-approval after silence. Every decision recorded to the audit trail with the operator's identity and the context they saw. Permission to hesitate. No friction punishment for caution. The invariants below protect the operator from the system, not the other way around.

**The deterministic record is designed to be legible to advocates acting on behalf of the affected person** — a patient whose care plan an agent modified, a claimant whose application an agent processed, a tenant whose lease an agent renewed, a borrower whose rate an agent adjusted. The affected person is often not in the approval loop, but the receipt produced by that loop is portable proof of what counted as authorized effect, verifiable with a public key, and contestable in whatever forum has standing to hear it. See [If an agent took an action that affected you](if-an-agent-affected-you.md).

**Three approval modes.** Single-approver (one operator taps approve or deny) is the default. The architecture also supports multi-approver-with-dissent (the action proceeds only if every required approver approves; a single dissent blocks) and deliberation-queue-without-timer (the action waits indefinitely for deliberation; no silence-is-consent window). The deployment chooses the mode that fits the legitimacy requirements of the context.

## How these commitments are kept

When the gate decides `ask` and an approval channel is configured, the ask is sent to that channel with the action, the rule that flagged it, the risk score, and a one-line description of what goes wrong if the action is wrong. The operator approves or denies through the configured route. In the current Codex adapter, Telegram dispatch is disabled by default; ask-class actions fail closed locally until an approved channel is configured.

Operational invariants protect the operator:

**H6 — decision cap.** Logs when an operator crosses the daily decision ceiling. Advisory: the ask still routes. The operator decides if they are overwhelmed, not the counter.

**H13 — pending queue capacity.** Logs when too many asks are in flight. Advisory for the same reason.

**H15 — deliberation floor.** Minimum read time per risk class: critical 30s, warn 10s, info 3s. An approval faster than the floor is rejected and the ask is re-queued. A denial faster than the floor stands.

**H17 — authenticity.** Responses that arrive faster than an operator could have read the question are treated as inauthentic. Same asymmetry as H15: suspicious approvals are rejected, denials stand.

The asymmetry is deliberate. Deny is cheap. Approve is consequential. The system makes approvals expensive enough that an operator cannot accidentally consent. The pre-ask invariants (H6, H13) surface conditions to the operator rather than lock them out, because authority belongs to the operator, not to a counter. Additional operational invariants are implemented in [`lib/human-invariants.sh`](../lib/human-invariants.sh); documentation of the full set is ongoing.

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

[ADR-006](adr/ADR-006-structural-independence.md) sets out why the entity that sells agents cannot credibly govern them.

## The Governed Action Receipt

The receipt is portable proof that a governed action was evaluated by deterministic policy and decided by the stated authority.

It is not a better log. It is the boarding credential for the action boundary:
what counted as authorized effect at the moment the action tried to board.

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
6. The receipt does not prove what the agent intended, what the operator understood, what the affected person experienced, or the agent's full history. It proves the gate's classification of the payload and the decision that counted as authorized effect at the boundary. Claims beyond that require evidence outside the receipt.

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

**Receipt non-repudiation** holds for all fields bound into the signature. Tail truncation (deleting the last receipt) is undetectable without an external witness. Presentational replay (reusing a genuine receipt as evidence for a different event) is mitigated by cross-referencing the audit trail but not enforced by the verifier. The protected-records fixture separately demonstrates a terminal-side single-use receipt policy for one bounded `records.write` adapter profile.

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

The gate behaves identically to 2.x when health is off. No performance cost, no behavioral data collected, no detectors running. ([Invariants](RESTORE-INVARIANTS.md), [ADR-008](adr/ADR-008-restorative-governance.md).)

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

`ZlarAgent.connect()` opens a JSON-RPC 2.0 connection to the gate daemon (`sdk/daemon/`) over a Unix socket. If the daemon is unreachable, construction throws `ZlarDaemonUnreachableError`. See [ADR-006](adr/ADR-006-structural-independence.md) for the architectural reasoning.

**Multi-agent delegation chains.** The SDK ships cryptographic delegation chain support for orchestrator/worker patterns. Each agent receives a per-session Ed25519 keypair; the daemon issues a signed root token via the `register` RPC; each parent signs its child's token with its own key. The daemon verifies the full chain cryptographically *before any policy evaluation* — an invalid chain fails closed with `rule: chain:verify` in the audit trail, and no policy rule is ever consulted.

**AuthZEN 1.0 standards interface.** `sdk/authzen/server.mjs` implements the OpenID Foundation AuthZEN 1.0 Final Specification (January 2026) — a standards-compliant Policy Decision Point at `POST /access/v1/evaluation` (single) and `POST /access/v1/evaluations` (batch). Any AuthZEN-aware policy enforcement point can call it. Default port 8181.

**HTTP hook adapter.** `sdk/hook-adapter/server.mjs` bridges Claude Code's HTTP hook protocol to the gate daemon. It always returns HTTP 200 with a valid JSON body — Claude Code treats non-2xx responses as fail-open, so the adapter handles every error condition internally and returns 200 + deny for any failure mode.

## Compliance

ZLAR ships schema-validated Cedar rulesets mapped to specific regulations. Each ruleset is an artifact, tested, and designed to wire into `lib/cedar-evaluator.mjs` per deployment.

**OSFI Guideline E-23 — Canadian Model Risk Management, effective May 1, 2027.** ZLAR ships a Cedar ruleset ([`cedar-poc/e23.cedar`](../cedar-poc/e23.cedar), [`cedar-poc/e23.cedarschema`](../cedar-poc/e23.cedarschema)) mapped to the enforcement layer of E-23 — ten rules covering kill switches, position limits, pre-execution checks, environment gates, and third-party model controls. The ruleset is not a drop-in: runtime wiring and bank-risk input population are per-deployment integration work. ZLAR does not attempt the non-enforcement layers of E-23 — model lifecycle, documentation, and board-level oversight belong to other systems.

Additional regulation mappings are added as customer engagements require them. The Cedar formal policy layer is general; the base ruleset ([`cedar-poc/zlar.cedar`](../cedar-poc/zlar.cedar)) is what the MCP gate evaluates when `ZLAR_POLICY_ENGINE=cedar` or `=both`.

## Architecture

| Layer | Component | What it does |
|-------|-----------|-------------|
| **Enforcement** | `zlar-gate` | Policy engine. Intercepts tool calls, classifies, evaluates signed rules, writes the audit trail, emits Worker Receipts when available, and can emit Governed Action Receipts when configured. |
| **Enforcement** | `mcp-gate` | TCP proxy for MCP. Same policy, same audit format, per-entry signing, standing approvals. Optional Cedar engine via `ZLAR_POLICY_ENGINE`. |
| **Evidence** | `lib/receipt.mjs` | Governed Action Receipt generation and verification (v0 inline and v1 envelope formats). Cross-gate compatible. |
| **Evidence** | `lib/semantic-validator.mjs` | Cross-field validation after signature verification. Rule-outcome consistency, authorizer coherence, delegation chain integrity, temporal bounds. Closes X.509/JWT/SAML-class attacks. |
| **Evidence** | `bin/zlar-verify` | Standalone receipt verifier. Anyone can verify receipt integrity with the supplied public key. V1 `kid` mismatch reports `UNKNOWN-SIGNER`; issuer recognition is a separate downstream rule. Runs semantic validation automatically on v1 receipts. |
| **Evidence** | `bin/zlar key-state --json` / `--sample --json` | Read-only local key-state report for verifier pins, embedded signing public keys, hardware-slot observation, and legacy software private-key presence as a boolean only. Sample mode emits deterministic fixture evidence for proof artifacts. No signing, PINs, private key bytes, custody proof, revocation truth, production trust registry, or external attestation. |
| **Observation** | `zlar-witness` | Sequence detection from audit trail. Detected, not enforced. |
| **Observation** | `zlar-digest` | Governance summary. Decisions, latency, sequences, novelty. |
| **Observation** | `zlar-restore` | Agent Health. 8 behavioral detectors, monotone trust-state machine, gate escalation. Advisory — observes, does not enforce directly. Disabled by default. |
| **Identity** | `zlar-agents` | Per-agent policy bindings, standing approvals, delegation depth limits. |
| **Identity** | Agent manifest | Capability boundary per agent. Narrows policy, never widens. ([Invariants](MANIFEST-INVARIANTS.md)) |
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

- **Implementers**: [`spec/governed-action-receipt-v1.md`](../spec/governed-action-receipt-v1.md) — build a compatible receipt producer or verifier in an afternoon.
- **Relying parties**: [`docs/trusted-receipt-issuer.md`](trusted-receipt-issuer.md) - distinguish receipt verification from issuer recognition, custody, rotation, retirement, and compromise.
- **Private verifier readiness**: `bin/zlar private-verifier-readiness build --evidence-dir <dir> --commit <verifier-source-sha> --evidence-source-commit <evidence-source-sha> --branch <branch> --output-dir <dir>` builds a local no-send `zlar-private-verifier-readiness-packet-v1` for supplied active-persistent lifecycle evidence. The packet binds the exact verifier source commit, evidence source commit, evidence hashes, verifier command templates, expected pass/fail criteria, side doors, and non-claims. `verify --input <packet> --evidence-dir <dir> --require-commit <verifier-source-sha> --require-evidence-source-commit <evidence-source-sha> --require-recomputed-evidence` recomputes the supplied evidence hashes and keeps `public_external_attestation=false`, `non_operator_review_proven=false`, `production_authority=false`, `enterprise_readiness=false`, and `current_machine_governance=false`. It does not contact a verifier, send email, publish, release, tag, update the website, change GitHub access, deploy production, or create external attestation.
- **External verifiers**: [`docs/external-verifier-packet.md`](external-verifier-packet.md) — private-by-default verifier request packet and intake protocol for checking bounded public fixture evidence without creating a public attestation claim. The non-sending helper `tools/release-forward-verifier-dry-run.sh` can run the release-forward packet path from a fresh clone pinned to an explicit release tag and commit SHA, preserves the standalone config-backed service-preflight sample verification for `v3.3.85+`, preserves `zlar-north-star-readiness-v1.json` for `v3.3.98+`, preserves `zlar-verifier-kit-reproducibility-v1.json` for `v3.3.100+`, preserves generated sample private-intake artifacts for `v3.3.104+`, preserves `zlar-verifier-kit-public-distribution-v1.json` for `v3.3.109+`, preserves `zlar-installed-runtime-profile-preflight-sample-verification.json` for `v3.4.5+`, preserves `zlar-installed-runtime-profile-recognition-proof-v1.json` for `v3.4.7+`, preserves `zlar-installed-runtime-profile-recognition-proof-artifact-v1.json` and `zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json` for `v3.4.8+`, preserves `zlar-product-proof-path-v1.json` for `v3.4.9+`, lets `zlar north-star-readiness` consume that artifact for `v3.4.10+`, preserves `zlar-installed-runtime-profile-service-proof-v1.json`, `zlar-installed-runtime-profile-service-proof-artifact-v1.json`, and `zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json` for `v3.4.11+`, requires readiness to consume the service-proof artifact verification for `v3.4.14+`, requires service-proof artifact-verification refusal taxonomy binding for `v3.4.18+`, requires installed-runtime-profile recognition-contract digest preservation for `v3.4.19+`, preserves `zlar-verifier-kit-external-runner-diagnostics-v1.json` for `v3.4.21+`, preserves terminal-chain named refusal evidence for `v3.4.22+`, preserves terminal-chain recognition refusal groups for `v3.4.23+`, requires exact terminal-chain recognition-refusal group case IDs in the manifest for `v3.4.24+`, requires proof-smoke and North Star readiness to preserve those same exact grouped case IDs for `v3.4.25+`, requires North Star readiness observed summaries to mirror that case-ID contract for `v3.4.26+`, requires terminal-chain nested artifacts and forged inner preflight/service-proof hash refusals for `v3.4.28+`, requires verifier-owned terminal-chain nested artifact binding summaries for `v3.4.30+`, keeps public-ready verifier-kit release-asset evidence tied to the exact asset-bearing target instead of every later proof-hardening release, requires first-class local fixture issuer-status evidence in the manifest and result for `v3.4.33+`, requires first-class trusted-issuer registry recognition evidence in the manifest and result for `v3.4.35+`, and preserves `zlar-installed-runtime-profile-terminal-chain-v1.json`, `zlar-installed-runtime-profile-terminal-chain-artifact-v1.json`, and `zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json` for `v3.4.15+`; it emits a machine-readable `DRY-RUN-MANIFEST.json` with target, hashes, assertion counts, privacy flags, non-claim flags, a non-circular pointer to the generated private-intake sample without adding it to the core artifact hashes, and for `v3.4.22+` targets a `terminal_chain_refusal_evidence` section with named receipt-refusal preservation, for `v3.4.23+` grouped recognition-refusal preservation, for `v3.4.24+` exact grouped recognition-refusal case-ID preservation, for `v3.4.25+` proof-smoke/readiness report-contract preservation of `group_count=3`, `case_count=18`, and exact grouped case IDs, for `v3.4.26+` observed-summary preservation of those same readiness counts, for `v3.4.28+` nested artifact tamper refusals, for `v3.4.30+` a verifier-owned `nested_artifact_binding` summary copied from terminal-chain artifact verification, for `v3.4.33+` an `issuer_status_evidence` summary that keeps local fixture issuer-status proof separate from live issuer status, key custody, revocation truth, production trust-registry, and downstream recognition claims, and for `v3.4.35+` a `trusted_issuer_registry_recognition_evidence` summary that keeps supplied fixture recognition separate from live registry, custody, revocation, production-recognition, production-authority, sovereign-recognition, non-operator-review, and public-attestation claims; the readiness report also records that bounded pointer contract for pinned `v3.3.104+` targets without reading the manifest or creating a circular hash and consumes the optional verifier-kit public distribution posture audit, where source-build reproducibility and live release publication are separate evidence receipts; for `v3.3.107+` targets, `DRY-RUN-RESULT.md` summarizes both the manifest-side pointer and the readiness report-side pointer for human review, for `v3.4.22+` it summarizes terminal-chain named refusal evidence, for `v3.4.24+` it prints exact recognition-refusal group case IDs, for `v3.4.25+` it prints the release-forward report contract plus false stronger-claim flags, for `v3.4.26+` it prints observed-summary preservation counts for puzzle pieces 3 and 5, for `v3.4.28+` it prints terminal-chain nested artifact tamper refusals, for `v3.4.30+` it prints verifier-owned nested artifact binding body hashes and binding booleans, for `v3.4.33+` it prints issuer-status fixture verdict, no-live boundary, and false live/custody/revocation/production-registry claim flags, and for `v3.4.35+` it prints trusted-issuer registry recognition verdict, no-live boundary, malformed-registry fail-closed result, and false live-registry/custody/revocation/production-authority claim flags; `bin/zlar private-verifier-result verify` validates private intake envelopes without public attribution or public external attestation, and `--evidence-dir <dir>` recomputes declared artifact hashes against local evidence files without printing local paths; `bin/zlar north-star-readiness --private-verifier-result-verification <file>` can consume sanitized private-result verification JSON as private/internal evidence while keeping public attestation and public attribution false; `bin/zlar verifier-kit-release-assets-live-read` reads explicit-tag public release assets and can save their downloaded bytes locally for hash recomputation; `bin/zlar verifier-kit-public-distribution` audits supplied release-asset JSON and reproducibility evidence without uploading assets, reading private keys, creating external attestation, or proving production publisher-key custody; neither command sends a verifier request or creates public external attestation.
  For `v3.4.34+`, `DRY-RUN-RESULT.md` also prints private result verification
  evidence: verification verdict, recomputed evidence-dir hash status,
  artifact count, sample/non-operator boundary, and false public-attestation,
  public-attribution, and public-non-operator-review flags.
  For `v3.4.35+`, `DRY-RUN-MANIFEST.json` and `DRY-RUN-RESULT.md` also print
  trusted-issuer registry recognition evidence: supplied fixture recognition,
  malformed-registry fail-closed result, and false live-registry, custody,
  revocation, production-authority, sovereign-recognition, non-operator-review,
  and public-attestation flags.
  For `v3.4.53+` targets, the helper also accepts optional supplied private-core
  completion evidence with `--trusted-issuer-completion-proof <file>`, preserves
  `zlar-trusted-receipt-issuer-completion-proof-v1.json` and its verification
  JSON, exposes `trusted_receipt_issuer_completion_evidence`, and lets
  readiness consume the proof without making it public by default or turning it
  into source-publication, production issuer custody, hardware custody,
  production downstream recognition, public external attestation, enterprise
  readiness, real records protection, side-door closure, sovereign recognition,
  absolute human intention, or legal consent.
  For `v3.4.39+` targets, those release-forward outputs also print the terminal-chain
  trusted-registry refusal summary: case count, exact case IDs/reason codes,
  `all_refused=true`, matching terminal-chain/artifact-verification refusal
  hashes, and false stronger-claim boundaries.
  For `v3.4.41+` targets, `DRY-RUN-MANIFEST.json` also includes
  `release_forward_report_contract`, a compact machine-readable report-contract
  summary derived only from preserved local dry-run artifacts and same-manifest
  evidence; it is not a new verifier result, public external attestation,
  live registry state, key-custody proof, revocation truth, current-machine
  governance, production authority, enterprise readiness, sovereign
  recognition, or unrouted-surface coverage.
  For `v3.4.42+` targets, that contract also binds
  `ZLAR/zlar-product-proof-path-v1.json` by source path/SHA-256 and compact
  Product Proof Path fields, including PASS/evidence model, receipt-verifier
  boundary, North Star consumption, false forbidden claims, and known
  unrouted-records noncoverage visibility.
  For `v3.4.45+` targets, that Product Proof Path contract also includes the
  terminal-chain boundary consumed by the Product Proof Path report: verified
  terminal artifact, binding/refusal hashes, exact trusted-registry refusal
  IDs/reasons, omitted public-key material, omitted receipt envelope, false
  external attestation, and false current-machine governance.
  Current local post-v3.4.50 proof-hardening also preserves the terminal-chain
  binding's own local `RECOGNIZED` verdict, issuer status, signature validity,
  local registry evaluation facts, and contract hashes in Product Proof Path and
  North Star readiness summaries.
  For `v3.4.46+` targets, it also includes exact grouped recognition-refusal
  case IDs from that Product Proof Path terminal-chain boundary.
  For `v3.4.47+`, private result verification over an evidence directory also
  validates that content contract from `DRY-RUN-MANIFEST.json`: the Product
  Proof Path terminal-chain boundary and its North Star mirror must preserve
  3 groups, 18 case IDs, and `preserved=true`. For `v3.4.48+`, the same
  private intake check also validates the Product Proof Path deployment-profile
  authority bridge and its North Star mirror. For `v3.4.49+`, it also validates
  the exact five-case deployment-profile authority refusal contract and
  before-service-proof boundary. For `v3.4.50+`, release-forward packets also
  validate the terminal-chain/proof-smoke/North Star mirror of that same
  five-case refusal contract. For future `v3.4.51+` local targets, the same
  release-forward/private-intake path also requires the Product Proof Path
  terminal-chain trusted-registry verdict/evaluation facts and
  downstream-refusal marker boundary in both the Product Proof Path contract and
  North Star mirror, including exact downstream refusal reasons and
  all-refusals-unboarded flags, while `v3.4.50` omits those fields.
  `DRY-RUN-RESULT.md` prints the private-intake content-binding status for
  human review. This is still private/internal intake only, not public external attestation,
  public attribution, non-operator review, production authority, enterprise
  readiness, current-machine governance, or unrouted-surface coverage.
- **If an agent took an action that affected you**: [`docs/if-an-agent-affected-you.md`](if-an-agent-affected-you.md) — how to find, verify, and contest.

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
sdk/           SDK, daemon, AuthZEN PDP, hook adapter
cedar-poc/     Cedar formal policy — base ruleset and per-regulation mappings
```

## Design decisions

| ADR | Decision |
|-----|----------|
| [001](adr/ADR-001-deterministic-enforcement.md) | Deterministic enforcement, not AI |
| [002](adr/ADR-002-bash-implementation.md) | Bash as implementation language |
| [003](adr/ADR-003-fail-closed.md) | Fail-closed as default |
| [004](adr/ADR-004-ed25519-signing.md) | Ed25519 for signing |
| [005](adr/ADR-005-manifest-narrows-policy.md) | Manifest narrows policy, never widens |
| [006](adr/ADR-006-structural-independence.md) | Structural independence from governed system |
| [007](adr/ADR-007-receipt-v1-envelope.md) | Receipt v1 envelope format |
| [008](adr/ADR-008-restorative-governance.md) | Restorative governance — observe, do not enforce |
| [009](adr/ADR-009-second-authority-law.md) | Second Authority Law |
| [010](adr/ADR-010-interception-coverage.md) | Interception coverage model |
| [011](adr/ADR-011-canonical-form-migration.md) | Canonical form migration |
| [012](adr/ADR-012-hash-chain-hardening.md) | Hash chain and non-repudiation hardening |

## Further reading

- [CONTRIBUTING.md](../CONTRIBUTING.md) — who decides, and the rules that don't bend
- [SECURITY.md](../SECURITY.md) — vulnerability disclosure, security principles
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to contribute
- [LEGAL.md](../LEGAL.md) — regulatory classification, liability, data processing
- [CHANGELOG.md](../CHANGELOG.md) — version history
