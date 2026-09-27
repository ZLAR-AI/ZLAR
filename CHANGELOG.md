# Changelog

Historical release entries preserve the wording that was accurate for that
release. Current public verifier and attestation boundaries are governed by the
latest release entry plus README, the external verifier packet, and the
governed-surface coverage map; older "pending" language is historical, not the
current public claim.

Historical entries may name maintainer-local observations, retired transport
paths, or old placeholder paths as provenance. Preserve that history. New
entries and public release preparation must pass `bash
tests/test-public-privacy.sh` unless a specific historical exception is reviewed
and documented.

## Unreleased

- Security: Demo 1 destination authority now checks challenge, grant, and
  credential freshness at record formation and the final application decision
  before transaction commit. Expiry or a backward clock reading rolls back
  allocation, consumption, the protected effect, and execution evidence.
  Commit and receipt timestamps retain their actual sampled values.
- Added deterministic expiry and clock-regression cases with offline evidence
  verification, and CI coverage for the portable Demo 1 source suites and
  source manifest. This source fix does not update an installed service.

- Added one exact local-disposable-fixture authority-grant contract for
  `protected-records.installed-runtime-profile.terminal-chain.records.write`,
  binding the authority domain, grantor role, issuer slot, target, runtime
  profile, recognition and target contracts, authorized effect, policy,
  half-open time window, and exact issue/renew/revoke powers.
- Enforced the ordered launcher transition from receipt recognition to grant
  issuance/effect evaluation, one-use grant consumption, and state mutation;
  missing, mismatched, expired, revoked, request-supplied, consumed, and replay
  cases fail before the protected effect.
- Preserved separate 18-case recognition and 5-case authority refusal
  taxonomies, fixed signed-payload replay identity, named non-atomic grant-burn
  windows, and evidenced that joint rollback of the local store, anchor, and
  witness can reopen grant reuse.
- Extended the terminal chain and `consequence-lifecycle-map-v0` with the full
  public fixture grant topology while keeping generic, portable, live,
  production, current-machine, and consequence-lifecycle-closure claims false.
- Reconciled the contract's `max_uses=1` and logical-fixture scope against the
  execution record, source-recorded contract
  `0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba`
  as exhausted, and made fresh effect use and repeated-use provenance fail
  closed as `authority_grant_contract_exhausted`.
- Demoted current fixture-rightful issuance and consequence-dependent coverage:
  the static map is now `4/6` governed, while historical exact-SHA artifacts
  retain identity, boarding, refusal, target, and side-door evidence without
  renewing permission.
- Added pre-effect exhaustion guards across direct generators, recursive
  wrappers, CLIs, Product Proof Path, proof-smoke, and readiness composition so
  fresh stores, temporary roots, default arguments, or exact artifact pins
  cannot act as replacement authority.
- Refused active-persistent live installation and closeout before activation-root
  inspection or mutation because the fixture grant never authorizes persistent
  profile mutation; a replacement fixture grant cannot reactivate that path.
- Made the assertion harness skip 37 legacy success-expecting suites as
  authority-inactive, retained focused current refusal/static tests, and stopped
  auto-discovery from executing non-test helper modules.

## 3.4.60 — 2026-07-08 — Active persistent profile and one-terminal Trusted Issuer hardening

### v3.4.60 - Active persistent profile and one-terminal Trusted Issuer hardening

- `v3.4.60` is a private-core checkpoint candidate for the active persistent
  profile path, named deployment-profile boundary, one-terminal Trusted Issuer
  completion path, and release-forward evidence-intake hardening that followed
  `v3.4.59`.
- Added source support and verifier coverage for the active persistent profile
  sequence: source preflight, path-guard hardening, live installation source
  support, governed-action crossing proof, strict lifecycle binding, and
  historical lifecycle readiness intake. The profile remains a bounded
  private-core proof path, not arbitrary current-machine governance.
- Added named deployment-profile real-boundary and readiness rehearsal support
  so the stronger North Star boundary can name which profile, action class,
  authority bridge, and refusal path are being exercised instead of implying
  all surfaces are governed.
- Added one-terminal Trusted Issuer evidence support: surface naming, private
  authority-record ceremony evidence, public-key identity scratch fact,
  hash-bound signed-receipt completion proof, and readiness consumption that
  moves the Trusted Issuer piece without turning scratch evidence into
  production custody.
- Hardened release-forward evidence intake for optional supplied private-core
  Trusted Issuer completion proof evidence, including explicit sidecar
  provenance, verifier output hashes, readiness consumption, and checkout-root
  refusal when a proof file appears without the explicit supplied-proof flag.
- Preserved the public/source split: `v3.4.59` remains the bounded public
  verifier-kit distribution readiness checkpoint on `zlar.ai`; this private
  source checkpoint prepares a later honest release-forward target instead of
  updating public metadata by implication.
- Covered post-`v3.4.59` prep commits: `c0e5b7c` (source bridge window
  protocol), `1f4247c` (source bridge window verifier), `5a12a2e` (source
  bridge proof-smoke sample), `c84e87a` and `a01e65c` (private ZIP verifier
  result intake), `62bb230` and `1d3b461` (one-terminal/readiness trigger
  summaries), `8a6c265` (static verifier-kit artifact evidence), `79037ef`
  and `6ea2441` (stronger North Star/deployment proof provenance), `c361b41`
  and `d6a9074` (named deployment-profile rehearsal and real-boundary proof),
  `d30693e`, `5d304dd`, `9b91bce`, `7a5ea02`, `41020b1`, `acf5806`,
  `184bb07`, and `9d9de6d` (active persistent profile and lifecycle path),
  `cabf0a6`, `778f53c`, `34d698d`, and `874ed18` (one-terminal Trusted Issuer
  surface and evidence-intake hardening).
- Boundary: `v3.4.60` is private-core release-prep only. It does not create or
  push a tag, publish a GitHub Release, align the public website, run GitHub
  Actions, publish current core source, grant source-transport credentials,
  create or store credential material, inspect private keys/tokens/HMAC/signing
  material, prove production issuer custody, prove hardware-backed custody,
  prove live issuer status, prove revocation truth, prove production downstream
  recognition/refusal, prove enterprise readiness, prove current-machine or
  all-surface governance, protect real records, close side doors, create public
  external attestation, claim sovereign recognition, prove absolute human
  intention, or alter the prior Apache-2.0 non-clawback boundary.

## 3.4.59 — 2026-07-05 — Runner, source transport, and configured-recognition hardening

### v3.4.59 - Runner, source transport, and configured-recognition hardening

- `v3.4.59` is a private-core checkpoint candidate for the ZLAR-owned runner,
  no-secret source transport, configured-recognition consumer path, and
  replay-store proof hardening that followed `v3.4.58`.
- Added a bounded ZLAR-owned `zlar run` surface that is designed to spawn only
  after a gate allow and matching audit evidence, with focused runner tests and
  receipt-binding hardening. The runner surface remains narrower than raw
  Codex desktop/developer-tool governance or all-shell governance.
- Added a no-secret GitHub App source-transport preflight and proof verifier
  path that validates source-movement report shape and private-key/token
  refusal boundaries without minting tokens, inspecting private keys, moving
  source by itself, or claiming durable source transport.
- Added no-secret GitHub App token-lifecycle wrapper tests and source-transport
  contract checks so credential-shaped material stays outside the no-secret
  harness while token and remote-ref/source-movement live crossings remain
  separately authorized evidence.
- Repaired no-secret source-transport and configured-recognition source/tests so
  repo-local paths are derived at runtime or expressed as neutral placeholders,
  preserving the public privacy guard against operator-local path residue.
- Added a configured-recognition verifier, configured-recognition consumer
  adapter, fake effect attestation/observer binding, and local fake replay-store
  path so one configured recognition can permit one fake effect while replay,
  invalid store state, stale/missing/forged material, request-supplied authority
  material, and false-boundary drift refuse before callback/effect.
- Added `zlar configured-recognition-consumer-replay-store-proof` and indexed
  that proof in `zlar proof-smoke`, with deterministic redacted output,
  fixture/report validation, fail-closed proof-smoke drift checks, and Product
  Proof Path / North Star readiness checks confirming the new proof is not
  promoted into a stronger readiness claim.
- Covered post-`v3.4.58` commits: `8cbd420` (ZLAR-owned runner), `80c5b16`
  (runner evidence binding), `88e66b3` (runner receipt binding), `0da556b`
  (runner issuer-recognition proof), `5a793ec` (source transport preflight),
  `5194e44` (GitHub App token lifecycle wrapper), `bf705c6` (source transport
  proof verifier), `7835944` (configured-recognition verifier), `7d85643`
  (configured-recognition consumer adapter), `9bb8e12` (effect attestation
  hardening), `bc97713` (fake effect observer binding), `21330f7`
  (configured-recognition replay store), `a1a4b1c` (replay-store proof
  harness), and `4c81a6e` (proof-smoke replay-store aggregation).
- Boundary: `v3.4.59` is private-core release-prep only. It does not tag or
  publish a GitHub Release, align the public website, run GitHub Actions, grant
  source-transport credentials, create or store credential material, inspect
  private keys/tokens/HMAC/signing material, prove durable source transport,
  prove production durable replay persistence, prove tamper-resistant or
  multi-host replay storage, prove live key custody, prove a production trust
  registry, prove live or production downstream recognition/refusal, create
  external attestation, install or activate ZLAR, mutate hooks/config, prove
  current-machine governance, prove all-surface governance, close side doors,
  claim public alignment, or alter the prior Apache-2.0 non-clawback boundary.

## 3.4.58 — 2026-07-01 — Trusted Receipt Issuer completion proof contract

### v3.4.58 - Trusted Receipt Issuer completion proof contract

- `v3.4.58` is a private-core checkpoint candidate for Trusted Receipt Issuer
  completion proof-contract hardening after `v3.4.57`.
- Added and remotely proved the bounded Trusted Receipt Issuer completion proof
  contract for the selected Star One surface:
  `protected-records.runtime.profile-installation.records.write`.
- The proof contract adds and verifies the `recognized_authority_event`
  boundary. It preserves the sentence:
  `Receipts prove recognized authority events, not absolute human intention.`
- The proof validates a v1 receipt identity, active issuer recognition fixture,
  selected-surface destination/action/detail binding, revocation/status refusal
  posture, and fail-closed refusal cases without treating the result as live
  key custody, a signing/key-custody ceremony, production relying-party trust,
  external attestation, or absolute human intent.
- Repaired installed proof context handling so installed-safe proof commands can
  bind installed-local proof context without pretending the installed tree is a
  source checkout, while preserving repo-source proof behavior for CI/source
  verification.
- Covered post-`v3.4.57` commits: `001341d` (installed proof context handling)
  and `5eafcf1` (Trusted Receipt Issuer completion proof contract).
- Boundary: `v3.4.58` is private-core release-prep only. It does not tag or
  publish a GitHub Release, align the public website, install or activate ZLAR,
  grant install/config authority, run a signing/key-custody ceremony, prove
  live key custody, prove a production trust registry, create customer
  relying-party trust, create external attestation, emit a live receipt, prove
  live or production downstream recognition/refusal, prove current-machine
  governance, prove hardware-backed custody, prove all-surface governance,
  close side doors, claim public alignment, or alter the prior Apache-2.0
  non-clawback boundary.

## 3.4.57 — 2026-07-01 — Private proof-chain and source-boundary hardening

### v3.4.57 - Private proof-chain and source-boundary hardening

- `v3.4.57` is private-core release-prep for the proof-chain, receipt
  identity, local destination boarding, source-boundary, automation-freeze, and
  CI proof-repair work that followed `v3.4.56`.
- Hardened local proof-pack, proof-smoke, Product Proof Path, and North Star
  readiness evidence so portable artifacts and generated verifier plans bind
  required hashes, component identities, source-boundary non-claims,
  required-result identity, bundle identity, artifact-set identity, and
  recomputed-evidence posture instead of accepting stale, summary-only, or
  overclaiming evidence.
- Added v1 receipt verifier required identity for the local verifier path:
  canonical signed receipt object SHA-256, supplied public-key SHA-256,
  receipt id, `kid`, format, v1-only posture, required identity, and command
  posture are exposed and enforced where requested. Legacy v0 remains
  compatibility-only and cannot satisfy recognized boarding identity.
- Propagated v1 receipt identity into receipt-verifier boundary proof,
  proof-pack, proof-smoke, Product Proof Path, and North Star readiness
  consumers, then clarified human-readable receipt scanner output so `VALID`,
  `INVALID`, and `UNKNOWN-SIGNER` remain local verifier results rather than
  issuer trust, downstream recognition, or governance claims.
- Hardened the local protected-records destination boarding proof so the local
  fixture destination refuses consequence for missing, invalid, unknown-issuer,
  inactive-issuer, wrong-destination, wrong-action, wrong-policy, stale,
  wrong-detail, v0, replayed, summary-only, malformed, and false-boundary
  material, accepts one recognized v1 receipt once, proves consequence absence
  on every refusal, and proves consequence presence exactly once on acceptance.
- Added and consumed a skinny protected-records boarding decision helper so
  runtime/profile code can exercise the bounded decision path without pulling
  in proof-pack, proof-smoke, Product Proof Path, GitHub/release/source-state,
  installed-config, website, or public-metadata machinery.
- Transitioned the private core source boundary to proprietary/commercial
  source while preserving explicit non-clawback language: prior ZLAR source
  distributions that were public under Apache-2.0 remain governed by
  Apache-2.0 and are not revoked, narrowed, clawed back, or altered by the
  current private-core license posture. Verifier-kit and thin public artifacts
  keep their own explicitly named license boundaries.
- Froze Dependabot version updates in source by removing the active
  `.github/dependabot.yml` / `.github/dependabot.yaml` config surface and
  preserving the frozen posture as `.github/dependabot.yml.frozen`, because the
  dynamic Dependabot Updates surface cannot be disabled through the normal
  workflow-disable endpoint.
- Repaired the private-main CI proof window by restoring the exact
  release-asset repository binding in `docs/cli-reference.md` without
  reopening public clone/source-inspection/open-source claims for current
  private core, and by deriving the runtime preflight CLI proof-case expectation
  from the 32-case runtime proof contract.
- Covered post-`v3.4.56` commits: `2f16bdf` (installer health-copy wording),
  `b83d55a` (installer health-copy assertion count), `01ac74f`
  (local proof-pack Claude hook replay), `76eeecd` (hook replay evidence
  hardening), `6933ba0` (portable proof-pack artifact verification),
  `c91c737` (proof-pack artifact required hash), `31bdcb3` (proof-smoke report
  required hash), `3dc92d1` (proof-smoke sample proof-pack identity),
  `3a27b1e` (proof-smoke artifact verifier required hashes), `5bcd73f`
  (recognition proof verifier required hash), `0e32e78` (approval packet
  required hash), `8f19192` (private verifier result required identity),
  `a858c70` (release-forward private verifier plan identity), `bd12a8e`
  (receipt verifier required identity), `d7c8920` (v1 receipt identity proof
  propagation), `0a906be` (receipt verifier display boundary), `d734c8b`
  (local destination boarding proof), `e9d6539` (skinny boarding decision
  helper guard), `c430578` (runtime profile helper consumption), `3d652f5`
  (private-core source boundary transition), `c3c7168` (Dependabot version
  update freeze), and `1b5a3ed` (private-main CI proof repair).
- Boundary: `v3.4.57` is private-core release-prep only. It does not tag or
  publish a GitHub Release, align the public website, grant source access,
  create customer commercial terms, claim counsel approval, install or activate
  ZLAR, grant install/config authority, prove live Claude app passage, prove
  app-originated hook crossing, prove current-machine governance, emit a live
  receipt, prove live or production downstream recognition/refusal, prove
  all-surface governance, close side doors, prove enterprise readiness, create
  external attestation, prove sovereign recognition, claim public GitHub/source
  inspection, claim public clone/install access, claim public CI visibility, or
  claim GHAS/code-scanning dashboard evidence for the private repo.

## 3.4.56 — 2026-06-28 — Local Claude hook-contract replay proof

### v3.4.56 - Local Claude hook-contract replay proof

- `v3.4.56` is private-core release-prep for the local Claude Code
  hook-contract replay layer and the repo hardening needed to keep private-core
  evidence truthful after `v3.4.55`.
- Added `zlar claude-code-hook-contract-replay-proof --json` with proof type
  `zlar-claude-code-hook-contract-replay-proof-v1`. The command uses built-in
  fixtures, defaults to the repo adapter source for CI hermeticity, and names
  its evidence model as local fixture/hook-contract replay, not live Claude app
  passage.
- The hook-contract replay proof covers allow JSON, deny JSON, denied-effect
  non-execution, adapter-does-not-execute-tool-input, missing-gate fail-closed,
  blank-gate fail-closed, malformed-output refusal, wrong-hook-event fixture
  refusal, and supporting protected-records local boarding proof.
- Repaired scoped Claude Code post-install proof blockers in the repo package
  surface by including dispatcher-required proof wrappers in the install plan
  and preserving Claude hook deny JSON output when the gate denies, without
  claiming installed-machine proof changes from repo-only work.
- Hardened private-core verifier continuity after `v3.4.55` by recognizing the
  explicit private-core `v3.4.55` Claude Code approval packet while preserving
  strict source-target verification, installer hash binding, dry-run identity
  binding, expiry/replay checks, delegation binding, backup/rollback
  requirements, and non-claim boundaries.
- Replaced GitHub-code-scanning-dependent private security workflow behavior
  with truthful private security evidence. Private CodeQL and Scorecard checks
  remain CI/security workflow evidence, not GHAS/code-scanning dashboard
  evidence, public CI visibility, or public source inspection.
- Covered post-`v3.4.55` commits: `eba05e6` (recognize `v3.4.55` approval
  packet), `da2c272` (private checkout workflow permissions), `df626fc`
  (private security workflow permissions), `55bb864` (Scorecard SARIF upload
  permissions), `c71e25e` (private security evidence without code-scanning
  upload), `fb5e317` (Claude Code post-install proof blocker repair), and
  `e034255` (local Claude hook-contract replay proof).
- Boundary: `v3.4.56` is private-core release-prep only. It does not publish or
  align public website metadata, prove live Claude Code application passage,
  prove app-originated hook crossing, prove current-machine governance, emit a
  live receipt, prove production downstream recognition or refusal, grant
  install/config authority, prove all-surface governance, close side doors,
  prove enterprise readiness, create external attestation, prove sovereign
  recognition, claim public GitHub/source inspection, claim public clone/install
  access, or claim GHAS/code-scanning dashboard evidence for the private repo.

## 3.4.55 — 2026-06-28 — Scoped Claude Code authority binding and local boarding proof

### v3.4.55 - Scoped Claude Code authority binding and local boarding proof

- `v3.4.55` packages post-`v3.4.54` repo hardening that tightens the scoped
  Claude Code pre-authority install path, preserves strict source-target and
  installer/plan/request binding for approval packet, intake, and
  request-preview verification, repairs CI checkout depth so local Git-object
  checks remain strict, and adds a local in-memory protected-records
  `records.write` boarding proof.
- Extended scoped Claude Code existing-install handling so existing installs
  remain fail-closed by default, `no-op`, `repair`, `upgrade`, and `reinstall`
  are explicit modes under `--surface claude-code --no-machine-helpers`,
  unknown-version repair refuses before writes, and write-capable modes remain
  backup-review-gated. `install.sh` reports the boundary but does not create
  backups.
- Hardened the current-machine approval packet, intake, and request-preview
  chain so no future install/config authority request can be prepared unless
  source target, installer identity, command posture, dry-run plan identity,
  authority request identity, selected surface, hook target, delegation target,
  issuer/policy, receipt path, downstream refusal matrix, backup/rollback
  requirements, and explicit non-claims are preserved and verified.
- Repaired CI checkout depth for approval-packet tests so historical local Git
  objects required by source-target verification are present in CI. Missing
  local Git objects still refuse; verifier strictness was not weakened.
- Added `zlar protected-records-local-boarding-proof` with proof type
  `zlar-protected-records-local-boarding-proof-v1`. The command runs a local,
  in-memory, fixture-only protected-records `records.write` boarding proof
  where one simulated destination accepts one recognized current-implementation
  receipt once and refuses missing, invalid, unknown-issuer, inactive-issuer,
  wrong-detail, and replayed receipts before local effect.
- Bounded the local boarding proof source-state scan so CI avoids unbounded
  untracked-file traversal while preserving clean/dirty source-state evidence.
- Covered post-`v3.4.54` commits: `e515a2f` (scoped Claude Code
  existing-install handling), `15dc159` (scoped Claude Code install authority
  binding), `c045129` (CI checkout repair for strict source-target
  verification), `2a11a78` (protected-records local boarding proof), and
  `a11afff` (bounded local boarding source-state scan).
- Boundary: `v3.4.55` is release-prep for repo hardening and local fixture
  proof only. It does not install or activate ZLAR, grant install/config
  authority, write hooks/profiles/services/user or machine config, prove
  current-machine governance, prove live hook execution, emit a live receipt,
  prove live or production downstream recognition, automate backup/rollback,
  prove production authority, prove enterprise readiness, create external
  attestation, prove sovereign recognition, prove live registry truth, prove
  live issuer truth, prove revocation truth, prove key-custody truth, prove
  full receipt-v1 conformance, prove durable replay or exactly-once production
  effects, or close unrouted surfaces.

## 3.4.54 — 2026-06-27 — Scoped Claude Code pre-authority install readiness

### v3.4.54 - Scoped Claude Code pre-authority install readiness

- `v3.4.54` packages a no-write/current-machine pre-authority chain and scoped
  Claude Code installer readiness, including packet verification, intake,
  request-preview verification, and a real
  `install.sh --surface claude-code --no-machine-helpers` posture.
- Added a Claude Code receipt bridge proof for the scratch protected-records
  `records.write` action class, preserving local-fixture evidence, receipt
  binding, refusal-before-mutation behavior, and no-live/no-production claim
  boundaries.
- Extended `install.sh --dry-run --json` with a machine-readable
  `current_machine_governance_design` boundary that names the selected surface,
  future approval-packet fields, downstream recognition refusal cases, and
  pre-claim checks for a one-surface current-machine governance path.
- Added the scoped current-machine install design boundary, making the
  approval packet, hook target, issuer/policy, receipt path, downstream
  refusal matrix, side doors, and non-claims explicit before any real
  install/config authority can be requested.
- Added `zlar current-machine-approval-packet verify` for selected-surface
  Claude Code approval packets. The verifier checks selected surface, hook
  target, issuer/policy, receipt path, downstream refusal matrix, and explicit
  non-claims while refusing incomplete, mutating, authority-bearing, or
  overclaiming packets.
- Added `zlar current-machine-approval-intake --packet <file|->`, which runs
  the packet verifier on an explicit packet and refuses to prepare install/
  config authority unless the packet is complete. Valid intake reports preserve
  `authority_request_allowed=true` and `authority_request_made=false`.
- Added `zlar current-machine-approval-request-preview --intake <file|->`,
  which consumes an intake report and refuses unless the intake allows
  authority-request preparation, no authority request has been made, packet
  verification is complete, required packet sections are preserved, and no
  install/config/live/current-machine governance claim is present.
- Promoted `install.sh --surface claude-code` from dry-run-only planning to a
  real scoped installer mode without running it. In scoped Claude Code mode,
  the installer selects only the Claude Code surface, keeps dry-run output
  aligned with the real scoped path, does not silently configure Cursor or
  Windsurf, and can omit optional `/usr/local/bin` helper writes with
  `--no-machine-helpers`.
- Aligned the current-machine approval packet fixture with the installer's real
  Claude Code hook target: `~/.zlar/adapters/claude-code/hook.sh`.
- Covered post-`v3.4.53` commits: `bf76965` (Claude Code receipt bridge
  proof), `e8887d3` (scoped install dry-run surface planning), `b52f5f5`
  (current-machine install design boundary), `793fc35` (approval packet
  verifier), `16fa86c` (approval packet test count output), `45683bf`
  (approval intake gate), `9af1c21` (approval request-preview verifier), and
  `fceba67` (scoped Claude Code install mode).
- Boundary: `v3.4.54` is scoped release-prep for no-write pre-authority and
  installer-readiness evidence only. It does not install or activate ZLAR,
  write hooks/profiles/services/user or machine config, prove current-machine
  governance, prove live hook execution, prove live receipt emission, prove
  live downstream recognition, prove production authority, prove enterprise
  readiness, create external attestation, prove sovereign recognition, prove
  live registry truth, prove live issuer truth, prove revocation truth, prove
  key-custody truth, or close unrouted surfaces.

## 3.4.53 — 2026-06-27 — No-write install planning and receipt-path guard hardening

### No-write install planning and receipt-path guard hardening

- Hardened future-local private-verifier and release-forward intake for compact
  recognized receipt-path mirror keys, rejecting missing, extra, renamed, and
  summary-shaped receipt-path fields without changing receipt semantics.
- Clarified protected-records terminal-chain first-run help as proof-only
  sample evidence and preserved the false install, activation,
  current-machine, and production-recognition boundary.
- Hardened public privacy/claim guard coverage for the active changelog window,
  recognition-overclaim wording, path allowlist behavior, `profiles/`, and
  `demos/`, while preserving legitimate local fixture recognition language and
  historical release provenance.
- Mirrored compact proof-smoke facts for artifact-owned
  `recognized_receipt_path_evidence` without mirroring the full evidence
  object or adding raw receipt envelopes, raw key material, signature bytes,
  private paths, or cryptographic reconstruction material.
- Added `install.sh --dry-run --json` as a no-write pre-install planning
  surface that reports detected client surfaces, planned file writes, existing
  ZLAR hook/profile conflicts, required human approvals, side doors left open,
  exact non-claims, and real-install write-effect booleans.
- Aligned README, troubleshooting, architecture map, CLI reference, and
  `zlar doctor` wording with the no-write install-plan reality: installer-
  managed hook/profile wording is limited to detected Claude Code, Cursor, and
  Windsurf, while Codex hook reality remains host/version-specific and must be
  locally verified before claiming a Codex route is governed.
- Boundary: `v3.4.53` hardens recognized receipt-path verifier evidence,
  proof-smoke summaries, public privacy/claim guard loops, proof-only first-run
  wording, and no-write install planning while preserving the `v3.4.52`
  proof-only, non-production, non-attestation, non-current-machine governance
  claim boundary. It does not install or activate ZLAR, write hooks/profiles/
  services/user or machine config, prove this Codex session is routed, prove
  current-machine governance, inspect live records, prove live MCP coverage,
  prove live trust-registry state, prove live issuer status, prove key custody,
  prove revocation truth, prove production downstream recognition, prove
  production authority, prove enterprise readiness, create public external
  attestation, prove public non-operator review, prove sovereign recognition,
  close unrouted surfaces, or prove that proof-only sample commands govern this
  machine.

## 3.4.52 — 2026-06-26 — Recognized receipt-path evidence hardening

### Recognized receipt-path evidence hardening

- Hardened the protected-records installed-runtime-profile terminal-chain
  artifact so artifact-contained recognized receipt-path evidence is
  distinguished from summary-only recognition and verification rejects missing,
  tampered, mismatched, summary-shaped, or unrecognized receipt-path evidence.
- Added compact recognized-receipt-path verifier facts to Product Proof Path
  and North Star readiness summaries without mirroring the full evidence
  object or adding raw receipt envelopes, raw key material, signature bytes,
  private paths, or cryptographic reconstruction material.
- Hardened future-local private-verifier and release-forward intake for the
  compact recognized-receipt-path mirror with version-gated, prefix/family
  scoped validation that rejects missing, extra, renamed, summary-shaped,
  tampered, source-binding-mismatched, or false-boundary-flipped mirror fields
  while preserving public `v3.4.51` evidence compatibility.
- Clarified the first safe protected-records run as proof-only sample evidence
  through README, CLI reference, runtime-profile installation help,
  installed-runtime-profile preflight help, and focused CLI tests.
- Boundary: `v3.4.52` hardens local protected-records recognized-receipt-path
  evidence by making receipt-path recognition artifact-owned, compactly
  mirrored into local proof summaries, and version-gated in
  private-verifier/release-forward intake, while clarifying that first-run
  protected-records commands are proof-only. It does not install or activate
  ZLAR, write hooks/user or machine config, start a live runtime service,
  inspect live records, prove current-machine governance, prove live
  trust-registry state, prove live issuer status, prove key custody, prove
  revocation truth, prove production downstream recognition, prove production
  authority, prove enterprise readiness, create public external attestation,
  prove public non-operator review, prove sovereign recognition, close
  unrouted surfaces, or prove that proof-only sample commands govern this
  machine.

## 3.4.51 — 2026-06-25 — Protected-records refusal and claim-boundary hardening

### Protected-records refusal and claim-boundary hardening

- Extended `zlar records-write-terminal-proof` with a machine-readable
  downstream refusal contract that preserves exact case IDs, refusal classes,
  expected/observed reason codes, before-mutation booleans, direct-API
  markers, and zero state-delta evidence for 21 local runtime refusal cases.
- Strengthened the local protected-records adapter tests so the actual
  `protected-records-write` mutation boundary refuses missing, invalid,
  stale/expired, unrecognized-issuer, wrong-policy, out-of-scope,
  binding-mismatch, and non-boarding receipts before ledger append.
- Strengthened the local protected-records service commit boundary so a
  post-append consumed-receipt store failure rolls back the service-state bytes
  and burns no receipt in fixture evidence.
- Strengthened installed-runtime-profile preflight selection so a symlinked
  `profiles/` parent is refused and active-index/profile reads must resolve
  inside the explicit install root before "selected from install root" can be
  reported.
- Strengthened one-terminal deployment-profile authority refusals so reported
  refusal reasons come from the actual failed bridge input, reason drift fails
  validation, and malformed preflight artifacts cannot satisfy the authority
  bridge.
- Made the runtime-profile request identity policy explicit: a request may omit
  `runtime_profile_id` because the launcher-owned service config is
  authoritative, while a supplied mismatched runtime-profile id is still refused
  before mutation as agent-supplied authority material.
- Hardened receipt freshness wording and tests around signed `payload.ts`,
  envelope `iat` mutation, future skew, stale payloads, and replay-after-TTL
  precedence while preserving the `receipt_stale`/`stale_or_expired` contract
  and not introducing a separate `receipt_expired` state.
- Sandboxed release-forward dry-run tag-dependent checks so transient test tags
  are created only in disposable repositories/worktrees and the main repo tag
  namespace is left unchanged.
- Hardened private-verifier and release-forward intake for `v3.4.51+` local
  targets with exact-key compact objects and prefix-scoped trusted-registry,
  downstream-refusal, deployment-profile authority, pointer, checksum, evidence
  hash, proof-summary, readiness, verifier-kit, and proof-pack claim-boundary
  validation, while preserving `v3.4.50` omission behavior and intentionally
  evolvable aggregate summaries.
- Clarified the external-verifier packet request boundary without sending a
  verifier request, creating public attribution, or creating public external
  attestation.
- Added `docs/AUTHORITY-MAP.md`, documentation authority banners on the
  highest-risk stale-map files, and release-readiness routing language so stale
  process/history notes are not treated as live authority.
- Added and hardened the public privacy/claim guard loop for repo public
  surfaces, including scoped allowlist behavior and release-readiness wording
  requiring `bash tests/test-public-privacy.sh` before public tag, GitHub
  Release, or website alignment.
- Added a separate website-side privacy/claim guard checkpoint in
  `ZLAR_Website` without changing website copy, release metadata, or aligning
  the website to this candidate.
- Boundary: `v3.4.51` hardens local protected-records downstream-refusal
  evidence, verifier/release-forward intake schema validation, documentation
  authority routing, and public privacy/claim guard loops while preserving the
  `v3.4.50` local-fixture, non-production, non-attestation,
  unrouted-surface-open claim boundary. It does not prove live records-system
  coverage, persistent install, activation, live runtime service,
  current-machine governance, live trust-registry state, live issuer status,
  key custody, revocation truth, production downstream recognition, production
  authority, enterprise readiness, public external attestation, public
  non-operator review, sovereign recognition, or closure of unrouted surfaces.

## 3.4.50 — 2026-06-23 — Terminal-chain authority-refusal mirror

### Terminal-chain authority-refusal mirror

- `zlar protected-records-installed-runtime-profile-terminal-chain` now mirrors
  the five deployment-profile authority refusal cases from the one-terminal
  deployment-profile fixture into terminal-chain evidence and terminal-chain
  artifact verification.
- `zlar proof-smoke`, North Star readiness, and release-forward dry-run evidence
  now require and preserve that terminal-chain mirror for sample evidence and
  `v3.4.50+` targets: exact five case IDs, before-service-proof refusal,
  before-mutation refusal, service-proof-not-started, and false
  current-machine/production/enterprise/external/sovereign/unrouted claims.
- Boundary: this is local fixture evidence and release-forward packet
  hardening. It does not install, activate, inspect live records, prove
  current-machine governance, prove production downstream recognition, prove
  production authority, prove enterprise readiness, create external
  attestation, prove sovereign recognition, or cover unrouted surfaces.

## 3.4.49 — 2026-06-23 — Deployment-profile authority refusal contract

### Deployment-profile authority refusal contract

- `zlar protected-records-one-terminal-deployment-profile` now proves five
  deployment-profile authority refusal cases before service proof starts:
  stale deployment-profile runtime SHA, runtime-profile id mismatch,
  preflight profile SHA mismatch, preflight `--latest` selection, and
  preflight request-stream authority material.
- `zlar product-proof-path`, North Star readiness, release-forward dry-run
  evidence, and private intake evidence-dir verification now preserve that
  authority-refusal case list and fail closed if the Product Proof Path or
  North Star mirror drops, mutates, starts service proof for, or weakens those
  pre-service refusal facts for `v3.4.49+` targets.
- Boundary: this is local fixture proof and release-forward/private-intake
  content-binding hardening only. It does not install, activate, start a live
  runtime service, inspect live records, prove current-machine governance,
  prove production downstream recognition, prove production authority, prove
  enterprise readiness, create external attestation, prove sovereign
  recognition, or cover unrouted surfaces.

## 3.4.48 — 2026-06-23 — Product Proof Path deployment-profile authority bridge

### Product Proof Path deployment-profile authority bridge

- Added `zlar protected-records-one-terminal-deployment-profile`, a local
  fixture proof that validates a deployment-owned profile artifact, binds the
  selected protected-records runtime profile by explicit id and SHA-256,
  consumes the matching installed-profile preflight artifact, and proves through
  a local disposable child-service proof that one recognized receipt mutates
  once while all 18 required refusal cases mutate zero state.
- `zlar product-proof-path`, North Star readiness, release-forward dry-run
  evidence, and private intake evidence-dir verification now preserve the
  deployment-profile authority bridge for `v3.4.48+` targets.
- Boundary: this is local fixture proof and release-forward/private-intake
  content-binding hardening only. It does not install, activate, start a live
  runtime service, inspect live records, prove current-machine governance,
  prove production downstream recognition, prove production authority, prove
  enterprise readiness, create external attestation, prove sovereign
  recognition, or cover unrouted surfaces.

## 3.4.47 — 2026-06-23 — Private intake Product Proof Path content binding

### Private intake Product Proof Path content binding

- `zlar private-verifier-result verify --evidence-dir` now validates a compact
  evidence-dir content contract for `v3.4.46+` targets. After declared artifact
  hashes are recomputed, the verifier reads `DRY-RUN-MANIFEST.json` and fails
  closed unless
  `release_forward_report_contract.product_proof_path.terminal_chain_boundary`
  and its North Star mirror preserve the exact Product Proof Path terminal-chain
  recognition-refusal group map: 3 groups, 18 case IDs, and preserved=true.
- The private result verification JSON now records
  `evidence_dir_contract_verification`, and release-forward
  `DRY-RUN-RESULT.md` prints that content-binding status for human review.
  North Star readiness carries the sanitized boolean without consuming raw
  private replies, verifier identity, contact channel, or custody directories.
- Boundary: this is private/internal intake and release-forward content-binding
  hardening only. It does not create public external attestation, public
  attribution, public non-operator review, production authority, enterprise
  readiness, current-machine governance, live MCP coverage, live trust-registry
  state, key custody, revocation truth, production downstream recognition,
  sovereign recognition, v3.4.0 readiness, or unrouted-surface coverage.

## 3.4.46 — 2026-06-23 — Product Proof Path exact terminal-chain refusal groups

### Product Proof Path exact terminal-chain refusal groups

- `zlar product-proof-path` now carries exact terminal-chain recognition
  refusal group case IDs through its `terminal_chain_boundary`. The boundary
  records `recognition_refusal_group_count=3`,
  `recognition_refusal_group_case_count=18`, the grouped case-ID map, and
  `recognition_refusal_group_case_ids_preserved=true`.
- North Star readiness and release-forward dry-run reports now fail closed if
  the Product Proof Path terminal-chain boundary compresses that grouped
  refusal map into hash-only evidence or lets the case IDs drift. The
  release-forward requirement starts at `v3.4.46+`; `v3.4.45` remains the
  historical compact-boundary contract.
- Boundary: this does not create new terminal-chain evidence, live governance,
  current-machine governance, production authority, enterprise readiness,
  sovereign recognition, external attestation, key custody, revocation truth,
  live trust-registry truth, all-MCP governance, or unrouted-surface coverage.
  It preserves already-existing fresh local terminal-chain grouped refusal
  evidence inside the Product Proof Path and release-forward verifier surface.

## 3.4.45 — 2026-06-23 — Product Proof Path terminal-chain boundary

### Product Proof Path terminal-chain boundary

- `zlar product-proof-path` now generates a fresh disposable
  installed-runtime-profile terminal chain, verifies its portable artifact, and
  preserves a compact `terminal_chain_boundary` in the Product Proof Path
  report. The boundary includes terminal-chain artifact verification, body
  SHA-256, trusted-issuer registry binding/refusal hashes, exact registry
  refusal case IDs/reasons, before-mutation refusal status, nested artifact
  binding preservation, and false stronger-claim flags.
- North Star readiness now consumes that Product Proof Path terminal-chain
  boundary directly, and release-forward dry-run packets now carry the same
  public-safe boundary inside
  `release_forward_report_contract.product_proof_path`. Both paths fail closed
  if the terminal-chain binding, refusal hash, refusal case IDs/reasons, public
  key omission, receipt-envelope omission, current-machine false boundary, or
  external-attestation false boundary drifts.
- Boundary: this is fresh local Product Proof Path and release-forward contract
  hardening over disposable fixture evidence only. It does not create a
  persistent install, runtime activation, live runtime service, hook/user/machine
  configuration, current-machine governance, live MCP coverage, production
  downstream recognition, production authority, enterprise readiness, sovereign
  recognition, public external attestation, live trust-registry state, live
  issuer status, key custody, revocation truth, or unrouted-surface coverage.

## 3.4.44 — 2026-06-23 — Product Proof Path artifact binding

### Product Proof Path artifact binding

- `zlar product-proof-path` now recomputes local proof-pack artifact
  verification before accepting any supplied artifact/verification pair inside
  the Product Proof Path builder. A stale verification JSON can no longer be
  paired with a mutated proof-pack artifact that carries extra authority-shaped
  fields.
- Added regression coverage that tampers a proof-pack artifact with an
  `external_attestation=true` field and proves the stale verification pair is
  refused before a PASS Product Proof Path report can be built.
- Boundary: this is local Product Proof Path evidence-binding hardening only.
  It does not create a verifier result, public external attestation,
  non-operator review, live registry state, live issuer status, key custody,
  revocation truth, current-machine governance, live MCP coverage, production
  downstream recognition, production authority, enterprise readiness, sovereign
  recognition, or unrouted-surface coverage.

## 3.4.43 — 2026-06-23 — Release-forward contract parser repair

### Release-forward contract parser repair

- `tools/release-forward-verifier-dry-run.sh` fixes the conditional manifest
  spread for the `v3.4.42+` Product Proof Path contract block so Node 22 can
  parse the release-forward dry-run helper consistently in local and GitHub
  Actions environments.
- Boundary: this is an executable-path repair for the released Product Proof
  Path contract binding. It does not change the contract threshold, expand
  governed surfaces, create external attestation, prove current-machine
  governance, prove live MCP coverage, or claim unrouted-surface coverage.

## 3.4.42 — 2026-06-23 — Product Proof Path contract binding

### Product Proof Path contract binding

- `tools/release-forward-verifier-dry-run.sh` now binds
  `ZLAR/zlar-product-proof-path-v1.json` into
  `release_forward_report_contract` for `v3.4.42+` explicit release targets.
  The manifest records the Product Proof Path source path/SHA-256, report type,
  PASS result, fresh-local-fixture proof-pack evidence model, false forbidden
  claims, simulated human authorization behavior, receipt-verifier boundary,
  North Star consumption, and known unrouted-records noncoverage visibility.
- `DRY-RUN-RESULT.md` renders those fields as
  `manifest.release_forward_report_contract.product_proof_path.*` lines from
  the manifest. The manifest remains canonical; Markdown remains presentation.
- Boundary: this is release-forward packet contract hardening over an existing
  local Product Proof Path artifact. It is not a new verifier result, not
  non-operator review, not public external attestation, not live registry
  state, not live issuer status, not key custody, not revocation truth, not
  current-machine governance, not live MCP coverage, not production downstream
  recognition, not production authority, not enterprise readiness, not
  sovereign recognition, and not unrouted-surface coverage.

## 3.4.41 — 2026-06-23 — Release-forward report contract manifest

### Release-forward report contract manifest

- `tools/release-forward-verifier-dry-run.sh` now emits
  `release_forward_report_contract` in `DRY-RUN-MANIFEST.json` for
  `v3.4.41+` explicit release targets. The object is a compact,
  machine-readable summary of the existing release-forward dry-run report
  contract, sourced from preserved local dry-run artifacts and same-manifest
  terminal-chain refusal evidence.
- `DRY-RUN-RESULT.md` now renders that manifest object as
  `manifest.release_forward_report_contract.*` lines for human review. The
  manifest remains canonical; Markdown is presentation, not the source of
  verifier authority.
- Boundary: this is verifier packet contract hardening only. It is not a new
  verifier result, not non-operator review, not public external attestation,
  not live registry state, not live issuer status, not key custody, not
  revocation truth, not current-machine governance, not live MCP coverage, not
  production downstream recognition, not production authority, not enterprise
  readiness, not sovereign recognition, and not unrouted-surface coverage.

## 3.4.40 — 2026-06-23 — Release-forward registry refusal summaries

### Release-forward registry refusal summaries

- `tools/release-forward-verifier-dry-run.sh` now carries the `v3.4.39`
  terminal-chain trusted-issuer registry refusal summary into
  `DRY-RUN-MANIFEST.json` for `v3.4.39+` explicit release targets.
  `terminal_chain_refusal_evidence` records the refusal case count, exact case
  IDs, exact reason codes, `all_refused=true`, matching terminal-chain/artifact
  verification refusal hashes, and
  `all_trusted_issuer_registry_recognition_refusals_preserved=true`.
- `DRY-RUN-RESULT.md` now prints those manifest fields and mirrors the
  proof-smoke / North Star readiness summary fields in `Release-Forward Report
  Contract`, including Enterprise Deployment Profile and Downstream Recognition
  Rule observed-summary preservation.
- Boundary: this is release-forward reporting hardening over already-bounded
  local fixture refusal evidence. It does not prove live trust-registry state,
  live issuer status, key custody, revocation truth, production trust-registry
  state, production downstream recognition, production authority,
  current-machine governance, enterprise readiness, public external
  attestation, real non-operator review, sovereign recognition, or
  unrouted-surface coverage.

## 3.4.39 — 2026-06-23 — Registry refusal summary surfacing

### Registry refusal summary surfacing

- `zlar proof-smoke --json` now mirrors the terminal-chain trusted issuer
  registry refusal object into first-class report counts for both terminal-chain
  evidence and terminal-chain artifact verification: refusal case count, exact
  case IDs, exact reason codes, `all_refused=true`, and canonical refusal
  SHA-256.
- `zlar north-star-readiness` now preserves the same registry-refusal summary
  in top-level counts and in the Enterprise Deployment Profile / Downstream
  Recognition Rule observed summaries. Evaluator tooling no longer has to dig
  through nested terminal-chain artifacts to see the refusal contract.
- Boundary: this surfaces already-bounded local terminal-chain refusal evidence.
  It does not prove live trust-registry state, live issuer status, key custody,
  revocation truth, production trust-registry state, production downstream
  recognition, production authority, current-machine governance, enterprise
  readiness, public external attestation, real non-operator review, sovereign
  recognition, or unrouted-surface coverage.

## 3.4.38 — 2026-06-23 — Terminal-chain registry refusal boundary

### Terminal-chain registry refusal boundary

- `zlar protected-records-installed-runtime-profile-terminal-chain` now embeds
  hash-bound `trusted_issuer_registry_recognition_refusals` inside the
  terminal-chain trusted issuer registry binding. The local fixture proves an
  unrecognized registry scope refuses with `scope_not_found`, and a valid
  signed receipt with a mismatched registry-bound receipt contract refuses with
  `detail_hash_mismatch` while preserving `signature_valid=true` and
  `issuer_status=active`.
- Terminal-chain artifact verification and CLI tests now preserve the refusal
  case count, refusal case IDs/reasons, `all_refused=true`, and a canonical
  `trusted_issuer_registry_recognition_refusals_sha256`. Tampering a refusal
  reason, refusal count, registry/receipt binding flag, or public-safety flag
  fails even when the outer artifact hash is recomputed.
- North Star readiness now evaluates the terminal-chain trusted-registry
  binding against the full false-boundary field contract, including no live
  probing, no embedded raw public-key material, no embedded receipt envelope,
  no artifact-only cryptographic reconstruction, no live registry, no live
  issuer status, no key custody, no revocation truth, no production trust
  registry, no production downstream recognition, no production authority, no
  sovereign recognition, no public external attestation, no real non-operator
  review, and no current-machine governance.
- Boundary: this is local terminal-chain fixture refusal hardening. It does
  not prove live trust-registry state, live issuer status, key custody,
  revocation truth, production trust-registry state, production downstream
  recognition, production authority, current-machine governance, enterprise
  readiness, public external attestation, real non-operator review, sovereign
  recognition, or unrouted-surface coverage.

## 3.4.37 — 2026-06-23 — Terminal-chain registry recognition boundary

### Terminal-chain registry recognition boundary

- `zlar protected-records-installed-runtime-profile-terminal-chain` now
  preserves a first-class `trusted_issuer_registry_recognition_binding` for the
  terminal-chain artifact and verifier. The binding records local
  bundled-registry fixture recognition, stable registry/receipt contract
  hashes, selected-profile/preflight/service-proof/artifact binding,
  malformed-registry fail-closed behavior, and false live, custody, revocation,
  production, current-machine, external-attestation, and sovereign-recognition
  claims.
- `zlar proof-smoke` and `zlar north-star-readiness` now require and preserve
  that terminal-chain registry-recognition binding for `v3.4.37+`, including
  hash equality between terminal-chain evidence and artifact verification and
  observed-summary propagation into Enterprise Deployment Profile / Downstream
  Recognition Rule.
- Boundary: this is public-safe local fixture summary preservation. It does not
  embed raw public-key material or the receipt envelope, does not make the
  artifact sufficient to reproduce cryptographic recognition, and does not
  prove live trust-registry state, live issuer status, key custody, revocation
  truth, production downstream recognition, production authority,
  current-machine governance, enterprise readiness, public external
  attestation, real non-operator review, sovereign recognition, or
  unrouted-surface coverage.

## 3.4.36 — 2026-06-23 — Product proof registry recognition component

### Product proof registry recognition component

- `zlar local-proof-pack` now emits a first-class
  `trusted_issuer_registry_recognition` component. The component validates and
  evaluates a valid bundled `trusted-receipt-issuers-v1` registry fixture
  through the shared downstream recognition rule, then records
  audit-event/detail-hash binding, active fixture issuer status, signature
  validity, and malformed-registry fail-closed behavior before the verifier and
  proof-smoke layers consume it.
- `zlar local-proof-pack verify`, `zlar proof-smoke`, and
  `zlar product-proof-path` now preserve that component as bounded evidence
  instead of reconstructing registry recognition from adjacent receipt-verifier
  or downstream summaries.
- North Star readiness now carries the Product Proof Path registry recognition
  summary with audit/detail binding, component non-claims, and false
  live-registry, live-issuer-status, key-custody, revocation, production,
  public-attestation, real-non-operator-review, sovereign-recognition, and
  current-machine-governance flags.
- Boundary: this is local fixture Product Proof Path hardening. It does not
  prove live trust-registry state, live issuer status, key custody, revocation
  truth, production trust-registry state, production downstream recognition,
  production authority, current-machine governance, public external
  attestation, real non-operator review, or sovereign recognition.

## 3.4.35 — 2026-06-23 — Registry recognition evidence boundary

### Registry recognition evidence boundary

- The release-forward verifier dry run now emits a first-class
  `trusted_issuer_registry_recognition_evidence` manifest object for
  `v3.4.35+` targets. It binds the existing trusted-issuer recognition JSON,
  malformed-registry JSON, and malformed-registry error hashes, and records the
  fixture registry type, `bundled-local-fixture` evidence model,
  `live_probing=false`, sample scope, recognized active issuer verdict,
  signature validity, and fail-closed malformed-registry result.
- `DRY-RUN-RESULT.md` now prints a `Trusted Issuer Registry Recognition
  Evidence` section for `v3.4.35+` targets so a verifier can review the
  registry fixture boundary without reconstructing it from artifact hashes.
- The release-forward helper no longer treats every public `v3.4.31+` target as
  an asset-bearing verifier-kit release. `v3.4.31` remains the known public
  release-asset evidence target; later proof-hardening releases use the bounded
  no-assets public-distribution path unless their release assets are explicitly
  added and the helper allowlist is updated.
- Boundary: this is fixture-evidence presentation and claim-boundary hardening.
  It does not create a live/operator trust registry, prove live issuer status,
  prove key custody, prove revocation truth, prove production trust-registry
  state, prove production downstream recognition, prove production authority,
  prove sovereign recognition, or create public external attestation.

## 3.4.34 — 2026-06-23 — Private result verification evidence

### Private result verification evidence

- The release-forward verifier dry run now prints a `Private Result
  Verification Evidence` section for `v3.4.34+` targets. It shows the generated
  private-result verification verdict, recomputed evidence-dir hash status,
  artifact count, sample/non-operator boundary, and false public-attestation,
  public-attribution, and public-non-operator-review flags without adding the
  late generated files to the core artifact hash cycle.
- Boundary: this is private-intake reviewability hardening for generated sample
  evidence. It does not create public external attestation, prove real
  non-operator review, publish verifier identity, prove production authority,
  prove enterprise readiness, or change live issuer, custody, revocation, or
  downstream-recognition claims.

## 3.4.33 — 2026-06-23 — Issuer-status evidence reviewability

### Issuer-status evidence reviewability

- The release-forward verifier dry run now emits a first-class
  `issuer_status_evidence` manifest object for `v3.4.33+` targets. It preserves
  the existing local hermetic issuer-status proof, verifier-kit issuer fixture,
  external-runner diagnostics hashes, active-issuer boarding, inactive/unknown/
  key-missing refusal booleans, and verifier-kit fixture verdict in one
  reviewable place.
- `DRY-RUN-RESULT.md` now prints an `Issuer Status Evidence` section for
  `v3.4.33+` targets so a human verifier can see the fixture verdict, no-live
  boundary, and false stronger-claim flags without reverse-engineering them
  from artifact hashes.
- Boundary: this is release-forward fixture-evidence presentation hardening. It
  does not create public external attestation, prove non-operator review, prove
  live issuer status, prove key custody, prove revocation truth, prove a
  production trust registry, prove production downstream recognition, prove
  enterprise readiness, or define the future live/operator-bound issuer-registry
  authority model.

## 3.4.32 — 2026-06-23 — Release-asset readiness handoff

### Release-asset readiness handoff

- The release-forward verifier dry run now uses live explicit-tag GitHub
  release-asset reads plus `--require-public` public-distribution validation
  for `v3.4.31+` public `ZLAR-AI/ZLAR` targets instead of the local no-assets
  fixture path.
- `zlar north-star-readiness --evidence-dir` now consumes
  `zlar-verifier-kit-release-assets-v1.json` when supplied, reports a
  verifier-kit release-asset live-read summary, and rebuilds the
  public-distribution posture from raw release-asset, reproducibility, and local
  dist-file evidence before accepting a public-distribution ready claim.
- Public-ready release-asset evidence must now bind to repository
  `ZLAR-AI/ZLAR`; the release URL and required asset download URLs must name
  that same repository and target tag.
- Local no-assets fixture evidence remains accepted as bounded `NOT_READY`
  evidence. Incomplete live release-asset evidence also remains bounded
  `NOT_READY` evidence unless it is used to make a public-ready claim.
- Boundary: this is evidence handoff hardening only. It does not mutate GitHub
  releases, upload assets, read private keys, prove production publisher key
  custody, create external attestation, prove non-operator review, prove live
  issuer status, prove enterprise readiness, or close unrouted records paths.

## 3.4.31 — 2026-06-23 — Verifier-kit release asset live read

### Verifier-kit release asset live read

- Added `zlar verifier-kit-release-assets-live-read`, a read-only explicit-tag
  helper that reads a public GitHub release, downloads release assets, records
  downloaded SHA-256 values, and emits
  `zlar-verifier-kit-release-assets-live-v1` for the existing public
  distribution validator.
- The public-distribution path can now consume the helper output directly, so a
  release can prove public verifier-kit asset byte binding without hand-shaped
  release JSON or a moving `--latest` target.
- Private verifier intake now requires the already-generated issuer-status
  proof and verifier-kit issuer-status fixture artifact hashes, so those files
  are required evidence rather than generic optional packet contents.
- Boundary: this is public release-asset evidence plumbing and private-intake
  schema hardening. It does not upload assets by itself, mutate releases, read
  private keys, prove production publisher key custody, create external
  attestation, prove non-operator review, prove enterprise readiness, recognize
  sovereign authority, prove live MCP coverage, or close unrouted records paths.

## 3.4.30 — 2026-06-23 — Verifier-owned nested binding summary

### Verifier-owned nested binding summary

- Terminal-chain artifact verification now emits a first-class
  `nested_artifact_binding` summary with nested generated preflight/service-proof
  artifact types, body hashes, verified flags, hash-binding booleans, and false
  stronger-claim flags.
- Proof-smoke and North Star readiness now require and preserve that verifier
  summary for `v3.4.30+` targets, including the Enterprise Deployment Profile
  and Downstream Recognition Rule observed summaries.
- The release-forward verifier dry run now separates `v3.4.28+` forged nested
  artifact tamper refusals from the `v3.4.30+` verifier-owned
  `nested_artifact_binding` manifest field, so the packet does not reconstruct
  binding authority from raw embedded artifacts.
- Boundary: this is local disposable terminal-chain proof-path hardening. It
  does not persistently install or activate a runtime profile, write
  hook/user/machine configuration, use Telegram, inspect a live records system,
  prove current-machine governance, prove production downstream recognition,
  create external attestation, prove enterprise readiness, recognize sovereign
  authority, prove live MCP coverage, or close unrouted records paths.

## 3.4.29 — 2026-06-23 — Terminal-chain nested preflight refusal export

### Terminal-chain nested preflight refusal export

- The terminal-chain unit and CLI tests now prove the symmetric forged inner
  preflight hash refusal after recomputing outer terminal-chain artifact
  integrity, matching the existing service-proof negative case.
- The release-forward verifier dry run now fabricates and refuses both forged
  inner preflight and forged inner service-proof summary hashes for
  `v3.4.28+` targets.
- `DRY-RUN-MANIFEST.json` now records
  `terminal_chain_refusal_evidence.nested_artifact_binding` with nested
  artifact types, artifact-embedded nested types, forged preflight/service
  refusal booleans, checksum coverage for the diagnostic tamper files, and
  false stronger-claim flags.
- Boundary: this is release-forward evidence export hardening over local
  disposable terminal-chain artifacts. It does not persistently install or
  activate a runtime profile, write hook/user/machine configuration, use
  Telegram, inspect a live records system, prove current-machine governance,
  prove production downstream recognition, create external attestation, prove
  enterprise readiness, recognize sovereign authority, prove live MCP coverage,
  or close unrouted records paths.

## 3.4.28 — 2026-06-23 — Terminal-chain nested artifact binding

### Terminal-chain nested artifact binding

- Terminal-chain reports and portable artifacts now carry the generated
  installed-runtime-profile preflight artifact and generated service-proof
  artifact in `nested_artifacts`.
- Terminal-chain verification now recomputes those nested artifact verifications
  and refuses summary-only forged inner service-proof hashes even when the outer
  terminal-chain artifact integrity is recomputed.
- The release-forward verifier dry run now fabricates that forged-inner-hash
  artifact for `v3.4.28+` targets and requires verifier refusal before recording
  the dry run as passing.
- Boundary: this is local disposable terminal-chain proof hardening. It does
  not persistently install or activate a runtime profile, write hook/user/machine
  configuration, use Telegram, inspect a live records system, prove
  current-machine governance, prove production downstream recognition, create
  external attestation, prove enterprise readiness, recognize sovereign
  authority, prove live MCP coverage, or close unrouted records paths.

## 3.4.27 — 2026-06-23 — Deterministic crypto tamper test

### Deterministic crypto tamper test

- `tests/test-crypto.sh` now creates its tampered Ed25519 signature by
  shortening the signature by one byte instead of overwriting a fixed byte with
  `0x00`.
- This removes a rare CI flake where the overwritten byte was already zero,
  leaving the signature unchanged and making the negative verification case
  nondeterministic.
- Boundary: this is test-harness stabilization for the existing crypto
  abstraction check. It does not change signing, verification, release
  evidence, runtime behavior, production authority, current-machine
  governance, external attestation, enterprise readiness, sovereign authority,
  live MCP coverage, or unrouted-surface coverage.

## 3.4.26 — 2026-06-23 — Readiness observed case-ID summaries

### Readiness observed case-ID summaries

- `north-star-readiness` now mirrors the existing terminal-chain
  recognition-refusal group case-ID contract into the Enterprise Deployment
  Profile and Downstream Recognition Rule observed summaries.
- The readiness validator now fails closed if those verifier-facing puzzle
  pieces omit, reorder, or miscount the exact grouped case IDs while top-level
  counts still claim preservation.
- The release-forward verifier dry-run now asserts the `v3.4.26+`
  observed-summary contract and records the preserved puzzle-piece counts in
  `DRY-RUN-RESULT.md`.
- Boundary: this mirrors the already-proven `v3.4.25` report contract into
  human-facing readiness summaries. It does not add a new evidence class,
  persistently install or activate a runtime profile, write hook/user/machine
  configuration, use Telegram, inspect a live records system, prove
  current-machine governance, prove production downstream recognition, create
  external attestation, prove enterprise readiness, recognize sovereign
  authority, or close unrouted records paths.

## 3.4.25 — 2026-06-22 — Readiness recognition case-ID contract

### Readiness recognition case-ID contract

- `proof-smoke` and `proof-smoke verify` now preserve exact terminal-chain
  recognition-refusal group case IDs in report counts for both the terminal
  chain and terminal-chain artifact verification. The preserved contract is
  three groups, six cases per group, and eighteen exact case IDs.
- `north-star-readiness` now requires and preserves those exact grouped case
  IDs for `v3.4.25+` release-forward targets, so readiness cannot pass on
  hash-only recognition-refusal group preservation.
- The release-forward verifier dry-run now asserts the `v3.4.25+`
  proof-smoke/readiness report contract and records the preserved counts, exact
  grouped case IDs, and false stronger-claim flags in `DRY-RUN-RESULT.md`.
- Boundary: this is local fixture and release-forward report-contract
  hardening over existing terminal-chain evidence. It does not persistently
  install or activate a runtime profile, write hook/user/machine configuration,
  use Telegram, inspect a live records system, prove current-machine
  governance, prove production downstream recognition, create external
  attestation, prove enterprise readiness, recognize sovereign authority, or
  close unrouted records paths.

## 3.4.24 — 2026-06-22 — Release-forward recognition case IDs

### Release-forward recognition case IDs

- The release-forward verifier dry-run manifest now records exact
  `recognition_refusal_group_case_ids` for the three terminal-chain
  recognition-refusal groups and sets
  `recognition_refusal_group_case_ids_required=true` for `v3.4.24+` targets.
- The manifest self-check now fails closed for `v3.4.24+` targets if any group
  case-id list is missing, incomplete, reordered, or not aligned with the
  stable terminal-chain group contract.
- `DRY-RUN-RESULT.md` now prints the exact case-id lists for no usable
  recognized receipt authority, recognized receipt scope mismatch, and
  route/request authority material refusal groups so a verifier can inspect the
  grouped evidence without reverse-engineering the full terminal-chain JSON.
- Boundary: this is release-forward verifier-packet hardening over existing
  local terminal-chain fixture evidence. It does not persistently install or
  activate a runtime profile, write hook/user/machine configuration, use
  Telegram, inspect a live records system, prove current-machine governance,
  prove production downstream recognition, create external attestation, prove
  enterprise readiness, recognize sovereign authority, or close unrouted
  records paths.

## 3.4.23 — 2026-06-22 — Terminal-chain recognition refusal groups

### Terminal-chain recognition refusal groups

- The installed-runtime-profile terminal-chain report now carries canonical
  `recognition_refusal_groups` that separate no usable recognized receipt
  authority, recognized receipt scope mismatch, and route/request authority
  material refusal cases.
- Terminal-chain artifacts, artifact verification, `proof-smoke`, and
  `north-star-readiness` now preserve
  `recognition_refusal_groups_sha256` alongside the existing refusal taxonomy
  and named receipt-refusal digest. North Star readiness requires this group
  digest for current sample evidence and `v3.4.23+` release-forward targets.
- The release-forward verifier dry-run manifest and result now include
  grouped terminal-chain recognition refusal evidence for `v3.4.23+` targets,
  while preserving `v3.4.22+` named receipt-refusal evidence.
- Boundary: this is local fixture proof-path and release-forward evidence
  hardening. It does not persistently install or activate a runtime profile,
  write hook/user/machine configuration, use Telegram, inspect a live records
  system, prove current-machine governance, prove production downstream
  recognition, create external attestation, prove enterprise readiness,
  recognize sovereign authority, or close unrouted records paths.

## 3.4.22 — 2026-06-22 — Terminal-chain named refusal evidence

### Terminal-chain named refusal evidence

- The installed-runtime-profile terminal-chain report now carries first-class
  named receipt-refusal evidence for missing, invalid, stale, unknown-issuer,
  wrong-policy, wrong-domain, and wrong-tool receipt cases, each bound to the
  observed case id, reason code, and before-mutation refusal result.
- Terminal-chain artifacts, artifact verification, `proof-smoke`, and
  `north-star-readiness` now preserve a canonical
  `named_receipt_refusals_sha256` alongside the existing full refusal taxonomy
  hash. North Star readiness requires this named-refusal digest for current
  sample evidence and `v3.4.22+` release-forward targets while remaining
  compatible with older terminal-chain packets.
- The release-forward verifier dry-run manifest and result now include a
  `terminal_chain_refusal_evidence` section for `v3.4.22+` targets so a
  verifier can inspect named terminal-chain refusal preservation without
  reverse-engineering the full taxonomy body.
- Boundary: this is local fixture proof-path and release-forward evidence
  hardening. It does not persistently install or activate a runtime profile,
  write hook/user/machine configuration, use Telegram, inspect a live records
  system, prove current-machine governance, prove production downstream
  recognition, create external attestation, prove enterprise readiness,
  recognize sovereign authority, or close unrouted records paths.

## 3.4.21 — 2026-06-22 — Release-forward verifier diagnostics preservation

### Release-forward verifier diagnostics preservation

- Added `tools/verifier-kit-external-runner-diagnostics.mjs`, a bounded
  machine-readable report for `v3.4.21+` release-forward dry runs. It preserves
  evidence that the `v3.4.20` verifier-kit external-runner diagnostic hardening
  is present in the source-built verifier packet.
- The release-forward helper now runs and preserves
  `zlar-verifier-kit-external-runner-diagnostics-v1.json`, binds it into
  `SHA256SUMS`, `DRY-RUN-MANIFEST.json`, and the private verifier-result sample
  hash set, and fails closed if the built helper hash, manifest entry, source
  helper, issuer-status artifact, or diagnostic contract drifts.
- The release-forward command plan now expands the target tag and expected
  commit SHA for the diagnostics command instead of printing shell placeholders,
  and root-level generated verifier packet artifacts are ignored so scratch
  evidence cannot become source truth in synthetic current-worktree tests.
- README, the external verifier packet, and their guard tests now document that
  `external-runner` means the bundled verifier-kit helper file, not a human
  external verifier.
- Boundary: this is release-forward proof-packet preservation and verifier-kit
  diagnostic evidence. It does not perform live probing, send a verifier
  request, create external attestation, prove non-operator review, prove
  production authority, prove enterprise readiness, prove current-machine
  governance, or prove that repo-side regression tests are inside the built
  verifier kit.

## 3.4.20 — 2026-06-22 — Verifier-kit dry-run diagnostics hardening

### Verifier-kit dry-run diagnostics hardening

- The verifier-kit external-runner dry run now avoids `grep -q` under
  `pipefail` when checking captured command output, removing a shell shape that
  could falsely fail on SIGPIPE after an early match.
- T-KIT-23 now proves its synthetic engagement receipt, public key, and chain
  fixtures were copied before invoking the external-runner dry run.
- Verifier-kit assertion failures now preserve first-line and tail context, and
  T-KIT-23 prints the dry-run failure tail when the helper exits nonzero, so CI
  evidence identifies the actual verifier failure instead of only the banner.
- Boundary: this is verifier-kit reliability and diagnostic hardening over the
  existing public fixture/external-runner proof path. It does not add new
  governed surfaces, use Telegram, inspect live operator state, create external
  attestation, prove production downstream recognition, prove enterprise
  readiness, or change the `v3.4.19` recognition-contract digest claim.

## 3.4.19 — 2026-06-22 — Recognition-contract digest binding

### Recognition-contract digest binding

- Installed-runtime-profile preflight verification now emits a canonical
  `recognition_contract_sha256` for the preserved recognition contract.
- The installed-runtime-profile service proof, selected-profile summary,
  service config provenance, service-proof artifact verification,
  terminal-chain report, and terminal-chain artifact verification now carry
  that same digest so downstream proof layers bind the exact recognition
  contract, not only the selected profile and refusal counts.
- `zlar proof-smoke`, `zlar north-star-readiness`, and the release-forward
  verifier dry-run path now preserve that digest and fail closed when it is
  missing or drifts across the proof chain. North Star readiness requires the
  digest for current sample evidence and `v3.4.19+` release-forward targets.
- Boundary: this is proof/receipt hardening over existing local disposable
  child-service, launcher-owned terminal-chain, and release-forward evidence.
  It does not persistently install or activate a runtime profile, write
  hook/user/machine configuration, use Telegram, inspect a live records system,
  prove current-machine governance, prove production downstream recognition,
  create external attestation, prove enterprise readiness, recognize sovereign
  authority, or close unrouted records paths.

## 3.4.18 — 2026-06-22 — Service-proof artifact refusal taxonomy binding

### Service-proof artifact refusal taxonomy binding

- The installed-runtime-profile service-proof artifact verifier now preserves
  the exact selected-profile refusal taxonomy: required refusal case ids,
  observed case ids, observed reason codes, before-mutation booleans, and a
  canonical `refusal_taxonomy_sha256`.
- `zlar proof-smoke`, `zlar north-star-readiness`, and the release-forward
  verifier dry-run path now carry that service-proof artifact-verification
  taxonomy hash and fail closed if it drifts from the verifier output.
- North Star readiness now records service-proof artifact-verification refusal
  taxonomy requirement/preservation fields and requires them for current sample
  evidence and `v3.4.18+` release-forward targets.
- The private verifier-result contract now requires the modern release-forward
  artifact set through product-proof, installed service-proof, service-proof
  artifacts, terminal-chain artifacts, and terminal-chain artifact verification
  for current `v3.4.x` targets.
- Boundary: this is proof/receipt hardening over existing local disposable
  child-service and release-forward evidence. It does not persistently install
  or activate a runtime profile, write hook/user/machine configuration, use
  Telegram, inspect a live records system, prove current-machine governance,
  prove production downstream recognition, create external attestation, prove
  enterprise readiness, recognize sovereign authority, or close unrouted
  records paths.

## 3.4.17 — 2026-06-22 — Terminal-chain refusal taxonomy binding

### Terminal-chain refusal taxonomy binding

- The installed-runtime-profile terminal chain now preserves the exact
  selected-profile refusal taxonomy in the generated service-proof summary:
  required refusal case ids, observed case ids, observed reason codes,
  before-mutation booleans, and a canonical `refusal_taxonomy_sha256`.
- The portable terminal-chain artifact verification and `proof-smoke` counts
  now carry that taxonomy hash, and release-forward dry-run checks prove it
  remains bound from chain report to artifact verifier to smoke summary.
- Added fail-closed regressions proving taxonomy drift is rejected even when
  refusal counts remain unchanged, and readiness still rejects terminal-chain
  artifact-verification hash drift.
- Boundary: this is proof/receipt hardening over the existing launcher-owned
  disposable terminal-chain evidence path. It does not persistently install or
  activate a runtime profile, write hook/user/machine configuration, use
  Telegram, inspect a live records system, prove current-machine governance,
  prove production downstream recognition, create external attestation, prove
  enterprise readiness, recognize sovereign authority, or close unrouted
  records paths.

## 3.4.16 — 2026-06-22 — Terminal-chain fail-closed test hardening

### Terminal-chain fail-closed test hardening

- Added a direct CLI regression proving
  `zlar protected-records-installed-runtime-profile-terminal-chain --plan ... --profile ...`
  fails closed when the explicit installation plan's runtime-profile SHA does
  not match the supplied runtime profile. The failure emits no report body and
  keeps local path/private data out of stderr.
- Added a North Star readiness regression proving `v3.4.15+`
  release-forward evidence fails closed when the terminal-chain JSON exists
  but `zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`
  is missing.
- Boundary: this is test hardening over the existing launcher-owned disposable
  terminal-chain evidence path. It does not persistently install or activate a
  runtime profile, write hook/user/machine configuration, use Telegram, inspect
  a live records system, prove current-machine governance, prove production
  downstream recognition, create external attestation, prove enterprise
  readiness, recognize sovereign authority, or close unrouted records paths.

## 3.4.15 — 2026-06-22 — Installed runtime-profile terminal chain

### Installed runtime-profile terminal chain

- Added `zlar protected-records-installed-runtime-profile-terminal-chain`, a
  fresh local proof path that creates a launcher-owned disposable installed
  runtime-profile root from an explicit plan and profile, preflights that
  generated root by explicit profile id and SHA, runs the selected-profile
  service proof from the generated preflight artifact, verifies the generated
  service-proof artifact, and emits a portable terminal-chain artifact.
- Integrated the terminal chain into `zlar proof-smoke`,
  `zlar north-star-readiness`, release-forward verifier dry-runs, CLI docs,
  README, the external verifier packet, and the governed-surface coverage map.
  For `v3.4.15+` release-forward evidence, the packet preserves
  `zlar-installed-runtime-profile-terminal-chain-v1.json`,
  `zlar-installed-runtime-profile-terminal-chain-artifact-v1.json`, and
  `zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`.
  North Star readiness consumes and requires the terminal-chain JSON plus the
  terminal-chain artifact-verification JSON.
- Boundary: this is launcher-owned disposable installed-runtime-profile chain
  evidence only. It does not persistently install or activate a runtime
  profile, write hook/user/machine configuration, use Telegram, inspect a live
  records system, prove current-machine governance, prove production downstream
  recognition, create external attestation, prove enterprise readiness,
  recognize sovereign authority, or close unrouted records paths.

## 3.4.14 — 2026-06-22 — Service-proof artifact verification readiness binding

### Service-proof artifact verification readiness binding

- `zlar proof-smoke` now runs and records
  `zlar protected-records-installed-runtime-profile-service-proof verify --sample --json`
  as its own committed-fixture step. The `zlar-proof-smoke-v1` report now
  preserves the installed runtime-profile service-proof artifact verification
  result, payload type, artifact body SHA-256, replay refusal, consumed-store
  case count, store-and-anchor rollback case count, before-mutation refusal
  result, current-machine false flag, and production-downstream false flag.
- `zlar north-star-readiness` now consumes the same service-proof artifact
  verification in sample and release-forward evidence-dir modes, reports
  `installed_runtime_profile_service_artifact_verification_required=true` for
  sample/current `v3.4.14+` targets, reports
  `installed_runtime_profile_service_artifact_verification_preserved=true`
  only when the verifier hash is bound to the supplied service proof, and
  requires `zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`
  for `v3.4.14+` release-forward targets.
- Boundary: this binds an already-produced verifier artifact into summary
  gates. It does not install or activate a runtime profile, write hook/user/
  machine configuration, inspect a live records system, prove current-machine
  governance, prove production downstream recognition, create external
  attestation, or close unrouted records paths.

## 3.4.13 — 2026-06-22 — Installed runtime-profile witness rollback proof

### Installed runtime-profile witness rollback proof

- Extended `zlar protected-records-installed-runtime-profile-service-proof` with
  a launcher-owned local proof witness for the consumed-receipt store. The
  disposable child-service proof now records that replay is refused before
  mutation when the consumed store and local anchor roll back together while
  the witness remains ahead, and that configured witness deletion refuses
  before mutation after store and anchor state exists.
- The service-proof artifact verifier, `zlar proof-smoke`,
  `zlar north-star-readiness`, and release-forward verifier dry-run now preserve
  the witness provenance, consumed-store witness-deletion refusal,
  store-and-anchor rollback case count, before-mutation refusal result, and
  zero-marker-delta evidence.
- Boundary: this closes only the bounded local proof case where the witness is
  not rolled back. It does not prove production-grade durable storage,
  tamper resistance, exactly-once effects, multi-host coordination, current
  machine governance, production downstream recognition, or rollback detection
  if the consumed store, local anchor, and local witness move together.

## 3.4.12 — 2026-06-22 — Installed runtime-profile service continuity proof

### Installed runtime-profile service continuity proof

- Extended `zlar protected-records-installed-runtime-profile-service-proof` so
  the local disposable installed-profile child-service proof now also proves
  same-process receipt replay refusal, replay refusal after child-service
  restart, invalid/duplicate/locked consumed-store refusal, invalid
  local-anchor refusal, and valid consumed-store rollback/deletion/replacement
  refusal before mutation.
- The proof report, portable artifact verifier, `zlar proof-smoke`, and
  `zlar north-star-readiness` now preserve the launcher-owned config
  provenance, replay refusal counts, consumed-store/local-anchor integrity
  refusal counts, and the explicit boundary that joint consumed-store plus
  local-anchor rollback detection remains false.
- Boundary: this is still local disposable installed-profile child-service
  evidence only. It does not install or activate a runtime profile, write
  persistent runtime config, write hook/user/machine configuration, start a
  live runtime service, inspect a live records system, prove current-machine
  governance, prove production downstream recognition, prove enterprise
  readiness, create external attestation, or close unrouted records paths.

## 3.4.11 — 2026-06-22 — Installed runtime-profile service proof

### Installed runtime-profile service proof

- Added `zlar protected-records-installed-runtime-profile-service-proof`, a
  local disposable child-service proof that consumes a verified
  installed-runtime-profile preflight artifact, preserves the selected profile
  recognition contract, starts a local JSONL runtime-service child process, and
  proves one matching `records.write` boards while all 18 selected-profile
  refusal cases refuse before service-state mutation.
- Integrated the service proof into `zlar proof-smoke`,
  `zlar north-star-readiness`, release-forward verifier dry-runs, CLI docs,
  README, the external verifier packet, and the governed-surface coverage map.
  The readiness report now preserves this local child-service proof and moves
  the Enterprise Deployment Profile piece to
  `local_disposable_profile_refusal_proven` without opening the v3.4 gate.
- Boundary: this is local disposable installed-profile child-service evidence
  only. It does not install or activate a runtime profile, write persistent
  runtime config, write hook/user/machine configuration, start a live runtime
  service, inspect a live records system, prove current-machine governance,
  prove production downstream recognition, create external attestation, prove
  enterprise readiness, or cover unrouted records paths.

## 3.4.10 — 2026-06-22 — Product proof path readiness intake

### North Star readiness

- Updated `zlar north-star-readiness` so the Product Proof Path puzzle piece
  consumes and validates `zlar-product-proof-path-v1` directly. `--sample`
  now runs `zlar product-proof-path --json`, and `--evidence-dir` consumes
  `zlar-product-proof-path-v1.json` when present in release-forward evidence.
- The readiness report now records `product_proof_path_verified=true` only
  when the supplied Product Proof Path report is `PASS`, all acceptance gates
  are true, all forbidden-claim flags are false, the proof-pack artifact is
  verified, live probing is false, and private operator state is not required.
- Boundary: this strengthens Product Proof Path intake only. It does not prove
  live approval, real human approval, current-machine governance, production
  downstream recognition, production authority, enterprise readiness,
  external attestation, sovereign recognition, all-MCP governance, or coverage
  of unrouted surfaces.

## 3.4.9 — 2026-06-22 — Product proof path

### Product proof path

- Added `zlar product-proof-path`, a fresh local evaluator-facing report that
  generates and verifies a local proof-pack artifact, then exposes one bounded
  Product Proof Path acceptance gate: allowed `records.write`, refused
  unrecognized/missing paths, simulated-human authorization, receipt verifier
  `VALID` / `UNKNOWN-SIGNER` / `INVALID` distinction, visible non-coverage,
  and false stronger-claim flags.
- Boundary: this is local fixture product-proof evidence only. It does not
  inspect live hooks, use Telegram, prove real human approval, install or
  activate persistent runtime profiles, write hook/user/machine configuration,
  prove current-machine governance, prove production downstream recognition,
  create external attestation, prove enterprise readiness, or prove sovereign
  recognition, all-MCP governance, or coverage of unrouted surfaces.
- Extended the release-forward verifier dry-run helper and external verifier
  packet so `v3.4.9+` targets preserve, assert, hash, and list
  `zlar-product-proof-path-v1.json` without creating live approval,
  production, external-attestation, all-MCP, or unrouted-surface claims.

## 3.4.8 — 2026-06-22 — Recognition proof artifact verification

### Installed runtime-profile recognition proof artifact

- Added a portable checksummed artifact wrapper for
  `zlar protected-records-installed-runtime-profile-recognition-proof`.
  `--artifact <file|->` emits
  `zlar-protected-records-installed-runtime-profile-recognition-proof-artifact-v1`,
  and `verify --input <file|->` / `verify --sample` check artifact integrity
  and embedded proof boundaries without rerunning the proof.
- Extended the release-forward verifier dry-run path so `v3.4.8+` targets
  preserve `zlar-installed-runtime-profile-recognition-proof-artifact-v1.json`
  and
  `zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json`.
- Boundary: this is artifact checkability for local hermetic
  selected-profile recognition proof only. It does not install or activate a
  runtime profile, start a live runtime service, inspect a live records system,
  prove current-machine governance, prove production downstream recognition,
  create external attestation, prove enterprise readiness, or prove sovereign
  recognition.

## 3.4.7 — 2026-06-22 — Installed runtime-profile recognition proof

### Installed runtime-profile recognition proof

- Added `zlar protected-records-installed-runtime-profile-recognition-proof`,
  a local hermetic proof that consumes a verified installed-runtime-profile
  preflight artifact, preserves the selected profile recognition contract, and
  proves one matching `records.write` receipt boards while all 18 required
  selected-profile refusal cases refuse before fake effect.
- Integrated the new proof into `zlar proof-smoke`,
  `zlar north-star-readiness`, the release-forward verifier dry-run helper, the
  external verifier packet, and the committed proof-smoke fixture so
  `v3.4.7+` verifier runs can preserve
  `zlar-installed-runtime-profile-recognition-proof-v1.json`.
- Boundary: this is local hermetic selected-profile recognition evidence only.
  It does not install or activate a runtime profile, write
  runtime/hook/user/machine configuration, start a live runtime service, inspect
  a live records system, prove current-machine governance, prove production
  downstream recognition, prove production authority, create external
  attestation, or cover unrouted surfaces.

## 3.4.6 — 2026-06-22 — Installed runtime-profile recognition contract

### Installed runtime-profile recognition contract

- Hardened `zlar protected-records-installed-runtime-profile-preflight` so the
  read-only installed-profile preflight preserves the selected profile
  recognition contract: launcher-owned recognition boundary,
  mutation-authoritative route, refusal of request-stream authority material,
  refusal of agent-supplied recognition rules, and the required refusal-case
  taxonomy.
- Hardened `zlar proof-smoke`, `zlar north-star-readiness`, and the
  release-forward verifier dry-run assertions so aggregate reports cannot treat
  a weakened installed-runtime-profile recognition taxonomy as preserved.
- Updated the external verifier packet and CLI docs so `v3.4.6+` verifier runs
  preserve `installed_runtime_profile_preflight_recognition_contract_preserved=true`
  without widening the claim into downstream refusal or production recognition.
- Boundary: this is read-only installed-profile recognition-contract evidence
  only. It does not install or activate a runtime profile, write
  runtime/hook/user/machine configuration, start a runtime service, run a
  downstream refusal proof, prove production downstream recognition, prove
  current-machine governance, prove production authority, prove enterprise
  readiness, create external attestation, or cover unrouted surfaces.

## 3.4.5 — 2026-06-22 — Installed runtime-profile selector preflight

### Installed runtime-profile selector preflight

- Added `zlar protected-records-installed-runtime-profile-preflight`, a
  read-only preflight for an explicit installed runtime-profile root that
  validates active-profile selection by profile id and SHA, refuses latest or
  default current-machine selection, checks installed profile contract
  integrity, and emits a portable verification artifact without installing or
  activating anything.
- Integrated the committed installed-runtime-profile preflight sample
  verification into `zlar proof-smoke`, `zlar north-star-readiness`, the
  release-forward verifier dry-run helper, and the external verifier packet so
  `v3.4.5+` verifier runs preserve the selector-integrity evidence.
- Boundary: this is read-only selector-integrity and artifact-verification
  evidence only. It does not install or activate a runtime profile, write
  runtime/hook/user/machine configuration, start a runtime service, run a
  downstream refusal proof, prove current-machine governance, prove production
  authority, prove enterprise readiness, create external attestation, or cover
  unrouted surfaces.

## 3.4.4 — 2026-06-22 — Proof authorization boundary hardening

### Proof-boundary hardening

- Exposed the embedded simulated-human authorization proof from
  `zlar local-proof-pack verify` as a machine-readable summary, including the
  simulated fixture channel, authorized boarding outcome, false live-probing
  flag, and explicit no-live-approval-channel claim boundary.
- Hardened `zlar proof-smoke` and proof-smoke report verification so the
  committed smoke report must carry and count that simulated-human authorization
  summary without converting it into a live approval-channel or real human
  approval claim.
- Hardened `zlar north-star-readiness` so supplied verifier-kit public
  distribution evidence is source-validated by the verifier-kit public
  distribution validator and tag-bound to `--release-tag` before readiness
  consumes it.
- Boundary: this is local fixture evidence and readiness validation hardening
  only. It does not use Telegram, prove live approval-channel health, prove real
  human approval, prove production authority, enterprise readiness, sovereign
  recognition, external attestation, current-machine governance, live MCP
  coverage, or coverage of unrouted surfaces.

## 3.4.3 — 2026-06-22 — Private verifier readiness intake

### Private verifier intake hardening

- Hardened `zlar private-verifier-result verify` so private verifier envelopes
  must use approved pseudonymous labels, approved relationship boundaries, and
  approved result-summary prose instead of free text that can overclaim or
  expose identity.
- Required `v3.3.109+` private verifier envelopes to preserve the verifier-kit
  release-assets and public-distribution posture artifacts before validation
  can pass.
- Added `zlar north-star-readiness --private-verifier-result-verification` so
  readiness can consume sanitized private-result verification JSON and record
  `private_non_operator_pass_validated=true` without ingesting a raw private
  reply or widening public attestation, public attribution, production
  authority, or enterprise readiness claims.
- Boundary: this is private-intake and readiness-bridge hardening only. It
  does not create public external attestation, prove public non-operator review,
  permit public attribution, prove production authority, enterprise readiness,
  sovereign recognition, current-machine governance, live MCP coverage, key
  custody, revocation truth, production downstream recognition, all-MCP
  governance, or coverage of unrouted surfaces.

### External verifier handoff

- Prepared the current byte-bound public-distribution verifier target as
  `v3.4.2` at commit
  `a101282cf901c8c124b0a4761359395baad3f829`, so a later authorized
  non-operator verifier reviews the release that actually carries the
  release-asset byte-binding hardening.
- Updated the verifier packet examples for the non-sending dry run and live
  release-asset audit to use the pinned `v3.4.2` target.
- Boundary: this prepares a current verifier handoff only. It does not send a
  verifier request, create public external attestation, prove non-operator
  review, prove production authority, enterprise readiness, sovereign
  recognition, live trust-registry truth, revocation truth, production
  downstream recognition, all-MCP governance, or coverage of unrouted surfaces.

## 3.4.2 — 2026-06-21 — Verifier-kit public asset byte binding

### Verifier-kit public asset byte binding

- Hardened `zlar verifier-kit-public-distribution --require-public` so a live
  public-distribution claim requires explicit non-draft GitHub release evidence,
  uploaded required assets with positive sizes, and SHA-256 byte binding between
  public release assets and the reproducibility evidence.
- Updated the external verifier packet so the live release-asset path preserves
  GitHub asset digests or downloaded SHA-256s, downloads the public assets,
  extracts the verifier kit, and verifies local downloaded bytes against the
  release reproducibility report.
- Wired the byte-binding check into North Star readiness so
  `READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION` cannot be reached from a
  ready-shaped public-distribution report that lacks public release-asset hash
  binding.
- Boundary: this is public-distribution evidence hardening only. It does not
  contact a verifier, create public external attestation, prove non-operator
  review, prove production publisher key custody, prove production signing
  identity, prove production authority, enterprise readiness, sovereign
  recognition, live trust-registry truth, revocation truth, production
  downstream recognition, all-MCP governance, or coverage of unrouted surfaces.

## 3.4.1 — 2026-06-21 — Prepared v3.4 verifier target

### External verifier target preparation

- Prepared a pinned `v3.4.0` release-forward verifier target in the external
  verifier packet, with exact commit
  `e38f7f58406a2d55c1e6afa1fe64dd08d8fb9244`.
- Added verifier-facing instructions for exporting live GitHub release-asset
  JSON and running `zlar verifier-kit-public-distribution --require-public`
  against the public `v3.4.0` verifier-kit release assets.
- Boundary: this prepares an exact review target and public-distribution check
  path only. It does not send a verifier request, create public external
  attestation, prove non-operator review, prove production authority, prove
  enterprise readiness, prove sovereign recognition, or extend coverage to
  unrouted surfaces.

## 3.4.0 — 2026-06-21 — Public verifier-kit distribution boundary release

### Public verifier-kit distribution boundary release

- Promoted the North Star readiness boundary from v3.3.x proof-path hardening
  to `READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION` when live GitHub
  release-asset evidence, reproducible verifier-kit hashes, and required
  public release assets are all present.
- Updated public verifier and CLI documentation so default no-assets
  release-forward runs remain `NOT_READY_FOR_V3_4_0`, while derived live
  publication evidence can support only the bounded v3.4.0 boundary-release
  readiness claim.
- Boundary: this is not external attestation, non-operator review, production
  publisher-key custody, production signing identity, production authority,
  enterprise readiness, sovereign recognition, live trust-registry truth,
  revocation truth, production downstream recognition, all-MCP governance, or
  coverage of unrouted surfaces.

## 3.3.110 — 2026-06-21 — Verifier-kit publication evidence split

### Verifier-kit publication evidence split

- Changed `zlar verifier-kit-public-distribution` so live GitHub release-asset
  evidence carries the public publication fact while
  `zlar-verifier-kit-reproducibility-v1.json` remains source-build
  determinism evidence.
- `--require-public` now requires required release assets, live release-asset
  publication evidence, and local artifact hashes matching the reproducibility
  report. It no longer requires mutating the reproducibility report's
  `public_release_publication` boundary flag.
- North Star readiness can now report
  `READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION` when public verifier-kit
  distribution posture is proven, without claiming external attestation,
  production authority, enterprise readiness, or sovereign recognition.

## 3.3.109 — 2026-06-21 — Verifier-kit public distribution posture audit

### Verifier-kit public distribution posture audit

- Added `zlar verifier-kit-public-distribution`, which consumes supplied
  release-asset JSON plus `zlar-verifier-kit-reproducibility-v1.json` and
  reports whether the verifier-kit tarball, sidecar, and reproducibility
  evidence support a public distribution posture.
- The release-forward dry-run helper now preserves
  `zlar-verifier-kit-public-distribution-v1.json` for `v3.3.109+` targets, and
  the North Star readiness report consumes that optional posture audit without
  upgrading the public claim.
- Boundary: this is a posture audit and guard. It does not upload release
  assets, read private keys, prove production publisher key custody, prove
  production signing identity, create external attestation, prove non-operator
  review, prove live trust-registry state, prove revocation truth, prove
  production downstream recognition, prove enterprise readiness, prove
  sovereign recognition, or prove v3.4.0 readiness.

## 3.3.108 — 2026-06-21 — Release-forward result pointer summary

### Release-forward result pointer summary

- `DRY-RUN-RESULT.md` now includes a `Private Intake Pointer Contract` section
  for `v3.3.107+` release-forward dry-run targets.
- The section summarizes both the manifest-side
  `private_verifier_result_sample` pointer and the North Star readiness
  report's puzzle-piece-7 `private_intake_sample_manifest_pointer` object, so
  a human evaluator can see the private-intake discoverability contract without
  opening JSON.
- Boundary: this is dry-run result readability only. It does not contact a
  verifier, publish a verifier, create public external attestation, prove
  non-operator review, prove production authority, prove enterprise readiness,
  prove current-machine governance, prove live MCP coverage, prove key custody,
  prove revocation truth, prove v3.4.0 readiness, or extend coverage to
  unrouted surfaces.

## 3.3.107 — 2026-06-21 — North Star private intake pointer reporting

### North Star private intake pointer reporting

- Updated `zlar north-star-readiness --evidence-dir` to accept
  `--release-tag <vX.Y.Z>` for release-forward dry-run reports.
- The readiness report now records the bounded
  `private_verifier_result_sample` manifest pointer contract for pinned
  `v3.3.104+` targets without reading the manifest or creating a circular
  hash.
- Extended the release-forward dry-run helper, verifier packet docs, CLI
  reference, and regression guards so the pointer is visible in both the
  manifest and the North Star readiness report.
- Boundary: this is private-intake sample discoverability only. It does not
  contact a verifier, publish a verifier, create public external attestation,
  prove non-operator review, prove production authority, prove enterprise
  readiness, prove current-machine governance, prove live MCP coverage, prove
  key custody, prove revocation truth, prove v3.4.0 readiness, or extend
  coverage to unrouted surfaces.

## 3.3.106 — 2026-06-21 — Private intake manifest pointer

### Private intake manifest pointer

- Added a `private_verifier_result_sample` object to
  `DRY-RUN-MANIFEST.json` for `v3.3.104+` release-forward dry-run targets.
- The pointer names the generated private-intake envelope, verification file,
  `DRY-RUN-RESULT.md`, and the `Private Verifier Result Intake` hash section.
- The pointer explicitly records that the generated private-intake sample files
  are not part of the core `artifact_hashes` list, avoiding circular
  self-hashing while keeping the sample discoverable.
- Extended the release-forward dry-run guard, external verifier packet, and
  README so the manifest pointer is regression-covered and documented.
- Boundary: this is manifest discoverability for a generated sample fixture
  only. It does not contact a verifier, publish a verifier, create public
  external attestation, prove non-operator review, prove production authority,
  prove enterprise readiness, prove current-machine governance, prove live MCP
  coverage, prove key custody, prove revocation truth, prove v3.4.0 readiness,
  or extend coverage to unrouted surfaces.

## 3.3.105 — 2026-06-21 — Release-forward private intake sample

### Release-forward private intake sample

- Extended `tools/release-forward-verifier-dry-run.sh` for `v3.3.104+`
  targets to generate `zlar-private-verifier-result-v1.json` over the
  dry-run packet's own artifacts.
- The helper now verifies that generated private-intake envelope with
  `bin/zlar private-verifier-result verify --evidence-dir .. --json` and
  preserves `zlar-private-verifier-result-verification-v1.json`.
- `DRY-RUN-RESULT.md` now records the generated private-intake envelope and
  verification hashes separately from the core dry-run manifest hashes, avoiding
  circular self-hashing while still preserving the sample-intake evidence.
- Updated the release-forward helper guard, external verifier packet, and
  README so the `v3.3.104+` private-intake sample path is documented and
  regression-covered.
- Boundary: this is sample private-intake reproducibility over a local
  non-sending dry-run packet only. It does not contact a verifier, publish a
  verifier, create public external attestation, prove non-operator review,
  prove production authority, prove enterprise readiness, prove current-machine
  governance, prove live MCP coverage, prove key custody, prove revocation
  truth, prove v3.4.0 readiness, or extend coverage to unrouted surfaces.

## 3.3.104 — 2026-06-21 — Private evidence hash verification

### Private evidence hash verification

- Added `--evidence-dir <dir>` to `zlar private-verifier-result verify`.
- When supplied, the validator recomputes every declared
  `evidence.artifact_hashes[]` SHA-256 against the matching safe relative file
  under the evidence directory.
- The validator fails closed on missing files, symlinks, directories, and hash
  mismatches while naming only the relative artifact path, not the operator's
  local evidence directory.
- Refreshed the committed private verifier result fixture to the latest
  `v3.3.103` release-forward dry-run hashes and added regression coverage for
  generated evidence directories, mismatch refusal, missing-file refusal,
  symlink refusal, CLI JSON output, and privacy-safe failure text.
- Boundary: this is private intake artifact-integrity hardening only. It does
  not contact a verifier, publish a verifier, create public external
  attestation, prove non-operator review, prove production authority, prove
  enterprise readiness, prove current-machine governance, prove live MCP
  coverage, prove key custody, prove revocation truth, prove v3.4.0 readiness,
  or extend coverage to unrouted surfaces.

## 3.3.103 — 2026-06-21 — Private verifier result intake

### Private verifier result intake

- Added `zlar private-verifier-result verify`, a read-only validator for
  `zlar-private-verifier-result-v1` private intake envelopes.
- The validator checks explicit release tag and commit SHA, required
  release-forward artifact hashes, private-by-default custody flags, privacy
  flags, and non-claim flags before accepting a returned verifier result
  envelope.
- Added a sample fixture and regression test coverage that reject moving-target
  evidence, public attribution approval, public external-attestation approval,
  identity/contact leakage, missing required artifact hashes, and sample
  fixtures that pretend to be real non-operator completion.
- Updated the external verifier packet, verifier-kit runner template, CLI
  reference, and README so private verifier replies have a machine-readable
  custody path without becoming public claims.
- Boundary: this is private result intake and claim-boundary hardening only. It
  does not contact a verifier, publish a verifier, create public external
  attestation, prove non-operator review, prove production authority, prove
  enterprise readiness, prove current-machine governance, prove live MCP
  coverage, prove key custody, prove revocation truth, prove v3.4.0 readiness,
  or extend coverage to unrouted surfaces.

## 3.3.102 — 2026-06-21 — Receipt emission boundary clarity

### Receipt emission boundary clarity

- Clarified public README architecture copy so the bash gate's default evidence
  path is signed audit entries plus Worker Receipts when the helper is
  available, while Governed Action Receipts are generated by verifier/proof
  commands or emitted by the bash gate only when `emit_receipts` /
  `ZLAR_EMIT_RECEIPTS=true` is configured.
- Corrected the quickstart wording to say the gate decisions are real and the
  v1 receipt is generated over a constructed quickstart audit event, not
  automatically emitted as live production governance evidence.
- Extended receipt-authority public-copy guards so future docs cannot restore
  "Nothing is simulated", unconditional "audit entry + receipt written", or
  "writes audit trail and receipts" overclaims.
- Boundary: this is claim-boundary and copy-guard hardening only. It does not
  change gate behavior, enable default Governed Action Receipt emission, create
  public external attestation, prove non-operator review, prove production
  authority, prove enterprise readiness, prove current-machine governance,
  prove live MCP coverage, or extend coverage to unrouted surfaces.

## 3.3.101 — 2026-06-21 — Readiness report reproducibility bridge

### Readiness report reproducibility bridge

- Updated `zlar north-star-readiness --evidence-dir` to consume
  `zlar-verifier-kit-reproducibility-v1.json` when a release-forward dry-run
  packet supplies it.
- The readiness report now records bounded verifier-kit reproducibility facts:
  same-source same-test-publisher-key tarball stability, manifest/signature
  stability, sidecar match, public artifact hashes present, and false
  reproducibility claim-boundary flags.
- Extended release-forward dry-run assertions and verifier-facing docs so the
  preserved reproducibility report is visible inside the North Star readiness
  packet instead of being a separate unmodeled artifact.
- Boundary: this is readiness-report accuracy over preserved release-forward
  evidence. It does not change the `NOT_READY_FOR_V3_4_0` result, create
  public external attestation, prove non-operator review, prove production
  publisher key custody, prove production signing identity, prove public
  release publication, prove production authority, prove enterprise readiness,
  prove current-machine governance, prove live MCP coverage, or extend
  coverage to unrouted surfaces.

## 3.3.100 — 2026-06-21 — Verifier kit reproducibility evidence

### Verifier kit reproducibility evidence

- Normalized verifier-kit archive metadata so identical source inputs with the
  same publisher key produce a stable distributable tarball SHA-256.
- Added `zlar verifier-kit-reproducibility`, which generates a temporary test
  publisher key, builds the verifier kit twice with that same key, and emits a
  bounded `zlar-verifier-kit-reproducibility-v1` JSON report with tarball,
  sidecar, `MANIFEST.json`, and `MANIFEST.sig` artifact hashes.
- Extended the release-forward dry-run for `v3.3.100+` targets to generate,
  assert, preserve, and hash the verifier-kit reproducibility report.
- Updated verifier-facing docs and guards so the reproducibility report is part
  of the public release-forward evidence packet without becoming an external
  attestation claim.
- Boundary: this is source-build archive determinism for identical inputs and
  the same publisher key. It does not prove production publisher key custody,
  production signing identity, public release publication, external
  attestation, live trust-registry state, revocation truth, enterprise
  readiness, current-machine governance, live MCP coverage, coverage of
  unrouted surfaces, or v3.4.0 readiness.

## 3.3.99 — 2026-06-21 — Release-forward result Markdown polish

### Release-forward result Markdown polish

- Fixed `DRY-RUN-RESULT.md` generation so the preserved runtime-profile and
  coverage artifact lines, plus the artifact-hash code fence, render with
  normal Markdown backticks instead of literal escaped backticks.
- Added release-forward dry-run regression coverage that inspects the generated
  result file and rejects escaped Markdown backticks.
- Boundary: this is release-forward packet readability hardening only. It does
  not change the machine-readable manifest, create public external attestation,
  prove non-operator review, prove production authority, prove enterprise
  readiness, prove current-machine governance, prove live MCP coverage, or
  extend coverage to unrouted surfaces.

## 3.3.98 — 2026-06-21 — North Star readiness report

### North Star readiness report

- Added `zlar north-star-readiness`, a bounded machine-readable closure report
  that maps the seven North Star puzzle pieces against the committed fixture
  and release-forward evidence path.
- Extended the release-forward verifier dry-run for `v3.3.98+` targets to
  generate, assert, preserve, and hash `zlar-north-star-readiness-v1.json`.
- Updated the CLI reference, README, and external verifier packet so evaluators
  can preserve the readiness report without treating it as a v3.4.0 readiness,
  external attestation, production authority, enterprise readiness,
  current-machine governance, live MCP coverage, key custody, or unrouted-
  surface coverage claim.

## 3.3.97 — 2026-06-21 — Release-forward malformed-registry evidence

### Release-forward malformed-registry evidence

- Extended the release-forward verifier dry-run packet for `v3.3.97+` targets
  to create and preserve a malformed
  `trusted-receipt-issuers-v1` registry fixture and the corresponding
  `verify-recognition.mjs` error output.
- Added release-forward assertions proving the malformed registry contract
  exits with error before any `RECOGNIZED` or `RECOGNITION-REFUSED` verdict is
  emitted, and records hashes for both the malformed fixture and error
  artifact in the dry-run manifest.
- Documented the new packet artifact boundary in the external verifier packet:
  this is portable schema-contract fail-closed evidence only.
- Boundary: this is local release-forward packet hardening. It does not prove
  live trust-registry state, key custody, revocation truth, production
  downstream recognition, external attestation, sovereign recognition,
  production authority, enterprise readiness, all-MCP governance, or coverage
  of unrouted surfaces.

## 3.3.96 — 2026-06-21 — Trusted issuer registry schema contract

### Trusted issuer registry schema contract

- Tightened `verify-recognition.mjs` so supplied
  `trusted-receipt-issuers-v1` registry fixtures fail closed when they violate
  the shipped schema contract: unsupported top-level fields, unsupported issuer
  fields, missing `evidence_model`, missing issuer `public_key_pem`, or bad
  `required_detail_hash`.
- Added verifier-kit regression coverage proving the bundled registry fixture
  matches the shipped schema contract and schema-contract mismatches exit with
  error before any recognized or refused verdict is emitted.
- Boundary: this is portable supplied-fixture registry contract hardening. It
  does not prove live trust-registry state, key custody, revocation truth,
  production downstream recognition, external attestation, sovereign
  recognition, production authority, enterprise readiness, all-MCP governance,
  or coverage of unrouted surfaces.

## 3.3.95 — 2026-06-21 — Verifier recognition refusal matrix

### Verifier recognition refusal matrix

- Added verifier-kit regression coverage for portable trusted issuer registry
  refusal cases: unknown issuer, retired issuer, compromised issuer, wrong
  policy, wrong scope, and malformed registry input.
- Documented those `verify-recognition.mjs` refusal reasons in the verifier-kit
  README so external runners can tell recognition from refusal without treating
  either as live trust-registry evidence.
- Boundary: this is supplied-fixture recognition refusal coverage and
  verifier-kit documentation hardening. It does not prove live trust-registry
  state, key custody, revocation truth, production downstream recognition,
  external attestation, sovereign recognition, production authority, enterprise
  readiness, all-MCP governance, or coverage of unrouted surfaces.

## 3.3.94 — 2026-06-21 — Verifier-kit issuer registry recognition

### Verifier-kit issuer registry recognition

- Added a `trusted-receipt-issuers-v1` registry schema and
  `verify-recognition.mjs` verifier-kit entry point that evaluates one
  supplied Governed Action Receipt v1 envelope against one supplied trusted
  issuer registry fixture.
- Made the built verifier kit ship a bundled trusted issuer registry fixture
  for the sample receipt and extended the external-runner dry run to exercise
  recognition in text and JSON form.
- Aligned the release-forward verifier packet so `v3.3.94+` targets can
  preserve `zlar-trusted-receipt-issuer-recognition.json` from the built kit.
- Boundary: this is supplied-fixture issuer recognition and verifier-kit
  portability hardening. It does not prove live trust-registry state, key
  custody, revocation truth, production downstream recognition, external
  attestation, sovereign recognition, production authority, enterprise
  readiness, all-MCP governance, or coverage of unrouted surfaces.

## 3.3.93 — 2026-06-21 — Service-profile wrong-policy refusal

### Service-profile wrong-policy refusal

- Added a config-backed protected-records service-profile preflight case that
  presents a valid signed receipt with the wrong policy version and proves the
  downstream service refuses it with `policy_not_recognized` before
  service-state mutation.
- Promoted the new `11/11` service-profile preflight case set through the
  committed service-profile sample artifact, governed-surface coverage input,
  local proof-pack artifact, proof-smoke report, CLI tests, release-forward
  dry-run assertions, README, CLI reference, and coverage-map docs.
- Tightened the external verifier packet by renaming the old pinned `v3.3.90`
  target from "latest completed" to a backward-compatibility release-forward
  target, and added guards so stale "latest completed" wording cannot return
  to that packet.
- Boundary: this is local disposable service-profile preflight and verifier
  packet hardening. It does not prove runtime activation for that service
  profile, persistent profile installation, live/current-machine governance,
  production service deployment, live approval-channel delivery, external
  attestation, sovereign recognition, enterprise readiness, all-MCP governance,
  or coverage of unrouted records paths.

## 3.3.92 — 2026-06-21 — Release-forward shallow-checkout guard

### Release-forward shallow-checkout guard

- Fixed the release-forward verifier dry-run guard so CI shallow checkouts fetch
  the pinned `v3.3.90` backward-compatibility target before verifying the
  pre-`v3.3.91` four-lane release path.
- Preserved the `v3.3.91+` five-lane service-profile coverage assertion for
  current targets while keeping older pinned release-forward targets truthful at
  `4/4`.
- Boundary: this is release-forward test harness hardening after the published
  `v3.3.91` remote test jobs exposed a shallow-checkout assumption. It does not
  add production deployment, live/current-machine governance, external
  attestation, sovereign recognition, enterprise readiness, all-MCP governance,
  or coverage of unrouted surfaces.

## 3.3.91 — 2026-06-21 — Service-profile coverage lane

### Service-profile coverage lane

- Promoted the committed protected-records service-profile preflight artifact
  into a first-class governed-surface coverage lane:
  `protected-records.service-profile.records.write`.
- Regenerated the committed governed-surface coverage input, local proof-pack
  artifact, and proof-smoke report so the public smoke path now records `5/5`
  governed counted lanes.
- Hardened `proof-smoke --json` and `proof-smoke verify --json` to write large
  JSON reports synchronously, preventing stdout truncation of the committed
  smoke report.
- Extended release-forward and external-verifier guards to preserve the
  service-profile lane by count, surface id, receipt-capable status, and
  `runtime_profile_not_installed` boundary.
- Retargeted the prepared latest-completed release-forward verifier target from
  `v3.3.88` to the already completed `v3.3.90` release target.
- Boundary: this is local disposable service-profile preflight and coverage-map
  proof hardening. It does not prove runtime activation for that service
  profile, persistent profile installation, live/current-machine governance,
  production service deployment, live approval-channel delivery, external
  attestation, sovereign recognition, enterprise readiness, all-MCP governance,
  or coverage of unrouted records paths.

## 3.3.90 — 2026-06-21 — Runtime profile-id refusal

### Runtime profile-id refusal

- Added the wrong-runtime-profile-id runtime-profile case so a request-stream
  `runtime_profile_id` mismatch is classified as supplied authority material
  and refused before runtime-state mutation.
- Promoted the expanded `31/31` runtime-profile case set through
  runtime-local-activation, runtime-profile-installation, governed-surface
  coverage map, local proof-pack, proof-smoke, release-forward dry-run
  assertions, external verifier packet boundary text, README, and CLI docs.
- Regenerated the committed activation-preflight, runtime-local-activation,
  runtime-profile-installation, coverage-map, local proof-pack, and proof-smoke
  fixtures so verifier sample artifacts carry `wrong_runtime_profile_id_refused`.
- Boundary: this is local disposable runtime/profile-installation proof
  hardening. It does not prove live/current-machine governance, persistent
  profile installation, production deployment, live downstream recognition,
  external attestation, sovereign recognition, enterprise readiness, all-MCP
  governance, or coverage of unrouted surfaces.

## 3.3.89 — 2026-06-21 — Verifier target and boundary guards

### Verifier target and boundary guards

- Retargeted the release-forward verifier packet to the latest completed
  `v3.3.88` release target and renamed the packet convention from "current"
  to "latest completed" so the pinned SHA requirement does not become stale at
  the next release boundary.
- Extended the release-forward dry-run assertions to preserve the expanded
  runtime-local-activation and runtime-profile-installation refusal taxonomy in
  standalone sample verification artifacts and embedded local proof-pack
  summaries.
- Tightened off-switch status and documentation around the structural
  `/etc/zlar/off-flag` path versus the legacy wrapper marker; `zlar off` no
  longer claims the current install-managed gate is off when only the legacy
  marker can be written.
- Hardened SECURITY, architecture, CLI, doctrine, signal, and public-copy guard
  language against unbounded governed-path claims, stale legacy-wrapper
  fallback claims, "impossible by design" language, and public attribution of
  ZLAR invariants to external traditions or frameworks.
- Boundary: this is verifier-packet, CLI-status, documentation, and guard
  hardening only. It does not install or activate a gate, prove
  current-machine governance, prove live approval-channel delivery, create
  public external attestation, prove production deployment, prove sovereign
  recognition, or prove coverage of unrouted surfaces.

## 3.3.88 — 2026-06-21 — Runtime refusal taxonomy

### Runtime refusal taxonomy

- Added the wrong-audit-event runtime-profile case and promoted the full local
  disposable runtime refusal taxonomy through runtime-local-activation,
  runtime-profile-installation, local proof-pack, proof-smoke, sample artifacts,
  and CLI/docs summaries.
- Regenerated the committed activation-preflight, runtime-local-activation,
  runtime-profile-installation, local proof-pack, coverage-map, and proof-smoke
  fixtures so verifiers can see the same refusal taxonomy without rerunning
  fresh evidence.
- Boundary: this is local disposable runtime/profile-installation proof
  hardening. It does not prove live/current-machine governance, persistent
  profile installation, production deployment, live downstream recognition,
  external attestation, sovereign recognition, enterprise readiness, all-MCP
  governance, or coverage of unrouted surfaces.

## 3.3.87 — 2026-06-21 — Downstream refusal explicit reasons

### Downstream refusal explicit reasons

- Extended the local hermetic downstream-refusal proof to refuse missing,
  invalid, stale, unknown-issuer, retired-issuer, wrong-policy, out-of-scope,
  wrong-audit-event, wrong-detail, and non-boarding receipts before a fake
  downstream marker write.
- Regenerated the committed local proof-pack and proof-smoke fixtures so the
  proof-pack carries the expanded refusal set.
- Refreshed the prepared current release-forward verifier target from
  `v3.3.81` to the already released `v3.3.86` target without claiming verifier
  contact or public external attestation.
- Boundary: this remains local hermetic fixture evidence. It does not prove
  live downstream recognition, production deployment, current-machine
  governance, external attestation, sovereign recognition, enterprise
  readiness, all-MCP governance, or coverage of unrouted surfaces.

## 3.3.86 — 2026-06-21 — Release-forward service-preflight quick-check

### Release-forward service-preflight quick-check

- Extended `tools/release-forward-verifier-dry-run.sh` and the external
  verifier packet to run and preserve
  `zlar-service-preflight-sample-verification.json`, the standalone
  config-backed protected-records service-preflight sample verification.
- Added dry-run assertions for the `10/10` config-backed service-preflight
  boundary: launcher-owned config required, request-stream authority material
  refused before mutation, direct-API-with-receipt refused through
  `request_stream_forbidden_fields`, and no production/external-attestation
  claim.
- Boundary: this is evaluator packet hardening only. It sends no verifier
  request, creates no public external attestation, and does not prove live
  records-system evidence, active profile installation, production service
  deployment, current-machine governance, sovereign recognition, or unrouted
  surface coverage.

## 3.3.85 — 2026-06-21 — Config-backed service preflight

### Protected records service config-backed preflight

- Extended `zlar protected-records-service-request` with an optional
  `--config <file|->` launcher-owned config mode. In this mode the request
  stream supplies only `receipt` and `record_update`; recognition rule, fixture
  mode, state path, consumed-receipt path, and fixture clock come from config.
- Upgraded the protected-records service profile preflight, committed
  service-preflight artifact, local proof pack, and proof-smoke fixture to prove
  request-stream authority-material refusal before service-state mutation.
- Boundary: this is still local disposable fixture/preflight evidence. It does
  not install or activate a profile, inspect a live records system, close
  direct filesystem writes to configured fixture paths, prove production
  records service deployment, prove current-machine governance, or provide
  external attestation or sovereign recognition.

## 3.3.84 — 2026-06-21 — Release-forward dry-run manifest

### Release-forward verifier dry-run manifest

- Extended `tools/release-forward-verifier-dry-run.sh` to emit
  `DRY-RUN-MANIFEST.json`, a machine-readable dry-run result envelope with the
  explicit target, observed commit, assertion counts, artifact hashes, run-file
  hashes, privacy flags, and non-claim flags.
- Extended helper and external-verifier packet guards to require the manifest
  and verify that local repo paths are sanitized and no verifier-contact,
  public-attestation, current-machine governance, production, or credential
  claims are introduced.
- Boundary: this is dry-run evidence packaging only. It sends no verifier
  request, contacts no verifier, creates no public external attestation, and
  does not prove non-operator review, production deployment, current-machine
  governance, live issuer status, key custody, sovereign recognition,
  enterprise readiness, or unrouted-surface coverage.

## 3.3.83 — 2026-06-21 — Release-forward verifier dry-run helper

### Release-forward verifier dry-run helper

- Added `tools/release-forward-verifier-dry-run.sh`, a non-sending helper that
  fresh-clones an explicit release target, checks the expected commit SHA, runs
  the bounded release-forward verifier packet commands, preserves artifacts and
  hashes, and refuses moving targets such as `main`, `HEAD`, `latest`, and
  `--latest`.
- Added guard coverage for the helper interface, pinned command plan, argument
  refusals, local-repo happy path, artifact preservation, JSON evidence fields,
  and transcript privacy.
- Boundary: this is dry-run automation only. It sends no verifier request,
  contacts no verifier, creates no public external attestation, and does not
  prove non-operator review, production deployment, current-machine governance,
  live issuer status, key custody, sovereign recognition, enterprise readiness,
  or unrouted-surface coverage.

## 3.3.82 — 2026-06-21 — Pinned v3.3.81 verifier target

### Pinned v3.3.81 verifier target

- Added a prepared pinned current release-forward verifier target for
  `v3.3.81` at commit `ebcfa57caf80624036f884d7133fbe92127d0180`.
- Kept the earlier prepared `v3.3.76` target intact and scoped it back to its
  active-profile evidence, while the new `v3.3.81` target carries the
  disposable runtime-profile installation summary and `4/4` coverage-map
  expectation.
- Extended the external-verifier packet guard to assert the `v3.3.81` tag/SHA,
  no-request boundary, no-attestation boundary, runtime-profile installation
  counts, artifact preservation, README guidance, and coverage-map guidance.
- Boundary: this prepares a pinned future verifier target only. It sends no
  verifier request, contacts no verifier, creates no public external
  attestation, and does not prove production deployment, current-machine
  governance, live issuer status, key custody, revocation truth, sovereign
  recognition, enterprise readiness, or unrouted-surface coverage.

## 3.3.81 — 2026-06-21 — Disposable runtime profile installation proof

### Disposable runtime profile installation proof

- Added `zlar protected-records-runtime-profile-installation`, a local
  disposable proof that validates an explicit installation plan and pinned
  runtime-profile SHA, copies the profile into a launcher-owned disposable proof
  root, writes an active profile index, selects by explicit id and SHA, and
  runs the bounded protected-records runtime-profile proof.
- Added artifact generation and verification for the disposable installation
  proof, including request-authority guard evidence that installed profile
  state, runtime config, runtime profile, and recognition-rule material supplied
  through the request stream are refused before mutation.
- Integrated the new proof into `local-proof-pack`, `proof-smoke`, and the
  governed-surface coverage sample, which now records `4/4` governed counted
  lanes including the disposable profile-installation records.write lane.
- Updated README, CLI reference, governed-surface coverage-map docs, and the
  external verifier packet with bounded v3.3.81+ preservation guidance for the
  runtime-profile installation summary and sample verification.
- Boundary: this is local disposable fixture evidence only. It does not prove
  persistent runtime profile installation, hook activation, user or machine
  configuration, live/current-machine runtime profile state, current-machine
  governance, production authority, public external attestation, sovereign
  recognition, enterprise readiness, or unrouted-surface coverage.

## 3.3.80 — 2026-06-21 — Approval-channel boundary normalization

### Approval-channel boundary normalization

- Replaced unconditional Telegram/phone approval-path wording in README and
  doctrine copy with configured approval-channel language and fail-closed
  behavior when no approved channel is enabled.
- Replaced broad "agents cannot modify their own rules" wording in the README
  execution diagram with the narrower signed-policy integrity boundary.
- Extended the receipt-authority public-copy guard to reject stale
  Telegram/phone route claims and categorical agent self-modification claims.
- Boundary: this is documentation and guard hardening only. It does not prove
  live approval-channel delivery or health, Telegram availability, phone
  delivery, current-machine governance, host protection, direct bypass
  prevention, production authority, public external attestation, sovereign
  recognition, enterprise readiness, or unrouted-surface coverage.

## 3.3.79 — 2026-06-21 — Verifier handoff wording normalization

### Verifier handoff wording normalization

- Renamed the prepared `v3.3.76` release-forward verifier target so it is
  explicitly a pinned prepared target, not a moving current-release claim.
- Added a changelog-currentness note so historical pending or current-release
  wording remains historical and does not become the present public boundary.
- Extended the external-verifier packet guard to assert both the prepared pinned
  target label and the changelog historical-wording boundary.
- Boundary: this is documentation and guard hardening only. It sends no new
  verifier request, contacts no verifier, creates no public external
  attestation, and does not prove persistent runtime profile installation, hook
  activation, live/current-machine profile state, current-machine governance,
  production authority, sovereign recognition, enterprise readiness, or
  unrouted-surface coverage.

## 3.3.78 — 2026-06-21 — Verifier active-profile boundary hardening

### Verifier active-profile boundary hardening

- Added README and governed-surface coverage-map evaluator guidance to preserve
  `v3.3.76+` active-profile smoke counts and the embedded proof-pack
  `active_profile_selection` summary.
- Tightened the external verifier packet so the prepared release-forward target
  is described as the pinned `v3.3.76` target, not a moving current-release
  claim, and so the attestation template prompts verifiers to preserve
  active-profile counts and summary evidence.
- Replaced pending-shaped verifier-kit runner wording with an explicit no-claim
  boundary: no external attestation is claimed for a run unless a real
  non-operator runner fills, signs, or publishes the result.
- Extended the external-verifier packet guard to scan verifier-kit source docs
  and assert the active-profile preservation guidance across README, the
  coverage map, packet template, and verifier-kit runner surfaces.
- Boundary: this is documentation and guard hardening only. It sends no new
  verifier request, contacts no verifier, creates no public external
  attestation, and does not prove persistent runtime profile installation, hook
  activation, live/current-machine profile state, current-machine governance,
  production authority, sovereign recognition, enterprise readiness, or
  unrouted-surface coverage.

## 3.3.77 — 2026-06-20 — Verifier packet v3.3.76 retarget

### Verifier packet v3.3.76 retarget

- Retargeted the prepared release-forward external verifier packet to
  `v3.3.76` at commit `3369ae5f04b0735c8a11bc55c70b49c09edad0da`.
- Added verifier-packet guidance for preserving proof-smoke active-profile
  selection counts and the local proof-pack verifier's embedded
  `active_profile_selection` summary when reviewing `v3.3.76+` releases.
- Locally simulated the release-forward packet from a fresh public clone of
  `v3.3.76`, including verifier environment checks, proof-smoke generated and
  sample verification, local proof-pack sample verification, issuer-status
  proof, verifier-kit issuer-status artifact output, runtime-local-activation
  sample verification, coverage-map JSON, receipt-authority guard, and the
  active-profile evidence checks.
- Boundary: this release prepares a pinned verifier packet target and local
  dry-run evidence only. It sends no new verifier request, contacts no verifier,
  creates no public external attestation, and does not prove production
  deployment, current-machine governance, live issuer status, key custody,
  revocation truth, sovereign recognition, enterprise readiness, or
  unrouted-surface coverage.

## 3.3.76 — 2026-06-20 — Proof-pack active profile selection summary

### Proof-pack active profile selection summary

- Surfaced the first `records.write` active-profile selection contract inside
  the local proof-pack artifact and proof-smoke report, so the broader proof
  bundle now records the selected disposable runtime profile, selection scope,
  route, downstream boundary, and plan/profile SHA binding.
- Extended proof-pack and proof-smoke verification to reject missing or drifted
  active-profile selection evidence, including accidental `--latest`, live
  runtime-profile inspection, persistent profile installation, or hook
  configuration claims.
- Regenerated the local proof-pack and proof-smoke fixtures so downstream
  verifiers see the embedded active-profile selection summary in the canonical
  sample contract.
- Boundary: this release propagates fixture-contained active-profile selection
  evidence into proof-pack and proof-smoke outputs only. It does not claim
  persistent runtime profile installation, hook activation, live/current-machine
  runtime profile state, current-machine governance, production authority,
  external attestation, sovereign recognition, all-MCP governance, or
  unrouted-surface coverage.

## 3.3.75 — 2026-06-20 — Records.write active profile selection proof

### Records.write active profile selection proof

- Extended `zlar records-write-terminal-proof` with an
  `active_profile_selection` contract that binds the first `records.write`
  terminal to an explicit pinned runtime profile selected as active inside the
  local disposable proof harness.
- The proof now records selection scope, plan/profile SHA binding, route,
  downstream boundary, fixture profile identity, and refusal of `--latest`,
  persistent runtime-profile installation, live runtime-profile checks, and
  hook configuration writes.
- Added regression coverage so active-profile selection cannot drift into a
  persistent install, live profile claim, or latest-profile selection.
- Boundary: this is fixture-contained active-profile selection evidence only.
  It does not claim persistent runtime profile installation, hook activation,
  live/current-machine runtime profile state, live records-system inspection,
  production service deployment, current-machine governance, external
  attestation, sovereign recognition, all-MCP governance, or unrouted-surface
  coverage.

## 3.3.74 — 2026-06-20 — Public claim guard hardening

### Public claim guard hardening

- Tightened README and public signal language so approval routing is described
  as configured-channel behavior, not unconditional phone or Telegram
  availability.
- Qualified agent self-governance protection language to configured
  ZLAR-governed routes and hardened deployments, preserving side-door honesty.
- Extended the receipt-authority public-copy guard to scan `signal/` and reject
  unconditional phone approval, Telegram approval, absolute self-governance
  impossibility, and unbounded "structurally impossible" phrasing.
- Boundary: this is public claim-boundary hardening only. It does not claim
  live approval-channel health, production authority, current-machine
  governance proof, external attestation, sovereign recognition, all-MCP
  governance, or coverage of unrouted surfaces.

## 3.3.73 — 2026-06-20 — Records.write terminal proof

### One-terminal records.write proof

- Added `zlar records-write-terminal-proof`, a one-command local disposable
  proof surface for the first `records.write` terminal.
- The command uses explicit fixture inputs, generates fresh local proof
  evidence in memory, verifies the in-memory runtime-local-activation
  artifact, and prints the bounded airport sentence for the terminal.
- Added regression coverage for the structured proof contract, CLI text/JSON
  output, default fixture paths, stdin plan input, unsupported `--latest`
  refusal, and public privacy boundaries.
- Tightened public signal wording around routed/intercepted actions and the
  Codex adapter's Telegram-disabled local fail-closed posture.
- Boundary: this release proves a local disposable routed proof path accepts
  one recognized `records.write` and refuses missing or unrecognized receipts
  before runtime-state mutation. It does not claim persistent install, hook
  configuration, live records-system evidence, current-machine governance,
  live approval-channel health, production authority, external attestation,
  sovereign recognition, or coverage of unrouted records paths.

## 3.3.72 — 2026-06-20 — Codex adapter Telegram silence

### Codex adapter local fail-closed Telegram silence

- Updated the Codex/Claude Code adapter so this orchestration path defaults
  `ZLAR_TELEGRAM_DISABLED=1` and skips `.env` Telegram credential loading.
- Updated the live gate to honor `ZLAR_TELEGRAM_DISABLED`, clear Telegram
  token/chat routing, classify the source as `disabled`, and deny ask-class
  actions locally instead of dispatching Telegram cards.
- Hardened manifest sequence handling so non-numeric manifest or seq-file
  values fall back to `0` before rollback/poison arithmetic comparisons.
- Added regression coverage for disabled Telegram dispatch, adapter token-load
  bypass, and non-numeric manifest sequence arithmetic guards.
- Boundary: this is Codex adapter operational hygiene and a local fail-closed
  approval-channel repair. It does not claim Telegram health, live approval
  channel availability, external attestation, production authority,
  current-machine governance proof, sovereign recognition, or unrouted-surface
  coverage.

## 3.3.71 — 2026-06-20 — Verifier environment JSON report

### Verifier environment failure report

- Added `zlar verifier-env --json` and
  `zlar verifier-env --json-out <file>` so a blocked external verifier can
  preserve a redacted machine-readable environment readiness or prerequisite
  failure report without exposing local paths, credentials, private-key
  markers, emails, or verifier identity.
- The JSON report is private-by-default environment readiness evidence only. It
  explicitly does not claim a verifier pass, ZLAR proof run, external
  attestation, key custody, live issuer status, production authority,
  current-machine governance, sovereign recognition, or unrouted-surface
  coverage.
- Updated the external verifier packet to preserve
  `zlar-verifier-env-report-v0.json` and to classify pre-proof environment
  failures as verifier environment prerequisite failures, not verification or
  attestation failures.

## 3.3.70 — 2026-06-20 — Verifier environment preflight

### Verifier environment preflight

- Added `zlar verifier-env`, a bash-only external verifier workstation
  preflight that checks Git, Bash, Node.js, `jq`, OpenSSL, and the exact
  OpenSSL Ed25519 command used by the release-forward packet.
- Added `tools/build-verifier-kit.sh --check-env` so the source-form verifier
  kit build path exposes the same no-write environment readiness gate before
  any `dist/` artifact is rebuilt.
- Updated the external verifier packet to run `bin/zlar verifier-env` before
  the longer proof sequence and to preserve the verifier-kit source-build
  preflight output so LibreSSL/Ed25519 failures are preserved as bounded
  environment evidence instead of ambiguous verifier failures.

## 3.3.69 — 2026-06-20 — External verifier packet OpenSSL preflight

### External verifier packet OpenSSL preflight

- Added an early `openssl genpkey -algorithm ED25519 -out /dev/null`
  release-forward packet preflight so verifiers fail fast when their OpenSSL
  build lacks Ed25519 support, before running the longer packet commands.

## 3.3.68 — 2026-06-20 — External verifier packet v3.3.67 retarget

### External verifier packet release-forward target

- Retargeted the prepared, not-sent release-forward verifier packet to
  `v3.3.67` at commit `92dc13ca86cbca864f189a154a42a6079ffdcca3`.
- Updated the packet's verifier-kit issuer-status artifact step to use
  `external-runner-dry-run.sh --issuer-status-json-out` while preserving the
  no-new-verifier-request and no-external-attestation boundary.

## 3.3.67 — 2026-06-20 — Verifier-kit runner issuer artifact output

### Verifier-kit external runner issuer-status artifact output

- Added `--issuer-status-json-out <file>` to
  `external-runner-dry-run.sh` so a clean-room runner can write the
  already-validated issuer-status JSON artifact requested by the
  release-forward packet without hand-copying transcript output.
- The helper refuses to overwrite an existing issuer-status JSON output file
  and does not print the local output path in its transcript.
- Extended verifier-kit regression coverage for the artifact file shape,
  privacy-safe transcript, and overwrite refusal.

## 3.3.66 — 2026-06-20 — Verifier-kit external runner issuer-status step

### Verifier-kit external runner issuer-status step

- Added `node verify-issuer-status.mjs` and
  `node verify-issuer-status.mjs --json` to the verifier-kit external-runner
  flow and dry-run helper so the kit-local runner matches the release-forward
  verifier packet.
- Updated the external-runner result template to preserve the
  `zlar-verifier-kit-issuer-status-fixture.json` hash when generated while
  keeping the boundary that this is fixture evidence only, not live issuer
  status, custody, revocation truth, production trust-registry state,
  production downstream recognition, or external attestation.
- Extended verifier-kit regression coverage so the runner transcript and
  runner docs cannot drop the issuer-status fixture step or its non-claims.

## 3.3.65 — 2026-06-20 — External verifier packet kit-local issuer-status check

### External verifier packet verifier-kit issuer-status check

- Added `v3.3.64+` release-forward packet steps for building the verifier kit
  and running `node verify-issuer-status.mjs` in text and JSON mode.
- Added evidence-preservation language for
  `zlar-verifier-kit-issuer-status-fixture.json` while preserving the boundary
  that this is fixture evidence only, not live issuer status, custody,
  revocation truth, production trust-registry state, production downstream
  recognition, or external attestation.

## 3.3.64 — 2026-06-20 — Verifier-kit issuer-status fixture

### Verifier-kit issuer-status fixture

- Added `verify-issuer-status.mjs` to the verifier kit so a third party can
  run a bundled hermetic issuer-status fixture after kit self-test without
  calling a ZLAR server.
- Packaged the bounded issuer-status proof and downstream recognition helper
  into the kit and documented the command as fixture evidence only.
- Extended verifier-kit regression coverage for text, JSON, help, README path,
  privacy, and bundle-integrity behavior of the new issuer-status entry point.

## 3.3.63 — 2026-06-20 — Verifier-kit issuer boundary help

### Verifier-kit issuer-recognition help boundary

- Corrected verifier-kit `verify.mjs --help` so the command-line non-claim
  text points to the nine documented kit limits (`L1-L9`) and explicitly names
  active issuer recognition as outside a `VALID` receipt-verification verdict.
- Extended the verifier-kit regression suite so executable help cannot drift
  back to the pre-L9 issuer-recognition boundary.

## 3.3.62 — 2026-06-20 — Release-forward verifier packet

### External verifier release-forward packet

- Added a release-forward verification template to the external verifier packet
  so future verifier requests pin an explicit release tag and exact commit SHA
  instead of reusing the historical `v3.3.49` request state or any moving
  target.
- Added a prepared, not-yet-sent `v3.3.61` release-forward target pinned to
  commit `36eb1f167d923adb64042e029adff05ecf7a8a1d` without creating a verifier
  request or attestation claim.
- Added a generated-smoke-report verification step so the release-forward path
  checks the `zlar-proof-smoke-v1.json` it just emitted, not only the committed
  sample report.
- Added release-forward evidence preservation for issuer-status proof JSON and
  coverage-map JSON, including the `v3.3.61+` coverage summary fields:
  `coverage_summary`, `last_decision`, `last_receipt`, `issuer_identity`, and
  `known_boundaries`.
- Extended the packet guard test so the historical private request remains
  bounded while future requests keep the no-`--latest`, no-public-attestation
  boundary.

## 3.3.61 — 2026-06-20 — Coverage map airport summaries

### Coverage map airport summaries

- Extended `zlar coverage --sample --json` and supplied-input coverage maps with
  privacy-safe `coverage_summary`, `last_decision`, `last_receipt`,
  `issuer_identity`, and `known_boundaries` fields for every reported surface.
- Updated the text coverage summary for counted lanes so evaluator output now
  names the latest supplied decision outcome, receipt verification status, and
  issuer/trust-anchor identifier alongside route, freshness, policy, receipt,
  and downstream-refusal gates.
- Regenerated the committed `zlar-proof-smoke-v1` fixture so the evaluator smoke
  report carries the expanded coverage-map summary shape.
- Hardened the proof-smoke command and test harnesses to file-capture large JSON
  subprocess output, avoiding 64 KiB stdout clipping in Node child-process
  captures as the committed smoke artifact grows.

### Boundaries and non-claims

- These summaries are derived from supplied fixture/report evidence only. They
  do not inspect live hooks, live audit stores, current-machine state, live MCP
  configuration, live records systems, or operator key material.
- `issuer_identity` is an evidence anchor summary, not proof of active issuer
  status, key custody, revocation truth, production trust-registry state,
  external attestation, sovereign recognition, production authority, or coverage
  of unrouted surfaces.

## 3.3.60 — 2026-06-20 — Key-state sample proof path

### Key-state sample proof path

- Added deterministic `zlar key-state --sample --json` output for evaluator
  fixtures that need the key-state report shape without inspecting an
  operator's home directory, hardware, private key paths, or current-machine
  custody state.
- Extended `zlar local-proof-pack` with a thirteenth `key_state_report`
  component, generated from the deterministic sample report and validated
  through the proof-pack contract.
- Extended local proof-pack artifact verification and `zlar proof-smoke` so
  committed fixtures expose an embedded key-state sample summary alongside the
  receipt-verifier, service-profile, activation-preflight, and runtime-local
  activation summaries.
- Regenerated the committed local proof-pack artifact and proof-smoke report.
  The proof-pack artifact body SHA-256 is now
  `e14c4570d18ff10f7d314c26396302fa3553451a1ba927390aea269a3072988a`.

### Boundaries and non-claims

- `zlar proof-smoke` still verifies committed sample artifacts. It does not run
  current-machine `zlar key-state --json`, inspect operator home key material,
  inspect hardware, prove key custody, prove hardware possession, prove
  revocation truth, prove production trust-registry state, provide external
  attestation, prove sovereign recognition, or prove current-machine
  governance.
- `zlar key-state --sample --json` is deterministic fixture evidence only. It
  is not a live key-state snapshot and not release, custody, revocation, or
  production-authority evidence.

## 3.3.59 — 2026-06-20 — Read-only key-state JSON report

### Read-only key-state JSON report

- Added `zlar key-state --json`, a machine-readable local key-state report for
  verifier pins, embedded signing public keys, hardware-slot observation, and
  legacy software private-key presence as a boolean only.
- Exposed the existing key-state command through the main `zlar key-state`
  dispatcher and added focused CLI tests for JSON shape, privacy, help, and
  fail-closed unsupported options.
- Corrected key-state text output so missing policy/constitution hardware
  targets do not falsely fail the current software-rooted signing posture.

### Boundaries and non-claims

- This is a local read-only key-state snapshot. It does not sign, request PINs,
  read private key bytes, rotate or revoke keys, prove key custody, prove
  hardware possession, prove production trust-registry truth, provide external
  attestation, prove sovereign recognition, or prove current-machine
  governance.

## 3.3.58 — 2026-06-20 — Runtime-local coverage lane bridge

### Runtime-local coverage lane bridge

- Extended `zlar coverage --sample --require-governed` so the committed
  coverage fixture now counts the protected-records runtime-local activation
  artifact as `protected-records.runtime.records.write`.
- Added runtime-local lane validation that requires the committed artifact to
  prove the explicit plan/profile SHA match, the
  `receipt-recognition-before-runtime-state-mutation` route, recognized
  `records.write` acceptance, and replay/missing/invalid/unknown-issuer/
  stale/wrong-policy/direct-API/agent-supplied-authority refusal before
  runtime-state mutation.
- Regenerated the committed local proof-pack artifact and proof-smoke report so
  the evaluator smoke path now records `3/3` governed counted lanes.

### Boundaries and non-claims

- This is a coverage-map bridge over existing local disposable fixture
  evidence. It does not install a persistent runtime profile, write hook or
  machine configuration, prove live/current-machine governance, prove live MCP
  coverage, inspect a live records system, deploy a production records service,
  provide external attestation, prove sovereign recognition, or cover unrouted
  records paths.

## 3.3.57 — 2026-06-20 — Compromised issuer recognition boundary

### Compromised issuer recognition boundary

- Hardened downstream recognition so a known issuer marked `compromised`
  refuses with distinct `issuer_compromised` instead of collapsing into the
  generic inactive-issuer refusal.
- Extended `zlar issuer-status-proof`, `zlar local-proof-pack`, and committed
  proof-smoke fixtures so local fixture evidence now distinguishes active,
  retired, compromised, missing-status, unknown, and key-missing receipt
  issuers before boarding.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the expanded issuer-status boundary.

### Boundaries and non-claims

- This is local fixture issuer-recognition evidence only. It proves a supplied
  downstream recognition rule can refuse a signer marked `compromised` before
  boarding. It does not prove live key custody, live trust registry state,
  rotation operations, revocation infrastructure, compromise response,
  production deployment, external attestation, sovereign recognition, or
  coverage of unrouted surfaces.

## 3.3.56 — 2026-06-20 — Local proof-pack receipt-verifier boundary evidence

### Local proof-pack receipt-verifier boundary evidence

- Added a twelfth `zlar local-proof-pack` component that runs the actual
  `zlar-verify <receipt.json> --pubkey <key.pub> --json` CLI against local
  ephemeral v1 receipts and proves `VALID`, `UNKNOWN-SIGNER`, and `INVALID`
  remain distinct by verdict and exit code.
- Extended local proof-pack artifact verification and `proof-smoke` validation
  so committed sample verification exposes the embedded receipt-verifier
  boundary summary without rerunning the verifier proof.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the twelve-component proof pack.

### Boundaries and non-claims

- This is local ephemeral receipt-verifier fixture evidence only. It proves
  signed-byte/semantic integrity under a supplied public key, wrong-key
  `UNKNOWN-SIGNER`, and tamper `INVALID` separation. It does not prove active
  issuer status, key custody, revocation state, downstream recognition,
  production deployment, current-machine governance, external attestation,
  sovereign recognition, or coverage of unrouted surfaces.

## 3.3.55 — 2026-06-20 — Local proof-pack runtime-local-activation evidence

### Local proof-pack runtime-local-activation evidence

- Upgraded `zlar local-proof-pack` from runtime-local-activation sample
  verification to fresh local disposable runtime-local-activation execution
  inside the proof pack.
- Added an eleventh proof-pack component that records explicit local activation
  command, plan/profile SHA match, launcher-owned disposable runtime config
  written inside the proof harness, local JSONL child service processes
  started, recognized write acceptance, replay/missing/invalid/stale/
  wrong-policy/direct-API refusal, and agent-supplied authority-material
  refusal before runtime-state mutation.
- Extended local proof-pack artifact verification and `proof-smoke` validation
  so committed sample verification exposes the embedded
  runtime-local-activation summary without rerunning the proof pack.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the eleven-component proof pack.

### Boundaries and non-claims

- This is local disposable fixture evidence only. It does not install a
  persistent runtime profile, write hook configuration, write machine or
  production configuration, inspect live/current-machine governance, prove
  production deployment, create public external attestation, prove sovereign
  recognition, or cover unrouted surfaces.

## 3.3.54 — 2026-06-20 — Unknown-signer verifier boundary

### Verifier unknown-signer boundary

- Hardened `bin/zlar-verify` so v1 receipt `kid` mismatch reports
  `UNKNOWN-SIGNER` with exit code `3` instead of collapsing wrong-key
  verification into generic `INVALID`.
- Added machine-readable `receipt_kid`, `provided_kid`, and `kid_match`
  fields to verifier JSON output and tightened CLI help text to state that
  verification proves signed-byte integrity under a supplied key, not issuer
  recognition or deployment authority.
- Updated affected-person and trusted-issuer guidance so wrong signer,
  malformed/tampered receipt, and downstream issuer recognition remain distinct.

### Boundaries and non-claims

- This is verifier-boundary hardening only. It does not create a live trust
  registry, prove key custody, prove rotation or revocation operations, inspect
  live/current-machine governance, prove production deployment, create public
  external attestation, prove sovereign recognition, or cover unrouted
  surfaces.

## 3.3.53 — 2026-06-20 — Runtime-local-activation proof-smoke path

### Runtime-local-activation proof-smoke path

- Added committed runtime-local-activation sample verification as a first-class
  `proof-smoke` step so evaluator smoke output now names the disposable
  `records.write` runtime terminal that refuses missing receipts before
  runtime-state mutation.
- Extended the `zlar-proof-smoke-v1` report contract and sample fixture to
  validate local activation applied inside the proof harness, disposable
  runtime config written, persistent runtime config and hook configuration not
  written, local JSONL child service started, missing receipt refusal,
  direct-API-with-receipt refusal, and agent-supplied authority-material
  refusal.
- Updated the README, CLI reference, and external verifier packet commands to
  preserve the runtime-local-activation sample verification boundary.

### Boundaries and non-claims

- This is committed-fixture evaluator packaging only. It does not install or
  activate a persistent runtime profile, write hooks or machine configuration,
  inspect live/current-machine governance, prove production deployment, create
  public external attestation, prove sovereign recognition, or cover unrouted
  surfaces.

## 3.3.52 — 2026-06-20 — Verifier custody intake protocol

### External verifier intake custody

- Added a private-result intake and custody protocol to the external verifier
  packet.
- Updated public docs and generated coverage/proof-pack defaults from
  attestation-pending wording to the narrower
  `private_request_sent_public_attestation_not_claimed` boundary.
- Added guard coverage so stale "attestation pending" and "no completed
  attestation received" wording cannot re-enter current public packet docs or
  generated coverage/proof-pack outputs.

### Boundaries and non-claims

- This is documentation, generator-default, and guard work only. It does not
  name or publicly attribute any private verifier, publish a private verifier
  result, create public external attestation, claim independent attestation,
  inspect live/current-machine governance, prove production deployment, prove
  sovereign recognition, or cover unrouted surfaces.

## 3.3.51 — 2026-06-20 — Verifier status drift guard

### Verifier status drift guard

- Removed stale no-contact/prepared-only wording from the current external
  verifier packet.
- Updated repo agent instructions so future agents use the private-request-sent
  boundary instead of the old prepared/pending boundary.
- Updated governed-profile coverage and proof-pack generator defaults from
  `prepared_pending` to `private_request_sent_attestation_pending`.
- Added negative guard coverage for stale pre-contact verifier status in public
  docs and generated proof-pack outputs.

### Boundaries and non-claims

- This is documentation, generator-default, and guard work only. It does not
  name or publicly attribute the verifier, create completed external
  attestation, claim independent public attestation, change runtime enforcement
  behavior, inspect live/current-machine governance, prove production
  deployment, prove sovereign recognition, or cover unrouted surfaces.

## 3.3.50 — 2026-06-20 — Private verifier request boundary

### Private verifier request boundary

- Updated the external verifier packet state after Vincent authorized a
  private-by-default non-Vincent verifier request for `v3.3.49`.
- Clarified that no completed attestation has been received and any later
  result must be bounded by verifier relationship, disclosure permission, and
  exact evidence returned.
- Updated the packet guard so current docs cannot preserve stale no-contact
  wording after the request has been sent.

### Boundaries and non-claims

- This is documentation and claim-boundary guard work only. It does not name or
  publicly attribute the verifier, create completed external attestation, claim
  independent public attestation, change runtime behavior, change receipt schema
  or verifier behavior, inspect live/current-machine governance, prove
  production deployment, prove sovereign recognition, or cover unrouted
  surfaces.

## 3.3.49 — 2026-06-20 — External verifier packet

### External verifier packet

- Added `docs/external-verifier-packet.md` as a no-contact packet for a future
  non-operator verifier to check bounded public fixture evidence.
- Added `tests/test-external-verifier-packet.sh` so the packet keeps its
  prepared/pending status, preserves the exact verifier commands, and refuses
  completed-attestation language.
- Linked the packet from the README and clarified that external attestation
  remains pending until a non-operator verifier actually runs the packet and
  signs or publishes a bounded result.

### Boundaries and non-claims

- This is verifier-readiness documentation and claim-boundary guard work only.
  It does not contact a verifier, appoint a verifier, create external
  attestation, change runtime behavior, change receipt schema or verifier
  behavior, inspect live/current-machine governance, prove production
  deployment, prove sovereign recognition, or cover unrouted surfaces.

## 3.3.48 — 2026-06-20 — Receipt authority copy guard

### Receipt authority copy guard

- Added `tests/test-receipt-authority-copy.sh` as a public-copy guard for the
  log-versus-receipt authority boundary.
- The guard keeps the review-checklist invariant present and fails public docs
  that describe receipts as after-the-fact proof of what happened, agent
  history, agent intent, decision correctness, or log equivalence.
- Repaired stale README and doctrine wording so receipts are described as
  proof of what counted as authorized effect, not a reconstruction of what
  happened.

### Boundaries and non-claims

- This is public-copy and test-guard hardening only. It does not change runtime
  behavior, receipt schema, verifier behavior, proof fixtures, release
  evidence, live/current-machine governance, production deployment, external
  attestation, sovereign recognition, or coverage of unrouted surfaces.

## 3.3.47 — 2026-06-20 — Receipt authority boundary

### Receipt authority boundary

- Added the log-versus-receipt invariant to the README, trusted receipt issuer
  boundary, affected-person receipt guidance, and public-copy review checklist.
- Clarified that logs record event history while ZLAR receipts record what
  counted as authorized effect at the action boundary.
- Clarified that ZLAR does not reconstruct an agent's full history, intent,
  context, or reasoning after the fact.

### Boundaries and non-claims

- This is documentation and claim-boundary language only. It does not change
  runtime behavior, receipt schema, verifier behavior, proof fixtures, release
  evidence, live/current-machine governance, production deployment, external
  attestation, sovereign recognition, or coverage of unrouted surfaces.

## 3.3.46 — 2026-06-20 — Protected records runtime local activation proof

### Protected records runtime local activation proof

- Added `zlar protected-records-runtime-local-activation --plan <file|-> --profile <file|->`
  as an explicit local disposable runtime activation proof. It validates a
  pinned runtime-profile SHA, writes only launcher-owned disposable config
  inside the proof harness, starts local JSONL child service processes, accepts
  one recognized `records.write`, and refuses replay, missing, invalid, stale,
  wrong-scope, direct-API, and agent-supplied-authority requests before
  runtime-state mutation.
- Added portable local-activation artifacts with
  `--artifact <file|->`, `verify --input <file|->`, and `verify --sample`.
- Added the committed sample artifact at
  `tests/fixtures/protected-records-runtime-local-activation-artifact-v1.json`
  and tests for the local activation library and CLI.
- Tightened evaluator smoke wording so `proof-smoke` is clearly committed
  fixture verification, not fresh proof generation.

### Boundaries and non-claims

- This is local disposable runtime activation evidence only. It is not a
  persistent runtime-profile install, not hook configuration, not live
  current-machine governance, not live records-system evidence, not production
  service deployment, not external attestation, not sovereign recognition, and
  not coverage of unrouted surfaces.

## 3.3.45 — 2026-06-20 — Evaluator smoke quickstart

### Evaluator smoke quickstart

- Added a short evaluator smoke path to the README and CLI/coverage docs so a
  fresh reviewer can run the committed fixture smoke and sample verification
  commands without knowing fixture file paths.
- Named `bin/zlar proof-smoke`, `bin/zlar proof-smoke --json`,
  `bin/zlar proof-smoke verify --sample`, and
  `bin/zlar coverage --sample --require-governed` as the quick path.

### Boundaries and non-claims

- This is documentation only. It does not change runtime behavior, generate
  fresh proof-pack, service-profile preflight, or activation-preflight evidence,
  inspect live/current-machine state, prove production deployment, provide
  external attestation, prove sovereign recognition, or cover unrouted surfaces.

## 3.3.44 — 2026-06-20 — Coverage sample input path

### Coverage sample input path

- Added `zlar coverage --sample [--json] [--require-governed]` so the
  committed governed-surface coverage-map input fixture can be used without
  supplying `tests/fixtures/governed-surface-coverage-map-v1-input.json`.
- Updated `zlar proof-smoke` to call
  `zlar coverage --sample --require-governed` and record
  `zlar coverage --sample --require-governed --json` in the committed
  `zlar-proof-smoke-v1` report.
- Expanded coverage CLI tests for sample parity with explicit `--input`,
  `--require-governed` sample mode, missing-input refusal, and
  `--input`/`--sample` conflict refusal.

### Boundaries and non-claims

- This remains supplied/committed fixture-input coverage-map evidence only.
  It does not inspect live hooks, live audit stores, live machine state, live
  MCP coverage, production deployment, external attestation, sovereign
  recognition, or unrouted-surface coverage.

## 3.3.43 — 2026-06-20 — Proof-smoke sample report verifier

### Proof-smoke sample report verifier

- Added `zlar proof-smoke verify --sample [--json]` so evaluator tooling can
  verify the committed `zlar-proof-smoke-v1` sample report without knowing or
  supplying `tests/fixtures/proof-smoke-v1-report.json`.
- Kept `verify --sample` read-only: it validates the committed smoke report
  contract and does not rerun the smoke test, run the proof pack, regenerate
  service-profile preflight evidence, regenerate activation-preflight evidence,
  inspect live state, or create external attestation.
- Expanded proof-smoke CLI tests for sample verification, JSON parity with
  explicit `--input`, missing-input refusal, and `--input`/`--sample` conflict
  refusal.

### Boundaries and non-claims

- This remains committed local fixture smoke-report verification only. It does
  not create new evidence, inspect live/current-machine state, prove production
  authority, provide external attestation, prove sovereign recognition, or cover
  unrouted records paths.

## 3.3.42 — 2026-06-20 — Proof-smoke service preflight sample artifact

### Proof-smoke service preflight sample artifact

- Wired `zlar proof-smoke` directly into the committed service-profile preflight
  sample artifact by adding
  `zlar protected-records-service-preflight verify --sample --json` as a
  smoke-test step.
- Regenerated `tests/fixtures/proof-smoke-v1-report.json` so the committed
  smoke report now records local proof-pack sample verification, standalone
  service-profile preflight sample verification, activation-preflight sample
  verification, and fixture-input coverage verification.
- Expanded proof-smoke report and CLI tests for the four-step report contract
  and standalone service-profile preflight sample refusal on drift.

### Boundaries and non-claims

- This remains committed local fixture smoke evidence only.
- Proof smoke does not run the proof pack, generate fresh proof-pack evidence,
  generate fresh service-profile preflight evidence, generate fresh
  activation-preflight evidence, inspect live/current-machine state, prove live
  MCP coverage, prove live approval-channel health, provide external
  attestation, prove sovereign recognition, or cover unrouted records paths.

## 3.3.41 — 2026-06-20 — Service-profile preflight artifact

### Service-profile preflight artifact

- Added `--artifact <file|->` to
  `zlar protected-records-service-preflight` so the standalone service-profile
  preflight can emit a portable canonical JSON artifact with a SHA-256 over the
  canonical artifact body.
- Added `zlar protected-records-service-preflight verify --input <file|->` and
  `verify --sample` for read-only artifact verification without rerunning the
  preflight.
- Added a committed sample artifact at
  `tests/fixtures/protected-records-service-preflight-artifact-v1.json`.

### Boundaries and non-claims

- This is fixture artifact integrity and embedded local service-profile
  preflight-boundary verification only. It does not select `--latest`, inspect
  live/current-machine state, install or activate a profile, close direct
  filesystem writes to fixture paths, prove live MCP coverage, prove live
  approval-channel health, provide external attestation, prove sovereign
  recognition, or cover unrouted records paths.

## 3.3.40 — 2026-06-20 — Proof-smoke service preflight summary

### Proof-smoke service preflight summary

- Added a bounded service-profile preflight summary to
  `zlar local-proof-pack verify` results. The summary is derived from the
  verified local proof-pack artifact and records the executed service preflight
  type, fixture evidence model, case count, sanitized case summaries,
  direct-API-with-receipt refusal reason, zero state mutation, and no-live /
  no-production / no-external-attestation flags.
- Tightened `zlar proof-smoke` so its committed report contract requires that
  embedded service-profile preflight summary without rerunning the proof pack or
  generating fresh evidence.

### Boundaries and non-claims

- This is committed-artifact verification metadata only. It does not run a live
  deployment preflight, install or activate a runtime profile, inspect
  live/current-machine state, prove live MCP coverage, prove live
  approval-channel health, provide external attestation, prove sovereign
  recognition, or cover unrouted records paths.

## 3.3.39 — 2026-06-20 — Service-profile preflight proof-pack execution

### Local proof pack service-profile preflight execution

- Upgraded `zlar local-proof-pack` from service-profile preflight identity
  metadata to executed protected-records service-profile preflight evidence.
- The proof pack now records the service-profile preflight type, evidence
  model, case counts, refusal summary, no-live/no-production side-door flags,
  open boundaries, and non-claims.
- Updated local proof-pack and proof-smoke fixtures to bind the new proof-pack
  body.

### Boundaries and non-claims

- This remains local disposable fixture evidence only.
- It does not install or activate a runtime profile, write runtime or hook
  configuration, start a runtime service, inspect live/current-machine state,
  prove live MCP coverage, prove live approval-channel health, provide
  external attestation, prove sovereign recognition, or cover unrouted records
  paths.

## 3.3.38 — 2026-06-20 — Proof smoke activation sample coverage

### Proof smoke activation sample coverage

- Wired `zlar proof-smoke` into the committed activation-preflight sample
  artifact by adding
  `zlar protected-records-runtime-activation-preflight verify --sample --json`
  as a smoke-test step.
- Regenerated `tests/fixtures/proof-smoke-v1-report.json` so the committed
  smoke report now records local proof-pack sample verification, activation
  preflight sample verification, and fixture-input coverage verification.
- Expanded proof-smoke report and CLI tests for the three-step report contract
  and activation-preflight sample refusal on drift.

### Boundaries and non-claims

- This remains committed local fixture smoke evidence only.
- Proof smoke does not run the proof pack, generate fresh proof-pack evidence,
  generate fresh activation-preflight evidence, inspect live/current-machine
  state, prove live MCP coverage, prove live approval-channel health, provide
  external attestation, prove sovereign recognition, or cover unrouted records
  paths.

## 3.3.37 — 2026-06-20 — Sample activation preflight artifact

### Sample activation preflight artifact

- Added a committed sample activation-preflight artifact at
  `tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json`.
- Added `zlar protected-records-runtime-activation-preflight verify --sample`
  so the committed sample artifact can be verified without generating fresh
  local evidence.
- Expanded focused library and CLI coverage for sample artifact stability,
  `--sample` text/JSON verification, and `--input`/`--sample` conflict refusal.

### Boundaries and non-claims

- This remains local fixture evidence only.
- Sample verification checks artifact integrity and embedded preflight
  boundaries. It does not install or activate a runtime profile, write runtime
  or hook configuration, start a runtime service, inspect live/current-machine
  state, prove live MCP coverage, prove live approval-channel health, provide
  external attestation, prove sovereign recognition, or cover unrouted records
  paths.

## 3.3.36 — 2026-06-20 — Portable activation preflight artifacts

### Portable activation preflight artifacts

- Added `zlar protected-records-runtime-activation-preflight --artifact <file|->`
  to emit a portable canonical JSON artifact containing the explicit activation
  plan, runtime profile, and preflight report.
- Added `zlar protected-records-runtime-activation-preflight verify --input <file|-> [--json]`
  to verify artifact integrity and embedded activation-preflight boundaries
  without rerunning the preflight or selecting a live/current-machine runtime
  profile.
- Added focused library and CLI coverage for artifact writing, stdout artifact
  emission, stdin verification, checksum verification, and tamper refusal.

### Boundaries and non-claims

- This remains local fixture evidence only.
- Verification checks artifact integrity and embedded preflight boundaries. It
  does not install or activate a runtime profile, write runtime or hook
  configuration, start a runtime service, inspect live/current-machine state,
  prove live MCP coverage, prove live approval-channel health, provide external
  attestation, prove sovereign recognition, or cover unrouted records paths.

## 3.3.35 — 2026-06-19 — Runtime activation preflight proof-pack execution

### Runtime activation preflight proof-pack execution

- Upgraded `zlar local-proof-pack` from activation-plan identity metadata to an
  executed protected-records runtime activation-plan preflight component.
- The proof pack now runs the bounded runtime-profile preflight/proof under the
  explicit fixture activation plan and runtime profile, then records nested
  proof case counts, boundary counts, replay/rollback/deletion/replacement
  refusal, and agent-supplied authority-material refusal.
- Updated the committed local proof-pack artifact and proof-smoke report
  fixtures to bind the new proof-pack body hash.

### Boundaries and non-claims

- This remains local fixture evidence only.
- It does not install or activate a runtime profile, write runtime or hook
  configuration, start a runtime service, inspect live/current-machine state,
  prove live MCP coverage, prove live approval-channel health, provide external
  attestation, prove sovereign recognition, or cover unrouted records paths.

## 3.3.34 — 2026-06-19 — Protected records service refusal matrix

### Protected records downstream service recognition matrix

- Expanded the local disposable protected-records downstream-service proof and
  service-profile preflight to refuse invalid, unknown-issuer, and stale
  receipts before service-state mutation, in addition to existing replay,
  missing-receipt, detail-mismatch, and direct-API refusal cases.
- Wired the expanded downstream-service refusal matrix into
  `zlar local-proof-pack` and regenerated the committed local proof-pack
  artifact plus proof-smoke report fixtures.

### Boundaries and non-claims

- This remains local disposable fixture evidence only.
- It does not activate or install a runtime profile, inspect live records
  systems, prove production service deployment, close direct filesystem writes
  to supplied fixture paths, provide external attestation, prove sovereign
  recognition, or cover unrouted records paths.

## 3.3.33 — 2026-06-19 — Runtime activation proof-pack identity

### Local proof pack

- Wired runtime activation-plan preflight identity metadata into
  `zlar local-proof-pack` as a tenth metadata-only component.
- The proof pack now records the activation plan id/SHA, bound runtime-profile
  SHA, profile-SHA match, explicit install requirement, no activation applied,
  no runtime/hook config writes, no runtime-service start, no `--latest`
  selection, and open activation/live/current-machine boundaries.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the ten-component proof pack.

### Boundaries and non-claims

- This is activation-plan identity metadata inside the local proof pack only.
- It does not run the activation preflight, install or activate a persistent
  runtime profile, modify current-machine hooks/configuration, inspect live
  records systems, prove production service deployment, external attestation,
  sovereign recognition, or coverage of unrouted records paths.

## 3.3.32 — 2026-06-19 — Runtime activation preflight

### Runtime activation preflight

- Added `zlar protected-records-runtime-activation-preflight --plan <file|-> --profile <file|-> [--json]`
  and `profiles/protected-records-runtime-activation-plan.fixture.json`.
- The activation preflight validates that an explicit sample activation plan
  binds an explicit runtime-profile SHA, requires explicit human install, does
  not select `--latest`, and does not write runtime config, write hook config,
  start a runtime service, or install a runtime profile.
- The activation preflight runs the bounded runtime-profile preflight and
  reports profile-SHA match, runtime proof case count, rollback refusal, no
  activation applied, and open activation/live/current-machine boundaries.

### Boundaries and non-claims

- This is activation-plan preflight evidence only.
- It does not install or activate a persistent runtime profile, inspect live
  records systems, prove production service deployment, modify current-machine
  hooks/configuration, prove production-grade anti-rollback, exactly-once
  effects, external attestation, sovereign recognition, or coverage of
  unrouted records paths.

## 3.3.31 — 2026-06-19 — Runtime profile preflight and proof-pack identity

### Runtime profile preflight

- Added `zlar protected-records-runtime-profile-preflight --profile <file|-> [--json]`
  and `profiles/protected-records-runtime-fixture.profile.json`.
- The runtime profile preflight validates launcher-owned runtime authority
  and storage boundaries, then runs the existing local disposable runtime-profile
  proof under that profile contract.
- The preflight reports the profile SHA-256, proof case count, required
  boundary observations, consumed-store rollback/deletion/replacement refusal,
  and the residual store-plus-anchor rollback boundary.
- Wired the runtime profile preflight profile identity into `zlar local-proof-pack`
  as a ninth metadata-only component, without running the runtime preflight or
  disposable runtime-profile proof inside the proof pack.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the nine-component proof pack.

### Boundaries and non-claims

- The profile is `sample_not_active` and `runtime_profile_preflight_only`.
- The preflight does not install or activate a persistent runtime profile,
  inspect live records systems, prove production service deployment,
  production-grade anti-rollback, exactly-once effects, stale-lock recovery,
  multi-host coordination, tamper resistance, external attestation, sovereign
  recognition, or coverage of unrouted records paths.

## 3.3.30 — 2026-06-19 — Runtime profile local anti-rollback anchor

### Runtime profile local anti-rollback anchor

- Added a launcher-owned local consumed-store anchor to the disposable
  protected-records runtime profile. The anchor commits to the canonical
  consumed-receipt store and is supplied by config outside the agent JSONL
  request stream.
- The runtime service now refuses recognized writes before mutation when the
  consumed store is rolled back, deleted, or replaced while the local anchor
  remains current.
- Invalid local anchor shape is refused before runtime-state mutation.
- Requests that try to supply a consumed-store anchor path are refused as
  agent-supplied authority material before runtime-state mutation.
- The proof now preserves the remaining boundary explicitly: if the consumed
  store and local anchor are rolled back, deleted, or replaced together to a
  matching earlier state, this local proof does not detect it without stronger
  custody or an external witness.

### Boundaries and non-claims

- This remains local disposable runtime-profile evidence only.
- It does not prove production-grade durable storage, stale-lock recovery,
  multi-host coordination, tamper resistance, production-grade anti-rollback,
  or exactly-once effect semantics.
- It does not install a persistent runtime profile, inspect a live records
  system, prove a production records service, close host side doors, prove
  live MCP/current-machine governance, or provide external attestation.

## 3.3.29 — 2026-06-19 — Runtime profile consumed-store hardening

### Runtime profile consumed-store hardening

- Hardened the local disposable protected-records runtime-profile consumed
  store with exact schema validation, duplicate receipt-id refusal, a
  launcher-owned per-store lockfile, and temp-file/fsync/rename replacement
  before runtime-state mutation.
- Added proof cases for invalid consumed stores, duplicate consumed stores,
  and pre-existing consumed-store locks; each refuses before runtime-state
  mutation.
- Added boundary observations for the two remaining storage truths: the proof
  is at-most-once receipt consumption rather than exactly-once effect
  semantics, and a valid rollback/deletion/replacement of the consumed store
  can reopen replay because this local proof does not implement anti-rollback
  or tamper-resistant storage.

### Boundaries and non-claims

- This remains local disposable runtime-profile evidence only.
- It does not prove production-grade durable storage, stale-lock recovery,
  multi-host coordination, tamper resistance, anti-rollback protection, or
  exactly-once effect semantics.
- It does not install a persistent runtime profile, inspect a live records
  system, prove a production records service, close host side doors, prove
  live MCP/current-machine governance, or provide external attestation.

## 3.3.28 — 2026-06-19 — Runtime profile persistent replay proof

### What changes

- Extended `zlar protected-records-runtime-service --config <file>` so the
  launcher-supplied config owns a persistent consumed-receipt store path outside
  the JSONL request stream.
- Proved replay of the accepted runtime `records.write` receipt refuses after a
  fresh service process restart by reusing that launcher-owned
  consumed-receipt store.
- Kept process-private runtime state and agent request authority separate:
  requests still cannot supply state paths, consumed-receipt paths, recognition
  rules, fixture mode, or unsupported fields.
- Updated runtime-profile validation, CLI tests, README, CLI reference, and
  governed-surface coverage docs for the new replay-store boundary.

### Boundaries and non-claims

- This is still a local disposable runtime-profile proof, not production
  deployment.
- It does not inspect a live records system.
- It does not install a persistent runtime profile.
- It does not prove a production records service.
- It does not prove production-grade durable storage, concurrency hardening, or
  tamper resistance for the consumed-receipt store.
- It does not close host process, memory, debugger, or operator filesystem side
  doors.
- It does not prove live MCP coverage, current-machine governance, external
  attestation, enterprise readiness, production authority, or sovereign
  recognition.
- It does not prove coverage of unrouted records paths.

## 3.3.27 — 2026-06-19 — Protected records disposable runtime profile proof

### What changes

- Added `zlar protected-records-runtime-service --config <file>`, a local
  disposable JSONL child service for protected-records runtime requests.
- Added `zlar protected-records-runtime-profile-proof [--json]`, which
  exercises that service with process-private state and a launcher-supplied
  recognition rule carried outside the request stream.
- Proved one recognized `records.write` mutates runtime state once, replay of
  that receipt refuses in the same service process, unrecognized receipt
  variants refuse before mutation, direct API attempts refuse before mutation,
  and agent-supplied state-path, recognition-rule, or unsupported-field
  attempts refuse before mutation.
- Added unit and CLI tests for the runtime profile proof, service JSONL
  contract, privacy-safe output, and fail-closed claim-boundary validation.

### Boundaries and non-claims

- This is a local disposable runtime-profile proof, not production deployment.
- It does not inspect a live records system.
- It does not install a persistent runtime profile.
- It does not prove a production records service.
- It does not prove replay refusal across service restarts or a persistent
  consumed-receipt store.
- It does not close host process, memory, debugger, or operator filesystem side
  doors.
- It does not prove live MCP coverage, current-machine governance, external
  attestation, enterprise readiness, production authority, or sovereign
  recognition.
- It does not prove coverage of unrouted records paths.

## 3.3.26 — 2026-06-19 — Protected records service profile preflight

### What changes

- Added `profiles/protected-records-service-fixture.profile.json`, a
  machine-readable sample deployable preflight profile for the local fixture
  protected-records downstream service.
- Added `zlar protected-records-service-preflight --profile <file|-> [--json]`
  to validate that profile and exercise the configured local fixture service
  path through disposable CLI-process boundaries.
- Added the service preflight profile id/SHA/status to the existing
  protected-records downstream-service proof-pack component without adding or
  running a ninth proof-pack component.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the profile identity metadata.
- Proved recognized write, replay refusal, missing receipt refusal,
  unrecognized receipt refusal, fixture service API without-receipt refusal,
  and contradictory direct-API-with-receipt refusal before service-state
  mutation.

### Boundaries and non-claims

- The profile is not installed or activated as a runtime profile.
- No live probing is performed.
- No live records system is inspected.
- No production records service is claimed.
- Direct filesystem writes to supplied fixture paths are not closed.
- No live MCP coverage, current-machine governance, external attestation,
  enterprise readiness, production authority, or sovereign recognition is
  claimed.

## 3.3.25 — 2026-06-19 — Protected records downstream service proof

This release packages the remote-green mainline protected-records downstream
service proof after v3.3.24 while keeping the release claim bounded to local
disposable fixture evidence.

### What changes

- Added `zlar protected-records-service-request --input <file|->`, a local
  fixture downstream service request path for protected records.
- Added `zlar protected-records-service-proof`, a local disposable
  CLI-process proof for the downstream service boundary.
- Proved a recognized receipt mutates bounded service state exactly once.
- Proved replay of that same receipt refuses across a fresh CLI process using
  the persistent consumed-receipt store.
- Proved missing and unrecognized receipts refuse before service-state
  mutation.
- Proved a fixture service API write attempt without a receipt refuses before
  mutation.
- Added adversarial coverage for state-path write failure, sanitized CLI
  stderr, and contradictory fixture service API inputs that try to carry a
  receipt into the without-receipt refusal case.
- Hardened verifier-kit README assertions against macOS `pipefail` /
  `grep -q` broken-pipe false negatives.
- Wired the downstream-service proof into the local proof pack as the eighth
  component.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the eight-component proof pack.
- Updated README, CLI reference, governed-surface coverage docs, and trusted
  receipt issuer docs to describe the service boundary without claiming live
  deployment.

### Boundaries and non-claims

- No live probing is performed.
- No live records system is inspected.
- No production records service is claimed.
- Direct filesystem writes to supplied fixture paths are not closed by this
  proof.
- No live MCP coverage is claimed.
- No live Telegram approval-channel delivery or health is claimed.
- No current-machine governance proof is claimed.
- No external attestation, enterprise readiness, production authority, or
  sovereign recognition is claimed.
- No coverage of unrouted records paths or unrouted surfaces is claimed.

## 3.3.24 — 2026-06-19 — Protected records adapter conformance

This release packages the remote-green mainline protected-records adapter
CLI-process conformance proof after v3.3.23 while keeping the release claim
bounded to local disposable fixture evidence.

### What changes

- Added `zlar protected-records-adapter-conformance`, a local disposable
  CLI-process conformance proof for `zlar protected-records-write`.
- Proved a recognized receipt appends exactly once through a separate CLI
  process.
- Proved replay of that same receipt refuses across a fresh CLI process using
  the persistent consumed-receipt store.
- Proved a missing receipt refuses before append.
- Proved an unsupported direct-write adapter option exits nonzero and does not
  append.
- Wired the conformance proof into the local proof pack as the seventh
  component.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the seven-component proof pack.
- Updated README, CLI reference, governed-surface coverage docs, and trusted
  receipt issuer docs to describe the conformance boundary without claiming
  live deployment.

### Boundaries and non-claims

- No live probing is performed.
- No live records system is inspected.
- No production records adapter is claimed.
- Direct filesystem writes to supplied fixture paths are not closed by this
  proof.
- No live MCP coverage is claimed.
- No live Telegram approval-channel delivery or health is claimed.
- No current-machine governance proof is claimed.
- No external attestation, enterprise readiness, production authority, or
  sovereign recognition is claimed.
- No coverage of unrouted records paths or unrouted surfaces is claimed.

## 3.3.23 — 2026-06-19 — Local protected records write adapter

This release packages the remote-green mainline local protected-records write
adapter command after v3.3.22 while keeping the release claim bounded to local
fixture evidence.

### What changes

- Added `zlar protected-records-write --input <file|->`, a callable local
  fixture protected-records action adapter.
- Required supplied `fixture_mode: true`, signed receipt, recognition rule,
  write detail, ledger path, and consumed-receipt-store path.
- Computed the canonical write-detail hash and required that hash during
  downstream recognition.
- Refused missing, invalid, stale, wrong-policy, wrong-domain, wrong-tool,
  wrong-detail, non-boarding, unknown/retired issuer, and replayed receipts
  before appending to the fixture ledger.
- Persisted consumed receipt ids and appended exactly one bounded JSONL ledger
  entry only after recognition.
- Refactored the protected-records terminal proof to use the same adapter module
  and carried the callable adapter action boundary into the local proof-pack
  component.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the new adapter action boundary.
- Updated README, CLI reference, governed-surface coverage docs, and trusted
  receipt issuer docs to describe the adapter command without claiming live
  deployment.

### Boundaries and non-claims

- No live probing is performed.
- No live records system is inspected.
- No production records adapter is claimed.
- No live MCP coverage is claimed.
- No live Telegram approval-channel delivery or health is claimed.
- No current-machine governance proof is claimed.
- No external attestation, enterprise readiness, production authority, or
  sovereign recognition is claimed.
- No coverage of unrouted records paths or unrouted surfaces is claimed.

## 3.3.22 — 2026-06-19 — Protected records adapter profile

This release packages the remote-green mainline protected-records adapter
profile evidence after v3.3.21 while keeping the release claim bounded to local
fixture evidence.

### What changes

- Exposed a local fixture protected-records adapter profile inside
  `zlar protected-records-proof`.
- Named the adapter profile type, adapter boundary, authoritative route,
  append-only fixture ledger model, consumed-receipt store, and per-adapter
  replay scope.
- Added adapter-harness evidence that all fixture mutations pass through the
  recognition boundary, direct fixture ledger writes are closed in the harness,
  and no live records adapter is claimed.
- Carried the adapter-profile fields into the local proof-pack component and
  regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures.
- Added fail-closed validation and CLI coverage for adapter-profile drift,
  direct-write path reopening, and live-adapter claim drift.
- Updated README, CLI reference, governed-surface coverage docs, and trusted
  receipt issuer docs to describe the adapter-profile boundary without claiming
  live deployment.

### Boundaries and non-claims

- No live probing is performed.
- No live records system is inspected.
- No production records adapter is claimed.
- No live MCP coverage is claimed.
- No live Telegram approval-channel delivery or health is claimed.
- No current-machine governance proof is claimed.
- No external attestation, enterprise readiness, production authority, or
  sovereign recognition is claimed.
- No coverage of unrouted records paths or unrouted surfaces is claimed.

## 3.3.21 — 2026-06-19 — Protected records replay refusal

This release packages the remote-green mainline protected-records
receipt-replay refusal hardening after v3.3.20 while keeping the release claim
bounded to local fixture evidence.

### What changes

- Added terminal-side replay refusal to the local protected-records
  `records.write` profile: one recognized receipt writes once, and replay of
  that same receipt id refuses before the protected record changes.
- Captured the protected-records replay policy in the profile contract and
  local proof-pack component.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the replay-refusal evidence.
- Updated README, CLI reference, governed-surface coverage docs, and trusted
  receipt issuer docs to preserve the boundary between verifier validity and
  terminal-side replay policy.

### Boundaries and non-claims

- No live probing is performed.
- No live records system is inspected.
- No production records adapter is claimed.
- No live MCP coverage is claimed.
- No live Telegram approval-channel delivery or health is claimed.
- No current-machine governance proof is claimed.
- No external attestation, enterprise readiness, production authority, or
  sovereign recognition is claimed.

## 3.3.20 — 2026-06-19 — Protected records profile contract

This release packages the remote-green mainline protected-records terminal
profile visibility and profile-contract work after v3.3.19 while keeping the
release claim bounded to local fixture evidence.

### What changes

- Exposed the protected-records terminal proof's deployment profile, action
  class, downstream boundary, accepted/refused write counts, refusal deltas,
  and known ungoverned boundaries inside the local proof-pack artifact.
- Added an explicit protected-records profile contract for one local
  `records.write` terminal.
- Captured the recognition checkpoint route
  `receipt-recognition-before-record-write`, checkpoint
  `downstream-recognition-rule`, and downstream effect
  `append-protected-records-ledger-entry`.
- Captured the canonical v1 receipt envelope and payload fields required by
  the protected-records profile contract.
- Captured accepted issuer status, policy version, domain, tool, and outcome
  boundaries for the fixture profile.
- Made the protected-records proof and local proof pack fail closed if the
  profile contract or required receipt fields drift.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the profile-contract evidence.
- Updated README, CLI reference, and governed-surface coverage docs for the
  profile-contract boundary.

### Boundaries and non-claims

- No live probing is performed.
- No live records system is inspected.
- No production records adapter is claimed.
- No live MCP coverage is claimed.
- No live Telegram approval-channel delivery or health is claimed.
- No current-machine governance proof is claimed.
- No production authority is claimed.
- No enterprise readiness is claimed.
- No external attestation is claimed.
- No sovereign recognition is claimed.
- No coverage of unrouted surfaces is claimed.

### Verification

- Release-prep verification should include protected-records proof tests and
  CLI tests, local proof-pack sample artifact verification with six components,
  proof-smoke JSON/report verification, receipt vector verification, verifier
  kit tests, and `git diff --check`.

## 3.3.19 — 2026-06-19 — Channel-neutral approval transport proof

This release packages the remote-green mainline approval-transport proof work
after v3.3.18 while keeping the release claim bounded to local fixture
evidence.

### What changes

- Added `zlar approval-transport-proof`, a local hermetic proof that models
  human approval delivery as a replaceable transport boundary.
- Demonstrated that unavailable approval transport fails closed before
  boarding.
- Demonstrated that a delivered ask without a signed human decision receipt
  still refuses before boarding.
- Demonstrated that a delivered ask with a signed human decision receipt
  boards through downstream recognition.
- Recorded Telegram as an optional adapter that is not required by the local
  fixture proof path.
- Wired the approval-transport proof into `zlar local-proof-pack` as the sixth
  component.
- Regenerated the committed local proof-pack artifact and proof-smoke report
  fixtures for the six-component proof pack.
- Updated README and CLI reference documentation for the new command and its
  claim boundary.

### Boundaries and non-claims

- No live probing is performed.
- No live Telegram approval-channel delivery is claimed.
- No live Telegram health is claimed.
- No live approval-channel runtime configuration is claimed.
- No production approval transport is claimed configured, healthy, or secure.
- No live machine coverage is claimed.
- No live MCP coverage is claimed.
- No production authority is claimed.
- No enterprise readiness is claimed.
- No external attestation is claimed.
- No sovereign recognition is claimed.
- No coverage of unrouted surfaces is claimed.

### Verification

- Release-prep verification should include `zlar approval-transport-proof`,
  approval-transport unit and CLI tests, local proof-pack sample artifact
  verification with six components, proof-smoke JSON/report verification,
  receipt vector verification, and `git diff --check`.

## 3.3.18 — 2026-06-19 — Local proof pack and issuer recognition boundary

This release packages the remote-green mainline local proof-pack and
downstream recognition work after v3.3.17 while keeping the release claim
bounded to local fixture evidence.

### What changes

- Added Bash and MCP coverage evidence assemblers for supplied fixture input.
- Added a downstream receipt recognition rule and CLI for evaluating supplied
  signed v1 receipts against one configured recognition rule.
- Bound downstream refusal evidence into the Governed Surface Coverage Map.
- Added hermetic downstream refusal and protected-records terminal proofs.
- Added `zlar local-proof-pack`, a portable proof-pack artifact writer,
  artifact verification, and a committed sample artifact.
- Added `zlar proof-smoke`, proof-smoke JSON output, and a committed
  proof-smoke report verifier.
- Added a simulated-human authorization proof component.
- Added issuer-status proof evidence for active, retired, unknown,
  key-missing, and explicit missing-status issuer cases.
- Documented the trusted receipt issuer boundary: receipt verification is not
  issuer recognition, custody proof, revocation status, downstream acceptance,
  or production authority.
- Hardened supporting diagnostics for Codex hook reality, audit append locking,
  doctor signing-key checks, bash 3.2 compatibility, and timing-sensitive
  human-invariant fixtures.

### Boundaries and non-claims

- No live probing is performed.
- No live machine coverage is claimed.
- No live MCP coverage is claimed.
- No live Telegram approval-channel delivery is claimed.
- No live trust registry is claimed.
- No live key custody, rotation, revocation infrastructure, or compromise
  response proof is claimed.
- No production authority is claimed.
- No enterprise readiness is claimed.
- No external attestation is claimed.
- No sovereign recognition is claimed.
- No coverage of unrouted surfaces is claimed.
- Historical corrupted audit lines are not repaired by this release.

### Verification

- Release-prep verification should include the local proof-pack sample artifact
  verification, proof-smoke JSON/report verification, downstream recognition
  unit and CLI tests, issuer-status proof tests, governed-surface coverage map
  tests, protected-records proof tests, receipt vector verification, verifier
  kit tests, all `.mjs` tests, and `git diff --check`.

## 3.3.17 — 2026-06-17 — Fixture-input coverage map

This release packages the remote-green mainline Governed Surface Coverage Map
work after v3.3.16 while keeping the release claim bounded to supplied evidence.

### What changes

- Added a fixture/report-input Governed Surface Coverage Map exposed through
  `zlar coverage`.
- The coverage map classifies supplied evidence for defined routed
  action-surface lanes.
- Counted lanes fail closed unless routing, heartbeat freshness, policy
  currency, Worker Receipt capability, and downstream refusal evidence are all
  present.
- Added a sanitized example fixture and core documentation for reproducing the
  fixture-input coverage map behavior.
- Added CLI reference coverage for `zlar coverage`, including summary, JSON,
  and `--require-governed` usage.
- Aligned the README test badge and current test-count line with the current
  sequential assertion-count evidence.

### Boundaries and non-claims

- No live probing is performed.
- No live machine coverage is claimed.
- No coverage of unrouted surfaces is claimed.
- No enterprise readiness is claimed.
- No external attestation is claimed.
- No production authority is claimed.
- No sovereign recognition is claimed.

### Verification

- Release-prep verification should include the fixture-input coverage command,
  coverage-map unit and CLI tests, governed-profile coverage reporting, Worker
  Receipt tests, sequential assertion counting and badge generation, and `git
  diff --check`.

## 3.3.16 — 2026-05-15 — Stabilization entrypoint fixes

This release packages the post-v3.3.15 stabilization entrypoint fixes for
the public install and quickstart paths.

### What changes

- Removed the stale installer fallback that could stamp version 3.0.0 when
  `VERSION` was unavailable.
- Preserved local source, versioned release tarball, and GitHub clone
  fallback behavior while deriving the installed version from the selected
  source.
- The installer now fails closed when no source `VERSION` can be determined.
- Quickstart now treats expected denies as JSON `deny` plus exit code 2 for
  clean DENY output while preserving failure detection.
- Added a focused stabilization regression test.

### Boundaries and non-claims

- No public claim boundary changes.
- No website content changes.
- No verifier, receipt, routed-MCP, or policy semantics are widened by this
  release.

### Verification

- Release-prep verification should include public privacy, stabilization
  script regression checks, quickstart receipt verification, and `git diff
  --check`.

## 3.3.15 — 2026-05-14 — Routed MCP proof packaging

This release packages the post-v3.3.14 routed-MCP proof stack while keeping
the same public claim boundary: ZLAR governs only actions that actually pass
through its routed/intercepted gate surfaces. Safe Codex wording remains:
"ZLAR can govern Codex CLI-invoked MCP tool calls when those MCP servers are
routed through ZLAR."

### What changes

- Added an isolated Codex MCP profile smoke harness that uses scratch
  `HOME`/`CODEX_HOME` state and bounded routed-MCP claim language.
- Hardened isolated profile checks against direct upstream MCP registration,
  extra MCP registration, unsafe scratch overrides, and symlink/path
  traversal.
- Added a reusable routed-MCP proof harness that exercises a local
  client-to-ZLAR-MCP-gate-to-fake-upstream path with fake inputs only.
- Worker Receipt `/why` now shows the action detail hash for governed
  receipt evidence without exposing raw action contents.
- Added a Verifier Kit external-runner flow with prepared runner
  instructions, a result template, a dry-run helper, and privacy-safe
  handoff tests.
- Added Governed Profile Coverage Report v0 for conservative coverage
  reporting over the isolated Codex routed-MCP profile.
- Wired the `coverage-report` command into the Codex smoke harness.
- Added Proof Pack Packaging v0 to package existing
  coverage/report/receipt/verifier evidence into a local manifest and README
  while summarizing or hashing optional evidence.

### Boundaries and non-claims

- Unrouted client surfaces remain outside this evidence path.
- Direct non-routed shell, filesystem, browser, app, network,
  model-reasoning, and final-text surfaces are not claimed as governed by
  this release.
- Direct MCP registrations that bypass the ZLAR route remain outside this
  evidence path.
- `/contest` is not implemented.
- External non-Vincent verifier attestation remains prepared/pending.
- Public website claims are unchanged.

### Verification

- GitHub CI, CodeQL, and OpenSSF Scorecard are green for the release-prep
  base commit.
- Local release-prep verification should include Proof Pack Packaging v0,
  governed profile coverage reporting, routed-MCP proof, Codex profile
  harness coverage, MCP Worker Receipt, public privacy, and `git diff
  --check`.

## 3.3.14 — 2026-05-14 — Post-release hardening

This release candidate packages the local hardening work that landed after
v3.3.13. It keeps the same public claim boundary: ZLAR governs only
actions that actually pass through its routed/intercepted gate surfaces.

### What changes

- Public privacy fixtures now use scrubbed placeholder identifiers, keeping
  regression coverage without carrying realistic chat, user, or token-like
  values.
- The broad assertion-count suite now keeps agent identity export and hook
  contract checks hermetic, so local developer environment and manifest state
  do not leak into the regression result.
- MCP terminal outcomes now clean up pending ask state, preventing stale
  pending entries after final allow, deny, authorized, denied, or timeout
  decisions.
- MCP Telegram ask cards now avoid raw argument leakage, tighten
  MarkdownV2 escaping, and keep denial cards easy to distinguish while
  preserving the routed MCP decision flow.
- Telegram dispatcher boot configuration is now plumbed through the
  generated service wrapper, keeping poller runtime configuration aligned
  with source-controlled defaults.

### What does NOT change

- No broad Codex, client, or agent governance claim is added.
- Unrouted MCP connections, direct shell/network paths outside the gate, and
  other unobserved actions remain outside this evidence path.
- Public website claims are unchanged.
- Governed Action Receipt signing semantics and Worker Receipt semantics are
  not widened by this release candidate.

### Verification

- Local release-candidate verification should include the broad assertion
  suite, public privacy guard, MCP adapter/stdio/live harness tests,
  Telegram bootstrap/config/doctor tests, Worker Receipt tests, and
  `git diff --check`.

## 3.3.13 — 2026-05-13 — Worker Receipt /why for routed MCP

This release extends Worker Receipt + `/why` from the bash gate path to
routed MCP `tools/call` events, while preserving the existing claim
boundary: ZLAR covers actions that actually pass through its gates. It
also includes the MCP routing hardening and ask-card clarity work that
landed after 3.3.12.

### What changes

- MCP callback inbox bootstrap now creates the MCP callback inbox during
  source bootstrap/install, so Telegram MCP approvals survive normal boot
  paths rather than depending on one-time local repair.
- MCP Telegram ask cards distinguish deny-intended asks from normal asks,
  making approve/deny intent easier to inspect before tapping.
- Worker Receipt + `/why` v0.1 now covers governed bash-gate events and
  routed MCP `tools/call` events.
- The MCP gate emits Worker Receipts after successful audit append for
  eligible final MCP decisions: `allow`, `deny`, `authorized`, `denied`,
  and future literal `timeout`.
- MCP Worker Receipts use `surface: mcp-gate`, `action.class: MCP tool
  call`, and a summary of `MCP tool: <tool>`. Raw MCP args are not printed;
  detail remains represented by hash.
- `/why` reads a mixed bash + MCP Worker Receipt store by exact event id.
- Worker Receipt emission remains additive: failures log a warning and do
  not change the already-computed governance decision.

### What does NOT change

- No broad Codex governance claim. ZLAR does not claim to govern all Codex
  actions or all agent actions.
- Unrouted MCP connections, shell/network paths outside the gate, and other
  unobserved actions remain outside this evidence path.
- `/contest` and worker self-service contestability are still not
  implemented.
- Public website claims are unchanged.
- Governed Action Receipt signing and audit semantics are not widened by
  this Worker Receipt side channel.
- Verifier Kit external-runner material remains private/readied; no
  external attestation has completed.

### Verification

- CI, CodeQL, and OpenSSF Scorecard are green for the release head.
- Codex CLI MCP routed through ZLAR has been proven in harness, and the
  real Telegram MCP approve/deny smoke passed.
- Isolated bash Worker Receipt smoke passed.
- Isolated MCP Worker Receipt smoke passed; it proved `surface: mcp-gate`,
  `action.class: MCP tool call`, tool-name summary, redaction of raw MCP
  args/fake secret/private path, and no Worker Receipt for operational
  gate-start audit rows.
- Regression coverage includes Worker Receipt contract tests, bash live-ish
  emission tests, MCP adapter conformance, stdio conformance, and receipt
  verification tests.

## 3.3.12 — 2026-05-12 — Hook Contract Hardening

Belt-and-suspenders alignment with the documented Claude Code PreToolUse
contract. Anthropic's HackerOne disposition (CLOSED — INFORMATIVE,
2026-05-12) clarified that PreToolUse hooks treat exit code 2 OR exit 0
with documented JSON deny output as blocking; any other non-zero exit is
a non-blocking error. ZLAR's response helpers already emitted the
documented JSON form on exit 0, which Claude Code was honoring as
blocking. This release adds exit 2 on every intended-block path so both
signals travel together. Either alone suffices per the contract; both
together remove a class of latent fragility from `set -e` and ERR-trap
interactions.

### What changes

- `_gate_crash` ERR trap, `~/.claude/.gate-locked` deny path, and the
  wrapper's missing-binary fail-closed all switch from `exit 0` to
  `exit 2`. JSON deny output on these paths is unchanged.
- `respond_deny` and `respond_subagent_deny` set a new `_GATE_EXIT_CODE`
  process-level flag to 2 after emitting JSON deny. The script's final
  line — added after `main` returns — reads the flag and exits with that
  code. Default is 0 (allow / non-blocking), so allow paths and the
  sandbox `updatedInput` allow are unchanged.
- The wrapper at `~/.claude/zlar-gate.sh` is regenerated by
  `adapters/claude-code/install.sh` from the updated source.

### What does NOT change

- JSON output bytes on every path. Existing `hookSpecificOutput`
  `permissionDecision` / `permissionDecisionReason` shape is preserved.
- Audit emission order (`emit_event` still fires before each `respond_*`).
- Path B seal + Agent Health restore-trigger blocks still execute on every
  non-early-exit path before the final exit.
- The off-flag allow path at `/etc/zlar/off-flag` still exits 0. The human
  override is the wide-allow / maintenance-mode path; exit 0 is correct.
- Cached approve / cached deny / pending / `ask_pending_retry` semantics.

### Testability env overrides

Three env-fallbacks added for the new process-level test isolation:
`ZLAR_AUDIT_FILE`, `ZLAR_APPROVAL_DIR`, `ZLAR_INBOX_DIR`. Production
defaults unchanged when env unset.

### Regression coverage

New `tests/test-hook-contract.sh` drives `bin/zlar-gate` as a subprocess
with isolated audit/approval/inbox fixtures and a PATH-shim curl for
Telegram. Asserts both `exit 2` and JSON `permissionDecision: deny` on
deterministic-deny scenarios (TC1 Bash sudo, TC2 Edit on enforcement
path); `exit 0` and JSON allow on the internal fast-path (TC3
TodoWrite). 14 assertions. Skips loud when `/etc/zlar/off-flag` is
present so the test doesn't pass spuriously under gate-off.

Live-harness verification (does Claude Code actually surface the JSON
reason when both signals are present?) was performed manually as part
of the R041 ceremony on 2026-05-12 UTC. Result: Claude Code's blocking
error contains the JSON `permissionDecisionReason` text verbatim — both
signals are honored together. Identical surfacing shape to the prior
exit-0 + JSON behavior.

### What this release explicitly does NOT claim

- Not a fix. The prior JSON-deny-on-exit-0 form was already blocking per
  Anthropic's documented contract. This is contract hardening — a second
  independent signal — not a correction of broken behavior.
- Not a security release. Per the HackerOne disposition (Informative /
  working as designed), there was no Claude Code vulnerability and no
  ZLAR vulnerability. This is developer-tooling design cleanup.
- Not a public claim broadening. Existing public copy did not assert
  retry-enforcement properties that this patch would suddenly make true;
  no public claims change.

## 3.3.11 — 2026-05-09 — Bounded Recovery Opportunity (forced canary ceiling)

The probability gate is unbounded. A long string of dice misses, or any future
trigger-path bug like the v3.3.7→v3.3.10 float-arith drought, produces invisible
friction with no recovery opportunity. Vincent acted on roughly 180 Telegram
asks since the last canary during the v3.3.7 bug window. That cost was paid out
of the human's labor, not the system's account. v3.3.11 caps that ceiling.

### Doctrine

After `min_approvals_before_trigger` is reached, roll probability normally. If
the drought counter reaches `max_approvals_before_forced_canary`, bypass the
probability gate and force a canary attempt. The system cannot pay its own
trigger failures out of the human's labor indefinitely. D2 axiom:
friction(h, t) ⟹ Evidence(h, t).

This does NOT guarantee promotion. It guarantees timely opportunity to
demonstrate recovery.

### What force bypasses, what force respects

Force bypasses ONLY the probability dice. Every structural eligibility check
remains binding — those are integrity, not luck:

- pending_held — one canary in flight at a time (D1 invariant; force defers).
- cooldown_active — minimum elapsed time since last canary (300s default).
- cooldown_eval_error — sentinel. Never force into a broken state machine.
- chat_id validation — refuses misdelivery; downstream in canary_send.

Misconfig handling: `max_approvals_before_forced_canary = 0` (default) disables
force entirely, preserving v3.3.10 behavior. `max <= min_approvals_before_trigger`
is silently a no-op (probability gate fires below max anyway, force is unreachable).

### Trigger reason in audit and artifact_payload

Force fires emit a single `canary_forced_trigger` info-severity audit event
with `{human_id, approvals_since_last, ceiling, reason: "forced_drought_ceiling"}`.
Probability fires do not emit per-call audit (already covered by canary_send and
the eventual canary_result event).

`canary_send` threads the trigger reason into `artifact_payload` (alongside
canary_id, human_id, session_id) before HMAC. A tampered "forced → probability"
relabel — which would let an attacker hide the system's accumulated debt to the
human — invalidates the claim hash. Default `"probability"` preserves the
v3.3.10 hash shape on legacy callers that did not set the marker.

Post-hoc calibration must filter forced canaries — they are not iid samples. The `trigger_reason` field in the audit
chain makes that filter possible.

### Status display

`bin/zlar status` Canary Subsystem block extended with two lines (only shown
when `max_approvals_before_forced_canary > 0`):

```
forced canary ceiling:                     25 approvals
next forced canary:                        in 19 approvals
```

Past the ceiling, the second line shows `eligible now` rather than a negative
remaining count. The system never displays the human owing it more friction.

### Threshold value

`max_approvals_before_forced_canary = 25` is the Vincent's-box default. With
`probability = 20%` and `min_approvals = 5`, force fires on roughly 1.2% of
healthy streaks (`0.8^20`); 98.8% of canaries fire by probability. Force is
unobtrusive in the healthy case and a hard ceiling in the broken case.

Recalibration is required for non-developer environments. Current 25 is a prior, not a posterior.

### `canary_load_config` set-e fragility removed

This release also normalizes every optional-key read in `canary_load_config`
from `[ -n "$_v" ] && X="$_v"` shorthand to explicit `if` blocks, plus a
trailing `return 0`. The shorthand returns the test's exit code (1 when the
key is absent), and bash `set -e` propagates that out of the function — fatal
to gate hooks that source this file.

The bug surfaced during this build: adding the new optional
`max_approvals_before_forced_canary` key as the function's last expression
crashed the gate hook on every invocation until the gate was disabled and the
fix landed. Pre-v3.3.11 the same pattern was latently safe only because every
key happened to be present on the maintainer's gate.json. Future-author proof.

### Files

- `lib/canary.sh` — force check in `canary_should_trigger`, trigger_reason in
  `canary_send` artifact_payload, all `canary_load_config` reads normalized,
  trailing `return 0`. New env override `ZLAR_CANARY_MAX_APPROVALS_FORCE`.
- `bin/zlar` — status block extended with ceiling + remaining-or-eligible-now.
- `tests/test-canary.sh` — TC-31..35 (12 new assertions: force fires at
  ceiling / below ceiling falls through / pending_held blocks / cooldown blocks /
  MAX_FORCE=0 backward-compat).
- `etc/gate.json` — `.canary.max_approvals_before_forced_canary: 25`
  (gitignored; operator config; not in this commit).
- `VERSION` — 3.3.10 → 3.3.11.

### Tests

81/81 in test-canary (was 69, +12 new). Full suite green:
test-human-invariants 136/136, test-status-display 12/12, test-gate-uptime
29/29, test-telegram-config 25/25, test-perimeter-closure 111/111 (one-off
transient on first run, stable on retry per existing pattern).

### Claim boundary

`bin/zlar-gate` (R041-protected enforcement-layer binary) untouched. No R041
maintenance window. `mcp-gate/gate.mjs` does NOT carry the force ceiling —
deferred to a future Phase F bundle alongside v3.3.9 chat_id and v3.3.10
float-fix MCP-side parity work. CHANGELOG entries for those are explicit;
v3.3.11 is the third deferred MCP item at the same architectural surface.

### Production observation, this build

The set-e crash window (21:07–21:11 UTC) blocked tools until the gate was
disabled and `canary_load_config` was repaired. Gate disable + fix + re-enable
took ~2 minutes once diagnosed. Live during this window: a real probability
canary fired at 21:06:32 (`CANARY PASSED: 69ffa0d4-...`), Vincent denied,
clean_run advanced 3/5 → 4/5. Promotion path post-v3.3.10 is alive — one more
healthy canary closes the v3.3.4 production-validation loop (guarded → fast).

The `approvals_since_last_canary` counter end-of-build was 6 (well below the
25 ceiling). First forced canary will fire when this counter reaches 25 if no
probability fire occurs first.

## 3.3.10 — 2026-05-09 — Canary Trigger Drought Fix + Skip Observability

The canary subsystem stopped firing on Vincent's box after the first canary
fired under v3.3.7. 71 deny-then-retry approvals over 4.6 days produced zero
canaries, against a 20% probability gate that should have produced ~14. The
clean_run promotion path was structurally unobservable. Discovered during
read-only post-v3.3.9 audit. The fix is one type cast applied at every site
where jq's `now` (float) is consumed by bash arithmetic, plus an observability
surface so the next drought is visible without code-level forensics.

### Root cause

`_hi_canary_claim_inner` wrote `.canary_last_epoch = now` via jq, which stores
the value as a floating-point second (`1777993446.847719`).
`hi_canary_should_trigger` then read that field and ran
`elapsed=$((now - last_epoch))` in bash. Bash `$(( ... ))` cannot evaluate
floats — the substitution emitted a syntax error to stderr (suppressed by
`2>/dev/null`), `elapsed` became empty, the subsequent `[ "" -ge 300 ]` exited
2 (integer expression expected), and `|| return 1` triggered. The cooldown
check returned false deterministically on every approval after the first
canary fire. Probability gate never reached.

The same pattern existed in `hi_canary_get_pending_started` feeding
`canary_check_result`'s in-flight age computation — latent because no pending
canary was outstanding on Vincent's box, but would have prematurely concluded
"timed out" on any pending canary issued post-v3.3.7.

### Fix: cast at every write, defend at every read

All eight `now` writes in `lib/human-invariants.sh` cast to integer via
`now | floor` before storage:

- `hi_apply_lane_demotion` — trust_lane_demotion.ts
- `hi_record_canary_outcome:passed` — clean_run_started_epoch + two trust_lane_auto_promoted.ts
- `hi_record_canary_outcome:failed/missed` — trust_lane_demotion.ts
- `_hi_canary_claim_inner` — canary_pending_started_epoch + canary_last_epoch
- `_hi_canary_record_delivery_inner` — canary_pending_delivered_epoch

Read sites consumed by bash arithmetic apply `| floor` defensively to handle
legacy floats already on disk (no migration write — state self-heals on next
canary fire that touches the field):

- `hi_canary_should_trigger` — canary_last_epoch
- `hi_canary_get_pending_started` — canary_pending_started_epoch

`bin/zlar` status display already accepted decimal-shaped values — no change.

### Observability: skip counters in state, not audit

Trigger eligibility decisions are evidence-bearing, but per-call audit
emission would spam the chain. With Vincent's typical traffic (~14 expected
probability skips per healthy day), every skip generating a signed audit
entry would fill the chain with non-events. Asymmetric design:

- Frequent skip reasons (probability, cooldown_active, below_threshold,
  pending_held) → counters in `.canary_skips` per-human state. Reset on
  canary claim. Surfaced via `bin/zlar status`.
- Rare structural events (cooldown_eval_error — corruption / jq missing /
  partial write that defeats the read-side cast) → ONE signed audit event
  per gate process, plus state counter. Pattern mirrors
  `_CANARY_MISCONFIG_LOGGED` in lib/canary.sh.

`hi_canary_should_trigger` now increments the right counter on every false
return. New helper `hi_canary_increment_skip` (public alias of
`_hi_canary_increment_skip`) exported for callers outside human-invariants.sh
— `lib/canary.sh`'s probability gate uses it.

### Status surface

`bin/zlar status` Canary Subsystem block adds a "trigger eligibility" sub-block:

- `approvals_since_last_canary` — counter advancing toward the next fire.
- `last_canary_iso` — ISO timestamp of the most recent canary that claimed
  pending (`never` if none), derived via `jq gmtime + strftime` so the
  display works regardless of int-vs-float on-disk shape.
- Five skip counters under "skips since last canary fire." cooldown_eval_error
  highlighted in red if non-zero (regression sentinel).

### Tests

5 new test cases (TC-26 through TC-30, +14 assertions) in `tests/test-canary.sh`:

- Float `canary_last_epoch` on disk does not block trigger eligibility.
- Non-numeric `canary_last_epoch` triggers cooldown_eval_error sentinel.
- Float `canary_pending_started_epoch` does not bypass in-flight guard.
- Skip counters increment by reason.
- canary_skips resets on claim.

### Claim boundary

`bin/zlar-gate` (Claude Code bash gate) only. `mcp-gate/gate.mjs` may carry
the same pattern in its canary path; not investigated this release. Same
boundary as v3.3.9. No `bin/zlar-gate` edit required (the bug is in lib/),
no R041 maintenance window needed.

### Diagnosis lineage

Found via session-44 read-only audit of post-v3.3.9 trigger drought. The
math (P(no fire | 67 dice rolls) ≈ 3×10⁻⁷) ruled out chance and forced
inspection of the deterministic gates. Source-traced `_hi_canary_claim_inner`
write site (jq `now` → float) → `hi_canary_should_trigger` read site (bash
`$(( ))` → can't eval float). v3.3.7 build-session validation passed because
the bug only exposes after the *second* should_trigger call following a
canary fire — only one canary had ever fired under v3.3.7-shape state on
Vincent's box. Same shape as the v3.3.6 build-session-self-validation
problem flagged by the round-2/3 mathematicians panel: n=1 in the
maintainer's environment isn't a sample.

### No policy changes, no receipt schema changes, no state shape changes

Adds `.canary_skips` (5 zero counters) to per-human state via idempotent
migration. Existing fields unchanged. Authority chain, signing posture,
89-rule policy at version 3.3.1 — all unchanged.

## 3.3.9 — 2026-05-09 — Telegram Chat ID Fail-Closed

`bin/zlar-gate:509` had a hardcoded chat_id fallback that, on a non-maintainer
deployment with missing or misconfigured `etc/gate.json` and no env override,
silently routed every general-ask Telegram card to the maintainer's chat.
v3.3.7 hardened the canary path against this; the general ask path remained
exposed. v3.3.9 closes that gap. The note in v3.3.7's CHANGELOG that "the
hardcoded chat_id at bin/zlar-gate:509 still falls through to the maintainer's
chat for the general ask path" is now resolved.

### Resolution: explicit source detection, no hardcoded fallback

`TELEGRAM_CHAT_ID_SOURCE` is resolved once at config-load time as one of:

- `env` — `ZLAR_TELEGRAM_CHAT_ID` was set before the gate started.
- `gate.json` — `etc/gate.json` `.telegram.chat_id` was non-empty.
- `unconfigured` — neither.

Both `lib/canary.sh:_canary_chat_id_validate` (v3.3.7) and the new
`_telegram_dispatch_ready` helper for the general ask path refuse to dispatch
when the source is non-authoritative. The hardcoded fallback is gone.

### Option β — structural guarantee that no human-state budget is consumed

Two checks, by intent. The defense-in-depth guard inside `telegram_ask_async`
ensures the function is safe to call from any path. The early guard in
`main()`'s ask flow runs *before* `hi_pre_ask_check`, `hi_record_ask_time`,
the rate-limit window write, and `gen_id`, so a misdeployed gate consumes no
pending counter, no rate-limit budget, no state writes. The shared helper's
once-per-process audit guard (`_TELEGRAM_MISCONFIG_LOGGED`) ensures only one
`telegram_subsystem_misconfigured` warn audit fires per gate invocation.

### Patch 1E — empty-`cb_from` callback rejection (line 1921)

Found in passing during the v3.3.9 audit. The existing callback verification
at `bin/zlar-gate:1921` was `[ "${cb_from}" != "${TELEGRAM_CHAT_ID}" ]`. Under
unconfigured, `TELEGRAM_CHAT_ID=""`. `jq -r '.from_id // ""'` returns `""`
when a callback file is missing `from_id` or has it as null. The equality
`"" != ""` is false, so a forged callback with empty `from_id` would have been
accepted under unconfigured. Narrow attack surface (transition window: chat_id
was set, asks fired, chat_id removed, stale `.pending` files on disk), but
real. Patch 1E rejects empty `cb_from` unconditionally:

```bash
if [ -z "${cb_from}" ] || [ "${cb_from}" != "${TELEGRAM_CHAT_ID}" ]; then
```

A callback without a real sender identity is never eligible to resolve an ask.

### `bin/zlar status` — three-state truth display

The old bottom-line `● Enabled — denied actions get sent to Telegram for
approval` claimed dispatch capability without verifying token presence or
chat_id source. Replaced (deleted, not conditionalized) with a top-level
`Telegram:` block that composes both:

- `state` is `enabled` only when token is present *and* chat_id source is
  authoritative (`gate.json` or `env`). Otherwise: `disabled (config)` if
  `.telegram.enabled=false`, `fail-closed (token missing)` if no token,
  `fail-closed (chat_id unconfigured)` if neither env nor gate.json.
- `chat_id source` and `token` are surfaced as their own lines.

Single source of truth at the same screen position. No contradictory
"enabled" claim while the gate is fail-closing.

### Manifest/constitution alerts under unconfigured — named trade-off

The manifest-attack and constitution-deletion alerts at `bin/zlar-gate:396`,
`:478`, and `:1189` are guarded by `[ -n "${TELEGRAM_CHAT_ID:-}" ]`. Under
unconfigured (`TELEGRAM_CHAT_ID=""`), the existing guard skips the Telegram
POST. `fail_closed_alert` (`lib/fail-closed-alert.sh:56`) has its own
`[ -z "${TELEGRAM_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]` guard and
also skips Telegram. Critical alerts on a misdeployed gate still land in
`audit.jsonl` + `gate.log` + `fail-closed-alert.log` — three local surfaces
carry the signal. Telegram is silent. Deliberate: when Telegram source is
non-authoritative, Telegram alerts cannot be trusted.

### Claim boundary

This release covers the Claude Code bash gate (`bin/zlar-gate`) only. The
MCP gate (`mcp-gate/gate.mjs`) carries the same architectural surface and
**is not covered in this release**. Deferred to a future window.

### Files

- `bin/zlar-gate`: replaced lines 507–510 with explicit source detection;
  added `_telegram_dispatch_ready` helper above `telegram_ask_async`; added
  early dispatch_ready guard in main()'s ask flow before any human-state
  writes; added `case 4` defense-in-depth in `send_result` switch; line 1921
  callback rejection hardened with unconditional empty-`cb_from` check.
- `bin/zlar`: replaced bottom Telegram block with three-state composite
  (`state`, `chat_id source`, `token`); deleted old `● Enabled` bottom line.
- `tests/test-approval-binding.sh`, `tests/test-approval-race.sh`,
  `tests/test-preconfirm.sh`: added `ZLAR_TELEGRAM_CHAT_ID` exports so the
  test fixtures resolve to source=`env` (authoritative) under v3.3.9.
- `tests/test-telegram-config.sh`: new file, 25 assertions covering source
  resolution, dispatch_ready return codes, once-per-process audit emission,
  structural guard ordering, env precedence, line 1921 empty-string
  rejection, three-state status composition, and live status block shape.

### Out of scope

- MCP gate hardening (deferred — see claim boundary above).
- The R012W_EDIT regex over-firing observed during the v3.3.9 audit (a
  read-only `cat etc/gate.json | jq '.telegram'` was matched as an edit).
  Tracked separately under post-Phase-F policy-rules audit.

### Policy / receipts / state shape

- Policy unchanged (3.3.1, 89 rules, default deny).
- Receipt schema unchanged.
- `var/human-state/{human_id}.json` shape unchanged.
- No `agent-policy-bindings.json` bump required.

### New audit events / reasons

- `telegram_subsystem_misconfigured` (warn, domain=`telegram`) — emitted
  once per gate invocation when source is non-authoritative.
- `gate:telegram_unconfigured` — new `respond_deny` reason on the
  operator-actionable deny path.

## 3.3.8 — 2026-05-09 — Status Display Truth

A read-only audit of v3.3.7 was queued under the name "Canary Audit Emit
Fidelity," premised on a hypothesis that `lib/canary.sh` outcomes were
mutating per-human lane state without emitting signed audit events. Direct
verification of `var/log/audit.jsonl` line 1214 (the demotion timestamp from
the live state file) showed the hypothesis was false: every canary outcome
*is* in the audit log with `domain="canary"` and `action="governance_health_check"`.
The original investigation grepped for `category="canary"` and
`event_type="governance_health_check"` — neither field exists in the audit
schema. The candidate v3.3.8 frame ("audit emit gap") was a measurement
artifact.

Three real bugs surfaced in the same pass — all in the bin/zlar status
display, all introduced or unmasked when v3.3.7 added the A4 status surface.
Display-only fixes; no canary outcome logic, human-invariants logic, or
state-data shape changes.

### Bug A — Canary 7d counters always 0 (correctness regression in v3.3.7 A4)

Two compounding bugs in the same parsing block; either alone collapsed the
counters to 0.

- `bin/zlar:401` read `.event_type`, a field that does not exist in the audit
  format. `emit_event` writes the value into `.action`. Every event lookup
  returned `""`, no case branch matched, and all seven canary counters
  (`passed`, `failed`, `missed`, `pending_lost`, `pending_tampered`,
  `claim_lost`, `artifact_destroyed_post_delivery`) stayed at 0.
- `bin/zlar:426` treated `.ts` as an epoch number and stripped a fractional
  part with `${entry_ts%%.*}`, then failed every line through the `[!0-9]`
  case because `.ts` is actually an ISO 8601 string ("2026-05-04T02:24:45Z").
  Even with the field name correct, the 7d window check would have rejected
  every line. Surfaced only after the field-name fix produced still-zero
  counters against a known-populated audit log.

Fix: change `.event_type` → `.action`, and parse `.ts` via jq's
`fromdateiso8601` with a numeric fallback so any future float-epoch lines
also resolve. Counters now reflect what the audit log actually contains:
on Vincent's box, `passed: 9, failed: 1` against the demotion at
2026-05-04 02:24:45Z and the subsequent healthy outcomes. Both fixes
documented in the parsing-block comment so the next contributor doesn't
re-introduce either assumption.

### Bug B — Longest streak frozen below the open streak

`lib/gate-uptime.sh:gu_status_lines` printed the stored `longest_streak_seconds`
raw. The on-disk field is a write-on-disable invariant: it records the longest
*completed* streak, and only updates when a streak ends. While the gate
remains on past the previous record, the displayed longest sat below the live
current, which on a screenshot looked like the data file had a contradiction
(current > longest).

Lifetime already handled this at the same call site (`display_lifetime =
lifetime_sec + current_sec`). v3.3.8 applies the same display-only correction
to longest: when `state="on"` and `current_sec > longest_sec`, the displayed
longest swaps to the open streak with a `(current — still running)`
annotation on both the duration line and the start-time line. The on-disk
value is not mutated.

### Bug C — Stale-state badge on bin/zlar status

Daily-bound counters (`decisions_today`, `response_times`) reset only when
`_hi_ensure_state` runs on the next gate write. `bin/zlar status` is read-only
by design, so when no gate call has fired since UTC midnight, the displayed
`State date` is yesterday's and the daily counters carry yesterday's values
without any annotation. An operator reading "decisions_today: 3.3 / 80" on
2026-05-09 with `State date: 2026-05-06` would reasonably read it as today's
activity when in fact the state had simply not rolled over.

Fix: compare `STATE_DATE` to `$(date -u +%Y-%m-%d)`. If different and not the
sentinel "?", append `(stale — will roll over on next gate call)` to the date
line and `(stale)` to `decisions_today` and `response_times`. The "?" sentinel
(missing-date failure mode, distinct from "yesterday's date") is excluded
from the badge so the two failure modes don't get conflated.

### Tests

- `tests/test-gate-uptime.sh`: three new assertions (open-streak supersedes
  stored, current < stored leaves annotation absent, state=off leaves
  annotation absent).
- `tests/test-status-display.sh`: new file. Reproduces the canary 7d parsing
  block against a fixture audit.jsonl with one event per canary action and
  asserts every counter increments. Defense-in-depth grep over `bin/zlar`
  for `.event_type` regression. Three Bug C cases (stale, fresh, missing-
  sentinel).

### What did NOT change

- `lib/canary.sh`, `lib/human-invariants.sh`, `lib/human-invariants.mjs`,
  `mcp-gate/gate.mjs` canary paths — untouched.
- Audit emit guards (`if type emit_event &>/dev/null; then`) — untouched.
- Policy rules — 89 rules, version 3.3.1.
- Per-human state schema — no migration.

### Memory hygiene

- `project_canary_audit_emit_gap.md` is marked **REFUTED** with a
  post-mortem block noting why the original grep failed. The memory's
  hypothesis ("canary outcomes don't emit") and proposed investigation moves
  ("source emit_event helpers in every dispatch context", "move emit into
  hi_record_canary_outcome") are no longer applicable.
- `MEMORY.md` index updated to reflect that v3.3.8 ships as Status Display
  Truth, not Canary Audit Emit Fidelity.

## 3.3.7 — 2026-05-05 — Canary Evidence Hardening

A six-task read-only audit of v3.3.6 surfaced four correctness bugs in the
canary lifecycle: a parallel-session pending claim race, an unsigned `.pending`
artifact whose deletion suppressed legitimate `canary_missed` demotions, a
hardcoded `TELEGRAM_CHAT_ID` fallback that silently routed canaries to the
maintainer on misdeployed boxes, and `canary_pending_lost` events with no
operator-facing surface. v3.3.7 closes the first three in code and adds
visibility for the fourth.

The thesis governing the change:

- Evidence Conservation Principle. The system must not convert its own
  missing, stale, or unrecorded internal state into friction against the
  human. Punitive lane transitions only proceed from non-zero witness, and
  the witness is something the system itself can produce — not a guess
  about what the human did or didn't see.
- Demotion requires three conjuncts: delivery evidence, timeout, and no
  valid callback. `msg_id` (Telegram POST returned a `message_id`) is
  delivery/posting evidence — the card was POSTED to the chat. It is not
  proof of human attention or proof the human ignored the card.
- The `.pending` routing artifact is no longer authoritative. Its
  existence, contents, or absence at resolve time signals the bookkeeping
  state, not the human's behavior.

### A1: Pending claim race (locked CAS)

`hi_canary_set_pending` is replaced by three lock-wrapped functions:

- `hi_canary_claim_pending(human_id, canary_id, session_id)` — locked
  read-modify-write. Refuses if `canary_pending_id` is already non-empty.
  Returns 0 on win, 1 on loss.
- `hi_canary_record_delivery(human_id, canary_id, msg_id, artifact_hash)` —
  records Telegram POST evidence under the per-human lock; verifies the
  claim still belongs to this `canary_id` before writing.
- `hi_canary_release_pending(human_id, canary_id)` — rollback for the
  send-failure path; only releases if `pending_id` matches.

Backend: `flock(1)` (Linux/CI) with mkdir-mutex fallback (macOS where
`flock` is absent). Both grant exactly one winner; both clean up the
lockfile on body completion.

`canary_send` (bash) and `sendCanary` (mcp-gate) now claim before sending.
Race losers exit before any Telegram POST or `.pending` write — only one
session can put a canary card in the human's chat for the same human at
the same time. New audit event: `canary_claim_lost`.

### A2: Pending artifact integrity (delivery evidence)

Three new fields in per-human state, idempotent migration:
- `canary_pending_msg_id` — Telegram `sendMessage` response message_id.
- `canary_pending_delivered_epoch` — wall-clock when delivery was
  confirmed.
- `canary_pending_artifact_hash` — HMAC over the claim payload.

The resolve algorithm replaces the old "artifact present + age > timeout
→ missed; artifact missing → pending_lost" with:

```
no delivery evidence + timeout
    → canary_pending_lost (clear, NO demote)
delivery evidence + timeout + intact artifact
    → canary_missed (demote)
delivery evidence + timeout + tampered artifact contents
    → canary_pending_tampered (clear, NO demote, warn audit)
delivery evidence + timeout + missing artifact
    → canary_missed (demote) + canary_artifact_destroyed_post_delivery
      correlation audit
```

Tampered evidence is not delivery evidence we can act on. Cannot rule
out attacker corruption of our own bookkeeping; acting on a tampered
artifact would let an attacker steer demotions.

Destroyed-post-delivery does not exonerate the timeout — delivery
evidence in state stands on its own. The correlation audit lets
operators detect the destruction pattern.

### A3: TELEGRAM_CHAT_ID source visibility

`lib/canary.sh` now reads `gate.json` directly to detect the chat_id
source. Sources: `gate.json`, `env`, `hardcoded-fallback`,
`unconfigured`. Only `gate.json` and `env` are accepted. The
`hardcoded-fallback` case (a non-empty `TELEGRAM_CHAT_ID` inherited
from `bin/zlar-gate:509` without an explicit gate.json or env value)
emits `canary_subsystem_misconfigured` once per process and refuses
to send.

`mcp-gate/gate.mjs` does the same for its own resolution path
(`cli` | `gate.json` | `unconfigured`).

The R041-protected `bin/zlar-gate:509` hardcoded-fallback removal is
deferred to a follow-up release at a scheduled R041 maintenance window.
v3.3.7 is shipped as a hardening-only release without that edit; the
lib-side guard is sufficient to prevent silent misdeployment in the
meantime.

### A4: canary_pending_lost monitoring

`bin/zlar status` now displays a Canary Subsystem block:

- state (enabled / misconfigured)
- chat_id source (gate.json / env / hardcoded-fallback)
- last 7 days outcome counts: passed, failed, missed, pending_lost,
  pending_tampered, claim_lost, artifact_destroyed_post_delivery
- pending_lost rate (per-day, alarm if > 1.0)

The 1.0/day threshold is a v3.3.7 prior, not a calibrated value;
recalibrate once non-developer production data
exists.

### Tests

Bash: 5 new TC-21..TC-25 in `tests/test-canary.sh`. TC-11 updated to
v3.3.7 semantics (delivery evidence + state-side timeout). 49 → 54
assertions.

MJS: 3 new TL-MCP-AD/TA/PL in `mcp-gate/test.mjs`. `writePending`
helper extended with v3.3.7 fields and four opt-in flags
(`skipArtifact`, `tamperedContents`, `noDelivery`,
`backdateStartedEpoch`).

### Migration

Three new state fields are added to per-human state on first read after
upgrade. Live state on Vincent's box has `canary_pending_id=""` at
upgrade time; migration adds three empty fields and the next canary
uses the new path cleanly.

If a canary is in flight at upgrade time (`canary_pending_id` non-empty
but new fields absent), the post-migration resolve treats it as
`pending_lost` (no delivery evidence) → no demotion. The human gets
one free pass on a probe issued under v3.3.6 rules.

### Deferred to v3.3.8+

- Telegram reveal / canary progress feedback (round-3 right-adjoint
  argument acknowledged; ships once production clean-run cycle has
  been observed under hardened evidence model).
- `bin/zlar canary explain <id>` contestability dump.
- Threshold recalibration.
- `bin/zlar-gate:509` hardcoded-chat-id removal — R041 maintenance
  window required.
- Worker-file ownership model under
  `project_who_asked_the_system_to_watch.md`.

### Rules saved this build

- `feedback_demotion_requires_evidence.md` (v3.3.6, applied here)
- `feedback_evidence_conservation_principle.md` (v3.3.6, applied here)
- `feedback_chat_context_must_match_ask.md` (v3.3.6, applied here)

## 3.3.6 — 2026-05-05 — Cross-Session Canary Lifecycle

A clean run should earn future canary opportunity across sessions. The human is
what the system is calibrating, not the Claude session.

The bug v3.3.6 fixes:
Pre-v3.3.6, canary trigger eligibility (the approvals counter, cooldown anchor,
and pending-canary lock) lived in `var/canary/{session_id}.canary.json` —
session-scoped state. Demotion and promotion (Trust Lane outcomes) were
already per-human via the v3.3.4 clean_run accounting. This scope mismatch
made recovery accidentally harder across short Claude Code sessions: each new
session reset the counter to 0, so even an active operator might never reach
the canary threshold to earn a clean-run promotion. Demotion was sticky
per-human, but chances to earn healthy canaries reset every restart.

Fix: trigger eligibility moves to per-human state. Five new fields in
`var/human-state/{human_id}.json`, idempotent migration on load:
- `canary_approvals_since_last` — counter advancing toward trigger threshold.
- `canary_last_epoch` — cooldown anchor; epoch of last canary sent.
- `canary_pending_id` — canary id of any outstanding probe (one per human).
- `canary_pending_session_id` — session that issued the pending probe (routing).
- `canary_pending_started_epoch` — for staleness check; survives gate restart.

All persist across UTC rollover (canary lifecycle is event-driven, not calendar).

The `.pending` file at `var/canary/{session_id}.canary.pending` stays as a
routing artifact for the existing inbox handler. Authoritative state is the
per-human record. `canary_check_result` is now keyed on `human_id` and reads
the pending session from human state — a canary fired in session A is
resolvable by any later gate invocation under the same human, in any session.

Per-human pending lock: only one canary may be outstanding per human. Parallel
sessions for the same human cannot fire concurrent canaries.

The invariant landed with this patch:
**Demotion requires evidence, not absence of evidence.**
Saved as a permanent rule. canary_failed (callback approve) and canary_missed
(artifact present, age > timeout, no callback) demote — those are evidence of
human behavior. canary_pending_lost (state says pending, but the routing
artifact is missing) is bookkeeping loss, not a human miss: clear pending,
emit `canary_pending_lost` warn audit event, do not touch trust lane. This
distinguishes a safety system from a superstition machine.

R041 considerations:
The original design called for editing `bin/zlar-gate` call sites to pass
`human_id`. R041 denies edits to the enforcement-layer binary. The patch was
restructured: `lib/canary.sh` functions now accept the existing single-arg
session_id call shape and fall back to `${TELEGRAM_CHAT_ID:-}` (a global in
bin/zlar-gate's scope) for `human_id`. Fail-safe: if `human_id` cannot be
resolved, no canary fires and no demotion path is reached. Punishment requires
identifying the human; nothing happens to a human the system can't even name.

`canary_check_result` accepts the existing 2-arg `(session_id, human_id)`
signature, ignores the first arg, and uses the second. The R041-protected
binary is untouched.

New behavior in `lib/human-invariants.{sh,mjs}`:
- `hi_record_canary_approval` / `recordCanaryApproval` — atomic per-human counter
  increment.
- `hi_canary_should_trigger` / `canaryShouldTrigger` — pure trigger evaluator
  (counter, cooldown, pending lock).
- `hi_canary_set_pending` / `canarySetPending` — atomic write of pending fields
  + counter reset + cadence record.
- `hi_canary_clear_pending` / `canaryClearPending` — clear pending fields
  (counter and last_epoch survive).
- `hi_canary_get_pending_*` / `getCanaryPending` — readers.

Updated in `lib/canary.sh`:
- `canary_record_approval` / `canary_should_trigger` / `canary_send` /
  `canary_check_result` — delegate trigger eligibility and pending to the
  per-human helpers above. Back-compat fallback to `TELEGRAM_CHAT_ID`.
- `canary_send` — early-return when `human_id` cannot be resolved (fail-safe;
  ungovernable canary cannot produce evidence).
- `canary_init` — orphan `.pending` sweep. A `.pending` file is swept only if
  age > `TELEGRAM_TIMEOUT_S` AND its canary_id is not referenced by any live
  human state's `canary_pending_id`. Two-condition guard so we never delete a
  fresh pending mid-write or a legitimate pending of a not-yet-loaded human.
- New `_canary_log_pending_lost` — emits `canary_pending_lost` warn event,
  clears pending state, does NOT call `hi_record_canary_outcome`. Carries
  the invariant.

Updated in `mcp-gate/gate.mjs`:
- `recordCanaryApproval`, `canaryShouldTrigger`, `sendCanary`, `checkCanaryResult`
  rewritten / removed in favor of the per-human helpers from `human-invariants.mjs`.
- Passive check call site (`handleRequest`): `checkCanaryResult(humanId)` —
  cross-session resolution.
- Post-approval call site: `recordCanaryApproval(humanId)` and
  `canaryShouldTrigger(humanId, opts)` — keyed on human.
- Same `canary_pending_lost` path on the MCP side.

Legacy stubs:
- `canary_is_fatigued` / `canary_fatigue_count` (bash) — return safe defaults.
  Pre-v3.3.6 these read the retired session-scoped `.canary.json`. The
  per-human signal is now `clean_run_count` via Trust Lane (v3.3.4).

Garbage collection:
- 50 stale `var/canary/*.canary.json` files (March–May 2026) become inert. A
  separate `bin/zlar canary-gc` patch will remove them. Not in v3.3.6.
- Orphan `.pending` files are swept on `canary_init` (see above).

Tests:
- `tests/test-canary.sh` — full rewrite. 37 assertions across 20 test cases:
  per-human counter (TC-1..3 incl. cross-session accumulation and human
  isolation), trigger evaluation (TC-4..7), send semantics (TC-8), outcome
  paths (TC-9..11), **TC-12 = the invariant test** (`pending_lost` clears
  state without demote), cross-session resolution (TC-13), orphan sweep
  (TC-14), back-compat fallback (TC-15), missing-human no-op (TC-16),
  scenario picker (TC-17), restored cosmetic checks (TC-18..20).
- `mcp-gate/test.mjs` — SEND-1..4 updated to read per-human state and
  exercise the per-human pending lock; SEND-5 unchanged. TL-MCP-* and
  CR-MCP-* unchanged (already keyed on humanId via recordCanaryOutcome).

No policy rule changes. Policy version stays 3.3.1 (89 rules). No receipt
schema changes. No change to ceremony or critical-severity gating. No
maintenance window — code-only change in `lib/` and `mcp-gate/`; the
R041-protected `bin/zlar-gate` is untouched.

## 3.3.5 — 2026-05-04 — Status truth refresh

`zlar status` was lying about live state. Hotfix on top of v3.3.4. No
behavior change to enforcement, canary, or trust lane — display only.

Bugs fixed:
- `decisions_today` displayed as 0 since v2.8.1 because the numeric
  validation regex rejected the decimal point added when the field
  became risk-weighted. Now allows floats.
- `approvals_recent: 0 entries` shown since v2.9.0 — the field was
  renamed to `response_times` and the status tool kept reading the
  retired name. Renamed in display.
- `var/human-state/` test-fixture artifacts (non-numeric human_ids)
  were enumerated as humans. Now skipped.

Trust Lane visibility added to status (was missing entirely):
- `trust_lane` (color-coded: fast=green, guarded=yellow, slow=red)
- `trust_lane_grant` source if present
- `clean_run` count / promotion threshold + started ISO timestamp
- `canary_tier` / `canary_trip_count`
- last `trust_lane_demotion` reason + ISO timestamp

The status tool now surfaces the v3.3.4 clean-run state and the most
recent demotion. Vincent caught the discrepancy in production within
hours of v3.3.4 going live.

Single-file patch: `bin/zlar` only.

## 3.3.4 — 2026-05-04 — Clean Run Trust Lane Auto-Promotion

ZLAR does not score the human. It watches the run.
A clean run earns speed; a broken run restores friction.

Trust lane now graduates on canary-outcome history rather than authority grant
alone. Five consecutive healthy canaries promote one lane (slow → guarded,
guarded → fast). One failed or missed canary resets the run and demotes one
lane. Manual authority grant remains as bootstrap and as override; it is no
longer required for promotion, and it does not shield from demotion.

State schema:
- clean_run_count (int, default 0) — consecutive healthy canary outcomes.
- clean_run_started_epoch (int, default 0) — telemetry; epoch when the
  current run began. Cleared on demotion or promotion.
Both fields persist across UTC rollover. A run is a logical sequence of
canary outcomes, not a calendar artifact. Idempotent migration on load.

New behavior in lib/human-invariants.{sh,mjs}:
- hi_record_canary_outcome / recordCanaryOutcome — single source of truth for
  clean-run accounting and lane transitions on canary outcomes.
  passed: count++; if count >= threshold and lane in {slow, guarded}, promote
  one lane and reset count. At lane=fast, reset count, no lane change. If
  auto_promotion_enabled=false, cap count at threshold (no drift).
  failed | missed: reset count and started_epoch; demote one lane (fast →
  guarded → slow); manual grant does not shield.

Call-site swap: lib/canary.sh and mcp-gate/gate.mjs canary-result paths now
call the new function instead of hi_apply_lane_demotion / hi_apply_lane_restore.
The old functions are kept exported for external operator scripts and marked
deprecated; do not call from new code.

Config in etc/gate.json .canary:
- clean_run_promotion_threshold (default 5)
- auto_promotion_enabled (default true) — kill switch.
Env overrides for test isolation: ZLAR_CANARY_PROMOTION_THRESHOLD,
ZLAR_CANARY_AUTO_PROMOTION.

Audit:
- New event trust_lane_auto_promoted on lane promotion (info severity).
- Existing demotion path now emits trust_lane_demoted with clean_run_reset:true.

No policy rule changes. Policy version stays 3.3.1 (89 rules). No receipt
schema changes. No change to ceremony or critical-severity gating — auto-
promotion only affects H14/H15/H17 floor handling, exactly as v3.3.0
trust_lane already does.

Tests:
- New tests/test-trust-lane-cleanrun.sh — 12 assertions covering increment,
  promotion at threshold from slow and guarded, no-op at fast, demotion from
  fast and guarded, slow-stays-slow, mixed sequences, auto_promotion_enabled
  off, threshold cap, migration.
- New mcp-gate/test-cleanrun.mjs — 12 parallel assertions for MJS gate.

## 3.3.3 — 2026-05-04 — MCP canary SEND parity

MCP gate can now initiate canary probes, closing the remaining gap where bash
gate was the only path that could generate governance health checks.

New functions in mcp-gate/gate.mjs:
- recordCanaryApproval(sessionId): increments per-session approval counter in
  var/canary/{sessionId}.canary.json after every human-approved MCP ask.
  Auto-creates state file on first approval. Same JSON schema as bash gate.
- canaryShouldTrigger(sessionId): evaluates enabled flag, min-approvals
  threshold, cooldown, probabilistic roll, and pending guard. Returns bool.
  Never throws — failure returns false.
- sendCanary(sessionId): picks a random scenario from etc/canary-scenarios.json,
  builds a Telegram card in MCP real-ask shape (🔷 prefix, *{display_rule}*
  header, consequence line, *MCP:* args line, Risk N/100), sends via telegramApi,
  writes var/canary/{sessionId}.canary.pending. Fail-open: errors log and return
  without affecting the governed action.

Call site: in handleRequest, immediately after emitEvent('authorized') on the
human-approved ask path. Not on policy auto-allow paths. sendCanary called async
with .catch(() => {}) — never blocks the approved tool call.

Callback data uses cc:canary:approve:{id} / cc:canary:deny:{id} (not mcp:canary:)
so results land in inbox/cc and v3.3.2 checkCanaryResult processes them without
a second inbox scan path. No second canary system.

Config loaded from gate.json .canary block (independent of telegram chat-id
check). Five env var overrides for test isolation: ZLAR_CANARY_ENABLED,
ZLAR_CANARY_MIN_APPROVALS, ZLAR_CANARY_PROBABILITY, ZLAR_CANARY_COOLDOWN,
ZLAR_CANARY_SCENARIOS_FILE.

Supporting changes:
- ZLAR_TELEGRAM_API_BASE env var in telegramApi — allows mock Telegram server
  in tests without hitting real bot API.
- ZLAR_MCP_INBOX_DIR env var in telegramAsk and telegramPreconfirm — enables
  test isolation of MCP inbox directory.
- writeFileSync, mkdirSync added to fs imports.

Tests: 5 new SEND assertions in mcp-gate/test.mjs (SEND-1 through SEND-5).
Uses a mock Telegram HTTP server that auto-injects MCP approvals and captures
canary send requests. 18/18 pass (was 13 on macOS/EPERM before SEND tests;
all pass on CI/Linux).

Shared artifacts (unchanged format):
- var/canary/{sessionId}.canary.json — bash and MCP gate share the same schema
- var/canary/{sessionId}.canary.pending — one-line canary ID
- cc:canary: callback routing via inbox/cc

Out of scope: cooldown behavior after canary send is driven by last_canary_epoch
in the shared state file; tested indirectly via SEND-4 (pending guard). A
dedicated cooldown test would require clock manipulation and is deferred.

## 3.3.2 — 2026-05-04 — MCP Trust Lane canary parity

MCP gate now participates in trust lane transitions driven by canary outcomes,
closing the gap where the bash gate was the only path that could demote or
restore the lane.

New function: checkCanaryResult(sessionId, humanId) in mcp-gate/gate.mjs.
Called passively at the top of handleRequest on every request (non-blocking,
never throws). Mirrors canary_check_result from lib/canary.sh (bash gate
line 2428).

Behavior:
  - Reads var/canary/{sessionId}.canary.pending for a pending canary ID.
  - If present, scans /var/run/zlar-tg/inbox/cc/*.json for a matching
    cc:canary:{approve|deny}:{canary_id} callback, HMAC-verified.
  - approve (fatigue detected) → applyLaneDemotion(humanId, 'canary_failed')
  - deny   (healthy)           → applyLaneRestore(humanId)
  - stale  (no response)       → applyLaneDemotion(humanId, 'canary_missed')
  - restore guarded→fast ONLY when trust_lane_grant is present in state
    (authority-issued; same rule as bash gate).

MCP canary SEND is not implemented in this release. The result-check is
operative today for canaries sent by the bash gate on the same session ID.
MCP send is a separate gap with a separate patch.

Supporting changes for test isolation:
  lib/human-invariants.mjs:
    - STATE_DIR: respects ZLAR_HUMAN_STATE_DIR env var (test override).
    - HMAC_KEY_FILE: respects ZLAR_HUMAN_STATE_HMAC_KEY_FILE env var (test
      override; enables unkeyed mode in isolated test environments).
  mcp-gate/gate.mjs:
    - HMAC_SECRET_FILE: respects ZLAR_INBOX_HMAC_SECRET_FILE env var.
    - New CONFIG: canaryStateDir, ccInboxDir (env + CLI override).
    - New CLI args: --session-id, --canary-state-dir, --cc-inbox-dir.

Tests: 5 new TL-MCP assertions in mcp-gate/test.mjs.
  TL-MCP-1: canary_failed demotes fast→guarded.
  TL-MCP-2: canary_missed (stale pending) demotes fast→guarded.
  TL-MCP-3: canary_passed restores guarded→fast with authority grant.
  TL-MCP-4: canary_passed keeps guarded (no authority grant present).
  TL-MCP-5: HMAC mismatch discards callback — lane unchanged.
Note: mcp-gate/test.mjs uses a TCP mock server and hits a pre-existing EPERM
flake on macOS due to application firewall restrictions. Tests pass on CI
(Linux). Human-invariants.sh: 108/108 (unchanged).

Out of scope for this patch:
  - MCP canary send
  - Phase F signing chain rotation
  - draft.json regeneration

## 3.3.1 — 2026-05-03 — Trust lane policy governance (R012W_TRUST_LANE)

Policy-only patch. No code changes to gate logic or enforcement functions.

Adds R012W_TRUST_LANE (ask/critical, bash domain) to active.policy.json.
This rule governs any agent Bash invocation of scripts/grant-trust-lane.sh,
closing the gap where the TTY check inside the script was the only control.
The TTY check remains as defence-in-depth; R012W_TRUST_LANE is the primary
policy control.

Rule: R012W_TRUST_LANE
  domain: bash
  action: ask
  severity: critical
  regex: grant-trust-lane(\.sh)?
  risk: 100/100/100
  verify_hint: confirm human_id, target lane, and reason before approving

Policy version: 3.2.2 → 3.3.1
Rule count: 88 → 89
Signed with software key (Ed25519, same key as v3.2.2).
draft.json not updated (stale at 3.1.0/82 rules — requires separate regeneration).

Out of scope for this patch:
- draft.json regeneration
- Trust lane revoke script (does not exist yet; will be governed when added)

## 3.3.0 — 2026-05-03 — Trust Lane system (Fast / Guarded / Slow)

## 3.2.3 — 2026-05-03 — H17/H15 timing observation recording layer (Slice 1)

Recording-only change. No floor values changed. No graduation logic. No H15
floor reductions. No canary_credits, no Level 1/2 operator profiles, no
operator_profile_level writes beyond schema initialization.

The gate now records a timing_observations entry on every human response
(approve or deny), regardless of whether H17 or H15 rejected it. This is the
data foundation for Calibrated Operator Trust Graduation (Slice 2), which will
not ship until timing_observations has accumulated real-usage data and a floor
review has been done.

New state fields (both bash and MJS gates):
- timing_observations: [] — per-response audit records; survives UTC rollover;
  ring-buffered at 100 entries; observations older than 30 days are pruned on
  each write.
- operator_profile_level: 0 — reserved for Slice 2 graduation level; written
  only on schema init; not used by any logic in this release.

Each timing_observations entry carries:
  ts, iso, elapsed_ms, h17_floor_ms, h15_floor_ms, effective_floor_ms,
  binding_floor ("h17" | "h15" | "none"), severity, risk_score,
  outcome ("accepted" | "rejected_h17" | "rejected_h15" | "deny_accepted"),
  source ("approve" | "deny")

hi_post_response_check / postResponseCheck rewritten:
- Deny path branches before H17/H15 checks. Deny always stands; the gate
  records a deny_accepted observation and calls hi_record_decision, then
  returns ok without running authenticity or deliberation checks.
- Elapsed computed once at function entry; reused by all exit paths.
- Single _hi_record_timing_observation call per distinct exit point —
  no write-then-overwrite ambiguity, no duplicate writes.
- H17 and H15 floor values are computed for the observation record before
  each check, so rejected events carry the floor that would have needed to
  be met.

mcp-gate/gate.mjs:
- approve path: postResponseCheck now receives {riskScore: evaluation.riskScore}
  so timing observations carry the actual risk score rather than the default 100.
- deny path: routes through postResponseCheck instead of bare recordDecision,
  achieving deny-observation parity with the bash gate.

v3.2.3 schema migration:
- _hi_ensure_state / loadState adds timing_observations and
  operator_profile_level to any existing state file that lacks them.
- UTC rollover does not clear timing_observations (explicit design — multi-day
  observation history is required for Slice 2 graduation).

Tests: 21 new assertions (75 → 96 in test-human-invariants.sh). T1-T7 cover:
fast approve → rejected_h17, accepted approve with correct floor fields,
H15 critical reject → rejected_h15, fast/slow deny → deny_accepted (never
rejected), date rollover preserves timing_observations, ring buffer cap.

Out of scope for this release:
- Floor selection wired to graduation level (Slice 2)
- compute_graduation_level() function
- canary_credits / hi_record_canary_pass
- Level 1 / Level 2 H15 floor reductions (15s/3s/0s and 5s/0s/0s)
- operator_profile_level write command
- Receipt schema additions (h17_graduation_level, h17_elapsed_ms, h17_floor_ms)

## 3.2.2 — 2026-04-28 — Security hardening: adapter-shim coverage, approval-state forgery, MCP loopback, pending-hash binding

Five narrow fixes from a six-agent roster review of v3.2.1. Each closes a
claimed-vs-reality gap or a gate-bypass vector. No new behaviour: every change
either tightens an existing surface or aligns code with a doctrine claim that
was already advertised.

Fix 1 — MCP gate listener was bound to all interfaces:
- mcp-gate/gate.mjs:1536 called server.listen(CONFIG.port, cb) with no host
  argument. Node defaults to ::, so the gate accepted JSON-RPC from any peer
  on the local network. The repo and BUILD-NOTE both claimed "127.0.0.1
  bind" — that claim was false. On any untrusted Wi-Fi the gate's policy
  evaluation and ask flows were reachable by other peers, who could initiate
  actions that paged the human's phone for approval.
- Fix: bind to 127.0.0.1 by default. CONFIG.host derives from
  ZLAR_MCP_HOST when set; otherwise 127.0.0.1 is hard-coded. Override is
  intended only for isolated-namespace deployments.

Fix 2 — Adapter shim was uncovered by policy:
- ~/.claude/zlar-gate.sh and ~/.claude/zlar-session-hook.sh are the
  scripts the Claude Code PreToolUse hook invokes. Neither was named in
  any policy rule. R032 covered ZLAR_Repo/bin/zlar-gate (the source
  binary) but not the deployed shim. A single Edit or Write to the shim
  could replace the gate body with `cat <<EOF; allow; EOF` — silently
  bypassing the entire stack downstream (audit chain, sig-verify,
  Telegram, fingerprint cache).
- Fix: three new deny/critical rules. R012D denies Bash writes/edits
  whose command string matches `\.claude/zlar-(gate|session-hook)\.sh`.
  R032H denies Write-tool writes to that path. R041K denies Edit-tool
  edits to that path. All three are deny — the shim must not be
  agent-editable. Net rule delta: 85 → 88.

Fix 3 — Approval state was forge-able via Bash redirect:
- R012W_EDIT (the broad enforcement-path ask rule) covered
  /var/log/(audit|gate) but NOT /var/log/approvals/. R032C covered
  Write-tool writes to ZLAR_Repo/var/log/ (deny) but Bash redirection
  (`printf ... > approvals/<rule>-<sid>-<hash>.approved`) slipped
  through. An attacker who could write a forged .approved file at the
  expected path would short-circuit check_pending_approval into a cache
  hit on the next ask.
- Fix: R012B regex extended to deny Bash commands targeting
  approvals/.+\.(approved|pending|acked|blocked). Closes the redirect
  vector. R032C continues to handle the Write-tool path.

Fix 4 — check_pending_approval empty-hash short-circuit:
- bin/zlar-gate:1874 only ran the action-hash binding check when both
  expected_action_hash AND pending_action_hash were non-empty. An
  attacker who planted a pending file with empty line 2 (forged or
  truncated) bypassed the binding check entirely — any subsequent
  approve callback for the embedded action_id was replayed, regardless
  of which command the caller asked for.
- Fix: when expected_action_hash is non-empty, an empty
  pending_action_hash is now treated as corrupt — the pending file is
  deleted and the call returns 2 (force fresh ask). The legacy
  empty-expected, empty-pending path is unchanged (graceful degradation
  preserved for callers that don't bind).
- Regression: tests/test-approval-race.sh Test 9 — plants a pending
  file with empty line 2, plants a matching approve callback, calls
  CPA with non-empty expected hash, asserts return 2 + pending file
  deleted + no approved cache seeded.

Fix 5 — H13 pending TTL drift between bash and mjs gates:
- lib/human-invariants.sh:46 set HI_PENDING_TTL to 360s; the comment
  explains v2.8.1 reduced from 1800s to fix spurious "overloaded"
  blocks during high-volume sessions. lib/human-invariants.mjs:78 set
  pendingTtl to 1800s — carrying the pre-v2.8.1 bug. The fix never
  propagated.
- Fix: mjs aligned to 360s with a comment crediting bash's earlier
  fix. Both gates now share the same TTL; the H13 spurious-overload
  failure mode is closed on the MJS path.

Fix 6 — R032E/R041E case-sensitivity gap:
- Both rules used regex `ZLAR.*/repo/(lib|tests|scripts|mcp-gate|docs
  |etc/canary)/` (lowercase repo). The actual repo directory is
  `ZLAR_Repo` (capital R). The regex never matched the live path, so
  the source-edit ask/warn rules — which exist precisely to surface
  agent edits to lib/, tests/, mcp-gate/, etc. — have been silently
  dormant since they were written. Every agent edit to those paths
  fell through to the catch-all R036/R042 (allow). This was a real
  enforcement gap, not a rule-design intention; the rules' descriptions
  ("Write to ZLAR repo code", "Edit ZLAR repo code") describe behaviour
  the regex did not deliver.
- Fix: regex updated in both rules to `ZLAR.*/(repo|ZLAR_Repo)/(lib
  |tests|scripts|mcp-gate|docs|etc/canary)/`. Matches both the actual
  repo dir and the lowercase form (in case the dir is renamed or
  cloned with a different case). Rules now fire as designed. Operator
  consequence: agent-driven edits to lib/, tests/, scripts/, mcp-gate/,
  docs/, and etc/canary/ inside ZLAR_Repo will start surfacing as
  ask/warn through Telegram — the friction these rules were always
  meant to add.

Policy:
- etc/policies/active.policy.json bumped 3.2.0 → 3.2.2, re-signed
  with software signing key. Description text rewritten to enumerate
  v3.2.2 additions (R012D / R032H / R041K, R012B regex extension)
  while carrying forward v3.2.0 R012 effect-split notes.
- tests/test-perimeter-closure.sh rule count assertion 85 → 88.

Tests:
- tests/test-approval-race.sh: 18 → 19 assertions (Test 9 added).
- tests/test-approval-binding.sh: passes unchanged (Test 3's
  "binding check skipped (backward compat)" narrative is now
  partially stale — the empty-pending case is no longer a graceful-
  degradation path when the caller binds. Assertion is structural
  only, no behavioural drift; narrative cleanup deferred).
- tests/test-perimeter-closure.sh: 106/106 with new rule count.
- tests/test-human-invariants.sh: 75/75 unchanged.

Out of scope for this release:
- Audit hash chain has no parity test asserting bash- and MJS-emitted
  audit lines are byte-identical for the same event. Open finding from
  the same roster review; not addressed here because it's neither a
  one-line fix nor a regex change.
- Doctrine/website copy drift (Execution Boundary vs Contact Boundary,
  v3.2.0 vs v3.2.2 eyebrow, softened doctrine sentences). Separate
  pass.

## 3.2.1 — 2026-04-27 — Hotfix: approved-cache replay, PC tombstones, H14 pass-through, MCP E2 ordering

Five post-release bugs found in operational testing of v3.2.0 (Element E2,
Tier 2 preconfirm). All fixes land as a single hotfix. No new behaviour:
every change corrects a broken guarantee.

Bug 1 — Approved-cache replay after H15/H17 rejection:
- When check_pending_approval matched an approve callback, it seeded a
  .approved cache file before H15/H17 ran. If H15 (deliberation floor) or
  H17 (authenticity) then rejected the action, the .approved file survived.
  The next retry read the cache, returned 0 (approved), and bypassed both
  checks entirely.
- Fix: in bin/zlar-gate, the H15/H17 hard-reject path now deletes
  ${APPROVAL_DIR}/${MATCHED_RULE}-${SESSION_ID}-${action_hash:0:16}.approved
  immediately after rejection. Cache hit on a rejected action is no longer
  possible within the same session.
- Regression: test-approval-race.sh Test 8 — simulates H15/H17 rejection by
  deleting the approved file; verifies next CPA call returns 2 (fresh ask).

Bug 2 — CC Tier 2 preconfirm BLOCK/timeout not sticky:
- check_preconfirm returned 2 (not_sent) on every retry after a BLOCK or
  timeout. The pending file was deleted on BLOCK/timeout, so each new retry
  sent a fresh preconfirm card and a fresh phone ping.
- Fix: on BLOCK or timeout, lib/preconfirm-cc.sh writes a TTL-aware .blocked
  tombstone keyed pc-{rule}-{SESSION_ID}-{hash:0:16}.blocked. On PROCEED,
  writes a .acked tombstone of the same form. Future calls within TTL read
  the tombstone (return 1 for blocked, 0 for acked) without sending any card.
  Tombstones expire after ZLAR_APPROVED_TTL_S (default 300s), same TTL as
  the main approval cache.
  Action hash stored in the pending file (line 2) is verified on each poll
  to guard against hash-prefix collisions.
- Regression: test-preconfirm.sh Tests 19-23 — retry-after-BLOCK sticky,
  retry-after-timeout sticky, retry-after-PROCEED acked, expired tombstone
  ignored, hash mismatch clears pending.

Bug 3 — H14 pre-check not recognising canary_pattern_check:
- hi_pre_ask_check compared the H14 result against the literal string
  "rubber_stamping". Since Element B (v3.2.0) replaced lockout with advisory
  reasons, hi_check_response_variance returns "canary_pattern_check" instead.
  The string comparison always missed, so the pre-ask gate never fired.
- Fix: condition changed from exact-match "rubber_stamping" to "!= ok" so
  any non-ok reason (canary_pattern_check or any future reason) is surfaced.
- Regression: test-human-invariants.sh Bug 3 section — feeds 10 uniform
  decisions, verifies variance returns canary_pattern_check, then verifies
  hi_pre_ask_check surfaces it (not ok).

Bug 4 — MCP gate E2 ordering: preconfirm ran after H13/H15 accounting:
- In mcp-gate/gate.mjs the Tier 2 preconfirm fork ran after preAskCheck
  (H13 pending-queue increment) and recordAskTime (H15 floor timer start).
  A BLOCK at the preconfirm stage was already counted against H13 and had
  already started the H15 clock.
- Fix: Tier 2 preconfirm moved to before preAskCheck and recordAskTime.
  H13 does not count a preconfirm-blocked ask. H15 timer starts when the
  main ask card is sent, not when the preconfirm card is sent.

Bug 5 — VERSION file:
- Updated 3.1.4 → 3.2.1.

Schema (optional, non-breaking):
- etc/receipt-v1-payload.schema.json: escalation_source field added between
  audit_prev_hash and h15_elapsed_seconds. Type string|null; null when not
  applicable. Was emitted by the gate but not declared in the schema.

Tests:
- test-human-invariants.sh: H17 v2 fixture date changed from hardcoded
  "2026-04-26" to $(date -u +%Y-%m-%d) across 8 fixture writes. The
  hardcoded date caused the _hi_ensure_state cross-day rollover to wipe
  response_times when CI ran on UTC 2026-04-27, breaking calibration and
  producing false "suspicious" results. 75/75 now.
- Total CI-passing assertions: 1697 across 43 files (macOS), 1669 (Ubuntu, no ML-DSA-44).

## 3.2.0 — 2026-04-26 — Human-Attention Canary v1

Trustworthy delegated motion milestone. The H14 response-variance detector now
produces a tier, the tier produces visible signals, and at Tier 2 the gate
structurally interrupts before the main ask card appears. Approval without
deliberation is architecturally harder, not just flagged.

v3.2.0 is a step toward trustworthy delegated motion: persistent intelligence
moving through bounded space. Scoped authority. Reversible paths. Escalating
human attention where risk patterns persist. In short: ordinary doors open
smoothly; dangerous doors require a human; the path leaves footprints.

Human-Attention Canary v1 (D → B → A → C → E1 → E2 build order):

Element D — canary audit fields in v1 receipt schema:
- Five optional fields added to v1 payload schema: h15_elapsed_seconds,
  h15_floor_seconds, h15_below_floor, h14_alert_tier,
  h14_alert_ack_receipt_id. Inert at write time. Schema addition only;
  no gate routing change.

Element B — H14 lockout replaced with advisory reason:
- h14_lockout_until removed from both gate implementations. When H14 variance
  trips, the gate records canary_pattern_check reason and clears response_times
  in the same atomic write. No cooldown window; no self-sealing lockout.
  hi_check_approval_rate / checkApprovalRate aliases retained for external
  callers.

Element A — H15 severity-aware deliberation floor:
- warn and info decisions below the deliberation floor now signal rather than
  hard-reject. critical decisions below floor remain hard-reject (unchanged).
  hi_check_deliberation / checkDeliberation detector unchanged — returns too_fast
  for all severity classes. Only the post-response handler changed.

Element C — R012 split by effect (policy v3.2.0, 85 rules):
- R012 retired. Replaced by four rules keyed to effect:
  R012I (read, allow+log), R012W_SIGN (sign operations, ask),
  R012W_MODE (gate mode/trust-state changes, ask),
  R012W_EDIT (write/edit enforcement layer, ask).
- Closes coverage gap: zlar on/off/reset were previously unprotected.
- jq .enabled evaluation bug fixed in gate and runner.

H17 v2 — operator-calibrated authenticity:
- Ms-precision timing via last_ask_epoch_ms. Three-floor structure:
  machine-speed absolute 500ms, calibrated-critical 1500ms,
  uncalibrated 2000ms. Calibration is derived from non-critical
  response-time variance: std_dev ≥ variance floor over the minimum
  sample window earns the lower 1500ms critical floor.
  ZLAR_MIN_RESPONSE_TIME still accepted for backward compatibility.
- elapsed_ms stored per decision in response_times alongside elapsed (seconds)
  for future floor tuning. Both CC gate and MCP gate updated in lockstep.

Element E1 — visible canary tiers:
- canary_tier and canary_trip_count added to per-human state. H14 trip
  increments tier (cap 2). hi_record_decision resets tier to 0 when variance
  recovers (stddev >= 2x floor). Both gates inject tier banner into ask cards:
  ⚡ Tier 1 / 🚨 Tier 2. Banner visible to the human on every ask while elevated.

Element E2 — Tier 2 preconfirm structural interrupt:
- When canary_tier == 2, the gate sends a preconfirm interrupt card before the
  main ask card. Human taps PROCEED to see the full ask, or BLOCK to halt
  immediately. Timeout hard-denies (differs from main ask which re-sends on
  timeout).
- lib/preconfirm-cc.sh: 4-state file-based machine (0=proceed_acked,
  1=blocked/timeout, 2=not_sent, 3=waiting). check_preconfirm(rule, action_hash).
  Pending files keyed pc-{rule}-{SESSION_ID}-{hash:0:16}.pending.
  telegram_preconfirm_async sends PROCEED/BLOCK inline keyboard card.
- bin/zlar-gate: _mdv2e promoted to top-level. Tier 2 fork in deny-then-retry
  *) case: PROCEED falls through to main ask; BLOCK/timeout/waiting deny
  immediately via _skip_ask flag.
- mcp-gate/gate.mjs: telegramPreconfirm() blocking poll with mcp:pc_proceed /
  mcp:pc_block callbacks. Fork between canaryTier lookup and telegramAsk.
- scripts/zlar-tg-poll: pc_proceed / pc_block UX text in answer and edit
  switches. Routing unchanged (cc: / mcp: prefix covers preconfirm callbacks).

Fixes:
- MarkdownV2 rule name escaping: *${rule}* in ask card bold span caused HTTP 400
  on rule IDs with underscores (R012W_EDIT, R012W_SIGN, R012W_MODE). _mdv2e
  now applied at rule name site. MJS gate unaffected (post-assembly escapedText
  handles _).
- MarkdownV2 content fields: pre-escaped via _mdv2e before template assembly
  in CC gate. Removes broken post-assembly sed chain.
- Uptime streak close: last_heartbeat used as streak endpoint on disable, not
  wall clock. Inflated lifetime_on and longest_streak on idle sessions fixed.

Operational:
- LaunchDaemon plist added to repo as source of truth:
  etc/com.zlar.tg-dispatcher.plist. KeepAlive=true added. Poller now
  auto-restarts on crash. Previously the plist lived only in the archive
  and was not repo-tracked.

Tests: 238 assertions across 5 suites (preconfirm 26, human-invariants 73,
canary 25, mcp-gate 8, perimeter-closure 106). 0 failures.

## 3.1.0 — 2026-04-15 — CODE-COMPLETE

Red-team hardened. Adversarial audit, same-day fixes, canonical-form
migration, and the honest coverage model. This is the build the
presentation layer, regulatory documents, and website are written against.

Security (from red-team audit):
- Unsigned policy / standing approvals now fail-closed (was: silently loaded)
- Tampered / expired manifest now hard-denies per invariant 8 (was: silently
  downgraded to policy-only)
- Policy and standing approvals reload on mtime change (was: startup-only in
  the long-running MCP daemon — governance drift window)
- Phantom --stdio / --upstream-cmd docs removed (were: documented but
  unimplemented — documentation lied about supported modes)

Cryptographic evidence:
- Strict audit signing by default (ZLAR_REQUIRE_SIGNED_AUDIT=true on MCP).
  Gate refuses to start without a signing key. Unsigned audit entries are
  not written. The Jidoka inversion: easy to stop, hard to go.
- Every caught exception becomes a signed gate.internal_error audit event.
  Errors are evidence, not noise. An attacker who induces errors leaves
  more records behind, not fewer.
- End-of-session anchor: gate.session_sealed event on clean SIGINT/SIGTERM
  with session_id and final sequence number. Any later entry claiming that
  session is provably forged.
- Receipt schema and semantic validator accept prefixed authorizers
  (standing:<id>, gate:<reason>, human:<chat_id>) that the gate actually
  emits. Internal consistency restored.
- Receipts only minted for schema-valid outcomes. Audit-only events
  (pending, logged, diagnostics) stay in the chain but do not become
  receipts.

Canonical form migration (ADR-011):
- Three canonical forms identified and named (spec, bash-pipeline,
  bash-pretty). Spec declared authoritative.
- lib/sig-verify.mjs: multi-form Ed25519 verifier accepts all three
  forms during migration. Logs LEGACY warnings when non-spec form matches.
- bin/zlar-policy sign and bin/zlar-constitution sign now emit spec form.
- Both bash gate and MCP gate verify under spec + legacy forms.
- All four deployed artifacts (policy, standing approvals, manifest,
  constitution) re-signed under spec form. Zero LEGACY warnings at startup.

Human invariants:
- H14 (rubber_stamping) aligned to advisory on both gates. All human
  invariant pre-checks now route to the human with a warning rather than
  silencing the channel. Prevents DoS via invariant-triggered lockout.
- Novelty escalation ported to MCP gate. First use of any tool per session
  escalates allow to ask. Telegram message shows "First use this session"
  banner.

Coverage model (ADR-010):
- Interception coverage model stated in README and ADR. Every guarantee
  applies to intercepted actions. The project names its own boundary before
  anyone else frames it as a gotcha.

Test fixtures:
- mcp-gate/test.mjs signs TEST_ALLOW_POLICY under spec form at runtime
  with an ephemeral Ed25519 keypair. No dependency on machine-specific
  signing keys.
- mcp-gate/test-fail-closed.mjs: 21 assertions covering unsigned policy,
  unsigned SA, tampered manifest, strict audit signing, deployed-artifact
  verification, and test-fixture signing path.
- --policy-pubkey CLI flag added so tests can point the gate at a
  test-specific pubkey without mutating etc/keys/.

Operational:
- ~/.zlar-signing.pub regenerated (was missing; SIGNING_KEY_ID showed
  'unknown' in audit entries).
- docs/phase-b-gate-hunks.md: hand-apply guide for the four bash gate
  verification hunks (R041 correctly blocks agent modification of the
  enforcement layer).

## 3.0.7 — 2026-04-15

zlar lock — intentional fail-closed before stepping away.

'zlar lock' sets ~/.claude/.gate-locked. The gate hard-denies all agent
actions with no Telegram routing and no policy evaluation — the agent
cannot act at all until 'zlar unlock' is run. No sudo required. Works
from any terminal at the keyboard.

Differs from 'zlar off' (which allows everything for maintenance) and
from the normal ON state (which routes decisions to Telegram). Lock is
the third state: gone but not permissive.

'zlar status' shows the lock flag and resolved gate state prominently.
'zlar on' clears the lock as well as the off flags.
'zlar help' now lists on/off/lock/unlock under a Gate control section.

## 3.0.6 — 2026-04-15

Human authority over throughput pressure — gates advise, humans decide.

H6 (daily cap) is now advisory. When the cap is reached, a Telegram notice
fires and the gate routes the ask anyway. The human decides whether to
continue. This matches the H13 treatment from v3.0.5. Only H14
(rubber-stamping detection) still blocks — it protects decision quality, not
throughput.

Risk-weighted H6 counting: each decision costs max(10, risk_score)/100
weighted units toward the daily budget. A risk-100 action costs 1.0 unit
(same as the old integer count). A risk-10 action costs 0.10. Low-risk
housekeeping consumes far less budget than high-risk one-shot actions.

Telegram approval messages improved:
- Context line: shows .description from Bash tool_input — why the agent
  ran the command, not just what it ran.
- Verify line: policy-authored check prompt. 23 ask-action rules now carry
  a specific question ("what file is being deleted?", "will this expose
  credentials?", etc.) that appears in the approval message on mobile.
  Helps the human know what to look for before tapping approve.

Both CC gate and MCP gate updated for all of the above.

Cross-gate adapter install script (adapters/claude-code/install.sh):
- Stamps ~/.claude/zlar-gate.sh with the correct PROJECT_DIR at install time
- Wires settings.json PreToolUse hook idempotently via Python3
- Checks /usr/local/bin/zlar symlink
- Fixes the silent break when the repo is moved or used on a second machine

## 3.0.4 — 2026-04-12

Structural fixes from false-positive analysis and simulation testing.
Two detectors caused false escalation to at_risk during normal human-
agent interaction, making ZLAR feel slow instead of fast. Three
structural changes prevent the cascade pattern from recurring.

Structural:
- Convergence rule: a single high-scoring detector can only push trust
  state to degraded, never to at_risk or suspended. at_risk and
  suspended now require 2+ detectors with signals above the convergence
  floor (degraded threshold). Previously: action_silence alone at score
  1.0 could push straight to at_risk. This was the root cause of the
  false positive cascade.
- Degraded is now visible: Telegram notification sent on degraded
  transition with informational headline ("watching, not slowing down").
  Previously: degraded only escalated to "log" which the human never
  sees. Now the human knows something is off without being interrupted.
- Activity window fix: action-silence detector now segments the trace
  into contiguous activity windows (split at 15-minute gaps). Only gaps
  WITHIN a window are analyzed. Gaps BETWEEN windows are human-absence
  (cleaning house, eating, meetings), not agent-silence. Previously:
  the detector treated the entire session span as one continuous period
  and flagged every human pause as pathological.

Calibration:
- action-silence: 15-minute absolute floor. Ratio threshold 5x to 20x.
  Score cap 50x to 200x. Window-scoped analysis.
- abnormal-burstiness: read-only domains (read, glob, grep) excluded
  from CV calculation. CV threshold 2.0 to 4.0. Burst clusters (500ms)
  unchanged.

UX:
- Telegram ask messages show restore escalation banner when Agent Health
  overrides policy. "Escalated by Agent Health (trust state: X)" so the
  human knows the source.
- Telegram health notifications now include active_detectors count and
  state-specific headlines (degraded = watching, at_risk = slowed,
  suspended = blocked).

Fix:
- Trust state reset to healthy after false positive. Evaluation history
  cleared.

Tests: 129 restore assertions (91 Node + 38 shell), 0 failures.
  8 new tests: convergence rule (single detector caps at degraded,
  multi-detector reaches at_risk), active_detectors in aggregate,
  human-absence window splitting, sub-15-min within-window gaps,
  read-heavy explore patterns, write bursts still caught.

## 3.0.3 — 2026-04-11

Post-unification hardening. Privacy invariant, health toggle UX, approval
latency fix, key permissions, naming cleanup.

Security:
- HMAC key files restricted to 0600, keys directory to 0700. Previously
  world-readable (0644). Caught in security audit.
- Shell injection fix in zlar-restore CLI: session_id and reset reason now
  passed via environment variables instead of string interpolation into
  Node -e strings. Defense-in-depth (CLI is operator-facing).
- R012BR policy fix: ZLAR reporting tools (zlar-digest, zlar-brief,
  zlar-audit, zlar-restore) now allowed to read audit files. Previously
  blocked by R012B which couldn't distinguish read from write.

Privacy:
- Privacy invariant on zlar-restore CLI. Four commands (evaluate, status,
  reset, history) now check enabled flag before accessing behavioral data.
  When Agent Health is disabled, CLI prints "not enabled" and exits.
  Enforces the unified-line contract: health off means no behavioral
  data access, period.

UX:
- New command: zlar health on/off/status. Single command to enable Agent
  Health (generates HMAC keys if missing, sets enabled, signs config).
  Idempotent — safe to run twice. Replaces the 3-step manual procedure.
- Renamed bin/zlar-health to bin/zlar-doctor. Clears namespace collision
  with the new zlar health subcommand.

Data quality:
- SEQ-005 fix: approval latency pairing now works. The digest and
  audit-reader looked for outcome "pending" but the CC gate writes
  "ask_pending". Readers now match both. Also removed stale seq==1/seq==2
  filter that assumed per-event-type sequence numbering (CC gate uses
  per-action-chain seq). 45 approval latencies now measurable from
  existing audit data.

Tests: 122 restore assertions (84 Node + 38 shell), 0 failures.

## 3.0.2 — 2026-04-11

Continued hardening. Config integrity, 7th detector, anti-evasion improvements.

Security:
- Config integrity HMAC (RESTORE-INV-12). Separate key signs restore-config.json
  via sidecar file. Tampered or unsigned config forces fail-closed: restore ON,
  all escalations forced to deny, Telegram alert. The attacker who disables
  restore gets maximum escalation instead.
- Diffuse weight jitter: the L2 aggregation weight is now jittered +/-10% per
  evaluation, matching threshold jitter. Removes the last stable target for an
  agent distributing pathology evenly across detectors.
- Separate HMAC key support: trust-state and evaluation-history can use
  independent HMAC keys (trust_state_hmac_key, evaluation_history_hmac_key
  in config). Shared key still works as fallback. Compartmentalization.

Detection:
- New detector: action-silence. Detects unusual gaps in agent activity within
  active sessions. Compares longest mid-session gap against session median
  interval. End-of-session gaps excluded (normal). 7 detectors total (was 6).

CLI:
- New command: zlar-restore sign-config. Signs restore-config.json after edits.

Invariants: 12 (was 11). New: RESTORE-INV-12 (config integrity, fail-closed).
Tests: 122 restore assertions (84 Node + 38 shell), 0 failures.

## 3.0.1 — 2026-04-11

Agent Health hardening. Security, aggregation, and anti-evasion improvements.

Security hardening:
- HMAC-SHA256 integrity on trust-state file. Tampered file treated as degraded
  (RESTORE-INV-09). Opt-in via etc/keys/restore-hmac.key.
- HMAC integrity on evaluation history file. Tampered history treated as empty
  (conservative: slowing-down detector does not fire).
- Detector reliability signal: 2+ crashed detectors in one evaluation triggers
  degraded regardless of scores. Closes detector-crash evasion vector.
- Bounded audit trail reads: trigger and CLI read in 64KB reverse-read chunks,
  capped at 500 events. Prevents OOM on long-running systems (RESTORE-INV-11).
- Pending evaluation marker: gate writes marker before background trigger,
  floor to degraded during evaluation window (30s). Closes temporal gap.
- Threshold randomization: +/-10% jitter per evaluation. Agent cannot predict
  exact thresholds (RESTORE-INV-10).

Aggregation:
- Dual-path scoring: dominant (max weighted) + diffuse (L2 norm / sqrt(N)).
  Five detectors at 0.25 each now triggers degraded. Catches distributed
  pathology that MAX alone missed.
- Type-aware Telegram routing: each detector maps to a syndrome name and
  human-actionable advice in the notification.
- Critical slowing down: evaluation history ring buffer (8 entries) with
  lag-1 autocorrelation. Rising autocorrelation tightens sensitivity.

Detection:
- New detector: entropy-shift. Measures Shannon entropy change rate of
  action domain distribution. Sharp narrowing or scattering both score.
  Self-referencing baseline (session's own earlier behavior).
- 6 detectors total (was 5).

CLI:
- zlar-restore evaluate now shows dual-path scores and primary signal.
- CLI reads bounded audit trail (same as trigger).
- CLI sets HMAC key for evaluate and reset commands.

11 invariants total (was 8). New: RESTORE-INV-09 (integrity),
RESTORE-INV-10 (anti-evasion), RESTORE-INV-11 (bounded reads).

## 3.0.0 — 2026-04-12

ZLAR 3.0: Agent Health (restorative governance subsystem).

Adds behavioral observation alongside deterministic enforcement.
Five detectors evaluate session traces and produce a trust state
(healthy / degraded / at_risk / suspended). The gate consults the
trust state and may escalate actions to human review. Ships disabled
by default. Gate behaves identically to 2.x when restore is off.

ZLAR 2.x remains a valid endpoint for users who want strong deterministic
enforcement without restorative governance. ZLAR 3.x extends, rather than
invalidates, that model.

### Agent Health subsystem

- Monotone trust-state machine: healthy -> degraded -> at_risk -> suspended.
  State can only worsen. Reset to healthy requires human action with friction
  (reason, delay, signed event, daily limit).
- 5 detectors: contradiction_increase, escalation_under_ambiguity,
  source_grounding_loss, abnormal_burstiness, authority_widening.
- Evaluation engine aggregates detector scores with configurable thresholds.
- Background trigger fires on deny/novelty/high-risk events, evaluates
  session trace non-blocking, updates trust state, sends Telegram notification.
- CLI: zlar-restore (evaluate, status, reset, history, detectors).
- 8 invariants documented in docs/RESTORE-INVARIANTS.md.

### Gate integration

- lib/restore.sh sourced by gate, error-trapped (INV-04: cannot crash gate).
- Step 9c escalation check: if trust state is degraded or worse, may
  escalate allow/log to ask or deny based on configurable mapping.
- Zero-risk when disabled: all code paths short-circuit on enabled=false.

### Test coverage

- 90 new assertions (38 shell + 52 Node.js).
- 6 trace fixtures (healthy + 5 pathological patterns).
- Total: 1171 assertions across 32 test files, 0 failures.

## 2.11.2 — 2026-04-12

Path B Phase 1 hardening.

- session_state_init verifies existing state files against audit seal,
  rebuilds on staleness.
- Five early-return paths in gate main() now seal before returning.
- 7 new test assertions. Full suite green.

## 2.11.1 — 2026-04-11

Score recalibration build: consequence-first messages, novelty detection,
session-scoped digest, and dotfile perimeter closure.

### Consequence-first Telegram messages

Every gate escalation now includes an "if wrong:" line showing the
worst plausible outcome. SubagentStart messages carry an authority-type
marker: "Authority envelope (not a single action)." Both CC gate (bash)
and MCP gate (Node) updated. 19 rule families covered with fallback.

### Novel action detection

First use of an MCP server or webfetch in a session escalates allow→ask.
MCP novelty tracked per server (not per tool). One-time review with a
training banner; subsequent calls to the same surface proceed normally.
Session-level tracking in var/log/sessions/.seen-domains files.

### Session-scoped governance digest

zlar-digest now supports --session and session-summary commands. Output
includes activity narrative: writes/edits grouped by directory, bash
grouped by command prefix, novelty escalation count. Scope label adapts
to session vs period mode.

### Dotfile perimeter closure

Six new policy rules close write/edit domain gaps
identified during score recalibration.

### What was missing

Write-domain rules (R031-R034) protected shell configs and .env files but had
no coverage for .ssh/ writes, nor for credential-adjacent dotfiles (.gitconfig,
.npmrc, .aws/, .kube/, .docker/config.json, .netrc). Edit-domain rules had
no mirrors for any of these — an agent using the Edit tool (not Write) to
modify .zshrc, .env, or .aws/credentials would fall through to R042 (allow).

### New rules

- R035: Write to .ssh/ — blocked. Consistent with R040 (edit .ssh → deny).
  Covers authorized_keys injection, config poisoning, private key writes.
- R035B: Write to credential-adjacent dotfiles — ask. .gitconfig, .npmrc,
  .pypirc, .pip/, .aws/, .kube/, .docker/config, .netrc.
- R033E: Edit to /etc/ — blocked. Mirrors R033 (write /etc/ → deny) for the
  edit domain.
- R041H: Edit shell config files — ask. Mirrors R034 for edit domain.
  Covers .zshrc, .bashrc, .bash_profile, .profile, .zprofile.
- R041I: Edit .env files — ask. Mirrors R031 for edit domain.
- R041J: Edit credential-adjacent dotfiles — ask. Mirrors R035B for edit domain.

Rule count: 74 → 80. Policy re-signed. Test assertion updated.

## 2.11.0 — 2026-04-11

DWP-01 (Deny Wins Precedence): close three instances of the downgrade pattern
found during the April 11 bug hunt, where a weaker evaluation path silently
overrode a stricter one.

### Engine divergence now fails strict

When ZLAR_POLICY_ENGINE=both and the JSON and Cedar engines disagree, the
stricter result now wins (deny > ask > allow). Previously JSON was primary
and Cedar was advisory — a JSON allow could override a Cedar deny.

### v0 receipt verification now runs semantic validation

verifyReceipt() (v0 path) previously checked structure and Ed25519 signature
only. It now calls validateSemantics() after signature verification, matching
the v1 path. Catches rule-outcome violations (deny-only rule claiming allow)
and authorizer-outcome violations (policy authorizer claiming authorized).
Existing valid receipts with sound semantics are unaffected.

### DWP-01 invariant added

New cross-path invariant in GOVERNANCE.md and MANIFEST-INVARIANTS.md: when
two evaluation paths exist, the path with fewer checks must either be removed
or must produce deny on any divergence from the stricter path.

### emitEvent synchronous design documented

The MCP gate emitEvent function is intentionally synchronous — crash handlers
rely on it completing before process.exit(). Comment block added explaining
why and when a mutex would be needed.

## 2.10.1 — 2026-04-11

Three bugs found live during the April 10 evening session, fixed before
turning the gate back on.

### Replay protection lockout fixed (CRITICAL)

The manifest replay check used `<=` (less-than-or-equal), which hard-denied
every gate invocation after the first within a session. The manifest sequence
doesn't change between tool calls — the same manifest loads every time. After
Telegram approval, the retry presented the same sequence the original call
already persisted, triggering invariant 10 and locking out all subsequent
tool calls.

**Fix:** Changed to strictly less-than (`<`). Same-sequence reload is normal
operation. Lower-sequence reload (actual rollback) still hard-denies.
MANIFEST-INVARIANTS.md updated to match.

### R012 false positive on read-only commands fixed

R012 pattern-matched on ZLAR file paths regardless of whether the command
read or wrote. A `cat` or `python3 -c open(...)` on audit.jsonl triggered
score-100 Telegram escalation for a read-only operation.

**Fix:** Added rules R012R and R012BR before R012 and R012B respectively.
These use `compound_guard` to match read-only command prefixes (`cat`, `head`,
`tail`, `grep`, `stat`, etc.) combined with ZLAR path patterns. Read-only
access is allowed with audit logging. Write-intent commands still route to
R012 (ask human) or R012B (hard deny). First-match-wins ordering ensures
correct precedence.

### Lockout recovery hint added

When the gate locks out (manifest hard-deny or human capacity exhaustion),
the deny message now includes: "To recover: run 'zlar off' from your
terminal." Previously, a locked-out user had no documented escape path
visible in the error output.

## 2.10.0 — 2026-04-10

Eight findings from the third multi-agent design review, fixing security bugs,
correctness gaps, and a self-sealing lockout. Discovered by nine specialist
agents (paradox hunter, game theorist, edge case analyst, interaction effects,
Goodhart auditor, temporal analyst, information theorist, formal verifier,
red team) running against v2.9.0 code.

### Inbox forgery hardening (CRITICAL — complete governance bypass closed)

A misaligned agent running as the same Unix user as the gate could forge
Telegram approval callbacks: read the HMAC secret (group-readable), compute
a valid HMAC, write a forged callback to the inbox directory (user-writable).
The human never sees the request. Complete bypass of the governance loop.

**Fix — three layers:**
- `oc/bin/zlar-tg-boot.sh`: inbox directories changed to `root:staff 750`
  (agent cannot write). HMAC secret changed to `root:wheel 600` (only
  dispatcher can read). The agent can no longer create files in the inbox.
- `bin/zlar-gate`: callback files are no longer deleted by the gate (it
  can't write to root-owned dirs). Consumed callbacks tracked in
  `var/log/.consumed-callbacks` to avoid re-processing. HMAC verification
  is now advisory — primary trust is directory ownership.
- Immediate: `sudo chown root:staff /var/run/zlar-tg/inbox/cc` +
  `sudo chmod 750` on existing installations.

### Manifest failure modes enforce hard deny (SERIOUS × 5)

MANIFEST-INVARIANTS.md documents that expired, tampered, replayed, and
deleted manifests produce hard deny. The code fell through to policy-only
mode for all four, plus silently accepted a signed manifest when the public
key file was missing. Five distinct bypass paths to strip the manifest's
capability ceiling.

**Fix:** Flag-based approach — manifest loading (lines 280-370, before
function definitions) sets `MANIFEST_HARD_DENY_REASON`. The flag is checked
at the top of `main()` where `respond_deny` and `emit_event` are available.
All five failure modes now produce: audit event + hard deny + return. No
policy-only fallback.

Cases now hard-denied:
- Expired manifest (invariant #6)
- Tampered manifest / bad signature (invariant #8)
- Rolled-back manifest / seq < last (invariant #10, tightened in v2.10.1)
- Deleted manifest with seq file present (invariant #9a)
- Signed manifest with missing public key (new — key deletion attack)

### H14 self-sealing lockout fixed (CRITICAL)

Once H14 (rubber-stamping variance check) fired, it blocked all new asks.
No asks → no decisions recorded → response_times never changes → H14 stays
fired until midnight UTC. Up to 24 hours of unrecoverable governance lockout.

**Fix:** Reset + cooldown. When H14 fires: clear `response_times` to `[]`,
set `h14_lockout_until = now + 300` (5-minute cooldown). After cooldown,
response_times is empty, min_sample check fails, H14 returns ok. Human
starts fresh. One state field (`h14_lockout_until`), backward compatible.

### Policy routing fixes

- **"log" action escaped manifest escalation.** The manifest override at
  line 1867 only caught `allow`, not `log` (functionally equivalent). A
  policy rule with `action: "log"` in an unmatched manifest category
  proceeded without human review. Fixed: manifest escalation now catches
  both `allow` and `log`.
- **Strict audit mode allowed without audit.** When
  `ZLAR_REQUIRE_SIGNED_AUDIT=true` and `emit_event` failed, the allow
  path continued — action executed with no audit record. Fixed: if
  emit_event fails in strict mode, the allow is converted to deny.

### Atomic writes in human-invariants.mjs

`writeFileSync` is not atomic — crash mid-write produces partial JSON that
breaks all subsequent `loadState` calls. Changed to `writeFileSync` to
temp file + `renameSync` (POSIX atomic rename), matching the pattern
already used in `human-invariants.sh`.

### Not in this release

- **State file integrity (var/ directory).** The game theorist identified
  that all files in `var/` (human state, canary, session, watchdog) lack
  HMAC/signature protection. An agent with filesystem access can poison
  every human invariant. Architectural fix needed — HMAC on write or
  derive mutable state from the immutable signed audit trail.
- **`last_ask_epoch` per-ask.** H15/H17 deliberation time is measured
  against a single scalar, but H13 allows 5 concurrent pending asks.
  Needs per-ask timestamps keyed by action_hash.
- **Score recalibration.** Risk score operates at 21% of channel capacity
  (1.4 bits of 6.66 possible). 73% of escalations carry score 60
  (hardcoded manifest constant). Dynamic per-instance scoring deferred.
- **Consequence-first Telegram messages.** 99.6% approval rate across 483
  decisions. Messages describe what the agent does, not what goes wrong.
- **Timestamp monoculture.** H14/H15/H17 all operate on wall-clock time.
  Non-temporal signals needed (complexity-correlated, decision-outcome).
- **NaN divergence.** Same corrupted input produces opposite outcomes in
  .sh (false-fires H14) vs .mjs (silently passes). Needs unified handling.
- **State file race conditions.** No locking on macOS. Concurrent sessions
  can lose increments. Needs advisory locking strategy.

---

## 2.9.0 — 2026-04-10

Three security hardening items and one behavioral fix, all discovered during
multi-agent design review (April 10, 2026). No incident — proactive.

### Gate security hardening (`bin/zlar-gate`)

Three attack surfaces the v2.8.0 sequence field opened or left unaddressed:

**Deletion attack detection.** Previously, a missing manifest file silently
fell back to policy-only enforcement. An attacker who can delete the manifest
file could strip the capability ceiling from all gate decisions. Now: if the
manifest file is absent but the seq file exists (proof the manifest was
previously loaded), the gate hard-denies everything and sends a Telegram
alert. Policy-only fallback is preserved only when the seq file is also
absent (genuine first-run or never-configured state).

**Replay protection.** The manifest's `sequence` field is now enforced
monotonically. On each successful manifest load, the gate persists
`_m_seq` to `${PROJECT_DIR}/var/.manifest-seq`. On the next load, any
manifest with `sequence ≤ last_seq` is rejected with hard deny. An attacker
who replaces a renewed manifest with an older copy gets hard-denied
immediately.

**Seq file poisoning.** Writing a large number (e.g., `99999`) to the seq
file permanently DoS's all future manifest loads — worse than the replay
attack it was designed to stop. Gap detection added: if `sequence − last_seq
> 100`, the gate logs a critical event, sends a Telegram alert, resets
`last_seq = 0` (self-healing), and continues. The threshold of 100 is
intentionally large — it fires only on clearly pathological jumps, not on
normal re-signs.

**Presence file eliminated.** The former `.manifest-present` sentinel file
was redundant with the seq file (both existed iff the manifest had ever been
loaded). Dropped. The seq file now serves both purposes: presence detection
and replay counter.

### SubagentStart auto-allow tightened (`bin/zlar-gate`)

`agent_type` values `general-purpose` and `claude-code-guide` removed from
the auto-allow list. Both have full tool access; auto-allowing them created
an `agent_type` spoofing path — a subagent could declare either type to
bypass the gate with zero friction. The auto-allow list is now `Explore|Plan`
only. Both are read-only by construction. Any other agent type routes through
the standard risk-scoring path.

### zlar-manifest: sequence auto-increment (`bin/zlar-manifest`)

`zlar-manifest new` (and re-sign) now reads `.sequence` from the input
manifest, increments it, writes it back, then signs. This means routine
renewal never resets the replay counter. Operators do not need to manually
maintain the sequence field. Output now displays `Sequence: N`.

### H14 replacement: response time variance (`lib/human-invariants.sh`, `lib/human-invariants.mjs`)

Both gates updated in lockstep. This completes the item deferred in v2.8.0.

The root failure of approval rate monitoring: a well-calibrated gate that
filters correctly produces high approval rates as a natural consequence. The
old H14 penalized correct behavior. There is no threshold that distinguishes
"high approval because the gate is too permissive" from "high approval
because the gate is exactly right."

Response time variance is a better signal. A rubber-stamper responds
uniformly fast regardless of request complexity. A genuine deliberator shows
variable response times correlated with what's being asked. Std dev below
the floor means suspiciously uniform — that's what H14 now detects.

**What changed:**
- `hi_check_approval_rate` / `checkApprovalRate` → `hi_check_response_variance`
  / `checkResponseVariance`. Backward-compat aliases kept at both call sites.
- State field `response_times` now stores `{elapsed, severity}` pairs instead
  of plain elapsed numbers. Backward compat: plain number entries in existing
  state files are handled at read time.
- Variance computed on **warn + info decisions only**. Critical decisions are
  excluded because H15's 30-second deliberation floor creates artificial
  uniformity on critical — including them would fire H14 against exactly the
  careful behavior H15 is designed to produce.
- New config keys: `HI_VARIANCE_STDDEV_FLOOR` (default 4s), `HI_VARIANCE_WINDOW`
  (default 20), `HI_VARIANCE_MIN_SAMPLE` (default 10). Old keys
  `HI_APPROVAL_RATE_THRESHOLD` / `HI_APPROVAL_RATE_WINDOW` removed.

### Not in this release

- **Score recalibration.** The current risk score conflates severity
  (technical category) with actual risk (`P(harm) × magnitude ×
  irreversibility`). The calibration problem causes desensitization — scores
  cluster in the 30–70 range on routine operations, eroding the signal value
  of a genuine 90 or 100. Score formula redesign deferred; architectural
  decision in progress.
- **Plain English consequence descriptions.** Telegram messages describe
  what the agent is doing, not what happens to the human if it goes wrong.
  Adding consequence-first language deferred alongside score recalibration
  (the two interact).
- **Maintenance window governance.** Three modes identified (surgical
  suspension, shadow mode, sovereign lock) but not yet implemented.

---

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
