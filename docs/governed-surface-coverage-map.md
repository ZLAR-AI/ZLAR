# Governed Surface Coverage Map

*Part of ZLAR's first design, the checkpoint that sits next to the AI, which is no longer the direction. ZLAR's current design, the force field, is in [cyan/](../cyan/). Start with the [README](../README.md) and [PROPOSITION.md](../PROPOSITION.md).*

`zlar coverage` builds a fixture-input coverage map for supplied action-surface
evidence. It does not probe the local machine, inspect live hooks, read live
audit stores, or claim live deployment coverage.

Use it to check whether supplied evidence describes a governed boarding lane.
In the airport model:

- An action surface is a boarding lane.
- Routing is the checkpoint path.
- A Worker Receipt is the boarding credential.
- Downstream refusal is the aircraft door refusing unrecognized boarding.

## Run The Example

Fast committed-fixture smoke commands:

```bash
bin/zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --sample
bin/zlar coverage --sample
bin/zlar coverage --sample --json
```

These commands only verify or map committed fixture inputs and sample reports;
they do not generate a fresh authority-requiring effect. They are not live
probing, live MCP coverage, current-machine governance, production deployment,
external attestation, sovereign recognition, or unrouted-surface coverage.
For `v3.3.76+` reviews, preserve the smoke active-profile counts
`active_profile_selection_verified=true`, `active_profile_selected=true`,
`active_profile_selects_latest=false`,
`active_profile_live_runtime_profile_checked=false`, and
`active_profile_persistent_runtime_profile_installed=false`, plus the embedded
proof-pack `active_profile_selection` summary. That is fixture-contained
selection evidence only; it is not persistent runtime profile installation,
hook activation, live/current-machine profile state, production authority, or
external attestation.
For `v3.3.81+` reviews, also preserve the disposable installed-profile counts
`runtime_profile_installation_applied=true`,
`runtime_profile_installation_request_authority_guard_refused=true`,
`runtime_profile_installation_selects_latest=false`,
`runtime_profile_installation_persistent_profile_installed=false`, and
`runtime_profile_installation_hook_configuration_written=false`. These fields
prove only the committed disposable proof-root fixture path, not persistent
install, hook activation, live/current-machine profile state, production
authority, or external attestation.
For current fixture reviews, `coverage --sample` must report `4/6` governed
counted lanes. Bash, MCP, service-profile, and runtime-local remain governed.
Runtime profile-installation and installed terminal-chain remain counted but
must report `receipt_not_capable` because their current governed posture needs
fixture-rightful authority and the exact one-use fixture grant is exhausted.
For `v3.3.91+` reviews, also preserve the service-profile coverage lane as a
counted governed fixture lane before treating the coverage-map evidence as
complete.
The service-profile lane proves only the committed local disposable
service-profile preflight artifact: a
launcher-owned-config service path accepts one recognized `records.write`
receipt and refuses replay, missing, unrecognized, invalid, unknown-issuer,
stale, request-stream authority-material, no-receipt direct API, and
direct-API-with-receipt attempts before service-state mutation. For
`v3.3.93+` reviews, also preserve the wrong-policy refusal with
`policy_not_recognized` and zero service-state mutation. It is not runtime
activation, persistent profile install, live/current-machine governance,
production service deployment, external attestation, sovereign recognition, or
unrouted records-path coverage.
For `v3.4.15+` reviews, also preserve the installed-runtime-profile terminal
chain proof and artifact verification: generated installed-root preflight,
generated preflight consumption by the service proof, generated service-proof
artifact verification, proof/artifact hash binding, one recognized
`records.write` boarded, missing and invalid receipts refused before mutation,
all 18 selected-profile refusal cases refused before mutation, and false
persistent install, activation, hook/user/machine configuration,
current-machine governance, production downstream recognition, enterprise
readiness, external attestation, sovereign recognition, and unrouted records
coverage flags.
For `v3.4.18+` reviews, also preserve the service-proof artifact-verification
refusal taxonomy SHA-256 so artifact verification binds exact selected-profile
case ids, reason codes, and before-mutation facts, not just refusal counts.
For `v3.4.19+` reviews, also preserve the installed-runtime-profile
recognition-contract SHA-256 across preflight, service proof, service-proof
artifact verification, terminal chain, and terminal-chain artifact verification
so the proof path cannot swap the recognized contract behind matching
profile/taxonomy counts.

```bash
bin/zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json
bin/zlar coverage --sample
```

Print the full JSON report:

```bash
bin/zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json --json
bin/zlar coverage --sample --json
```

Fail nonzero if any counted lane is not governed. With the current committed
fixture, both commands intentionally fail because the two authority-dependent
historical lanes are demoted:

```bash
bin/zlar coverage --input tests/fixtures/governed-surface-coverage-map-v1-input.json --require-governed
bin/zlar coverage --sample --require-governed
```

Use stdin instead of a file:

```bash
bin/zlar coverage --input - --json < tests/fixtures/governed-surface-coverage-map-v1-input.json
```

`--sample` reads the committed fixture at
`tests/fixtures/governed-surface-coverage-map-v1-input.json` without requiring
callers to supply the path. It is still fixture-input evidence and does not
probe live hooks, live audit stores, or live MCP coverage. The committed sample
currently counts four governed fixture lanes:

- `bash.pre_tool_use`
- `mcp.tools_call`
- `protected-records.service-profile.records.write`
- `protected-records.runtime.records.write`

It also counts two historical fixture lanes as non-governed
`receipt_not_capable` evidence:

- `protected-records.runtime.profile-installation.records.write`
- `protected-records.installed-runtime-profile.terminal-chain.records.write`

The protected-records service-profile lane is derived from the committed
service-profile preflight artifact. It is local disposable fixture evidence:
the map checks artifact integrity, launcher-owned config routing, the
downstream recognition boundary, one recognized `records.write` acceptance, and
refusal before service-state mutation for replay, missing, unrecognized,
invalid, unknown-issuer, wrong-policy, stale, request-stream authority-material,
no-receipt direct API, and direct-API-with-receipt cases.

The protected-records runtime lane is derived from the committed
runtime-local-activation artifact. It is local disposable fixture evidence: the
map checks the artifact integrity boundary, explicit plan/profile SHA match,
profile SHA
`e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469`,
and the exact
`receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation`
route. The report keeps 18 receipt/recognition refusals separate from five
authority-grant refusals, and keeps same-process signed-payload replay refusal
separate from restart consumed-grant refusal. It also projects the persistent
single-use authority-grant-contract SHA-256 store, grant-contract consumption
identity, signed-payload replay identity, and launcher-owned local witness.
The local-activation artifact satisfies the fixture grant effect, but does not
itself carry an explicit rightful-issuance-path claim; the map therefore keeps
`fixture_rightful_issuance_path_evidenced=false` for this lane.

The protected-records runtime profile-installation lane is derived from the
committed disposable runtime-profile-installation artifact. It is local
disposable fixture evidence: the map checks the artifact integrity boundary,
the same exact profile SHA and recognition-then-authority-grant route,
launcher-owned disposable install root, profile copy, active index write,
explicit id/SHA profile selection, 18 recognition refusals, five authority-
grant refusals, both replay identities, and request-authority guard refusal.
Its supplied artifact preserves a historical named local-fixture
rightful-issuance assertion, but it does not bind an authority-grant contract
identity to the shared source status. The map therefore keeps the historical
assertion visible while forcing current
`fixture_rightful_issuance_path_evidenced=false`, `receipt_capable=false`, and
`governed=false`. It does not select `--latest`, install a persistent profile,
or write hook/user/machine configuration.

The protected-records installed-runtime-profile terminal-chain lane is derived
from the committed terminal-chain artifact. It is local disposable fixture
evidence: the map checks generated-root preflight consumption, selected service
proof and service artifact binding, the same exact profile SHA and
recognition-then-authority-grant route, one boarded `records.write` receipt,
18 recognition refusals before mutation, and five authority-grant refusals
before grant consumption and mutation. It separately binds signed-payload
replay and consumed-grant replay identities, the persistent single-use grant
store, grant-contract SHA-256 consumption identity, launcher-owned witness,
and exact terminal-chain trusted-registry local refusal IDs/reasons. The map
also preserves observed grant-burn windows, witness-ahead rollback refusal,
the open joint store/anchor/witness rollback side door, and the open host-path
time-of-check/time-of-use side door. Those topology and refusal facts remain
visible after governance demotion.

That terminal-chain evidence binds one launcher-owned logical-fixture target:
the request target handle is assertion-only, the boarded service receipt detail
hash binds the target handle with the record update, and the accepted
state-effect summary is hash-bound. It does not prove profile-wide, per-run,
physical, or live target authority. The separate synthetic registry-evidence
receipt supplies only the generation-time signature-valid and issuer-recognized
summary; it is not the boarded service receipt, did not authorize the write, and
has a distinct detail hash. Neither receipt role alone proves rightful
issuance. The separate public grant contract, appointment, issuance decision,
authorized update, one-use effect, and evaluation-time window memorialize one
historical fixture crossing. Source status records the exact contract as
exhausted with one recorded use, no fresh effect, invalid repeated-use
provenance, and no replacement grant. The map does not trust the artifact's
embedded positive as current authority: it forces current fixture-rightful,
receipt-capable, and governed false. Generic and portable rightful issuance,
live authority, production rightful issuance, current-machine governance, and
consequence lifecycle closure also remain false.

The JSON report also emits derived airport-map summaries for each surface:
`coverage_summary`, `last_decision`, `last_receipt`, `issuer_identity`, and
`known_boundaries`. For counted lanes, the text summary names the latest
supplied decision outcome, receipt verification status, and issuer or
recognition-anchor identifier. These are summaries of supplied evidence, not
live discovery.

## Assemble Bash Evidence

`zlar coverage-evidence bash` assembles supplied, event-scoped evidence for one
bash `PreToolUse -> zlar-gate` lane. It does not choose the latest event, does
not probe the local machine, and does not inspect live hook or audit stores.

Run the sanitized example fixture:

```bash
bin/zlar coverage-evidence bash --input tests/fixtures/bash-gate-coverage-evidence-v1-input.json --event-id bash-fixture-event-001
```

Pipe the assembled coverage input into `zlar coverage`:

```bash
bin/zlar coverage-evidence bash --input tests/fixtures/bash-gate-coverage-evidence-v1-input.json --event-id bash-fixture-event-001 | bin/zlar coverage --input - --require-governed
```

The fixture uses fake host, user, session, policy, audit, and receipt values. It
is an example of the supplied-evidence contract, not a statement about the
current machine.

Receipt references are reference-only. A caller cannot make a lane
`receipt_capable=true` by supplying `worker_receipt_ref.valid=true`. A raw
`worker_receipt` object must validate and match the supplied event id, audit
hash, policy version, and bash-gate surface evidence.

## Assemble MCP Evidence

`zlar coverage-evidence mcp` assembles supplied, event-scoped evidence for one
MCP `tools/call -> mcp-gate` lane. It does not choose the latest event, does
not probe the local machine, and does not inspect live MCP configuration, hooks,
or audit stores.

Run the sanitized example fixture:

```bash
bin/zlar coverage-evidence mcp --input tests/fixtures/mcp-gate-coverage-evidence-v1-input.json --event-id mcp-fixture-event-001
```

Pipe the assembled coverage input into `zlar coverage`:

```bash
bin/zlar coverage-evidence mcp --input tests/fixtures/mcp-gate-coverage-evidence-v1-input.json --event-id mcp-fixture-event-001 | bin/zlar coverage --input - --require-governed
```

The fixture uses fake host, user, session, policy, audit, MCP route, and receipt
values. It is an example of the supplied-evidence contract, not a statement
about the current machine, live MCP coverage, or all MCP tools.

Receipt references are reference-only. A caller cannot make a lane
`receipt_capable=true` by supplying `worker_receipt_ref.valid=true`. A raw
`worker_receipt` object must validate and match the supplied event id, audit
hash, policy version, and MCP-gate surface evidence.

Direct upstream MCP evidence, extra MCP server registration evidence, stale
heartbeat evidence, policy mismatch, missing Worker Receipt validation, or
missing downstream refusal proof fails closed when the assembled input is passed
to `zlar coverage`.

## Evaluate Downstream Recognition

`zlar downstream-recognition` evaluates one supplied signed v1 receipt against
one supplied downstream recognition rule. It prints a bounded
`downstream-recognition-rule-v1` decision JSON. It does not inspect live
downstream systems, live audit stores, or runtime configuration.

Run the sanitized example fixture:

```bash
bin/zlar downstream-recognition --input tests/fixtures/downstream-recognition-v1-input.json --require-refused
```

That fixture proves a valid signed receipt can still be refused when the
configured downstream recognition rule does not accept its policy version.

Run the hermetic fake-downstream effect proof:

```bash
bin/zlar downstream-refusal-proof
bin/zlar downstream-refusal-proof --json
```

That proof creates ephemeral issuer keys, accepts one matching signed receipt,
writes exactly one bounded fake effect marker, and proves missing, tampered,
unknown-issuer, retired-issuer, non-boarding, wrong-policy, wrong-domain,
wrong-tool, wrong-audit-event, wrong-detail, and stale receipts do not board.
It is local fixture evidence only. It is not live downstream integration,
production deployment, external attestation, sovereign recognition, or coverage
of unrouted surfaces.

Developer test harness:

```bash
node tests/test-downstream-recognition-refusal.mjs
```

Historical E1 command inventory. The two proof-generator commands and the
direct `protected-records-write` surface now fixed-refuse in current source:

Current boundary: the service-proof and service-preflight positive generators
are permanently retired in source. Service-preflight verification remains an
exact historical artifact lane. The direct service request/factory now
fixed-refuses in current checked-out source, the main dispatcher no longer
routes it, and future installer copies omit its wrapper/module. Old
installed/copied/mutated source remains a side door. Future accepted repair,
upgrade, and reinstall source now plans exact stale-wrapper/module cleanup, but
refuses unsafe parent chains, and assumes a quiescent filesystem because the
shell validation/delete sequence is not concurrency-atomic. No installer ran
and no live installation was inspected. This is not installed-copy retirement,
E2 elimination, concurrency closure, or runtime unreachability.
Runtime-profile preflight/activation,
records-write-terminal, and runtime-profile-proof positive commands still
refuse under `authority_grant_contract_exhausted`; their `verify` forms are
historical-only and project current fixture-rightful issuance false.

```bash
bin/zlar protected-records-write --input ./protected-records-write-input.json --require-written
bin/zlar protected-records-write --input - --require-refused < ./protected-records-write-input.json
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
bin/zlar protected-records-runtime-local-activation --plan profiles/protected-records-runtime-local-activation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json --artifact ./runtime-local-activation-artifact.json
bin/zlar protected-records-runtime-local-activation verify --input ./runtime-local-activation-artifact.json
bin/zlar protected-records-runtime-local-activation verify --sample
bin/zlar records-write-terminal-proof
bin/zlar records-write-terminal-proof --json
bin/zlar protected-records-runtime-profile-proof
bin/zlar protected-records-runtime-profile-proof --json
```

The historical terminal and CLI-process conformance reports remain exact
committed evidence only. Fresh `protected-records-proof` generation
fixed-refuses as `e1_positive_terminal_proof_generation_retired`; fresh
`protected-records-adapter-conformance` generation fixed-refuses as
`e1_positive_adapter_conformance_generation_retired`. Their positive bodies,
key/signing machinery, scratch writes, child process calls, and adapter calls
were removed. Historical schemas and validators remain decoupled from the
positive adapter module. The direct adapter/factory is separately source-retired
as `e1_direct_adapter_factory_source_retired`: positive body removed, wrapper
fixed-refused, main dispatch removed, and future installer source copies
excluded. Future accepted repair, upgrade, and reinstall source plans exact
stale-wrapper/module cleanup and refuses unexpected file types before installer
writes, including symlink/non-directory parent refusal. Same-user concurrent
parent/leaf substitution remains open. Historical adapter validators remain in
an import-inert module. This establishes only exact checked-out-source and
future-installer dispositions; no installer ran. It does not establish
installed-copy retirement, E1 elimination, concurrency safety, runtime
unreachability, or side-door closure. Direct filesystem writes,
old/installed/copied/loaded/mutated source,
dynamic or alternate interpreters, E4, live records systems, production
records adapters, and unrouted records paths remain outside the claim.
`protected-records-service-proof` now fixed-refuses fresh generation without
key generation, signing, scratch creation, child execution, or E2 invocation.
Its exact pre-retirement evidence remains historical content in the pinned
local-proof-pack artifact. `protected-records-service-preflight verify --input
<file|->` and `verify --sample` validate exact historical artifact integrity
and embedded preflight boundaries without rerunning E2. Current generation
forms refuse before reading a profile or output path. The direct request and
factory also fixed-refuse in current source, but these dispositions do not
retire old or installed copies, raw filesystem writes, dynamic loaders, or
source mutation.

`protected-records-runtime-profile-preflight --profile
profiles/protected-records-runtime-fixture.profile.json` validates a sample
runtime-profile preflight profile and then runs the local disposable
runtime-profile proof under that profile contract. The profile names the
runtime service command, proof command, launcher-owned authority boundary,
consumed-store lock/validation/anchor/write model, replay scope, required
proof cases, required boundary observations, and known open boundaries. The
preflight reports the profile SHA-256, recognized write acceptance,
replay-after-restart refusal, invalid consumed-store and invalid-anchor
refusal, consumed-store rollback/deletion/replacement refusal relative to the
current local anchor, agent-supplied authority-material refusal, and the
store-plus-anchor rollback boundary. It is not an active or installed runtime
profile, not live records-system evidence, not production service evidence,
not production-grade anti-rollback, and not closure of host side doors or
unrouted records paths.

`protected-records-runtime-activation-preflight --plan
profiles/protected-records-runtime-activation-plan.fixture.json --profile
profiles/protected-records-runtime-fixture.profile.json` validates a sample
runtime activation plan against the explicit runtime profile it names. The
plan binds the runtime-profile SHA, requires explicit human install, refuses
latest/current-machine profile selection, and records that it does not write
runtime config, write hook configuration, start a runtime service, or accept
request-stream authority material. The preflight runs the bounded runtime
profile preflight and reports profile-SHA match, proof case count, rollback
refusal, no activation applied, no config/hook write, and open
activation/live/current-machine boundaries. `--artifact <file|->` emits a
portable canonical JSON artifact containing the explicit plan, runtime
profile, and preflight report with a SHA-256 over the canonical artifact body.
`verify --input <file|->` checks artifact integrity and embedded
activation-preflight boundaries without rerunning the preflight or selecting a
live/current-machine runtime profile. `verify --sample` checks the committed
sample artifact at
`tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json`
without generating fresh evidence. It is not an installed runtime profile, not
current-machine governance, not live records-system evidence, not production
service evidence, not external attestation, and not sovereign recognition.

`protected-records-runtime-local-activation --plan
profiles/protected-records-runtime-local-activation-plan.fixture.json --profile
profiles/protected-records-runtime-fixture.profile.json` runs an explicit local
disposable runtime activation proof. It validates the plan and profile SHA,
writes only launcher-owned disposable config inside the proof harness, starts
local JSONL child service processes, accepts one recognized `records.write`,
and refuses replay, missing, invalid, unknown-issuer, retired-issuer,
missing-issuer-status, stale, wrong-policy, wrong-domain, wrong-tool,
wrong-audit-event, wrong-detail, non-boarding, direct-API, and
agent-supplied-authority requests before runtime-state mutation. `--artifact
<file|->` emits a portable canonical JSON artifact; `verify --input <file|->`
and `verify --sample` check artifact integrity and embedded local-activation
boundaries without rerunning the proof. It is not a persistent runtime profile
install, not hook configuration, not current-machine governance evidence, not
live records-system evidence, not production service evidence, not external
attestation, and not sovereign recognition.

`records-write-terminal-proof` packages that same first terminal as a
one-command evaluator surface. It uses explicit local fixture inputs, generates
fresh local disposable proof evidence in memory, verifies the in-memory
artifact, and prints the bounded airport sentence for the `records.write`
route. The claim is only that this local routed proof path accepts one
recognized receipt and carries a machine-readable downstream refusal contract
showing exact reason-code and zero-mutation evidence for missing, invalid,
stale/expired, unrecognized-issuer, wrong-policy, out-of-scope,
binding-mismatch, direct-API, and agent-supplied-authority attempts before
runtime-state mutation. It is not a persistent install, not hook
configuration, not current-machine governance, not live records-system
evidence, not production service evidence, not external attestation, and not
coverage of unrouted records paths.

`protected-records-runtime-profile-proof` separately invokes a disposable
runtime-profile service as a JSONL child process. The service process owns
private in-memory state; launcher-supplied config carries the recognition rule
and lockfile-guarded persistent consumed-authority-grant store plus local
anchor and witness outside the request stream; agent requests carry receipt,
record update, and supported routing metadata only. It proves one recognized
and authorized `records.write` mutates runtime state once, same-process replay
of the verified signed payload refuses, and restart replay of the consumed
authority-grant contract refuses while the launcher-owned store remains intact,
invalid/duplicate/locked consumed-store states and invalid anchor shape refuse
before mutation, valid consumed-store rollback/deletion/replacement relative
to the local anchor refuses before mutation, unrecognized receipt variants
refuse before mutation, direct API attempts refuse before mutation, and
requests that try to supply state paths, consumed-receipt paths,
consumed-store anchor paths, recognition rules, fixture mode, or unsupported
fields refuse as agent-supplied authority material. The installed service
proof also records configured witness deletion refusal after store and anchor
state exists, and store-plus-anchor rollback refusal when a launcher-owned
local proof witness remains ahead. It also records that the proof is
at-most-once receipt consumption, not exactly-once effect semantics, and that
rollback/deletion/replacement of the consumed store, local anchor, and local
witness together can reopen replay without stronger custody. It is not a
persistent runtime
profile, not live records-system evidence, not production service evidence,
not production-grade durable storage, production-grade anti-rollback,
stale-lock recovery, multi-host coordination, or tamper resistance for the
consumed store, local anchor, or local witness, not host
process/memory/debugger/operator filesystem side-door closure, and not
external attestation or sovereign recognition.

Run the issuer status proof:

```bash
bin/zlar issuer-status-proof
bin/zlar issuer-status-proof --json
```

That proof creates ephemeral issuer keys and one fixture recognition rule. It
accepts the active issuer and refuses retired, compromised, missing-status,
unknown, and key-missing issuers before boarding. It is local fixture evidence
only, not live trust-registry, key-custody, revocation infrastructure,
compromise-response, production deployment, external attestation, sovereign
recognition, or unrouted-surface coverage evidence.

The proof deliberately separates receipt verification from issuer recognition.
A receipt can be cryptographically valid under a supplied public key and still
fail the recognition rule because the issuer is unknown, retired, compromised,
missing status, missing key material, stale, or out of scope. See
[`trusted-receipt-issuer.md`](trusted-receipt-issuer.md).

Run the simulated-human authorization proof:

```bash
bin/zlar human-authorization-proof
bin/zlar human-authorization-proof --json
```

That proof names a local fixture ask-class action. The action does not board
while the ask is pending without a receipt, boards after a simulated human
approval produces a signed `authorized` receipt, and refuses after a simulated
human denial produces a non-boarding receipt. It is local fixture evidence
only; it does not use Telegram, prove live operator approval delivery, prove
external attestation, prove sovereign recognition, or prove production
deployment.

Current refusal probes and exact historical verification:

```bash
bin/zlar proof-smoke
bin/zlar proof-smoke --json
bin/zlar proof-smoke verify --historical --input tests/fixtures/proof-smoke-v1-report.json --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80
bin/zlar proof-smoke verify --historical --input tests/fixtures/proof-smoke-v1-report.json --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80 --json
bin/zlar issuer-status-proof
bin/zlar issuer-status-proof --json
bin/zlar key-state --sample --json
bin/zlar local-proof-pack verify --sample
bin/zlar local-proof-pack verify --sample --json
bin/zlar local-proof-pack verify --input tests/fixtures/local-proof-pack-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --json
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --artifact ./installed-runtime-profile-terminal-chain-artifact.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input ./installed-runtime-profile-terminal-chain-artifact.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --sample
```

The historical pre-retirement proof pack ran the fixture-input coverage map, downstream refusal proof,
simulated-human authorization proof, approval-transport proof, issuer-status
proof, local receipt-verifier boundary proof, protected records terminal proof,
protected records adapter conformance proof, protected records downstream-
service proof, protected records service-profile preflight, protected records
runtime activation-plan preflight, and protected records runtime-local-
activation proof through their existing validators, and carries separate
runtime-profile preflight identity metadata plus a deterministic key-state
sample summary from `zlar key-state --sample --json`.
Its key-state component reports the `zlar-key-state-report-v1` sample summary,
software-rooted policy/constitution posture, software pin alignment, privacy
flags, and non-claims without inspecting operator home key material, hardware,
private key paths, or current-machine custody state.
Its receipt-verifier component runs the actual
`zlar-verify <receipt.json> --pubkey <key.pub> --json` CLI against local
ephemeral v1 receipts and proves `VALID`, `UNKNOWN-SIGNER`, and `INVALID`
stay distinct by verdict and exit code. It does not prove active issuer status,
key custody, revocation state, downstream recognition, or production relying-
party acceptance.
Its protected-records component names the fixture deployment profile,
`records.write` action class, protected records downstream boundary, fixture
adapter profile, adapter route, callable local adapter action, append-only
ledger model, per-adapter replay scope, profile contract route, required
receipt fields, terminal-side replay policy, accepted write, refused write
count, and known ungoverned boundaries. Its adapter-conformance component names
the CLI-process boundary, persistent consumed-receipt-store replay refusal, and
unsupported direct-write adapter-option refusal, while preserving direct
filesystem writes to supplied fixture paths as an open boundary. Its
downstream-service component names the service CLI-process boundary,
persistent consumed-receipt-store replay refusal, missing,
unrecognized/detail-mismatch, invalid, unknown-issuer, stale, and fixture
service API write-without-receipt refusal before service-state mutation, plus
the executed launcher-owned-config service preflight profile id/SHA/status,
case counts, request-stream authority-material refusal, direct-API refusal
summary, open boundaries, and non-claims, while preserving direct filesystem
writes to configured fixture paths as an open boundary for the preflight. Its
runtime-profile-preflight identity component names the runtime
preflight profile id/SHA/status, launcher-owned authority boundary, local anchor
model, and open store-plus-anchor rollback boundary. Its
runtime-activation-preflight component names the activation plan id/SHA, bound
runtime-profile SHA, profile-SHA match, activation preflight execution, nested
runtime-profile proof case and boundary counts, rollback/deletion/replacement
refusal, agent-supplied authority-material refusal, explicit install
requirement, no activation applied, no runtime/hook config writes, no
runtime-service start, no `--latest` selection, and open activation, live, and
current-machine boundaries. The runtime-local-activation component names the
explicit local activation command, local activation plan id/SHA, bound
runtime-profile SHA, profile-SHA match, active-profile selection for the first
`records.write` terminal under explicit plan/profile inputs, local disposable
activation execution, launcher-owned disposable runtime config written inside
the proof harness, local JSONL child service processes started, recognized write
acceptance, replay/missing/invalid/unknown-issuer/retired-issuer/
missing-issuer-status/stale/wrong-policy/wrong-domain/wrong-tool/
wrong-audit-event/wrong-detail/non-boarding/direct-API refusal,
agent-supplied authority-material refusal, and no persistent
profile/hook/production/live claim. The active-profile selection summary records
`selects_latest_profile=false`, `persistent_runtime_profile_installed=false`,
`live_runtime_profile_checked=false`, and `hook_configuration_written=false`.
The service preflight and runtime-local activation run as local
disposable fixture evidence, but the proof pack is still local fixture evidence
only; it does not install a persistent runtime profile, write hook
configuration, write machine or production configuration, inspect live hooks,
live audit stores, runtime state, live approval channels, live trust
registries, live downstream systems, operator home key material, or hardware.
It does not use Telegram or prove live human approval-channel delivery.

`--artifact <file>` writes a portable JSON envelope containing the validated
proof-pack report and a SHA-256 over the canonical artifact body. `--artifact
-` prints that envelope to stdout. The artifact makes the bounded local proof
pack easier to hand to another verifier; it is not live governance evidence,
production deployment evidence, external attestation, or sovereign recognition.

`verify --input <file|->` checks a supplied artifact without regenerating the
proof pack. It recomputes the canonical artifact-body SHA-256 and validates the
embedded local fixture proof-pack boundaries. The verification result exposes
the embedded key-state sample summary from the artifact: read-only report type,
software-rooted policy posture, privacy flags, and no key custody, revocation,
production trust registry, current-machine governance, external attestation, or
sovereign recognition claim. It also exposes the embedded receipt-verifier
boundary summary from the artifact: valid receipt accepted under the supplied
key, wrong public key reported as `UNKNOWN-SIGNER`, tampering reported as
`INVALID`, and no issuer-recognition/key-custody/revocation/downstream-
recognition claim. It also exposes the embedded service-
profile preflight summary from the artifact: preflight type, fixture evidence
model, case count, sanitized case summaries, direct-API-with-receipt refusal
reason, zero state mutation, and no-live/no-production/no-external-attestation
flags. It also exposes the embedded runtime-local-activation summary: local
activation applied, disposable config written, embedded active-profile
selection, no persistent config or hook write, local child service started,
the expanded runtime refusal taxonomy, wrong-runtime-profile-id refusal, direct-API-with-receipt refusal, and no
live/production/external claim. It is artifact integrity checking only, not
fresh runtime evidence or external attestation.
It also exposes the embedded runtime-profile-installation summary: disposable
install root created, profile copy written, active profile index written,
profile selected from the disposable root by explicit id and SHA, request
authority guard refused, the expanded runtime refusal taxonomy, wrong-runtime-profile-id refusal, no latest
selection, no persistent profile install, no hook/user/machine configuration,
and no live/production/external claim.
`verify --sample` checks the committed sample artifact at
`tests/fixtures/local-proof-pack-artifact-v1.json` without requiring the path to
be supplied. The sample exists for verifier smoke tests and does not prove live
governance.

Current authority status overrides the pre-exhaustion behavior described below:
`zlar local-proof-pack` and `zlar proof-smoke` refuse before fresh consequence
execution because the exact one-use fixture grant is exhausted. The committed
proof-pack is permanently historical-only; exact SHA identity does not restore
fixture-rightful issuance. A future positive path requires a new artifact-bound
schema and replacement grant.

Before exhaustion, `zlar local-proof-pack` was the fresh local fixture
proof-pack path. It regenerated bounded local fixture evidence without live
probing, including a
trusted issuer registry recognition component that validates and evaluates a
bundled registry fixture through the shared downstream recognition rule and
keeps live registry, key custody, revocation, production, external-attestation,
and current-machine governance claims false. `zlar proof-smoke` was the shortest
committed-fixture smoke test. It verified the
committed sample proof-pack artifact, verifies the committed service-profile
preflight sample artifact, verifies the committed activation preflight sample
artifact, verifies the committed runtime-local-activation sample artifact,
verifies the committed runtime-profile-installation sample artifact, verifies
the committed installed-runtime-profile preflight sample artifact, runs the
installed-runtime-profile recognition proof, runs the installed-runtime-profile
disposable service proof, verifies that service-proof artifact, runs the
installed-runtime-profile terminal chain, verifies that terminal-chain artifact,
and then evaluates the committed fixture-input coverage map. The coverage step
must preserve the current `4/6` result and the two authority-exhausted
`receipt_not_capable` lanes; it must not require all six lanes to be governed.
It does not run the proof
pack, rerun the service-profile preflight, rerun the activation preflight,
rerun local activation, rerun disposable profile installation, regenerate the
installed-runtime-profile preflight, rerun key-state or receipt-verifier
evidence, or generate fresh proof-pack evidence. It does start a local
disposable child service for the installed-runtime-profile service proof; that
proof now also preserves same-process/restart replay refusal and
consumed-store/local-anchor/witness integrity refusal, plus store-plus-anchor
rollback refusal when the local witness remains ahead, while keeping joint
store-plus-anchor-witness rollback detection false. It also starts local
disposable child service processes inside the terminal-chain proof, after
creating only a launcher-owned disposable installed runtime-profile root and
preflighting that generated root by explicit id and SHA. Those child services
are not live runtime services. `zlar proof-smoke --json`
emits the same bounded result as a parseable
`zlar-proof-smoke-v1` report. That report locks the local proof-pack verifier's
embedded key-state sample summary, including privacy flags, software-rooted
policy/constitution posture, and no key-custody/revocation/production-trust-
registry/current-machine-governance claim. It also locks the embedded
receipt-verifier boundary summary, including `VALID`, `UNKNOWN-SIGNER`, and
`INVALID` distinction and no issuer-recognition/key-custody/revocation/
downstream-recognition claim. It also locks the embedded
service-profile preflight summary, including the fixture case count, direct-
API-with-receipt refusal reason, zero state mutation, and no-live/no-production
boundary flags, and it locks the embedded runtime-local-activation summary from
the committed proof-pack artifact. It also locks the embedded
runtime-profile-installation summary from the committed proof-pack artifact. It
also locks the standalone service-profile preflight sample artifact
verification, including the 11/11 case count, wrong-policy refusal reason,
direct-API-with-receipt refusal reason, zero state mutation, and
no-live/no-production/no-external-attestation flags, and the standalone
runtime-profile-installation sample artifact verification, including disposable
install root/profile copy/active index/explicit id-and-SHA selection, request
authority guard refusal, no latest selection, no persistent install, and no
hook/user/machine configuration. It also locks the installed-runtime-profile
preflight selector-integrity verification and the installed-runtime-profile
service proof: one matching `records.write` boards through a local disposable
JSONL child service, and all 18 selected-profile refusal cases refuse before
service-state mutation while persistent install, activation, current-machine
governance, and production downstream recognition remain false. It also locks
the service-proof artifact verification result, including the artifact hash
bound to the service proof carried in the same report, proof payload type,
replay refusal, rollback-refusal counts, before-mutation refusal result, and
false current-machine/production flags. It also locks the service-proof
artifact-verification refusal taxonomy SHA-256, so the report cannot substitute
a different case/reason taxonomy behind the same refusal count. It also locks
the installed-runtime-profile recognition-contract SHA-256 across preflight,
service proof, service-proof artifact verification, terminal chain, and
terminal-chain artifact verification. It also locks
the terminal-chain proof and artifact verification result, including generated installed-root preflight,
generated preflight consumption, generated service-proof artifact verification,
proof/artifact hash binding, recognized write boarding, missing/invalid receipt
refusal before mutation, all 18 selected-profile refusals before mutation,
refusal taxonomy SHA-256 binding, terminal-chain trusted issuer registry
recognition summary preservation with stable registry/receipt contract hashes,
exact local refusal IDs/reasons for unrecognized registry scope and
registry/receipt contract mismatch, first-class proof-smoke/readiness summary
fields for that refusal evidence, release-forward manifest/result preservation of that same
trusted-registry refusal summary for `v3.4.39+` targets, and a compact
`release_forward_report_contract` manifest object for `v3.4.41+` targets whose
Markdown rendering is human review only. For `v3.4.42+` targets, that contract
also binds Product Proof Path by artifact path/SHA-256, PASS/evidence model,
receipt-verifier boundary, North Star consumption, false-claim flags, and known
unrouted-records noncoverage visibility. For `v3.4.45+` targets, Product Proof
Path also consumes fresh terminal-chain artifact verification and the contract
preserves that terminal-chain boundary with binding/refusal hashes, exact
trusted-registry refusal IDs/reasons, omitted public-key material, omitted
receipt envelope, false external attestation, and false current-machine
governance. For `v3.4.46+` targets, the same Product Proof Path boundary also
preserves exact grouped recognition-refusal case IDs, `group_count=3`,
`case_count=18`, and `preserved=true`. For `v3.4.48+` targets, Product Proof
Path and release-forward evidence also preserve the local fixture
deployment-profile authority bridge: explicit deployment/runtime profile SHA
binding, no `--latest`, verified preflight, one recognized receipt mutation,
18/18 zero-mutation refusals, request/agent authority-material refusal, direct
API refusal, and false current-machine, production, enterprise, external,
sovereign, and unrouted flags. For `v3.4.49+` targets, that bridge also
preserves five pre-service deployment-profile authority refusals for stale
profile artifacts, profile recognition mismatch, `--latest` selection, and
request-stream authority material. For `v3.4.50+` targets, terminal-chain
evidence, terminal-chain artifact verification, proof-smoke, North Star
readiness, and release-forward evidence also mirror that same five-case
authority-refusal list with exact IDs, before-service-proof refusal,
before-mutation refusal, service-proof-not-started, and false stronger-claim
flags. For future `v3.4.51+` local targets, release-forward/private-intake
contracts also require the Product Proof Path terminal-chain trusted-registry
verdict/evaluation facts and downstream-refusal marker boundary in both the
Product Proof Path contract and North Star mirror, including exact downstream
refusal reasons and all-refusals-unboarded flags; `v3.4.50` omits those fields.
These remain local dry-run packet
evidence, not
live registry state, key custody, revocation truth, current-machine governance,
production authority, enterprise readiness, external attestation, sovereign
recognition, or unrouted-surface coverage. The
committed sample report at
`tests/fixtures/proof-smoke-v1-report.json` and validator at
`lib/proof-smoke-report.mjs` lock the report shape for evaluator tooling; they
do not create fresh runtime evidence.
`zlar proof-smoke verify --historical --input <file|-> --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80`
validates only the exact pinned historical smoke report against its non-current
contract. `zlar proof-smoke verify --historical --sample --require-file-sha de6272b72aa8b1a8140519e3144d7dfd88dd4920c19349c47661c92a17b36268 --require-sha 8fa70251edbcbc4a5ae92fa776815ce0c6029c644452f5b6dbd6ea865028aa80` validates the
committed sample report without requiring the path to be supplied. Both forms
emit a `zlar-proof-smoke-historical-report-verification-v2` result. They do not rerun
the smoke test, regenerate proof, inspect live state, inspect operator home key
material or hardware, or create external attestation.

The emitted refused decision can be supplied as
`downstream_refusal.recognition_decision` in coverage-map input. An accepted
recognition decision is not refusal proof and does not satisfy the
`downstream_refusal` gate. The refused decision must also match the counted
lane's audit event id and detail hash; a refused decision for a different
action cannot prove this lane's downstream refusal.

## Evidence Model

This slice is fixture/report-input only. The input JSON supplies evidence for
counted lanes and optional boundary entries. `zlar coverage` validates and
summarizes that supplied evidence; it does not discover evidence by itself.

A counted lane can be marked `governed=true` only when all of these are true:

- `configured`: the lane has supplied configuration evidence.
- `routed`: the lane has supplied checkpoint-path evidence and no bypass
  evidence.
- `alive`: the supplied heartbeat is fresh.
- `policy_current`: the supplied policy version evidence is current and valid.
- `receipt_capable`: the supplied Worker Receipt matches the audit event,
  surface, policy version, and audit hash.
- `downstream_refusal`: the supplied evidence shows unrecognized boarding would
  be refused.

Each reported surface carries summary fields for evaluator tooling:

- `coverage_summary`: route, freshness, policy, receipt, downstream-refusal, and
  verification status derived from the report fields.
- `last_decision`: the supplied audit or fixture decision summary.
- `last_receipt`: the supplied receipt or fixture-recognition summary.
- `issuer_identity`: policy key, audit public key, or recognition anchor
  identifiers when supplied.
- `known_boundaries`: named open boundaries for the lane.

`issuer_identity` names evidence anchors only. It deliberately keeps
`issuer_status_proven`, `key_custody_proven`, `revocation_state_proven`,
`production_trust_registry_proven`, `external_attestation`, and
`sovereign_recognition` false unless a future proof path can support those
claims.

`downstream_refusal` can be supplied as explicit refusal proof, as MCP evidence
that a denied call did not reach upstream, or as a
`downstream-recognition-rule-v1` `recognition_decision` whose decision is
`refuse`. An accepted recognition decision alone is not downstream refusal
evidence. A refused recognition decision must match the counted lane's audit
event id and detail hash before it can satisfy the gate.

For the `protected-records.runtime.records.write` fixture lane, the map uses
the committed runtime-local-activation artifact instead of a Worker Receipt.
It still fails closed through the same coverage shape: missing or invalid
artifact evidence becomes `missing_configuration`, missing plan/profile SHA
match becomes non-governed, and missing runtime refusal proof prevents the lane
from being counted as governed. This is a bridge over existing fixture proof,
not a live runtime discovery mechanism.

The runtime-local lane remains North Star 1 boarding-only governed evidence when
its supplied artifact preserves the exact
`e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469`
profile SHA, exact recognition-then-authority-grant route, grant and witness
identities, 18 recognition refusals, five authority refusals, and the separate
signed-payload and consumed-grant replay boundaries; it continues to project
fixture-rightful false. Runtime profile-installation and installed terminal-
chain evidence additionally require a source-recognized, artifact-bound grant
whose fresh effect and repeated-use provenance are valid before they can be
receipt-capable or governed. The current one-use grant fails that gate. Burn-
window evidence does not close exactly-once effects; witness-ahead rollback
refusal does not close joint store/anchor/witness rollback; launcher path
validation does not close host-filesystem TOCTOU. Historical local-fixture
evidence does not raise the generic, portable, live, production,
current-machine, or consequence-lifecycle claim ceiling.

If any required item is missing, stale, mismatched, or malformed, the counted
lane fails closed with a downgraded `verification_status`.

## Boundaries

The report also names boundary entries that are not governed coverage. Examples
include deferred SDK/membrane/AuthZEN coverage, SubagentStart without current
receipt evidence, Cursor `afterFileEdit`, Windsurf `post_*`, direct MCP
registration, and unrouted shell, filesystem, browser, app-control, network,
model-reasoning, and final-text surfaces.

Boundary entries are map labels. They are not counted as governed lanes.

## Claim Boundary

The safe claim for this slice is:

> ZLAR can produce a fixture-input Governed Surface Coverage Map for supplied
> defined routed action-surface evidence.

This does not create a release, version bump, live machine coverage claim,
deployment-readiness claim, external attestation, production authority, or
coverage of unrouted surfaces.
