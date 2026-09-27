# Historical Fixture-Authority Test Suites

This file records the current test-routing boundary after exhaustion of fixture
authority grant contract
`0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba`.
It is routing metadata, not renewed authority.
The machine-readable inventory is
`tests/authority-inactive-test-suites.txt`. The assertion harness skips every
listed basename as authority-inactive and no longer executes helper modules
that do not match `tests/test-*.mjs`.

## Current truth

- Consequence class:
  `protected-records.installed-runtime-profile.terminal-chain.records.write`.
- Authority status: `exhausted` with `maximum_effect_uses=1`,
  `recorded_effect_uses=1`, and `fresh_effect_allowed=false`.
- Current static coverage: `governed=4/6`, `counted=6`.
- The runtime profile-installation and installed terminal-chain lanes are
  `receipt_not_capable` under the exhausted grant.
- Historical pinned-release artifacts and packet contracts may still contain
  `governed=6/6`. That is historical artifact identity and release-contract
  evidence only. It must not be projected as current coverage or current
  fixture-rightful issuance.

## Retired legacy runtime direct entry

`bin/zlar-protected-records-runtime-service` is now an import-free fixed
refusal. Its committed script body does not read argv, process environment,
config, stdin, caller identity, or fixture authority status. Interpreter/PATH
selection and loaders/preloads remain outside that body-level claim. The
runtime-profile and installed-service proof child
helpers remain as historical source, but their positive generation dependency
on that executable is retired. The named-deployment real-boundary child source
was already unreachable behind an unconditional authority refusal.

This retirement is not E3 elimination. Direct imports of
`createProtectedRecordsRuntimeService`, alternate source copies, loaders, and
raw fixture-storage writes remain open. Reactivating a fixture-internal E3 route
requires a new versioned design and separate consequence authority; changing
the exhausted-grant constant or adding a hidden CLI mode is forbidden.

## Inactive positive suites

The inventory covers the legacy success-expecting local-pack, Product Proof
Path, proof-smoke, readiness, runtime proof/preflight/activation/installation,
installed recognition/service/terminal-chain, records-write terminal,
one-terminal, active-persistent crossing/lifecycle/live-installation, private
readiness, and release-forward suites. They must not run against the current
checkout.

Two especially direct gateways also stop themselves before execution:

- `test-proof-smoke-cli.mjs` invokes `bin/zlar proof-smoke`, which historically
  ran fresh local recognition, service, and terminal-chain proof paths. Its
  embedded `6/6` assertions describe the legacy `zlar-proof-smoke-v1` report.
- `test-release-forward-verifier-dry-run.sh` includes safe `--plan-only`
  assertions, but later real `--out-dir` cases execute pinned release-forward
  command blocks containing positive proof paths. Treat the whole suite as
  inactive until the plan-only checks are split from execution checks or the
  suite has an explicit exhaustion skip.

`tests/count-assertions.sh` records every machine-listed suite as skipped before
invocation. The two files above also return exit `77` when invoked directly.
The active-persistent live-install and closeout library functions independently
refuse before root inspection or mutation as
`active_persistent_profile_mutation_authority_absent`. Reactivation requires a
new versioned suite and the matching consequence authority; changing only a
current-grant constant is forbidden.

## Active static and refusal evidence

The current authority-exhaustion lane is evidenced by focused tests that do not
create a fresh protected-records consequence, including:

- `test-protected-records-fixture-authority-grant.mjs`
- `test-protected-records-fixture-authority-exhausted-routing.mjs`
- `test-protected-records-detached-artifact-authority-status.mjs`
- `test-protected-records-runtime-artifact-authority-exhaustion.mjs`
- `test-local-proof-pack-exhausted-artifact.mjs`
- `test-protected-records-historical-raw-formatter-authority.mjs`
- `test-governed-surface-coverage-map.mjs`
- `test-governed-surface-coverage-map-cli.mjs`
- `test-consequence-lifecycle-map.mjs`
- `test-protected-records-named-deployment-profile-readiness.mjs`
- `test-protected-records-named-deployment-profile-readiness-cli.mjs`
- `test-protected-records-named-deployment-profile-real-boundary.mjs`
- `test-protected-records-named-deployment-profile-real-boundary-cli.mjs`
- `test-external-verifier-packet.sh`

`test-downstream-recognition-cli.mjs` is a supplied-input recognition and
coverage integration test, not a protected-record effect test. It remains
active at `Counts: governed=4/6` and proves that `--require-governed` refuses
the two demoted lanes; a recognized decision in that isolated rule test is not
fixture consequence authority.

## Claim ceiling

The active tests can prove source-level refusal, exact historical artifact
identity, and the current `4/6` static coverage projection. They cannot prove a
fresh rightful fixture consequence, current `6/6` coverage, production or
current-machine governance, external attestation, or authority renewal.
