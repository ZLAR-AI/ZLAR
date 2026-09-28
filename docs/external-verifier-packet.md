# External Verifier Packet v0

*Part of ZLAR's first design, the checkpoint that sits next to the AI, which is no longer the direction. ZLAR's current design, the force field, is in [cyan/](../cyan/). Start with the [README](../README.md) and [PROPOSITION.md](../PROPOSITION.md).*

This packet prepares ZLAR evidence for a non-operator verifier. After Vincent
authorized contact on 2026-06-20, a private-by-default non-Vincent verifier
request was sent using this packet. The request does not appoint an independent
public verifier, create completed external attestation, or permit public
attribution without later permission.

Packet id: `zlar-external-verifier-packet-v0`

Status: private verifier request sent; public attestation not claimed.

No completed external attestation is created by this packet or by sending the
request.

Current request state:

- Sent: 2026-06-20 from `vincent@zlar.ai`.
- Recipient attribution: private by default; no public name in this repo.
- Release under review: `v3.3.49`.
- Expected commit SHA:
  `2390bb1f69c78e79b10665b2bc9ff1d049564ed5`.
- Public claim: no public external attestation is claimed in this repo.
- Private replies, if any, remain private/internal unless later disclosure is
  explicitly approved and the verifier relationship is disclosed honestly.

The state above is historical. Do not overwrite it when a later release is
reviewed. A later request must be release-forwarded by adding a new pinned
target, not by pretending the original request reviewed newer evidence.

Prepared pinned release-forward target:

- Status: target prepared; no new verifier request sent by this section.
- Release under review: `v3.3.76`.
- Expected commit SHA:
  `3369ae5f04b0735c8a11bc55c70b49c09edad0da`.
- Evidence focus: proof-pack and proof-smoke active-profile selection summary,
  committed evaluator smoke path, issuer-status proof, verifier kit
  issuer-status artifact output, runtime local activation sample verification,
  and `v3.3.61+` coverage-map airport summaries.
- Public claim: no public external attestation is claimed in this repo.

This target lets a later authorized verifier review the pinned `v3.3.76`
release-forward target without mutating the historical `v3.3.49` request
record. It is not evidence that any non-operator verifier has reviewed
`v3.3.76`.

Prepared pinned backward-compatibility release-forward target:

- Status: target prepared; no new verifier request sent by this section.
- Release under review: `v3.3.90`.
- Expected commit SHA:
  `9a8147163384f776777bf283217a5cd55cbbdfe7`.
- Evidence focus: proof-pack and proof-smoke active-profile selection summary,
  disposable runtime-profile installation summary, committed evaluator smoke
  path, config-backed service-preflight sample verification, expanded
  runtime-local-activation and runtime-profile-installation refusal taxonomy
  including wrong-runtime-profile-id refusal, issuer-status proof, verifier kit
  issuer-status artifact output, runtime local activation sample verification,
  runtime profile installation sample verification, and coverage-map airport
  summaries with `4/4` governed counted lanes.
- Public claim: no public external attestation is claimed in this repo.

This target lets a later authorized verifier review the pinned `v3.3.90`
release-forward target without mutating the historical `v3.3.49` request
record or the earlier prepared `v3.3.76` target. It is not evidence that any
non-operator verifier has reviewed `v3.3.90`.

Prepared pinned byte-bound public-distribution release-forward target:

- Status: target prepared; no new verifier request sent by this section.
- Release under review: `v3.4.2`.
- Expected commit SHA:
  `a101282cf901c8c124b0a4761359395baad3f829`.
- Evidence focus: byte-bound public verifier-kit distribution release, live
  GitHub release assets, verifier-kit reproducibility evidence, live
  public-distribution audit, derived North Star readiness result
  `READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION`, private-intake sample
  pointer contract, protected-records runtime/profile refusal taxonomy,
  trusted issuer recognition fixture, and coverage-map airport summaries.
- Public claim: no public external attestation is claimed in this repo.

This target lets an authorized verifier review the pinned `v3.4.2`
release-forward target without mutating the historical `v3.3.49` request record
or the earlier prepared targets. This public packet section is not evidence
that any non-operator verifier has reviewed `v3.4.2`, and any private reply or
intake result for this target remains private/internal unless separate public
disclosure is approved.

## Purpose

The packet gives an outside verifier a bounded way to check the committed ZLAR
fixture evidence without asking Vincent what it means.

The verifier should be able to answer:

- Which release and commit did I inspect?
- Did the committed smoke report and sample artifacts verify?
- Did the coverage map name governed lanes and ungoverned boundaries?
- Did the public-copy guard preserve the receipt authority boundary?
- What did I not verify?

The packet does not ask the verifier to trust a ZLAR server, a Telegram channel,
Vincent's workstation, live hooks, live audit stores, or any private operator
state.

## Before Sending Future Requests

Do not send this packet to an additional verifier until Vincent names or
authorizes that verifier.

Before any future contact, fill in:

Request boundary contract: `zlar-external-verifier-request-boundary-v1`.

```text
verifier_name:
verifier_organization:
verifier_contact:
release_under_review:
expected_release_tag:
expected_commit_sha:
packet_sender:
packet_sent_date:
```

If those fields are blank for a future request, that future request is not
authorized to send.

Those eight request-boundary fields are closed and exact for future contact
authorization. Missing, blank, extra, renamed, summary-only, or moving-target
fields do not authorize contact and are not verifier evidence. The closed
record identifies who Vincent authorized, the pinned release/tag/SHA, sender,
and date; it does not prove receipt, review, approval, non-operator result,
public attribution, completed external attestation, production/current-machine
governance, or public claim expansion.

Evidence-focus summaries, version-specific release-forward commands, verifier
environment notes, private-intake result summaries, and prepared-target
narrative may evolve by pinned release. They are not request authorization
fields and must not be used as boarding credentials for contact or public
claims.

For any future request, use an explicit release tag and exact commit SHA. Do
not use `--latest`, a moving branch name, or a current-machine checkout as the
verification target.

## Verifier Prerequisites

The verifier needs:

- a clean machine or disposable workspace;
- Git;
- Bash;
- Node.js 18 or newer;
- `jq`;
- OpenSSL with Ed25519 support;
- network access to `github.com`;
- enough comfort running command-line verification steps.

The release-forward template includes an OpenSSL Ed25519 preflight. If that
preflight fails, stop and upgrade or select an OpenSSL build with Ed25519
support before running the longer packet commands.

To make that prerequisite failure easy to diagnose and preserve as evidence,
run:

```bash
bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json
bash tools/build-verifier-kit.sh --check-env
```

If either command reports `Result: FAIL`, stop and fix the verifier
environment before running the longer proof commands. On macOS this usually
means selecting an OpenSSL 3 build such as Homebrew `openssl@3` before Apple
LibreSSL on `PATH`. Preserve the JSON report before changing the verifier
environment. These are verifier-environment readiness checks only, not a ZLAR
proof run and not external attestation.

The verifier does not need:

- access to Vincent's computer;
- ZLAR signing keys;
- Telegram;
- private audit logs;
- GitHub admin rights;
- a ZLAR cloud account.

## Verification Steps

Use the release tag or private-core source checkpoint under review. For current
private-core targets, the verifier must receive an authorized source checkout,
source archive, or source-review access path before running these commands. For
the post-grant-exhaustion checkout, positive proof-smoke, runtime, recognition,
service, terminal, Product Proof Path, and readiness commands are not an
authorized verifier route: they refuse, and only static/read-only historical
artifact checks may run. The blocks below are version-pinned historical release
instructions, not a current-checkout runbook. For
the private request sent on 2026-06-20, the release under review is `v3.3.49`;
the minimal historical public-release path was:

```bash
git clone <authorized-source-url-or-local-source-archive> ZLAR
cd ZLAR
git checkout v3.3.49
git rev-parse HEAD

bin/zlar proof-smoke
bin/zlar proof-smoke --json > zlar-proof-smoke-v1.json
bin/zlar proof-smoke verify --sample
bin/zlar proof-smoke verify --sample --json > zlar-proof-smoke-sample-verification.json
bin/zlar local-proof-pack verify --sample
bin/zlar local-proof-pack verify --sample --json > zlar-local-proof-pack-sample-verification.json
bin/zlar protected-records-runtime-local-activation verify --sample
bin/zlar protected-records-runtime-local-activation verify --sample --json > zlar-runtime-local-activation-sample-verification.json
bin/zlar coverage --sample --require-governed
bash tests/test-receipt-authority-copy.sh
```

## Release-Forward Verification Template

Use this template only after Vincent names or authorizes the verifier and the
specific release under review. Replace the placeholders before sending. The
template is intentionally pinned; it must not be converted to `--latest`. The
template must not be run against the post-grant-exhaustion checkout; a new
artifact-bound verifier schema is required there. The
complete command block below is for current `v3.4.28+` targets. For older
targets, use `bash tools/release-forward-verifier-dry-run.sh --release-tag
<explicit-release-tag> --expected-commit-sha <expected-commit-sha> --plan-only`
from that checked-out release to generate the version-specific command plan;
later-release commands must not be backported into older release reviews.

```bash
git clone <authorized-source-url-or-local-source-archive> ZLAR
cd ZLAR
git checkout <explicit-release-tag>
test "$(git rev-parse HEAD)" = "<expected-commit-sha>"
bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json
bash tools/build-verifier-kit.sh --check-env
openssl genpkey -algorithm ED25519 -out /dev/null

bin/zlar proof-smoke
bin/zlar proof-smoke --json > zlar-proof-smoke-v1.json
bin/zlar proof-smoke verify --input zlar-proof-smoke-v1.json --json > zlar-proof-smoke-generated-verification.json
bin/zlar proof-smoke verify --sample
bin/zlar proof-smoke verify --sample --json > zlar-proof-smoke-sample-verification.json
bin/zlar protected-records-service-preflight verify --sample
bin/zlar protected-records-service-preflight verify --sample --json > zlar-service-preflight-sample-verification.json
bin/zlar local-proof-pack verify --sample
bin/zlar local-proof-pack verify --sample --json > zlar-local-proof-pack-sample-verification.json
bin/zlar issuer-status-proof
bin/zlar issuer-status-proof --json > zlar-issuer-status-proof.json
bash tools/build-verifier-kit.sh
bin/zlar verifier-kit-reproducibility --json-out zlar-verifier-kit-reproducibility-v1.json
node --input-type=module -e "import { writeFileSync } from 'node:fs'; writeFileSync('zlar-verifier-kit-release-assets-v1.json', JSON.stringify({ tagName: '<explicit-release-tag>', url: 'not-queried-release-forward-dry-run', evidence_model: 'release-forward-local-no-assets-fixture', assets: [] }, null, 2) + '\n');"
bin/zlar verifier-kit-public-distribution --release-tag <explicit-release-tag> --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --json-out zlar-verifier-kit-public-distribution-v1.json
( cd dist/zlar-verifier-kit-v0.1.0 && node verify-issuer-status.mjs )
( cd dist/zlar-verifier-kit-v0.1.0 && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample )
( cd dist/zlar-verifier-kit-v0.1.0 && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample --json > ../../zlar-trusted-receipt-issuer-recognition.json )
node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; const r = JSON.parse(readFileSync('dist/zlar-verifier-kit-v0.1.0/examples/trusted-receipt-issuers-v1.json', 'utf8')); r.production_authority = true; writeFileSync('zlar-trusted-receipt-issuer-recognition-malformed-registry.json', JSON.stringify(r, null, 2) + '\n');"
node dist/zlar-verifier-kit-v0.1.0/verify-recognition.mjs --receipt dist/zlar-verifier-kit-v0.1.0/examples/sample-receipt.json --registry zlar-trusted-receipt-issuer-recognition-malformed-registry.json --scope verifier-kit-sample > zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt 2>&1 # expected exit 2
( cd dist/zlar-verifier-kit-v0.1.0 && bash external-runner-dry-run.sh --issuer-status-json-out ../../zlar-verifier-kit-issuer-status-fixture.json )
ZLAR_RELEASE_FORWARD_TARGET_TAG=<explicit-release-tag> ZLAR_RELEASE_FORWARD_EXPECTED_SHA=<expected-commit-sha> ZLAR_RELEASE_FORWARD_OBSERVED_SHA=$(git rev-parse HEAD) node tools/verifier-kit-external-runner-diagnostics.mjs --json-out zlar-verifier-kit-external-runner-diagnostics-v1.json
bin/zlar protected-records-runtime-local-activation verify --sample
bin/zlar protected-records-runtime-local-activation verify --sample --json > zlar-runtime-local-activation-sample-verification.json
bin/zlar protected-records-runtime-profile-installation verify --sample
bin/zlar protected-records-runtime-profile-installation verify --sample --json > zlar-runtime-profile-installation-sample-verification.json
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample --json > zlar-installed-runtime-profile-preflight-sample-verification.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --json > zlar-installed-runtime-profile-recognition-proof-v1.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --artifact zlar-installed-runtime-profile-recognition-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json --json > zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json
bin/zlar protected-records-installed-runtime-profile-service-proof --sample
bin/zlar protected-records-installed-runtime-profile-service-proof --sample --json > zlar-installed-runtime-profile-service-proof-v1.json
bin/zlar protected-records-installed-runtime-profile-service-proof --sample --artifact zlar-installed-runtime-profile-service-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json --json > zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --json > zlar-installed-runtime-profile-terminal-chain-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --artifact zlar-installed-runtime-profile-terminal-chain-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json --json > zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json
node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; import { canonicalize } from './lib/canonicalize.mjs'; import { sha256hex } from './lib/receipt.mjs'; const artifact = JSON.parse(readFileSync('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json', 'utf8')); artifact.payload.chain.generated_preflight.artifact_body_sha256 = 'e'.repeat(64); artifact.payload.chain.generated_service_proof.source_preflight_body_sha256 = 'e'.repeat(64); artifact.integrity.body_sha256 = sha256hex(canonicalize(artifact.payload)); writeFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json', JSON.stringify(artifact, null, 2) + '\n');"
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json # expected exit 1
node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; import { canonicalize } from './lib/canonicalize.mjs'; import { sha256hex } from './lib/receipt.mjs'; const artifact = JSON.parse(readFileSync('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json', 'utf8')); artifact.payload.chain.generated_service_proof.artifact_body_sha256 = 'f'.repeat(64); artifact.payload.chain.generated_service_proof.verification_body_sha256 = 'f'.repeat(64); artifact.integrity.body_sha256 = sha256hex(canonicalize(artifact.payload)); writeFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json', JSON.stringify(artifact, null, 2) + '\n');"
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json # expected exit 1
bin/zlar product-proof-path --json-out zlar-product-proof-path-v1.json
bin/zlar coverage --sample --require-governed
bin/zlar coverage --sample --require-governed --json > zlar-coverage-map-sample.json
bin/zlar north-star-readiness --evidence-dir . --release-tag <explicit-release-tag> --json > zlar-north-star-readiness-v1.json
bash tests/test-receipt-authority-copy.sh
```

For the prepared pinned release-forward target, replace the placeholders with:

```bash
git checkout v3.3.76
test "$(git rev-parse HEAD)" = "3369ae5f04b0735c8a11bc55c70b49c09edad0da"
bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json
bash tools/build-verifier-kit.sh --check-env
openssl genpkey -algorithm ED25519 -out /dev/null
```

For the prepared pinned backward-compatibility release-forward target, replace the
placeholders with:

```bash
git checkout v3.3.90
test "$(git rev-parse HEAD)" = "9a8147163384f776777bf283217a5cd55cbbdfe7"
bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json
bash tools/build-verifier-kit.sh --check-env
openssl genpkey -algorithm ED25519 -out /dev/null
```

For the prepared pinned public-distribution release-forward target, replace the
placeholders with:

```bash
git checkout v3.4.2
test "$(git rev-parse HEAD)" = "a101282cf901c8c124b0a4761359395baad3f829"
bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json
bash tools/build-verifier-kit.sh --check-env
openssl genpkey -algorithm ED25519 -out /dev/null
```

Local non-sending dry-run helper:

```bash
bash tools/release-forward-verifier-dry-run.sh --release-tag v3.3.90 --expected-commit-sha 9a8147163384f776777bf283217a5cd55cbbdfe7 --out-dir ../zlar-release-forward-verifier-dry-run-v3.3.90
bash tools/release-forward-verifier-dry-run.sh --release-tag v3.3.90 --expected-commit-sha 9a8147163384f776777bf283217a5cd55cbbdfe7 --plan-only
bash tools/release-forward-verifier-dry-run.sh --release-tag v3.4.2 --expected-commit-sha a101282cf901c8c124b0a4761359395baad3f829 --out-dir ../zlar-release-forward-verifier-dry-run-v3.4.2
bash tools/release-forward-verifier-dry-run.sh --release-tag v3.4.2 --expected-commit-sha a101282cf901c8c124b0a4761359395baad3f829 --plan-only
```

The helper refuses moving targets such as `main`, `HEAD`, `latest`, and
`--latest`; writes `COMMANDS.txt`, `transcript.txt`, `ASSERTIONS.txt`,
`SHA256SUMS`, `RUN-SHA256SUMS`, `DRY-RUN-MANIFEST.json`, and
`DRY-RUN-RESULT.md`; and keeps the same non-sending boundary as the template.
The manifest is a machine-readable result envelope that records the explicit
target, observed commit, assertion counts, artifact hashes, run-file hashes,
privacy flags, and non-claim flags. It sends no verifier request, contacts no
verifier, creates no public external attestation, and does not prove
non-operator review.

For `v3.3.98+` targets, the helper also preserves
`zlar-north-star-readiness-v1.json`. This is a bounded North Star closure
report over the preserved release-forward artifacts. It records which puzzle
pieces are locally proven, partial, or unproven. The default release-forward
helper uses a no-assets public-distribution fixture and reports
`NOT_READY_FOR_V3_4_0`; that default helper path does not prove v3.4.0 readiness.
A derived evidence directory that substitutes a live GitHub
release-asset public-distribution report may report
`READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION`. That is only boundary-
release readiness. It does not prove external attestation, non-operator review,
production authority, enterprise readiness, sovereign recognition,
current-machine governance, live hooks, live MCP coverage, live
approval-channel health, live trust-registry state, key custody, revocation
truth, production downstream recognition, persistent runtime profile
installation, production service deployment, all-MCP governance, or coverage of
unrouted surfaces.

For `v3.3.100+` targets, the helper also preserves
`zlar-verifier-kit-reproducibility-v1.json`. This report builds the verifier
kit twice from the same source tree with one temporary test publisher key and
requires identical tarball, manifest, and manifest-signature SHA-256 values.
It lists public artifact hashes for the tarball, sidecar, `MANIFEST.json`, and
`MANIFEST.sig`. It does not prove production publisher key custody, production
signing identity, public release publication, external attestation, live
trust-registry state, revocation truth, enterprise readiness, or v3.4.0
readiness.

For `v3.3.109+` targets, the helper also preserves
`zlar-verifier-kit-public-distribution-v1.json` and the supplied
`zlar-verifier-kit-release-assets-v1.json`. The default release-forward helper
uses an explicit no-assets fixture because it does not depend on `gh` or live
GitHub release asset queries. The posture audit still checks the local
verifier-kit artifact hashes against the reproducibility report and names why
`ready_for_public_distribution_claim=false`. A real GitHub release-assets JSON
export can be substituted later with
`evidence_model: "github-release-assets-json-live-read"`, a release URL that
names the target tag, explicit `isDraft: false`, required assets with
`state: "uploaded"`, positive sizes, and either GitHub
`digest: "sha256:<hash>"` fields or downloaded `downloaded_sha256` values.
Publication evidence belongs to that live release-asset JSON; the
reproducibility report remains source-build determinism evidence and continues
to say it does not prove public release publication. This report does not upload assets,
read private keys, prove production publisher key custody, create external
attestation, prove non-operator review, or prove enterprise readiness.

For the `v3.4.2` prepared target, a verifier can additionally create a live
release-asset JSON export from the public GitHub Release and run the byte-bound
public distribution check with `--require-public`:

```bash
bin/zlar verifier-kit-release-assets-live-read \
  --release-tag v3.4.2 \
  --download-dir zlar-verifier-kit-release-assets \
  --json-out zlar-verifier-kit-release-assets-live-v1.json

tar -xzf zlar-verifier-kit-release-assets/zlar-verifier-kit-v0.1.0.tar.gz \
  -C zlar-verifier-kit-release-assets

bin/zlar verifier-kit-public-distribution \
  --release-tag v3.4.2 \
  --release-assets-json zlar-verifier-kit-release-assets-live-v1.json \
  --reproducibility zlar-verifier-kit-release-assets/zlar-verifier-kit-reproducibility-v1.json \
  --asset-dir zlar-verifier-kit-release-assets \
  --require-public \
  --json-out zlar-verifier-kit-public-distribution-live-v1.json
```

The live-read helper emits `github-release-assets-json-live-read` evidence with
downloaded SHA-256 values for the release assets. With `--download-dir`, it also
saves the downloaded asset bytes so the tarball can be extracted and checked
against the reproducibility report.

This live release-asset read can support only the bounded
`READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION` evidence path when the
required assets are present, explicit public-release evidence is supplied,
public release-asset byte hashes match the reproducibility evidence, and the
local downloaded/extracted artifact hashes match the reproducibility report. It
still does not create external attestation, prove non-operator review, prove
production publisher key custody, prove production signing identity, prove
production authority, prove enterprise readiness, prove sovereign recognition,
prove live trust-registry or revocation truth, prove production downstream
recognition, prove all-MCP governance, or cover unrouted surfaces.

For `v3.3.104+` targets, the helper also preserves
`zlar-private-verifier-result-v1.json` and
`zlar-private-verifier-result-verification-v1.json`. These files are a
generated sample fixture over the dry-run packet's own artifacts. The
verification recomputes declared hashes with `--evidence-dir ..` and proves
only that the private-intake envelope shape can be checked against the
preserved dry-run evidence. It is not a real verifier reply, not non-operator
review, not public attribution, and not public external attestation. The
manifest includes a non-circular `private_verifier_result_sample` pointer to
these files and to the `DRY-RUN-RESULT.md` hash section, but does not include
the generated private-intake sample files in the core `artifact_hashes` list.
The North Star readiness report generated with `--release-tag` records the
same bounded pointer contract without reading the manifest or creating a
circular hash. For `v3.3.107+` targets, `DRY-RUN-RESULT.md` also includes a
`Private Intake Pointer Contract` section that summarizes both the
manifest-side pointer and the readiness report-side pointer for human review.
That section is readability evidence only; it does not create public external
attestation or prove non-operator review.

For `v3.4.34+` targets, `DRY-RUN-RESULT.md` also includes a `Private Result
Verification Evidence` section showing the verifier-result verification
verdict, recomputed evidence-dir hash status, artifact count, sample fixture
and non-operator boundary, and false public-attestation/public-attribution
flags. That section is still generated sample evidence. It is not a real
non-operator reply and is not public external attestation.

For `v3.3.97+` targets, the helper also preserves
`zlar-trusted-receipt-issuer-recognition-malformed-registry.json` and
`zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt`. This
is portable schema-contract fail-closed evidence only: the supplied fixture is
intentionally malformed, the scanner must exit with error before any
`RECOGNIZED` or `RECOGNITION-REFUSED` verdict, and the artifact does not prove
live trust-registry state, custody, revocation truth, production downstream
recognition, or external attestation.

For release targets at `v3.3.61` or later, preserve the coverage JSON and
confirm that reported surfaces carry `coverage_summary`, `last_decision`,
`last_receipt`, `issuer_identity`, and `known_boundaries`. Those fields are
supplied-evidence summaries. They do not prove live hook state, active issuer
status, key custody, revocation truth, production trust-registry state,
external attestation, sovereign recognition, production authority, or coverage
of unrouted surfaces.

For release targets at `v3.3.64` or later, preserve the verifier-kit
issuer-status fixture JSON. That command builds the source-form verifier kit
and runs `node verify-issuer-status.mjs` after bundle self-test. It proves only
that the bundled local fixture recognition rule distinguishes active, retired,
compromised, missing-status, unknown, and missing-key fixture issuers. It does
not prove live active issuer status, key custody, revocation truth, production
trust-registry state, production downstream recognition, external attestation,
sovereign recognition, production authority, or coverage of unrouted surfaces.

For release targets at `v3.3.67` or later, the external-runner dry-run can
write the issuer-status JSON artifact directly with
`--issuer-status-json-out <file>`. The helper writes only the already-validated
fixture JSON, refuses to overwrite an existing artifact file, and does not print
the local output path in the transcript. This is artifact-preservation hygiene,
not a verifier request, external attestation, live issuer-status proof, custody
proof, revocation proof, production trust-registry proof, downstream-recognition
proof, sovereign-recognition proof, production-authority proof, or coverage of
unrouted surfaces.

For release targets at `v3.4.21` or later, preserve
`zlar-verifier-kit-external-runner-diagnostics-v1.json`. Here
`external-runner` means the bundled verifier-kit helper file, not a human
external verifier. The report proves the `v3.4.20` verifier-kit
external-runner diagnostic hardening is present in the source-built verifier
packet: the built helper hash matches the kit manifest entry and source helper,
the last-output check uses the pipefail-safe Bash substring form instead of
`grep -q`, and the issuer-status JSON artifact is verified. The report also
states that repo-side regression tests are not inside the built kit. This is
packet preservation evidence only; it is not live probing, a verifier request,
external attestation, non-operator review, production authority, enterprise
readiness, current-machine governance, sovereign recognition, or coverage of
unrouted surfaces.

For release targets at `v3.3.94` or later, preserve the trusted receipt issuer
registry recognition JSON. That command evaluates the bundled sample receipt
against the bundled `trusted-receipt-issuers-v1` registry fixture after bundle
self-test. It proves only supplied fixture recognition for one receipt under
one local registry fixture. It does not prove live trust-registry state, key
custody, revocation truth, production downstream recognition, external
attestation, sovereign recognition, production authority, or coverage of
unrouted surfaces.

For release targets at `v3.3.76` or later, preserve the proof-smoke active
profile selection counts and the local proof-pack verifier's embedded
`active_profile_selection` summary. The expected bounded facts are:
`active_profile_selection_verified=true`, `active_profile_selected=true`,
`active_profile_selects_latest=false`,
`active_profile_live_runtime_profile_checked=false`, and
`active_profile_persistent_runtime_profile_installed=false`. The local
proof-pack verifier summary should preserve
`selection_scope=local-disposable-proof-harness`,
`profile_id=protected-records-runtime-fixture-profile`,
`runtime_profile_id=protected-records-disposable-runtime-profile`,
`selects_latest_profile=false`, `persistent_runtime_profile_installed=false`,
and `live_runtime_profile_checked=false`. These fields are fixture-contained
sample-contract evidence only. They do not prove persistent runtime profile
installation, hook activation, live/current-machine runtime profile state,
current-machine governance, production authority, external attestation, or
coverage of unrouted surfaces.

For release targets at `v3.3.81` or later, also preserve the proof-smoke
runtime-profile installation counts and the local proof-pack verifier's
embedded `runtime_profile_installation` summary. The expected bounded facts are:
`runtime_profile_installation_applied=true`,
`runtime_profile_installation_request_authority_guard_refused=true`,
`runtime_profile_installation_selects_latest=false`,
`runtime_profile_installation_persistent_profile_installed=false`, and
`runtime_profile_installation_hook_configuration_written=false`. The embedded
summary should preserve disposable install root creation, profile copy, active
profile index write, explicit id-and-SHA selection, request authority guard
refusal, no persistent profile install, no hook/user/machine configuration, and
no live/current-machine profile claim. These fields are fixture-contained
sample-contract evidence only. They do not prove persistent runtime profile
installation, hook activation, user or machine configuration, live/current-
machine runtime profile state, current-machine governance, production
authority, external attestation, or coverage of unrouted surfaces.

For release targets at `v3.4.5` or later, also preserve the read-only
installed-runtime-profile preflight sample verification. The expected bounded
facts are: `installed_runtime_profile_preflight_sample_artifact_verified=true`,
`installed_runtime_profile_preflight_read_only=true`,
`installed_runtime_profile_preflight_selected=true`,
`installed_runtime_profile_preflight_selects_latest=false`,
`installed_runtime_profile_preflight_installation_performed=false`,
`installed_runtime_profile_preflight_activation_performed=false`,
`installed_runtime_profile_preflight_downstream_refusal_proven=false`, and
`installed_runtime_profile_preflight_current_machine_governance_proven=false`.
The standalone `zlar-installed-runtime-profile-preflight-sample-verification.json`
should preserve the same no-effect boundary. This is selector-integrity preflight evidence only. It does not prove persistent installation, activation, runtime-service start, hook/user/machine configuration, downstream refusal, current-machine governance, production authority, external attestation, or coverage of unrouted surfaces.

For release targets at `v3.4.6` or later, that same installed-runtime-profile
preflight sample verification must also preserve
`installed_runtime_profile_preflight_recognition_contract_preserved=true`.
This records the selected profile recognition contract, launcher-owned
recognition boundary, mutation-authoritative route, and required refusal-case
count. It does not prove production downstream recognition.

For release targets at `v3.4.7` or later, also preserve
`zlar-installed-runtime-profile-recognition-proof-v1.json`. The expected
bounded facts are:
`installed_runtime_profile_recognition_proof_verified=true`,
`installed_runtime_profile_recognition_recognized_write_boarded=true`,
`installed_runtime_profile_recognition_refusal_case_count=18`,
`installed_runtime_profile_recognition_all_refusals_before_mutation=true`,
`installed_runtime_profile_recognition_runtime_service_started=false`,
`installed_runtime_profile_recognition_current_machine_governance_proven=false`,
and
`installed_runtime_profile_recognition_production_downstream_recognition=false`.
This is local hermetic selected-profile recognition proof only. It does not
start a live runtime service, prove current-machine governance, or prove
production downstream recognition.

For release targets at `v3.4.8` or later, also preserve
`zlar-installed-runtime-profile-recognition-proof-artifact-v1.json` and
`zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json`.
The artifact is a checksummed portable wrapper for the same local hermetic
recognition proof. The verification file checks artifact integrity and embedded
proof boundaries without rerunning the proof. This is artifact checkability
only; it does not create install, activation, live governance, production
downstream recognition, external attestation, enterprise readiness, or
sovereign recognition.

For release targets at `v3.4.9` or later, also preserve
`zlar-product-proof-path-v1.json`. The expected bounded facts include:
`report_type=zlar-product-proof-path-v1`, `result=PASS`, an explicit bounded
Product Proof Path evidence model, `live_probing=false`,
`private_operator_state_required=false`, all acceptance gates true,
all forbidden-claim flags false, simulated-human fixture authorization,
receipt-verifier `VALID` / `UNKNOWN-SIGNER` / `INVALID` separation, and visible
trusted issuer registry recognition facts including
`trusted_issuer_registry_recognition_observed=true`,
`registry_type=trusted-receipt-issuers-v2`,
`registry_evidence_model=bundled-local-fixture`, `live_probing=false`,
`registry_fixture_validated=true`, `registry_fixture_evaluated=true`,
`registry_to_recognition_rule_evaluated=true`,
`registry_evaluation_result_type=downstream-recognition-rule-v1`,
`verdict=RECOGNIZED`, `issuer_status=active`, `signature_valid=true`,
`malformed_registry_fail_closed_before_verdict=true`, false live-registry,
live-issuer-status, key-custody, revocation, production-registry,
production-recognition, production-authority, sovereign-recognition,
public-attestation, real-non-operator-review, and current-machine-governance
flags, and visible known ungoverned boundaries including
`unrouted_records_paths`. This is fresh local fixture Product Proof Path
evidence only. It does not prove live human approval, approval-channel health,
live trust-registry state, live issuer status, key custody, revocation truth,
current-machine governance, production trust
registry state, production downstream recognition, production authority,
external attestation, enterprise readiness, sovereign recognition, all-MCP
governance, or coverage of unrouted surfaces. For `v3.4.10+` targets, the North
Star readiness report also
consumes this artifact directly and records `product_proof_path_verified=true`
only when those bounded Product Proof Path gates remain intact.
For `v3.4.45+` targets, also confirm the report includes
`evidence_model=fresh-local-fixture-proof-pack-and-terminal-chain-artifact-verification`,
`terminal_chain_boundary.verified=true`, matching trusted-issuer registry
binding/refusal hashes, exact trusted-registry refusal IDs/reasons, omitted raw
public-key material, omitted receipt envelope, `external_attestation=false`, and
`current_machine_governance_proven=false`.
Current local post-v3.4.50 proof-hardening also requires the Product Proof Path
and North Star readiness summaries to preserve the terminal-chain binding's
local `RECOGNIZED` verdict, issuer status, signature validity, local registry
evaluation facts, and contract hashes. This remains bundled local fixture
evidence only, not live registry state or production recognition.
It also requires those summaries to preserve the proof-pack downstream-refusal
marker boundary: recognized marker-count delta one, final marker count one,
exact refusal count/reasons, all refusals unboarded, and all refusal
marker-count deltas zero. This is local hermetic fixture evidence only, not
live downstream recognition or production authority.
For `v3.4.46+` targets, also confirm
`terminal_chain_boundary.recognition_refusal_group_count=3`,
`recognition_refusal_group_case_count=18`,
`recognition_refusal_group_case_ids_preserved=true`, and the exact grouped
recognition-refusal case-ID map.
For `v3.4.48+` targets, also confirm
`evidence_model=fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge`,
`acceptance_gate.deployment_profile_authority_bridge_observed=true`,
`deployment_profile_authority_bridge.selected_by_explicit_id_and_sha=true`,
`selects_latest_profile=false`, `preflight_artifact_verified=true`,
`recognized_receipt_mutates_once=true`, `observed_refusal_case_count=18`,
`agent_supplied_authority_refused_before_mutation=true`,
`request_stream_authority_material_accepted=false`,
`current_machine_governance=false`, `production_authority=false`, and
`external_attestation=false`.
For `v3.4.49+` targets, also confirm
`deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_count=5`,
`deployment_profile_authority_refusal_case_ids` lists the five pre-service
authority refusal cases, `deployment_profile_authority_refusals_before_service_proof=true`,
and `deployment_profile_authority_refusal_service_proof_started=false`.
For `v3.4.50+` targets, also confirm the terminal-chain/proof-smoke/North Star
mirror of the same five-case list:
`installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true`,
`installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count=5`,
the exact five `installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids`,
`installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof=true`,
and `installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started=false`.

For release targets at `v3.4.11` or later, also preserve
`zlar-installed-runtime-profile-service-proof-v1.json`,
`zlar-installed-runtime-profile-service-proof-artifact-v1.json`, and
`zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`.
The expected bounded facts are:
`installed_runtime_profile_service_proof_verified=true`,
`installed_runtime_profile_service_runtime_service_started=true`,
`installed_runtime_profile_service_disposable_runtime_config_written=true`,
`installed_runtime_profile_service_persistent_runtime_config_written=false`,
`installed_runtime_profile_service_recognized_write_boarded=true`,
`installed_runtime_profile_service_refusal_case_count=18`,
`installed_runtime_profile_service_all_refusals_before_mutation=true`,
`installed_runtime_profile_service_source_preflight_downstream_refusal_proven=false`,
`installed_runtime_profile_service_install_performed=false`,
`installed_runtime_profile_service_activation_performed=false`,
`installed_runtime_profile_service_current_machine_governance_proven=false`,
and
`installed_runtime_profile_service_production_downstream_recognition=false`.
This is local disposable child-service evidence only. It does not prove
persistent installation, activation, live runtime service, hook/user/machine
configuration, current-machine governance, production downstream recognition,
enterprise readiness, external attestation, or coverage of unrouted surfaces.
For `v3.4.14+` targets, the North Star readiness report also consumes
`zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`
and records `installed_runtime_profile_service_artifact_verification_required=true`
plus
`installed_runtime_profile_service_artifact_verification_preserved=true` only
when the service-proof artifact verifier preserves an artifact hash bound to
the supplied service proof, proof payload type, replay refusal, rollback-refusal
counts, before-mutation refusal result, and false current-machine/production
flags.
For `v3.4.18+` targets, the readiness report must also preserve
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required=true`
and
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved=true`,
with the verifier's canonical `refusal_taxonomy_sha256` bound to exact
case ids, reason codes, and before-mutation facts.
For `v3.4.19+` targets, the readiness report must also preserve
`installed_runtime_profile_recognition_contract_digest_required=true`,
`installed_runtime_profile_recognition_contract_digest_preserved=true`, and a
canonical `installed_runtime_profile_recognition_contract_sha256` bound across
preflight, service proof, service-proof artifact verification, terminal chain,
and terminal-chain artifact verification.
For `v3.4.22+` targets, the readiness report must also preserve
`installed_runtime_profile_terminal_chain_named_receipt_refusals_required=true`
and
`installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved=true`,
with a canonical `named_receipt_refusals_sha256` bound across the terminal
chain and terminal-chain artifact verification for missing, invalid, stale,
unknown-issuer, wrong-policy, wrong-domain, and wrong-tool receipt cases.
For `v3.4.23+` targets, the readiness report must also preserve
`installed_runtime_profile_terminal_chain_recognition_refusal_groups_required=true`
and
`installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved=true`,
with a canonical `recognition_refusal_groups_sha256` bound across the terminal
chain and terminal-chain artifact verification for no usable recognized receipt
authority, recognized receipt scope mismatch, and route/request authority
material refusal groups.
For `v3.4.24+` targets, the release-forward manifest must also report
`recognition_refusal_group_case_ids_required=true` and
`all_recognition_refusal_group_case_ids_preserved=true`, and `DRY-RUN-RESULT.md`
must print the exact case-id lists for no usable recognized receipt authority,
recognized receipt scope mismatch, and route/request authority material refusal
groups.
For `v3.4.25+` targets, proof-smoke and North Star readiness must also preserve
that exact report contract directly:
`group_count=3`, `case_count=18`, and exact grouped case IDs for both
terminal-chain evidence and terminal-chain artifact verification.
For `v3.4.26+` targets, the North Star readiness Enterprise Deployment Profile
and Downstream Recognition Rule observed summaries must also mirror that
preserved case-ID contract, including `group_count=3`, `case_count=18`, and
artifact-verification counts.
For `v3.4.28+` targets, terminal-chain evidence and its portable artifact must
also preserve nested generated preflight and service-proof artifacts, and the
verifier must refuse forged inner preflight and service-proof summary hashes
after the outer terminal-chain artifact integrity is recomputed.
For `v3.4.30+` targets, proof-smoke, North Star readiness, and the
release-forward manifest must also preserve the verifier-owned
`nested_artifact_binding` summary from terminal-chain artifact verification.
For `v3.4.37+` targets, proof-smoke and North Star readiness must also preserve
the terminal-chain trusted issuer registry recognition binding from both
terminal-chain evidence and terminal-chain artifact verification: stable
registry/receipt contract hashes, `registry_receipt_contract_hash_bound=true`,
and false embedded-key, embedded-envelope, and artifact-only cryptographic
reconstruction flags. This remains bundled-local-fixture evidence; the
terminal-chain artifact does not embed raw public-key material or the receipt
envelope and is not sufficient by itself to reproduce cryptographic registry
recognition.
For `v3.4.38+` targets, that same binding must also preserve terminal-chain-
local trusted-registry refusal evidence: unrecognized registry scope refused
with `scope_not_found`, registry/receipt contract mismatch refused with
`detail_hash_mismatch`, `all_refused=true`, and a canonical
`trusted_issuer_registry_recognition_refusals_sha256`.
For `v3.4.39+` targets, proof-smoke and North Star readiness must also surface
that refusal contract in first-class evaluator summaries: case count, exact case
IDs, exact reason codes, `all_refused=true`, and refusal SHA-256 for both
terminal-chain evidence and terminal-chain artifact verification. Readiness
observed summaries for puzzle pieces 3 and 5 must mirror the same fields.
For `v3.4.39+` targets, `DRY-RUN-MANIFEST.json` and `DRY-RUN-RESULT.md` must
also surface that same trusted-registry refusal summary under
`terminal_chain_refusal_evidence`: exact case count, exact case IDs, exact
reason codes, `all_refused=true`, matching terminal-chain/artifact-verification
refusal hashes, and
`all_trusted_issuer_registry_recognition_refusals_preserved=true`.
`DRY-RUN-RESULT.md`
must include `Release-Forward Report Contract` with those counts plus false
public-external-attestation, production-authority, current-machine-governance,
live-MCP-coverage, and unrouted-surface-coverage flags.
For `v3.4.41+` targets, `DRY-RUN-MANIFEST.json` must also include
`release_forward_report_contract`, a compact machine-readable summary of the
existing release-forward dry-run report contract. The object is derived only
from preserved local dry-run artifacts and same-manifest evidence.
`DRY-RUN-RESULT.md` renders that object as
`manifest.release_forward_report_contract.*` lines for human review. The
manifest remains canonical. This is not a new verifier result, not
non-operator review, not public external attestation, not live registry state,
not key custody or revocation truth, not current-machine governance, not
production downstream recognition, not production authority, not enterprise
readiness, not sovereign recognition, and not unrouted-surface coverage.
For `v3.4.42+` targets, that canonical object must also bind
`ZLAR/zlar-product-proof-path-v1.json` by source path/SHA-256 and compact
Product Proof Path fields: PASS/evidence model, receipt-verifier boundary,
North Star consumption, false forbidden claims, and known unrouted-records
noncoverage visibility.
For `v3.4.45+` targets, that Product Proof Path contract must also carry the
public-safe terminal-chain boundary consumed by Product Proof Path: terminal
artifact verification, binding/refusal hashes, exact trusted-registry refusal
IDs/reasons, omitted public-key material, omitted receipt envelope, false
external attestation, and false current-machine governance.
Current local post-v3.4.50 proof-hardening also keeps the terminal-chain
binding's local `RECOGNIZED` verdict, issuer status, signature validity, local
registry evaluation facts, and contract hashes visible in Product Proof Path and
North Star readiness summaries.
It also keeps the proof-pack downstream-refusal marker boundary visible in
Product Proof Path and North Star readiness summaries: recognized marker-count
delta one, final marker count one, exact refusal count/reasons, all refusals
unboarded, and all refusal marker-count deltas zero.
For `v3.4.46+` targets, that contract must also carry the exact grouped
recognition-refusal case IDs from the Product Proof Path terminal-chain
boundary.
For `v3.4.48+` targets, that contract must also carry the Product Proof Path
deployment-profile authority bridge and North Star mirror: explicit deployment
profile/runtime profile SHA binding, no `--latest`, verified preflight, one
recognized receipt mutation, 18/18 zero-mutation refusals, agent/request
authority-material refusal, direct API refusal, and false
current-machine/production/external/sovereign/unrouted flags.
For `v3.4.49+` targets, that contract must also carry the exact five-case
deployment-profile authority-refusal list and the before-service-proof boundary
in both Product Proof Path and North Star mirrors.
For `v3.4.50+` targets, that contract must also carry the same five-case
authority-refusal mirror through terminal-chain evidence, proof-smoke counts,
and North Star counts.

For `v3.4.15+` targets, also preserve
`zlar-installed-runtime-profile-terminal-chain-v1.json`,
`zlar-installed-runtime-profile-terminal-chain-artifact-v1.json`, and
`zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`.
The North Star readiness report consumes the terminal-chain JSON and its
artifact verification and records
`installed_runtime_profile_terminal_chain_required=true` plus
`installed_runtime_profile_terminal_chain_preserved=true` only when the generated
installed-root preflight, generated preflight consumption, generated service-
proof artifact verification, service-proof/preflight binding, artifact/service-
proof binding, recognized write boarding, missing/invalid receipt refusal, all
18 selected-profile refusals before mutation, and false persistent-install/
activation/current-machine/production flags remain intact. This is launcher-
owned disposable terminal-chain evidence only. It does not prove persistent
install, runtime activation, hook/user/machine configuration, live records
service deployment, current-machine governance, production downstream
recognition, enterprise readiness, external attestation, sovereign recognition,
or coverage of unrouted records paths.

For release targets at `v3.3.85` or later, also preserve
`zlar-service-preflight-sample-verification.json`. The expected bounded facts
are: `verified=true`,
`evidence_model=local-disposable-config-backed-profile-preflight-fixture`,
`case_count=10`, `required_case_count=10`,
`launcher_owned_config_required=true`,
`request_stream_authority_material_refused=true`,
`request_stream_authority_material_reason=request_stream_authority_material`,
`request_stream_authority_material_state_delta=0`,
`direct_api_receipt_present_reason=request_stream_forbidden_fields`,
`production_records_service_checked=false`, and
`external_attestation=false`. These fields are sample service-profile preflight
evidence only. They do not prove active profile installation, live records
system evidence, production service deployment, current-machine governance,
external attestation, sovereign recognition, or coverage of unrouted surfaces.

For release targets at `v3.3.90` or later, also preserve the expanded
runtime-local-activation and runtime-profile-installation refusal taxonomy in
`zlar-runtime-local-activation-sample-verification.json`,
`zlar-runtime-profile-installation-sample-verification.json`, and the embedded
local proof-pack summaries. The expected bounded facts include:
`wrong_policy_refused=true`, `wrong_domain_refused=true`,
`wrong_tool_refused=true`, `wrong_runtime_profile_id_refused=true`,
`wrong_audit_event_refused=true`,
`wrong_detail_refused=true`, `non_boarding_outcome_refused=true`,
`stale_receipt_refused=true`, `missing_issuer_status_refused=true`,
`direct_api_with_receipt_refused=true`, and
`agent_supplied_authority_material_refused=true`. These fields prove only the
committed local disposable runtime/profile-installation samples and embedded
summary contract. They do not prove persistent runtime profile installation,
hook activation, live/current-machine runtime profile state, live records-system
evidence, production service deployment, current-machine governance, external
attestation, sovereign recognition, or coverage of unrouted surfaces.

Historical pinned-release contract only: for release targets at `v3.3.91` or
later, preserve the service-profile coverage lane in
`zlar-proof-smoke-sample-verification.json` and
`zlar-coverage-map-sample.json`. The historical bounded facts include:
`governed_lanes=6`, `counted_lanes=6`, and a governed
`protected-records.service-profile.records.write` surface with receipt-capable
status and `runtime_profile_not_installed` in its known boundaries. These
fields prove only the committed local disposable service-profile preflight artifact:
launcher-owned config routing, one recognized `records.write` acceptance, and
refusal before service-state mutation for replay, missing, unrecognized,
invalid, unknown-issuer, stale, request-stream authority-material, no-receipt
direct API, and direct-API-with-receipt cases. For release targets at
`v3.3.93` or later, also preserve `wrong_policy_refused=true`,
`wrong_policy_reason=policy_not_recognized`, and
`wrong_policy_state_delta=0`. They do not prove
runtime activation, persistent profile installation, live/current-machine
governance, production service deployment, external attestation, sovereign
recognition, enterprise readiness, or coverage of unrouted records paths.

Current checkout note: its static coverage result is `4/6`, not `6/6`.
Runtime profile-installation and installed terminal-chain are counted but
`receipt_not_capable` under the exhausted grant. The `6/6` contract above is
historical for the named release targets and must not be projected forward.

For release targets at `v3.3.98` or later, also preserve
`zlar-north-star-readiness-v1.json`. The expected bounded facts include:
`result=NOT_READY_FOR_V3_4_0` for the default no-assets release-forward path,
seven North Star puzzle pieces,
`public_external_attestation=false`, `production_authority=false`,
`current_machine_governance=false`, `live_mcp_coverage=false`,
`unrouted_surface_coverage=false`, trusted issuer registry fixture recognition
marked as provided, and malformed-registry schema-contract refusal marked as
fail-closed before verdict. For `v3.3.100+` targets, the expected bounded facts
also include `verifier_kit_reproducibility.provided=true`, reproducible tarball,
manifest, and manifest-signature hash stability, sidecar match, public artifact
hashes present, and false claim-boundary flags for the verifier-kit
reproducibility report. For `v3.3.109+` targets, they also include
`verifier_kit_public_distribution.provided=true`,
`ready_for_public_distribution_claim=false`, public artifact hashes present,
and named blockers for the public distribution claim in the no-assets path.
When a live public-distribution report is substituted after public release
asset publication, the expected bounded facts may instead include
`READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION`,
`ready_for_public_distribution_claim=true`, and zero public-distribution
blockers. This report is a closure audit over preserved local fixture artifacts
and supplied release evidence. It does not prove external attestation,
non-operator review, production authority, enterprise readiness, sovereign
recognition, current-machine governance, live hooks, live MCP coverage, live
trust-registry state, key custody, revocation truth, production downstream
recognition, persistent runtime profile installation, production service
deployment, all-MCP governance, or coverage of unrouted surfaces.

Historical optional fresh local fixture proof interface:

The current checkout must not run this positive lane. The exact one-use grant
is exhausted, so `local-proof-pack` refuses before proof execution and its
legacy artifact remains historical-only even when exact-SHA pinned. A future
verifier campaign requires an explicit replacement or per-run campaign grant
and a new artifact-bound schema.

```bash
bin/zlar local-proof-pack --artifact ./zlar-local-proof-pack-artifact.json
bin/zlar local-proof-pack verify --input ./zlar-local-proof-pack-artifact.json
bin/zlar local-proof-pack verify --input ./zlar-local-proof-pack-artifact.json --json > zlar-local-proof-pack-verification.json
```

At releases where the historical interface was active, the optional proof
generated local fixture evidence on the verifier's machine. It did not inspect
live hooks, live audit stores, Vincent's machine, production systems, Telegram
delivery, or current-machine governance.

## Evidence To Preserve

Ask the verifier to preserve:

- release tag and commit SHA from `git rev-parse HEAD`;
- terminal transcript or CI log for every command they ran;
- `bin/zlar verifier-env` output;
- `zlar-verifier-env-report-v0.json`;
- `bash tools/build-verifier-kit.sh --check-env` output;
- `zlar-proof-smoke-v1.json`;
- `zlar-proof-smoke-generated-verification.json`, when using the
  release-forward template;
- `zlar-proof-smoke-sample-verification.json`;
- `zlar-service-preflight-sample-verification.json`, when reviewing a
  `v3.3.85+` release-forward target;
- `zlar-local-proof-pack-sample-verification.json`;
- active-profile selection counts and embedded proof-pack
  `active_profile_selection` summary, when reviewing a `v3.3.76+`
  release-forward target;
- runtime-profile installation counts and embedded proof-pack
  `runtime_profile_installation` summary, when reviewing a `v3.3.81+`
  release-forward target;
- `zlar-issuer-status-proof.json`, when using the release-forward template;
- `zlar-verifier-kit-issuer-status-fixture.json`, when reviewing a
  `v3.3.64+` release-forward target;
- `zlar-runtime-local-activation-sample-verification.json`;
- `zlar-runtime-profile-installation-sample-verification.json`;
- `zlar-installed-runtime-profile-preflight-sample-verification.json`, when
  reviewing a `v3.4.5+` release-forward target;
- `zlar-installed-runtime-profile-recognition-proof-v1.json`, when reviewing a
  `v3.4.7+` release-forward target;
- `zlar-installed-runtime-profile-recognition-proof-artifact-v1.json` and
  `zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json`,
  when reviewing a `v3.4.8+` release-forward target;
- `zlar-installed-runtime-profile-service-proof-v1.json`,
  `zlar-installed-runtime-profile-service-proof-artifact-v1.json`, and
  `zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`,
  when reviewing a `v3.4.11+` release-forward target; for `v3.4.14+`, the
  readiness report must also preserve
  `installed_runtime_profile_service_artifact_verification_required=true` and
  `installed_runtime_profile_service_artifact_verification_preserved=true`;
  for `v3.4.18+`, it must also preserve
  `installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required=true`
  and
  `installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved=true`;
  for `v3.4.19+`, it must also preserve
  `installed_runtime_profile_recognition_contract_digest_required=true`,
  `installed_runtime_profile_recognition_contract_digest_preserved=true`, and
  `installed_runtime_profile_recognition_contract_sha256`;
- `zlar-installed-runtime-profile-terminal-chain-v1.json`,
  `zlar-installed-runtime-profile-terminal-chain-artifact-v1.json`, and
  `zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`,
  when reviewing a `v3.4.15+` release-forward target; the readiness report must
  also preserve `installed_runtime_profile_terminal_chain_required=true` and
  `installed_runtime_profile_terminal_chain_preserved=true`; for `v3.4.25+`,
  proof-smoke and readiness must also preserve terminal-chain recognition-
  refusal `group_count=3`, `case_count=18`, and exact grouped case IDs for both
  terminal-chain evidence and terminal-chain artifact verification; for
  `v3.4.26+`, readiness observed summaries for puzzle pieces 3 and 5 must
  mirror the same case-ID preservation counts; for `v3.4.28+`, terminal-chain
  evidence and its portable artifact must also preserve nested generated
  preflight and service-proof artifacts, and forged inner preflight and
  service-proof hash artifacts must be refused; for `v3.4.30+`, the
  verifier-owned terminal-chain artifact-verification `nested_artifact_binding`
  summary must also be preserved; for `v3.4.39+`, proof-smoke and readiness
  must expose the trusted-registry refusal contract as summary fields, including
  case count, exact case IDs, exact reason codes, `all_refused=true`, and
  refusal SHA-256; for `v3.4.39+` targets, the release-forward manifest and result must
  also expose that same trusted-registry refusal summary with matching
  terminal-chain/artifact-verification refusal hashes; for `v3.4.50+`,
  proof-smoke, North Star readiness, the release-forward manifest/result, and
  the report contract must also expose the terminal-chain deployment-profile
  authority-refusal mirror with exact five case IDs, before-service-proof
  refusal, before-mutation refusal, and service-proof-not-started;
- `zlar-product-proof-path-v1.json`, when reviewing a `v3.4.9+`
  release-forward target; for `v3.4.45+`, the report must also carry verified
  terminal-chain artifact boundary facts, binding/refusal hashes, exact
  trusted-registry refusal IDs/reasons, omitted public-key material, omitted
  receipt envelope, false external attestation, and false current-machine
  governance; for `v3.4.46+`, it must also carry exact grouped
  recognition-refusal case IDs; for `v3.4.48+`, it must also carry the local
  fixture deployment-profile authority bridge with explicit profile SHA
  binding, no `--latest`, one recognized mutation, 18/18 zero-mutation
  refusals, and false production/current-machine claim flags; for `v3.4.49+`,
  it must also carry the exact five deployment-profile authority refusals
  before service proof starts;
- `zlar-coverage-map-sample.json`, when using the release-forward template;
- `zlar-north-star-readiness-v1.json`, when reviewing a `v3.3.98+`
  release-forward target;
- `zlar-verifier-kit-reproducibility-v1.json`, when reviewing a `v3.3.100+`
  release-forward target;
- `zlar-verifier-kit-external-runner-diagnostics-v1.json`, when reviewing a
  `v3.4.21+` release-forward target; the report is bundled-helper diagnostic
  preservation evidence, not human external attestation;
- `zlar-verifier-kit-release-assets-v1.json` and
  `zlar-verifier-kit-public-distribution-v1.json`, when reviewing a
  `v3.3.109+` release-forward target;
- `zlar-private-verifier-result-v1.json` and
  `zlar-private-verifier-result-verification-v1.json`, when reviewing the
  helper-generated sample private-intake check for a `v3.3.104+`
  release-forward target;
- optional `zlar-local-proof-pack-artifact.json`;
- optional `zlar-local-proof-pack-verification.json`;
- verifier environment notes: OS, shell, Node.js version, `jq` version,
  OpenSSL version, date, and timezone.

## Verifier Environment Failure Report v0

If `bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json` or
`bash tools/build-verifier-kit.sh --check-env` reports `Result: FAIL`, preserve
a private, redacted, machine-readable verifier environment prerequisite failure
report before changing the verifier environment.

Recommended failure files:

- `zlar-verifier-env-output.txt`;
- `zlar-verifier-kit-check-env-output.txt`;
- `zlar-verifier-env-report-v0.json`;
- `zlar-verifier-env-failure-report-v0.json`, when the JSON `schema` is
  `zlar-verifier-env-failure-report-v0`;
- `zlar-verifier-env-failure-report-v0.sha256`, if a checksum file is created.

The JSON report is failure evidence only. It records prerequisite status,
sanitized tool/version observations, redacted failure output, and the claim
boundary. It must not include usernames, hostnames, raw `PATH`, private
filesystem paths, tokens, emails, private-key material, Telegram identifiers,
or verifier identity unless separately approved for private intake.

This report is private by default. It is not a ZLAR proof run, not a public
external attestation, not key custody evidence, not live issuer-status evidence,
not production authority, and not evidence that any release passed or failed.

## Private Result Intake And Custody

If a verifier replies privately, do not turn the reply into a public
attestation claim. Intake is a custody step, not publication.

For a useful private intake, preserve:

- the source channel and received timestamp;
- attachment names and sizes;
- SHA-256 for the zip or bundle received;
- SHA-256 for any checksum file received;
- an extracted file list;
- `unzip -t` or equivalent archive-integrity output;
- checksum verification for each included evidence file;
- JSON syntax validation for generated JSON artifacts;
- a scan result showing no `--latest` substitution;
- a scan result for obvious verifier identity, email, tokens, passwords,
  secrets, and private-key strings;
- a private custody receipt with the claim boundary.

The custody receipt should record the verifier result as private/internal
unless public use is separately approved. It should not restate private
identity or email in public repo material.

Use the machine-readable private verifier result envelope for the custody
receipt:

```bash
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json --evidence-dir release-forward-result-dir
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json --evidence-dir release-forward-result-dir --json > zlar-private-verifier-result-verification-v1.json
bin/zlar north-star-readiness --evidence-dir release-forward-result-dir/ZLAR --release-tag <explicit-release-tag> --private-verifier-result-verification zlar-private-verifier-result-verification-v1.json --json
```

A committed sample fixture lives at
`tests/fixtures/private-verifier-result-v1.json` and can be checked with:

```bash
bin/zlar private-verifier-result verify --sample
bin/zlar private-verifier-result verify --sample --json
```

The envelope is privacy-safe intake metadata only. It rejects moving targets,
public attribution approval, public external-attestation approval, private
identity/contact leakage, obvious secret strings, missing required release-
forward artifact hashes, unapproved verifier labels or relationships, unapproved
result-summary prose, and any claim that private intake proves production
authority, enterprise readiness, current-machine governance, live MCP coverage,
key custody, revocation truth, v3.4.0 readiness, or unrouted-surface coverage.
With `--evidence-dir <dir>`, it also recomputes the declared artifact hashes
against local evidence files and fails closed on missing files, symlinks,
directories, or mismatches without printing the local evidence directory.
For `v3.4.47+`, that evidence-dir verification also validates the `v3.4.46+`
Product Proof Path content contract from the already hash-checked
`DRY-RUN-MANIFEST.json`: the Product Proof Path terminal-chain boundary and
its North Star mirror must preserve 3 recognition-refusal groups, 18 case IDs,
and `preserved=true`.
For `v3.4.48+`, the same verification also validates the Product Proof Path
deployment-profile authority bridge and its North Star mirror from
`DRY-RUN-MANIFEST.json`; it fails closed if explicit profile SHA binding,
verified preflight, one recognized mutation, 18/18 zero-mutation refusals,
authority-material refusal, or false current-machine/production flags drift.
For `v3.4.49+`, the same verification also validates the exact five-case
deployment-profile authority-refusal list, before-service-proof boundary, and
service-proof-not-started flag.
For future `v3.4.51+` local targets, the same verification also validates the
Product Proof Path terminal-chain trusted-registry `RECOGNIZED` verdict, active
issuer status, signature-valid fact, local registry rule evaluation facts, and
registry/receipt contract hashes in both the manifest terminal-chain boundary
and North Star mirror, plus the downstream-refusal marker boundary in both the
manifest Product Proof Path contract and North Star mirror, including exact
downstream refusal reasons and all-refusals-unboarded flags; `v3.4.50` omits
those new fields.
For `v3.4.50+`, the same verification also validates the terminal-chain,
proof-smoke, and North Star mirror of that five-case authority-refusal list in
the release-forward evidence directory.
It does not publish the verifier, replace the raw private reply, or turn the
reply into public external attestation.

`north-star-readiness` may consume only the sanitized
`zlar-private-verifier-result-verification-v1` output. It must not consume the
raw private reply, verifier identity, contact channel, or custody directory.
When the supplied verification is a same-release private non-operator PASS with
hashes recomputed against the evidence directory, and with any required
evidence-dir content contract verified, the readiness report may
record `private_non_operator_pass_validated=true` while keeping public external
attestation, public attribution, public non-operator review, production
authority, and enterprise readiness false.

## Attestation Template

The verifier may use this template after they actually perform the steps. List
only commands actually run. The command list below reflects a `v3.4.19+`
release-forward review; omit later-release command lines for earlier targets
unless the helper-generated plan for that checked-out tag includes them.

```text
I, [name], verified ZLAR release [tag] at commit [sha] on [date].

I independently cloned the public repository and ran the following commands:
- bin/zlar proof-smoke
- bin/zlar proof-smoke --json
- bin/zlar proof-smoke verify --input zlar-proof-smoke-v1.json --json
- bin/zlar proof-smoke verify --sample
- bin/zlar proof-smoke verify --sample --json
- bin/zlar protected-records-service-preflight verify --sample
- bin/zlar protected-records-service-preflight verify --sample --json
- bin/zlar local-proof-pack verify --sample
- bin/zlar local-proof-pack verify --sample --json
- bin/zlar protected-records-runtime-local-activation verify --sample
- bin/zlar protected-records-runtime-local-activation verify --sample --json
- bin/zlar protected-records-runtime-profile-installation verify --sample
- bin/zlar protected-records-runtime-profile-installation verify --sample --json
- bin/zlar protected-records-installed-runtime-profile-preflight verify --sample
- bin/zlar protected-records-installed-runtime-profile-preflight verify --sample --json
- bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample
- bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --json
- bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --artifact zlar-installed-runtime-profile-recognition-proof-artifact-v1.json
- bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json
- bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json --json
- bin/zlar protected-records-installed-runtime-profile-service-proof --sample
- bin/zlar protected-records-installed-runtime-profile-service-proof --sample --json
- bin/zlar protected-records-installed-runtime-profile-service-proof --sample --artifact zlar-installed-runtime-profile-service-proof-artifact-v1.json
- bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json
- bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json --json
- bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample
- bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --json
- bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --artifact zlar-installed-runtime-profile-terminal-chain-artifact-v1.json
- bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json
- bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json --json
- bin/zlar product-proof-path --json-out zlar-product-proof-path-v1.json
- bin/zlar issuer-status-proof
- bin/zlar issuer-status-proof --json
- bash tools/build-verifier-kit.sh
- bin/zlar verifier-kit-reproducibility --json-out zlar-verifier-kit-reproducibility-v1.json
- bin/zlar verifier-kit-public-distribution --release-tag <explicit-release-tag> --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --json-out zlar-verifier-kit-public-distribution-v1.json
- node verify-issuer-status.mjs from the built verifier kit
- node verify-recognition.mjs from the built verifier kit
- node verify-recognition.mjs --json from the built verifier kit
- node verify-recognition.mjs malformed-registry contract check from the built
  verifier kit
- external-runner-dry-run.sh --issuer-status-json-out from the built verifier kit
- node tools/verifier-kit-external-runner-diagnostics.mjs --json-out zlar-verifier-kit-external-runner-diagnostics-v1.json
- bin/zlar coverage --sample --require-governed
- bin/zlar coverage --sample --require-governed --json
- bin/zlar north-star-readiness --evidence-dir . --release-tag <explicit-release-tag> --json
- bash tests/test-receipt-authority-copy.sh

Result:
[pass/fail summary]

Evidence preserved:
[links, hashes, or attached files]
For v3.3.76+ targets, active-profile counts and the embedded proof-pack
active_profile_selection summary are preserved: [links, hashes, or attached files]

For v3.3.81+ targets, runtime-profile installation counts and the embedded
proof-pack runtime_profile_installation summary are preserved: [links, hashes,
or attached files]

For v3.3.98+ targets, the North Star readiness report is preserved. The
default no-assets release-forward path reports NOT_READY_FOR_V3_4_0; a derived
live-publication evidence run may report
READY_FOR_V3_4_0_PUBLIC_VERIFIER_KIT_DISTRIBUTION: [links, hashes, or attached files]

For v3.3.104+ targets, the North Star readiness report also records the
bounded `private_verifier_result_sample` manifest pointer contract for the
pinned release tag. This is private-intake sample discoverability only; it is
not a manifest self-read, not a circular hash, not public external attestation,
and not non-operator review.

For v3.4.21+ targets, the verifier-kit external-runner diagnostics report is
preserved: [links, hashes, or attached files]. In that sentence,
external-runner means the bundled verifier-kit helper file. This preserves the
v3.4.20 diagnostic-hardening evidence in the packet; it is not live probing,
not public external attestation, not non-operator review, not production
authority, and not proof that repo-side regression tests are inside the built
kit.

For v3.3.107+ targets, `DRY-RUN-RESULT.md` also summarizes the manifest-side
private-intake pointer and the readiness report-side pointer in a `Private
Intake Pointer Contract` section: [links, hashes, or attached files]

For v3.4.34+ targets, `DRY-RUN-RESULT.md` also summarizes
`Private Result Verification Evidence`: verification verdict, recomputed
evidence-dir hash status, artifact hash count, `completed_by_non_operator`,
`private_non_operator_pass_validated`, and false public-attestation,
public-attribution, and public-non-operator-review flags. The generated sample
should keep `private_non_operator_pass_validated=false`: [links, hashes, or
attached files]

When a private verifier-result verification JSON is supplied to North Star
readiness, the External Attestation puzzle remains unproven and private/internal.
For future v3.4.51+ local private-intake contracts, its summary must preserve
`downstream_refusal_all_refusals_unboarded=true`, the exact
`downstream_refusal_reasons`, `north_star_downstream_refusal_all_refusals_unboarded=true`,
and the exact `north_star_downstream_refusal_reasons` from the private
verification result while public attestation, public attribution, and public
non-operator review remain false.

For v3.4.35+ targets, `DRY-RUN-MANIFEST.json` and `DRY-RUN-RESULT.md` also
summarize `Trusted Issuer Registry Recognition Evidence`: recognized fixture
verdict, `registry_type=trusted-receipt-issuers-v1`,
`registry_evidence_model=bundled-local-fixture`, `live_probing=false`, active
issuer status, signature validity, malformed-registry fail-closed result, and
false live-registry, custody, revocation, production-recognition,
production-authority, sovereign-recognition, non-operator-review, and
public-attestation flags: [links, hashes, or attached files]

For v3.3.100+ targets, the verifier-kit reproducibility report is preserved and
reports same-source same-key tarball, manifest, and manifest-signature hash
stability: [links, hashes, or attached files]

For v3.3.109+ targets, the verifier-kit public distribution posture report is
preserved. The no-assets release-forward path reports
`ready_for_public_distribution_claim=false` with named blockers; a live
release-asset evidence run may report `ready_for_public_distribution_claim=true`
with zero blockers: [links, hashes, or attached files]

For v3.4.9+ targets, the fresh Product Proof Path report is preserved
(`zlar-product-proof-path-v1.json`). Confirm all acceptance gates are true, all
forbidden-claim flags are false, simulated-human authorization is fixture-only,
receipt verification distinguishes `VALID`, `UNKNOWN-SIGNER`, and `INVALID`,
trusted issuer registry recognition remains bundled-local-fixture evidence
validated and evaluated through the shared downstream recognition rule, keeps
malformed-registry fail-closed behavior, and keeps known ungoverned boundaries
visible. For v3.4.44+ targets, the Product Proof Path builder also recomputes
proof-pack artifact verification before accepting an artifact/verification
pair, so stale verification cannot be paired with a mutated proof-pack artifact.
For v3.4.45+ targets, Product Proof Path also generates a fresh disposable
terminal chain, verifies the terminal-chain artifact, and preserves the compact
terminal-chain boundary consumed by North Star readiness and the release-forward
report contract. For v3.4.46+ targets, that boundary also preserves the exact
three-group, 18-case recognition-refusal map instead of reducing it to a hash.
Current local post-v3.4.50 proof-hardening also preserves the terminal-chain
trusted-registry binding's own local `RECOGNIZED` verdict, issuer status,
signature validity, local registry evaluation facts, and contract hashes instead
of reducing that boundary to binding/refusal hashes.
For v3.4.48+ targets, Product Proof Path also preserves the local fixture
deployment-profile authority bridge: explicit deployment/runtime profile SHA
binding, no `--latest`, verified preflight, one recognized receipt mutation,
18/18 zero-mutation refusals, authority-material refusal, direct API refusal,
and false current-machine, production, external, sovereign, and unrouted flags.
For v3.4.49+ targets, that bridge also preserves five pre-service
deployment-profile authority refusals for stale profile artifacts, profile
recognition mismatch, `--latest` selection, and request-stream authority
material.
For v3.4.50+ targets, terminal-chain evidence, terminal-chain artifact
verification, proof-smoke, North Star readiness, and the release-forward report
contract also mirror that same five-case authority-refusal list with exact IDs,
before-service-proof refusal, before-mutation refusal, service-proof-not-started,
and false stronger-claim flags.
It does not prove live approval, live trust-registry state, live issuer status,
key custody, revocation truth, production trust registry, production downstream
recognition, external attestation, all-MCP governance, or coverage of unrouted
surfaces. It also keeps current-machine governance false. For v3.4.10+ targets,
confirm
the North Star readiness report consumes this Product Proof Path report and
records `product_proof_path_verified=true`.

For v3.4.13+ targets, the installed-runtime-profile service proof is preserved
with service-continuity and local witness rollback hardening.
Confirm it starts only a local disposable child service, boards one matching
`records.write`, refuses same-process and restart replay, refuses
consumed-store/local-anchor/witness integrity failures, refuses
store-plus-anchor rollback when a launcher-owned local proof witness remains
ahead, refuses all 18 selected-profile cases before service-state mutation,
records store-and-anchor-witness joint rollback detection as false, and keeps
persistent install, activation, current-machine governance, production
downstream recognition, enterprise readiness, and external attestation false.
For v3.4.14+ targets, confirm `zlar-north-star-readiness-v1.json` records
`installed_runtime_profile_service_artifact_verification_required=true` and
`installed_runtime_profile_service_artifact_verification_preserved=true`, with
the verifier hash bound to the supplied service proof.
For v3.4.18+ targets, confirm the same readiness report records
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_required=true`
and
`installed_runtime_profile_service_artifact_verification_refusal_taxonomy_preserved=true`,
with the service-proof artifact verifier's refusal taxonomy SHA-256 preserved.
For v3.4.19+ targets, confirm the same readiness report records
`installed_runtime_profile_recognition_contract_digest_required=true`,
`installed_runtime_profile_recognition_contract_digest_preserved=true`, and a
canonical `installed_runtime_profile_recognition_contract_sha256` preserved
across preflight, service proof, service-proof artifact verification, terminal
chain, and terminal-chain artifact verification.
For v3.4.15+ targets, confirm `zlar-north-star-readiness-v1.json` records
`installed_runtime_profile_terminal_chain_required=true` and
`installed_runtime_profile_terminal_chain_preserved=true`, with generated-root
preflight, generated preflight consumption, generated service-proof artifact
verification, service-proof/preflight binding, artifact/service-proof binding,
recognized write boarding, missing/invalid receipt refusal, all 18 selected-
profile refusals before mutation, and false persistent-install/current-machine/
production flags intact.
For v3.4.22+ targets, also confirm `DRY-RUN-MANIFEST.json` contains
`terminal_chain_refusal_evidence.enabled=true` and that `DRY-RUN-RESULT.md`
includes `Terminal Chain Refusal Evidence` with the same
`named_receipt_refusals_sha256`, all seven named receipt refusals marked before
mutation, and false current-machine/production downstream recognition flags.
For v3.4.23+ targets, also confirm that section contains
`recognition_refusal_groups_required=true`, the same
`recognition_refusal_groups_sha256`, and grouped no-usable-authority,
scope-mismatch, and route/request-authority refusals marked before mutation.
For v3.4.24+ targets, also confirm that section contains
`recognition_refusal_group_case_ids_required=true`,
`all_recognition_refusal_group_case_ids_preserved=true`, and the exact grouped
case-id lists for all 18 terminal-chain recognition-refusal cases.
For v3.4.25+ targets, also confirm `DRY-RUN-RESULT.md` contains
`Release-Forward Report Contract`,
`north_star.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required=true`,
`north_star.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved=true`,
`proof_smoke.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count=3`,
`proof_smoke.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count=18`,
and the false stronger-claim flags for public external attestation, production
authority, current-machine governance, live MCP coverage, and unrouted-surface
coverage.
For v3.4.26+ targets, also confirm `DRY-RUN-RESULT.md` contains
`north_star.puzzle_3.observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved=true`,
`north_star.puzzle_3.observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_count=3`,
`north_star.puzzle_5.observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved=true`,
and `north_star.puzzle_5.observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count=18`.
For v3.4.28+ targets, also confirm `DRY-RUN-RESULT.md` contains
`release_forward.terminal_chain_nested_artifact_tamper_refusals.generated_preflight_artifact_type=zlar-protected-records-installed-runtime-profile-preflight-artifact-v1`,
`release_forward.terminal_chain_nested_artifact_tamper_refusals.generated_service_proof_artifact_type=zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1`,
`release_forward.terminal_chain_nested_artifact_tamper_refusals.forged_inner_preflight_hash_refused=true`,
and `release_forward.terminal_chain_nested_artifact_tamper_refusals.forged_inner_service_hash_refused=true`.
For v3.4.30+ targets, also confirm `DRY-RUN-RESULT.md` contains
`release_forward.terminal_chain_nested_artifact_binding.generated_preflight_artifact_body_sha256=`,
`release_forward.terminal_chain_nested_artifact_binding.generated_service_proof_artifact_body_sha256=`,
`release_forward.terminal_chain_nested_artifact_binding.preflight_artifact_hash_bound=true`,
and `release_forward.terminal_chain_nested_artifact_binding.service_artifact_hash_bound=true`.
When verifier-kit release-asset live-read evidence is supplied, confirm the
summary names repository `ZLAR-AI/ZLAR`, the release URL and required asset
download URLs name that same repository and target tag, and incomplete live
release-asset evidence remains bounded `NOT_READY` evidence unless it is used
to make a public-ready claim.
For v3.4.33+ targets, also confirm `DRY-RUN-MANIFEST.json` contains
`issuer_status_evidence.enabled=true`,
`issuer_status_evidence.evidence_model=release-forward-local-issuer-status-fixture`,
`issuer_status_evidence.verifier_kit_fixture_verdict=ISSUER-STATUS-FIXTURE-VERIFIED`,
`issuer_status_evidence.proof_live_probing=false`, active-issuer boarding,
retired/compromised/missing-status/unknown/missing-key issuer refusals, and
false stronger-claim flags for live issuer status, key custody, revocation
truth, production trust registry, production downstream recognition,
non-operator review, and public external attestation. Also confirm
`DRY-RUN-RESULT.md` contains `Issuer Status Evidence` with the same boundary.

For v3.4.34+ targets, confirm `DRY-RUN-RESULT.md` contains `Private Result
Verification Evidence` with `verified=true`,
`evidence_dir_hashes_recomputed=true`, `completed_by_non_operator=false`,
`private_non_operator_pass_validated=false`,
`public_external_attestation=false`, `public_attribution=false`, and
`non_operator_review_publicly_claimed=false`.
For v3.4.35+ targets, also confirm `DRY-RUN-MANIFEST.json` contains
`trusted_issuer_registry_recognition_evidence.enabled=true`,
`trusted_issuer_registry_recognition_evidence.evidence_model=release-forward-local-trusted-issuer-registry-fixture`,
`trusted_issuer_registry_recognition_evidence.registry_type=trusted-receipt-issuers-v1`,
`trusted_issuer_registry_recognition_evidence.registry_evidence_model=bundled-local-fixture`,
`trusted_issuer_registry_recognition_evidence.live_probing=false`,
`trusted_issuer_registry_recognition_evidence.verdict=RECOGNIZED`,
`trusted_issuer_registry_recognition_evidence.issuer_status=active`,
`trusted_issuer_registry_recognition_evidence.signature_valid=true`,
`trusted_issuer_registry_recognition_evidence.malformed_registry_fail_closed_before_verdict=true`,
and false stronger-claim flags for live registry, live issuer status, key
custody, revocation truth, production trust registry, production downstream
recognition, production authority, sovereign recognition, non-operator review,
and public external attestation. Also confirm `DRY-RUN-RESULT.md` contains
`Trusted Issuer Registry Recognition Evidence` with the same boundary.
For v3.4.39+ targets, also confirm `DRY-RUN-MANIFEST.json` contains
`terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals_required=true`,
`terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_case_count=2`,
`terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_case_ids`
with `unrecognized_terminal_chain_registry_scope_refused` and
`registry_receipt_contract_mismatch_refused`,
`terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_reason_codes`
with `scope_not_found` and `detail_hash_mismatch`,
`terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals_all_refused=true`,
and matching terminal-chain/artifact-verification
`trusted_issuer_registry_recognition_refusals_sha256`. Also confirm
`DRY-RUN-RESULT.md` prints the same values.
For v3.4.41+ targets, also confirm `DRY-RUN-MANIFEST.json` contains
`release_forward_report_contract.enabled=true`,
`release_forward_report_contract.contract_type=zlar-release-forward-dry-run-report-contract-v1`,
`release_forward_report_contract.report_contract_satisfied=true`,
`release_forward_report_contract.manifest_is_canonical=true`, exact trusted
registry refusal case IDs and reason codes, matching trusted-registry refusal
hashes, and false claim-boundary flags for public external attestation,
non-operator review, live registry, live issuer status, key custody,
revocation truth, current-machine governance, live MCP coverage, production
downstream recognition, production authority, enterprise readiness, sovereign
recognition, and unrouted-surface coverage. Also confirm
`release_forward_report_contract.product_proof_path.terminal_chain_boundary.verified=true`,
matching Product Proof Path terminal-chain binding/refusal hashes, exact
trusted-registry refusal IDs/reasons, public-key omission, receipt-envelope
omission, `external_attestation=false`, and
`current_machine_governance_proven=false`. For v3.4.46+ targets, also confirm
the Product Proof Path contract renders
`terminal_chain_boundary.recognition_refusal_group_case_ids.*` and
`north_star.terminal_chain_recognition_refusal_group_case_ids.*` with the exact
grouped case-ID map. Also confirm
`DRY-RUN-RESULT.md` renders the same object with
`manifest.release_forward_report_contract.*` lines and does not require
scraping legacy `proof_smoke.*` or `north_star.*` Markdown lines for
machine-readable report-contract evidence.
For v3.4.47+ targets, also confirm `DRY-RUN-RESULT.md` prints
`private_result_verification.evidence_dir_contract_verified=true`,
`private_result_verification.evidence_dir_contract_type=product-proof-path-terminal-chain-recognition-refusal-group-case-ids-v1`,
`private_result_verification.terminal_chain_recognition_refusal_group_count=3`,
`private_result_verification.terminal_chain_recognition_refusal_group_case_count=18`,
and preserved Product Proof Path and North Star grouped refusal case-ID
booleans. For v3.4.46+ targets, also confirm
`private_result_verification.terminal_chain_trusted_registry_recognition_refusals_required_for_target=true`
and
`private_result_verification.terminal_chain_trusted_registry_recognition_refusals_preserved=true`;
these lines describe exact-family validation of the same-manifest
`terminal_chain_refusal_evidence` trusted-registry refusal fields, not live
registry state or production recognition. For v3.4.48+ targets, also confirm
`private_result_verification.evidence_dir_contract_type=product-proof-path-terminal-chain-and-deployment-profile-authority-bridge-v1`,
`private_result_verification.deployment_profile_authority_bridge_required_for_target=true`,
`private_result_verification.deployment_profile_authority_bridge_preserved=true`,
`private_result_verification.north_star_deployment_profile_authority_bridge_preserved=true`,
`private_result_verification.deployment_profile_authority_bridge_refusal_case_count=18`,
`private_result_verification.deployment_profile_authority_bridge_current_machine_governance=false`,
and `private_result_verification.deployment_profile_authority_bridge_production_authority=false`.
For v3.4.49+ targets, confirm the private result verification upgrades to
`private_result_verification.evidence_dir_contract_type=product-proof-path-terminal-chain-deployment-profile-authority-bridge-and-authority-refusals-v1`,
prints `private_result_verification.deployment_profile_authority_refusals_required_for_target=true`,
`private_result_verification.deployment_profile_authority_refusals_preserved=true`,
`private_result_verification.north_star_deployment_profile_authority_refusals_preserved=true`,
`private_result_verification.deployment_profile_authority_refusal_case_count=5`,
`private_result_verification.deployment_profile_authority_refusal_case_ids_preserved=true`,
`private_result_verification.deployment_profile_authority_refusals_before_service_proof=true`,
`private_result_verification.stale_deployment_profile_artifact_refused_before_service_proof=true`,
`private_result_verification.profile_recognition_mismatch_refused_before_service_proof=true`,
`private_result_verification.latest_profile_selection_refused_before_service_proof=true`, and
`private_result_verification.request_stream_authority_material_refused_before_service_proof=true`.
For v3.4.50+ targets, also confirm the release-forward manifest and result
contain `deployment_profile_authority_refusal_mirror_preserved=true` under
`terminal_chain_refusal_evidence`,
`installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true`
under proof-smoke counts, and
`installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true`
under North Star counts. The same sections must keep the mirror's false
current-machine, production, enterprise, external-attestation, sovereign, and
unrouted-surface claim fields false. The private result verification section
must also print
`private_result_verification.terminal_chain_deployment_profile_authority_refusal_mirror_required_for_target=true`
and
`private_result_verification.terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true`;
these lines describe exact-family validation of the same-manifest mirror, not
service activation, current-machine governance, production authority, or
external attestation.
For future v3.4.51+ local targets, also confirm the release-forward manifest,
result, and private verifier evidence-dir verification preserve the Product
Proof Path terminal-chain trusted-registry verdict/evaluation facts in both the
terminal-chain boundary and North Star mirror, plus the downstream-refusal
marker boundary in both the Product Proof Path contract and North Star mirror.
The private result verification section must print
`private_result_verification.evidence_dir_contract_type=product-proof-path-terminal-chain-deployment-profile-authority-refusals-trusted-registry-verdict-and-downstream-refusal-boundary-v1`,
`private_result_verification.terminal_chain_trusted_registry_verdict_required_for_target=true`,
`private_result_verification.product_proof_path_terminal_chain_trusted_registry_verdict_preserved=true`,
`private_result_verification.north_star_terminal_chain_trusted_registry_verdict_preserved=true`,
`private_result_verification.terminal_chain_trusted_registry_recognition_verdict=RECOGNIZED`,
`private_result_verification.terminal_chain_trusted_registry_signature_valid=true`,
`private_result_verification.downstream_refusal_boundary_required_for_target=true`,
`private_result_verification.product_proof_path_downstream_refusal_boundary_preserved=true`,
`private_result_verification.north_star_downstream_refusal_boundary_preserved=true`,
`private_result_verification.downstream_refusal_recognized_marker_count_delta=1`,
`private_result_verification.downstream_refusal_all_refusals_unboarded=true`,
`private_result_verification.downstream_refusal_reasons=receipt_missing,receipt_invalid,issuer_not_active,unknown_issuer,outcome_not_boarding,policy_not_recognized,domain_out_of_scope,tool_out_of_scope,audit_event_mismatch,detail_hash_mismatch,receipt_stale`,
`private_result_verification.north_star_downstream_refusal_all_refusals_unboarded=true`,
`private_result_verification.north_star_downstream_refusal_reasons=receipt_missing,receipt_invalid,issuer_not_active,unknown_issuer,outcome_not_boarding,policy_not_recognized,domain_out_of_scope,tool_out_of_scope,audit_event_mismatch,detail_hash_mismatch,receipt_stale`,
and `private_result_verification.downstream_refusal_marker_count_deltas_zero=true`.
For v3.4.50, those fields should be absent from the release-forward Product
Proof Path contract.
This is private-intake content binding only, not public external attestation or
non-operator review.

Limits:
This attestation covers only the public release/tag and the commands above.
It does not attest production deployment, live/current-machine governance,
Telegram or approval-channel health, live records-system inspection, live MCP
coverage, external trust-registry recognition, sovereign recognition, enterprise
readiness, or coverage of unrouted surfaces.

Verifier:
[name, organization, contact, signature or publication URL]
```

The template becomes an attestation only when a real non-operator verifier
fills it out and signs or publishes it.

## What A Passing Result Means

A passing result means the verifier reproduced bounded public evidence:

- committed smoke and sample artifacts verify;
- committed proof reports keep their fixture-only boundaries;
- the sample coverage map marks governed and ungoverned lanes explicitly;
- the receipt authority copy guard passes.

That is useful. It proves the packet can be checked from outside the operator's
machine.

## What A Passing Result Does Not Mean

A passing result does not prove:

- production deployment;
- current-machine governance;
- live hook configuration;
- live audit-store integrity;
- live MCP coverage;
- live approval-channel delivery or health;
- Telegram availability;
- key custody beyond the public verifier material supplied in the repo;
- downstream acceptance outside the fixture recognition rules;
- external trust-registry recognition;
- sovereign recognition;
- enterprise readiness;
- coverage of unrouted shell, filesystem, browser, app-control, network,
  memory, planning, model reasoning, final text, or direct MCP paths.

Do not shorten a passing private result into a public attestation claim. The
truthful public repo claim after the first private request was sent is:

> ZLAR has sent a private-by-default non-Vincent verifier request for bounded
> public fixture evidence. No public external attestation is claimed in this
> repo. Any private reply or later result remains bounded by verifier
> relationship, disclosure permission, and exact evidence returned.

## Failure Handling

If any command fails:

1. Preserve the full redacted output and the machine-readable verifier
   environment failure report if the failure occurred before proof commands.
2. Record the release tag and commit SHA.
3. Record the verifier environment.
4. Stop the attestation.
5. Report the failure without changing the claim boundary.

A failed packet is not a reputational problem. It is exactly what the packet is
for: an outside check that can refuse to certify the evidence.
