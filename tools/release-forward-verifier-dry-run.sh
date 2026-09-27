#!/usr/bin/env bash
# Non-sending release-forward verifier dry-run helper.

set -euo pipefail

REPO_URL=""
TAG=""
EXPECTED_SHA=""
OUTPUT_DIR=""
PLAN_ONLY=0
TRANSCRIPT_FILE=""
TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF=""

usage() {
    cat <<'USAGE'
Usage:
  bash tools/release-forward-verifier-dry-run.sh --release-tag <vX.Y.Z> --expected-commit-sha <40-hex-sha> --out-dir <dir> --repo-url <authorized-source-url-or-local-repo>
  bash tools/release-forward-verifier-dry-run.sh --release-tag <vX.Y.Z> --expected-commit-sha <40-hex-sha> --plan-only [--repo-url <authorized-source-url-or-local-repo>]

Runs the bounded release-forward verifier packet commands from a fresh
authorized source checkout pinned to an explicit release tag and expected commit
SHA. Current private-core source access is private; this helper does not grant a
public clone path.

Optional supplied private-core evidence:
  --trusted-issuer-completion-proof <file>
    Copies and verifies a supplied
    zlar-trusted-receipt-issuer-completion-proof-v1.json artifact for supported
    targets. This preserves the artifact for north-star-readiness evidence-dir
    intake without generating signing keys, receipts, custody, public
    attestation, or source-publication evidence.

Boundary:
  This helper sends no verifier request, contacts no verifier, creates no
  public external attestation, and does not prove non-operator review,
  production deployment, current-machine governance, live hooks, live MCP
  coverage, approval-channel health, live issuer status, key custody,
  revocation truth, sovereign recognition, enterprise readiness, or coverage of
  unrouted surfaces. A supplied Trusted Issuer completion proof remains
  private-core evidence intake only, not public by default and not proof of
  production issuer custody, hardware custody, production downstream
  recognition, source publication, real records protection, side-door closure,
  sovereign recognition, absolute human intention, or legal consent.
USAGE
}

fail() {
    if [ -n "${TRANSCRIPT_FILE}" ]; then
        printf 'ERROR: %s\n' "$*" | sanitize_transcript | tee -a "${TRANSCRIPT_FILE}" >&2
    else
        printf 'ERROR: %s\n' "$*" >&2
    fi
    exit 2
}

require_value() {
    local flag="$1"
    local value="${2:-}"
    if [ -z "${value}" ]; then
        fail "${flag} requires a value"
    fi
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command not found: $1"
    fi
}

sanitize_transcript() {
    sed -E \
        -e 's#/Users/[^[:space:]]+#<local-path>#g' \
        -e 's#/home/[^[:space:]]+#<local-path>#g' \
        -e 's#/private/[^[:space:]]+#<local-path>#g' \
        -e 's#/tmp/[^[:space:]]+#<local-path>#g' \
        -e 's#/var/[^[:space:]]+#<local-path>#g'
}

validate_tag() {
    if [ -z "${TAG}" ]; then
        fail "--release-tag is required"
    fi
    case "${TAG}" in
        main|master|HEAD|latest|--latest)
            fail "--tag must be an explicit immutable release tag, not ${TAG}"
            ;;
    esac
    case "${TAG}" in
        *[!A-Za-z0-9._-]*)
            fail "--tag contains unsupported characters"
            ;;
    esac
    if ! [[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        fail "--tag must look like vX.Y.Z"
    fi
}

validate_sha() {
    if [ -z "${EXPECTED_SHA}" ]; then
        fail "--expected-commit-sha is required"
    fi
    if [ "${#EXPECTED_SHA}" -ne 40 ]; then
        fail "--sha must be a 40-character lowercase hex commit"
    fi
    case "${EXPECTED_SHA}" in
        *[!0-9a-f]*)
            fail "--sha must be lowercase hex"
            ;;
    esac
}

tag_at_least() {
    local major="$1"
    local minor="$2"
    local patch="$3"
    local version="${TAG#v}"
    local got_major="${version%%.*}"
    local rest="${version#*.}"
    local got_minor="${rest%%.*}"
    local got_patch="${rest#*.}"
    got_patch="${got_patch%%[^0-9]*}"
    if [ "${got_major}" -gt "${major}" ]; then
        return 0
    fi
    if [ "${got_major}" -lt "${major}" ]; then
        return 1
    fi
    if [ "${got_minor}" -gt "${minor}" ]; then
        return 0
    fi
    if [ "${got_minor}" -lt "${minor}" ]; then
        return 1
    fi
    [ "${got_patch}" -ge "${patch}" ]
}

public_release_assets_expected() {
    # Asset-bearing releases are explicit; later proof releases must not inherit this claim by version range.
    [ "${TAG}" = "v3.4.31" ]
}

private_verifier_required_identity_expected() {
    # Required-identity flags are a post-v3.4.56 verifier feature. Older
    # release targets must stay runnable with the verifier they check out.
    tag_at_least 3 4 57
}

print_boundary() {
    cat <<'BOUNDARY'
claim_boundary:
- This is a non-sending local dry run of the release-forward verifier packet.
- It sends no verifier request and contacts no verifier.
- It creates no public external attestation and does not prove non-operator review.
- It does not prove production deployment, current-machine governance, live hooks, live MCP coverage, approval-channel health, live issuer status, key custody, revocation truth, sovereign recognition, enterprise readiness, or coverage of unrouted surfaces.
BOUNDARY
}

print_command_plan() {
    local plan_repo_url="${REPO_URL:-<authorized-source-url-or-local-source-archive>}"
    cat <<EOF
git clone ${plan_repo_url} ZLAR
cd ZLAR
git checkout ${TAG}
test "\$(git rev-parse HEAD)" = "${EXPECTED_SHA}"
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
EOF
    if tag_at_least 3 3 100; then
        cat <<'EOF'
bin/zlar verifier-kit-reproducibility --json-out zlar-verifier-kit-reproducibility-v1.json
EOF
    fi
    if public_release_assets_expected; then
        cat <<EOF
mkdir -p zlar-verifier-kit-release-assets
bin/zlar verifier-kit-release-assets-live-read --release-tag ${TAG} --download-dir zlar-verifier-kit-release-assets --json-out zlar-verifier-kit-release-assets-v1.json
bin/zlar verifier-kit-public-distribution --release-tag ${TAG} --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --require-public --json-out zlar-verifier-kit-public-distribution-v1.json
EOF
    elif tag_at_least 3 3 109; then
        cat <<EOF
node --input-type=module -e "import { writeFileSync } from 'node:fs'; writeFileSync('zlar-verifier-kit-release-assets-v1.json', JSON.stringify({ tagName: '${TAG}', url: 'not-queried-release-forward-dry-run', evidence_model: 'release-forward-local-no-assets-fixture', assets: [] }, null, 2) + '\\n');"
bin/zlar verifier-kit-public-distribution --release-tag ${TAG} --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --json-out zlar-verifier-kit-public-distribution-v1.json
EOF
    fi
    cat <<'EOF'
( cd dist/zlar-verifier-kit-v0.1.0 && node verify-issuer-status.mjs )
EOF
    if tag_at_least 3 3 94; then
        cat <<'EOF'
( cd dist/zlar-verifier-kit-v0.1.0 && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample )
( cd dist/zlar-verifier-kit-v0.1.0 && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample --json > ../../zlar-trusted-receipt-issuer-recognition.json )
EOF
    fi
    if tag_at_least 3 3 97; then
        cat <<'EOF'
node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; const r = JSON.parse(readFileSync('dist/zlar-verifier-kit-v0.1.0/examples/trusted-receipt-issuers-v1.json', 'utf8')); r.production_authority = true; writeFileSync('zlar-trusted-receipt-issuer-recognition-malformed-registry.json', JSON.stringify(r, null, 2) + '\n');"
node dist/zlar-verifier-kit-v0.1.0/verify-recognition.mjs --receipt dist/zlar-verifier-kit-v0.1.0/examples/sample-receipt.json --registry zlar-trusted-receipt-issuer-recognition-malformed-registry.json --scope verifier-kit-sample > zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt 2>&1 # expected exit 2
EOF
    fi
    cat <<'EOF'
( cd dist/zlar-verifier-kit-v0.1.0 && bash external-runner-dry-run.sh --issuer-status-json-out ../../zlar-verifier-kit-issuer-status-fixture.json )
EOF
    if tag_at_least 3 4 21; then
        cat <<EOF
ZLAR_RELEASE_FORWARD_TARGET_TAG=${TAG} ZLAR_RELEASE_FORWARD_EXPECTED_SHA=${EXPECTED_SHA} ZLAR_RELEASE_FORWARD_OBSERVED_SHA=\$(git rev-parse HEAD) node tools/verifier-kit-external-runner-diagnostics.mjs --json-out zlar-verifier-kit-external-runner-diagnostics-v1.json
EOF
    fi
    cat <<'EOF'
bin/zlar protected-records-runtime-local-activation verify --sample
bin/zlar protected-records-runtime-local-activation verify --sample --json > zlar-runtime-local-activation-sample-verification.json
bin/zlar protected-records-runtime-profile-installation verify --sample
bin/zlar protected-records-runtime-profile-installation verify --sample --json > zlar-runtime-profile-installation-sample-verification.json
EOF
    if tag_at_least 3 4 5; then
        cat <<'EOF'
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample
bin/zlar protected-records-installed-runtime-profile-preflight verify --sample --json > zlar-installed-runtime-profile-preflight-sample-verification.json
EOF
    fi
    if tag_at_least 3 4 7; then
        cat <<'EOF'
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --json > zlar-installed-runtime-profile-recognition-proof-v1.json
EOF
    fi
    if tag_at_least 3 4 8; then
        cat <<'EOF'
bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --artifact zlar-installed-runtime-profile-recognition-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json --json > zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json
EOF
    fi
    if tag_at_least 3 4 11; then
        cat <<'EOF'
bin/zlar protected-records-installed-runtime-profile-service-proof --sample
bin/zlar protected-records-installed-runtime-profile-service-proof --sample --json > zlar-installed-runtime-profile-service-proof-v1.json
bin/zlar protected-records-installed-runtime-profile-service-proof --sample --artifact zlar-installed-runtime-profile-service-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json --json > zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json
EOF
    fi
    if tag_at_least 3 4 15; then
        cat <<'EOF'
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --json > zlar-installed-runtime-profile-terminal-chain-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --artifact zlar-installed-runtime-profile-terminal-chain-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json --json > zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json
EOF
    fi
if tag_at_least 3 4 28; then
    cat <<'EOF'
node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; import { canonicalize } from './lib/canonicalize.mjs'; import { sha256hex } from './lib/receipt.mjs'; const artifact = JSON.parse(readFileSync('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json', 'utf8')); artifact.payload.chain.generated_preflight.artifact_body_sha256 = 'e'.repeat(64); artifact.payload.chain.generated_service_proof.source_preflight_body_sha256 = 'e'.repeat(64); artifact.integrity.body_sha256 = sha256hex(canonicalize(artifact.payload)); writeFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json', JSON.stringify(artifact, null, 2) + '\n');"
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json # expected exit 1
node --input-type=module -e "import { readFileSync, writeFileSync } from 'node:fs'; import { canonicalize } from './lib/canonicalize.mjs'; import { sha256hex } from './lib/receipt.mjs'; const artifact = JSON.parse(readFileSync('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json', 'utf8')); artifact.payload.chain.generated_service_proof.artifact_body_sha256 = 'f'.repeat(64); artifact.payload.chain.generated_service_proof.verification_body_sha256 = 'f'.repeat(64); artifact.integrity.body_sha256 = sha256hex(canonicalize(artifact.payload)); writeFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json', JSON.stringify(artifact, null, 2) + '\n');"
bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json # expected exit 1
EOF
fi
    if tag_at_least 3 4 9; then
        cat <<'EOF'
bin/zlar product-proof-path --json-out zlar-product-proof-path-v1.json
EOF
    fi
    cat <<'EOF'
bin/zlar coverage --sample --require-governed
bin/zlar coverage --sample --require-governed --json > zlar-coverage-map-sample.json
EOF
    if tag_at_least 3 4 53; then
        if [ -n "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" ]; then
            local plan_trusted_completion_proof
            plan_trusted_completion_proof="$(printf '%s\n' "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" | sanitize_transcript)"
            cat <<EOF
cp ${plan_trusted_completion_proof} zlar-trusted-receipt-issuer-completion-proof-v1.json
EOF
        fi
        cat <<'EOF'
if [ -f zlar-trusted-receipt-issuer-completion-proof-v1.json ]; then
  bin/zlar trusted-receipt-issuer-completion-proof verify --input zlar-trusted-receipt-issuer-completion-proof-v1.json --json > zlar-trusted-receipt-issuer-completion-proof-verification-v1.json
fi
EOF
    fi
    if tag_at_least 3 3 98; then
        if tag_at_least 3 3 107; then
            cat <<EOF
bin/zlar north-star-readiness --evidence-dir . --release-tag ${TAG} --json > zlar-north-star-readiness-v1.json
EOF
        else
            cat <<'EOF'
bin/zlar north-star-readiness --evidence-dir . --json > zlar-north-star-readiness-v1.json
EOF
        fi
    fi
    cat <<'EOF'
bash tests/test-receipt-authority-copy.sh
EOF
    if tag_at_least 3 3 104; then
        if private_verifier_required_identity_expected; then
            cat <<EOF
private_result_sha="\$(shasum -a 256 zlar-private-verifier-result-v1.json)"
private_result_sha="\${private_result_sha%% *}"
private_result_identity="\$(node --input-type=module -e 'import { readFileSync } from "node:fs"; import { privateVerifierArtifactSetSha256 } from "./lib/private-verifier-result.mjs"; const result = JSON.parse(readFileSync("zlar-private-verifier-result-v1.json", "utf8")); console.log(result.evidence.received_bundle_sha256 + " " + privateVerifierArtifactSetSha256(result.evidence.artifact_hashes));')"
private_result_bundle_sha="\${private_result_identity%% *}"
private_result_artifact_set_sha="\${private_result_identity#* }"
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json --evidence-dir .. --require-result-sha "\${private_result_sha}" --require-target ${TAG}@${EXPECTED_SHA} --require-bundle-sha "\${private_result_bundle_sha}" --require-artifact-set-sha "\${private_result_artifact_set_sha}" --require-recomputed-evidence --json > zlar-private-verifier-result-verification-v1.json
EOF
        else
            cat <<'EOF'
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json --evidence-dir .. --json > zlar-private-verifier-result-verification-v1.json
EOF
        fi
    fi
}

prepare_output_dir() {
    if [ -z "${OUTPUT_DIR}" ]; then
        fail "--out-dir is required unless --plan-only is used"
    fi
    if [ -e "${OUTPUT_DIR}" ]; then
        if [ ! -d "${OUTPUT_DIR}" ]; then
            fail "--out-dir exists and is not a directory"
        fi
        if [ -n "$(find "${OUTPUT_DIR}" -mindepth 1 -maxdepth 1 | sed -n '1p')" ]; then
            fail "--out-dir must be empty"
        fi
    else
        mkdir -p "${OUTPUT_DIR}"
    fi
    OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
}

validate_trusted_receipt_issuer_completion_proof_scope() {
    if [ -z "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" ]; then
        return
    fi
    if ! tag_at_least 3 4 53; then
        fail "--trusted-issuer-completion-proof requires --release-tag v3.4.53 or later"
    fi
}

prepare_trusted_receipt_issuer_completion_proof() {
    if [ -z "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" ]; then
        return
    fi
    validate_trusted_receipt_issuer_completion_proof_scope
    if [ ! -f "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" ]; then
        fail "--trusted-issuer-completion-proof file not found"
    fi
    local proof_dir proof_base
    proof_dir="$(cd "$(dirname "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}")" && pwd)"
    proof_base="$(basename "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}")"
    TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF="${proof_dir}/${proof_base}"
}

guard_checkout_trusted_receipt_issuer_completion_proof() {
    if ! tag_at_least 3 4 53; then
        return
    fi
    if [ -n "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" ]; then
        return
    fi
    if [ -f zlar-trusted-receipt-issuer-completion-proof-v1.json ]; then
        fail "checkout-root trusted receipt issuer completion proof requires --trusted-issuer-completion-proof"
    fi
}

run_cmd() {
    {
        printf '\n$'
        printf ' %q' "$@"
        printf '\n'
    } | sanitize_transcript | tee -a "${TRANSCRIPT_FILE}"
    set +e
    "$@" 2>&1 | sanitize_transcript | tee -a "${TRANSCRIPT_FILE}"
    local ec="${PIPESTATUS[0]}"
    set -e
    if [ "${ec}" -ne 0 ]; then
        fail "command failed with exit ${ec}: $*"
    fi
}

run_shell() {
    printf '\n$ %s\n' "$1" | sanitize_transcript | tee -a "${TRANSCRIPT_FILE}"
    set +e
    bash -c "$1" 2>&1 | sanitize_transcript | tee -a "${TRANSCRIPT_FILE}"
    local ec="${PIPESTATUS[0]}"
    set -e
    if [ "${ec}" -ne 0 ]; then
        fail "command failed with exit ${ec}: $1"
    fi
}

run_expected_shell() {
    local expected_ec="$1"
    local output_path="$2"
    local command="$3"
    printf '\n$ %s # expected exit %s\n' "${command}" "${expected_ec}" | sanitize_transcript | tee -a "${TRANSCRIPT_FILE}"
    set +e
    bash -c "${command}" 2>&1 | sanitize_transcript | tee "${output_path}" | tee -a "${TRANSCRIPT_FILE}"
    local ec="${PIPESTATUS[0]}"
    set -e
    if [ "${ec}" -ne "${expected_ec}" ]; then
        fail "command exited ${ec}, expected ${expected_ec}: ${command}"
    fi
}

write_assertions() {
    local public_release_assets_expected_value
    public_release_assets_expected_value=false
    if public_release_assets_expected; then
        public_release_assets_expected_value=true
    fi
    ZLAR_DRY_RUN_TARGET_TAG="${TAG}" \
        ZLAR_DRY_RUN_PUBLIC_RELEASE_ASSETS_EXPECTED="${public_release_assets_expected_value}" \
        node <<'NODE'
const fs = require('fs');

function readJson(name) {
  return JSON.parse(fs.readFileSync(name, 'utf8'));
}
function assert(name, condition, detail) {
  if (!condition) {
    console.error(`FAIL ${name}${detail ? `: ${detail}` : ''}`);
    process.exitCode = 1;
  } else {
    console.log(`PASS ${name}`);
  }
}
function targetAtLeast(tag, major, minor, patch) {
  const match = String(tag || '').match(/^v(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return false;
  const parts = match.slice(1).map(Number);
  if (parts[0] !== major) return parts[0] > major;
  if (parts[1] !== minor) return parts[1] > minor;
  return parts[2] >= patch;
}
const smoke = readJson('zlar-proof-smoke-sample-verification.json');
const servicePreflight = readJson('zlar-service-preflight-sample-verification.json');
const pack = readJson('zlar-local-proof-pack-sample-verification.json');
const runtimeLocalActivation = readJson('zlar-runtime-local-activation-sample-verification.json');
const runtimeProfileInstallation = readJson('zlar-runtime-profile-installation-sample-verification.json');
const coverage = readJson('zlar-coverage-map-sample.json');
const expectsServiceCoverageLane = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 91);
const expectsServiceProfileWrongPolicy = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 93);
const expectsTrustedIssuerRegistryRecognition = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 94);
const expectsTrustedIssuerRegistrySchemaContract = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 97);
const expectsNorthStarReadiness = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 98);
const expectsVerifierKitReproducibility = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 100);
const expectsVerifierKitPublicDistribution = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 109);
const expectsVerifierKitPublicReleaseAssets =
  process.env.ZLAR_DRY_RUN_PUBLIC_RELEASE_ASSETS_EXPECTED === 'true';
const expectsVerifierKitExternalRunnerDiagnostics = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 21);
const expectsInstalledRuntimeProfilePreflight = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 5);
const expectsInstalledRuntimeProfileRecognitionContract = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 6);
const expectsInstalledRuntimeProfileRecognitionProof = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 7);
const expectsInstalledRuntimeProfileRecognitionProofArtifact = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 8);
const expectsProductProofPath = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 9);
const expectsProductProofPathTerminalChainBoundary = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 45);
const expectsProductProofPathTerminalChainRecognitionRefusalGroupCaseIds = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 46);
const expectsProductProofPathTerminalChainRegistryVerdict = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 51);
const expectsProductProofPathDeploymentProfileAuthorityBridge = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 48);
const expectsProductProofPathDeploymentProfileAuthorityRefusals = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 49);
const expectsInstalledRuntimeProfileServiceProof = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 11);
const expectsInstalledRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomy = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 18);
const expectsInstalledRuntimeProfileRecognitionContractDigest = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 19);
const expectsInstalledRuntimeProfileTerminalChain = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 15);
const expectsInstalledRuntimeProfileTerminalChainNamedReceiptRefusals = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 22);
const expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroups = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 23);
const expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIds = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 25);
const expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroupObservedSummaries = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 26);
const expectsInstalledRuntimeProfileTerminalChainNestedArtifactTamperRefusals = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 28);
const expectsInstalledRuntimeProfileTerminalChainNestedArtifactBinding = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 30);
const expectedGovernedLanes = expectsInstalledRuntimeProfileTerminalChain
  ? 6
  : (expectsServiceCoverageLane ? 5 : 4);
const expectedTotalSurfaces = expectsInstalledRuntimeProfileTerminalChain
  ? 18
  : (expectsServiceCoverageLane ? 17 : 16);
const expectedServicePreflightCases = expectsServiceProfileWrongPolicy ? 11 : 10;
const expectedRecognitionRefusalGroupCaseIds = {
  no_usable_recognized_receipt_authority: [
    'missing_receipt_refused_before_runtime_mutation',
    'invalid_receipt_refused_before_runtime_mutation',
    'unknown_issuer_refused_before_runtime_mutation',
    'retired_issuer_refused_before_runtime_mutation',
    'missing_issuer_status_refused_before_runtime_mutation',
    'stale_receipt_refused_before_runtime_mutation',
  ],
  recognized_receipt_scope_mismatch: [
    'wrong_policy_refused_before_runtime_mutation',
    'wrong_domain_refused_before_runtime_mutation',
    'wrong_tool_refused_before_runtime_mutation',
    'wrong_audit_event_refused_before_runtime_mutation',
    'wrong_detail_refused_before_runtime_mutation',
    'non_boarding_outcome_refused_before_runtime_mutation',
  ],
  route_or_request_authority_material_refused: [
    'wrong_runtime_profile_id_refused_before_runtime_mutation',
    'direct_api_without_receipt_refused_before_runtime_mutation',
    'direct_api_with_receipt_refused_before_runtime_mutation',
    'agent_supplied_recognition_rule_refused_before_runtime_mutation',
    'agent_supplied_fixture_mode_refused_before_runtime_mutation',
    'unsupported_request_field_refused_before_runtime_mutation',
  ],
};
const expectedDeploymentProfileAuthorityRefusalCaseIds = [
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
];
function arraysEqual(left, right) {
  return Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((item, index) => item === right[index]);
}
function groupCaseIdsMatch(value) {
  return Object.entries(expectedRecognitionRefusalGroupCaseIds)
    .every(([key, expected]) => arraysEqual(value?.[key], expected));
}
function groupCaseIdsExact(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = Object.keys(expectedRecognitionRefusalGroupCaseIds).sort();
  return (
    arraysEqual(actual, expected) &&
    groupCaseIdsMatch(value)
  );
}
function assertObservedGroupCaseIds(prefix, observed, counts) {
  assert(`${prefix} case IDs preserved`, observed?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
  assert(`${prefix} group count preserved`, observed?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
  assert(`${prefix} case count preserved`, observed?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
  assert(`${prefix} case IDs preserved`, groupCaseIdsMatch(observed?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids));
  assert(`${prefix} artifact group count preserved`, observed?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count === counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
  assert(`${prefix} artifact case count preserved`, observed?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count === counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
  assert(`${prefix} artifact case IDs preserved`, groupCaseIdsMatch(observed?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids));
}
function assertNestedArtifactBinding(prefix, nested) {
  const preflightArtifactType =
    'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
  const serviceArtifactType =
    'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';
  assert(`${prefix} preflight type`, nested?.generated_preflight_artifact_type === preflightArtifactType);
  assert(`${prefix} service proof type`, nested?.generated_service_proof_artifact_type === serviceArtifactType);
  assert(`${prefix} preflight body hash`, /^[a-f0-9]{64}$/.test(nested?.generated_preflight_artifact_body_sha256 || ''));
  assert(`${prefix} service body hash`, /^[a-f0-9]{64}$/.test(nested?.generated_service_proof_artifact_body_sha256 || ''));
  assert(`${prefix} preflight verified`, nested?.generated_preflight_artifact_verified === true);
  assert(`${prefix} service proof verified`, nested?.generated_service_proof_artifact_verified === true);
  assert(`${prefix} preflight hash bound`, nested?.preflight_artifact_hash_bound === true);
  assert(`${prefix} service proof source preflight hash bound`, nested?.service_proof_source_preflight_hash_bound === true);
  assert(`${prefix} service artifact hash bound`, nested?.service_artifact_hash_bound === true);
  assert(`${prefix} service artifact verification bound`, nested?.service_artifact_verification_bound_to_service_proof === true);
  assert(`${prefix} no public attestation`, nested?.creates_public_external_attestation === false);
  assert(`${prefix} no non-operator review`, nested?.proves_non_operator_review === false);
  assert(`${prefix} no current-machine governance`, nested?.proves_current_machine_governance === false);
  assert(`${prefix} no production downstream`, nested?.proves_production_downstream_recognition === false);
}
function recognitionRefusalGroupCaseIds(groups) {
  return Object.fromEntries(Object.keys(expectedRecognitionRefusalGroupCaseIds).map((key) => [
    key,
    Array.isArray(groups?.[key]?.cases)
      ? groups[key].cases.map((item) => item.case_id)
      : [],
  ]));
}
const trustedIssuerRegistryRecognition = expectsTrustedIssuerRegistryRecognition
  ? readJson('zlar-trusted-receipt-issuer-recognition.json')
  : null;
const malformedRegistry = expectsTrustedIssuerRegistrySchemaContract
  ? readJson('zlar-trusted-receipt-issuer-recognition-malformed-registry.json')
  : null;
const malformedRegistryError = expectsTrustedIssuerRegistrySchemaContract
  ? fs.readFileSync('zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt', 'utf8')
  : null;
const northStarReadiness = expectsNorthStarReadiness
  ? readJson('zlar-north-star-readiness-v1.json')
  : null;
const verifierKitReproducibility = expectsVerifierKitReproducibility
  ? readJson('zlar-verifier-kit-reproducibility-v1.json')
  : null;
const verifierKitPublicDistribution = expectsVerifierKitPublicDistribution
  ? readJson('zlar-verifier-kit-public-distribution-v1.json')
  : null;
const verifierKitReleaseAssets = expectsVerifierKitPublicReleaseAssets
  ? readJson('zlar-verifier-kit-release-assets-v1.json')
  : null;
const verifierKitExternalRunnerDiagnostics = expectsVerifierKitExternalRunnerDiagnostics
  ? readJson('zlar-verifier-kit-external-runner-diagnostics-v1.json')
  : null;
const installedRuntimeProfilePreflight = expectsInstalledRuntimeProfilePreflight
  ? readJson('zlar-installed-runtime-profile-preflight-sample-verification.json')
  : null;
const installedRuntimeProfileRecognitionProof = expectsInstalledRuntimeProfileRecognitionProof
  ? readJson('zlar-installed-runtime-profile-recognition-proof-v1.json')
  : null;
const installedRuntimeProfileRecognitionProofArtifact = expectsInstalledRuntimeProfileRecognitionProofArtifact
  ? readJson('zlar-installed-runtime-profile-recognition-proof-artifact-v1.json')
  : null;
const installedRuntimeProfileRecognitionProofArtifactVerification = expectsInstalledRuntimeProfileRecognitionProofArtifact
  ? readJson('zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json')
  : null;
const productProofPath = expectsProductProofPath
  ? readJson('zlar-product-proof-path-v1.json')
  : null;
const installedRuntimeProfileServiceProof = expectsInstalledRuntimeProfileServiceProof
  ? readJson('zlar-installed-runtime-profile-service-proof-v1.json')
  : null;
const installedRuntimeProfileServiceProofArtifact = expectsInstalledRuntimeProfileServiceProof
  ? readJson('zlar-installed-runtime-profile-service-proof-artifact-v1.json')
  : null;
const installedRuntimeProfileServiceProofArtifactVerification = expectsInstalledRuntimeProfileServiceProof
  ? readJson('zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json')
  : null;
const installedRuntimeProfileTerminalChain = expectsInstalledRuntimeProfileTerminalChain
  ? readJson('zlar-installed-runtime-profile-terminal-chain-v1.json')
  : null;
const installedRuntimeProfileTerminalChainArtifact = expectsInstalledRuntimeProfileTerminalChain
  ? readJson('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json')
  : null;
const installedRuntimeProfileTerminalChainArtifactVerification = expectsInstalledRuntimeProfileTerminalChain
  ? readJson('zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json')
  : null;
assert('proof-smoke sample verified', smoke.verified === true);
assert(`proof-smoke governed lanes ${expectedGovernedLanes}`, smoke.counts?.governed_lanes === expectedGovernedLanes, String(smoke.counts?.governed_lanes));
assert('proof-smoke runtime profile artifact verified', smoke.counts?.runtime_profile_installation_sample_artifact_verified === true);
assert('proof-smoke runtime profile applied', smoke.counts?.runtime_profile_installation_applied === true);
assert('proof-smoke request authority guard refused', smoke.counts?.runtime_profile_installation_request_authority_guard_refused === true);
if (expectsInstalledRuntimeProfilePreflight) {
  assert('proof-smoke installed runtime profile preflight verified', smoke.counts?.installed_runtime_profile_preflight_sample_artifact_verified === true);
  assert('proof-smoke installed runtime profile preflight read only', smoke.counts?.installed_runtime_profile_preflight_read_only === true);
  assert('proof-smoke installed runtime profile preflight current-machine false', smoke.counts?.installed_runtime_profile_preflight_current_machine_governance_proven === false);
  assert('installed runtime profile preflight verified', installedRuntimeProfilePreflight.verified === true);
  assert('installed runtime profile preflight read only', installedRuntimeProfilePreflight.read_only === true);
  assert('installed runtime profile preflight no activation', installedRuntimeProfilePreflight.runtime_profile_activation_performed === false);
}
if (expectsInstalledRuntimeProfileRecognitionContract) {
  assert('proof-smoke installed runtime profile recognition contract preserved', smoke.counts?.installed_runtime_profile_preflight_recognition_contract_preserved === true);
  assert('installed runtime profile recognition contract preserved', installedRuntimeProfilePreflight.recognition_contract_preserved === true);
  assert('installed runtime profile recognition boundary', installedRuntimeProfilePreflight.recognition_boundary === 'service-configured-recognition-rule', installedRuntimeProfilePreflight.recognition_boundary);
  assert('installed runtime profile recognition rule not agent supplied', installedRuntimeProfilePreflight.recognition_rule_supplied_by_agent === false);
}
if (expectsInstalledRuntimeProfileRecognitionContractDigest) {
  assert('proof-smoke installed runtime profile recognition contract digest preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_preflight_recognition_contract_sha256 || ''));
  assert('installed runtime profile preflight recognition contract digest bound', smoke.counts?.installed_runtime_profile_preflight_recognition_contract_sha256 === installedRuntimeProfilePreflight.recognition_contract_sha256);
}
if (expectsInstalledRuntimeProfileRecognitionProof) {
  assert('proof-smoke installed runtime profile recognition proof verified', smoke.counts?.installed_runtime_profile_recognition_proof_verified === true);
  assert('proof-smoke installed runtime profile recognition refusal cases', smoke.counts?.installed_runtime_profile_recognition_refusal_case_count === 18, String(smoke.counts?.installed_runtime_profile_recognition_refusal_case_count));
  assert('proof-smoke installed runtime profile recognition refusals before mutation', smoke.counts?.installed_runtime_profile_recognition_all_refusals_before_mutation === true);
  assert('proof-smoke installed runtime profile recognition current-machine false', smoke.counts?.installed_runtime_profile_recognition_current_machine_governance_proven === false);
  assert('installed runtime profile recognition proof type', installedRuntimeProfileRecognitionProof.proof_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-v1', installedRuntimeProfileRecognitionProof.proof_type);
  assert('installed runtime profile recognition proof boarded', installedRuntimeProfileRecognitionProof.recognized_boarding?.boarded === true);
  assert('installed runtime profile recognition proof refusal cases', installedRuntimeProfileRecognitionProof.refusal_cases?.length === 18, String(installedRuntimeProfileRecognitionProof.refusal_cases?.length));
  assert('installed runtime profile recognition proof refusals before mutation', (installedRuntimeProfileRecognitionProof.refusal_cases || []).every((item) => item.boarded === false && item.service_write_accepted === false && item.state_entry_count_delta === 0));
  assert('installed runtime profile recognition proof no runtime service', installedRuntimeProfileRecognitionProof.proof_boundary?.runtime_service_started === false);
  assert('installed runtime profile recognition proof no current-machine governance', installedRuntimeProfileRecognitionProof.proof_boundary?.current_machine_governance_proven === false);
  assert('installed runtime profile recognition proof no production downstream', installedRuntimeProfileRecognitionProof.proof_boundary?.production_downstream_recognition === false);
}
if (expectsInstalledRuntimeProfileRecognitionProofArtifact) {
  assert('installed runtime profile recognition proof artifact type', installedRuntimeProfileRecognitionProofArtifact.artifact_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-artifact-v1', installedRuntimeProfileRecognitionProofArtifact.artifact_type);
  assert('installed runtime profile recognition proof artifact embeds proof', installedRuntimeProfileRecognitionProofArtifact.payload?.proof?.proof_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-v1', installedRuntimeProfileRecognitionProofArtifact.payload?.proof?.proof_type);
  assert('installed runtime profile recognition proof artifact verification type', installedRuntimeProfileRecognitionProofArtifactVerification.verification_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-artifact-verification-v1', installedRuntimeProfileRecognitionProofArtifactVerification.verification_type);
  assert('installed runtime profile recognition proof artifact verifies true', installedRuntimeProfileRecognitionProofArtifactVerification.verified === true);
  assert('installed runtime profile recognition proof artifact refusals before mutation', installedRuntimeProfileRecognitionProofArtifactVerification.all_refusals_before_mutation === true);
  assert('installed runtime profile recognition proof artifact current-machine false', installedRuntimeProfileRecognitionProofArtifactVerification.current_machine_governance_proven === false);
  assert('installed runtime profile recognition proof artifact production downstream false', installedRuntimeProfileRecognitionProofArtifactVerification.production_downstream_recognition === false);
}
if (expectsInstalledRuntimeProfileServiceProof) {
  assert('proof-smoke installed runtime profile service proof verified', smoke.counts?.installed_runtime_profile_service_proof_verified === true);
  assert('proof-smoke installed runtime profile service runtime service started', smoke.counts?.installed_runtime_profile_service_runtime_service_started === true);
  assert('proof-smoke installed runtime profile service replay refused', smoke.counts?.installed_runtime_profile_service_restart_replay_refused === true);
  assert('proof-smoke installed runtime profile service consumed-store integrity refused', smoke.counts?.installed_runtime_profile_service_consumed_store_integrity_refusals_proven === true);
  assert('proof-smoke installed runtime profile service refusals before mutation', smoke.counts?.installed_runtime_profile_service_all_refusals_before_mutation === true);
  assert('proof-smoke installed runtime profile service current-machine false', smoke.counts?.installed_runtime_profile_service_current_machine_governance_proven === false);
  assert('proof-smoke installed runtime profile service proof artifact verification preserved', smoke.counts?.installed_runtime_profile_service_artifact_verification_verified === true);
  assert('proof-smoke installed runtime profile service proof artifact verification restart replay refused', smoke.counts?.installed_runtime_profile_service_artifact_verification_restart_replay_refused === true);
  assert('proof-smoke installed runtime profile service proof artifact verification current-machine false', smoke.counts?.installed_runtime_profile_service_artifact_verification_current_machine_governance_proven === false);
  assert('installed runtime profile service proof type', installedRuntimeProfileServiceProof.proof_type === 'zlar-protected-records-installed-runtime-profile-service-proof-v1', installedRuntimeProfileServiceProof.proof_type);
  assert('installed runtime profile service proof runtime service started', installedRuntimeProfileServiceProof.proof_boundary?.runtime_service_started === true);
  assert('installed runtime profile service proof boarded', installedRuntimeProfileServiceProof.recognized_boarding?.boarded === true);
  assert('installed runtime profile service proof replay cases', installedRuntimeProfileServiceProof.service_replay_cases?.length === 2, String(installedRuntimeProfileServiceProof.service_replay_cases?.length));
  assert('installed runtime profile service proof restart replay refused', installedRuntimeProfileServiceProof.proof_boundary?.cross_process_replay_after_restart_closed === true);
  assert('installed runtime profile service proof consumed-store integrity cases', installedRuntimeProfileServiceProof.consumed_store_integrity_cases?.length === 8, String(installedRuntimeProfileServiceProof.consumed_store_integrity_cases?.length));
  assert('installed runtime profile service proof consumed-store integrity refused', installedRuntimeProfileServiceProof.service_boundary?.consumed_store_integrity_refusals_proven === true);
  assert('installed runtime profile service proof joint store-anchor rollback detected with witness', installedRuntimeProfileServiceProof.proof_boundary?.store_and_anchor_joint_rollback_detection === true);
  assert('installed runtime profile service proof joint store-anchor-witness rollback false', installedRuntimeProfileServiceProof.proof_boundary?.store_anchor_and_witness_joint_rollback_detection === false);
  assert('installed runtime profile service proof store-anchor rollback case count', installedRuntimeProfileServiceProof.store_and_anchor_rollback_cases?.length === 1);
  assert('installed runtime profile service proof refusal cases', installedRuntimeProfileServiceProof.refusal_cases?.length === 18, String(installedRuntimeProfileServiceProof.refusal_cases?.length));
  assert('installed runtime profile service proof refusals before mutation', (installedRuntimeProfileServiceProof.refusal_cases || []).every((item) => item.boarded === false && item.service_write_accepted === false && item.state_entry_count_delta === 0));
  assert('installed runtime profile service proof persistent runtime config false', installedRuntimeProfileServiceProof.proof_boundary?.persistent_runtime_config_written === false);
  assert('installed runtime profile service proof no current-machine governance', installedRuntimeProfileServiceProof.proof_boundary?.current_machine_governance_proven === false);
  assert('installed runtime profile service proof no production downstream', installedRuntimeProfileServiceProof.proof_boundary?.production_downstream_recognition === false);
  assert('installed runtime profile service proof artifact type', installedRuntimeProfileServiceProofArtifact.artifact_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1', installedRuntimeProfileServiceProofArtifact.artifact_type);
  assert('installed runtime profile service proof artifact embeds proof', installedRuntimeProfileServiceProofArtifact.payload?.proof?.proof_type === 'zlar-protected-records-installed-runtime-profile-service-proof-v1', installedRuntimeProfileServiceProofArtifact.payload?.proof?.proof_type);
  assert('installed runtime profile service proof artifact verification type', installedRuntimeProfileServiceProofArtifactVerification.verification_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-verification-v1', installedRuntimeProfileServiceProofArtifactVerification.verification_type);
  assert('installed runtime profile service proof artifact verifies true', installedRuntimeProfileServiceProofArtifactVerification.verified === true);
  assert('installed runtime profile service proof artifact runtime service started', installedRuntimeProfileServiceProofArtifactVerification.runtime_service_started === true);
  assert('installed runtime profile service proof artifact replay refused', installedRuntimeProfileServiceProofArtifactVerification.restart_replay_refused === true);
  assert('installed runtime profile service proof artifact consumed-store refused', installedRuntimeProfileServiceProofArtifactVerification.consumed_store_integrity_refusals_proven === true);
  assert('installed runtime profile service proof artifact joint store-anchor rollback detected with witness', installedRuntimeProfileServiceProofArtifactVerification.store_and_anchor_joint_rollback_detection === true);
  assert('installed runtime profile service proof artifact joint store-anchor-witness rollback false', installedRuntimeProfileServiceProofArtifactVerification.store_anchor_and_witness_joint_rollback_detection === false);
  assert('installed runtime profile service proof artifact store-anchor rollback case count', installedRuntimeProfileServiceProofArtifactVerification.store_and_anchor_rollback_case_count === 1);
  assert('installed runtime profile service proof artifact refusals before mutation', installedRuntimeProfileServiceProofArtifactVerification.all_refusals_before_mutation === true);
  assert('installed runtime profile service proof artifact current-machine false', installedRuntimeProfileServiceProofArtifactVerification.current_machine_governance_proven === false);
  assert('installed runtime profile service proof artifact production downstream false', installedRuntimeProfileServiceProofArtifactVerification.production_downstream_recognition === false);
}
if (expectsInstalledRuntimeProfileRecognitionContractDigest) {
  assert('proof-smoke installed runtime profile service recognition contract digest preserved', smoke.counts?.installed_runtime_profile_service_recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_preflight_recognition_contract_sha256 && /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_service_recognition_contract_sha256 || ''));
  assert('proof-smoke installed runtime profile service artifact recognition contract digest preserved', smoke.counts?.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_service_recognition_contract_sha256);
  assert('installed runtime profile service proof recognition contract digest bound', installedRuntimeProfileServiceProof.recognition_contract?.recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_service_recognition_contract_sha256);
  assert('installed runtime profile service proof artifact recognition contract digest bound', installedRuntimeProfileServiceProofArtifactVerification.recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_service_recognition_contract_sha256);
}
if (expectsInstalledRuntimeProfileServiceProofArtifactVerificationRefusalTaxonomy) {
  assert('proof-smoke installed runtime profile service proof artifact verification refusal taxonomy hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 || ''));
  assert('installed runtime profile service proof artifact refusal taxonomy hash bound', smoke.counts?.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 === installedRuntimeProfileServiceProofArtifactVerification.refusal_taxonomy_sha256 && /^[a-f0-9]{64}$/.test(installedRuntimeProfileServiceProofArtifactVerification.refusal_taxonomy_sha256 || ''));
}
if (expectsInstalledRuntimeProfileTerminalChain) {
  assert('proof-smoke installed runtime profile terminal chain preserved', smoke.counts?.installed_runtime_profile_terminal_chain_verified === true);
  assert('proof-smoke installed runtime profile terminal chain missing receipt refused', smoke.counts?.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation === true);
  assert('proof-smoke installed runtime profile terminal chain refusal taxonomy hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 || ''));
  assert('proof-smoke installed runtime profile terminal chain current-machine false', smoke.counts?.installed_runtime_profile_terminal_chain_current_machine_governance_proven === false);
  assert('installed runtime profile terminal chain type', installedRuntimeProfileTerminalChain.chain_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-v1', installedRuntimeProfileTerminalChain.chain_type);
  assert('installed runtime profile terminal chain generated root preflighted', installedRuntimeProfileTerminalChain.terminal_chain?.generated_installed_root_preflighted === true);
  assert('installed runtime profile terminal chain generated preflight consumed', installedRuntimeProfileTerminalChain.terminal_chain?.generated_preflight_artifact_consumed_by_service_proof === true);
  assert('installed runtime profile terminal chain service proof bound', installedRuntimeProfileTerminalChain.terminal_chain?.service_proof_bound_to_generated_preflight === true);
  assert('installed runtime profile terminal chain service artifact bound', installedRuntimeProfileTerminalChain.terminal_chain?.service_artifact_verification_bound_to_service_proof === true);
  assert('installed runtime profile terminal chain boarded', installedRuntimeProfileTerminalChain.terminal_chain?.recognized_write_boarded === true);
  assert('installed runtime profile terminal chain missing receipt refused', installedRuntimeProfileTerminalChain.terminal_chain?.missing_receipt_refused_before_mutation === true);
  assert('installed runtime profile terminal chain invalid receipt refused', installedRuntimeProfileTerminalChain.terminal_chain?.invalid_receipt_refused_before_mutation === true);
  assert('installed runtime profile terminal chain refusals before mutation', installedRuntimeProfileTerminalChain.terminal_chain?.all_required_refusals_before_mutation === true);
  assert('installed runtime profile terminal chain required refusal cases', installedRuntimeProfileTerminalChain.generated_service_proof?.required_refusal_cases?.length === 18);
  assert('installed runtime profile terminal chain observed refusal cases', installedRuntimeProfileTerminalChain.generated_service_proof?.observed_refusal_cases?.length === 18);
  assert('installed runtime profile terminal chain refusal taxonomy hash bound', installedRuntimeProfileTerminalChain.terminal_chain?.refusal_taxonomy_sha256 === installedRuntimeProfileTerminalChain.generated_service_proof?.refusal_taxonomy_sha256 && /^[a-f0-9]{64}$/.test(installedRuntimeProfileTerminalChain.terminal_chain?.refusal_taxonomy_sha256 || ''));
  assert('proof-smoke installed runtime profile terminal chain refusal taxonomy count bound', smoke.counts?.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 === installedRuntimeProfileTerminalChain.terminal_chain?.refusal_taxonomy_sha256);
  assert('installed runtime profile terminal chain no persistent install', installedRuntimeProfileTerminalChain.side_door_report?.persistent_runtime_profile_installed === false);
  assert('installed runtime profile terminal chain no activation', installedRuntimeProfileTerminalChain.side_door_report?.runtime_profile_activation_performed === false);
  assert('installed runtime profile terminal chain no current-machine governance', installedRuntimeProfileTerminalChain.side_door_report?.current_machine_governance_proven === false);
  assert('installed runtime profile terminal chain no production downstream', installedRuntimeProfileTerminalChain.generated_service_proof?.production_downstream_recognition === false);
  assert('installed runtime profile terminal chain artifact type', installedRuntimeProfileTerminalChainArtifact.artifact_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-v1', installedRuntimeProfileTerminalChainArtifact.artifact_type);
  assert('installed runtime profile terminal chain artifact embeds chain', installedRuntimeProfileTerminalChainArtifact.payload?.chain?.chain_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-v1', installedRuntimeProfileTerminalChainArtifact.payload?.chain?.chain_type);
  assert('installed runtime profile terminal chain artifact verification type', installedRuntimeProfileTerminalChainArtifactVerification.verification_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-verification-v1', installedRuntimeProfileTerminalChainArtifactVerification.verification_type);
  assert('installed runtime profile terminal chain artifact verifies true', installedRuntimeProfileTerminalChainArtifactVerification.verified === true);
  assert('installed runtime profile terminal chain artifact missing receipt refused', installedRuntimeProfileTerminalChainArtifactVerification.missing_receipt_refused_before_mutation === true);
  assert('installed runtime profile terminal chain artifact refusal taxonomy hash bound', installedRuntimeProfileTerminalChainArtifactVerification.refusal_taxonomy_sha256 === installedRuntimeProfileTerminalChain.terminal_chain?.refusal_taxonomy_sha256);
  assert('proof-smoke installed runtime profile terminal chain artifact refusal taxonomy count bound', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256 === installedRuntimeProfileTerminalChainArtifactVerification.refusal_taxonomy_sha256);
  assert('installed runtime profile terminal chain artifact current-machine false', installedRuntimeProfileTerminalChainArtifactVerification.current_machine_governance_proven === false);
  assert('installed runtime profile terminal chain artifact production downstream false', installedRuntimeProfileTerminalChainArtifactVerification.production_downstream_recognition === false);
}
if (expectsInstalledRuntimeProfileTerminalChainNestedArtifactTamperRefusals) {
  const preflightArtifactType =
    'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
  const serviceArtifactType =
    'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';
  const forgedInnerPreflightHashError = fs.existsSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt')
    ? fs.readFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt', 'utf8')
    : '';
  const forgedInnerHashError = fs.existsSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt')
    ? fs.readFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt', 'utf8')
    : '';
  assert('installed runtime profile terminal chain nested preflight artifact preserved', installedRuntimeProfileTerminalChain.nested_artifacts?.generated_preflight_artifact?.artifact_type === preflightArtifactType);
  assert('installed runtime profile terminal chain nested service proof artifact preserved', installedRuntimeProfileTerminalChain.nested_artifacts?.generated_service_proof_artifact?.artifact_type === serviceArtifactType);
  assert('installed runtime profile terminal chain artifact nested preflight artifact preserved', installedRuntimeProfileTerminalChainArtifact.payload?.chain?.nested_artifacts?.generated_preflight_artifact?.artifact_type === preflightArtifactType);
  assert('installed runtime profile terminal chain artifact nested service proof artifact preserved', installedRuntimeProfileTerminalChainArtifact.payload?.chain?.nested_artifacts?.generated_service_proof_artifact?.artifact_type === serviceArtifactType);
  assert('installed runtime profile terminal chain forged inner preflight hash refused', forgedInnerPreflightHashError.includes('nested preflight artifact binding'));
  assert('installed runtime profile terminal chain forged inner service hash refused', forgedInnerHashError.includes('nested service proof artifact binding'));
}
if (expectsInstalledRuntimeProfileTerminalChainNestedArtifactBinding) {
  assertNestedArtifactBinding(
    'installed runtime profile terminal chain nested artifact binding summary',
    installedRuntimeProfileTerminalChain.terminal_chain?.nested_artifact_binding
  );
  assertNestedArtifactBinding(
    'installed runtime profile terminal chain artifact verification nested artifact binding summary',
    installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding
  );
  assert(
    'installed runtime profile terminal chain nested artifact binding summary matches verifier',
    JSON.stringify(installedRuntimeProfileTerminalChain.terminal_chain?.nested_artifact_binding) ===
      JSON.stringify(installedRuntimeProfileTerminalChainArtifactVerification.nested_artifact_binding)
  );
  assert('proof-smoke installed runtime profile terminal chain nested artifact binding preserved', smoke.counts?.installed_runtime_profile_terminal_chain_nested_artifact_binding_preserved === true);
  assert('proof-smoke installed runtime profile terminal chain artifact verification nested artifact binding preserved', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_nested_artifact_binding_preserved === true);
}
if (expectsInstalledRuntimeProfileTerminalChainNamedReceiptRefusals) {
  const namedKeys = ['missing', 'invalid', 'stale', 'unknown_issuer', 'wrong_policy', 'wrong_domain', 'wrong_tool'];
  const chainNamed = installedRuntimeProfileTerminalChain.terminal_chain?.named_receipt_refusals || {};
  const proofNamed = installedRuntimeProfileTerminalChain.generated_service_proof?.named_receipt_refusals || {};
  const artifactNamed = installedRuntimeProfileTerminalChainArtifactVerification.named_receipt_refusals || {};
  assert('proof-smoke installed runtime profile terminal chain named receipt refusals hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 || ''));
  assert('proof-smoke installed runtime profile terminal chain artifact named receipt refusals hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 || ''));
  assert('proof-smoke installed runtime profile terminal chain named receipt refusals count bound', smoke.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 === installedRuntimeProfileTerminalChain.terminal_chain?.named_receipt_refusals_sha256);
  assert('proof-smoke installed runtime profile terminal chain artifact named receipt refusals count bound', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 === installedRuntimeProfileTerminalChainArtifactVerification.named_receipt_refusals_sha256);
  assert('installed runtime profile terminal chain named receipt refusals hash bound', installedRuntimeProfileTerminalChain.terminal_chain?.named_receipt_refusals_sha256 === installedRuntimeProfileTerminalChain.generated_service_proof?.named_receipt_refusals_sha256 && /^[a-f0-9]{64}$/.test(installedRuntimeProfileTerminalChain.terminal_chain?.named_receipt_refusals_sha256 || ''));
  assert('installed runtime profile terminal chain artifact named receipt refusals hash bound', installedRuntimeProfileTerminalChainArtifactVerification.named_receipt_refusals_sha256 === installedRuntimeProfileTerminalChain.terminal_chain?.named_receipt_refusals_sha256);
  assert('installed runtime profile terminal chain named receipt refusal keys present', namedKeys.every((key) => chainNamed[key] && proofNamed[key] && artifactNamed[key]));
  assert('installed runtime profile terminal chain named receipt refusals before mutation', namedKeys.every((key) => chainNamed[key]?.refused_before_mutation === true && proofNamed[key]?.refused_before_mutation === true && artifactNamed[key]?.refused_before_mutation === true));
}
if (expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroups) {
  const groupKeys = [
    'no_usable_recognized_receipt_authority',
    'recognized_receipt_scope_mismatch',
    'route_or_request_authority_material_refused',
  ];
  const chainGroups = installedRuntimeProfileTerminalChain.terminal_chain?.recognition_refusal_groups || {};
  const proofGroups = installedRuntimeProfileTerminalChain.generated_service_proof?.recognition_refusal_groups || {};
  const artifactGroups = installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_groups || {};
  assert('proof-smoke installed runtime profile terminal chain recognition refusal groups hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 || ''));
  assert('proof-smoke installed runtime profile terminal chain artifact recognition refusal groups hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 || ''));
  assert('proof-smoke installed runtime profile terminal chain recognition refusal groups count bound', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 === installedRuntimeProfileTerminalChain.terminal_chain?.recognition_refusal_groups_sha256);
  assert('proof-smoke installed runtime profile terminal chain artifact recognition refusal groups count bound', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 === installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_groups_sha256);
  assert('installed runtime profile terminal chain recognition refusal groups hash bound', installedRuntimeProfileTerminalChain.terminal_chain?.recognition_refusal_groups_sha256 === installedRuntimeProfileTerminalChain.generated_service_proof?.recognition_refusal_groups_sha256 && /^[a-f0-9]{64}$/.test(installedRuntimeProfileTerminalChain.terminal_chain?.recognition_refusal_groups_sha256 || ''));
  assert('installed runtime profile terminal chain artifact recognition refusal groups hash bound', installedRuntimeProfileTerminalChainArtifactVerification.recognition_refusal_groups_sha256 === installedRuntimeProfileTerminalChain.terminal_chain?.recognition_refusal_groups_sha256);
  assert('installed runtime profile terminal chain recognition refusal group keys present', groupKeys.every((key) => chainGroups[key] && proofGroups[key] && artifactGroups[key]));
  assert('installed runtime profile terminal chain recognition refusal groups before mutation', groupKeys.every((key) => chainGroups[key]?.all_refused_before_mutation === true && proofGroups[key]?.all_refused_before_mutation === true && artifactGroups[key]?.all_refused_before_mutation === true));
  if (expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIds) {
    assert('proof-smoke installed runtime profile terminal chain recognition refusal group count preserved', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3);
    assert('proof-smoke installed runtime profile terminal chain recognition refusal group case count preserved', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === 18);
    assert('proof-smoke installed runtime profile terminal chain recognition refusal group case IDs preserved', groupCaseIdsExact(smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids));
    assert('proof-smoke installed runtime profile terminal chain artifact recognition refusal group count preserved', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count === 3);
    assert('proof-smoke installed runtime profile terminal chain artifact recognition refusal group case count preserved', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count === 18);
    assert('proof-smoke installed runtime profile terminal chain artifact recognition refusal group case IDs preserved', groupCaseIdsExact(smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids));
    assert('installed runtime profile terminal chain recognition refusal group case IDs bound', groupCaseIdsExact(recognitionRefusalGroupCaseIds(chainGroups)) && groupCaseIdsExact(recognitionRefusalGroupCaseIds(proofGroups)));
    assert('installed runtime profile terminal chain artifact recognition refusal group case IDs bound', groupCaseIdsExact(recognitionRefusalGroupCaseIds(artifactGroups)));
  }
}
if (expectsInstalledRuntimeProfileRecognitionContractDigest) {
  assert('proof-smoke installed runtime profile terminal chain recognition contract digest preserved', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_service_artifact_verification_recognition_contract_sha256 && /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_recognition_contract_sha256 || ''));
  assert('proof-smoke installed runtime profile terminal chain artifact recognition contract digest preserved', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_terminal_chain_recognition_contract_sha256);
  assert('installed runtime profile terminal chain recognition contract digest bound', installedRuntimeProfileTerminalChain.terminal_chain?.recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_terminal_chain_recognition_contract_sha256);
  assert('installed runtime profile terminal chain artifact recognition contract digest bound', installedRuntimeProfileTerminalChainArtifactVerification.recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_terminal_chain_recognition_contract_sha256);
}
if (expectsProductProofPath) {
  const productProofPathEvidenceModelAccepted =
    expectsProductProofPathDeploymentProfileAuthorityBridge
      ? productProofPath.evidence_model ===
          'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge'
      : expectsProductProofPathTerminalChainBoundary
        ? [
            'fresh-local-fixture-proof-pack-and-terminal-chain-artifact-verification',
            'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge',
          ].includes(productProofPath.evidence_model)
        : [
            'fresh-local-fixture-proof-pack',
            'fresh-local-fixture-proof-pack-and-terminal-chain-artifact-verification',
            'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge',
          ].includes(productProofPath.evidence_model);
  assert('product proof path report type', productProofPath.report_type === 'zlar-product-proof-path-v1', productProofPath.report_type);
  assert('product proof path result pass', productProofPath.result === 'PASS', productProofPath.result);
  assert('product proof path evidence model', productProofPathEvidenceModelAccepted, productProofPath.evidence_model);
  assert('product proof path no live probing', productProofPath.live_probing === false);
  assert('product proof path no private operator state', productProofPath.private_operator_state_required === false);
  assert('product proof path acceptance gates true', Object.values(productProofPath.acceptance_gate || {}).every((value) => value === true));
  assert('product proof path forbidden claims false', Object.values(productProofPath.forbidden_claims || {}).every((value) => value === false));
  if (expectsProductProofPathTerminalChainBoundary) {
    assert('product proof path terminal chain boundary observed', productProofPath.acceptance_gate?.terminal_chain_boundary_observed === true);
    assert('product proof path terminal chain artifact verified', productProofPath.acceptance_gate?.terminal_chain_artifact_verified === true);
    assert('product proof path terminal chain verified', productProofPath.terminal_chain_boundary?.verified === true);
    assert('product proof path terminal chain binding matches verification', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification === true);
    assert('product proof path terminal chain refusal hash matches binding', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_refusal_hash_matches_binding === true);
    assert('product proof path terminal chain trusted registry refusals all refused', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_refusals_all_refused === true);
    assert('product proof path terminal chain public key omitted', productProofPath.terminal_chain_boundary?.registry_public_key_material_included === false);
    assert('product proof path terminal chain receipt envelope omitted', productProofPath.terminal_chain_boundary?.receipt_envelope_included === false);
    assert('product proof path terminal chain no external attestation', productProofPath.terminal_chain_boundary?.external_attestation === false);
    assert('product proof path terminal chain no current-machine governance', productProofPath.terminal_chain_boundary?.current_machine_governance_proven === false);
    if (expectsProductProofPathTerminalChainRegistryVerdict) {
      assert('product proof path terminal chain trusted registry verdict recognized', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_verdict === 'RECOGNIZED');
      assert('product proof path terminal chain trusted registry recognized true', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_recognized === true);
      assert('product proof path terminal chain trusted registry decision accept', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_decision === 'accept');
      assert('product proof path terminal chain trusted registry reason recognized', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_reason_code === 'recognized');
      assert('product proof path terminal chain trusted registry active issuer', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_issuer_status === 'active');
      assert('product proof path terminal chain trusted registry signature valid', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_signature_valid === true);
      assert('product proof path terminal chain trusted registry fixture validated', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_fixture_validated === true);
      assert('product proof path terminal chain trusted registry fixture evaluated', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_fixture_evaluated === true);
      assert('product proof path terminal chain trusted registry rule evaluated', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated === true);
      assert('product proof path terminal chain trusted registry evaluator type', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_evaluation_result_type === 'downstream-recognition-rule-v1');
      assert('product proof path terminal chain trusted registry issuer count', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_trusted_issuer_count === 1);
      assert('product proof path terminal chain trusted registry audit bound', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_required_audit_event_id_bound === true);
      assert('product proof path terminal chain trusted registry detail bound', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_required_detail_hash_bound === true);
      assert('product proof path terminal chain trusted registry fixture contract sha', /^[a-f0-9]{64}$/.test(productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_fixture_contract_sha256 || ''));
      assert('product proof path terminal chain trusted registry receipt payload contract sha', /^[a-f0-9]{64}$/.test(productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_receipt_payload_contract_sha256 || ''));
    }
    if (expectsProductProofPathTerminalChainRecognitionRefusalGroupCaseIds) {
      assert('product proof path terminal chain recognition refusal group count', productProofPath.terminal_chain_boundary?.recognition_refusal_group_count === 3);
      assert('product proof path terminal chain recognition refusal group case count', productProofPath.terminal_chain_boundary?.recognition_refusal_group_case_count === 18);
      assert('product proof path terminal chain recognition refusal group case IDs preserved', productProofPath.terminal_chain_boundary?.recognition_refusal_group_case_ids_preserved === true);
      assert('product proof path terminal chain recognition refusal group case IDs exact', groupCaseIdsExact(productProofPath.terminal_chain_boundary?.recognition_refusal_group_case_ids));
    }
  }
  if (expectsProductProofPathDeploymentProfileAuthorityBridge) {
    assert('product proof path deployment bridge observed', productProofPath.acceptance_gate?.deployment_profile_authority_bridge_observed === true);
    assert('product proof path deployment bridge proof type', productProofPath.deployment_profile_authority_bridge?.proof_type === 'zlar-protected-records-one-terminal-deployment-profile-proof-v1', productProofPath.deployment_profile_authority_bridge?.proof_type);
    assert('product proof path deployment bridge evidence model', productProofPath.deployment_profile_authority_bridge?.evidence_model === 'local-fixture-one-terminal-deployment-profile-authority-bridge', productProofPath.deployment_profile_authority_bridge?.evidence_model);
    assert('product proof path deployment bridge no live probing', productProofPath.deployment_profile_authority_bridge?.live_probing === false);
    assert('product proof path deployment bridge profile sha', /^[a-f0-9]{64}$/.test(productProofPath.deployment_profile_authority_bridge?.deployment_profile_sha256 || ''));
    assert('product proof path deployment bridge runtime sha', /^[a-f0-9]{64}$/.test(productProofPath.deployment_profile_authority_bridge?.runtime_profile_sha256 || ''));
    assert('product proof path deployment bridge explicit selection', productProofPath.deployment_profile_authority_bridge?.selected_by_explicit_id_and_sha === true);
    assert('product proof path deployment bridge no latest', productProofPath.deployment_profile_authority_bridge?.selects_latest_profile === false);
    assert('product proof path deployment bridge preflight verified', productProofPath.deployment_profile_authority_bridge?.preflight_artifact_verified === true);
    assert('product proof path deployment bridge recognized once', productProofPath.deployment_profile_authority_bridge?.recognized_receipt_mutates_once === true);
    assert('product proof path deployment bridge recognized delta one', productProofPath.deployment_profile_authority_bridge?.recognized_state_entry_count_delta === 1);
    assert('product proof path deployment bridge refusal count', productProofPath.deployment_profile_authority_bridge?.required_refusal_case_count === 18 && productProofPath.deployment_profile_authority_bridge?.observed_refusal_case_count === 18);
    assert('product proof path deployment bridge refusals before mutation', productProofPath.deployment_profile_authority_bridge?.all_required_refusals_before_mutation === true);
    assert('product proof path deployment bridge agent authority refused', productProofPath.deployment_profile_authority_bridge?.agent_supplied_authority_refused_before_mutation === true);
    assert('product proof path deployment bridge direct API refused', productProofPath.deployment_profile_authority_bridge?.direct_api_refused_before_mutation === true);
    assert('product proof path deployment bridge downstream refusal proven', productProofPath.deployment_profile_authority_bridge?.downstream_refusal_proven === true);
    assert('product proof path deployment bridge request authority false', productProofPath.deployment_profile_authority_bridge?.request_stream_authority_material_accepted === false);
    if (expectsProductProofPathDeploymentProfileAuthorityRefusals) {
      assert('product proof path deployment bridge authority refusal count', productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusal_case_count === expectedDeploymentProfileAuthorityRefusalCaseIds.length);
      assert('product proof path deployment bridge authority refusal case IDs', arraysEqual(productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
      assert('product proof path deployment bridge authority refusals before service proof', productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusals_before_service_proof === true);
      assert('product proof path deployment bridge authority refusals before mutation', productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusals_before_mutation === true);
      assert('product proof path deployment bridge authority refusal service proof not started', productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusal_service_proof_started === false);
      assert('product proof path deployment bridge stale artifact refusal', productProofPath.deployment_profile_authority_bridge?.stale_deployment_profile_artifact_refused_before_service_proof === true);
      assert('product proof path deployment bridge profile mismatch refusal', productProofPath.deployment_profile_authority_bridge?.profile_recognition_mismatch_refused_before_service_proof === true);
      assert('product proof path deployment bridge latest selection refusal', productProofPath.deployment_profile_authority_bridge?.latest_profile_selection_refused_before_service_proof === true);
      assert('product proof path deployment bridge request authority refusal', productProofPath.deployment_profile_authority_bridge?.request_stream_authority_material_refused_before_service_proof === true);
    }
    assert('product proof path deployment bridge current-machine false', productProofPath.deployment_profile_authority_bridge?.current_machine_governance === false);
    assert('product proof path deployment bridge production false', productProofPath.deployment_profile_authority_bridge?.production_downstream_recognition === false && productProofPath.deployment_profile_authority_bridge?.production_authority === false);
    assert('product proof path deployment bridge enterprise/external false', productProofPath.deployment_profile_authority_bridge?.enterprise_readiness === false && productProofPath.deployment_profile_authority_bridge?.external_attestation === false);
    assert('product proof path deployment bridge sovereign/unrouted false', productProofPath.deployment_profile_authority_bridge?.sovereign_recognition === false && productProofPath.deployment_profile_authority_bridge?.unrouted_surface_coverage === false);
  }
  assert('product proof path simulated channel', productProofPath.observed?.simulated_human_authorization?.approval_channel === 'simulated-human-fixture', productProofPath.observed?.simulated_human_authorization?.approval_channel);
  assert('product proof path authorized boarded', productProofPath.observed?.simulated_human_authorization?.authorized_boarded === true);
  assert('product proof path pending not boarded', productProofPath.observed?.simulated_human_authorization?.pending_boarded === false);
  assert('product proof path denied not boarded', productProofPath.observed?.simulated_human_authorization?.denied_boarded === false);
  assert('product proof path receipt valid verdict', productProofPath.observed?.receipt_verifier_boundary?.valid_verdict === 'VALID', productProofPath.observed?.receipt_verifier_boundary?.valid_verdict);
  assert('product proof path receipt unknown signer verdict', productProofPath.observed?.receipt_verifier_boundary?.unknown_signer_verdict === 'UNKNOWN-SIGNER', productProofPath.observed?.receipt_verifier_boundary?.unknown_signer_verdict);
  assert('product proof path receipt invalid verdict', productProofPath.observed?.receipt_verifier_boundary?.invalid_verdict === 'INVALID', productProofPath.observed?.receipt_verifier_boundary?.invalid_verdict);
  assert('product proof path receipt downstream recognition false', productProofPath.observed?.receipt_verifier_boundary?.downstream_recognition_proven === false);
  assert('product proof path current-machine false', productProofPath.forbidden_claims?.current_machine_governance === false);
  assert('product proof path external attestation false', productProofPath.forbidden_claims?.external_attestation === false);
  assert('product proof path all-MCP false', productProofPath.forbidden_claims?.all_mcp_governance === false);
  assert('product proof path unrouted coverage false', productProofPath.forbidden_claims?.unrouted_surface_coverage === false);
  assert('product proof path known noncoverage visible', (productProofPath.observed?.known_ungoverned_boundaries || []).includes('unrouted_records_paths'));
}
assert('service preflight sample verified', servicePreflight.verified === true);
assert('service preflight evidence model config backed', servicePreflight.evidence_model === 'local-disposable-config-backed-profile-preflight-fixture', servicePreflight.evidence_model);
assert(`service preflight cases ${expectedServicePreflightCases}`, servicePreflight.case_count === expectedServicePreflightCases && servicePreflight.required_case_count === expectedServicePreflightCases, `${servicePreflight.case_count}/${servicePreflight.required_case_count}`);
if (expectsServiceProfileWrongPolicy) {
  assert('service preflight wrong policy refused', servicePreflight.wrong_policy_refused === true);
  assert('service preflight wrong policy reason', servicePreflight.wrong_policy_reason === 'policy_not_recognized', servicePreflight.wrong_policy_reason);
  assert('service preflight wrong policy state delta zero', servicePreflight.wrong_policy_state_delta === 0, String(servicePreflight.wrong_policy_state_delta));
}
if (expectsTrustedIssuerRegistryRecognition) {
  assert('trusted issuer registry recognition verdict', trustedIssuerRegistryRecognition.verdict === 'RECOGNIZED', trustedIssuerRegistryRecognition.verdict);
  assert('trusted issuer registry recognition fixture model', trustedIssuerRegistryRecognition.registry_evidence_model === 'bundled-local-fixture', trustedIssuerRegistryRecognition.registry_evidence_model);
  assert('trusted issuer registry recognition live probing false', trustedIssuerRegistryRecognition.live_probing === false);
  assert('trusted issuer registry recognition scope', trustedIssuerRegistryRecognition.registry_scope === 'verifier-kit-sample', trustedIssuerRegistryRecognition.registry_scope);
  assert('trusted issuer registry recognition recognized', trustedIssuerRegistryRecognition.recognized === true);
  assert('trusted issuer registry recognition signature valid', trustedIssuerRegistryRecognition.signature_valid === true);
}
if (expectsTrustedIssuerRegistrySchemaContract) {
  assert('trusted issuer registry schema negative fixture malformed', malformedRegistry.production_authority === true);
  assert('trusted issuer registry schema negative exits with unsupported field', /unsupported field: production_authority/.test(malformedRegistryError), malformedRegistryError);
  assert('trusted issuer registry schema negative emits no recognized verdict', !/^RECOGNIZED/m.test(malformedRegistryError));
  assert('trusted issuer registry schema negative emits no refused verdict', !/^RECOGNITION-REFUSED/m.test(malformedRegistryError));
}
assert('service preflight launcher config required', servicePreflight.launcher_owned_config_required === true);
assert('service preflight request authority refused', servicePreflight.request_stream_authority_material_refused === true);
assert('service preflight request authority reason', servicePreflight.request_stream_authority_material_reason === 'request_stream_authority_material', servicePreflight.request_stream_authority_material_reason);
assert('service preflight request authority state delta zero', servicePreflight.request_stream_authority_material_state_delta === 0, String(servicePreflight.request_stream_authority_material_state_delta));
assert('service preflight forbidden fields refused', servicePreflight.request_stream_forbidden_fields_refused === true);
assert('service preflight direct api receipt reason', servicePreflight.direct_api_receipt_present_reason === 'request_stream_forbidden_fields', servicePreflight.direct_api_receipt_present_reason);
assert('service preflight no live profile install', servicePreflight.live_profile_installed === false);
assert('service preflight no production service', servicePreflight.production_records_service_checked === false);
assert('service preflight no external attestation', servicePreflight.external_attestation === false);
assert('local proof-pack verified', pack.verified === true);
const rpi = pack.runtime_profile_installation || {};
assert('local proof-pack runtime installation included', rpi.run_in_proof_pack === true);
assert('runtime installation install root kind disposable', rpi.disposable_profile_selection?.install_root_kind === 'launcher-owned-disposable-proof-root');
assert('runtime installation selected by explicit id and sha', rpi.disposable_profile_selection?.selected_by_explicit_id_and_sha === true);
assert('runtime installation selected from install root', rpi.disposable_profile_selection?.profile_selected_from_install_root === true);
assert('runtime installation request guard refused installed profile state', rpi.request_authority_guard_summary?.installed_profile_state_refused === true);
assert('runtime installation request guard refused runtime config', rpi.request_authority_guard_summary?.runtime_config_refused === true);
assert('runtime installation request guard refused runtime profile', rpi.request_authority_guard_summary?.runtime_profile_refused === true);
assert('runtime installation request guard refused recognition rule', rpi.request_authority_guard_summary?.recognition_rule_refused === true);
assert('runtime installation request guard refused before mutation', rpi.request_authority_guard_summary?.all_refused_before_mutation === true);
assert('runtime installation persistent config false', rpi.persistent_runtime_config_written === false);
assert('runtime installation hook config false', rpi.hook_configuration_written === false);
assert('runtime installation user config false', rpi.user_config_written === false);
assert('runtime installation machine config false', rpi.machine_config_written === false);
const refusalFields = [
  'missing_issuer_status_refused',
  'stale_receipt_refused',
  'wrong_policy_refused',
  'wrong_domain_refused',
  'wrong_tool_refused',
  'wrong_runtime_profile_id_refused',
  'wrong_audit_event_refused',
  'wrong_detail_refused',
  'non_boarding_outcome_refused',
  'direct_api_with_receipt_refused',
  'agent_supplied_authority_material_refused',
];
for (const field of refusalFields) {
  assert(`runtime local activation ${field}`, runtimeLocalActivation[field] === true);
  assert(`runtime profile installation ${field}`, runtimeProfileInstallation[field] === true);
  assert(`local proof-pack runtime local activation ${field}`, pack.runtime_local_activation?.[field] === true);
  assert(`local proof-pack runtime installation ${field}`, rpi[field] === true);
}
assert(`coverage map governed lanes ${expectedGovernedLanes}`, coverage.counts?.governed_lanes === expectedGovernedLanes, String(coverage.counts?.governed_lanes));
assert(`coverage map counted lanes ${expectedGovernedLanes}`, coverage.counts?.counted_lanes === expectedGovernedLanes, String(coverage.counts?.counted_lanes));
assert(`coverage map total surfaces ${expectedTotalSurfaces}`, coverage.counts?.total_surfaces === expectedTotalSurfaces, String(coverage.counts?.total_surfaces));
assert('coverage map live probing false', coverage.evidence_model?.live_probing_performed === false);
const serviceLane = (coverage.surfaces || []).find((surface) => surface.surface_id === 'protected-records.service-profile.records.write');
if (expectsServiceCoverageLane) {
  assert('coverage includes service-profile lane', Boolean(serviceLane));
  assert('service-profile lane governed', serviceLane?.governed === true);
  assert('service-profile lane receipt capable', serviceLane?.coverage_summary?.receipt_status === 'receipt_capable');
  assert('service-profile lane has runtime install boundary', (serviceLane?.known_boundaries || []).includes('runtime_profile_not_installed'));
}
const installLane = (coverage.surfaces || []).find((surface) => surface.surface_id === 'protected-records.runtime.profile-installation.records.write');
assert('coverage includes profile-installation lane', Boolean(installLane));
assert('profile-installation lane governed', installLane?.governed === true);
assert('profile-installation lane receipt capable', installLane?.coverage_summary?.receipt_status === 'receipt_capable');
if (expectsNorthStarReadiness) {
  const privateIntakePointer = northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 7)?.observed?.private_intake_sample_manifest_pointer || {};
  const northStarVerifierKitDistribution = northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.verifier_kit_public_distribution || {};
  const northStarEnterpriseProfile = northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 3)?.observed || {};
  const northStarDownstreamRecognition = northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 5)?.observed || {};
  assert('north star readiness report type', northStarReadiness.report_type === 'zlar-north-star-readiness-v1', northStarReadiness.report_type);
  assert('north star readiness not v3.4 ready', northStarReadiness.result === 'NOT_READY_FOR_V3_4_0' && northStarReadiness.v3_4_0_gate?.ready === false);
  assert('north star readiness release-forward evidence model', northStarReadiness.evidence_model === 'release-forward-dry-run-artifacts', northStarReadiness.evidence_model);
  assert('north star readiness seven pieces', northStarReadiness.counts?.puzzle_pieces_total === 7, String(northStarReadiness.counts?.puzzle_pieces_total));
  assert('north star readiness external attestation unproven', northStarReadiness.claim_boundary?.public_external_attestation === false);
  assert('north star readiness production authority false', northStarReadiness.claim_boundary?.production_authority === false);
  assert('north star readiness current-machine governance false', northStarReadiness.claim_boundary?.current_machine_governance === false);
  assert('north star readiness live mcp false', northStarReadiness.claim_boundary?.live_mcp_coverage === false);
  assert('north star readiness unrouted coverage false', northStarReadiness.claim_boundary?.unrouted_surface_coverage === false);
  if (expectsInstalledRuntimeProfileServiceProof) {
    assert('north star readiness installed runtime profile service proof artifact verification preserved', northStarReadiness.counts?.installed_runtime_profile_service_artifact_verification_preserved === true);
  }
  if (expectsInstalledRuntimeProfileTerminalChain) {
    assert('north star readiness installed runtime profile terminal chain preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_preserved === true);
    assert('north star readiness installed runtime profile terminal chain required', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_required === true);
  }
  if (expectsInstalledRuntimeProfileTerminalChainNamedReceiptRefusals) {
    assert('north star readiness installed runtime profile terminal chain named receipt refusals required', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_required === true);
    assert('north star readiness installed runtime profile terminal chain named receipt refusals preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved === true);
    assert('north star readiness installed runtime profile terminal chain named receipt refusals hash preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 === smoke.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 && /^[a-f0-9]{64}$/.test(northStarReadiness.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 || ''));
    assert('north star readiness installed runtime profile terminal chain artifact named receipt refusals hash preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 === smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256);
  }
  if (expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroups) {
    assert('north star readiness installed runtime profile terminal chain recognition refusal groups required', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required === true);
    assert('north star readiness installed runtime profile terminal chain recognition refusal groups preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved === true);
    assert('north star readiness installed runtime profile terminal chain recognition refusal groups hash preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 === smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 && /^[a-f0-9]{64}$/.test(northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 || ''));
    assert('north star readiness installed runtime profile terminal chain artifact recognition refusal groups hash preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 === smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256);
    if (expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroupCaseIds) {
      assert('north star readiness installed runtime profile terminal chain recognition refusal group case IDs required', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required === true);
      assert('north star readiness installed runtime profile terminal chain recognition refusal group case IDs preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true);
      assert('north star readiness installed runtime profile terminal chain recognition refusal group count preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3);
      assert('north star readiness installed runtime profile terminal chain recognition refusal group case count preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === 18);
      assert('north star readiness installed runtime profile terminal chain recognition refusal group case IDs preserved', groupCaseIdsExact(northStarReadiness.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids));
      assert('north star readiness installed runtime profile terminal chain artifact recognition refusal group count preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count === 3);
      assert('north star readiness installed runtime profile terminal chain artifact recognition refusal group case count preserved', northStarReadiness.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count === 18);
      assert('north star readiness installed runtime profile terminal chain artifact recognition refusal group case IDs preserved', groupCaseIdsExact(northStarReadiness.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids));
    }
    if (expectsInstalledRuntimeProfileTerminalChainRecognitionRefusalGroupObservedSummaries) {
      assertObservedGroupCaseIds('north star readiness enterprise observed recognition refusal group', northStarEnterpriseProfile, northStarReadiness.counts);
      assertObservedGroupCaseIds('north star readiness downstream observed recognition refusal group', northStarDownstreamRecognition, northStarReadiness.counts);
    }
  }
  if (expectsInstalledRuntimeProfileRecognitionContractDigest) {
    assert('north star readiness installed runtime profile recognition contract digest required', northStarReadiness.counts?.installed_runtime_profile_recognition_contract_digest_required === true);
    assert('north star readiness installed runtime profile recognition contract digest preserved', northStarReadiness.counts?.installed_runtime_profile_recognition_contract_digest_preserved === true);
    assert('north star readiness installed runtime profile recognition contract digest hash preserved', northStarReadiness.counts?.installed_runtime_profile_recognition_contract_sha256 === smoke.counts?.installed_runtime_profile_preflight_recognition_contract_sha256 && /^[a-f0-9]{64}$/.test(northStarReadiness.counts?.installed_runtime_profile_recognition_contract_sha256 || ''));
  }
  assert('north star readiness trusted issuer recognition provided', northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.trusted_issuer_registry_recognition?.provided === true);
  assert('north star readiness malformed registry preserved', northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.malformed_registry_contract?.fail_closed_before_verdict === true);
  assert('north star readiness external attestation piece unproven', northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 6)?.status === 'unproven');
  assert('north star readiness private intake pointer reported', privateIntakePointer.provided === targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 107));
  assert('north star readiness verifier kit public distribution reported', northStarVerifierKitDistribution.provided === expectsVerifierKitPublicDistribution);
  if (expectsVerifierKitPublicDistribution) {
    assert('north star readiness verifier kit public distribution readiness matches expected public assets', northStarVerifierKitDistribution.ready_for_public_distribution_claim === expectsVerifierKitPublicReleaseAssets);
    assert('north star readiness verifier kit public distribution blockers match expected public assets', expectsVerifierKitPublicReleaseAssets ? northStarVerifierKitDistribution.blocking_reasons_count === 0 : northStarVerifierKitDistribution.blocking_reasons_count > 0);
    assert('north star readiness verifier kit public distribution hashes present', northStarVerifierKitDistribution.public_artifact_hashes_present === true);
    assert('north star readiness verifier kit public distribution release assets present matches expected public assets', northStarVerifierKitDistribution.required_release_assets_present === expectsVerifierKitPublicReleaseAssets);
    assert('north star readiness verifier kit public distribution release asset byte binding matches expected public assets', northStarVerifierKitDistribution.release_asset_hashes_bound === expectsVerifierKitPublicReleaseAssets);
    assert('north star readiness verifier kit public distribution local hashes match', northStarVerifierKitDistribution.local_artifact_hashes_match === true);
  }
  if (targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 3, 107)) {
    assert('north star readiness private intake pointer field', privateIntakePointer.manifest_field === 'private_verifier_result_sample');
    assert('north star readiness private intake pointer section', privateIntakePointer.result_section === 'Private Verifier Result Intake');
    assert('north star readiness private intake pointer non-circular', privateIntakePointer.included_in_core_artifact_hashes === false && privateIntakePointer.circular_hash_avoided === true);
    assert('north star readiness private intake pointer not attestation', privateIntakePointer.creates_public_external_attestation === false && privateIntakePointer.proves_non_operator_review === false);
  }
}
if (expectsVerifierKitReproducibility) {
  const hashes = verifierKitReproducibility.public_artifact_hashes || [];
  const northStarVerifierKit = northStarReadiness.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.verifier_kit_reproducibility || {};
  assert('verifier kit reproducibility report type', verifierKitReproducibility.report_type === 'zlar-verifier-kit-reproducibility-v1', verifierKitReproducibility.report_type);
  assert('verifier kit reproducibility result pass', verifierKitReproducibility.result === 'PASS', verifierKitReproducibility.result);
  assert('verifier kit reproducibility tarball identical', verifierKitReproducibility.reproducible?.tarball_sha256_identical === true);
  assert('verifier kit reproducibility manifest identical', verifierKitReproducibility.reproducible?.manifest_and_signature_sha256_identical === true);
  assert('verifier kit reproducibility sidecar matches', verifierKitReproducibility.reproducible?.sidecar_matches_tarball === true);
  assert('verifier kit reproducibility public tarball hash', hashes.some((entry) => entry.path === 'dist/zlar-verifier-kit-v0.1.0.tar.gz' && /^[0-9a-f]{64}$/.test(entry.sha256)));
  assert('verifier kit reproducibility boundary false', Object.values(verifierKitReproducibility.claim_boundary || {}).every((value) => value === false));
  assert('north star readiness verifier kit reproducibility provided', northStarVerifierKit.provided === true);
  assert('north star readiness verifier kit reproducibility boundary false', northStarVerifierKit.claim_boundary_flags_false === true);
}
if (expectsVerifierKitExternalRunnerDiagnostics) {
  assert('verifier kit external-runner diagnostics report type', verifierKitExternalRunnerDiagnostics.report_type === 'zlar-verifier-kit-external-runner-diagnostics-v1', verifierKitExternalRunnerDiagnostics.report_type);
  assert('verifier kit external-runner diagnostics result pass', verifierKitExternalRunnerDiagnostics.result === 'PASS', verifierKitExternalRunnerDiagnostics.result);
  assert('verifier kit external-runner diagnostics hardening minimum', verifierKitExternalRunnerDiagnostics.minimum_hardening_release_tag === 'v3.4.20');
  assert('verifier kit external-runner diagnostics preservation minimum', verifierKitExternalRunnerDiagnostics.artifact_preservation_minimum_release_tag === 'v3.4.21');
  assert('verifier kit external-runner diagnostics target tag', verifierKitExternalRunnerDiagnostics.target?.release_tag === process.env.ZLAR_DRY_RUN_TARGET_TAG, verifierKitExternalRunnerDiagnostics.target?.release_tag);
  assert('verifier kit external-runner diagnostics target sha match', verifierKitExternalRunnerDiagnostics.target?.expected_commit_sha === verifierKitExternalRunnerDiagnostics.target?.observed_commit_sha);
  assert('verifier kit external-runner diagnostics manifest entry bound', verifierKitExternalRunnerDiagnostics.built_kit?.manifest_entry_matches_built_file === true);
  assert('verifier kit external-runner diagnostics source built match', verifierKitExternalRunnerDiagnostics.built_kit?.source_matches_built_file === true);
  assert('verifier kit external-runner diagnostics grep q absent', verifierKitExternalRunnerDiagnostics.diagnostic_contract?.grep_q_absent_from_external_runner === true);
  assert('verifier kit external-runner diagnostics substring check', verifierKitExternalRunnerDiagnostics.diagnostic_contract?.pipefail_safe_last_output_check_present === true);
  assert('verifier kit external-runner diagnostics issuer artifact verified', verifierKitExternalRunnerDiagnostics.execution_evidence?.issuer_status_json_artifact_verified === true);
  assert('verifier kit external-runner diagnostics command boundary', verifierKitExternalRunnerDiagnostics.execution_evidence?.external_runner_dry_run_executed_by_this_command === false);
  assert('verifier kit external-runner diagnostics issuer artifact verdict', verifierKitExternalRunnerDiagnostics.execution_evidence?.issuer_status_verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED');
  assert('verifier kit external-runner diagnostics live probing false', verifierKitExternalRunnerDiagnostics.execution_evidence?.live_probing === false);
  assert('verifier kit external-runner diagnostics fixture copy assertions', verifierKitExternalRunnerDiagnostics.repo_regression_contract?.t_kit_23_fixture_copy_assertions_present === true);
  assert('verifier kit external-runner diagnostics failure tail preserved', verifierKitExternalRunnerDiagnostics.repo_regression_contract?.t_kit_23_failure_tail_diagnostic_present === true);
  assert('verifier kit external-runner diagnostics source regression not in kit', verifierKitExternalRunnerDiagnostics.repo_regression_contract?.included_in_built_kit === false);
  assert('verifier kit external-runner diagnostics boundary false', Object.values(verifierKitExternalRunnerDiagnostics.claim_boundary || {}).every((value) => value === false));
}
if (expectsVerifierKitPublicDistribution) {
  assert('verifier kit public distribution report type', verifierKitPublicDistribution.report_type === 'zlar-verifier-kit-public-distribution-v1', verifierKitPublicDistribution.report_type);
  assert('verifier kit public distribution audit pass', verifierKitPublicDistribution.result === 'AUDIT_PASS', verifierKitPublicDistribution.result);
  assert('verifier kit public distribution posture matches expected public assets', verifierKitPublicDistribution.posture === (expectsVerifierKitPublicReleaseAssets ? 'public_distribution_posture_ready' : 'public_release_assets_absent'), verifierKitPublicDistribution.posture);
  assert('verifier kit public distribution readiness matches expected public assets', verifierKitPublicDistribution.ready_for_public_distribution_claim === expectsVerifierKitPublicReleaseAssets);
  assert('verifier kit public distribution release asset presence matches expected public assets', (verifierKitPublicDistribution.required_public_release_assets || []).every((asset) => asset.present === expectsVerifierKitPublicReleaseAssets));
  assert('verifier kit public distribution local hashes match', verifierKitPublicDistribution.local_artifact_hashes?.all_checked_hashes_match === true);
  assert('verifier kit public distribution byte binding matches expected public assets', verifierKitPublicDistribution.release_assets?.release_asset_hashes?.all_required_assets_bound === expectsVerifierKitPublicReleaseAssets);
  assert('verifier kit public distribution boundary false', Object.values(verifierKitPublicDistribution.claim_boundary || {}).every((value) => value === false));
  if (expectsVerifierKitPublicReleaseAssets) {
    assert('verifier kit release assets report type', verifierKitReleaseAssets.report_type === 'zlar-verifier-kit-release-assets-live-v1', verifierKitReleaseAssets.report_type);
    assert('verifier kit release assets evidence model live read', verifierKitReleaseAssets.evidence_model === 'github-release-assets-json-live-read', verifierKitReleaseAssets.evidence_model);
    assert('verifier kit release assets all present', verifierKitReleaseAssets.all_required_assets_present === true);
    assert('verifier kit release assets all downloaded', verifierKitReleaseAssets.all_required_assets_downloaded === true);
    assert('verifier kit release assets boundary false', Object.values(verifierKitReleaseAssets.claim_boundary || {}).every((value) => value === false));
  }
}
if (process.exitCode) process.exit(process.exitCode);
NODE
}

write_manifest_file() {
    local completed_at observed_sha sanitized_repo_url private_result_sample_enabled issuer_status_evidence_enabled trusted_issuer_registry_recognition_evidence_enabled trusted_receipt_issuer_completion_evidence_enabled terminal_chain_refusal_evidence_enabled terminal_chain_recognition_refusal_groups_required terminal_chain_recognition_refusal_group_case_ids_required terminal_chain_nested_artifact_tamper_refusals_required terminal_chain_nested_artifact_binding_required terminal_chain_trusted_issuer_registry_recognition_refusals_required terminal_chain_deployment_profile_authority_refusal_mirror_required release_forward_report_contract_required release_forward_product_proof_path_contract_required release_forward_product_proof_path_terminal_chain_boundary_required release_forward_product_proof_path_terminal_chain_registry_verdict_required release_forward_product_proof_path_downstream_refusal_boundary_required release_forward_product_proof_path_recognized_receipt_path_mirror_required release_forward_product_proof_path_deployment_profile_authority_bridge_required release_forward_product_proof_path_deployment_profile_authority_refusals_required
    completed_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    observed_sha="$(cat "${OUTPUT_DIR}/target-head.txt")"
    sanitized_repo_url="$(printf '%s\n' "${REPO_URL}" | sanitize_transcript)"
    private_result_sample_enabled=false
    if tag_at_least 3 3 104; then
        private_result_sample_enabled=true
    fi
    issuer_status_evidence_enabled=false
    if tag_at_least 3 4 33; then
        issuer_status_evidence_enabled=true
    fi
    trusted_issuer_registry_recognition_evidence_enabled=false
    if tag_at_least 3 4 35; then
        trusted_issuer_registry_recognition_evidence_enabled=true
    fi
    trusted_receipt_issuer_completion_evidence_enabled=false
    if tag_at_least 3 4 53 &&
        [ -n "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" ] &&
        [ -f "${OUTPUT_DIR}/ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json" ]; then
        trusted_receipt_issuer_completion_evidence_enabled=true
    fi
    terminal_chain_refusal_evidence_enabled=false
    if tag_at_least 3 4 22; then
        terminal_chain_refusal_evidence_enabled=true
    fi
    terminal_chain_recognition_refusal_groups_required=false
    if tag_at_least 3 4 23; then
        terminal_chain_recognition_refusal_groups_required=true
    fi
    terminal_chain_recognition_refusal_group_case_ids_required=false
    if tag_at_least 3 4 24; then
        terminal_chain_recognition_refusal_group_case_ids_required=true
    fi
    terminal_chain_nested_artifact_tamper_refusals_required=false
    if tag_at_least 3 4 28; then
        terminal_chain_nested_artifact_tamper_refusals_required=true
    fi
    terminal_chain_nested_artifact_binding_required=false
    if tag_at_least 3 4 30; then
        terminal_chain_nested_artifact_binding_required=true
    fi
    terminal_chain_trusted_issuer_registry_recognition_refusals_required=false
    if tag_at_least 3 4 39; then
        terminal_chain_trusted_issuer_registry_recognition_refusals_required=true
    fi
    terminal_chain_deployment_profile_authority_refusal_mirror_required=false
    if tag_at_least 3 4 50; then
        terminal_chain_deployment_profile_authority_refusal_mirror_required=true
    fi
    release_forward_report_contract_required=false
    if tag_at_least 3 4 41; then
        release_forward_report_contract_required=true
    fi
    release_forward_product_proof_path_contract_required=false
    if tag_at_least 3 4 42; then
        release_forward_product_proof_path_contract_required=true
    fi
    release_forward_product_proof_path_terminal_chain_boundary_required=false
    if tag_at_least 3 4 45; then
        release_forward_product_proof_path_terminal_chain_boundary_required=true
    fi
    release_forward_product_proof_path_terminal_chain_recognition_refusal_group_case_ids_required=false
    if tag_at_least 3 4 46; then
        release_forward_product_proof_path_terminal_chain_recognition_refusal_group_case_ids_required=true
    fi
    release_forward_product_proof_path_terminal_chain_registry_verdict_required=false
    if tag_at_least 3 4 51; then
        release_forward_product_proof_path_terminal_chain_registry_verdict_required=true
    fi
    release_forward_product_proof_path_downstream_refusal_boundary_required=false
    if tag_at_least 3 4 51; then
        release_forward_product_proof_path_downstream_refusal_boundary_required=true
    fi
    release_forward_product_proof_path_recognized_receipt_path_mirror_required=false
    if tag_at_least 3 4 52; then
        release_forward_product_proof_path_recognized_receipt_path_mirror_required=true
    fi
    release_forward_product_proof_path_deployment_profile_authority_bridge_required=false
    if tag_at_least 3 4 48; then
        release_forward_product_proof_path_deployment_profile_authority_bridge_required=true
    fi
    release_forward_product_proof_path_deployment_profile_authority_refusals_required=false
    if tag_at_least 3 4 49; then
        release_forward_product_proof_path_deployment_profile_authority_refusals_required=true
    fi
    DRY_RUN_COMPLETED_AT="${completed_at}" \
        DRY_RUN_TAG="${TAG}" \
        DRY_RUN_EXPECTED_SHA="${EXPECTED_SHA}" \
        DRY_RUN_OBSERVED_SHA="${observed_sha}" \
        DRY_RUN_REPO_URL="${sanitized_repo_url}" \
        DRY_RUN_PRIVATE_RESULT_SAMPLE_ENABLED="${private_result_sample_enabled}" \
        DRY_RUN_ISSUER_STATUS_EVIDENCE_ENABLED="${issuer_status_evidence_enabled}" \
        DRY_RUN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_EVIDENCE_ENABLED="${trusted_issuer_registry_recognition_evidence_enabled}" \
        DRY_RUN_TRUSTED_RECEIPT_ISSUER_COMPLETION_EVIDENCE_ENABLED="${trusted_receipt_issuer_completion_evidence_enabled}" \
        DRY_RUN_TERMINAL_CHAIN_REFUSAL_EVIDENCE_ENABLED="${terminal_chain_refusal_evidence_enabled}" \
        DRY_RUN_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS_REQUIRED="${terminal_chain_recognition_refusal_groups_required}" \
        DRY_RUN_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUP_CASE_IDS_REQUIRED="${terminal_chain_recognition_refusal_group_case_ids_required}" \
        DRY_RUN_TERMINAL_CHAIN_NESTED_ARTIFACT_TAMPER_REFUSALS_REQUIRED="${terminal_chain_nested_artifact_tamper_refusals_required}" \
        DRY_RUN_TERMINAL_CHAIN_NESTED_ARTIFACT_BINDING_REQUIRED="${terminal_chain_nested_artifact_binding_required}" \
        DRY_RUN_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS_REQUIRED="${terminal_chain_trusted_issuer_registry_recognition_refusals_required}" \
        DRY_RUN_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_REQUIRED="${terminal_chain_deployment_profile_authority_refusal_mirror_required}" \
        DRY_RUN_RELEASE_FORWARD_REPORT_CONTRACT_REQUIRED="${release_forward_report_contract_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_CONTRACT_REQUIRED="${release_forward_product_proof_path_contract_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_TERMINAL_CHAIN_BOUNDARY_REQUIRED="${release_forward_product_proof_path_terminal_chain_boundary_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUP_CASE_IDS_REQUIRED="${release_forward_product_proof_path_terminal_chain_recognition_refusal_group_case_ids_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_TERMINAL_CHAIN_REGISTRY_VERDICT_REQUIRED="${release_forward_product_proof_path_terminal_chain_registry_verdict_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_DOWNSTREAM_REFUSAL_BOUNDARY_REQUIRED="${release_forward_product_proof_path_downstream_refusal_boundary_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_RECOGNIZED_RECEIPT_PATH_MIRROR_REQUIRED="${release_forward_product_proof_path_recognized_receipt_path_mirror_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_REQUIRED="${release_forward_product_proof_path_deployment_profile_authority_bridge_required}" \
        DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_DEPLOYMENT_PROFILE_AUTHORITY_REFUSALS_REQUIRED="${release_forward_product_proof_path_deployment_profile_authority_refusals_required}" \
        DRY_RUN_MANIFEST_PATH="${OUTPUT_DIR}/DRY-RUN-MANIFEST.json" \
        node <<'NODE'
const crypto = require('crypto');
const fs = require('fs');

function fileSha256(path) {
  return crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');
}

function parseSums(path, prefix = '') {
  return fs.readFileSync(path, 'utf8')
    .trim()
    .split(/\n+/)
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^([0-9a-f]{64})  (.+)$/);
      if (!match) {
        throw new Error(`invalid checksum line in ${path}: ${line}`);
      }
      return { path: `${prefix}${match[2]}`, sha256: match[1] };
    });
}

function parseAssertions(path) {
  const lines = fs.readFileSync(path, 'utf8')
    .trim()
    .split(/\n+/)
    .filter(Boolean);
  const passed = [];
  const failed = [];
  for (const line of lines) {
    if (line.startsWith('PASS ')) passed.push(line.slice(5));
    if (line.startsWith('FAIL ')) failed.push(line.slice(5));
  }
  return {
    total: passed.length + failed.length,
    passed: passed.length,
    failed: failed.length,
    passed_names: passed,
    failed_names: failed,
  };
}

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function targetAtLeast(tag, major, minor, patch) {
  const match = String(tag || '').match(/^v(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return false;
  const parts = match.slice(1).map(Number);
  if (parts[0] !== major) return parts[0] > major;
  if (parts[1] !== minor) return parts[1] > minor;
  return parts[2] >= patch;
}

function arraysEqual(left, right) {
  return Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((item, index) => item === right[index]);
}
const expectedDeploymentProfileAuthorityRefusalCaseIds = [
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
];
const deploymentProfileAuthorityBridgeFields = [
  'proof_type',
  'evidence_model',
  'live_probing',
  'deployment_profile_id',
  'deployment_profile_sha256',
  'runtime_profile_sha256',
  'deployment_profile_artifact_authoritative',
  'selected_by_explicit_id_and_sha',
  'selects_latest_profile',
  'preflight_artifact_verified',
  'recognized_receipt_mutates_once',
  'recognized_state_entry_count_delta',
  'required_refusal_case_count',
  'observed_refusal_case_count',
  'all_required_refusals_before_mutation',
  'agent_supplied_authority_refused_before_mutation',
  'direct_api_refused_before_mutation',
  'downstream_refusal_proven',
  'request_stream_authority_material_accepted',
  'current_machine_governance',
  'production_downstream_recognition',
  'production_authority',
  'enterprise_readiness',
  'external_attestation',
  'sovereign_recognition',
  'unrouted_surface_coverage',
];
const deploymentProfileAuthorityBridgeNorthStarFields = [
  'deployment_profile_authority_bridge_required',
  'deployment_profile_authority_bridge_preserved',
  'deployment_profile_authority_bridge_observed',
  'deployment_profile_authority_bridge_proof_type',
  'deployment_profile_authority_bridge_refusal_count',
  'deployment_profile_authority_bridge_current_machine_governance',
  'deployment_profile_authority_bridge_production_authority',
];
const deploymentProfileAuthorityRefusalBridgeFields = [
  'deployment_profile_authority_refusal_case_count',
  'deployment_profile_authority_refusal_case_ids',
  'deployment_profile_authority_refusals_before_service_proof',
  'deployment_profile_authority_refusals_before_mutation',
  'deployment_profile_authority_refusal_service_proof_started',
  'stale_deployment_profile_artifact_refused_before_service_proof',
  'profile_recognition_mismatch_refused_before_service_proof',
  'latest_profile_selection_refused_before_service_proof',
  'request_stream_authority_material_refused_before_service_proof',
];
const deploymentProfileAuthorityRefusalNorthStarFields = [
  'deployment_profile_authority_refusals_required',
  'deployment_profile_authority_refusals_preserved',
  'deployment_profile_authority_refusal_case_count',
  'deployment_profile_authority_refusal_case_ids',
  'deployment_profile_authority_refusals_before_service_proof',
  'deployment_profile_authority_refusals_before_mutation',
  'deployment_profile_authority_refusal_service_proof_started',
  'stale_deployment_profile_artifact_refused_before_service_proof',
  'profile_recognition_mismatch_refused_before_service_proof',
  'latest_profile_selection_refused_before_service_proof',
  'request_stream_authority_material_refused_before_service_proof',
];
const deploymentProfileAuthorityBridgeWithRefusalFields = [
  ...deploymentProfileAuthorityBridgeFields,
  ...deploymentProfileAuthorityRefusalBridgeFields,
];
const deploymentProfileAuthorityNorthStarFields = [
  ...deploymentProfileAuthorityBridgeNorthStarFields,
  ...deploymentProfileAuthorityRefusalNorthStarFields,
];
const deploymentProfileAuthorityNorthStarPrefixes = [
  'deployment_profile_authority_',
  'stale_deployment_profile_artifact_',
  'profile_recognition_mismatch_',
  'latest_profile_selection_',
  'request_stream_authority_material_',
];

const artifactHashes = parseSums('SHA256SUMS', 'ZLAR/');
const runHashes = parseSums('RUN-SHA256SUMS');
const assertions = parseAssertions('ASSERTIONS.txt');

function requireArtifactSha(path) {
  const entry = artifactHashes.find((item) => item.path === path);
  if (!entry) {
    throw new Error(`missing artifact hash for ${path}`);
  }
  return entry.sha256;
}

const productProofPathContractRequired =
  process.env.DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_CONTRACT_REQUIRED === 'true';
const productProofPathTerminalChainBoundaryRequired =
  process.env.DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_TERMINAL_CHAIN_BOUNDARY_REQUIRED ===
  'true';
const productProofPathTerminalChainRecognitionRefusalGroupCaseIdsRequired =
  process.env
    .DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUP_CASE_IDS_REQUIRED ===
  'true';
const productProofPathTerminalChainRegistryVerdictRequired =
  process.env
    .DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_TERMINAL_CHAIN_REGISTRY_VERDICT_REQUIRED ===
  'true';
const productProofPathDownstreamRefusalBoundaryRequired =
  process.env
    .DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_DOWNSTREAM_REFUSAL_BOUNDARY_REQUIRED ===
  'true';
const productProofPathRecognizedReceiptPathMirrorRequired =
  process.env
    .DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_RECOGNIZED_RECEIPT_PATH_MIRROR_REQUIRED ===
  'true';
const productProofPathDeploymentProfileAuthorityBridgeRequired =
  process.env
    .DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_DEPLOYMENT_PROFILE_AUTHORITY_BRIDGE_REQUIRED ===
  'true';
const productProofPathDeploymentProfileAuthorityRefusalsRequired =
  process.env
    .DRY_RUN_RELEASE_FORWARD_PRODUCT_PROOF_PATH_DEPLOYMENT_PROFILE_AUTHORITY_REFUSALS_REQUIRED ===
  'true';
const terminalChainDeploymentProfileAuthorityRefusalMirrorRequired =
  process.env
    .DRY_RUN_TERMINAL_CHAIN_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_MIRROR_REQUIRED ===
  'true';
function productProofPathEvidenceModelAccepted(value) {
  if (productProofPathDeploymentProfileAuthorityBridgeRequired) {
    return value ===
      'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge';
  }
  if (productProofPathTerminalChainBoundaryRequired) {
    return [
      'fresh-local-fixture-proof-pack-and-terminal-chain-artifact-verification',
      'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge',
    ].includes(value);
  }
  return [
    'fresh-local-fixture-proof-pack',
    'fresh-local-fixture-proof-pack-and-terminal-chain-artifact-verification',
    'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge',
  ].includes(value);
}

const terminalChainTrustedRegistryVerdictFields = [
  'trusted_issuer_registry_recognition_verdict',
  'trusted_issuer_registry_recognition_recognized',
  'trusted_issuer_registry_recognition_decision',
  'trusted_issuer_registry_recognition_reason_code',
  'trusted_issuer_registry_recognition_issuer_status',
  'trusted_issuer_registry_recognition_signature_valid',
  'trusted_issuer_registry_recognition_registry_fixture_validated',
  'trusted_issuer_registry_recognition_registry_fixture_evaluated',
  'trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated',
  'trusted_issuer_registry_recognition_registry_evaluation_result_type',
  'trusted_issuer_registry_recognition_registry_trusted_issuer_count',
  'trusted_issuer_registry_recognition_required_audit_event_id_bound',
  'trusted_issuer_registry_recognition_required_detail_hash_bound',
  'trusted_issuer_registry_recognition_registry_contract_evidence',
  'trusted_issuer_registry_recognition_registry_fixture_contract_sha256',
  'trusted_issuer_registry_recognition_registry_public_safe_summary_sha256',
  'trusted_issuer_registry_recognition_receipt_payload_contract_sha256',
];
const terminalChainTrustedRegistryRecognitionFields = [
  'trusted_issuer_registry_recognition_binding_sha256',
  'trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification',
  ...terminalChainTrustedRegistryVerdictFields,
  'trusted_issuer_registry_recognition_refusals_sha256',
  'trusted_issuer_registry_recognition_refusal_hash_matches_binding',
  'trusted_issuer_registry_recognition_refusal_case_count',
  'trusted_issuer_registry_recognition_refusal_case_ids',
  'trusted_issuer_registry_recognition_refusal_reason_codes',
  'trusted_issuer_registry_recognition_refusals_all_refused',
];
const northStarTerminalChainTrustedRegistryVerdictFields =
  terminalChainTrustedRegistryVerdictFields.map((field) => `terminal_chain_${field}`);
const terminalChainRecognizedReceiptPathMirrorFields = [
  'recognized_receipt_path_evidence_sha256',
  'recognized_receipt_path_evidence_artifact_verification_sha256',
  'recognized_receipt_path_evidence_sha256_matches_artifact_verification',
  'recognized_receipt_path_evidence_bound_to_artifact_body',
  'recognized_receipt_path_evidence_source_binding_sha256',
  'recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding',
  'recognized_receipt_path_evidence_verdict',
  'recognized_receipt_path_evidence_recognized',
  'recognized_receipt_path_evidence_receipt_envelope_included',
  'recognized_receipt_path_evidence_registry_public_key_material_included',
  'recognized_receipt_path_evidence_artifact_crypto_reproducible',
  'recognized_receipt_path_evidence_live_state_proven',
  'recognized_receipt_path_evidence_live_issuer_status_proven',
  'recognized_receipt_path_evidence_key_custody_proven',
  'recognized_receipt_path_evidence_revocation_truth_proven',
  'recognized_receipt_path_evidence_production_downstream_recognition_proven',
  'recognized_receipt_path_evidence_public_external_attestation',
  'recognized_receipt_path_evidence_sovereign_recognition',
  'recognized_receipt_path_evidence_current_machine_governance_proven',
];
const northStarTerminalChainRecognizedReceiptPathMirrorFields =
  terminalChainRecognizedReceiptPathMirrorFields.map((field) => `terminal_chain_${field}`);
const expectedDownstreamRefusalReasons = [
  'receipt_missing',
  'receipt_invalid',
  'issuer_not_active',
  'unknown_issuer',
  'outcome_not_boarding',
  'policy_not_recognized',
  'domain_out_of_scope',
  'tool_out_of_scope',
  'audit_event_mismatch',
  'detail_hash_mismatch',
  'receipt_stale',
];
const downstreamRefusalBoundaryFields = [
  'provided',
  'recognized_boarded',
  'recognized_marker_count_delta',
  'final_marker_count',
  'refusal_case_count',
  'all_refusals_unboarded',
  'all_refusal_marker_count_deltas_zero',
  'refusal_reasons',
];
const releaseForwardReportContractClaimBoundaryFields = [
  'creates_public_external_attestation',
  'proves_non_operator_review',
  'proves_live_registry',
  'proves_live_issuer_status',
  'proves_key_custody',
  'proves_revocation_truth',
  'proves_current_machine_governance',
  'proves_live_mcp_coverage',
  'proves_production_downstream_recognition',
  'proves_production_authority',
  'proves_enterprise_readiness',
  'proves_sovereign_recognition',
  'proves_unrouted_surface_coverage',
];
const releaseForwardProductProofPathClaimBoundaryFields = [
  'creates_public_external_attestation',
  'proves_current_machine_governance',
  'proves_all_mcp_governance',
  'proves_unrouted_surface_coverage',
];
const releaseForwardProductProofPathSimulatedHumanAuthorizationFields = [
  'approval_channel',
  'authorized_boarded',
  'denied_boarded',
  'pending_boarded',
];
const releaseForwardProductProofPathReceiptVerifierBoundaryFields = [
  'downstream_recognition_proven',
  'invalid_verdict',
  'unknown_signer_verdict',
  'valid_verdict',
];
const releaseForwardTerminalChainNestedArtifactTamperRefusalFields = [
  'generated_preflight_artifact_type',
  'generated_service_proof_artifact_type',
  'artifact_generated_preflight_artifact_type',
  'artifact_generated_service_proof_artifact_type',
  'forged_inner_preflight_hash_refused',
  'forged_inner_service_hash_refused',
];
const releaseForwardTerminalChainNestedArtifactBindingFields = [
  'generated_preflight_artifact_type',
  'generated_service_proof_artifact_type',
  'generated_preflight_artifact_body_sha256',
  'generated_service_proof_artifact_body_sha256',
  'generated_preflight_artifact_verified',
  'generated_service_proof_artifact_verified',
  'preflight_artifact_hash_bound',
  'service_proof_source_preflight_hash_bound',
  'service_artifact_hash_bound',
  'service_artifact_verification_bound_to_service_proof',
  'creates_public_external_attestation',
  'proves_non_operator_review',
  'proves_current_machine_governance',
  'proves_production_downstream_recognition',
];
const privateVerifierResultSamplePointerFields = [
  'enabled',
  'evidence_model',
  'minimum_target',
  'envelope_path',
  'verification_path',
  'result_file',
  'result_section',
  'hash_record_location',
  'included_in_core_artifact_hashes',
  'circular_hash_avoided',
  'verification_result_section',
  'verification_result_minimum_target',
  'creates_public_external_attestation',
  'proves_non_operator_review',
];

function hasAnyOwn(value, fields) {
  return fields.some((field) => Object.prototype.hasOwnProperty.call(value || {}, field));
}

function hasAnyPrefixedOwn(value, prefix) {
  return Object.keys(value || {}).some((key) => key.startsWith(prefix));
}

function hasExactKeys(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function hasOnlyExpectedPrefixedKeys(value, prefix, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const expected = new Set(fields);
  return Object.keys(value)
    .filter((key) => key.startsWith(prefix))
    .every((key) => expected.has(key));
}

function hasOnlyExpectedRecognizedReceiptPathKeys(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const expected = new Set(fields);
  return Object.keys(value)
    .filter((key) => key.includes('recognized_receipt_path'))
    .every((key) => expected.has(key));
}

function hasAnyRecognizedReceiptPathOwn(value) {
  return Object.keys(value || {}).some((key) => key.includes('recognized_receipt_path'));
}

function hasOnlyExpectedDeploymentProfileAuthorityNorthStarKeys(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const expected = new Set(fields);
  return Object.keys(value)
    .filter((key) =>
      deploymentProfileAuthorityNorthStarPrefixes.some((prefix) =>
        key.startsWith(prefix)
      )
    )
    .every((key) => expected.has(key));
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function downstreamRefusalBoundaryFromProductProofPath(report) {
  return {
    provided: true,
    recognized_boarded: report?.observed?.allow_path?.downstream_recognized_boarded,
    recognized_marker_count_delta:
      report?.observed?.allow_path?.downstream_recognized_marker_count_delta,
    final_marker_count: report?.observed?.allow_path?.downstream_final_marker_count,
    refusal_case_count: report?.observed?.refusal_path?.downstream_refusal_case_count,
    all_refusals_unboarded:
      report?.observed?.refusal_path?.downstream_all_refusals_unboarded,
    all_refusal_marker_count_deltas_zero:
      report?.observed?.refusal_path?.downstream_all_refusal_marker_count_deltas_zero,
    refusal_reasons: report?.observed?.refusal_path?.downstream_refusal_reasons,
  };
}

function downstreamRefusalBoundaryPasses(boundary) {
  return (
    hasExactKeys(boundary, downstreamRefusalBoundaryFields) &&
    boundary?.provided === true &&
    boundary?.recognized_boarded === true &&
    boundary?.recognized_marker_count_delta === 1 &&
    boundary?.final_marker_count === 1 &&
    boundary?.refusal_case_count === expectedDownstreamRefusalReasons.length &&
    boundary?.all_refusals_unboarded === true &&
    boundary?.all_refusal_marker_count_deltas_zero === true &&
    arraysEqual(boundary?.refusal_reasons, expectedDownstreamRefusalReasons)
  );
}

function privateVerifierResultSamplePointerPasses(pointer) {
  const expectedVerificationSection = targetAtLeast(process.env.DRY_RUN_TAG, 3, 4, 34)
    ? 'Private Result Verification Evidence'
    : 'not-required-for-this-target';
  return (
    hasExactKeys(pointer, privateVerifierResultSamplePointerFields) &&
    pointer?.enabled === true &&
    pointer?.evidence_model === 'generated-sample-fixture' &&
    pointer?.minimum_target === 'v3.3.104' &&
    pointer?.envelope_path === 'ZLAR/zlar-private-verifier-result-v1.json' &&
    pointer?.verification_path ===
      'ZLAR/zlar-private-verifier-result-verification-v1.json' &&
    pointer?.result_file === 'DRY-RUN-RESULT.md' &&
    pointer?.result_section === 'Private Verifier Result Intake' &&
    pointer?.hash_record_location ===
      'DRY-RUN-RESULT.md#private-verifier-result-intake' &&
    pointer?.included_in_core_artifact_hashes === false &&
    pointer?.circular_hash_avoided === true &&
    pointer?.verification_result_section === expectedVerificationSection &&
    pointer?.verification_result_minimum_target === 'v3.4.34' &&
    pointer?.creates_public_external_attestation === false &&
    pointer?.proves_non_operator_review === false
  );
}

function terminalChainTrustedRegistryVerdictPasses(boundary) {
  return (
    hasOnlyExpectedPrefixedKeys(
      boundary,
      'trusted_issuer_registry_recognition_',
      terminalChainTrustedRegistryRecognitionFields
    ) &&
    boundary?.trusted_issuer_registry_recognition_verdict === 'RECOGNIZED' &&
    boundary?.trusted_issuer_registry_recognition_recognized === true &&
    boundary?.trusted_issuer_registry_recognition_decision === 'accept' &&
    boundary?.trusted_issuer_registry_recognition_reason_code === 'recognized' &&
    boundary?.trusted_issuer_registry_recognition_issuer_status === 'active' &&
    boundary?.trusted_issuer_registry_recognition_signature_valid === true &&
    boundary?.trusted_issuer_registry_recognition_registry_fixture_validated === true &&
    boundary?.trusted_issuer_registry_recognition_registry_fixture_evaluated === true &&
    boundary?.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated ===
      true &&
    boundary?.trusted_issuer_registry_recognition_registry_evaluation_result_type ===
      'downstream-recognition-rule-v1' &&
    boundary?.trusted_issuer_registry_recognition_registry_trusted_issuer_count === 1 &&
    boundary?.trusted_issuer_registry_recognition_required_audit_event_id_bound === true &&
    boundary?.trusted_issuer_registry_recognition_required_detail_hash_bound === true &&
    (
      !Object.prototype.hasOwnProperty.call(
        boundary || {},
        'trusted_issuer_registry_recognition_registry_contract_evidence'
      ) ||
      boundary?.trusted_issuer_registry_recognition_registry_contract_evidence ===
        'no-secret-registry-contract-v2'
    ) &&
    isSha256Hex(
      boundary?.trusted_issuer_registry_recognition_registry_fixture_contract_sha256
    ) &&
    (
      !Object.prototype.hasOwnProperty.call(
        boundary || {},
        'trusted_issuer_registry_recognition_registry_public_safe_summary_sha256'
      ) ||
      isSha256Hex(
        boundary
          ?.trusted_issuer_registry_recognition_registry_public_safe_summary_sha256
      )
    ) &&
    isSha256Hex(
      boundary?.trusted_issuer_registry_recognition_receipt_payload_contract_sha256
    )
  );
}

function northStarTerminalChainTrustedRegistryVerdictPasses(northStar) {
  return (
    hasOnlyExpectedPrefixedKeys(
      northStar,
      'terminal_chain_trusted_issuer_registry_recognition_',
      northStarTerminalChainTrustedRegistryVerdictFields
    ) &&
    northStar?.terminal_chain_trusted_issuer_registry_recognition_verdict ===
      'RECOGNIZED' &&
    northStar?.terminal_chain_trusted_issuer_registry_recognition_recognized === true &&
    northStar?.terminal_chain_trusted_issuer_registry_recognition_decision ===
      'accept' &&
    northStar?.terminal_chain_trusted_issuer_registry_recognition_reason_code ===
      'recognized' &&
    northStar?.terminal_chain_trusted_issuer_registry_recognition_issuer_status ===
      'active' &&
    northStar?.terminal_chain_trusted_issuer_registry_recognition_signature_valid ===
      true &&
    northStar
      ?.terminal_chain_trusted_issuer_registry_recognition_registry_fixture_validated ===
      true &&
    northStar
      ?.terminal_chain_trusted_issuer_registry_recognition_registry_fixture_evaluated ===
      true &&
    northStar
      ?.terminal_chain_trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated ===
      true &&
    northStar
      ?.terminal_chain_trusted_issuer_registry_recognition_registry_evaluation_result_type ===
      'downstream-recognition-rule-v1' &&
    northStar
      ?.terminal_chain_trusted_issuer_registry_recognition_registry_trusted_issuer_count ===
      1 &&
    northStar
      ?.terminal_chain_trusted_issuer_registry_recognition_required_audit_event_id_bound ===
      true &&
    northStar
      ?.terminal_chain_trusted_issuer_registry_recognition_required_detail_hash_bound ===
      true &&
    (
      !Object.prototype.hasOwnProperty.call(
        northStar || {},
        'terminal_chain_trusted_issuer_registry_recognition_registry_contract_evidence'
      ) ||
      northStar
        ?.terminal_chain_trusted_issuer_registry_recognition_registry_contract_evidence ===
        'no-secret-registry-contract-v2'
    ) &&
    isSha256Hex(
      northStar
        ?.terminal_chain_trusted_issuer_registry_recognition_registry_fixture_contract_sha256
    ) &&
    (
      !Object.prototype.hasOwnProperty.call(
        northStar || {},
        'terminal_chain_trusted_issuer_registry_recognition_registry_public_safe_summary_sha256'
      ) ||
      isSha256Hex(
        northStar
          ?.terminal_chain_trusted_issuer_registry_recognition_registry_public_safe_summary_sha256
      )
    ) &&
    isSha256Hex(
      northStar
        ?.terminal_chain_trusted_issuer_registry_recognition_receipt_payload_contract_sha256
    )
  );
}

function recognizedReceiptPathMirrorPasses(boundary) {
  return (
    hasOnlyExpectedRecognizedReceiptPathKeys(
      boundary,
      terminalChainRecognizedReceiptPathMirrorFields
    ) &&
    isSha256Hex(boundary?.recognized_receipt_path_evidence_sha256) &&
    isSha256Hex(
      boundary?.recognized_receipt_path_evidence_artifact_verification_sha256
    ) &&
    boundary?.recognized_receipt_path_evidence_sha256 ===
      boundary?.recognized_receipt_path_evidence_artifact_verification_sha256 &&
    boundary?.recognized_receipt_path_evidence_sha256_matches_artifact_verification ===
      true &&
    boundary?.recognized_receipt_path_evidence_bound_to_artifact_body === true &&
    isSha256Hex(boundary?.recognized_receipt_path_evidence_source_binding_sha256) &&
    boundary?.recognized_receipt_path_evidence_source_binding_sha256 ===
      boundary?.trusted_issuer_registry_recognition_binding_sha256 &&
    boundary
      ?.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding ===
      true &&
    boundary?.recognized_receipt_path_evidence_verdict === 'RECOGNIZED' &&
    boundary?.recognized_receipt_path_evidence_recognized === true &&
    boundary?.recognized_receipt_path_evidence_receipt_envelope_included === false &&
    boundary?.recognized_receipt_path_evidence_registry_public_key_material_included ===
      false &&
    boundary?.recognized_receipt_path_evidence_artifact_crypto_reproducible ===
      false &&
    boundary?.recognized_receipt_path_evidence_live_state_proven === false &&
    boundary?.recognized_receipt_path_evidence_live_issuer_status_proven ===
      false &&
    boundary?.recognized_receipt_path_evidence_key_custody_proven === false &&
    boundary?.recognized_receipt_path_evidence_revocation_truth_proven === false &&
    boundary?.recognized_receipt_path_evidence_production_downstream_recognition_proven ===
      false &&
    boundary?.recognized_receipt_path_evidence_public_external_attestation ===
      false &&
    boundary?.recognized_receipt_path_evidence_sovereign_recognition === false &&
    boundary?.recognized_receipt_path_evidence_current_machine_governance_proven ===
      false
  );
}

function northStarRecognizedReceiptPathMirrorPasses(northStar, terminalBoundary) {
  return (
    hasOnlyExpectedRecognizedReceiptPathKeys(
      northStar,
      northStarTerminalChainRecognizedReceiptPathMirrorFields
    ) &&
    terminalChainRecognizedReceiptPathMirrorFields.every((field) =>
      JSON.stringify(northStar?.[`terminal_chain_${field}`]) ===
      JSON.stringify(terminalBoundary?.[field])
    )
  );
}

const manifest = {
  result_type: 'zlar-release-forward-verifier-dry-run-result-v1',
  result: 'PASS',
  completed_at_utc: process.env.DRY_RUN_COMPLETED_AT,
  target: {
    release_tag: process.env.DRY_RUN_TAG,
    expected_commit_sha: process.env.DRY_RUN_EXPECTED_SHA,
    observed_commit_sha: process.env.DRY_RUN_OBSERVED_SHA,
    repo_url: process.env.DRY_RUN_REPO_URL,
    source: 'fresh-clone',
    moving_target_selected: false,
  },
  assertions,
  artifact_hashes: artifactHashes,
  run_hashes: runHashes,
  claim_boundary: {
    sends_verifier_request: false,
    contacts_verifier: false,
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_production_deployment: false,
    proves_current_machine_governance: false,
    proves_live_hooks: false,
    proves_live_mcp_coverage: false,
    proves_approval_channel_health: false,
    proves_live_issuer_status: false,
    proves_key_custody: false,
    proves_revocation_truth: false,
    proves_sovereign_recognition: false,
    proves_enterprise_readiness: false,
    proves_unrouted_surface_coverage: false,
  },
  privacy: {
    transcript_sanitized: true,
    raw_mcp_args_included: false,
    env_values_included: false,
    prompt_text_included: false,
    final_client_text_included: false,
    private_paths_included: false,
    credentials_included: false,
    operator_config_values_included: false,
  },
};

if (process.env.DRY_RUN_PRIVATE_RESULT_SAMPLE_ENABLED === 'true') {
  manifest.private_verifier_result_sample = {
    enabled: true,
    evidence_model: 'generated-sample-fixture',
    minimum_target: 'v3.3.104',
    envelope_path: 'ZLAR/zlar-private-verifier-result-v1.json',
    verification_path: 'ZLAR/zlar-private-verifier-result-verification-v1.json',
    result_file: 'DRY-RUN-RESULT.md',
    result_section: 'Private Verifier Result Intake',
    hash_record_location: 'DRY-RUN-RESULT.md#private-verifier-result-intake',
    included_in_core_artifact_hashes: false,
    circular_hash_avoided: true,
    verification_result_section: targetAtLeast(process.env.DRY_RUN_TAG, 3, 4, 34)
      ? 'Private Result Verification Evidence'
      : 'not-required-for-this-target',
    verification_result_minimum_target: 'v3.4.34',
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
  };
}

if (process.env.DRY_RUN_ISSUER_STATUS_EVIDENCE_ENABLED === 'true') {
  const proofPath = 'ZLAR/zlar-issuer-status-proof.json';
  const fixturePath = 'ZLAR/zlar-verifier-kit-issuer-status-fixture.json';
  const diagnosticsPath = 'ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json';
  const proof = readJson(proofPath);
  const fixture = readJson(fixturePath);
  const diagnostics = readJson(diagnosticsPath);
  const fixtureSha = requireArtifactSha(fixturePath);
  const diagnosticsIssuerSha =
    diagnostics.execution_evidence?.issuer_status_json_sha256 || 'not-provided';

  manifest.issuer_status_evidence = {
    enabled: true,
    evidence_model: 'release-forward-local-issuer-status-fixture',
    minimum_target: 'v3.4.33',
    issuer_status_proof_path: proofPath,
    issuer_status_proof_sha256: requireArtifactSha(proofPath),
    verifier_kit_fixture_path: fixturePath,
    verifier_kit_fixture_sha256: fixtureSha,
    external_runner_diagnostics_path: diagnosticsPath,
    external_runner_diagnostics_sha256: requireArtifactSha(diagnosticsPath),
    proof_type: proof.proof_type || '',
    proof_evidence_model: proof.evidence_model || '',
    proof_live_probing: proof.live_probing,
    trust_anchor_model: proof.trust_anchor_model || '',
    action_class: proof.action_class || '',
    active_issuer_boards: proof.issuer_boundary?.active_issuer_boards,
    retired_issuer_refuses: proof.issuer_boundary?.retired_issuer_refuses,
    compromised_issuer_refuses: proof.issuer_boundary?.compromised_issuer_refuses,
    missing_status_issuer_refuses: proof.issuer_boundary?.missing_status_issuer_refuses,
    unknown_issuer_refuses: proof.issuer_boundary?.unknown_issuer_refuses,
    missing_key_issuer_refuses: proof.issuer_boundary?.missing_key_issuer_refuses,
    raw_public_key_material_included: proof.issuer_boundary?.raw_public_key_material_included,
    raw_private_key_material_included: proof.issuer_boundary?.raw_private_key_material_included,
    verifier_kit_fixture_verdict: fixture.verdict || '',
    verifier_kit_fixture_live_probing: fixture.live_probing,
    diagnostics_issuer_artifact_verified:
      diagnostics.execution_evidence?.issuer_status_json_artifact_verified,
    diagnostics_issuer_artifact_sha256: diagnosticsIssuerSha,
    diagnostics_issuer_artifact_sha256_matches_fixture: diagnosticsIssuerSha === fixtureSha,
    safe_claim_ceiling: proof.safe_claim_ceiling || '',
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_live_issuer_status: false,
    proves_key_custody: false,
    proves_revocation_truth: false,
    proves_production_trust_registry: false,
    proves_production_downstream_recognition: false,
  };
}

if (process.env.DRY_RUN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_EVIDENCE_ENABLED === 'true') {
  const recognitionPath = 'ZLAR/zlar-trusted-receipt-issuer-recognition.json';
  const malformedRegistryPath =
    'ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry.json';
  const malformedRegistryErrorPath =
    'ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt';
  const recognition = readJson(recognitionPath);
  const malformedRegistry = readJson(malformedRegistryPath);
  const malformedRegistryError = fs.readFileSync(malformedRegistryErrorPath, 'utf8');
  const malformedRegistryFailClosedBeforeVerdict =
    malformedRegistry.production_authority === true &&
    malformedRegistryError.includes('unsupported field: production_authority') &&
    !/^RECOGNIZED/m.test(malformedRegistryError) &&
    !/^RECOGNITION-REFUSED/m.test(malformedRegistryError);

  manifest.trusted_issuer_registry_recognition_evidence = {
    enabled: true,
    evidence_model: 'release-forward-local-trusted-issuer-registry-fixture',
    minimum_target: 'v3.4.35',
    recognition_path: recognitionPath,
    recognition_sha256: requireArtifactSha(recognitionPath),
    malformed_registry_path: malformedRegistryPath,
    malformed_registry_sha256: requireArtifactSha(malformedRegistryPath),
    malformed_registry_error_path: malformedRegistryErrorPath,
    malformed_registry_error_sha256: requireArtifactSha(malformedRegistryErrorPath),
    registry_type: recognition.registry_type || '',
    registry_evidence_model: recognition.registry_evidence_model || '',
    live_probing: recognition.live_probing,
    requested_scope: recognition.requested_scope || '',
    registry_scope: recognition.registry_scope || '',
    verdict: recognition.verdict || '',
    recognized: recognition.recognized,
    decision: recognition.decision || '',
    reason_code: recognition.reason_code || '',
    receipt_id: recognition.receipt_id || '',
    kid: recognition.kid || '',
    issuer_status: recognition.issuer_status || '',
    signature_valid: recognition.signature_valid,
    safe_claim_ceiling: recognition.safe_claim_ceiling || '',
    non_claims_count: Array.isArray(recognition.non_claims)
      ? recognition.non_claims.length
      : 0,
    malformed_registry_unsupported_field: malformedRegistry.production_authority === true,
    malformed_registry_error_names_unsupported_field:
      malformedRegistryError.includes('unsupported field: production_authority'),
    malformed_registry_fail_closed_before_verdict:
      malformedRegistryFailClosedBeforeVerdict,
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_live_registry: false,
    proves_live_issuer_status: false,
    proves_key_custody: false,
    proves_revocation_truth: false,
    proves_production_trust_registry: false,
    proves_production_downstream_recognition: false,
    proves_production_authority: false,
    proves_sovereign_recognition: false,
  };
}

if (process.env.DRY_RUN_TRUSTED_RECEIPT_ISSUER_COMPLETION_EVIDENCE_ENABLED === 'true') {
  const proofPath = 'ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json';
  const verificationPath =
    'ZLAR/zlar-trusted-receipt-issuer-completion-proof-verification-v1.json';
  const proof = readJson(proofPath);
  const verification = readJson(verificationPath);
  const claimBoundary = verification.claim_boundary || {};
  const claimBoundaryFlagsFalse =
    Object.keys(claimBoundary).length > 0 &&
    Object.values(claimBoundary).every((value) => value === false);

  manifest.trusted_receipt_issuer_completion_evidence = {
    enabled: true,
    evidence_model: 'release-forward-supplied-private-core-completion-proof',
    minimum_target: 'v3.4.53',
    proof_path: proofPath,
    proof_artifact_sha256: fileSha256(proofPath),
    verification_path: verificationPath,
    verification_artifact_sha256: fileSha256(verificationPath),
    proof_type: proof.proof_type || '',
    verification_type: verification.verification_type || '',
    verified: verification.verified,
    proof_body_sha256: verification.proof_sha256 || '',
    selected_surface_id: verification.selected_surface_id || '',
    readiness_selected_terminal_surface_id:
      'protected-records.runtime.profile-installation.records.write',
    proof_selected_surface_can_differ_from_readiness_selected_terminal: true,
    authority_primitive: verification.authority_primitive || '',
    authority_event_type: verification.authority_event_type || '',
    core_sentence: verification.core_sentence || '',
    issuer_kid: verification.issuer_kid || '',
    issuer_public_key_sha256: verification.issuer_public_key_sha256 || '',
    registry_sha256: verification.registry_sha256 || '',
    recognition_contract_sha256: verification.recognition_contract_sha256 || '',
    status_source_sha256: verification.status_source_sha256 || '',
    custody_posture: verification.custody_posture || '',
    custody_posture_sha256: verification.custody_posture_sha256 || '',
    key_state_sha256: verification.key_state_sha256 || '',
    completed_for_selected_surface: verification.completed_for_selected_surface,
    receipt_validity_distinct_from_human_intention:
      verification.receipt_validity_distinct_from_human_intention,
    issuer_recognition_distinct_from_human_yes:
      verification.issuer_recognition_distinct_from_human_yes,
    authority_event_distinct_from_legal_consent:
      verification.authority_event_distinct_from_legal_consent,
    operator_registry_distinct_from_customer_production_trust:
      verification.operator_registry_distinct_from_customer_production_trust,
    software_custody_not_hardware_backed:
      verification.software_custody_not_hardware_backed,
    revocation_status_not_global_certainty:
      verification.revocation_status_not_global_certainty,
    summary_only_evidence_accepted: verification.summary_only_evidence_accepted,
    fixture_only_evidence_accepted: verification.fixture_only_evidence_accepted,
    overclaim_flags_accepted: verification.overclaim_flags_accepted,
    claim_boundary_flags_false: claimBoundaryFlagsFalse,
    not_public_by_default: true,
    source_publication_evidence: false,
    creates_public_external_attestation: false,
    proves_public_external_attestation: false,
    proves_source_publication: false,
    proves_production_issuer_custody: false,
    proves_hardware_custody: false,
    proves_key_custody: false,
    proves_revocation_truth: false,
    proves_live_issuer_status: false,
    proves_production_downstream_recognition: false,
    proves_production_authority: false,
    proves_enterprise_readiness: false,
    proves_current_machine_governance: false,
    proves_real_records_protection: false,
    proves_side_door_closure: false,
    proves_sovereign_recognition: false,
    proves_absolute_human_intention_or_legal_consent: false,
  };
}

if (process.env.DRY_RUN_TERMINAL_CHAIN_REFUSAL_EVIDENCE_ENABLED === 'true') {
  const chain = readJson('ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json');
  const artifact = readJson('ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json');
  const verification = readJson('ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json');
  const namedRefusals = chain.terminal_chain?.named_receipt_refusals || {};
  const recognitionGroups = chain.terminal_chain?.recognition_refusal_groups || {};
  const nestedArtifactTamperRefusalsRequired =
    process.env.DRY_RUN_TERMINAL_CHAIN_NESTED_ARTIFACT_TAMPER_REFUSALS_REQUIRED === 'true';
  const nestedArtifactBindingRequired =
    process.env.DRY_RUN_TERMINAL_CHAIN_NESTED_ARTIFACT_BINDING_REQUIRED === 'true';
  const trustedIssuerRegistryRecognitionRefusalsRequired =
    process.env.DRY_RUN_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS_REQUIRED === 'true';
  const forgedInnerPreflightHashError = fs.existsSync(
    'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt'
  )
    ? fs.readFileSync(
        'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt',
        'utf8'
      )
    : '';
  const forgedInnerServiceHashError = fs.existsSync(
    'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt'
  )
    ? fs.readFileSync(
        'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt',
        'utf8'
      )
    : '';
  const namedKeys = ['missing', 'invalid', 'stale', 'unknown_issuer', 'wrong_policy', 'wrong_domain', 'wrong_tool'];
  const groupKeys = [
    'no_usable_recognized_receipt_authority',
    'recognized_receipt_scope_mismatch',
    'route_or_request_authority_material_refused',
  ];
  const expectedRecognitionRefusalGroupCaseIds = {
    no_usable_recognized_receipt_authority: [
      'missing_receipt_refused_before_runtime_mutation',
      'invalid_receipt_refused_before_runtime_mutation',
      'unknown_issuer_refused_before_runtime_mutation',
      'retired_issuer_refused_before_runtime_mutation',
      'missing_issuer_status_refused_before_runtime_mutation',
      'stale_receipt_refused_before_runtime_mutation',
    ],
    recognized_receipt_scope_mismatch: [
      'wrong_policy_refused_before_runtime_mutation',
      'wrong_domain_refused_before_runtime_mutation',
      'wrong_tool_refused_before_runtime_mutation',
      'wrong_audit_event_refused_before_runtime_mutation',
      'wrong_detail_refused_before_runtime_mutation',
      'non_boarding_outcome_refused_before_runtime_mutation',
    ],
    route_or_request_authority_material_refused: [
      'wrong_runtime_profile_id_refused_before_runtime_mutation',
      'direct_api_without_receipt_refused_before_runtime_mutation',
      'direct_api_with_receipt_refused_before_runtime_mutation',
      'agent_supplied_recognition_rule_refused_before_runtime_mutation',
      'agent_supplied_fixture_mode_refused_before_runtime_mutation',
      'unsupported_request_field_refused_before_runtime_mutation',
    ],
  };
  const recognitionRefusalGroupCaseIds = Object.fromEntries(
    groupKeys.map((key) => [
      key,
      Array.isArray(recognitionGroups[key]?.cases)
        ? recognitionGroups[key].cases.map((item) => item.case_id)
        : [],
    ])
  );
  const trustedIssuerRegistryRecognitionRefusals =
    chain.terminal_chain?.trusted_issuer_registry_recognition_binding
      ?.trusted_issuer_registry_recognition_refusals || {};
  const artifactVerificationTrustedIssuerRegistryRecognitionRefusals =
    verification.trusted_issuer_registry_recognition_binding
      ?.trusted_issuer_registry_recognition_refusals || {};
  const trustedIssuerRegistryRecognitionRefusalCaseIds = Array.isArray(
    trustedIssuerRegistryRecognitionRefusals.cases
  )
    ? trustedIssuerRegistryRecognitionRefusals.cases.map((item) => item.case_id)
    : [];
  const artifactVerificationTrustedIssuerRegistryRecognitionRefusalCaseIds = Array.isArray(
    artifactVerificationTrustedIssuerRegistryRecognitionRefusals.cases
  )
    ? artifactVerificationTrustedIssuerRegistryRecognitionRefusals.cases.map((item) => item.case_id)
    : [];
  const trustedIssuerRegistryRecognitionRefusalReasonCodes = Array.isArray(
    trustedIssuerRegistryRecognitionRefusals.cases
  )
    ? trustedIssuerRegistryRecognitionRefusals.cases.map((item) => item.reason_code)
    : [];
  const artifactVerificationTrustedIssuerRegistryRecognitionRefusalReasonCodes = Array.isArray(
    artifactVerificationTrustedIssuerRegistryRecognitionRefusals.cases
  )
    ? artifactVerificationTrustedIssuerRegistryRecognitionRefusals.cases.map((item) => item.reason_code)
    : [];
  const expectedTrustedIssuerRegistryRecognitionRefusalCaseIds = [
    'unrecognized_terminal_chain_registry_scope_refused',
    'registry_receipt_contract_mismatch_refused',
  ];
  const expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes = [
    'scope_not_found',
    'detail_hash_mismatch',
  ];
  const arraysEqual = (left, right) =>
    Array.isArray(left) &&
    left.length === right.length &&
    left.every((item, index) => item === right[index]);
  const trustedIssuerRegistryRecognitionRefusalsPreserved =
    trustedIssuerRegistryRecognitionRefusalsRequired &&
    trustedIssuerRegistryRecognitionRefusals.case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    artifactVerificationTrustedIssuerRegistryRecognitionRefusals.case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    trustedIssuerRegistryRecognitionRefusals.all_refused === true &&
    artifactVerificationTrustedIssuerRegistryRecognitionRefusals.all_refused === true &&
    arraysEqual(
      trustedIssuerRegistryRecognitionRefusalCaseIds,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      artifactVerificationTrustedIssuerRegistryRecognitionRefusalCaseIds,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      trustedIssuerRegistryRecognitionRefusalReasonCodes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    arraysEqual(
      artifactVerificationTrustedIssuerRegistryRecognitionRefusalReasonCodes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    /^[a-f0-9]{64}$/.test(
      chain.terminal_chain?.trusted_issuer_registry_recognition_binding
        ?.trusted_issuer_registry_recognition_refusals_sha256 || ''
    ) &&
    chain.terminal_chain?.trusted_issuer_registry_recognition_binding
      ?.trusted_issuer_registry_recognition_refusals_sha256 ===
      verification.trusted_issuer_registry_recognition_binding
        ?.trusted_issuer_registry_recognition_refusals_sha256;
  const trustedIssuerRegistryRecognitionRefusalEvidence =
    trustedIssuerRegistryRecognitionRefusalsRequired
      ? {
          trusted_issuer_registry_recognition_refusals_minimum_target: 'v3.4.39',
          trusted_issuer_registry_recognition_refusals_required:
            trustedIssuerRegistryRecognitionRefusalsRequired,
          trusted_issuer_registry_recognition_refusal_case_count:
            trustedIssuerRegistryRecognitionRefusals.case_count || 0,
          artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
            artifactVerificationTrustedIssuerRegistryRecognitionRefusals.case_count || 0,
          trusted_issuer_registry_recognition_refusals_all_refused:
            trustedIssuerRegistryRecognitionRefusals.all_refused === true,
          artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
            artifactVerificationTrustedIssuerRegistryRecognitionRefusals.all_refused === true,
          trusted_issuer_registry_recognition_refusal_case_ids:
            trustedIssuerRegistryRecognitionRefusalCaseIds,
          artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
            artifactVerificationTrustedIssuerRegistryRecognitionRefusalCaseIds,
          trusted_issuer_registry_recognition_refusal_reason_codes:
            trustedIssuerRegistryRecognitionRefusalReasonCodes,
          artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
            artifactVerificationTrustedIssuerRegistryRecognitionRefusalReasonCodes,
          trusted_issuer_registry_recognition_refusals_sha256:
            chain.terminal_chain?.trusted_issuer_registry_recognition_binding
              ?.trusted_issuer_registry_recognition_refusals_sha256 || 'not-provided',
          artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
            verification.trusted_issuer_registry_recognition_binding
              ?.trusted_issuer_registry_recognition_refusals_sha256 || 'not-provided',
          all_trusted_issuer_registry_recognition_refusals_preserved:
            trustedIssuerRegistryRecognitionRefusalsPreserved,
        }
      : {};
  const terminalChainDeploymentProfileAuthorityRefusalMirror =
    chain.terminal_chain?.deployment_profile_authority_refusal_mirror || {};
  const artifactVerificationDeploymentProfileAuthorityRefusalMirror =
    verification.deployment_profile_authority_refusal_mirror || {};
  function deploymentProfileAuthorityRefusalMirrorPasses(mirror) {
    return (
      mirror &&
      mirror.source === 'committed-one-terminal-deployment-profile-fixture' &&
      mirror.source_proof_type ===
        'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
      mirror.evidence_model ===
        'local-fixture-one-terminal-deployment-profile-authority-bridge' &&
      mirror.local_fixture_only === true &&
      mirror.mirrored_from_one_terminal_deployment_profile === true &&
      mirror.source_runtime_profile_sha_matches_terminal_chain === true &&
      mirror.deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      arraysEqual(
        mirror.deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) &&
      mirror.deployment_profile_authority_refusals_before_service_proof === true &&
      mirror.deployment_profile_authority_refusals_before_mutation === true &&
      mirror.deployment_profile_authority_refusal_service_proof_started === false &&
      mirror.stale_deployment_profile_artifact_refused_before_service_proof === true &&
      mirror.profile_recognition_mismatch_refused_before_service_proof === true &&
      mirror.latest_profile_selection_refused_before_service_proof === true &&
      mirror.request_stream_authority_material_refused_before_service_proof === true &&
      mirror.current_machine_governance === false &&
      mirror.production_downstream_recognition === false &&
      mirror.production_authority === false &&
      mirror.enterprise_readiness === false &&
      mirror.external_attestation === false &&
      mirror.sovereign_recognition === false &&
      mirror.unrouted_surface_coverage === false
    );
  }
  const terminalChainDeploymentProfileAuthorityRefusalMirrorPreserved =
    terminalChainDeploymentProfileAuthorityRefusalMirrorRequired &&
    deploymentProfileAuthorityRefusalMirrorPasses(
      terminalChainDeploymentProfileAuthorityRefusalMirror
    ) &&
    deploymentProfileAuthorityRefusalMirrorPasses(
      artifactVerificationDeploymentProfileAuthorityRefusalMirror
    );
  const terminalChainDeploymentProfileAuthorityRefusalMirrorEvidence =
    terminalChainDeploymentProfileAuthorityRefusalMirrorRequired
      ? {
          deployment_profile_authority_refusal_mirror_minimum_target: 'v3.4.50',
          deployment_profile_authority_refusal_mirror_required:
            terminalChainDeploymentProfileAuthorityRefusalMirrorRequired,
          deployment_profile_authority_refusal_mirror_preserved:
            terminalChainDeploymentProfileAuthorityRefusalMirrorPreserved,
          deployment_profile_authority_refusal_case_count:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusal_case_count || 0,
          artifact_verification_deployment_profile_authority_refusal_case_count:
            artifactVerificationDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusal_case_count || 0,
          deployment_profile_authority_refusal_case_ids:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusal_case_ids || [],
          artifact_verification_deployment_profile_authority_refusal_case_ids:
            artifactVerificationDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusal_case_ids || [],
          deployment_profile_authority_refusals_before_service_proof:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusals_before_service_proof === true,
          artifact_verification_deployment_profile_authority_refusals_before_service_proof:
            artifactVerificationDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusals_before_service_proof === true,
          deployment_profile_authority_refusals_before_mutation:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusals_before_mutation === true,
          artifact_verification_deployment_profile_authority_refusals_before_mutation:
            artifactVerificationDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusals_before_mutation === true,
          deployment_profile_authority_refusal_service_proof_started:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusal_service_proof_started === true,
          artifact_verification_deployment_profile_authority_refusal_service_proof_started:
            artifactVerificationDeploymentProfileAuthorityRefusalMirror
              .deployment_profile_authority_refusal_service_proof_started === true,
          stale_deployment_profile_artifact_refused_before_service_proof:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .stale_deployment_profile_artifact_refused_before_service_proof === true,
          profile_recognition_mismatch_refused_before_service_proof:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .profile_recognition_mismatch_refused_before_service_proof === true,
          latest_profile_selection_refused_before_service_proof:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .latest_profile_selection_refused_before_service_proof === true,
          request_stream_authority_material_refused_before_service_proof:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .request_stream_authority_material_refused_before_service_proof === true,
          current_machine_governance:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .current_machine_governance === true,
          production_downstream_recognition:
            terminalChainDeploymentProfileAuthorityRefusalMirror
              .production_downstream_recognition === true,
          production_authority:
            terminalChainDeploymentProfileAuthorityRefusalMirror.production_authority === true,
          enterprise_readiness:
            terminalChainDeploymentProfileAuthorityRefusalMirror.enterprise_readiness === true,
          external_attestation:
            terminalChainDeploymentProfileAuthorityRefusalMirror.external_attestation === true,
          sovereign_recognition:
            terminalChainDeploymentProfileAuthorityRefusalMirror.sovereign_recognition === true,
          unrouted_surface_coverage:
            terminalChainDeploymentProfileAuthorityRefusalMirror.unrouted_surface_coverage === true,
        }
      : {};
  const allRecognitionRefusalGroupCaseIdsPreserved = groupKeys.every((key) => {
    const expected = expectedRecognitionRefusalGroupCaseIds[key];
    const observed = recognitionRefusalGroupCaseIds[key];
    return (
      Array.isArray(observed) &&
      observed.length === expected.length &&
      recognitionGroups[key]?.case_count === expected.length &&
      observed.every((caseId, index) => caseId === expected[index])
    );
  });
  manifest.terminal_chain_refusal_evidence = {
    enabled: true,
    evidence_model: 'release-forward-local-terminal-chain-fixture',
    minimum_target: 'v3.4.22',
    recognition_refusal_groups_minimum_target: 'v3.4.23',
    recognition_refusal_groups_required:
      process.env.DRY_RUN_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS_REQUIRED === 'true',
    recognition_refusal_group_case_ids_minimum_target: 'v3.4.24',
    recognition_refusal_group_case_ids_required:
      process.env.DRY_RUN_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUP_CASE_IDS_REQUIRED === 'true',
    nested_artifact_tamper_refusals_minimum_target: 'v3.4.28',
    nested_artifact_tamper_refusals_required: nestedArtifactTamperRefusalsRequired,
    nested_artifact_binding_minimum_target: 'v3.4.30',
    nested_artifact_binding_required: nestedArtifactBindingRequired,
    chain_path: 'ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json',
    artifact_path: 'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json',
    artifact_verification_path: 'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json',
    refusal_taxonomy_sha256: chain.terminal_chain?.refusal_taxonomy_sha256 || 'not-provided',
    artifact_verification_refusal_taxonomy_sha256: verification.refusal_taxonomy_sha256 || 'not-provided',
    named_receipt_refusals_sha256: chain.terminal_chain?.named_receipt_refusals_sha256 || 'not-provided',
    artifact_verification_named_receipt_refusals_sha256:
      verification.named_receipt_refusals_sha256 || 'not-provided',
    named_receipt_refusals: namedRefusals,
    all_named_receipt_refusals_before_mutation:
      namedKeys.every((key) => namedRefusals[key]?.refused_before_mutation === true),
    recognition_refusal_groups_sha256:
      chain.terminal_chain?.recognition_refusal_groups_sha256 || 'not-provided',
    artifact_verification_recognition_refusal_groups_sha256:
      verification.recognition_refusal_groups_sha256 || 'not-provided',
    recognition_refusal_groups: recognitionGroups,
    recognition_refusal_group_case_ids: recognitionRefusalGroupCaseIds,
    all_recognition_refusal_groups_before_mutation:
      groupKeys.every((key) => recognitionGroups[key]?.all_refused_before_mutation === true),
    all_recognition_refusal_group_case_ids_preserved:
      allRecognitionRefusalGroupCaseIdsPreserved,
    ...trustedIssuerRegistryRecognitionRefusalEvidence,
    ...terminalChainDeploymentProfileAuthorityRefusalMirrorEvidence,
    nested_artifact_tamper_refusals: nestedArtifactTamperRefusalsRequired
      ? {
          generated_preflight_artifact_type:
            chain.nested_artifacts?.generated_preflight_artifact?.artifact_type || 'not-provided',
          generated_service_proof_artifact_type:
            chain.nested_artifacts?.generated_service_proof_artifact?.artifact_type || 'not-provided',
          artifact_generated_preflight_artifact_type:
            artifact.payload?.chain?.nested_artifacts?.generated_preflight_artifact?.artifact_type ||
            'not-provided',
          artifact_generated_service_proof_artifact_type:
            artifact.payload?.chain?.nested_artifacts?.generated_service_proof_artifact?.artifact_type ||
            'not-provided',
          forged_inner_preflight_hash_refused:
            forgedInnerPreflightHashError.includes('nested preflight artifact binding'),
          forged_inner_service_hash_refused:
            forgedInnerServiceHashError.includes('nested service proof artifact binding'),
        }
      : undefined,
    nested_artifact_binding: nestedArtifactBindingRequired
      ? verification.nested_artifact_binding
      : undefined,
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_current_machine_governance: false,
    proves_production_downstream_recognition: false,
  };
}

if (process.env.DRY_RUN_RELEASE_FORWARD_REPORT_CONTRACT_REQUIRED === 'true') {
  const proofSmokePath = 'ZLAR/zlar-proof-smoke-sample-verification.json';
  const northStarPath = 'ZLAR/zlar-north-star-readiness-v1.json';
  const productProofPathPath = 'ZLAR/zlar-product-proof-path-v1.json';
  const smoke = readJson(proofSmokePath);
  const northStar = readJson(northStarPath);
  const productProofPath = productProofPathContractRequired
    ? readJson(productProofPathPath)
    : null;
  const terminalEvidence = manifest.terminal_chain_refusal_evidence || {};
  const productProofPiece =
    northStar.puzzle_pieces?.find((piece) => piece.id === 1) || {};
  const northStarProductProofPath = productProofPiece.observed?.product_proof_path || {};
  const enterpriseProfile =
    northStar.puzzle_pieces?.find((piece) => piece.id === 3)?.observed || {};
  const downstreamRecognition =
    northStar.puzzle_pieces?.find((piece) => piece.id === 5)?.observed || {};
  const groupKeys = [
    'no_usable_recognized_receipt_authority',
    'recognized_receipt_scope_mismatch',
    'route_or_request_authority_material_refused',
  ];
  const expectedRecognitionRefusalGroupCaseIds = {
    no_usable_recognized_receipt_authority: [
      'missing_receipt_refused_before_runtime_mutation',
      'invalid_receipt_refused_before_runtime_mutation',
      'unknown_issuer_refused_before_runtime_mutation',
      'retired_issuer_refused_before_runtime_mutation',
      'missing_issuer_status_refused_before_runtime_mutation',
      'stale_receipt_refused_before_runtime_mutation',
    ],
    recognized_receipt_scope_mismatch: [
      'wrong_policy_refused_before_runtime_mutation',
      'wrong_domain_refused_before_runtime_mutation',
      'wrong_tool_refused_before_runtime_mutation',
      'wrong_audit_event_refused_before_runtime_mutation',
      'wrong_detail_refused_before_runtime_mutation',
      'non_boarding_outcome_refused_before_runtime_mutation',
    ],
    route_or_request_authority_material_refused: [
      'wrong_runtime_profile_id_refused_before_runtime_mutation',
      'direct_api_without_receipt_refused_before_runtime_mutation',
      'direct_api_with_receipt_refused_before_runtime_mutation',
      'agent_supplied_recognition_rule_refused_before_runtime_mutation',
      'agent_supplied_fixture_mode_refused_before_runtime_mutation',
      'unsupported_request_field_refused_before_runtime_mutation',
    ],
  };
  const groupCaseIdsExact = (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }
    return (
      arraysEqual(Object.keys(value).sort(), [...groupKeys].sort()) &&
      groupKeys.every((key) =>
        arraysEqual(value[key], expectedRecognitionRefusalGroupCaseIds[key])
      )
    );
  };
  const expectedTrustedIssuerRegistryRecognitionRefusalCaseIds = [
    'unrecognized_terminal_chain_registry_scope_refused',
    'registry_receipt_contract_mismatch_refused',
  ];
  const expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes = [
    'scope_not_found',
    'detail_hash_mismatch',
  ];
  const proofSmokeGroupCaseIds =
    smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids ||
    {};
  const northStarGroupCaseIds =
    northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids ||
    {};
  const proofSmokeGroupCaseIdsPreserved = groupKeys.every((key) =>
    arraysEqual(proofSmokeGroupCaseIds[key], expectedRecognitionRefusalGroupCaseIds[key])
  );
  const northStarGroupCaseIdsPreserved = groupKeys.every((key) =>
    arraysEqual(northStarGroupCaseIds[key], expectedRecognitionRefusalGroupCaseIds[key])
  );
  const trustedRegistryRefusalsPreserved =
    terminalEvidence.trusted_issuer_registry_recognition_refusals_required === true &&
    terminalEvidence.all_trusted_issuer_registry_recognition_refusals_preserved === true &&
    terminalEvidence.trusted_issuer_registry_recognition_refusal_case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    terminalEvidence.trusted_issuer_registry_recognition_refusals_all_refused === true &&
    terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused ===
      true &&
    arraysEqual(
      terminalEvidence.trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      terminalEvidence.trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    arraysEqual(
      terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    /^[a-f0-9]{64}$/.test(
      terminalEvidence.trusted_issuer_registry_recognition_refusals_sha256 || ''
    ) &&
    terminalEvidence.trusted_issuer_registry_recognition_refusals_sha256 ===
      terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256;
  const proofSmokeTrustedRegistryRefusalsPreserved =
    smoke.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    smoke.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    smoke.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused ===
      true &&
    smoke.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused ===
      true &&
    arraysEqual(
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    arraysEqual(
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    /^[a-f0-9]{64}$/.test(
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 ||
        ''
    ) &&
    smoke.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 ===
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256;
  const northStarTrustedRegistryRefusalsPreserved =
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved ===
      true &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count ===
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused ===
      true &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused ===
      true &&
    arraysEqual(
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    arraysEqual(
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    /^[a-f0-9]{64}$/.test(
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 ||
        ''
    ) &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256 ===
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256;
  const observedTrustedRegistryRefusalsPreserved =
    enterpriseProfile.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved ===
      true &&
    downstreamRecognition.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved ===
      true &&
    arraysEqual(
      enterpriseProfile.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      downstreamRecognition.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) &&
    arraysEqual(
      enterpriseProfile.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) &&
    arraysEqual(
      downstreamRecognition.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    );
  const groupContractSatisfied =
    smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3 &&
    smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count ===
      18 &&
    smoke.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count ===
      3 &&
    smoke.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count ===
      18 &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required === true &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true &&
    northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3 &&
    northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count ===
      18 &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count ===
      3 &&
    northStar.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count ===
      18 &&
    proofSmokeGroupCaseIdsPreserved &&
    northStarGroupCaseIdsPreserved;
  const observedGroupContractSatisfied =
    enterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved ===
      true &&
    enterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3 &&
    enterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count ===
      18 &&
    enterpriseProfile
      .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count ===
      3 &&
    enterpriseProfile
      .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count ===
      18 &&
    downstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved ===
      true &&
    downstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_count ===
      3 &&
    downstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count ===
      18 &&
    downstreamRecognition
      .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count ===
      3 &&
    downstreamRecognition
      .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count ===
      18;
  const productProofPathAcceptanceGateAllTrue =
    productProofPath &&
    Object.values(productProofPath.acceptance_gate || {}).every((value) => value === true);
  const productProofPathForbiddenClaimsAllFalse =
    productProofPath &&
    Object.values(productProofPath.forbidden_claims || {}).every((value) => value === false);
  const productProofPathTerminalChainBoundarySatisfied =
    !productProofPathTerminalChainBoundaryRequired ||
    (
      productProofPath?.acceptance_gate?.terminal_chain_boundary_observed === true &&
      productProofPath?.acceptance_gate?.terminal_chain_artifact_verified === true &&
      productProofPath?.terminal_chain_boundary?.verified === true &&
      productProofPath?.terminal_chain_boundary
        ?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification ===
        true &&
      productProofPath?.terminal_chain_boundary
        ?.trusted_issuer_registry_recognition_refusal_hash_matches_binding === true &&
      productProofPath?.terminal_chain_boundary
        ?.trusted_issuer_registry_recognition_refusals_all_refused === true &&
      productProofPath?.terminal_chain_boundary?.registry_public_key_material_included ===
        false &&
      productProofPath?.terminal_chain_boundary?.receipt_envelope_included === false &&
      productProofPath?.terminal_chain_boundary?.external_attestation === false &&
      productProofPath?.terminal_chain_boundary?.current_machine_governance_proven ===
        false &&
      northStarProductProofPath.terminal_chain_boundary_observed === true &&
      northStarProductProofPath.terminal_chain_artifact_verified === true &&
      northStarProductProofPath.terminal_chain_boundary?.verified === true &&
      northStarProductProofPath.terminal_chain_boundary
        ?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification ===
        true &&
      northStarProductProofPath.terminal_chain_boundary
        ?.trusted_issuer_registry_recognition_refusal_hash_matches_binding === true &&
      northStarProductProofPath.terminal_chain_boundary?.external_attestation === false &&
      northStarProductProofPath.terminal_chain_boundary?.current_machine_governance_proven ===
        false
    );
  const productProofPathTerminalChainRecognitionRefusalGroupCaseIdsSatisfied =
    !productProofPathTerminalChainRecognitionRefusalGroupCaseIdsRequired ||
    (
      productProofPath?.terminal_chain_boundary?.recognition_refusal_group_count ===
        groupKeys.length &&
      productProofPath?.terminal_chain_boundary?.recognition_refusal_group_case_count ===
        18 &&
      productProofPath?.terminal_chain_boundary
        ?.recognition_refusal_group_case_ids_preserved === true &&
      groupCaseIdsExact(
        productProofPath?.terminal_chain_boundary
          ?.recognition_refusal_group_case_ids
      ) &&
      northStarProductProofPath.terminal_chain_boundary
        ?.recognition_refusal_group_count === groupKeys.length &&
      northStarProductProofPath.terminal_chain_boundary
        ?.recognition_refusal_group_case_count === 18 &&
      northStarProductProofPath.terminal_chain_boundary
        ?.recognition_refusal_group_case_ids_preserved === true &&
      groupCaseIdsExact(
        northStarProductProofPath.terminal_chain_boundary
          ?.recognition_refusal_group_case_ids
      )
    );
  const productProofPathTerminalChainRegistryVerdictSatisfied =
    !productProofPathTerminalChainRegistryVerdictRequired ||
    (
      terminalChainTrustedRegistryVerdictPasses(
        productProofPath?.terminal_chain_boundary
      ) &&
      terminalChainTrustedRegistryVerdictPasses(
        northStarProductProofPath.terminal_chain_boundary
      )
    );
  const productProofPathRecognizedReceiptPathMirrorSatisfied =
    !productProofPathRecognizedReceiptPathMirrorRequired ||
    (
      recognizedReceiptPathMirrorPasses(
        productProofPath?.terminal_chain_boundary
      ) &&
      recognizedReceiptPathMirrorPasses(
        northStarProductProofPath.terminal_chain_boundary
      )
    );
  const productProofPathDownstreamRefusalBoundary =
    downstreamRefusalBoundaryFromProductProofPath(productProofPath);
  const productProofPathDownstreamRefusalBoundarySatisfied =
    !productProofPathDownstreamRefusalBoundaryRequired ||
    (
      downstreamRefusalBoundaryPasses(productProofPathDownstreamRefusalBoundary) &&
      downstreamRefusalBoundaryPasses(
        northStarProductProofPath.downstream_refusal_boundary
      )
    );
  function deploymentProfileAuthorityBridgePasses(
    bridge,
    includeAuthorityRefusals = false
  ) {
    return (
      bridge.proof_type ===
        'zlar-protected-records-one-terminal-deployment-profile-proof-v1' &&
      bridge.evidence_model ===
        'local-fixture-one-terminal-deployment-profile-authority-bridge' &&
      bridge.live_probing === false &&
      /^[a-f0-9]{64}$/.test(bridge.deployment_profile_sha256 || '') &&
      /^[a-f0-9]{64}$/.test(bridge.runtime_profile_sha256 || '') &&
      bridge.deployment_profile_artifact_authoritative === true &&
      bridge.selected_by_explicit_id_and_sha === true &&
      bridge.selects_latest_profile === false &&
      bridge.preflight_artifact_verified === true &&
      bridge.recognized_receipt_mutates_once === true &&
      bridge.recognized_state_entry_count_delta === 1 &&
      bridge.required_refusal_case_count === 18 &&
      bridge.observed_refusal_case_count === 18 &&
      bridge.all_required_refusals_before_mutation === true &&
      bridge.agent_supplied_authority_refused_before_mutation === true &&
      bridge.direct_api_refused_before_mutation === true &&
      bridge.downstream_refusal_proven === true &&
      bridge.request_stream_authority_material_accepted === false &&
      bridge.current_machine_governance === false &&
      bridge.production_downstream_recognition === false &&
      bridge.production_authority === false &&
      bridge.enterprise_readiness === false &&
      bridge.external_attestation === false &&
      bridge.sovereign_recognition === false &&
      bridge.unrouted_surface_coverage === false
    );
  }
  function deploymentProfileAuthorityRefusalsPasses(bridge) {
    return (
      bridge &&
      bridge.deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      arraysEqual(
        bridge.deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds,
      ) &&
      bridge.deployment_profile_authority_refusals_before_service_proof === true &&
      bridge.deployment_profile_authority_refusals_before_mutation === true &&
      bridge.deployment_profile_authority_refusal_service_proof_started === false &&
      bridge.stale_deployment_profile_artifact_refused_before_service_proof === true &&
      bridge.profile_recognition_mismatch_refused_before_service_proof === true &&
      bridge.latest_profile_selection_refused_before_service_proof === true &&
      bridge.request_stream_authority_material_refused_before_service_proof === true
    );
  }
  const productProofPathDeploymentProfileAuthorityBridgeSatisfied =
    !productProofPathDeploymentProfileAuthorityBridgeRequired ||
    (
      productProofPath?.acceptance_gate
        ?.deployment_profile_authority_bridge_observed === true &&
      deploymentProfileAuthorityBridgePasses(
        productProofPath?.deployment_profile_authority_bridge,
        productProofPathDeploymentProfileAuthorityRefusalsRequired
      ) &&
      northStar.counts
        ?.product_proof_path_deployment_profile_authority_bridge_required === true &&
      northStar.counts
        ?.product_proof_path_deployment_profile_authority_bridge_preserved === true &&
      northStarProductProofPath.deployment_profile_authority_bridge_observed === true &&
      deploymentProfileAuthorityBridgePasses(
        northStarProductProofPath.deployment_profile_authority_bridge,
        productProofPathDeploymentProfileAuthorityRefusalsRequired
      )
    );
  const productProofPathDeploymentProfileAuthorityRefusalsSatisfied =
    !productProofPathDeploymentProfileAuthorityRefusalsRequired ||
    (
      productProofPathDeploymentProfileAuthorityBridgeSatisfied &&
      deploymentProfileAuthorityRefusalsPasses(
        productProofPath?.deployment_profile_authority_bridge
      ) &&
      northStar.counts
        ?.product_proof_path_deployment_profile_authority_refusals_required === true &&
      northStar.counts
        ?.product_proof_path_deployment_profile_authority_refusals_preserved === true &&
      deploymentProfileAuthorityRefusalsPasses(
        northStarProductProofPath.deployment_profile_authority_bridge
      )
    );
  const terminalChainDeploymentProfileAuthorityRefusalMirrorSatisfied =
    !terminalChainDeploymentProfileAuthorityRefusalMirrorRequired ||
    (
      terminalEvidence.deployment_profile_authority_refusal_mirror_minimum_target ===
        'v3.4.50' &&
      terminalEvidence.deployment_profile_authority_refusal_mirror_required === true &&
      terminalEvidence.deployment_profile_authority_refusal_mirror_preserved === true &&
      terminalEvidence.deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      terminalEvidence.artifact_verification_deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      arraysEqual(
        terminalEvidence.deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) &&
      arraysEqual(
        terminalEvidence.artifact_verification_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) &&
      terminalEvidence.deployment_profile_authority_refusals_before_service_proof === true &&
      terminalEvidence.artifact_verification_deployment_profile_authority_refusals_before_service_proof === true &&
      terminalEvidence.deployment_profile_authority_refusals_before_mutation === true &&
      terminalEvidence.artifact_verification_deployment_profile_authority_refusals_before_mutation === true &&
      terminalEvidence.deployment_profile_authority_refusal_service_proof_started === false &&
      terminalEvidence.artifact_verification_deployment_profile_authority_refusal_service_proof_started === false &&
      terminalEvidence.stale_deployment_profile_artifact_refused_before_service_proof === true &&
      terminalEvidence.profile_recognition_mismatch_refused_before_service_proof === true &&
      terminalEvidence.latest_profile_selection_refused_before_service_proof === true &&
      terminalEvidence.request_stream_authority_material_refused_before_service_proof === true &&
      terminalEvidence.current_machine_governance === false &&
      terminalEvidence.production_downstream_recognition === false &&
      terminalEvidence.production_authority === false &&
      terminalEvidence.enterprise_readiness === false &&
      terminalEvidence.external_attestation === false &&
      terminalEvidence.sovereign_recognition === false &&
      terminalEvidence.unrouted_surface_coverage === false &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      arraysEqual(
        smoke.counts
          ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) &&
      arraysEqual(
        smoke.counts
          ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation ===
        true &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started ===
        false &&
      smoke.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started ===
        false &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required ===
        true &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved ===
        true &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count ===
        expectedDeploymentProfileAuthorityRefusalCaseIds.length &&
      arraysEqual(
        northStar.counts
          ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) &&
      arraysEqual(
        northStar.counts
          ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof ===
        true &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof ===
        true &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation ===
        true &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation ===
        true &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started ===
        false &&
      northStar.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started ===
        false
    );
  const productProofPathContractSatisfied =
    !productProofPathContractRequired ||
    (
      productProofPath?.report_type === 'zlar-product-proof-path-v1' &&
      productProofPath?.result === 'PASS' &&
      productProofPath?.north_star_piece === 'Product Proof Path' &&
      productProofPathEvidenceModelAccepted(productProofPath?.evidence_model) &&
      productProofPath?.live_probing === false &&
      productProofPath?.private_operator_state_required === false &&
      productProofPath?.proof_pack?.verified === true &&
      /^[a-f0-9]{64}$/.test(productProofPath?.proof_pack?.body_sha256 || '') &&
      productProofPathAcceptanceGateAllTrue &&
      productProofPathForbiddenClaimsAllFalse &&
      productProofPathTerminalChainBoundarySatisfied &&
      productProofPathTerminalChainRecognitionRefusalGroupCaseIdsSatisfied &&
      productProofPathTerminalChainRegistryVerdictSatisfied &&
      productProofPathRecognizedReceiptPathMirrorSatisfied &&
      productProofPathDownstreamRefusalBoundarySatisfied &&
      productProofPathDeploymentProfileAuthorityBridgeSatisfied &&
      productProofPathDeploymentProfileAuthorityRefusalsSatisfied &&
      productProofPath?.observed?.simulated_human_authorization?.approval_channel ===
        'simulated-human-fixture' &&
      productProofPath?.observed?.simulated_human_authorization?.authorized_boarded === true &&
      productProofPath?.observed?.simulated_human_authorization?.pending_boarded === false &&
      productProofPath?.observed?.simulated_human_authorization?.denied_boarded === false &&
      productProofPath?.observed?.receipt_verifier_boundary?.valid_verdict === 'VALID' &&
      productProofPath?.observed?.receipt_verifier_boundary?.unknown_signer_verdict ===
        'UNKNOWN-SIGNER' &&
      productProofPath?.observed?.receipt_verifier_boundary?.invalid_verdict === 'INVALID' &&
      productProofPath?.observed?.receipt_verifier_boundary?.downstream_recognition_proven === false &&
      (productProofPath?.observed?.known_ungoverned_boundaries || []).includes(
        'unrouted_records_paths'
      ) &&
      northStar.counts?.product_proof_path_verified === true &&
      (northStar.artifacts_consumed || []).includes('zlar-product-proof-path-v1.json') &&
      productProofPiece.acceptance_gate_scope === 'fresh-local-product-proof-path' &&
      northStarProductProofPath.provided === true &&
      northStarProductProofPath.live_probing === false &&
      northStarProductProofPath.forbidden_claims_false === true
    );
  const claimBoundary = {
    creates_public_external_attestation: false,
    proves_non_operator_review: false,
    proves_live_registry: false,
    proves_live_issuer_status: false,
    proves_key_custody: false,
    proves_revocation_truth: false,
    proves_current_machine_governance: false,
    proves_live_mcp_coverage: false,
    proves_production_downstream_recognition: false,
    proves_production_authority: false,
    proves_enterprise_readiness: false,
    proves_sovereign_recognition: false,
    proves_unrouted_surface_coverage: false,
  };
  const reportContractSatisfactionChecks = [
    ['group_contract', groupContractSatisfied],
    ['observed_group_contract', observedGroupContractSatisfied],
    ['trusted_registry_refusals', trustedRegistryRefusalsPreserved],
    ['proof_smoke_trusted_registry_refusals', proofSmokeTrustedRegistryRefusalsPreserved],
    ['north_star_trusted_registry_refusals', northStarTrustedRegistryRefusalsPreserved],
    ['observed_trusted_registry_refusals', observedTrustedRegistryRefusalsPreserved],
    ['product_proof_path_contract', productProofPathContractSatisfied],
    [
      'terminal_chain_deployment_profile_authority_refusal_mirror',
      terminalChainDeploymentProfileAuthorityRefusalMirrorSatisfied,
    ],
    [
      'claim_boundary_all_false',
      Object.values(claimBoundary).every((value) => value === false),
    ],
  ];
  const reportContractSatisfied = reportContractSatisfactionChecks.every(
    ([, passed]) => passed
  );

  manifest.release_forward_report_contract = {
    enabled: true,
    contract_type: 'zlar-release-forward-dry-run-report-contract-v1',
    evidence_model: 'release-forward-dry-run-artifacts',
    minimum_target: 'v3.4.41',
    report_contract_satisfied: reportContractSatisfied,
    manifest_is_canonical: true,
    result_file: 'DRY-RUN-RESULT.md',
    result_lines_prefix: 'manifest.release_forward_report_contract',
    source_artifacts: {
      proof_smoke_sample_verification_path: proofSmokePath,
      proof_smoke_sample_verification_sha256: requireArtifactSha(proofSmokePath),
      north_star_readiness_path: northStarPath,
      north_star_readiness_sha256: requireArtifactSha(northStarPath),
      ...(productProofPathContractRequired
        ? {
            product_proof_path_path: productProofPathPath,
            product_proof_path_sha256: requireArtifactSha(productProofPathPath),
          }
        : {}),
      terminal_chain_refusal_evidence_source:
        'DRY-RUN-MANIFEST.json#terminal_chain_refusal_evidence',
      terminal_chain_refusal_evidence_included_in_same_manifest: true,
    },
    ...(productProofPathContractRequired
      ? {
          product_proof_path: {
            minimum_target: 'v3.4.42',
            source: productProofPathPath,
            report_type: productProofPath.report_type,
            result: productProofPath.result,
            north_star_piece: productProofPath.north_star_piece,
            evidence_model: productProofPath.evidence_model,
            live_probing: productProofPath.live_probing,
            private_operator_state_required:
              productProofPath.private_operator_state_required,
            proof_pack_verified: productProofPath.proof_pack?.verified,
            proof_pack_body_sha256: productProofPath.proof_pack?.body_sha256,
            proof_pack_component_count: productProofPath.proof_pack?.component_count,
            acceptance_gate_all_true: productProofPathAcceptanceGateAllTrue,
            forbidden_claims_all_false: productProofPathForbiddenClaimsAllFalse,
            ...(productProofPathTerminalChainBoundaryRequired
              ? {
                  terminal_chain_boundary: {
                    verified: productProofPath.terminal_chain_boundary?.verified,
                    artifact_type: productProofPath.terminal_chain_boundary?.artifact_type,
                    payload_type: productProofPath.terminal_chain_boundary?.payload_type,
                    evidence_model: productProofPath.terminal_chain_boundary?.evidence_model,
                    live_probing: productProofPath.terminal_chain_boundary?.live_probing,
                    body_sha256: productProofPath.terminal_chain_boundary?.body_sha256,
                    generated_installed_root_preflighted:
                      productProofPath.terminal_chain_boundary
                        ?.generated_installed_root_preflighted,
                    generated_preflight_artifact_consumed_by_service_proof:
                      productProofPath.terminal_chain_boundary
                        ?.generated_preflight_artifact_consumed_by_service_proof,
                    generated_service_proof_artifact_verified:
                      productProofPath.terminal_chain_boundary
                        ?.generated_service_proof_artifact_verified,
                    recognized_write_boarded:
                      productProofPath.terminal_chain_boundary?.recognized_write_boarded,
                    all_required_refusals_before_mutation:
                      productProofPath.terminal_chain_boundary
                        ?.all_required_refusals_before_mutation,
                    required_refusal_case_count:
                      productProofPath.terminal_chain_boundary?.required_refusal_case_count,
                    observed_refusal_case_count:
                      productProofPath.terminal_chain_boundary?.observed_refusal_case_count,
                    recognition_contract_sha256:
                      productProofPath.terminal_chain_boundary?.recognition_contract_sha256,
                    refusal_taxonomy_sha256:
                      productProofPath.terminal_chain_boundary?.refusal_taxonomy_sha256,
                    named_receipt_refusals_sha256:
                      productProofPath.terminal_chain_boundary?.named_receipt_refusals_sha256,
                    recognition_refusal_groups_sha256:
                      productProofPath.terminal_chain_boundary?.recognition_refusal_groups_sha256,
                    ...(productProofPathTerminalChainRecognitionRefusalGroupCaseIdsRequired
                      ? {
                          recognition_refusal_group_count:
                            productProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_count,
                          recognition_refusal_group_case_count:
                            productProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_case_count,
                          recognition_refusal_group_case_ids:
                            productProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_case_ids,
                          recognition_refusal_group_case_ids_preserved:
                            productProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_case_ids_preserved,
                        }
                      : {}),
                    trusted_issuer_registry_recognition_binding_sha256:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_binding_sha256,
                    trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification,
                    ...(productProofPathTerminalChainRegistryVerdictRequired
                      ? {
                          trusted_issuer_registry_recognition_verdict:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_verdict,
                          trusted_issuer_registry_recognition_recognized:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_recognized,
                          trusted_issuer_registry_recognition_decision:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_decision,
                          trusted_issuer_registry_recognition_reason_code:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_reason_code,
                          trusted_issuer_registry_recognition_issuer_status:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_issuer_status,
                          trusted_issuer_registry_recognition_signature_valid:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_signature_valid,
                          trusted_issuer_registry_recognition_registry_fixture_validated:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_fixture_validated,
                          trusted_issuer_registry_recognition_registry_fixture_evaluated:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_fixture_evaluated,
                          trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated,
                          trusted_issuer_registry_recognition_registry_evaluation_result_type:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_evaluation_result_type,
                          trusted_issuer_registry_recognition_registry_trusted_issuer_count:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_trusted_issuer_count,
                          trusted_issuer_registry_recognition_required_audit_event_id_bound:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_required_audit_event_id_bound,
                          trusted_issuer_registry_recognition_required_detail_hash_bound:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_required_detail_hash_bound,
                          trusted_issuer_registry_recognition_registry_fixture_contract_sha256:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_fixture_contract_sha256,
                          trusted_issuer_registry_recognition_receipt_payload_contract_sha256:
                            productProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_receipt_payload_contract_sha256,
                        }
                      : {}),
                    ...(productProofPathRecognizedReceiptPathMirrorRequired
                      ? {
                          recognized_receipt_path_evidence_sha256:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_sha256,
                          recognized_receipt_path_evidence_artifact_verification_sha256:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_artifact_verification_sha256,
                          recognized_receipt_path_evidence_sha256_matches_artifact_verification:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_sha256_matches_artifact_verification,
                          recognized_receipt_path_evidence_bound_to_artifact_body:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_bound_to_artifact_body,
                          recognized_receipt_path_evidence_source_binding_sha256:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_source_binding_sha256,
                          recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding,
                          recognized_receipt_path_evidence_verdict:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_verdict,
                          recognized_receipt_path_evidence_recognized:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_recognized,
                          recognized_receipt_path_evidence_receipt_envelope_included:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_receipt_envelope_included,
                          recognized_receipt_path_evidence_registry_public_key_material_included:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_registry_public_key_material_included,
                          recognized_receipt_path_evidence_artifact_crypto_reproducible:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_artifact_crypto_reproducible,
                          recognized_receipt_path_evidence_live_state_proven:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_live_state_proven,
                          recognized_receipt_path_evidence_live_issuer_status_proven:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_live_issuer_status_proven,
                          recognized_receipt_path_evidence_key_custody_proven:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_key_custody_proven,
                          recognized_receipt_path_evidence_revocation_truth_proven:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_revocation_truth_proven,
                          recognized_receipt_path_evidence_production_downstream_recognition_proven:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_production_downstream_recognition_proven,
                          recognized_receipt_path_evidence_public_external_attestation:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_public_external_attestation,
                          recognized_receipt_path_evidence_sovereign_recognition:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_sovereign_recognition,
                          recognized_receipt_path_evidence_current_machine_governance_proven:
                            productProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_current_machine_governance_proven,
                        }
                      : {}),
                    trusted_issuer_registry_recognition_refusals_sha256:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_refusals_sha256,
                    trusted_issuer_registry_recognition_refusal_hash_matches_binding:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_refusal_hash_matches_binding,
                    trusted_issuer_registry_recognition_refusal_case_count:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_refusal_case_count,
                    trusted_issuer_registry_recognition_refusal_case_ids:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_refusal_case_ids,
                    trusted_issuer_registry_recognition_refusal_reason_codes:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_refusal_reason_codes,
                    trusted_issuer_registry_recognition_refusals_all_refused:
                      productProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_refusals_all_refused,
                    registry_receipt_contract_hash_bound:
                      productProofPath.terminal_chain_boundary
                        ?.registry_receipt_contract_hash_bound,
                    selected_profile_hash_bound:
                      productProofPath.terminal_chain_boundary?.selected_profile_hash_bound,
                    recognition_contract_hash_bound:
                      productProofPath.terminal_chain_boundary?.recognition_contract_hash_bound,
                    terminal_chain_decision_bound:
                      productProofPath.terminal_chain_boundary?.terminal_chain_decision_bound,
                    nested_artifact_binding_preserved:
                      productProofPath.terminal_chain_boundary?.nested_artifact_binding
                        ?.preflight_artifact_hash_bound === true &&
                      productProofPath.terminal_chain_boundary?.nested_artifact_binding
                        ?.service_proof_source_preflight_hash_bound === true &&
                      productProofPath.terminal_chain_boundary?.nested_artifact_binding
                        ?.service_artifact_hash_bound === true &&
                      productProofPath.terminal_chain_boundary?.nested_artifact_binding
                        ?.service_artifact_verification_bound_to_service_proof === true,
                    registry_public_key_material_included:
                      productProofPath.terminal_chain_boundary
                        ?.registry_public_key_material_included,
                    receipt_envelope_included:
                      productProofPath.terminal_chain_boundary?.receipt_envelope_included,
                    cryptographic_evidence_reproducible_from_artifact:
                      productProofPath.terminal_chain_boundary
                        ?.cryptographic_evidence_reproducible_from_artifact,
                    current_machine_governance_proven:
                      productProofPath.terminal_chain_boundary
                        ?.current_machine_governance_proven,
                    production_downstream_recognition:
                      productProofPath.terminal_chain_boundary
                        ?.production_downstream_recognition,
                    external_attestation:
                      productProofPath.terminal_chain_boundary?.external_attestation,
                    sovereign_recognition:
                      productProofPath.terminal_chain_boundary?.sovereign_recognition,
                    unrouted_records_paths_checked:
                      productProofPath.terminal_chain_boundary
                        ?.unrouted_records_paths_checked,
                  },
                }
              : {}),
            ...(productProofPathDeploymentProfileAuthorityBridgeRequired
              ? {
                  deployment_profile_authority_bridge: {
                    proof_type:
                      productProofPath.deployment_profile_authority_bridge?.proof_type,
                    evidence_model:
                      productProofPath.deployment_profile_authority_bridge?.evidence_model,
                    live_probing:
                      productProofPath.deployment_profile_authority_bridge?.live_probing,
                    deployment_profile_id:
                      productProofPath.deployment_profile_authority_bridge
                        ?.deployment_profile_id,
                    deployment_profile_sha256:
                      productProofPath.deployment_profile_authority_bridge
                        ?.deployment_profile_sha256,
                    runtime_profile_sha256:
                      productProofPath.deployment_profile_authority_bridge
                        ?.runtime_profile_sha256,
	                    deployment_profile_artifact_authoritative:
	                      productProofPath.deployment_profile_authority_bridge
	                        ?.deployment_profile_artifact_authoritative,
	                    ...(productProofPathDeploymentProfileAuthorityRefusalsRequired
	                      ? {
	                          deployment_profile_authority_refusal_case_count:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusal_case_count,
	                          deployment_profile_authority_refusal_case_ids:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusal_case_ids,
	                          deployment_profile_authority_refusals_before_service_proof:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusals_before_service_proof,
	                          deployment_profile_authority_refusals_before_mutation:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusals_before_mutation,
	                          deployment_profile_authority_refusal_service_proof_started:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusal_service_proof_started,
	                          stale_deployment_profile_artifact_refused_before_service_proof:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.stale_deployment_profile_artifact_refused_before_service_proof,
	                          profile_recognition_mismatch_refused_before_service_proof:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.profile_recognition_mismatch_refused_before_service_proof,
	                          latest_profile_selection_refused_before_service_proof:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.latest_profile_selection_refused_before_service_proof,
	                          request_stream_authority_material_refused_before_service_proof:
	                            productProofPath.deployment_profile_authority_bridge
	                              ?.request_stream_authority_material_refused_before_service_proof,
	                        }
	                      : {}),
	                    selected_by_explicit_id_and_sha:
	                      productProofPath.deployment_profile_authority_bridge
	                        ?.selected_by_explicit_id_and_sha,
                    selects_latest_profile:
                      productProofPath.deployment_profile_authority_bridge
                        ?.selects_latest_profile,
                    preflight_artifact_verified:
                      productProofPath.deployment_profile_authority_bridge
                        ?.preflight_artifact_verified,
                    recognized_receipt_mutates_once:
                      productProofPath.deployment_profile_authority_bridge
                        ?.recognized_receipt_mutates_once,
                    recognized_state_entry_count_delta:
                      productProofPath.deployment_profile_authority_bridge
                        ?.recognized_state_entry_count_delta,
                    required_refusal_case_count:
                      productProofPath.deployment_profile_authority_bridge
                        ?.required_refusal_case_count,
                    observed_refusal_case_count:
                      productProofPath.deployment_profile_authority_bridge
                        ?.observed_refusal_case_count,
                    all_required_refusals_before_mutation:
                      productProofPath.deployment_profile_authority_bridge
                        ?.all_required_refusals_before_mutation,
                    agent_supplied_authority_refused_before_mutation:
                      productProofPath.deployment_profile_authority_bridge
                        ?.agent_supplied_authority_refused_before_mutation,
                    direct_api_refused_before_mutation:
                      productProofPath.deployment_profile_authority_bridge
                        ?.direct_api_refused_before_mutation,
                    downstream_refusal_proven:
                      productProofPath.deployment_profile_authority_bridge
                        ?.downstream_refusal_proven,
                    request_stream_authority_material_accepted:
                      productProofPath.deployment_profile_authority_bridge
                        ?.request_stream_authority_material_accepted,
                    current_machine_governance:
                      productProofPath.deployment_profile_authority_bridge
                        ?.current_machine_governance,
                    production_downstream_recognition:
                      productProofPath.deployment_profile_authority_bridge
                        ?.production_downstream_recognition,
                    production_authority:
                      productProofPath.deployment_profile_authority_bridge
                        ?.production_authority,
                    enterprise_readiness:
                      productProofPath.deployment_profile_authority_bridge
                        ?.enterprise_readiness,
                    external_attestation:
                      productProofPath.deployment_profile_authority_bridge
                        ?.external_attestation,
                    sovereign_recognition:
                      productProofPath.deployment_profile_authority_bridge
                        ?.sovereign_recognition,
                    unrouted_surface_coverage:
                      productProofPath.deployment_profile_authority_bridge
                        ?.unrouted_surface_coverage,
                  },
                }
              : {}),
            simulated_human_authorization: {
              approval_channel:
                productProofPath.observed?.simulated_human_authorization?.approval_channel,
              authorized_boarded:
                productProofPath.observed?.simulated_human_authorization?.authorized_boarded,
              pending_boarded:
                productProofPath.observed?.simulated_human_authorization?.pending_boarded,
              denied_boarded:
                productProofPath.observed?.simulated_human_authorization?.denied_boarded,
            },
            receipt_verifier_boundary: {
              valid_verdict:
                productProofPath.observed?.receipt_verifier_boundary?.valid_verdict,
              unknown_signer_verdict:
                productProofPath.observed?.receipt_verifier_boundary?.unknown_signer_verdict,
              invalid_verdict:
                productProofPath.observed?.receipt_verifier_boundary?.invalid_verdict,
              downstream_recognition_proven:
                productProofPath.observed?.receipt_verifier_boundary?.downstream_recognition_proven,
            },
            ...(productProofPathDownstreamRefusalBoundaryRequired
              ? {
                  downstream_refusal_boundary:
                    productProofPathDownstreamRefusalBoundary,
                }
              : {}),
            north_star: {
              product_proof_path_verified:
                northStar.counts?.product_proof_path_verified,
              artifact_consumed: (northStar.artifacts_consumed || []).includes(
                'zlar-product-proof-path-v1.json'
              ),
              puzzle_piece_provided: northStarProductProofPath.provided,
              acceptance_gate_scope: productProofPiece.acceptance_gate_scope,
              live_probing: northStarProductProofPath.live_probing,
              forbidden_claims_false: northStarProductProofPath.forbidden_claims_false,
              ...(productProofPathDownstreamRefusalBoundaryRequired
                ? {
                    downstream_refusal_boundary:
                      northStarProductProofPath.downstream_refusal_boundary,
                  }
                : {}),
              ...(productProofPathTerminalChainBoundaryRequired
                ? {
                    terminal_chain_boundary_observed:
                      northStarProductProofPath.terminal_chain_boundary_observed,
                    terminal_chain_artifact_verified:
                      northStarProductProofPath.terminal_chain_artifact_verified,
                    terminal_chain_boundary_verified:
                      northStarProductProofPath.terminal_chain_boundary?.verified,
                    terminal_chain_binding_matches_artifact_verification:
                      northStarProductProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification,
                    terminal_chain_refusal_hash_matches_binding:
                      northStarProductProofPath.terminal_chain_boundary
                        ?.trusted_issuer_registry_recognition_refusal_hash_matches_binding,
                    ...(productProofPathTerminalChainRegistryVerdictRequired
                      ? {
                          terminal_chain_trusted_issuer_registry_recognition_verdict:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_verdict,
                          terminal_chain_trusted_issuer_registry_recognition_recognized:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_recognized,
                          terminal_chain_trusted_issuer_registry_recognition_decision:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_decision,
                          terminal_chain_trusted_issuer_registry_recognition_reason_code:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_reason_code,
                          terminal_chain_trusted_issuer_registry_recognition_issuer_status:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_issuer_status,
                          terminal_chain_trusted_issuer_registry_recognition_signature_valid:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_signature_valid,
                          terminal_chain_trusted_issuer_registry_recognition_registry_fixture_validated:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_fixture_validated,
                          terminal_chain_trusted_issuer_registry_recognition_registry_fixture_evaluated:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_fixture_evaluated,
                          terminal_chain_trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated,
                          terminal_chain_trusted_issuer_registry_recognition_registry_evaluation_result_type:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_evaluation_result_type,
                          terminal_chain_trusted_issuer_registry_recognition_registry_trusted_issuer_count:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_trusted_issuer_count,
                          terminal_chain_trusted_issuer_registry_recognition_required_audit_event_id_bound:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_required_audit_event_id_bound,
                          terminal_chain_trusted_issuer_registry_recognition_required_detail_hash_bound:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_required_detail_hash_bound,
                          terminal_chain_trusted_issuer_registry_recognition_registry_fixture_contract_sha256:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_registry_fixture_contract_sha256,
                          terminal_chain_trusted_issuer_registry_recognition_receipt_payload_contract_sha256:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.trusted_issuer_registry_recognition_receipt_payload_contract_sha256,
                        }
                      : {}),
                    ...(productProofPathRecognizedReceiptPathMirrorRequired
                      ? {
                          terminal_chain_recognized_receipt_path_evidence_sha256:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_sha256,
                          terminal_chain_recognized_receipt_path_evidence_artifact_verification_sha256:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_artifact_verification_sha256,
                          terminal_chain_recognized_receipt_path_evidence_sha256_matches_artifact_verification:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_sha256_matches_artifact_verification,
                          terminal_chain_recognized_receipt_path_evidence_bound_to_artifact_body:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_bound_to_artifact_body,
                          terminal_chain_recognized_receipt_path_evidence_source_binding_sha256:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_source_binding_sha256,
                          terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding,
                          terminal_chain_recognized_receipt_path_evidence_verdict:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_verdict,
                          terminal_chain_recognized_receipt_path_evidence_recognized:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_recognized,
                          terminal_chain_recognized_receipt_path_evidence_receipt_envelope_included:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_receipt_envelope_included,
                          terminal_chain_recognized_receipt_path_evidence_registry_public_key_material_included:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_registry_public_key_material_included,
                          terminal_chain_recognized_receipt_path_evidence_artifact_crypto_reproducible:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_artifact_crypto_reproducible,
                          terminal_chain_recognized_receipt_path_evidence_live_state_proven:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_live_state_proven,
                          terminal_chain_recognized_receipt_path_evidence_live_issuer_status_proven:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_live_issuer_status_proven,
                          terminal_chain_recognized_receipt_path_evidence_key_custody_proven:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_key_custody_proven,
                          terminal_chain_recognized_receipt_path_evidence_revocation_truth_proven:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_revocation_truth_proven,
                          terminal_chain_recognized_receipt_path_evidence_production_downstream_recognition_proven:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_production_downstream_recognition_proven,
                          terminal_chain_recognized_receipt_path_evidence_public_external_attestation:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_public_external_attestation,
                          terminal_chain_recognized_receipt_path_evidence_sovereign_recognition:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_sovereign_recognition,
                          terminal_chain_recognized_receipt_path_evidence_current_machine_governance_proven:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognized_receipt_path_evidence_current_machine_governance_proven,
                        }
                      : {}),
                    ...(productProofPathTerminalChainRecognitionRefusalGroupCaseIdsRequired
                      ? {
                          terminal_chain_recognition_refusal_group_count:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_count,
                          terminal_chain_recognition_refusal_group_case_count:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_case_count,
                          terminal_chain_recognition_refusal_group_case_ids:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_case_ids,
                          terminal_chain_recognition_refusal_group_case_ids_preserved:
                            northStarProductProofPath.terminal_chain_boundary
                              ?.recognition_refusal_group_case_ids_preserved,
                        }
                      : {}),
                    terminal_chain_external_attestation:
                      northStarProductProofPath.terminal_chain_boundary?.external_attestation,
                    terminal_chain_current_machine_governance:
                      northStarProductProofPath.terminal_chain_boundary
                        ?.current_machine_governance_proven,
                  }
                : {}),
              ...(productProofPathDeploymentProfileAuthorityBridgeRequired
                ? {
                    deployment_profile_authority_bridge_required:
                      northStar.counts
                        ?.product_proof_path_deployment_profile_authority_bridge_required,
                    deployment_profile_authority_bridge_preserved:
                      northStar.counts
                        ?.product_proof_path_deployment_profile_authority_bridge_preserved,
                    deployment_profile_authority_bridge_observed:
                      northStarProductProofPath
                        .deployment_profile_authority_bridge_observed,
                    deployment_profile_authority_bridge_proof_type:
                      northStarProductProofPath.deployment_profile_authority_bridge
                        ?.proof_type,
	                    deployment_profile_authority_bridge_refusal_count:
	                      northStarProductProofPath.deployment_profile_authority_bridge
	                        ?.observed_refusal_case_count,
	                    ...(productProofPathDeploymentProfileAuthorityRefusalsRequired
	                      ? {
	                          deployment_profile_authority_refusals_required:
	                            northStar.counts
	                              ?.product_proof_path_deployment_profile_authority_refusals_required,
	                          deployment_profile_authority_refusals_preserved:
	                            northStar.counts
	                              ?.product_proof_path_deployment_profile_authority_refusals_preserved,
	                          deployment_profile_authority_refusal_case_count:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusal_case_count,
	                          deployment_profile_authority_refusal_case_ids:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusal_case_ids,
	                          deployment_profile_authority_refusals_before_service_proof:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusals_before_service_proof,
	                          deployment_profile_authority_refusals_before_mutation:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusals_before_mutation,
	                          deployment_profile_authority_refusal_service_proof_started:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.deployment_profile_authority_refusal_service_proof_started,
	                          stale_deployment_profile_artifact_refused_before_service_proof:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.stale_deployment_profile_artifact_refused_before_service_proof,
	                          profile_recognition_mismatch_refused_before_service_proof:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.profile_recognition_mismatch_refused_before_service_proof,
	                          latest_profile_selection_refused_before_service_proof:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.latest_profile_selection_refused_before_service_proof,
	                          request_stream_authority_material_refused_before_service_proof:
	                            northStarProductProofPath.deployment_profile_authority_bridge
	                              ?.request_stream_authority_material_refused_before_service_proof,
	                        }
	                      : {}),
	                    deployment_profile_authority_bridge_current_machine_governance:
                      northStarProductProofPath.deployment_profile_authority_bridge
                        ?.current_machine_governance,
                    deployment_profile_authority_bridge_production_authority:
                      northStarProductProofPath.deployment_profile_authority_bridge
                        ?.production_authority,
                  }
                : {}),
            },
            known_ungoverned_boundaries_includes_unrouted_records_paths:
              (productProofPath.observed?.known_ungoverned_boundaries || []).includes(
                'unrouted_records_paths'
              ),
            claim_boundary: {
              creates_public_external_attestation:
                productProofPath.forbidden_claims?.external_attestation,
              proves_current_machine_governance:
                productProofPath.forbidden_claims?.current_machine_governance,
              proves_all_mcp_governance:
                productProofPath.forbidden_claims?.all_mcp_governance,
              proves_unrouted_surface_coverage:
                productProofPath.forbidden_claims?.unrouted_surface_coverage,
            },
          },
        }
      : {}),
    proof_smoke: {
      counts: {
        installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
          smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids:
          proofSmokeGroupCaseIds,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
          smoke.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
        ...(terminalChainDeploymentProfileAuthorityRefusalMirrorRequired
          ? {
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage:
                smoke.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage,
            }
          : {}),
      },
    },
    north_star: {
      counts: {
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
          northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids:
          northStarGroupCaseIds,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
        installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
          northStar.counts
            ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
        ...(terminalChainDeploymentProfileAuthorityRefusalMirrorRequired
          ? {
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition,
              installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage,
              installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage:
                northStar.counts
                  ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage,
            }
          : {}),
      },
      puzzle_3_observed: {
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved:
          enterpriseProfile
            .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
          enterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
          enterpriseProfile
            .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
          enterpriseProfile
            .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
          enterpriseProfile
            .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
          enterpriseProfile
            .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
          enterpriseProfile
            .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
          enterpriseProfile
            .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      },
      puzzle_5_observed: {
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved:
          downstreamRecognition
            .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_count:
          downstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count:
          downstreamRecognition
            .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count:
          downstreamRecognition
            .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count,
        installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count:
          downstreamRecognition
            .installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved:
          downstreamRecognition
            .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids:
          downstreamRecognition
            .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
        installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes:
          downstreamRecognition
            .installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      },
    },
    terminal_chain_refusal_evidence: {
      source: 'same-manifest.terminal_chain_refusal_evidence',
      recognition_refusal_group_case_ids_required:
        terminalEvidence.recognition_refusal_group_case_ids_required,
      all_recognition_refusal_group_case_ids_preserved:
        terminalEvidence.all_recognition_refusal_group_case_ids_preserved,
      recognition_refusal_group_case_ids:
        terminalEvidence.recognition_refusal_group_case_ids,
      trusted_issuer_registry_recognition_refusals_required:
        terminalEvidence.trusted_issuer_registry_recognition_refusals_required,
      trusted_issuer_registry_recognition_refusal_case_count:
        terminalEvidence.trusted_issuer_registry_recognition_refusal_case_count,
      artifact_verification_trusted_issuer_registry_recognition_refusal_case_count:
        terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count,
      trusted_issuer_registry_recognition_refusals_all_refused:
        terminalEvidence.trusted_issuer_registry_recognition_refusals_all_refused,
      artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused:
        terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused,
      trusted_issuer_registry_recognition_refusal_case_ids:
        terminalEvidence.trusted_issuer_registry_recognition_refusal_case_ids,
      artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids:
        terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      trusted_issuer_registry_recognition_refusal_reason_codes:
        terminalEvidence.trusted_issuer_registry_recognition_refusal_reason_codes,
      artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes:
        terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      trusted_issuer_registry_recognition_refusals_sha256:
        terminalEvidence.trusted_issuer_registry_recognition_refusals_sha256,
      artifact_verification_trusted_issuer_registry_recognition_refusals_sha256:
        terminalEvidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256,
      all_trusted_issuer_registry_recognition_refusals_preserved:
        terminalEvidence.all_trusted_issuer_registry_recognition_refusals_preserved,
      ...(terminalChainDeploymentProfileAuthorityRefusalMirrorRequired
        ? {
            deployment_profile_authority_refusal_mirror_required:
              terminalEvidence.deployment_profile_authority_refusal_mirror_required,
            deployment_profile_authority_refusal_mirror_preserved:
              terminalEvidence.deployment_profile_authority_refusal_mirror_preserved,
            deployment_profile_authority_refusal_case_count:
              terminalEvidence.deployment_profile_authority_refusal_case_count,
            artifact_verification_deployment_profile_authority_refusal_case_count:
              terminalEvidence.artifact_verification_deployment_profile_authority_refusal_case_count,
            deployment_profile_authority_refusal_case_ids:
              terminalEvidence.deployment_profile_authority_refusal_case_ids,
            artifact_verification_deployment_profile_authority_refusal_case_ids:
              terminalEvidence.artifact_verification_deployment_profile_authority_refusal_case_ids,
            deployment_profile_authority_refusals_before_service_proof:
              terminalEvidence.deployment_profile_authority_refusals_before_service_proof,
            artifact_verification_deployment_profile_authority_refusals_before_service_proof:
              terminalEvidence.artifact_verification_deployment_profile_authority_refusals_before_service_proof,
            deployment_profile_authority_refusals_before_mutation:
              terminalEvidence.deployment_profile_authority_refusals_before_mutation,
            artifact_verification_deployment_profile_authority_refusals_before_mutation:
              terminalEvidence.artifact_verification_deployment_profile_authority_refusals_before_mutation,
            deployment_profile_authority_refusal_service_proof_started:
              terminalEvidence.deployment_profile_authority_refusal_service_proof_started,
            artifact_verification_deployment_profile_authority_refusal_service_proof_started:
              terminalEvidence.artifact_verification_deployment_profile_authority_refusal_service_proof_started,
            stale_deployment_profile_artifact_refused_before_service_proof:
              terminalEvidence.stale_deployment_profile_artifact_refused_before_service_proof,
            profile_recognition_mismatch_refused_before_service_proof:
              terminalEvidence.profile_recognition_mismatch_refused_before_service_proof,
            latest_profile_selection_refused_before_service_proof:
              terminalEvidence.latest_profile_selection_refused_before_service_proof,
            request_stream_authority_material_refused_before_service_proof:
              terminalEvidence.request_stream_authority_material_refused_before_service_proof,
            current_machine_governance:
              terminalEvidence.current_machine_governance,
            production_downstream_recognition:
              terminalEvidence.production_downstream_recognition,
            production_authority:
              terminalEvidence.production_authority,
            enterprise_readiness:
              terminalEvidence.enterprise_readiness,
            external_attestation:
              terminalEvidence.external_attestation,
            sovereign_recognition:
              terminalEvidence.sovereign_recognition,
            unrouted_surface_coverage:
              terminalEvidence.unrouted_surface_coverage,
          }
        : {}),
    },
    terminal_chain_nested_artifact_tamper_refusals:
      terminalEvidence.nested_artifact_tamper_refusals,
    terminal_chain_nested_artifact_binding:
      terminalEvidence.nested_artifact_binding,
    claim_boundary: claimBoundary,
  };
}

if (assertions.failed !== 0) {
  throw new Error('manifest cannot report PASS with failed assertions');
}
if (manifest.target.expected_commit_sha !== manifest.target.observed_commit_sha) {
  throw new Error('manifest target SHA mismatch');
}
if (manifest.issuer_status_evidence) {
  const evidence = manifest.issuer_status_evidence;
  if (
    evidence.enabled !== true ||
    evidence.evidence_model !== 'release-forward-local-issuer-status-fixture' ||
    evidence.minimum_target !== 'v3.4.33' ||
    evidence.proof_type !== 'issuer-status-proof-v1' ||
    evidence.proof_evidence_model !== 'local-hermetic-fixture' ||
    evidence.proof_live_probing !== false ||
    evidence.trust_anchor_model !== 'local-fixture-recognition-rule' ||
    evidence.action_class !== 'records.write' ||
    !/^[a-f0-9]{64}$/.test(evidence.issuer_status_proof_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(evidence.verifier_kit_fixture_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(evidence.external_runner_diagnostics_sha256 || '') ||
    evidence.active_issuer_boards !== true ||
    evidence.retired_issuer_refuses !== true ||
    evidence.compromised_issuer_refuses !== true ||
    evidence.missing_status_issuer_refuses !== true ||
    evidence.unknown_issuer_refuses !== true ||
    evidence.missing_key_issuer_refuses !== true ||
    evidence.raw_public_key_material_included !== false ||
    evidence.raw_private_key_material_included !== false ||
    evidence.verifier_kit_fixture_verdict !== 'ISSUER-STATUS-FIXTURE-VERIFIED' ||
    evidence.verifier_kit_fixture_live_probing !== false ||
    evidence.diagnostics_issuer_artifact_verified !== true ||
    evidence.diagnostics_issuer_artifact_sha256_matches_fixture !== true ||
    evidence.creates_public_external_attestation !== false ||
    evidence.proves_non_operator_review !== false ||
    evidence.proves_live_issuer_status !== false ||
    evidence.proves_key_custody !== false ||
    evidence.proves_revocation_truth !== false ||
    evidence.proves_production_trust_registry !== false ||
    evidence.proves_production_downstream_recognition !== false
  ) {
    throw new Error('manifest issuer status evidence drifted');
  }
}
if (manifest.trusted_issuer_registry_recognition_evidence) {
  const evidence = manifest.trusted_issuer_registry_recognition_evidence;
  if (
    evidence.enabled !== true ||
    evidence.evidence_model !== 'release-forward-local-trusted-issuer-registry-fixture' ||
    evidence.minimum_target !== 'v3.4.35' ||
    !/^[a-f0-9]{64}$/.test(evidence.recognition_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(evidence.malformed_registry_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(evidence.malformed_registry_error_sha256 || '') ||
    evidence.registry_type !== 'trusted-receipt-issuers-v1' ||
    evidence.registry_evidence_model !== 'bundled-local-fixture' ||
    evidence.live_probing !== false ||
    evidence.requested_scope !== 'verifier-kit-sample' ||
    evidence.registry_scope !== 'verifier-kit-sample' ||
    evidence.verdict !== 'RECOGNIZED' ||
    evidence.recognized !== true ||
    evidence.decision !== 'accept' ||
    evidence.reason_code !== 'recognized' ||
    evidence.issuer_status !== 'active' ||
    evidence.signature_valid !== true ||
    evidence.malformed_registry_unsupported_field !== true ||
    evidence.malformed_registry_error_names_unsupported_field !== true ||
    evidence.malformed_registry_fail_closed_before_verdict !== true ||
    evidence.creates_public_external_attestation !== false ||
    evidence.proves_non_operator_review !== false ||
    evidence.proves_live_registry !== false ||
    evidence.proves_live_issuer_status !== false ||
    evidence.proves_key_custody !== false ||
    evidence.proves_revocation_truth !== false ||
    evidence.proves_production_trust_registry !== false ||
    evidence.proves_production_downstream_recognition !== false ||
    evidence.proves_production_authority !== false ||
    evidence.proves_sovereign_recognition !== false
  ) {
    throw new Error('manifest trusted issuer registry recognition evidence drifted');
  }
}
if (manifest.trusted_receipt_issuer_completion_evidence) {
  const evidence = manifest.trusted_receipt_issuer_completion_evidence;
  const trustedReceiptIssuerCompletionAuthorityEventTypes = [
    'direct_human_approval',
    'delegated_policy_approval',
    'standing_mandate',
    'quorum_approval',
    'emergency_override',
    'system_control_approval_under_pre_approved_policy',
    'blocked',
    'escalated',
    'timed_out',
    'refused_due_to_missing_authority',
    'refused_due_to_invalid_receipt',
    'refused_due_to_stale_or_unrecognized_registry_state',
  ];
  if (
    evidence.enabled !== true ||
    evidence.evidence_model !== 'release-forward-supplied-private-core-completion-proof' ||
    evidence.minimum_target !== 'v3.4.53' ||
    evidence.proof_path !== 'ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json' ||
    evidence.verification_path !==
      'ZLAR/zlar-trusted-receipt-issuer-completion-proof-verification-v1.json' ||
    !/^[a-f0-9]{64}$/.test(evidence.proof_artifact_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(evidence.verification_artifact_sha256 || '') ||
    evidence.proof_type !== 'zlar-trusted-receipt-issuer-completion-proof-v1' ||
    evidence.verification_type !==
      'zlar-trusted-receipt-issuer-completion-proof-verification-v1' ||
    evidence.verified !== true ||
    !/^[a-f0-9]{64}$/.test(evidence.proof_body_sha256 || '') ||
    ![
      'protected-records.runtime.profile-installation.records.write',
      'protected-records.private-operator.records-terminal.records.write',
    ].includes(evidence.selected_surface_id) ||
    evidence.readiness_selected_terminal_surface_id !==
      'protected-records.runtime.profile-installation.records.write' ||
    evidence.proof_selected_surface_can_differ_from_readiness_selected_terminal !== true ||
    evidence.authority_primitive !== 'recognized_authority_event' ||
    !trustedReceiptIssuerCompletionAuthorityEventTypes.includes(
      evidence.authority_event_type || ''
    ) ||
    evidence.core_sentence !==
      'Receipts prove recognized authority events, not absolute human intention.' ||
    evidence.completed_for_selected_surface !== true ||
    evidence.receipt_validity_distinct_from_human_intention !== true ||
    evidence.issuer_recognition_distinct_from_human_yes !== true ||
    evidence.authority_event_distinct_from_legal_consent !== true ||
    evidence.operator_registry_distinct_from_customer_production_trust !== true ||
    evidence.software_custody_not_hardware_backed !== true ||
    evidence.revocation_status_not_global_certainty !== true ||
    evidence.summary_only_evidence_accepted !== false ||
    evidence.fixture_only_evidence_accepted !== false ||
    evidence.overclaim_flags_accepted !== false ||
    evidence.claim_boundary_flags_false !== true ||
    evidence.not_public_by_default !== true ||
    evidence.source_publication_evidence !== false ||
    evidence.creates_public_external_attestation !== false ||
    evidence.proves_public_external_attestation !== false ||
    evidence.proves_source_publication !== false ||
    evidence.proves_production_issuer_custody !== false ||
    evidence.proves_hardware_custody !== false ||
    evidence.proves_key_custody !== false ||
    evidence.proves_revocation_truth !== false ||
    evidence.proves_live_issuer_status !== false ||
    evidence.proves_production_downstream_recognition !== false ||
    evidence.proves_production_authority !== false ||
    evidence.proves_enterprise_readiness !== false ||
    evidence.proves_current_machine_governance !== false ||
    evidence.proves_real_records_protection !== false ||
    evidence.proves_side_door_closure !== false ||
    evidence.proves_sovereign_recognition !== false ||
    evidence.proves_absolute_human_intention_or_legal_consent !== false
  ) {
    throw new Error('manifest trusted receipt issuer completion evidence drifted');
  }
}
if (manifest.terminal_chain_refusal_evidence) {
  const evidence = manifest.terminal_chain_refusal_evidence;
  const expectedRecognitionRefusalGroupCaseIds = {
    no_usable_recognized_receipt_authority: [
      'missing_receipt_refused_before_runtime_mutation',
      'invalid_receipt_refused_before_runtime_mutation',
      'unknown_issuer_refused_before_runtime_mutation',
      'retired_issuer_refused_before_runtime_mutation',
      'missing_issuer_status_refused_before_runtime_mutation',
      'stale_receipt_refused_before_runtime_mutation',
    ],
    recognized_receipt_scope_mismatch: [
      'wrong_policy_refused_before_runtime_mutation',
      'wrong_domain_refused_before_runtime_mutation',
      'wrong_tool_refused_before_runtime_mutation',
      'wrong_audit_event_refused_before_runtime_mutation',
      'wrong_detail_refused_before_runtime_mutation',
      'non_boarding_outcome_refused_before_runtime_mutation',
    ],
    route_or_request_authority_material_refused: [
      'wrong_runtime_profile_id_refused_before_runtime_mutation',
      'direct_api_without_receipt_refused_before_runtime_mutation',
      'direct_api_with_receipt_refused_before_runtime_mutation',
      'agent_supplied_recognition_rule_refused_before_runtime_mutation',
      'agent_supplied_fixture_mode_refused_before_runtime_mutation',
      'unsupported_request_field_refused_before_runtime_mutation',
    ],
  };
  const arraysEqual = (left, right) =>
    Array.isArray(left) &&
    left.length === right.length &&
    left.every((item, index) => item === right[index]);
  const groupCaseIdsExact = (value) =>
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    arraysEqual(
      Object.keys(value).sort(),
      Object.keys(expectedRecognitionRefusalGroupCaseIds).sort()
    ) &&
    Object.entries(expectedRecognitionRefusalGroupCaseIds).every(([key, expected]) =>
      arraysEqual(value[key], expected)
    );
  const recognitionRefusalGroupsRequired =
    evidence.recognition_refusal_groups_required === true;
  const recognitionRefusalGroupCaseIdsRequired =
    evidence.recognition_refusal_group_case_ids_required === true;
  const nestedArtifactTamperRefusalsRequired =
    evidence.nested_artifact_tamper_refusals_required === true;
  const nestedArtifactBindingRequired =
    evidence.nested_artifact_binding_required === true;
  const trustedIssuerRegistryRecognitionRefusalsRequired =
    evidence.trusted_issuer_registry_recognition_refusals_required === true;
  const deploymentProfileAuthorityRefusalMirrorRequired =
    evidence.deployment_profile_authority_refusal_mirror_required === true;
  if (
    evidence.named_receipt_refusals_sha256 !==
      evidence.artifact_verification_named_receipt_refusals_sha256 ||
    evidence.refusal_taxonomy_sha256 !==
      evidence.artifact_verification_refusal_taxonomy_sha256 ||
    evidence.all_named_receipt_refusals_before_mutation !== true ||
    evidence.proves_current_machine_governance !== false ||
    evidence.proves_production_downstream_recognition !== false
  ) {
    throw new Error('manifest terminal chain refusal evidence drifted');
  }
  if (
    recognitionRefusalGroupsRequired &&
    (
      evidence.recognition_refusal_groups_sha256 !==
        evidence.artifact_verification_recognition_refusal_groups_sha256 ||
      !/^[a-f0-9]{64}$/.test(evidence.recognition_refusal_groups_sha256 || '') ||
      evidence.all_recognition_refusal_groups_before_mutation !== true ||
      recognitionRefusalGroupCaseIdsRequired &&
        evidence.recognition_refusal_groups_required !== true
    )
  ) {
    throw new Error('manifest terminal chain recognition refusal groups drifted');
  }
  if (
    recognitionRefusalGroupCaseIdsRequired &&
    (
      evidence.all_recognition_refusal_group_case_ids_preserved !== true ||
      !groupCaseIdsExact(evidence.recognition_refusal_group_case_ids)
    )
  ) {
    throw new Error('manifest terminal chain recognition refusal group case ids drifted');
  }
  if (trustedIssuerRegistryRecognitionRefusalsRequired) {
    const expectedTrustedIssuerRegistryRecognitionRefusalCaseIds = [
      'unrecognized_terminal_chain_registry_scope_refused',
      'registry_receipt_contract_mismatch_refused',
    ];
    const expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes = [
      'scope_not_found',
      'detail_hash_mismatch',
    ];
    if (
      evidence.trusted_issuer_registry_recognition_refusals_minimum_target !== 'v3.4.39' ||
      evidence.trusted_issuer_registry_recognition_refusal_case_count !==
        expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length ||
      evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
        expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length ||
      evidence.trusted_issuer_registry_recognition_refusals_all_refused !== true ||
      evidence.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused !==
        true ||
      !arraysEqual(
        evidence.trusted_issuer_registry_recognition_refusal_case_ids,
        expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
      ) ||
      !arraysEqual(
        evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
        expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
      ) ||
      !arraysEqual(
        evidence.trusted_issuer_registry_recognition_refusal_reason_codes,
        expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
      ) ||
      !arraysEqual(
        evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
        expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
      ) ||
      !/^[a-f0-9]{64}$/.test(
        evidence.trusted_issuer_registry_recognition_refusals_sha256 || ''
      ) ||
      evidence.trusted_issuer_registry_recognition_refusals_sha256 !==
        evidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 ||
      evidence.all_trusted_issuer_registry_recognition_refusals_preserved !== true
    ) {
      throw new Error('manifest terminal chain trusted issuer registry recognition refusals drifted');
    }
  }
  if (deploymentProfileAuthorityRefusalMirrorRequired) {
    const expectedDeploymentProfileAuthorityRefusalCaseIds = [
      'stale_deployment_profile_runtime_sha_refused_before_service_proof',
      'runtime_profile_id_mismatch_refused_before_service_proof',
      'preflight_profile_sha_mismatch_refused_before_service_proof',
      'preflight_latest_selection_refused_before_service_proof',
      'preflight_request_authority_material_refused_before_service_proof',
    ];
    if (
      evidence.deployment_profile_authority_refusal_mirror_minimum_target !== 'v3.4.50' ||
      evidence.deployment_profile_authority_refusal_mirror_preserved !== true ||
      evidence.deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      evidence.artifact_verification_deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      !arraysEqual(
        evidence.deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      !arraysEqual(
        evidence.artifact_verification_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      evidence.deployment_profile_authority_refusals_before_service_proof !== true ||
      evidence.artifact_verification_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      evidence.deployment_profile_authority_refusals_before_mutation !== true ||
      evidence.artifact_verification_deployment_profile_authority_refusals_before_mutation !==
        true ||
      evidence.deployment_profile_authority_refusal_service_proof_started !== false ||
      evidence.artifact_verification_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      evidence.stale_deployment_profile_artifact_refused_before_service_proof !== true ||
      evidence.profile_recognition_mismatch_refused_before_service_proof !== true ||
      evidence.latest_profile_selection_refused_before_service_proof !== true ||
      evidence.request_stream_authority_material_refused_before_service_proof !== true ||
      evidence.current_machine_governance !== false ||
      evidence.production_downstream_recognition !== false ||
      evidence.production_authority !== false ||
      evidence.enterprise_readiness !== false ||
      evidence.external_attestation !== false ||
      evidence.sovereign_recognition !== false ||
      evidence.unrouted_surface_coverage !== false
    ) {
      throw new Error('manifest terminal chain deployment-profile authority refusal mirror drifted');
    }
  }
  if (nestedArtifactTamperRefusalsRequired) {
    const nestedTamper = evidence.nested_artifact_tamper_refusals || {};
    const preflightArtifactType =
      'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
    const serviceArtifactType =
      'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';
    if (
      evidence.nested_artifact_tamper_refusals_minimum_target !== 'v3.4.28' ||
      !hasExactKeys(
        nestedTamper,
        releaseForwardTerminalChainNestedArtifactTamperRefusalFields
      ) ||
      nestedTamper.generated_preflight_artifact_type !== preflightArtifactType ||
      nestedTamper.generated_service_proof_artifact_type !== serviceArtifactType ||
      nestedTamper.artifact_generated_preflight_artifact_type !== preflightArtifactType ||
      nestedTamper.artifact_generated_service_proof_artifact_type !== serviceArtifactType ||
      nestedTamper.forged_inner_preflight_hash_refused !== true ||
      nestedTamper.forged_inner_service_hash_refused !== true
    ) {
      throw new Error('manifest terminal chain nested artifact tamper refusals drifted');
    }
  }
  if (nestedArtifactBindingRequired) {
    const nested = evidence.nested_artifact_binding || {};
    const preflightArtifactType =
      'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
    const serviceArtifactType =
      'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1';
    if (
      evidence.nested_artifact_binding_minimum_target !== 'v3.4.30' ||
      !hasExactKeys(
        nested,
        releaseForwardTerminalChainNestedArtifactBindingFields
      ) ||
      nested.generated_preflight_artifact_type !== preflightArtifactType ||
      nested.generated_service_proof_artifact_type !== serviceArtifactType ||
      !/^[a-f0-9]{64}$/.test(nested.generated_preflight_artifact_body_sha256 || '') ||
      !/^[a-f0-9]{64}$/.test(nested.generated_service_proof_artifact_body_sha256 || '') ||
      nested.generated_preflight_artifact_verified !== true ||
      nested.generated_service_proof_artifact_verified !== true ||
      nested.preflight_artifact_hash_bound !== true ||
      nested.service_proof_source_preflight_hash_bound !== true ||
      nested.service_artifact_hash_bound !== true ||
      nested.service_artifact_verification_bound_to_service_proof !== true ||
      nested.creates_public_external_attestation !== false ||
      nested.proves_non_operator_review !== false ||
      nested.proves_current_machine_governance !== false ||
      nested.proves_production_downstream_recognition !== false
    ) {
      throw new Error('manifest terminal chain nested artifact binding drifted');
    }
  }
}
if (targetAtLeast(process.env.DRY_RUN_TAG, 3, 3, 104)) {
  if (
    !privateVerifierResultSamplePointerPasses(
      manifest.private_verifier_result_sample
    )
  ) {
    throw new Error('manifest private verifier result sample pointer drifted');
  }
} else if (
  Object.prototype.hasOwnProperty.call(
    manifest,
    'private_verifier_result_sample'
  )
) {
  throw new Error(
    'manifest private verifier result sample pointer appeared before v3.3.104'
  );
}
if (manifest.release_forward_report_contract) {
  const contract = manifest.release_forward_report_contract;
  const expectedRecognitionRefusalGroupCaseIds = {
    no_usable_recognized_receipt_authority: [
      'missing_receipt_refused_before_runtime_mutation',
      'invalid_receipt_refused_before_runtime_mutation',
      'unknown_issuer_refused_before_runtime_mutation',
      'retired_issuer_refused_before_runtime_mutation',
      'missing_issuer_status_refused_before_runtime_mutation',
      'stale_receipt_refused_before_runtime_mutation',
    ],
    recognized_receipt_scope_mismatch: [
      'wrong_policy_refused_before_runtime_mutation',
      'wrong_domain_refused_before_runtime_mutation',
      'wrong_tool_refused_before_runtime_mutation',
      'wrong_audit_event_refused_before_runtime_mutation',
      'wrong_detail_refused_before_runtime_mutation',
      'non_boarding_outcome_refused_before_runtime_mutation',
    ],
    route_or_request_authority_material_refused: [
      'wrong_runtime_profile_id_refused_before_runtime_mutation',
      'direct_api_without_receipt_refused_before_runtime_mutation',
      'direct_api_with_receipt_refused_before_runtime_mutation',
      'agent_supplied_recognition_rule_refused_before_runtime_mutation',
      'agent_supplied_fixture_mode_refused_before_runtime_mutation',
      'unsupported_request_field_refused_before_runtime_mutation',
    ],
  };
  const groupKeys = Object.keys(expectedRecognitionRefusalGroupCaseIds);
  const groupCaseIdsExact = (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }
    return (
      arraysEqual(Object.keys(value).sort(), [...groupKeys].sort()) &&
      groupKeys.every((key) =>
        arraysEqual(value[key], expectedRecognitionRefusalGroupCaseIds[key])
      )
    );
  };
  const exactObjectMirror = (value, mirror, fields) =>
    hasExactKeys(value, fields) &&
    hasExactKeys(mirror, fields) &&
    fields.every((field) => value[field] === mirror[field]);
  const expectedTrustedIssuerRegistryRecognitionRefusalCaseIds = [
    'unrecognized_terminal_chain_registry_scope_refused',
    'registry_receipt_contract_mismatch_refused',
  ];
  const expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes = [
    'scope_not_found',
    'detail_hash_mismatch',
  ];
  const contractBoundaryChecks = [
    ['enabled', contract.enabled === true],
    ['contract_type', contract.contract_type === 'zlar-release-forward-dry-run-report-contract-v1'],
    ['evidence_model', contract.evidence_model === 'release-forward-dry-run-artifacts'],
    ['minimum_target', contract.minimum_target === 'v3.4.41'],
    ['report_contract_satisfied', contract.report_contract_satisfied === true],
    ['manifest_is_canonical', contract.manifest_is_canonical === true],
    ['result_lines_prefix', contract.result_lines_prefix === 'manifest.release_forward_report_contract'],
    [
      'proof_smoke_sample_verification_path',
      contract.source_artifacts?.proof_smoke_sample_verification_path ===
        'ZLAR/zlar-proof-smoke-sample-verification.json',
    ],
    [
      'proof_smoke_sample_verification_sha256',
      /^[a-f0-9]{64}$/.test(
        contract.source_artifacts?.proof_smoke_sample_verification_sha256 || ''
      ),
    ],
    [
      'north_star_readiness_path',
      contract.source_artifacts?.north_star_readiness_path ===
        'ZLAR/zlar-north-star-readiness-v1.json',
    ],
    [
      'north_star_readiness_sha256',
      /^[a-f0-9]{64}$/.test(
        contract.source_artifacts?.north_star_readiness_sha256 || ''
      ),
    ],
    [
      'terminal_chain_refusal_evidence_included_in_same_manifest',
      contract.source_artifacts?.terminal_chain_refusal_evidence_included_in_same_manifest ===
        true,
    ],
    [
      'claim_boundary_exact_keys',
      hasExactKeys(
        contract.claim_boundary,
        releaseForwardReportContractClaimBoundaryFields
      ),
    ],
    [
      'claim_boundary_all_false',
      !Object.values(contract.claim_boundary || {}).some((value) => value !== false),
    ],
  ];
  const failedContractBoundaryChecks = contractBoundaryChecks
    .filter(([, passed]) => !passed)
    .map(([label]) => label);
  if (failedContractBoundaryChecks.length > 0) {
    throw new Error(
      `manifest release-forward report contract boundary drifted: ${failedContractBoundaryChecks.join(',')}`
    );
  }
  if (
    !exactObjectMirror(
      contract.terminal_chain_nested_artifact_tamper_refusals,
      manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals,
      releaseForwardTerminalChainNestedArtifactTamperRefusalFields
    ) ||
    !exactObjectMirror(
      contract.terminal_chain_nested_artifact_binding,
      manifest.terminal_chain_refusal_evidence?.nested_artifact_binding,
      releaseForwardTerminalChainNestedArtifactBindingFields
    )
  ) {
    throw new Error('manifest release-forward report contract terminal-chain nested artifact evidence drifted');
  }
  if (productProofPathContractRequired) {
    const productContract = contract.product_proof_path || {};
    if (
      contract.source_artifacts?.product_proof_path_path !==
        'ZLAR/zlar-product-proof-path-v1.json' ||
      !/^[a-f0-9]{64}$/.test(
        contract.source_artifacts?.product_proof_path_sha256 || ''
      ) ||
      productContract.minimum_target !== 'v3.4.42' ||
      productContract.source !== 'ZLAR/zlar-product-proof-path-v1.json' ||
      productContract.report_type !== 'zlar-product-proof-path-v1' ||
      productContract.result !== 'PASS' ||
      productContract.north_star_piece !== 'Product Proof Path' ||
      !productProofPathEvidenceModelAccepted(productContract.evidence_model) ||
      productContract.live_probing !== false ||
      productContract.private_operator_state_required !== false ||
      productContract.proof_pack_verified !== true ||
      !/^[a-f0-9]{64}$/.test(productContract.proof_pack_body_sha256 || '') ||
      productContract.acceptance_gate_all_true !== true ||
      productContract.forbidden_claims_all_false !== true ||
      !hasExactKeys(
        productContract.simulated_human_authorization,
        releaseForwardProductProofPathSimulatedHumanAuthorizationFields
      ) ||
      productContract.simulated_human_authorization?.approval_channel !==
        'simulated-human-fixture' ||
      productContract.simulated_human_authorization?.authorized_boarded !== true ||
      productContract.simulated_human_authorization?.pending_boarded !== false ||
      productContract.simulated_human_authorization?.denied_boarded !== false ||
      !hasExactKeys(
        productContract.receipt_verifier_boundary,
        releaseForwardProductProofPathReceiptVerifierBoundaryFields
      ) ||
      productContract.receipt_verifier_boundary?.valid_verdict !== 'VALID' ||
      productContract.receipt_verifier_boundary?.unknown_signer_verdict !==
        'UNKNOWN-SIGNER' ||
      productContract.receipt_verifier_boundary?.invalid_verdict !== 'INVALID' ||
      productContract.receipt_verifier_boundary?.downstream_recognition_proven !==
        false ||
      productContract.north_star?.product_proof_path_verified !== true ||
      productContract.north_star?.artifact_consumed !== true ||
      productContract.north_star?.puzzle_piece_provided !== true ||
      productContract.north_star?.acceptance_gate_scope !==
        'fresh-local-product-proof-path' ||
      productContract.north_star?.live_probing !== false ||
      productContract.north_star?.forbidden_claims_false !== true ||
      productContract.known_ungoverned_boundaries_includes_unrouted_records_paths !==
        true ||
      !hasExactKeys(
        productContract.claim_boundary,
        releaseForwardProductProofPathClaimBoundaryFields
      ) ||
      Object.values(productContract.claim_boundary || {}).some((value) => value !== false)
    ) {
      throw new Error(
        'manifest release-forward report contract product proof path drifted'
      );
    }
    if (productProofPathDownstreamRefusalBoundaryRequired) {
      if (
        !downstreamRefusalBoundaryPasses(
          productContract.downstream_refusal_boundary
        ) ||
        !downstreamRefusalBoundaryPasses(
          productContract.north_star?.downstream_refusal_boundary
        )
      ) {
        throw new Error(
          'manifest release-forward report contract product proof path downstream-refusal boundary drifted'
        );
      }
    } else if (
      Object.prototype.hasOwnProperty.call(
        productContract,
        'downstream_refusal_boundary'
      ) ||
      Object.prototype.hasOwnProperty.call(
        productContract.north_star || {},
        'downstream_refusal_boundary'
      )
    ) {
      throw new Error(
        'manifest release-forward report contract product proof path downstream-refusal boundary appeared before v3.4.51'
      );
    }
    if (productProofPathTerminalChainBoundaryRequired) {
      if (
        productContract.terminal_chain_boundary?.verified !== true ||
        productContract.terminal_chain_boundary?.artifact_type !==
          'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-v1' ||
        productContract.terminal_chain_boundary?.payload_type !==
          'zlar-protected-records-installed-runtime-profile-terminal-chain-v1' ||
        productContract.terminal_chain_boundary?.evidence_model !==
          'fresh-local-disposable-installed-runtime-profile-terminal-chain' ||
        productContract.terminal_chain_boundary?.live_probing !== false ||
        !/^[a-f0-9]{64}$/.test(
          productContract.terminal_chain_boundary?.body_sha256 || ''
        ) ||
        productContract.terminal_chain_boundary?.generated_installed_root_preflighted !==
          true ||
        productContract.terminal_chain_boundary
          ?.generated_preflight_artifact_consumed_by_service_proof !== true ||
        productContract.terminal_chain_boundary
          ?.generated_service_proof_artifact_verified !== true ||
        productContract.terminal_chain_boundary?.recognized_write_boarded !== true ||
        productContract.terminal_chain_boundary
          ?.all_required_refusals_before_mutation !== true ||
        productContract.terminal_chain_boundary?.required_refusal_case_count !== 18 ||
        productContract.terminal_chain_boundary?.observed_refusal_case_count !== 18 ||
        !/^[a-f0-9]{64}$/.test(
          productContract.terminal_chain_boundary?.recognition_contract_sha256 || ''
        ) ||
        !/^[a-f0-9]{64}$/.test(
          productContract.terminal_chain_boundary?.refusal_taxonomy_sha256 || ''
        ) ||
        !/^[a-f0-9]{64}$/.test(
          productContract.terminal_chain_boundary?.named_receipt_refusals_sha256 || ''
        ) ||
        !/^[a-f0-9]{64}$/.test(
          productContract.terminal_chain_boundary?.recognition_refusal_groups_sha256 || ''
        ) ||
        !/^[a-f0-9]{64}$/.test(
          productContract.terminal_chain_boundary
            ?.trusted_issuer_registry_recognition_binding_sha256 || ''
        ) ||
        productContract.terminal_chain_boundary
          ?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification !==
          true ||
        !/^[a-f0-9]{64}$/.test(
          productContract.terminal_chain_boundary
            ?.trusted_issuer_registry_recognition_refusals_sha256 || ''
        ) ||
        productContract.terminal_chain_boundary
          ?.trusted_issuer_registry_recognition_refusal_hash_matches_binding !== true ||
        productContract.terminal_chain_boundary
          ?.trusted_issuer_registry_recognition_refusal_case_count !==
          expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length ||
        !arraysEqual(
          productContract.terminal_chain_boundary
            ?.trusted_issuer_registry_recognition_refusal_case_ids,
          expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
        ) ||
        !arraysEqual(
          productContract.terminal_chain_boundary
            ?.trusted_issuer_registry_recognition_refusal_reason_codes,
          expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
        ) ||
        productContract.terminal_chain_boundary
          ?.trusted_issuer_registry_recognition_refusals_all_refused !== true ||
        productContract.terminal_chain_boundary?.registry_receipt_contract_hash_bound !==
          true ||
        productContract.terminal_chain_boundary?.selected_profile_hash_bound !== true ||
        productContract.terminal_chain_boundary?.recognition_contract_hash_bound !== true ||
        productContract.terminal_chain_boundary?.terminal_chain_decision_bound !== true ||
        productContract.terminal_chain_boundary?.nested_artifact_binding_preserved !==
          true ||
        productContract.terminal_chain_boundary?.registry_public_key_material_included !==
          false ||
        productContract.terminal_chain_boundary?.receipt_envelope_included !== false ||
        productContract.terminal_chain_boundary
          ?.cryptographic_evidence_reproducible_from_artifact !== false ||
        productContract.terminal_chain_boundary?.current_machine_governance_proven !==
          false ||
        productContract.terminal_chain_boundary?.production_downstream_recognition !==
          false ||
        productContract.terminal_chain_boundary?.external_attestation !== false ||
        productContract.terminal_chain_boundary?.sovereign_recognition !== false ||
        productContract.terminal_chain_boundary?.unrouted_records_paths_checked !== false ||
        productContract.north_star?.terminal_chain_boundary_observed !== true ||
        productContract.north_star?.terminal_chain_artifact_verified !== true ||
        productContract.north_star?.terminal_chain_boundary_verified !== true ||
        productContract.north_star
          ?.terminal_chain_binding_matches_artifact_verification !== true ||
        productContract.north_star?.terminal_chain_refusal_hash_matches_binding !==
          true ||
        productContract.north_star?.terminal_chain_external_attestation !== false ||
        productContract.north_star?.terminal_chain_current_machine_governance !== false
      ) {
        throw new Error(
          'manifest release-forward report contract product proof path terminal chain boundary drifted'
        );
      }
      if (productProofPathTerminalChainRegistryVerdictRequired) {
        if (
          !terminalChainTrustedRegistryVerdictPasses(
            productContract.terminal_chain_boundary
          ) ||
          !northStarTerminalChainTrustedRegistryVerdictPasses(
            productContract.north_star
          )
        ) {
          throw new Error(
            'manifest release-forward report contract product proof path terminal chain trusted-registry verdict drifted'
          );
        }
      } else if (
        hasAnyOwn(
          productContract.terminal_chain_boundary,
          terminalChainTrustedRegistryVerdictFields
        ) ||
        hasAnyOwn(
          productContract.north_star,
          northStarTerminalChainTrustedRegistryVerdictFields
        )
      ) {
        throw new Error(
          'manifest release-forward report contract product proof path terminal chain trusted-registry verdict appeared before v3.4.51'
        );
      }
      if (productProofPathRecognizedReceiptPathMirrorRequired) {
        if (
          !recognizedReceiptPathMirrorPasses(
            productContract.terminal_chain_boundary
          ) ||
          !northStarRecognizedReceiptPathMirrorPasses(
            productContract.north_star,
            productContract.terminal_chain_boundary
          )
        ) {
          throw new Error(
            'manifest release-forward report contract product proof path recognized receipt path mirror drifted'
          );
        }
      } else if (
        hasAnyRecognizedReceiptPathOwn(productContract.terminal_chain_boundary) ||
        hasAnyRecognizedReceiptPathOwn(productContract.north_star)
      ) {
        throw new Error(
          'manifest release-forward report contract product proof path recognized receipt path mirror appeared before v3.4.52'
        );
      }
      if (productProofPathTerminalChainRecognitionRefusalGroupCaseIdsRequired) {
        if (
          productContract.terminal_chain_boundary?.recognition_refusal_group_count !==
            groupKeys.length ||
          productContract.terminal_chain_boundary
            ?.recognition_refusal_group_case_count !== 18 ||
          productContract.terminal_chain_boundary
            ?.recognition_refusal_group_case_ids_preserved !== true ||
          !groupCaseIdsExact(
            productContract.terminal_chain_boundary
              ?.recognition_refusal_group_case_ids
          ) ||
          productContract.north_star?.terminal_chain_recognition_refusal_group_count !==
            groupKeys.length ||
          productContract.north_star
            ?.terminal_chain_recognition_refusal_group_case_count !== 18 ||
          productContract.north_star
            ?.terminal_chain_recognition_refusal_group_case_ids_preserved !== true ||
          !groupCaseIdsExact(
            productContract.north_star
              ?.terminal_chain_recognition_refusal_group_case_ids
          )
        ) {
          throw new Error(
            'manifest release-forward report contract product proof path terminal chain recognition refusal group case IDs drifted'
          );
        }
      } else if (
        Object.prototype.hasOwnProperty.call(
          productContract.terminal_chain_boundary || {},
          'recognition_refusal_group_count'
        ) ||
        Object.prototype.hasOwnProperty.call(
          productContract.terminal_chain_boundary || {},
          'recognition_refusal_group_case_count'
        ) ||
        Object.prototype.hasOwnProperty.call(
          productContract.terminal_chain_boundary || {},
          'recognition_refusal_group_case_ids'
        ) ||
        Object.prototype.hasOwnProperty.call(
          productContract.terminal_chain_boundary || {},
          'recognition_refusal_group_case_ids_preserved'
        ) ||
        Object.prototype.hasOwnProperty.call(
          productContract.north_star || {},
          'terminal_chain_recognition_refusal_group_count'
        ) ||
        Object.prototype.hasOwnProperty.call(
          productContract.north_star || {},
          'terminal_chain_recognition_refusal_group_case_count'
        ) ||
        Object.prototype.hasOwnProperty.call(
          productContract.north_star || {},
          'terminal_chain_recognition_refusal_group_case_ids'
        ) ||
        Object.prototype.hasOwnProperty.call(
          productContract.north_star || {},
          'terminal_chain_recognition_refusal_group_case_ids_preserved'
        )
      ) {
        throw new Error(
          'manifest release-forward report contract product proof path terminal chain recognition refusal group case IDs appeared before v3.4.46'
        );
      }
    } else if (
      Object.prototype.hasOwnProperty.call(productContract, 'terminal_chain_boundary') ||
      Object.prototype.hasOwnProperty.call(
        productContract.north_star || {},
        'terminal_chain_boundary_observed'
      )
    ) {
      throw new Error(
        'manifest release-forward report contract product proof path terminal chain boundary appeared before v3.4.45'
      );
    }
	    if (productProofPathDeploymentProfileAuthorityBridgeRequired) {
      const deploymentBridge = productContract.deployment_profile_authority_bridge;
      const deploymentNorthStar = productContract.north_star || {};
      if (
        !productProofPathDeploymentProfileAuthorityRefusalsRequired &&
        (
          hasAnyOwn(
            deploymentBridge,
            deploymentProfileAuthorityRefusalBridgeFields
          ) ||
          hasAnyOwn(
            deploymentNorthStar,
            deploymentProfileAuthorityRefusalNorthStarFields
          )
        )
      ) {
        throw new Error(
          'manifest release-forward report contract product proof path deployment-profile authority refusals appeared before v3.4.49'
        );
      }
	      if (
        !hasExactKeys(
          deploymentBridge,
          productProofPathDeploymentProfileAuthorityRefusalsRequired
            ? deploymentProfileAuthorityBridgeWithRefusalFields
            : deploymentProfileAuthorityBridgeFields
        ) ||
        !hasOnlyExpectedDeploymentProfileAuthorityNorthStarKeys(
          deploymentNorthStar,
          productProofPathDeploymentProfileAuthorityRefusalsRequired
            ? deploymentProfileAuthorityNorthStarFields
            : deploymentProfileAuthorityBridgeNorthStarFields
        ) ||
	        deploymentBridge?.proof_type !==
          'zlar-protected-records-one-terminal-deployment-profile-proof-v1' ||
        deploymentBridge?.evidence_model !==
          'local-fixture-one-terminal-deployment-profile-authority-bridge' ||
        deploymentBridge?.live_probing !== false ||
        !/^[a-f0-9]{64}$/.test(
          deploymentBridge?.deployment_profile_sha256 || ''
        ) ||
        !/^[a-f0-9]{64}$/.test(
          deploymentBridge?.runtime_profile_sha256 || ''
        ) ||
        deploymentBridge?.deployment_profile_artifact_authoritative !== true ||
        deploymentBridge?.selected_by_explicit_id_and_sha !== true ||
        deploymentBridge?.selects_latest_profile !==
          false ||
        deploymentBridge?.preflight_artifact_verified !== true ||
        deploymentBridge?.recognized_receipt_mutates_once !== true ||
        deploymentBridge?.recognized_state_entry_count_delta !== 1 ||
        deploymentBridge?.required_refusal_case_count !== 18 ||
        deploymentBridge?.observed_refusal_case_count !== 18 ||
        deploymentBridge?.all_required_refusals_before_mutation !== true ||
        deploymentBridge?.agent_supplied_authority_refused_before_mutation !== true ||
        deploymentBridge?.direct_api_refused_before_mutation !== true ||
        deploymentBridge?.downstream_refusal_proven !== true ||
        deploymentBridge?.request_stream_authority_material_accepted !== false ||
        deploymentBridge?.current_machine_governance !== false ||
        deploymentBridge?.production_downstream_recognition !== false ||
        deploymentBridge?.production_authority !==
          false ||
        deploymentBridge?.enterprise_readiness !==
          false ||
        deploymentBridge?.external_attestation !==
          false ||
        deploymentBridge?.sovereign_recognition !==
          false ||
        deploymentBridge?.unrouted_surface_coverage !== false ||
        deploymentNorthStar.deployment_profile_authority_bridge_required !==
          true ||
        deploymentNorthStar.deployment_profile_authority_bridge_preserved !==
          true ||
        deploymentNorthStar.deployment_profile_authority_bridge_observed !==
          true ||
        deploymentNorthStar.deployment_profile_authority_bridge_proof_type !==
          'zlar-protected-records-one-terminal-deployment-profile-proof-v1' ||
        deploymentNorthStar.deployment_profile_authority_bridge_refusal_count !== 18 ||
        deploymentNorthStar.deployment_profile_authority_bridge_current_machine_governance !==
          false ||
        deploymentNorthStar.deployment_profile_authority_bridge_production_authority !== false
      ) {
        throw new Error(
	          'manifest release-forward report contract product proof path deployment-profile authority bridge drifted'
	        );
	      }
	      if (productProofPathDeploymentProfileAuthorityRefusalsRequired) {
	        if (
	          deploymentBridge?.deployment_profile_authority_refusal_case_count !==
	            expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
	          !arraysEqual(
	            deploymentBridge?.deployment_profile_authority_refusal_case_ids,
	            expectedDeploymentProfileAuthorityRefusalCaseIds
	          ) ||
	          deploymentBridge?.deployment_profile_authority_refusals_before_service_proof !==
	            true ||
	          deploymentBridge?.deployment_profile_authority_refusals_before_mutation !== true ||
	          deploymentBridge?.deployment_profile_authority_refusal_service_proof_started !==
	            false ||
	          deploymentBridge?.stale_deployment_profile_artifact_refused_before_service_proof !==
	            true ||
	          deploymentBridge?.profile_recognition_mismatch_refused_before_service_proof !==
	            true ||
	          deploymentBridge?.latest_profile_selection_refused_before_service_proof !== true ||
	          deploymentBridge?.request_stream_authority_material_refused_before_service_proof !==
	            true ||
	          deploymentNorthStar.deployment_profile_authority_refusals_required !== true ||
	          deploymentNorthStar.deployment_profile_authority_refusals_preserved !== true ||
	          deploymentNorthStar.deployment_profile_authority_refusal_case_count !==
	            expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
	          !arraysEqual(
	            deploymentNorthStar.deployment_profile_authority_refusal_case_ids,
	            expectedDeploymentProfileAuthorityRefusalCaseIds
	          ) ||
	          deploymentNorthStar.deployment_profile_authority_refusals_before_service_proof !==
	            true ||
	          deploymentNorthStar.deployment_profile_authority_refusals_before_mutation !== true ||
	          deploymentNorthStar.deployment_profile_authority_refusal_service_proof_started !==
	            false ||
	          deploymentNorthStar.stale_deployment_profile_artifact_refused_before_service_proof !==
	            true ||
	          deploymentNorthStar.profile_recognition_mismatch_refused_before_service_proof !==
	            true ||
	          deploymentNorthStar.latest_profile_selection_refused_before_service_proof !== true ||
	          deploymentNorthStar.request_stream_authority_material_refused_before_service_proof !==
	            true
	        ) {
	          throw new Error(
	            'manifest release-forward report contract product proof path deployment-profile authority refusals drifted'
	          );
	        }
	      }
	    } else if (
      Object.prototype.hasOwnProperty.call(
        productContract,
        'deployment_profile_authority_bridge'
      ) ||
      Object.prototype.hasOwnProperty.call(
        productContract.north_star || {},
        'deployment_profile_authority_bridge_observed'
      ) ||
      Object.prototype.hasOwnProperty.call(
        productContract.north_star || {},
        'deployment_profile_authority_bridge_required'
      )
    ) {
      throw new Error(
        'manifest release-forward report contract product proof path deployment-profile authority bridge appeared before v3.4.48'
      );
    }
  } else if (
    Object.prototype.hasOwnProperty.call(contract, 'product_proof_path') ||
    Object.prototype.hasOwnProperty.call(
      contract.source_artifacts || {},
      'product_proof_path_path'
    ) ||
    Object.prototype.hasOwnProperty.call(
      contract.source_artifacts || {},
      'product_proof_path_sha256'
    )
  ) {
    throw new Error(
      'manifest release-forward report contract product proof path appeared before v3.4.42'
    );
  }
  if (
    contract.proof_smoke?.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count !== 3 ||
    contract.proof_smoke?.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count !== 18 ||
    contract.proof_smoke?.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count !==
      3 ||
    contract.proof_smoke?.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count !==
      18 ||
    !groupCaseIdsExact(
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
    ) ||
    contract.north_star?.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required !==
      true ||
    contract.north_star?.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved !==
      true ||
    contract.north_star?.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count !== 3 ||
    contract.north_star?.counts
      ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count !== 18 ||
    contract.north_star?.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count !==
      3 ||
    contract.north_star?.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count !==
      18 ||
    !groupCaseIdsExact(
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids
    )
  ) {
    throw new Error('manifest release-forward report contract group evidence drifted');
  }
  if (
    contract.terminal_chain_refusal_evidence
      ?.trusted_issuer_registry_recognition_refusals_required !== true ||
    contract.terminal_chain_refusal_evidence
      ?.trusted_issuer_registry_recognition_refusal_case_count !==
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length ||
    contract.terminal_chain_refusal_evidence
      ?.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length ||
    contract.terminal_chain_refusal_evidence
      ?.trusted_issuer_registry_recognition_refusals_all_refused !== true ||
    contract.terminal_chain_refusal_evidence
      ?.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused !==
      true ||
    !arraysEqual(
      contract.terminal_chain_refusal_evidence
        ?.trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) ||
    !arraysEqual(
      contract.terminal_chain_refusal_evidence
        ?.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) ||
    !arraysEqual(
      contract.terminal_chain_refusal_evidence
        ?.trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) ||
    !arraysEqual(
      contract.terminal_chain_refusal_evidence
        ?.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) ||
    !/^[a-f0-9]{64}$/.test(
      contract.terminal_chain_refusal_evidence
        ?.trusted_issuer_registry_recognition_refusals_sha256 || ''
    ) ||
    contract.terminal_chain_refusal_evidence
      ?.trusted_issuer_registry_recognition_refusals_sha256 !==
      contract.terminal_chain_refusal_evidence
        ?.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 ||
    contract.terminal_chain_refusal_evidence
      ?.all_trusted_issuer_registry_recognition_refusals_preserved !== true
  ) {
    throw new Error(
      'manifest release-forward report contract trusted issuer registry refusals drifted'
    );
  }
  if (
    contract.proof_smoke?.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count !==
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length ||
    contract.proof_smoke?.counts
      ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count !==
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds.length ||
    !arraysEqual(
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) ||
    !arraysEqual(
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) ||
    !arraysEqual(
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) ||
    !arraysEqual(
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) ||
    contract.north_star?.counts
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved !==
      true ||
    !arraysEqual(
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) ||
    !arraysEqual(
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) ||
    !arraysEqual(
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) ||
    !arraysEqual(
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes,
      expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes
    ) ||
    contract.north_star?.puzzle_3_observed
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved !==
      true ||
    contract.north_star?.puzzle_5_observed
      ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved !==
      true ||
    !arraysEqual(
      contract.north_star?.puzzle_3_observed
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    ) ||
    !arraysEqual(
      contract.north_star?.puzzle_5_observed
        ?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids,
      expectedTrustedIssuerRegistryRecognitionRefusalCaseIds
    )
  ) {
    throw new Error(
      'manifest release-forward report contract proof-smoke/readiness evidence drifted'
    );
  }
  if (terminalChainDeploymentProfileAuthorityRefusalMirrorRequired) {
    if (
      contract.terminal_chain_refusal_evidence
        ?.deployment_profile_authority_refusal_mirror_required !== true ||
      contract.terminal_chain_refusal_evidence
        ?.deployment_profile_authority_refusal_mirror_preserved !== true ||
      contract.terminal_chain_refusal_evidence
        ?.deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      contract.terminal_chain_refusal_evidence
        ?.artifact_verification_deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      !arraysEqual(
        contract.terminal_chain_refusal_evidence
          ?.deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      !arraysEqual(
        contract.terminal_chain_refusal_evidence
          ?.artifact_verification_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      contract.terminal_chain_refusal_evidence
        ?.deployment_profile_authority_refusals_before_service_proof !== true ||
      contract.terminal_chain_refusal_evidence
        ?.artifact_verification_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      contract.terminal_chain_refusal_evidence
        ?.deployment_profile_authority_refusals_before_mutation !== true ||
      contract.terminal_chain_refusal_evidence
        ?.artifact_verification_deployment_profile_authority_refusals_before_mutation !==
        true ||
      contract.terminal_chain_refusal_evidence
        ?.deployment_profile_authority_refusal_service_proof_started !== false ||
      contract.terminal_chain_refusal_evidence
        ?.artifact_verification_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      contract.terminal_chain_refusal_evidence
        ?.stale_deployment_profile_artifact_refused_before_service_proof !== true ||
      contract.terminal_chain_refusal_evidence
        ?.profile_recognition_mismatch_refused_before_service_proof !== true ||
      contract.terminal_chain_refusal_evidence
        ?.latest_profile_selection_refused_before_service_proof !== true ||
      contract.terminal_chain_refusal_evidence
        ?.request_stream_authority_material_refused_before_service_proof !== true ||
      contract.terminal_chain_refusal_evidence?.current_machine_governance !== false ||
      contract.terminal_chain_refusal_evidence?.production_downstream_recognition !== false ||
      contract.terminal_chain_refusal_evidence?.production_authority !== false ||
      contract.terminal_chain_refusal_evidence?.enterprise_readiness !== false ||
      contract.terminal_chain_refusal_evidence?.external_attestation !== false ||
      contract.terminal_chain_refusal_evidence?.sovereign_recognition !== false ||
      contract.terminal_chain_refusal_evidence?.unrouted_surface_coverage !== false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_preserved !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_mirror_profile_sha_matches !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      !arraysEqual(
        contract.proof_smoke?.counts
          ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      !arraysEqual(
        contract.proof_smoke?.counts
          ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation !==
        true ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage !==
        false ||
      contract.proof_smoke?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required !==
        true ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved !==
        true ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_count !==
        expectedDeploymentProfileAuthorityRefusalCaseIds.length ||
      !arraysEqual(
        contract.north_star?.counts
          ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      !arraysEqual(
        contract.north_star?.counts
          ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids,
        expectedDeploymentProfileAuthorityRefusalCaseIds
      ) ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_service_proof !==
        true ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation !==
        true ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusals_before_mutation !==
        true ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_service_proof_started !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_current_machine_governance !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_downstream_recognition !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_production_authority !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_enterprise_readiness !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_external_attestation !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_sovereign_recognition !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage !==
        false ||
      contract.north_star?.counts
        ?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_unrouted_surface_coverage !==
        false
    ) {
      throw new Error(
        'manifest release-forward report contract deployment-profile authority refusal mirror drifted'
      );
    }
  }
}

fs.writeFileSync(process.env.DRY_RUN_MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
NODE
}

write_result_file() {
    local completed_at sanitized_repo_url
    completed_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    sanitized_repo_url="$(printf '%s\n' "${REPO_URL}" | sanitize_transcript)"
    {
        cat <<EOF
# ZLAR Release-Forward Verifier Dry Run

Result: PASS
Completed: ${completed_at}

## Target

- Release target: \`${TAG}\`
- Expected commit: \`${EXPECTED_SHA}\`
- Observed commit: \`$(cat "${OUTPUT_DIR}/target-head.txt")\`
- Source: fresh clone of \`${sanitized_repo_url}\`

## Boundary

This is local dry-run evidence only. It sent no verifier request, contacted no
verifier, created no public external attestation, and does not prove
non-operator review, production deployment, current-machine governance, live
hooks, live MCP coverage, approval-channel health, live issuer status, key
custody, revocation truth, sovereign recognition, enterprise readiness, or
coverage of unrouted surfaces.

## Preserved Files

- \`transcript.txt\`
- \`COMMANDS.txt\`
- \`ASSERTIONS.txt\`
- \`DRY-RUN-MANIFEST.json\`
- \`SHA256SUMS\`
- \`RUN-SHA256SUMS\`
- \`target-head.txt\`
- \`target-status.txt\`
- \`ZLAR/zlar-verifier-env-report-v0.json\`
- \`ZLAR/zlar-proof-smoke-v1.json\`
- \`ZLAR/zlar-proof-smoke-generated-verification.json\`
- \`ZLAR/zlar-proof-smoke-sample-verification.json\`
- \`ZLAR/zlar-service-preflight-sample-verification.json\`
- \`ZLAR/zlar-local-proof-pack-sample-verification.json\`
- \`ZLAR/zlar-issuer-status-proof.json\`
- \`ZLAR/zlar-verifier-kit-issuer-status-fixture.json\`
EOF
        if tag_at_least 3 3 94; then
            echo "- \`ZLAR/zlar-trusted-receipt-issuer-recognition.json\`"
        fi
        if tag_at_least 3 3 97; then
            echo "- \`ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry.json\`"
            echo "- \`ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt\`"
        fi
        cat <<'EOF'
- `ZLAR/zlar-runtime-local-activation-sample-verification.json`
- `ZLAR/zlar-runtime-profile-installation-sample-verification.json`
EOF
        if tag_at_least 3 4 5; then
            echo "- \`ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json\`"
        fi
        if tag_at_least 3 4 7; then
            echo "- \`ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json\`"
        fi
        if tag_at_least 3 4 8; then
            echo "- \`ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json\`"
        fi
        if tag_at_least 3 4 11; then
            echo "- \`ZLAR/zlar-installed-runtime-profile-service-proof-v1.json\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json\`"
        fi
        if tag_at_least 3 4 15; then
            echo "- \`ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json\`"
        fi
        if tag_at_least 3 4 28; then
            echo "- \`ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json\`"
            echo "- \`ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt\`"
        fi
        if tag_at_least 3 4 9; then
            echo "- \`ZLAR/zlar-product-proof-path-v1.json\`"
        fi
        if tag_at_least 3 4 53 && [ -f "${OUTPUT_DIR}/ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json" ]; then
            echo "- \`ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json\`"
            echo "- \`ZLAR/zlar-trusted-receipt-issuer-completion-proof-verification-v1.json\`"
        fi
        cat <<'EOF'
- `ZLAR/zlar-coverage-map-sample.json`
EOF
        if tag_at_least 3 3 98; then
            echo "- \`ZLAR/zlar-north-star-readiness-v1.json\`"
        fi
        if tag_at_least 3 3 100; then
            echo "- \`ZLAR/zlar-verifier-kit-reproducibility-v1.json\`"
        fi
        if tag_at_least 3 4 21; then
            echo "- \`ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json\`"
        fi
        if tag_at_least 3 3 109; then
            echo "- \`ZLAR/zlar-verifier-kit-release-assets-v1.json\`"
            echo "- \`ZLAR/zlar-verifier-kit-public-distribution-v1.json\`"
        fi
        if tag_at_least 3 3 104; then
            echo "- \`ZLAR/zlar-private-verifier-result-v1.json\`"
            echo "- \`ZLAR/zlar-private-verifier-result-verification-v1.json\`"
        fi
        cat <<'EOF'

## Artifact Hashes

```text
EOF
        cat "${OUTPUT_DIR}/SHA256SUMS"
        cat <<'EOF'
```

## Run Hashes

```text
EOF
        cat "${OUTPUT_DIR}/RUN-SHA256SUMS"
        cat <<'EOF'
```

## Machine-Readable Manifest

```text
EOF
        shasum -a 256 DRY-RUN-MANIFEST.json
        cat <<'EOF'
```
EOF
        if tag_at_least 3 4 33; then
            cat <<'EOF'

## Issuer Status Evidence

```text
EOF
            node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function print(prefix, key, value) {
  console.log(`${prefix}.${key}=${value}`);
}

const manifest = readJson('DRY-RUN-MANIFEST.json');
const evidence = manifest.issuer_status_evidence || {};
if (evidence.enabled !== true) {
  throw new Error('missing manifest issuer status evidence');
}

print('manifest.issuer_status_evidence', 'enabled', evidence.enabled);
print('manifest.issuer_status_evidence', 'evidence_model', evidence.evidence_model);
print('manifest.issuer_status_evidence', 'issuer_status_proof_path', evidence.issuer_status_proof_path);
print('manifest.issuer_status_evidence', 'issuer_status_proof_sha256', evidence.issuer_status_proof_sha256);
print('manifest.issuer_status_evidence', 'verifier_kit_fixture_path', evidence.verifier_kit_fixture_path);
print('manifest.issuer_status_evidence', 'verifier_kit_fixture_sha256', evidence.verifier_kit_fixture_sha256);
print('manifest.issuer_status_evidence', 'external_runner_diagnostics_path', evidence.external_runner_diagnostics_path);
print('manifest.issuer_status_evidence', 'external_runner_diagnostics_sha256', evidence.external_runner_diagnostics_sha256);
print('manifest.issuer_status_evidence', 'proof_type', evidence.proof_type);
print('manifest.issuer_status_evidence', 'proof_evidence_model', evidence.proof_evidence_model);
print('manifest.issuer_status_evidence', 'proof_live_probing', evidence.proof_live_probing);
print('manifest.issuer_status_evidence', 'trust_anchor_model', evidence.trust_anchor_model);
print('manifest.issuer_status_evidence', 'action_class', evidence.action_class);
print('manifest.issuer_status_evidence', 'active_issuer_boards', evidence.active_issuer_boards);
print('manifest.issuer_status_evidence', 'retired_issuer_refuses', evidence.retired_issuer_refuses);
print('manifest.issuer_status_evidence', 'compromised_issuer_refuses', evidence.compromised_issuer_refuses);
print('manifest.issuer_status_evidence', 'missing_status_issuer_refuses', evidence.missing_status_issuer_refuses);
print('manifest.issuer_status_evidence', 'unknown_issuer_refuses', evidence.unknown_issuer_refuses);
print('manifest.issuer_status_evidence', 'missing_key_issuer_refuses', evidence.missing_key_issuer_refuses);
print('manifest.issuer_status_evidence', 'raw_public_key_material_included', evidence.raw_public_key_material_included);
print('manifest.issuer_status_evidence', 'raw_private_key_material_included', evidence.raw_private_key_material_included);
print('manifest.issuer_status_evidence', 'verifier_kit_fixture_verdict', evidence.verifier_kit_fixture_verdict);
print('manifest.issuer_status_evidence', 'verifier_kit_fixture_live_probing', evidence.verifier_kit_fixture_live_probing);
print('manifest.issuer_status_evidence', 'diagnostics_issuer_artifact_verified', evidence.diagnostics_issuer_artifact_verified);
print('manifest.issuer_status_evidence', 'diagnostics_issuer_artifact_sha256_matches_fixture', evidence.diagnostics_issuer_artifact_sha256_matches_fixture);
print('manifest.issuer_status_evidence', 'creates_public_external_attestation', evidence.creates_public_external_attestation);
print('manifest.issuer_status_evidence', 'proves_non_operator_review', evidence.proves_non_operator_review);
print('manifest.issuer_status_evidence', 'proves_live_issuer_status', evidence.proves_live_issuer_status);
print('manifest.issuer_status_evidence', 'proves_key_custody', evidence.proves_key_custody);
print('manifest.issuer_status_evidence', 'proves_revocation_truth', evidence.proves_revocation_truth);
print('manifest.issuer_status_evidence', 'proves_production_trust_registry', evidence.proves_production_trust_registry);
print('manifest.issuer_status_evidence', 'proves_production_downstream_recognition', evidence.proves_production_downstream_recognition);
NODE
            cat <<'EOF'
```
EOF
        fi
        if tag_at_least 3 4 35; then
            cat <<'EOF'

## Trusted Issuer Registry Recognition Evidence

```text
EOF
            node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function print(prefix, key, value) {
  console.log(`${prefix}.${key}=${value}`);
}

const manifest = readJson('DRY-RUN-MANIFEST.json');
const evidence = manifest.trusted_issuer_registry_recognition_evidence || {};
if (evidence.enabled !== true) {
  throw new Error('missing manifest trusted issuer registry recognition evidence');
}

print('manifest.trusted_issuer_registry_recognition_evidence', 'enabled', evidence.enabled);
print('manifest.trusted_issuer_registry_recognition_evidence', 'evidence_model', evidence.evidence_model);
print('manifest.trusted_issuer_registry_recognition_evidence', 'recognition_path', evidence.recognition_path);
print('manifest.trusted_issuer_registry_recognition_evidence', 'recognition_sha256', evidence.recognition_sha256);
print('manifest.trusted_issuer_registry_recognition_evidence', 'malformed_registry_path', evidence.malformed_registry_path);
print('manifest.trusted_issuer_registry_recognition_evidence', 'malformed_registry_sha256', evidence.malformed_registry_sha256);
print('manifest.trusted_issuer_registry_recognition_evidence', 'malformed_registry_error_path', evidence.malformed_registry_error_path);
print('manifest.trusted_issuer_registry_recognition_evidence', 'malformed_registry_error_sha256', evidence.malformed_registry_error_sha256);
print('manifest.trusted_issuer_registry_recognition_evidence', 'registry_type', evidence.registry_type);
print('manifest.trusted_issuer_registry_recognition_evidence', 'registry_evidence_model', evidence.registry_evidence_model);
print('manifest.trusted_issuer_registry_recognition_evidence', 'live_probing', evidence.live_probing);
print('manifest.trusted_issuer_registry_recognition_evidence', 'requested_scope', evidence.requested_scope);
print('manifest.trusted_issuer_registry_recognition_evidence', 'registry_scope', evidence.registry_scope);
print('manifest.trusted_issuer_registry_recognition_evidence', 'verdict', evidence.verdict);
print('manifest.trusted_issuer_registry_recognition_evidence', 'recognized', evidence.recognized);
print('manifest.trusted_issuer_registry_recognition_evidence', 'decision', evidence.decision);
print('manifest.trusted_issuer_registry_recognition_evidence', 'reason_code', evidence.reason_code);
print('manifest.trusted_issuer_registry_recognition_evidence', 'issuer_status', evidence.issuer_status);
print('manifest.trusted_issuer_registry_recognition_evidence', 'signature_valid', evidence.signature_valid);
print('manifest.trusted_issuer_registry_recognition_evidence', 'malformed_registry_fail_closed_before_verdict', evidence.malformed_registry_fail_closed_before_verdict);
print('manifest.trusted_issuer_registry_recognition_evidence', 'creates_public_external_attestation', evidence.creates_public_external_attestation);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_non_operator_review', evidence.proves_non_operator_review);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_live_registry', evidence.proves_live_registry);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_live_issuer_status', evidence.proves_live_issuer_status);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_key_custody', evidence.proves_key_custody);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_revocation_truth', evidence.proves_revocation_truth);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_production_trust_registry', evidence.proves_production_trust_registry);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_production_downstream_recognition', evidence.proves_production_downstream_recognition);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_production_authority', evidence.proves_production_authority);
print('manifest.trusted_issuer_registry_recognition_evidence', 'proves_sovereign_recognition', evidence.proves_sovereign_recognition);
NODE
            cat <<'EOF'
```
EOF
        fi
        if tag_at_least 3 4 53 && [ -f "${OUTPUT_DIR}/ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json" ]; then
            cat <<'EOF'

## Trusted Receipt Issuer Completion Evidence

```text
EOF
            node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function print(prefix, key, value) {
  console.log(`${prefix}.${key}=${value}`);
}

const manifest = readJson('DRY-RUN-MANIFEST.json');
const evidence = manifest.trusted_receipt_issuer_completion_evidence || {};
if (evidence.enabled !== true) {
  throw new Error('missing manifest trusted receipt issuer completion evidence');
}

const prefix = 'manifest.trusted_receipt_issuer_completion_evidence';
for (const key of [
  'enabled',
  'evidence_model',
  'minimum_target',
  'proof_path',
  'proof_artifact_sha256',
  'verification_path',
  'verification_artifact_sha256',
  'proof_type',
  'verification_type',
  'verified',
  'proof_body_sha256',
  'selected_surface_id',
  'readiness_selected_terminal_surface_id',
  'proof_selected_surface_can_differ_from_readiness_selected_terminal',
  'authority_primitive',
  'authority_event_type',
  'core_sentence',
  'completed_for_selected_surface',
  'receipt_validity_distinct_from_human_intention',
  'issuer_recognition_distinct_from_human_yes',
  'authority_event_distinct_from_legal_consent',
  'operator_registry_distinct_from_customer_production_trust',
  'software_custody_not_hardware_backed',
  'revocation_status_not_global_certainty',
  'summary_only_evidence_accepted',
  'fixture_only_evidence_accepted',
  'overclaim_flags_accepted',
  'claim_boundary_flags_false',
  'not_public_by_default',
  'source_publication_evidence',
  'creates_public_external_attestation',
  'proves_public_external_attestation',
  'proves_source_publication',
  'proves_production_issuer_custody',
  'proves_hardware_custody',
  'proves_key_custody',
  'proves_revocation_truth',
  'proves_live_issuer_status',
  'proves_production_downstream_recognition',
  'proves_production_authority',
  'proves_enterprise_readiness',
  'proves_current_machine_governance',
  'proves_real_records_protection',
  'proves_side_door_closure',
  'proves_sovereign_recognition',
  'proves_absolute_human_intention_or_legal_consent',
]) {
  print(prefix, key, evidence[key]);
}
NODE
            cat <<'EOF'
```
EOF
        fi
        if tag_at_least 3 4 22; then
            cat <<'EOF'

## Terminal Chain Refusal Evidence

```text
EOF
            node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function print(prefix, key, value) {
  console.log(`${prefix}.${key}=${value}`);
}

const manifest = readJson('DRY-RUN-MANIFEST.json');
const evidence = manifest.terminal_chain_refusal_evidence || {};
const named = evidence.named_receipt_refusals || {};
const groups = evidence.recognition_refusal_groups || {};
const groupCaseIds = evidence.recognition_refusal_group_case_ids || {};
const nestedTamper = evidence.nested_artifact_tamper_refusals || {};
const nested = evidence.nested_artifact_binding || {};
if (evidence.enabled !== true) {
  throw new Error('missing manifest terminal chain refusal evidence');
}

print('manifest.terminal_chain_refusal_evidence', 'enabled', evidence.enabled);
print('manifest.terminal_chain_refusal_evidence', 'evidence_model', evidence.evidence_model);
print('manifest.terminal_chain_refusal_evidence', 'chain_path', evidence.chain_path);
print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_path', evidence.artifact_verification_path);
print('manifest.terminal_chain_refusal_evidence', 'refusal_taxonomy_sha256', evidence.refusal_taxonomy_sha256);
print('manifest.terminal_chain_refusal_evidence', 'named_receipt_refusals_sha256', evidence.named_receipt_refusals_sha256);
print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_named_receipt_refusals_sha256', evidence.artifact_verification_named_receipt_refusals_sha256);
print('manifest.terminal_chain_refusal_evidence', 'all_named_receipt_refusals_before_mutation', evidence.all_named_receipt_refusals_before_mutation);
print('manifest.terminal_chain_refusal_evidence', 'recognition_refusal_groups_required', evidence.recognition_refusal_groups_required);
print('manifest.terminal_chain_refusal_evidence', 'recognition_refusal_group_case_ids_required', evidence.recognition_refusal_group_case_ids_required);
print('manifest.terminal_chain_refusal_evidence', 'recognition_refusal_groups_sha256', evidence.recognition_refusal_groups_sha256);
print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_recognition_refusal_groups_sha256', evidence.artifact_verification_recognition_refusal_groups_sha256);
print('manifest.terminal_chain_refusal_evidence', 'all_recognition_refusal_groups_before_mutation', evidence.all_recognition_refusal_groups_before_mutation);
print('manifest.terminal_chain_refusal_evidence', 'all_recognition_refusal_group_case_ids_preserved', evidence.all_recognition_refusal_group_case_ids_preserved);
if (evidence.trusted_issuer_registry_recognition_refusals_required === true) {
  print('manifest.terminal_chain_refusal_evidence', 'trusted_issuer_registry_recognition_refusals_required', evidence.trusted_issuer_registry_recognition_refusals_required);
  print('manifest.terminal_chain_refusal_evidence', 'trusted_issuer_registry_recognition_refusal_case_count', evidence.trusted_issuer_registry_recognition_refusal_case_count);
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_trusted_issuer_registry_recognition_refusal_case_count', evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count);
  print('manifest.terminal_chain_refusal_evidence', 'trusted_issuer_registry_recognition_refusals_all_refused', evidence.trusted_issuer_registry_recognition_refusals_all_refused);
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused', evidence.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused);
  print('manifest.terminal_chain_refusal_evidence', 'trusted_issuer_registry_recognition_refusal_case_ids', Array.isArray(evidence.trusted_issuer_registry_recognition_refusal_case_ids) ? evidence.trusted_issuer_registry_recognition_refusal_case_ids.join(',') : '');
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids', Array.isArray(evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids) ? evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids.join(',') : '');
  print('manifest.terminal_chain_refusal_evidence', 'trusted_issuer_registry_recognition_refusal_reason_codes', Array.isArray(evidence.trusted_issuer_registry_recognition_refusal_reason_codes) ? evidence.trusted_issuer_registry_recognition_refusal_reason_codes.join(',') : '');
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes', Array.isArray(evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes) ? evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes.join(',') : '');
  print('manifest.terminal_chain_refusal_evidence', 'trusted_issuer_registry_recognition_refusals_sha256', evidence.trusted_issuer_registry_recognition_refusals_sha256);
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_trusted_issuer_registry_recognition_refusals_sha256', evidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256);
  print('manifest.terminal_chain_refusal_evidence', 'all_trusted_issuer_registry_recognition_refusals_preserved', evidence.all_trusted_issuer_registry_recognition_refusals_preserved);
}
if (evidence.deployment_profile_authority_refusal_mirror_required === true) {
  print('manifest.terminal_chain_refusal_evidence', 'deployment_profile_authority_refusal_mirror_required', evidence.deployment_profile_authority_refusal_mirror_required);
  print('manifest.terminal_chain_refusal_evidence', 'deployment_profile_authority_refusal_mirror_preserved', evidence.deployment_profile_authority_refusal_mirror_preserved);
  print('manifest.terminal_chain_refusal_evidence', 'deployment_profile_authority_refusal_case_count', evidence.deployment_profile_authority_refusal_case_count);
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_deployment_profile_authority_refusal_case_count', evidence.artifact_verification_deployment_profile_authority_refusal_case_count);
  print('manifest.terminal_chain_refusal_evidence', 'deployment_profile_authority_refusal_case_ids', Array.isArray(evidence.deployment_profile_authority_refusal_case_ids) ? evidence.deployment_profile_authority_refusal_case_ids.join(',') : '');
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_deployment_profile_authority_refusal_case_ids', Array.isArray(evidence.artifact_verification_deployment_profile_authority_refusal_case_ids) ? evidence.artifact_verification_deployment_profile_authority_refusal_case_ids.join(',') : '');
  print('manifest.terminal_chain_refusal_evidence', 'deployment_profile_authority_refusals_before_service_proof', evidence.deployment_profile_authority_refusals_before_service_proof);
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_deployment_profile_authority_refusals_before_service_proof', evidence.artifact_verification_deployment_profile_authority_refusals_before_service_proof);
  print('manifest.terminal_chain_refusal_evidence', 'deployment_profile_authority_refusals_before_mutation', evidence.deployment_profile_authority_refusals_before_mutation);
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_deployment_profile_authority_refusals_before_mutation', evidence.artifact_verification_deployment_profile_authority_refusals_before_mutation);
  print('manifest.terminal_chain_refusal_evidence', 'deployment_profile_authority_refusal_service_proof_started', evidence.deployment_profile_authority_refusal_service_proof_started);
  print('manifest.terminal_chain_refusal_evidence', 'artifact_verification_deployment_profile_authority_refusal_service_proof_started', evidence.artifact_verification_deployment_profile_authority_refusal_service_proof_started);
  print('manifest.terminal_chain_refusal_evidence', 'stale_deployment_profile_artifact_refused_before_service_proof', evidence.stale_deployment_profile_artifact_refused_before_service_proof);
  print('manifest.terminal_chain_refusal_evidence', 'profile_recognition_mismatch_refused_before_service_proof', evidence.profile_recognition_mismatch_refused_before_service_proof);
  print('manifest.terminal_chain_refusal_evidence', 'latest_profile_selection_refused_before_service_proof', evidence.latest_profile_selection_refused_before_service_proof);
  print('manifest.terminal_chain_refusal_evidence', 'request_stream_authority_material_refused_before_service_proof', evidence.request_stream_authority_material_refused_before_service_proof);
  print('manifest.terminal_chain_refusal_evidence', 'current_machine_governance', evidence.current_machine_governance);
  print('manifest.terminal_chain_refusal_evidence', 'production_downstream_recognition', evidence.production_downstream_recognition);
  print('manifest.terminal_chain_refusal_evidence', 'production_authority', evidence.production_authority);
  print('manifest.terminal_chain_refusal_evidence', 'enterprise_readiness', evidence.enterprise_readiness);
  print('manifest.terminal_chain_refusal_evidence', 'external_attestation', evidence.external_attestation);
  print('manifest.terminal_chain_refusal_evidence', 'sovereign_recognition', evidence.sovereign_recognition);
  print('manifest.terminal_chain_refusal_evidence', 'unrouted_surface_coverage', evidence.unrouted_surface_coverage);
}
print('manifest.terminal_chain_refusal_evidence', 'nested_artifact_tamper_refusals_required', evidence.nested_artifact_tamper_refusals_required);
print('manifest.terminal_chain_refusal_evidence', 'nested_artifact_binding_required', evidence.nested_artifact_binding_required);
for (const key of ['missing', 'invalid', 'stale', 'unknown_issuer', 'wrong_policy', 'wrong_domain', 'wrong_tool']) {
  print(`manifest.terminal_chain_refusal_evidence.named_receipt_refusals.${key}`, 'reason_code', named[key]?.reason_code);
  print(`manifest.terminal_chain_refusal_evidence.named_receipt_refusals.${key}`, 'refused_before_mutation', named[key]?.refused_before_mutation);
}
for (const key of ['no_usable_recognized_receipt_authority', 'recognized_receipt_scope_mismatch', 'route_or_request_authority_material_refused']) {
  print(`manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.${key}`, 'case_count', groups[key]?.case_count);
  print(`manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.${key}`, 'case_ids', Array.isArray(groupCaseIds[key]) ? groupCaseIds[key].join(',') : '');
  print(`manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.${key}`, 'all_refused_before_mutation', groups[key]?.all_refused_before_mutation);
}
if (evidence.nested_artifact_tamper_refusals_required === true) {
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals', 'generated_preflight_artifact_type', nestedTamper.generated_preflight_artifact_type);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals', 'generated_service_proof_artifact_type', nestedTamper.generated_service_proof_artifact_type);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals', 'artifact_generated_preflight_artifact_type', nestedTamper.artifact_generated_preflight_artifact_type);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals', 'artifact_generated_service_proof_artifact_type', nestedTamper.artifact_generated_service_proof_artifact_type);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals', 'forged_inner_preflight_hash_refused', nestedTamper.forged_inner_preflight_hash_refused);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals', 'forged_inner_service_hash_refused', nestedTamper.forged_inner_service_hash_refused);
}
if (evidence.nested_artifact_binding_required === true) {
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'generated_preflight_artifact_type', nested.generated_preflight_artifact_type);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'generated_service_proof_artifact_type', nested.generated_service_proof_artifact_type);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'generated_preflight_artifact_body_sha256', nested.generated_preflight_artifact_body_sha256);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'generated_service_proof_artifact_body_sha256', nested.generated_service_proof_artifact_body_sha256);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'generated_preflight_artifact_verified', nested.generated_preflight_artifact_verified);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'generated_service_proof_artifact_verified', nested.generated_service_proof_artifact_verified);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'preflight_artifact_hash_bound', nested.preflight_artifact_hash_bound);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'service_proof_source_preflight_hash_bound', nested.service_proof_source_preflight_hash_bound);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'service_artifact_hash_bound', nested.service_artifact_hash_bound);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'service_artifact_verification_bound_to_service_proof', nested.service_artifact_verification_bound_to_service_proof);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'creates_public_external_attestation', nested.creates_public_external_attestation);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'proves_current_machine_governance', nested.proves_current_machine_governance);
  print('manifest.terminal_chain_refusal_evidence.nested_artifact_binding', 'proves_production_downstream_recognition', nested.proves_production_downstream_recognition);
}
print('manifest.terminal_chain_refusal_evidence', 'creates_public_external_attestation', evidence.creates_public_external_attestation);
print('manifest.terminal_chain_refusal_evidence', 'proves_current_machine_governance', evidence.proves_current_machine_governance);
print('manifest.terminal_chain_refusal_evidence', 'proves_production_downstream_recognition', evidence.proves_production_downstream_recognition);
NODE
            cat <<'EOF'
```
EOF
        fi
        if tag_at_least 3 4 25; then
            cat <<'EOF'

## Release-Forward Report Contract

```text
EOF
            if tag_at_least 3 4 41; then
                node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function printFlat(prefix, value) {
  if (Array.isArray(value)) {
    console.log(`${prefix}=${value.join(',')}`);
    return;
  }
  if (value && typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      printFlat(`${prefix}.${key}`, nested);
    }
    return;
  }
  console.log(`${prefix}=${value}`);
}

const manifest = readJson('DRY-RUN-MANIFEST.json');
const contract = manifest.release_forward_report_contract;
if (!contract || contract.enabled !== true) {
  throw new Error('missing manifest release-forward report contract');
}
printFlat('manifest.release_forward_report_contract', contract);
NODE
            else
            ZLAR_DRY_RUN_TARGET_TAG="${TAG}" node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function print(prefix, key, value) {
  console.log(`${prefix}.${key}=${value}`);
}

function targetAtLeast(tag, major, minor, patch) {
  const match = String(tag || '').match(/^v(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return false;
  const parts = match.slice(1).map(Number);
  if (parts[0] !== major) return parts[0] > major;
  if (parts[1] !== minor) return parts[1] > minor;
  return parts[2] >= patch;
}

const smoke = readJson('ZLAR/zlar-proof-smoke-sample-verification.json');
const northStar = readJson('ZLAR/zlar-north-star-readiness-v1.json');
const terminalChain = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 28)
  ? readJson('ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json')
  : null;
const terminalChainArtifact = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 28)
  ? readJson('ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json')
  : null;
const terminalChainArtifactVerification = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 30)
  ? readJson('ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json')
  : null;
const forgedInnerPreflightHashError = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 28)
  ? fs.readFileSync('ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt', 'utf8')
  : '';
const forgedInnerHashError = targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 28)
  ? fs.readFileSync('ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt', 'utf8')
  : '';
const enterpriseProfile = northStar.puzzle_pieces?.find((piece) => piece.id === 3)?.observed || {};
const downstreamRecognition = northStar.puzzle_pieces?.find((piece) => piece.id === 5)?.observed || {};
const groupKeys = [
  'no_usable_recognized_receipt_authority',
  'recognized_receipt_scope_mismatch',
  'route_or_request_authority_material_refused',
];

print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_count', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
for (const key of groupKeys) {
  print('proof_smoke.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids', key, (smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids?.[key] || []).join(','));
  print('north_star.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids', key, (northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids?.[key] || []).join(','));
}
print('north_star.counts', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required);
print('north_star.counts', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
print('north_star.counts', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_count', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
print('north_star.counts', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
print('north_star.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count', northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
print('north_star.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count', northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
if (targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 26)) {
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved', enterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_count', enterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count', enterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count', enterpriseProfile.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count', enterpriseProfile.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved', downstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved);
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_count', downstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_count);
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count', downstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count);
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count', downstreamRecognition.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count);
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count', downstreamRecognition.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count);
}
if (targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 39)) {
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count', smoke.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count);
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused', smoke.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused);
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids', (smoke.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids || []).join(','));
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes', (smoke.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes || []).join(','));
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256', smoke.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256);
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count);
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused);
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids', (smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids || []).join(','));
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes', (smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes || []).join(','));
  print('proof_smoke.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256);
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved', northStar.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved);
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count', northStar.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count);
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused', northStar.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused);
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids', (northStar.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids || []).join(','));
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes', (northStar.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes || []).join(','));
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256', northStar.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256);
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count', northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count);
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused', northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused);
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids', (northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids || []).join(','));
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes', (northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes || []).join(','));
  print('north_star.counts', 'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256', northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256);
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved', enterpriseProfile.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved);
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids', (enterpriseProfile.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids || []).join(','));
  print('north_star.puzzle_3.observed', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes', (enterpriseProfile.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes || []).join(','));
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved', downstreamRecognition.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved);
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids', (downstreamRecognition.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids || []).join(','));
  print('north_star.puzzle_5.observed', 'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes', (downstreamRecognition.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes || []).join(','));
}
if (targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 28)) {
  print('release_forward.terminal_chain_nested_artifact_tamper_refusals', 'generated_preflight_artifact_type', terminalChain.nested_artifacts?.generated_preflight_artifact?.artifact_type);
  print('release_forward.terminal_chain_nested_artifact_tamper_refusals', 'generated_service_proof_artifact_type', terminalChain.nested_artifacts?.generated_service_proof_artifact?.artifact_type);
  print('release_forward.terminal_chain_nested_artifact_tamper_refusals', 'artifact_generated_preflight_artifact_type', terminalChainArtifact.payload?.chain?.nested_artifacts?.generated_preflight_artifact?.artifact_type);
  print('release_forward.terminal_chain_nested_artifact_tamper_refusals', 'artifact_generated_service_proof_artifact_type', terminalChainArtifact.payload?.chain?.nested_artifacts?.generated_service_proof_artifact?.artifact_type);
  print('release_forward.terminal_chain_nested_artifact_tamper_refusals', 'forged_inner_preflight_hash_refused', forgedInnerPreflightHashError.includes('nested preflight artifact binding'));
  print('release_forward.terminal_chain_nested_artifact_tamper_refusals', 'forged_inner_service_hash_refused', forgedInnerHashError.includes('nested service proof artifact binding'));
}
if (targetAtLeast(process.env.ZLAR_DRY_RUN_TARGET_TAG, 3, 4, 30)) {
  const nested = terminalChainArtifactVerification.nested_artifact_binding || {};
  print('release_forward.terminal_chain_nested_artifact_binding', 'generated_preflight_artifact_type', nested.generated_preflight_artifact_type);
  print('release_forward.terminal_chain_nested_artifact_binding', 'generated_service_proof_artifact_type', nested.generated_service_proof_artifact_type);
  print('release_forward.terminal_chain_nested_artifact_binding', 'generated_preflight_artifact_body_sha256', nested.generated_preflight_artifact_body_sha256);
  print('release_forward.terminal_chain_nested_artifact_binding', 'generated_service_proof_artifact_body_sha256', nested.generated_service_proof_artifact_body_sha256);
  print('release_forward.terminal_chain_nested_artifact_binding', 'generated_preflight_artifact_verified', nested.generated_preflight_artifact_verified);
  print('release_forward.terminal_chain_nested_artifact_binding', 'generated_service_proof_artifact_verified', nested.generated_service_proof_artifact_verified);
  print('release_forward.terminal_chain_nested_artifact_binding', 'preflight_artifact_hash_bound', nested.preflight_artifact_hash_bound);
  print('release_forward.terminal_chain_nested_artifact_binding', 'service_proof_source_preflight_hash_bound', nested.service_proof_source_preflight_hash_bound);
  print('release_forward.terminal_chain_nested_artifact_binding', 'service_artifact_hash_bound', nested.service_artifact_hash_bound);
  print('release_forward.terminal_chain_nested_artifact_binding', 'service_artifact_verification_bound_to_service_proof', nested.service_artifact_verification_bound_to_service_proof);
  print('release_forward.terminal_chain_nested_artifact_binding', 'creates_public_external_attestation', nested.creates_public_external_attestation);
  print('release_forward.terminal_chain_nested_artifact_binding', 'proves_current_machine_governance', nested.proves_current_machine_governance);
  print('release_forward.terminal_chain_nested_artifact_binding', 'proves_production_downstream_recognition', nested.proves_production_downstream_recognition);
}
print('north_star.claim_boundary', 'public_external_attestation', northStar.claim_boundary?.public_external_attestation);
print('north_star.claim_boundary', 'production_authority', northStar.claim_boundary?.production_authority);
print('north_star.claim_boundary', 'current_machine_governance', northStar.claim_boundary?.current_machine_governance);
print('north_star.claim_boundary', 'live_mcp_coverage', northStar.claim_boundary?.live_mcp_coverage);
print('north_star.claim_boundary', 'unrouted_surface_coverage', northStar.claim_boundary?.unrouted_surface_coverage);
NODE
            fi
            cat <<'EOF'
```
EOF
        fi
        if tag_at_least 3 3 104; then
            cat <<'EOF'

## Private Verifier Result Intake

```text
EOF
            shasum -a 256 \
                ZLAR/zlar-private-verifier-result-v1.json \
                ZLAR/zlar-private-verifier-result-verification-v1.json
            cat <<'EOF'
```
EOF
        fi
        if tag_at_least 3 4 34; then
            cat <<'EOF'

## Private Result Verification Evidence

```text
EOF
            node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function print(prefix, key, value) {
  console.log(`${prefix}.${key}=${value}`);
}

const verification = readJson('ZLAR/zlar-private-verifier-result-verification-v1.json');
const hashVerification = verification.evidence_dir_hash_verification || {};
const contractVerification = verification.evidence_dir_contract_verification || {};
const privateNonOperatorPassValidated =
  verification.verified === true &&
  verification.intake_class === 'private-verifier-reply' &&
  verification.verdict === 'PASS' &&
  verification.completed_by_non_operator === true &&
  verification.private_by_default === true &&
  verification.evidence_model === 'release-forward-dry-run-artifacts' &&
  hashVerification.verified === true &&
  (contractVerification.required_for_target !== true ||
    contractVerification.verified === true) &&
  verification.public_external_attestation === false &&
  verification.public_attribution === false &&
  verification.non_operator_review_publicly_claimed === false &&
  verification.production_authority === false &&
  verification.enterprise_readiness === false &&
  verification.current_machine_governance === false &&
  verification.live_mcp_coverage === false &&
  verification.v3_4_0_readiness === false;

if (verification.verification_type !== 'zlar-private-verifier-result-verification-v1') {
  throw new Error('private verifier result verification type drifted');
}
if (verification.public_external_attestation !== false) {
  throw new Error('private verifier result verification must not claim public external attestation');
}
if (verification.public_attribution !== false) {
  throw new Error('private verifier result verification must not claim public attribution');
}
if (verification.non_operator_review_publicly_claimed !== false) {
  throw new Error('private verifier result verification must not claim public non-operator review');
}

print('private_result_verification', 'verification_type', verification.verification_type);
print('private_result_verification', 'verified', verification.verified);
print('private_result_verification', 'intake_class', verification.intake_class);
print('private_result_verification', 'verdict', verification.verdict);
print('private_result_verification', 'release_tag', verification.release_tag);
print('private_result_verification', 'result_sha256', verification.result_sha256);
print('private_result_verification', 'artifact_set_sha256', verification.artifact_set_sha256);
print('private_result_verification', 'evidence_model', verification.evidence_model);
print('private_result_verification', 'artifact_hash_count', verification.artifact_hash_count);
print('private_result_verification', 'required_identity.command_posture', verification.required_identity?.command_posture);
print('private_result_verification', 'required_identity.result_sha256_required', verification.required_identity?.result_sha256_required);
print('private_result_verification', 'required_identity.result_sha256_matched', verification.required_identity?.result_sha256_matched);
print('private_result_verification', 'required_identity.target_required', verification.required_identity?.target_required);
print('private_result_verification', 'required_identity.target_matched', verification.required_identity?.target_matched);
print('private_result_verification', 'required_identity.bundle_sha256_required', verification.required_identity?.bundle_sha256_required);
print('private_result_verification', 'required_identity.bundle_sha256_matched', verification.required_identity?.bundle_sha256_matched);
print('private_result_verification', 'required_identity.artifact_set_sha256_required', verification.required_identity?.artifact_set_sha256_required);
print('private_result_verification', 'required_identity.artifact_set_sha256_matched', verification.required_identity?.artifact_set_sha256_matched);
print('private_result_verification', 'required_identity.recomputed_evidence_required', verification.required_identity?.recomputed_evidence_required);
print('private_result_verification', 'required_identity.recomputed_evidence_matched', verification.required_identity?.recomputed_evidence_matched);
print('private_result_verification', 'evidence_dir_hashes_recomputed', hashVerification.hashes_recomputed);
print('private_result_verification', 'evidence_dir_hashes_verified', hashVerification.verified);
print('private_result_verification', 'evidence_dir_artifact_hash_count', hashVerification.artifact_hash_count);
print('private_result_verification', 'evidence_dir_contract_required_for_target', contractVerification.required_for_target);
print('private_result_verification', 'evidence_dir_contract_verified', contractVerification.verified);
print('private_result_verification', 'evidence_dir_contract_type', contractVerification.contract_type);
print('private_result_verification', 'evidence_dir_contract_source_path', contractVerification.source_path);
print('private_result_verification', 'terminal_chain_recognition_refusal_group_count', contractVerification.product_proof_path_terminal_chain_recognition_refusal_group_count);
print('private_result_verification', 'terminal_chain_recognition_refusal_group_case_count', contractVerification.product_proof_path_terminal_chain_recognition_refusal_group_case_count);
print('private_result_verification', 'terminal_chain_recognition_refusal_group_case_ids_preserved', contractVerification.product_proof_path_terminal_chain_recognition_refusal_group_case_ids_preserved);
print('private_result_verification', 'north_star_terminal_chain_recognition_refusal_group_case_ids_preserved', contractVerification.north_star_terminal_chain_recognition_refusal_group_case_ids_preserved);
print('private_result_verification', 'deployment_profile_authority_bridge_required_for_target', contractVerification.deployment_profile_authority_bridge_required_for_target);
print('private_result_verification', 'deployment_profile_authority_bridge_preserved', contractVerification.product_proof_path_deployment_profile_authority_bridge_preserved);
print('private_result_verification', 'north_star_deployment_profile_authority_bridge_preserved', contractVerification.north_star_deployment_profile_authority_bridge_preserved);
print('private_result_verification', 'deployment_profile_authority_bridge_refusal_case_count', contractVerification.deployment_profile_authority_bridge_refusal_case_count);
print('private_result_verification', 'deployment_profile_authority_refusals_required_for_target', contractVerification.deployment_profile_authority_refusals_required_for_target);
print('private_result_verification', 'deployment_profile_authority_refusals_preserved', contractVerification.product_proof_path_deployment_profile_authority_refusals_preserved);
print('private_result_verification', 'north_star_deployment_profile_authority_refusals_preserved', contractVerification.north_star_deployment_profile_authority_refusals_preserved);
print('private_result_verification', 'deployment_profile_authority_refusal_case_count', contractVerification.deployment_profile_authority_refusal_case_count);
print('private_result_verification', 'deployment_profile_authority_refusal_case_ids_preserved', contractVerification.deployment_profile_authority_refusal_case_ids_preserved);
print('private_result_verification', 'deployment_profile_authority_refusals_before_service_proof', contractVerification.deployment_profile_authority_refusals_before_service_proof);
print('private_result_verification', 'stale_deployment_profile_artifact_refused_before_service_proof', contractVerification.stale_deployment_profile_artifact_refused_before_service_proof);
print('private_result_verification', 'profile_recognition_mismatch_refused_before_service_proof', contractVerification.profile_recognition_mismatch_refused_before_service_proof);
print('private_result_verification', 'latest_profile_selection_refused_before_service_proof', contractVerification.latest_profile_selection_refused_before_service_proof);
print('private_result_verification', 'request_stream_authority_material_refused_before_service_proof', contractVerification.request_stream_authority_material_refused_before_service_proof);
print('private_result_verification', 'deployment_profile_authority_bridge_current_machine_governance', contractVerification.deployment_profile_authority_bridge_current_machine_governance);
print('private_result_verification', 'deployment_profile_authority_bridge_production_authority', contractVerification.deployment_profile_authority_bridge_production_authority);
print('private_result_verification', 'terminal_chain_trusted_registry_verdict_required_for_target', contractVerification.terminal_chain_trusted_registry_verdict_required_for_target);
print('private_result_verification', 'product_proof_path_terminal_chain_trusted_registry_verdict_preserved', contractVerification.product_proof_path_terminal_chain_trusted_registry_verdict_preserved);
print('private_result_verification', 'north_star_terminal_chain_trusted_registry_verdict_preserved', contractVerification.north_star_terminal_chain_trusted_registry_verdict_preserved);
print('private_result_verification', 'terminal_chain_trusted_registry_recognition_verdict', contractVerification.terminal_chain_trusted_registry_recognition_verdict);
print('private_result_verification', 'terminal_chain_trusted_registry_signature_valid', contractVerification.terminal_chain_trusted_registry_signature_valid);
print('private_result_verification', 'downstream_refusal_boundary_required_for_target', contractVerification.downstream_refusal_boundary_required_for_target);
print('private_result_verification', 'product_proof_path_downstream_refusal_boundary_preserved', contractVerification.product_proof_path_downstream_refusal_boundary_preserved);
print('private_result_verification', 'north_star_downstream_refusal_boundary_preserved', contractVerification.north_star_downstream_refusal_boundary_preserved);
print('private_result_verification', 'downstream_refusal_recognized_marker_count_delta', contractVerification.downstream_refusal_recognized_marker_count_delta);
print('private_result_verification', 'downstream_refusal_final_marker_count', contractVerification.downstream_refusal_final_marker_count);
print('private_result_verification', 'downstream_refusal_case_count', contractVerification.downstream_refusal_case_count);
print('private_result_verification', 'downstream_refusal_all_refusals_unboarded', contractVerification.downstream_refusal_all_refusals_unboarded);
print('private_result_verification', 'downstream_refusal_reasons', Array.isArray(contractVerification.downstream_refusal_reasons) ? contractVerification.downstream_refusal_reasons.join(',') : '');
print('private_result_verification', 'north_star_downstream_refusal_all_refusals_unboarded', contractVerification.north_star_downstream_refusal_all_refusals_unboarded);
print('private_result_verification', 'north_star_downstream_refusal_reasons', Array.isArray(contractVerification.north_star_downstream_refusal_reasons) ? contractVerification.north_star_downstream_refusal_reasons.join(',') : '');
print('private_result_verification', 'downstream_refusal_marker_count_deltas_zero', contractVerification.downstream_refusal_marker_count_deltas_zero);
print('private_result_verification', 'terminal_chain_recognized_receipt_path_mirror_required_for_target', contractVerification.terminal_chain_recognized_receipt_path_mirror_required_for_target);
print('private_result_verification', 'product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved', contractVerification.product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved);
print('private_result_verification', 'north_star_terminal_chain_recognized_receipt_path_mirror_preserved', contractVerification.north_star_terminal_chain_recognized_receipt_path_mirror_preserved);
print('private_result_verification', 'terminal_chain_recognized_receipt_path_evidence_sha256', contractVerification.terminal_chain_recognized_receipt_path_evidence_sha256);
print('private_result_verification', 'terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding', contractVerification.terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding);
print('private_result_verification', 'completed_by_non_operator', verification.completed_by_non_operator);
print('private_result_verification', 'private_by_default', verification.private_by_default);
print('private_result_verification', 'private_non_operator_pass_validated', privateNonOperatorPassValidated);
print('private_result_verification', 'public_external_attestation', verification.public_external_attestation);
print('private_result_verification', 'public_attribution', verification.public_attribution);
print('private_result_verification', 'non_operator_review_publicly_claimed', verification.non_operator_review_publicly_claimed);
print('private_result_verification', 'production_authority', verification.production_authority);
print('private_result_verification', 'enterprise_readiness', verification.enterprise_readiness);
print('private_result_verification', 'current_machine_governance', verification.current_machine_governance);
print('private_result_verification', 'live_mcp_coverage', verification.live_mcp_coverage);
print('private_result_verification', 'v3_4_0_readiness', verification.v3_4_0_readiness);
NODE
            cat <<'EOF'
```
EOF
        fi
        if tag_at_least 3 3 107; then
            cat <<'EOF'

## Private Intake Pointer Contract

```text
EOF
            node <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function print(prefix, key, value) {
  console.log(`${prefix}.${key}=${value}`);
}

const manifest = readJson('DRY-RUN-MANIFEST.json');
const readiness = readJson('ZLAR/zlar-north-star-readiness-v1.json');
const manifestPointer = manifest.private_verifier_result_sample || {};
const readinessPointer = readiness.puzzle_pieces
  ?.find((piece) => piece.id === 7)
  ?.observed
  ?.private_intake_sample_manifest_pointer || {};

if (manifestPointer.enabled !== true) {
  throw new Error('missing manifest private verifier result sample pointer');
}
if (readinessPointer.provided !== true) {
  throw new Error('missing readiness private intake sample manifest pointer');
}

print('manifest.private_verifier_result_sample', 'enabled', manifestPointer.enabled);
print('manifest.private_verifier_result_sample', 'evidence_model', manifestPointer.evidence_model);
print('manifest.private_verifier_result_sample', 'envelope_path', manifestPointer.envelope_path);
print('manifest.private_verifier_result_sample', 'verification_path', manifestPointer.verification_path);
print('manifest.private_verifier_result_sample', 'result_file', manifestPointer.result_file);
print('manifest.private_verifier_result_sample', 'result_section', manifestPointer.result_section);
print('manifest.private_verifier_result_sample', 'hash_record_location', manifestPointer.hash_record_location);
print('manifest.private_verifier_result_sample', 'included_in_core_artifact_hashes', manifestPointer.included_in_core_artifact_hashes);
print('manifest.private_verifier_result_sample', 'circular_hash_avoided', manifestPointer.circular_hash_avoided);
print('manifest.private_verifier_result_sample', 'creates_public_external_attestation', manifestPointer.creates_public_external_attestation);
print('manifest.private_verifier_result_sample', 'proves_non_operator_review', manifestPointer.proves_non_operator_review);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'provided', readinessPointer.provided);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'evidence_model', readinessPointer.evidence_model);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'release_tag', readinessPointer.release_tag);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'manifest_field', readinessPointer.manifest_field);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'result_file', readinessPointer.result_file);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'result_section', readinessPointer.result_section);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'hash_record_location', readinessPointer.hash_record_location);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'included_in_core_artifact_hashes', readinessPointer.included_in_core_artifact_hashes);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'circular_hash_avoided', readinessPointer.circular_hash_avoided);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'creates_public_external_attestation', readinessPointer.creates_public_external_attestation);
print('readiness.puzzle_7.private_intake_sample_manifest_pointer', 'proves_non_operator_review', readinessPointer.proves_non_operator_review);
NODE
            cat <<'EOF'
```
EOF
        fi
    } > "${OUTPUT_DIR}/DRY-RUN-RESULT.md"
}

write_private_verifier_result_files() {
    local generated_at
    generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    PRIVATE_VERIFIER_RESULT_GENERATED_AT="${generated_at}" \
        PRIVATE_VERIFIER_RESULT_TAG="${TAG}" \
        PRIVATE_VERIFIER_RESULT_EXPECTED_SHA="${EXPECTED_SHA}" \
        PRIVATE_VERIFIER_RESULT_COMMIT_SHA="$(cat "${OUTPUT_DIR}/target-head.txt")" \
        node <<'NODE'
const crypto = require('crypto');
const fs = require('fs');

function sha256(path) {
  return crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');
}

function parseSums(path, prefix = '') {
  return fs.readFileSync(path, 'utf8')
    .trim()
    .split(/\n+/)
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^([0-9a-f]{64})  (.+)$/);
      if (!match) {
        throw new Error(`invalid checksum line in ${path}: ${line}`);
      }
      return { path: `${prefix}${match[2]}`, sha256: match[1] };
    });
}

const artifactHashes = [
  { path: 'DRY-RUN-MANIFEST.json', sha256: sha256('DRY-RUN-MANIFEST.json') },
  { path: 'SHA256SUMS', sha256: sha256('SHA256SUMS') },
  { path: 'RUN-SHA256SUMS', sha256: sha256('RUN-SHA256SUMS') },
  ...parseSums('SHA256SUMS', 'ZLAR/'),
];

const report = {
  report_type: 'zlar-private-verifier-result-v1',
  schema_version: 1,
  generated_at: process.env.PRIVATE_VERIFIER_RESULT_GENERATED_AT,
  intake_class: 'sample-fixture',
  target: {
    release_tag: process.env.PRIVATE_VERIFIER_RESULT_TAG,
    expected_commit_sha: process.env.PRIVATE_VERIFIER_RESULT_EXPECTED_SHA,
    commit_sha: process.env.PRIVATE_VERIFIER_RESULT_COMMIT_SHA,
    moving_target_used: false,
  },
  verifier: {
    public_label: 'release-forward-private-verifier-result-fixture',
    relationship_to_zlar: 'release-forward dry-run generated sample only; no real verifier identity or public attribution',
    identity_public: false,
    contact_public: false,
  },
  custody: {
    source_channel_recorded_privately: false,
    received_timestamp_recorded_privately: false,
    raw_reply_publicly_committed: false,
    private_storage_required: true,
    public_repo_material_contains_private_identity: false,
  },
  review_result: {
    verdict: 'PASS',
    completed_by_non_operator: false,
    commands_completed_without_usage_coaching: true,
    used_explicit_release_tag: true,
    used_expected_commit_sha: true,
    used_latest: false,
    result_summary: 'Release-forward dry-run generated sample proving private intake artifact hashes for this packet only; it is not a real verifier reply.',
  },
  evidence: {
    evidence_model: 'release-forward-dry-run-artifacts',
    received_bundle_sha256: sha256('SHA256SUMS'),
    archive_integrity_checked: true,
    checksum_verification_checked: true,
    json_artifacts_validated: true,
    latest_substitution_scan_passed: true,
    identity_secret_scan_passed: true,
    artifact_hashes: artifactHashes,
  },
  privacy: {
    private_by_default: true,
    public_attribution_approved: false,
    public_external_attestation_approved: false,
    verifier_identity_public: false,
    verifier_contact_public: false,
    private_contact_included: false,
    private_paths_included: false,
    credentials_included: false,
  },
  claim_boundary: {
    private_intake_only: true,
    public_external_attestation: false,
    public_attribution: false,
    non_operator_review_publicly_claimed: false,
    production_authority: false,
    enterprise_readiness: false,
    sovereign_recognition: false,
    current_machine_governance: false,
    live_mcp_coverage: false,
    live_approval_channel_health: false,
    live_trust_registry_state: false,
    key_custody: false,
    revocation_truth: false,
    production_downstream_recognition: false,
    unrouted_surface_coverage: false,
    v3_4_0_readiness: false,
  },
  non_claims: [
    'This result is private/internal intake only unless separate public disclosure is approved.',
    'This result does not create public external attestation.',
    'This result does not create public attribution.',
    'This result does not prove production authority, enterprise readiness, or sovereign recognition.',
    'This result does not prove current-machine governance, live MCP coverage, or approval-channel health.',
    'This result does not prove key custody, revocation truth, live trust-registry state, or production downstream recognition.',
    'This result does not prove v3.4.0 readiness or coverage of unrouted surfaces.',
  ],
};

if (report.target.expected_commit_sha !== report.target.commit_sha) {
  throw new Error('private verifier result target SHA mismatch');
}

fs.writeFileSync('ZLAR/zlar-private-verifier-result-v1.json', `${JSON.stringify(report, null, 2)}\n`);
NODE

    local private_result_sha=""
    local private_result_identity=""
    local private_result_bundle_sha=""
    local private_result_artifact_set_sha=""
    if private_verifier_required_identity_expected; then
        private_result_sha="$(shasum -a 256 ZLAR/zlar-private-verifier-result-v1.json)"
        private_result_sha="${private_result_sha%% *}"
        private_result_identity="$(
            cd ZLAR &&
                node --input-type=module -e 'import { readFileSync } from "node:fs"; import { privateVerifierArtifactSetSha256 } from "./lib/private-verifier-result.mjs"; const result = JSON.parse(readFileSync("zlar-private-verifier-result-v1.json", "utf8")); console.log(result.evidence.received_bundle_sha256 + " " + privateVerifierArtifactSetSha256(result.evidence.artifact_hashes));'
        )"
        private_result_bundle_sha="${private_result_identity%% *}"
        private_result_artifact_set_sha="${private_result_identity#* }"
    fi

    set +e
    if private_verifier_required_identity_expected; then
        (
            cd ZLAR &&
                bin/zlar private-verifier-result verify \
                    --input zlar-private-verifier-result-v1.json \
                    --evidence-dir .. \
                    --require-result-sha "${private_result_sha}" \
                    --require-target "${TAG}@${EXPECTED_SHA}" \
                    --require-bundle-sha "${private_result_bundle_sha}" \
                    --require-artifact-set-sha "${private_result_artifact_set_sha}" \
                    --require-recomputed-evidence \
                    --json > zlar-private-verifier-result-verification-v1.json
        )
    else
        (
            cd ZLAR &&
                bin/zlar private-verifier-result verify \
                    --input zlar-private-verifier-result-v1.json \
                    --evidence-dir .. \
                    --json > zlar-private-verifier-result-verification-v1.json
        )
    fi
    local ec=$?
    set -e
    if [ "${ec}" -ne 0 ]; then
        fail "private verifier result verification failed with exit ${ec}"
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --release-tag|--tag)
            require_value "$1" "${2:-}"
            TAG="$2"
            shift 2
            ;;
        --expected-commit-sha|--sha)
            require_value "$1" "${2:-}"
            EXPECTED_SHA="$2"
            shift 2
            ;;
        --out-dir|--output-dir)
            require_value "$1" "${2:-}"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --repo-url)
            require_value "$1" "${2:-}"
            REPO_URL="$2"
            shift 2
            ;;
        --trusted-issuer-completion-proof)
            require_value "$1" "${2:-}"
            TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF="$2"
            shift 2
            ;;
        --plan-only)
            PLAN_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

validate_tag
validate_sha
validate_trusted_receipt_issuer_completion_proof_scope

if [ "${PLAN_ONLY}" -eq 1 ]; then
    printf 'ZLAR release-forward verifier dry-run plan\n'
    printf 'target_tag=%s\n' "${TAG}"
    printf 'expected_sha=%s\n' "${EXPECTED_SHA}"
    print_boundary
    printf '\ncommands:\n'
    print_command_plan
    exit 0
fi

if [ -z "${OUTPUT_DIR}" ]; then
    fail "--out-dir is required unless --plan-only is used"
fi
if [ -e "${OUTPUT_DIR}" ]; then
    if [ ! -d "${OUTPUT_DIR}" ]; then
        fail "--out-dir exists and is not a directory"
    fi
    if [ -n "$(find "${OUTPUT_DIR}" -mindepth 1 -maxdepth 1 | sed -n '1p')" ]; then
        fail "--out-dir must be empty"
    fi
fi
if [ -z "${REPO_URL}" ]; then
    fail "--repo-url is required for current private-core source checkouts"
fi

require_cmd git
require_cmd bash
require_cmd node
require_cmd openssl
require_cmd shasum
require_cmd gzip
require_cmd cp
require_cmd tee
require_cmd find
require_cmd sed

prepare_output_dir
prepare_trusted_receipt_issuer_completion_proof
print_command_plan > "${OUTPUT_DIR}/COMMANDS.txt"
if grep -Eq '(^|[[:space:]])--latest([[:space:]]|$)' "${OUTPUT_DIR}/COMMANDS.txt"; then
    fail "internal command plan unexpectedly contains --latest"
fi

TRANSCRIPT_FILE="${OUTPUT_DIR}/transcript.txt"
: > "${TRANSCRIPT_FILE}"

{
    printf 'ZLAR release-forward verifier local dry run\n'
    printf 'started_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'target_tag=%s\n' "${TAG}"
    printf 'expected_sha=%s\n' "${EXPECTED_SHA}"
    printf 'output_dir=<dry-run-output-dir>\n'
    print_boundary
} | tee -a "${TRANSCRIPT_FILE}"

cd "${OUTPUT_DIR}"
run_cmd git clone "${REPO_URL}" ZLAR
cd ZLAR
run_cmd git checkout "${TAG}"
observed_sha="$(git rev-parse HEAD)"
printf '%s\n' "${observed_sha}" > "${OUTPUT_DIR}/target-head.txt"
git status --short --branch > "${OUTPUT_DIR}/target-status.txt"
if [ "${observed_sha}" != "${EXPECTED_SHA}" ]; then
    fail "checked-out commit ${observed_sha} did not match expected ${EXPECTED_SHA}"
fi
guard_checkout_trusted_receipt_issuer_completion_proof

run_shell "bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json"
run_shell "bash tools/build-verifier-kit.sh --check-env"
run_shell "openssl genpkey -algorithm ED25519 -out /dev/null"
run_shell "bin/zlar proof-smoke"
run_shell "bin/zlar proof-smoke --json > zlar-proof-smoke-v1.json"
run_shell "bin/zlar proof-smoke verify --input zlar-proof-smoke-v1.json --json > zlar-proof-smoke-generated-verification.json"
run_shell "bin/zlar proof-smoke verify --sample"
run_shell "bin/zlar proof-smoke verify --sample --json > zlar-proof-smoke-sample-verification.json"
run_shell "bin/zlar protected-records-service-preflight verify --sample"
run_shell "bin/zlar protected-records-service-preflight verify --sample --json > zlar-service-preflight-sample-verification.json"
run_shell "bin/zlar local-proof-pack verify --sample"
run_shell "bin/zlar local-proof-pack verify --sample --json > zlar-local-proof-pack-sample-verification.json"
run_shell "bin/zlar issuer-status-proof"
run_shell "bin/zlar issuer-status-proof --json > zlar-issuer-status-proof.json"
run_shell "bash tools/build-verifier-kit.sh"
if tag_at_least 3 3 100; then
    run_shell "bin/zlar verifier-kit-reproducibility --json-out zlar-verifier-kit-reproducibility-v1.json"
fi
if public_release_assets_expected; then
    run_shell "mkdir -p zlar-verifier-kit-release-assets"
    run_shell "bin/zlar verifier-kit-release-assets-live-read --release-tag ${TAG} --download-dir zlar-verifier-kit-release-assets --json-out zlar-verifier-kit-release-assets-v1.json"
    run_shell "bin/zlar verifier-kit-public-distribution --release-tag ${TAG} --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --require-public --json-out zlar-verifier-kit-public-distribution-v1.json"
elif tag_at_least 3 3 109; then
    run_shell "node --input-type=module -e \"import { writeFileSync } from 'node:fs'; writeFileSync('zlar-verifier-kit-release-assets-v1.json', JSON.stringify({ tagName: '${TAG}', url: 'not-queried-release-forward-dry-run', evidence_model: 'release-forward-local-no-assets-fixture', assets: [] }, null, 2) + '\\n');\""
    run_shell "bin/zlar verifier-kit-public-distribution --release-tag ${TAG} --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --json-out zlar-verifier-kit-public-distribution-v1.json"
fi
run_shell "( cd dist/zlar-verifier-kit-v0.1.0 && node verify-issuer-status.mjs )"
if tag_at_least 3 3 94; then
    run_shell "( cd dist/zlar-verifier-kit-v0.1.0 && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample )"
    run_shell "( cd dist/zlar-verifier-kit-v0.1.0 && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample --json > ../../zlar-trusted-receipt-issuer-recognition.json )"
fi
if tag_at_least 3 3 97; then
    run_shell "node --input-type=module -e \"import { readFileSync, writeFileSync } from 'node:fs'; const r = JSON.parse(readFileSync('dist/zlar-verifier-kit-v0.1.0/examples/trusted-receipt-issuers-v1.json', 'utf8')); r.production_authority = true; writeFileSync('zlar-trusted-receipt-issuer-recognition-malformed-registry.json', JSON.stringify(r, null, 2) + '\\n');\""
    run_expected_shell 2 \
        "zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt" \
        "node dist/zlar-verifier-kit-v0.1.0/verify-recognition.mjs --receipt dist/zlar-verifier-kit-v0.1.0/examples/sample-receipt.json --registry zlar-trusted-receipt-issuer-recognition-malformed-registry.json --scope verifier-kit-sample"
fi
run_shell "( cd dist/zlar-verifier-kit-v0.1.0 && bash external-runner-dry-run.sh --issuer-status-json-out ../../zlar-verifier-kit-issuer-status-fixture.json )"
if tag_at_least 3 4 21; then
    run_shell "ZLAR_RELEASE_FORWARD_TARGET_TAG=${TAG} ZLAR_RELEASE_FORWARD_EXPECTED_SHA=${EXPECTED_SHA} ZLAR_RELEASE_FORWARD_OBSERVED_SHA=$(git rev-parse HEAD) node tools/verifier-kit-external-runner-diagnostics.mjs --json-out zlar-verifier-kit-external-runner-diagnostics-v1.json"
fi
run_shell "bin/zlar protected-records-runtime-local-activation verify --sample"
run_shell "bin/zlar protected-records-runtime-local-activation verify --sample --json > zlar-runtime-local-activation-sample-verification.json"
run_shell "bin/zlar protected-records-runtime-profile-installation verify --sample"
run_shell "bin/zlar protected-records-runtime-profile-installation verify --sample --json > zlar-runtime-profile-installation-sample-verification.json"
if tag_at_least 3 4 5; then
    run_shell "bin/zlar protected-records-installed-runtime-profile-preflight verify --sample"
    run_shell "bin/zlar protected-records-installed-runtime-profile-preflight verify --sample --json > zlar-installed-runtime-profile-preflight-sample-verification.json"
fi
if tag_at_least 3 4 7; then
    run_shell "bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample"
    run_shell "bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --json > zlar-installed-runtime-profile-recognition-proof-v1.json"
fi
if tag_at_least 3 4 8; then
    run_shell "bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --artifact zlar-installed-runtime-profile-recognition-proof-artifact-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json --json > zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json"
fi
if tag_at_least 3 4 11; then
    run_shell "bin/zlar protected-records-installed-runtime-profile-service-proof --sample"
    run_shell "bin/zlar protected-records-installed-runtime-profile-service-proof --sample --json > zlar-installed-runtime-profile-service-proof-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-service-proof --sample --artifact zlar-installed-runtime-profile-service-proof-artifact-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json --json > zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json"
fi
if tag_at_least 3 4 15; then
    run_shell "bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample"
    run_shell "bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --json > zlar-installed-runtime-profile-terminal-chain-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --artifact zlar-installed-runtime-profile-terminal-chain-artifact-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json"
    run_shell "bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json --json > zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json"
fi
if tag_at_least 3 4 28; then
    run_shell "node --input-type=module -e \"import { readFileSync, writeFileSync } from 'node:fs'; import { canonicalize } from './lib/canonicalize.mjs'; import { sha256hex } from './lib/receipt.mjs'; const artifact = JSON.parse(readFileSync('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json', 'utf8')); artifact.payload.chain.generated_preflight.artifact_body_sha256 = 'e'.repeat(64); artifact.payload.chain.generated_service_proof.source_preflight_body_sha256 = 'e'.repeat(64); artifact.integrity.body_sha256 = sha256hex(canonicalize(artifact.payload)); writeFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json', JSON.stringify(artifact, null, 2) + '\\n');\""
    run_expected_shell 1 "zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt" "bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json"
    run_shell "node --input-type=module -e \"import { readFileSync, writeFileSync } from 'node:fs'; import { canonicalize } from './lib/canonicalize.mjs'; import { sha256hex } from './lib/receipt.mjs'; const artifact = JSON.parse(readFileSync('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json', 'utf8')); artifact.payload.chain.generated_service_proof.artifact_body_sha256 = 'f'.repeat(64); artifact.payload.chain.generated_service_proof.verification_body_sha256 = 'f'.repeat(64); artifact.integrity.body_sha256 = sha256hex(canonicalize(artifact.payload)); writeFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json', JSON.stringify(artifact, null, 2) + '\\n');\""
    run_expected_shell 1 "zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt" "bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json"
fi
if tag_at_least 3 4 9; then
    run_shell "bin/zlar product-proof-path --json-out zlar-product-proof-path-v1.json"
fi
run_shell "bin/zlar coverage --sample --require-governed"
run_shell "bin/zlar coverage --sample --require-governed --json > zlar-coverage-map-sample.json"
if tag_at_least 3 4 53; then
    if [ -n "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" ]; then
        run_cmd cp "${TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF}" zlar-trusted-receipt-issuer-completion-proof-v1.json
        run_shell "bin/zlar trusted-receipt-issuer-completion-proof verify --input zlar-trusted-receipt-issuer-completion-proof-v1.json --json > zlar-trusted-receipt-issuer-completion-proof-verification-v1.json"
    fi
fi
if tag_at_least 3 3 98; then
    if tag_at_least 3 3 107; then
        run_shell "bin/zlar north-star-readiness --evidence-dir . --release-tag ${TAG} --json > zlar-north-star-readiness-v1.json"
    else
        run_shell "bin/zlar north-star-readiness --evidence-dir . --json > zlar-north-star-readiness-v1.json"
    fi
fi
run_shell "bash tests/test-receipt-authority-copy.sh"

write_assertions > "${OUTPUT_DIR}/ASSERTIONS.txt"
tee -a "${TRANSCRIPT_FILE}" < "${OUTPUT_DIR}/ASSERTIONS.txt"

shasum -a 256 \
    zlar-verifier-env-report-v0.json \
    zlar-proof-smoke-v1.json \
    zlar-proof-smoke-generated-verification.json \
    zlar-proof-smoke-sample-verification.json \
    zlar-service-preflight-sample-verification.json \
    zlar-local-proof-pack-sample-verification.json \
    zlar-issuer-status-proof.json \
    zlar-verifier-kit-issuer-status-fixture.json \
    zlar-runtime-local-activation-sample-verification.json \
    zlar-runtime-profile-installation-sample-verification.json \
    zlar-coverage-map-sample.json \
    > "${OUTPUT_DIR}/SHA256SUMS"
if tag_at_least 3 4 5; then
    shasum -a 256 zlar-installed-runtime-profile-preflight-sample-verification.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 4 7; then
    shasum -a 256 zlar-installed-runtime-profile-recognition-proof-v1.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 4 8; then
    shasum -a 256 zlar-installed-runtime-profile-recognition-proof-artifact-v1.json >> "${OUTPUT_DIR}/SHA256SUMS"
    shasum -a 256 zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 4 11; then
    {
        shasum -a 256 zlar-installed-runtime-profile-service-proof-v1.json
        shasum -a 256 zlar-installed-runtime-profile-service-proof-artifact-v1.json
        shasum -a 256 zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json
    } >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 4 15; then
    {
        shasum -a 256 zlar-installed-runtime-profile-terminal-chain-v1.json
        shasum -a 256 zlar-installed-runtime-profile-terminal-chain-artifact-v1.json
        shasum -a 256 zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json
    } >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 4 28; then
    {
        shasum -a 256 zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json
        shasum -a 256 zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt
        shasum -a 256 zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json
        shasum -a 256 zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt
    } >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 4 9; then
    shasum -a 256 zlar-product-proof-path-v1.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 3 98; then
    shasum -a 256 zlar-north-star-readiness-v1.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 3 100; then
    shasum -a 256 zlar-verifier-kit-reproducibility-v1.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 4 21; then
    shasum -a 256 zlar-verifier-kit-external-runner-diagnostics-v1.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 3 109; then
    shasum -a 256 \
        zlar-verifier-kit-release-assets-v1.json \
        zlar-verifier-kit-public-distribution-v1.json \
        >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 3 94; then
    shasum -a 256 zlar-trusted-receipt-issuer-recognition.json >> "${OUTPUT_DIR}/SHA256SUMS"
fi
if tag_at_least 3 3 97; then
    shasum -a 256 \
        zlar-trusted-receipt-issuer-recognition-malformed-registry.json \
        zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt \
        >> "${OUTPUT_DIR}/SHA256SUMS"
fi

cd "${OUTPUT_DIR}"

{
    printf '\ncompleted_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'result=PASS\n'
    printf 'evidence_root=<dry-run-output-dir>\n'
} | tee -a "${TRANSCRIPT_FILE}"

shasum -a 256 transcript.txt COMMANDS.txt ASSERTIONS.txt target-head.txt target-status.txt SHA256SUMS > RUN-SHA256SUMS
write_manifest_file
if tag_at_least 3 3 104; then
    write_private_verifier_result_files
fi
write_result_file
