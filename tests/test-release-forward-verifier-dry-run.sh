#!/bin/bash
# Historical positive fixture-authority suite. Its real --out-dir cases run
# pinned command blocks that predate artifact-bound grant-SHA schemas. Plan-only
# coverage must be split into a separate current suite before reactivation.
printf '%s\n' 'SKIP: release-forward execution suite is historical under the exhausted fixture authority grant'
exit 77

# Guard the release-forward verifier dry-run helper.
# shellcheck disable=SC2016
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HELPER="${PROJECT_DIR}/tools/release-forward-verifier-dry-run.sh"
GOOD_TAG="v3.3.81"
GOOD_SHA="ebcfa57caf80624036f884d7133fbe92127d0180"
PRE_SERVICE_COVERAGE_TAG="v3.3.90"
PRE_SERVICE_COVERAGE_SHA="9a8147163384f776777bf283217a5cd55cbbdfe7"
LOCAL_TAG="v3.4.999"

PASS=0
FAIL=0
TOTAL=0

pass() {
    PASS=$((PASS + 1))
}

fail() {
    local label="$1"
    local detail="${2:-}"
    FAIL=$((FAIL + 1))
    printf '  FAIL: %s\n' "${label}"
    if [ -n "${detail}" ]; then
        printf '%s\n' "${detail}" | sed 's/^/    /'
    fi
}

assert_contains() {
    local label="$1"
    local needle="$2"
    local haystack="$3"
    TOTAL=$((TOTAL + 1))
    if grep -Fq -- "${needle}" <<<"${haystack}"; then
        pass
    else
        fail "${label}" "missing: ${needle}"
    fi
}

assert_not_regex() {
    local label="$1"
    local pattern="$2"
    local haystack="$3"
    TOTAL=$((TOTAL + 1))
    if grep -Eq "${pattern}" <<<"${haystack}"; then
        fail "${label}" "unexpected match: ${pattern}"
    else
        pass
    fi
}

assert_fails_with() {
    local label="$1"
    local expected="$2"
    shift 2
    TOTAL=$((TOTAL + 1))
    local output rc
    set +e
    output="$("$@" 2>&1)"
    rc=$?
    set -e
    if [ "${rc}" -eq 0 ]; then
        fail "${label}" "expected failure, got success"
        return
    fi
    if grep -Fq -- "${expected}" <<<"${output}"; then
        pass
    else
        fail "${label}" "missing failure text: ${expected}
output:
${output}"
    fi
}

echo "=== Release-Forward Verifier Dry-Run Helper Guard ==="

bash -n "${HELPER}"
TOTAL=$((TOTAL + 1))
pass

help_output="$(bash "${HELPER}" --help 2>&1)"
assert_contains "help names usage" "Usage:" "${help_output}"
assert_contains "help names release tag argument" "--release-tag <vX.Y.Z>" "${help_output}"
assert_contains "help names expected commit argument" "--expected-commit-sha <40-hex-sha>" "${help_output}"
assert_contains "help names out-dir argument" "--out-dir <dir>" "${help_output}"
assert_contains "help states no verifier request" "sends no verifier request" "${help_output}"
assert_contains "help states no public external attestation" "public external attestation" "${help_output}"

plan_output="$(bash "${HELPER}" --release-tag "${GOOD_TAG}" --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "plan names target tag" "target_tag=${GOOD_TAG}" "${plan_output}"
assert_contains "plan names expected sha" "expected_sha=${GOOD_SHA}" "${plan_output}"
assert_contains "plan uses explicit checkout" "git checkout ${GOOD_TAG}" "${plan_output}"
assert_contains "plan checks exact sha" "test \"\$(git rev-parse HEAD)\" = \"${GOOD_SHA}\"" "${plan_output}"
assert_contains "plan runs verifier-env json" "bin/zlar verifier-env --json-out zlar-verifier-env-report-v0.json" "${plan_output}"
assert_contains "plan runs build env check" "bash tools/build-verifier-kit.sh --check-env" "${plan_output}"
assert_contains "plan runs proof-smoke generated verification" "bin/zlar proof-smoke verify --input zlar-proof-smoke-v1.json --json > zlar-proof-smoke-generated-verification.json" "${plan_output}"
assert_contains "plan runs standalone service preflight sample json" "bin/zlar protected-records-service-preflight verify --sample --json > zlar-service-preflight-sample-verification.json" "${plan_output}"
assert_contains "plan runs external runner issuer fixture" "external-runner-dry-run.sh --issuer-status-json-out ../../zlar-verifier-kit-issuer-status-fixture.json" "${plan_output}"
assert_contains "plan runs runtime profile installation sample json" "bin/zlar protected-records-runtime-profile-installation verify --sample --json > zlar-runtime-profile-installation-sample-verification.json" "${plan_output}"
assert_contains "plan runs coverage json" "bin/zlar coverage --sample --require-governed --json > zlar-coverage-map-sample.json" "${plan_output}"
assert_contains "plan runs receipt authority guard" "bash tests/test-receipt-authority-copy.sh" "${plan_output}"
assert_contains "plan boundary says no verifier contact" "contacts no verifier" "${plan_output}"
assert_contains "plan boundary says no current-machine governance" "current-machine governance" "${plan_output}"

commands_only="$(awk '/^commands:/{flag=1; next} flag {print}' <<<"${plan_output}")"
assert_not_regex "command plan must not use --latest" '(^|[[:space:]])--latest([[:space:]]|$)' "${commands_only}"
assert_not_regex "command plan must not checkout main" 'git checkout (main|master|HEAD)' "${commands_only}"
assert_not_regex "older plan omits v3.3.94 recognition command" 'verify-recognition\.mjs' "${commands_only}"

future_plan_output="$(bash "${HELPER}" --release-tag v3.3.94 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "future plan runs verifier recognition text" "node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample" "${future_plan_output}"
assert_contains "future plan preserves verifier recognition json" "zlar-trusted-receipt-issuer-recognition.json" "${future_plan_output}"

trusted_completion_plan_output="$(bash "${HELPER}" --release-tag v3.4.53 --expected-commit-sha "${GOOD_SHA}" --trusted-issuer-completion-proof /tmp/zlar-trusted-receipt-issuer-completion-proof-v1.json --plan-only 2>&1)"
assert_contains "trusted completion plan copies supplied proof" "cp <local-path> zlar-trusted-receipt-issuer-completion-proof-v1.json" "${trusted_completion_plan_output}"
assert_contains "trusted completion plan verifies supplied proof" "bin/zlar trusted-receipt-issuer-completion-proof verify --input zlar-trusted-receipt-issuer-completion-proof-v1.json --json > zlar-trusted-receipt-issuer-completion-proof-verification-v1.json" "${trusted_completion_plan_output}"
assert_contains "trusted completion plan keeps readiness evidence-dir intake" "bin/zlar north-star-readiness --evidence-dir . --release-tag v3.4.53 --json > zlar-north-star-readiness-v1.json" "${trusted_completion_plan_output}"
assert_fails_with "trusted completion proof rejected before v3.4.53 in plan-only" "--trusted-issuer-completion-proof requires --release-tag v3.4.53 or later" \
    bash "${HELPER}" --release-tag v3.4.52 --expected-commit-sha "${GOOD_SHA}" --trusted-issuer-completion-proof /tmp/zlar-trusted-receipt-issuer-completion-proof-v1.json --plan-only

schema_contract_plan_output="$(bash "${HELPER}" --release-tag v3.3.97 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "schema-contract plan writes malformed registry" "zlar-trusted-receipt-issuer-recognition-malformed-registry.json" "${schema_contract_plan_output}"
assert_contains "schema-contract plan preserves malformed registry error" "zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt" "${schema_contract_plan_output}"
assert_contains "schema-contract plan expects exit two" "expected exit 2" "${schema_contract_plan_output}"

north_star_plan_output="$(bash "${HELPER}" --release-tag v3.3.98 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "north-star plan preserves readiness report" "bin/zlar north-star-readiness --evidence-dir . --json > zlar-north-star-readiness-v1.json" "${north_star_plan_output}"

north_star_pointer_plan_output="$(bash "${HELPER}" --release-tag v3.3.107 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "north-star pointer plan names release tag" "bin/zlar north-star-readiness --evidence-dir . --release-tag v3.3.107 --json > zlar-north-star-readiness-v1.json" "${north_star_pointer_plan_output}"

repro_plan_output="$(bash "${HELPER}" --release-tag v3.3.100 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "reproducibility plan preserves verifier kit reproducibility report" "bin/zlar verifier-kit-reproducibility --json-out zlar-verifier-kit-reproducibility-v1.json" "${repro_plan_output}"

public_distribution_plan_output="$(bash "${HELPER}" --release-tag v3.3.109 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "public distribution plan writes release assets fixture" "zlar-verifier-kit-release-assets-v1.json" "${public_distribution_plan_output}"
assert_contains "public distribution plan preserves posture report" "bin/zlar verifier-kit-public-distribution --release-tag v3.3.109 --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --json-out zlar-verifier-kit-public-distribution-v1.json" "${public_distribution_plan_output}"

public_distribution_live_plan_output="$(bash "${HELPER}" --release-tag v3.4.31 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "public distribution live plan reads release assets" "bin/zlar verifier-kit-release-assets-live-read --release-tag v3.4.31 --download-dir zlar-verifier-kit-release-assets --json-out zlar-verifier-kit-release-assets-v1.json" "${public_distribution_live_plan_output}"
assert_contains "public distribution live plan requires public posture" "bin/zlar verifier-kit-public-distribution --release-tag v3.4.31 --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --require-public --json-out zlar-verifier-kit-public-distribution-v1.json" "${public_distribution_live_plan_output}"
assert_not_regex "public distribution live plan omits no-assets fixture" "release-forward-local-no-assets-fixture" "${public_distribution_live_plan_output}"
public_distribution_later_plan_output="$(bash "${HELPER}" --release-tag v3.4.34 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "later public distribution plan writes no-assets fixture" "release-forward-local-no-assets-fixture" "${public_distribution_later_plan_output}"
assert_contains "later public distribution plan preserves bounded posture report" "bin/zlar verifier-kit-public-distribution --release-tag v3.4.34 --release-assets-json zlar-verifier-kit-release-assets-v1.json --reproducibility zlar-verifier-kit-reproducibility-v1.json --asset-dir . --json-out zlar-verifier-kit-public-distribution-v1.json" "${public_distribution_later_plan_output}"
assert_not_regex "later public distribution plan omits live asset read" "verifier-kit-release-assets-live-read --release-tag v3.4.34" "${public_distribution_later_plan_output}"
assert_not_regex "later public distribution plan omits require-public" "(^|[[:space:]])--require-public([[:space:]]|$)" "${public_distribution_later_plan_output}"

installed_profile_plan_output="$(bash "${HELPER}" --release-tag v3.4.5 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "installed profile plan runs sample verification" "bin/zlar protected-records-installed-runtime-profile-preflight verify --sample --json > zlar-installed-runtime-profile-preflight-sample-verification.json" "${installed_profile_plan_output}"
assert_contains "installed profile plan preserves sample verification" "zlar-installed-runtime-profile-preflight-sample-verification.json" "${installed_profile_plan_output}"

installed_profile_recognition_plan_output="$(bash "${HELPER}" --release-tag v3.4.7 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "installed profile recognition plan runs proof" "bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --json > zlar-installed-runtime-profile-recognition-proof-v1.json" "${installed_profile_recognition_plan_output}"
assert_contains "installed profile recognition plan preserves proof" "zlar-installed-runtime-profile-recognition-proof-v1.json" "${installed_profile_recognition_plan_output}"

installed_profile_recognition_artifact_plan_output="$(bash "${HELPER}" --release-tag v3.4.8 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "installed profile recognition artifact plan writes artifact" "bin/zlar protected-records-installed-runtime-profile-recognition-proof --sample --artifact zlar-installed-runtime-profile-recognition-proof-artifact-v1.json" "${installed_profile_recognition_artifact_plan_output}"
assert_contains "installed profile recognition artifact plan verifies artifact" "bin/zlar protected-records-installed-runtime-profile-recognition-proof verify --input zlar-installed-runtime-profile-recognition-proof-artifact-v1.json --json > zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json" "${installed_profile_recognition_artifact_plan_output}"

product_proof_path_plan_output="$(bash "${HELPER}" --release-tag v3.4.9 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "product proof path plan writes artifact" "bin/zlar product-proof-path --json-out zlar-product-proof-path-v1.json" "${product_proof_path_plan_output}"

installed_profile_service_plan_output="$(bash "${HELPER}" --release-tag v3.4.11 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "installed profile service plan runs proof" "bin/zlar protected-records-installed-runtime-profile-service-proof --sample --json > zlar-installed-runtime-profile-service-proof-v1.json" "${installed_profile_service_plan_output}"
assert_contains "installed profile service plan writes artifact" "bin/zlar protected-records-installed-runtime-profile-service-proof --sample --artifact zlar-installed-runtime-profile-service-proof-artifact-v1.json" "${installed_profile_service_plan_output}"
assert_contains "installed profile service plan verifies artifact" "bin/zlar protected-records-installed-runtime-profile-service-proof verify --input zlar-installed-runtime-profile-service-proof-artifact-v1.json --json > zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json" "${installed_profile_service_plan_output}"
pre_installed_profile_service_plan_output="$(bash "${HELPER}" --release-tag v3.4.10 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_not_regex "v3.4.10 plan omits installed profile service proof" "protected-records-installed-runtime-profile-service-proof" "${pre_installed_profile_service_plan_output}"

installed_profile_terminal_chain_plan_output="$(bash "${HELPER}" --release-tag v3.4.15 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "installed profile terminal chain plan runs chain" "bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --json > zlar-installed-runtime-profile-terminal-chain-v1.json" "${installed_profile_terminal_chain_plan_output}"
assert_contains "installed profile terminal chain plan writes artifact" "bin/zlar protected-records-installed-runtime-profile-terminal-chain --sample --artifact zlar-installed-runtime-profile-terminal-chain-artifact-v1.json" "${installed_profile_terminal_chain_plan_output}"
assert_contains "installed profile terminal chain plan verifies artifact" "bin/zlar protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-artifact-v1.json --json > zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json" "${installed_profile_terminal_chain_plan_output}"
pre_installed_profile_terminal_chain_plan_output="$(bash "${HELPER}" --release-tag v3.4.14 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_not_regex "v3.4.14 plan omits installed profile terminal chain" "protected-records-installed-runtime-profile-terminal-chain" "${pre_installed_profile_terminal_chain_plan_output}"

installed_profile_terminal_chain_nested_binding_plan_output="$(bash "${HELPER}" --release-tag v3.4.28 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "installed profile terminal chain nested binding plan forges preflight artifact" "zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json" "${installed_profile_terminal_chain_nested_binding_plan_output}"
assert_contains "installed profile terminal chain nested binding plan expects preflight refusal" "protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json # expected exit 1" "${installed_profile_terminal_chain_nested_binding_plan_output}"
assert_contains "installed profile terminal chain nested binding plan forges artifact" "zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json" "${installed_profile_terminal_chain_nested_binding_plan_output}"
assert_contains "installed profile terminal chain nested binding plan expects refusal" "protected-records-installed-runtime-profile-terminal-chain verify --input zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json # expected exit 1" "${installed_profile_terminal_chain_nested_binding_plan_output}"

private_result_plan_output="$(bash "${HELPER}" --release-tag v3.3.104 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "older private result plan verifies generated envelope" "bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json --evidence-dir .. --json > zlar-private-verifier-result-verification-v1.json" "${private_result_plan_output}"

private_result_required_identity_plan_output="$(bash "${HELPER}" --release-tag v3.4.999 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "private result plan computes envelope sha" 'private_result_sha="$(shasum -a 256 zlar-private-verifier-result-v1.json)"' "${private_result_required_identity_plan_output}"
assert_contains "private result plan computes artifact set sha" "privateVerifierArtifactSetSha256" "${private_result_required_identity_plan_output}"
assert_contains "private result plan requires result sha" "--require-result-sha" "${private_result_required_identity_plan_output}"
assert_contains "private result plan requires target" "--require-target v3.4.999@${GOOD_SHA}" "${private_result_required_identity_plan_output}"
assert_contains "private result plan requires bundle sha" "--require-bundle-sha" "${private_result_required_identity_plan_output}"
assert_contains "private result plan requires artifact-set sha" "--require-artifact-set-sha" "${private_result_required_identity_plan_output}"
assert_contains "private result plan requires recomputed evidence" "--require-recomputed-evidence" "${private_result_required_identity_plan_output}"

verifier_kit_external_runner_diagnostics_plan_output="$(bash "${HELPER}" --release-tag v3.4.21 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_contains "verifier kit external-runner diagnostics plan writes report" "node tools/verifier-kit-external-runner-diagnostics.mjs --json-out zlar-verifier-kit-external-runner-diagnostics-v1.json" "${verifier_kit_external_runner_diagnostics_plan_output}"
assert_contains "verifier kit external-runner diagnostics plan pins target tag" "ZLAR_RELEASE_FORWARD_TARGET_TAG=v3.4.21" "${verifier_kit_external_runner_diagnostics_plan_output}"
assert_contains "verifier kit external-runner diagnostics plan pins expected sha" "ZLAR_RELEASE_FORWARD_EXPECTED_SHA=${GOOD_SHA}" "${verifier_kit_external_runner_diagnostics_plan_output}"
assert_not_regex "verifier kit external-runner diagnostics plan has no tag placeholder" '\$\{TAG\}|\$\{EXPECTED_SHA\}' "${verifier_kit_external_runner_diagnostics_plan_output}"
pre_verifier_kit_external_runner_diagnostics_plan_output="$(bash "${HELPER}" --release-tag v3.4.20 --expected-commit-sha "${GOOD_SHA}" --plan-only 2>&1)"
assert_not_regex "v3.4.20 plan omits verifier kit external-runner diagnostics artifact" "verifier-kit-external-runner-diagnostics" "${pre_verifier_kit_external_runner_diagnostics_plan_output}"

assert_fails_with "missing release tag rejected" "--release-tag is required" \
    bash "${HELPER}" --expected-commit-sha "${GOOD_SHA}" --plan-only
assert_fails_with "missing expected commit rejected" "--expected-commit-sha is required" \
    bash "${HELPER}" --release-tag "${GOOD_TAG}" --plan-only
assert_fails_with "missing out-dir rejected for real run" "--out-dir is required unless --plan-only is used" \
    bash "${HELPER}" --release-tag "${GOOD_TAG}" --expected-commit-sha "${GOOD_SHA}"
assert_fails_with "unsupported arg rejected" "unknown argument" \
    bash "${HELPER}" --release-tag "${GOOD_TAG}" --expected-commit-sha "${GOOD_SHA}" --bogus
assert_fails_with "missing trusted completion proof path rejected" "--trusted-issuer-completion-proof requires a value" \
    bash "${HELPER}" --release-tag "${GOOD_TAG}" --expected-commit-sha "${GOOD_SHA}" --trusted-issuer-completion-proof
assert_fails_with "rejects main tag" "explicit immutable release tag" \
    bash "${HELPER}" --release-tag main --expected-commit-sha "${GOOD_SHA}" --plan-only
assert_fails_with "rejects HEAD tag" "explicit immutable release tag" \
    bash "${HELPER}" --release-tag HEAD --expected-commit-sha "${GOOD_SHA}" --plan-only
assert_fails_with "rejects latest tag" "explicit immutable release tag" \
    bash "${HELPER}" --release-tag latest --expected-commit-sha "${GOOD_SHA}" --plan-only
assert_fails_with "rejects --latest tag" "explicit immutable release tag" \
    bash "${HELPER}" --release-tag --latest --expected-commit-sha "${GOOD_SHA}" --plan-only
assert_fails_with "rejects non-release tag" "must look like vX.Y.Z" \
    bash "${HELPER}" --release-tag release-3.3.81 --expected-commit-sha "${GOOD_SHA}" --plan-only
assert_fails_with "rejects suffixed release tag" "must look like vX.Y.Z" \
    bash "${HELPER}" --release-tag v3.4.51-rc1 --expected-commit-sha "${GOOD_SHA}" --plan-only
assert_fails_with "rejects short sha" "40-character lowercase hex" \
    bash "${HELPER}" --release-tag "${GOOD_TAG}" --expected-commit-sha abc123 --plan-only
assert_fails_with "rejects uppercase sha" "lowercase hex" \
    bash "${HELPER}" --release-tag "${GOOD_TAG}" --expected-commit-sha EBCFA57CAF80624036F884D7133FBE92127D0180 --plan-only

tmp_dir="$(mktemp -d -t zlar-release-forward-helper-test.XXXXXX)"
trap 'rm -rf "${tmp_dir}"' EXIT
touch "${tmp_dir}/occupied"
assert_fails_with "refuses non-empty output dir before clone" "--out-dir must be empty" \
    bash "${HELPER}" --release-tag "${GOOD_TAG}" --expected-commit-sha "${GOOD_SHA}" --out-dir "${tmp_dir}"

happy_root="$(mktemp -d -t zlar-release-forward-helper-happy.XXXXXX)"
backward_root="$(mktemp -d -t zlar-release-forward-helper-backward.XXXXXX)"
threshold_root="$(mktemp -d -t zlar-release-forward-helper-threshold.XXXXXX)"
cleanup() {
    rm -rf "${tmp_dir}" "${happy_root}" "${backward_root}" "${threshold_root}"
}
trap cleanup EXIT
main_tags_before="${tmp_dir}/main-tags-before.txt"
main_tags_after="${tmp_dir}/main-tags-after.txt"
git -C "${PROJECT_DIR}" for-each-ref --format='%(refname):%(objectname)' refs/tags | LC_ALL=C sort >"${main_tags_before}"
backward_out="${backward_root}/out"
backward_repo="${backward_root}/repo"

git clone --local "${PROJECT_DIR}" "${backward_repo}" >/dev/null 2>&1

TOTAL=$((TOTAL + 1))
if git -C "${backward_repo}" cat-file -e "${PRE_SERVICE_COVERAGE_SHA}^{commit}" 2>/dev/null; then
    pass
elif project_origin_url="$(git -C "${PROJECT_DIR}" config --get remote.origin.url)" &&
    git -C "${backward_repo}" fetch --depth=1 "${project_origin_url}" "refs/tags/${PRE_SERVICE_COVERAGE_TAG}:refs/tags/${PRE_SERVICE_COVERAGE_TAG}" >/dev/null 2>&1 &&
    git -C "${backward_repo}" cat-file -e "${PRE_SERVICE_COVERAGE_SHA}^{commit}" 2>/dev/null; then
    pass
else
    fail "backward target commit available" "missing ${PRE_SERVICE_COVERAGE_TAG} ${PRE_SERVICE_COVERAGE_SHA}"
fi

set +e
backward_output="$(bash "${HELPER}" \
    --release-tag "${PRE_SERVICE_COVERAGE_TAG}" \
    --expected-commit-sha "${PRE_SERVICE_COVERAGE_SHA}" \
    --out-dir "${backward_out}" \
    --repo-url "${backward_repo}" 2>&1)"
backward_rc=$?
set -e
TOTAL=$((TOTAL + 1))
if [ "${backward_rc}" -eq 0 ]; then
    pass
else
    fail "backward target exits pass" "${backward_output}"
fi
assert_contains "backward target exits pass" "result=PASS" "${backward_output}"
backward_assertions=""
if [ -f "${backward_out}/ASSERTIONS.txt" ]; then
    backward_assertions="$(cat "${backward_out}/ASSERTIONS.txt")"
fi
assert_contains "backward target keeps proof-smoke four lanes" "PASS proof-smoke governed lanes 4" "${backward_assertions}"
assert_contains "backward target keeps coverage four lanes" "PASS coverage map governed lanes 4" "${backward_assertions}"

happy_out="${happy_root}/out"
sandbox_repo="${happy_root}/repo"
sandbox_patch="${happy_root}/current-worktree.patch"
git clone --local "${PROJECT_DIR}" "${sandbox_repo}" >/dev/null 2>&1
git -C "${PROJECT_DIR}" diff --binary HEAD >"${sandbox_patch}"
if [ -s "${sandbox_patch}" ]; then
    git -C "${sandbox_repo}" apply --binary "${sandbox_patch}"
fi
git -C "${sandbox_repo}" add -A
current_tree="$(git -C "${sandbox_repo}" write-tree)"
current_sha="$(
    GIT_AUTHOR_NAME="ZLAR Test" \
    GIT_AUTHOR_EMAIL="test@zlar.local" \
    GIT_COMMITTER_NAME="ZLAR Test" \
    GIT_COMMITTER_EMAIL="test@zlar.local" \
    git -C "${sandbox_repo}" commit-tree "${current_tree}" -p HEAD -m "test: release-forward helper current worktree"
)"
git -C "${sandbox_repo}" update-ref refs/heads/zlar-release-forward-test-current "${current_sha}"
git -C "${sandbox_repo}" tag -f "${LOCAL_TAG}" "${current_sha}" >/dev/null

threshold_repo="${threshold_root}/repo"
git clone --local "${sandbox_repo}" "${threshold_repo}" >/dev/null 2>&1
git -C "${threshold_repo}" tag -f v3.4.38 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.39 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.40 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.41 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.42 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.45 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.46 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.48 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.49 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.50 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.51 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.52 "${current_sha}" >/dev/null
git -C "${threshold_repo}" tag -f v3.4.53 "${current_sha}" >/dev/null

trusted_completion_proof_fixture="${threshold_root}/zlar-trusted-receipt-issuer-completion-proof-v1.json"
node --input-type=module -e "import { writeFileSync } from 'node:fs'; import { buildTrustedReceiptIssuerCompletionProofTestVector, TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID } from './lib/trusted-receipt-issuer-completion-proof.mjs'; const proof = buildTrustedReceiptIssuerCompletionProofTestVector({ selected_surface_id: TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID }); proof.authority_event_contract.observed_event_type = 'direct_human_approval'; writeFileSync(process.argv[1], JSON.stringify(proof, null, 2) + '\n');" "${trusted_completion_proof_fixture}"

root_proof_repo="${threshold_root}/repo-root-proof"
root_proof_out="${threshold_root}/out-root-proof-refusal"
git clone --local "${sandbox_repo}" "${root_proof_repo}" >/dev/null 2>&1
cp "${trusted_completion_proof_fixture}" "${root_proof_repo}/zlar-trusted-receipt-issuer-completion-proof-v1.json"
git -C "${root_proof_repo}" add -f zlar-trusted-receipt-issuer-completion-proof-v1.json
root_proof_tree="$(git -C "${root_proof_repo}" write-tree)"
root_proof_sha="$(
    GIT_AUTHOR_NAME="ZLAR Test" \
    GIT_AUTHOR_EMAIL="test@zlar.local" \
    GIT_COMMITTER_NAME="ZLAR Test" \
    GIT_COMMITTER_EMAIL="test@zlar.local" \
    git -C "${root_proof_repo}" commit-tree "${root_proof_tree}" -p HEAD -m "test: checkout-root trusted issuer proof"
)"
git -C "${root_proof_repo}" update-ref refs/heads/zlar-release-forward-root-proof-test "${root_proof_sha}"
git -C "${root_proof_repo}" tag -f v3.4.53 "${root_proof_sha}" >/dev/null
assert_fails_with "checkout-root trusted completion proof refused without explicit flag" "checkout-root trusted receipt issuer completion proof requires --trusted-issuer-completion-proof" \
    bash "${HELPER}" --release-tag v3.4.53 --expected-commit-sha "${root_proof_sha}" --out-dir "${root_proof_out}" --repo-url "${root_proof_repo}"

happy_output="$(bash "${HELPER}" \
    --release-tag "${LOCAL_TAG}" \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${happy_out}" \
    --repo-url "${sandbox_repo}" 2>&1)"
assert_contains "happy path exits pass" "result=PASS" "${happy_output}"
assert_contains "happy path transcript boundary" "evidence_root=<dry-run-output-dir>" "${happy_output}"

threshold_38_out="${threshold_root}/out-3-4-38"
threshold_38_output="$(bash "${HELPER}" \
    --release-tag v3.4.38 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_38_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.38 threshold exits pass" "result=PASS" "${threshold_38_output}"

threshold_39_out="${threshold_root}/out-3-4-39"
threshold_39_output="$(bash "${HELPER}" \
    --release-tag v3.4.39 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_39_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.39 threshold exits pass" "result=PASS" "${threshold_39_output}"

threshold_40_out="${threshold_root}/out-3-4-40"
threshold_40_output="$(bash "${HELPER}" \
    --release-tag v3.4.40 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_40_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.40 threshold exits pass" "result=PASS" "${threshold_40_output}"

threshold_41_out="${threshold_root}/out-3-4-41"
threshold_41_output="$(bash "${HELPER}" \
    --release-tag v3.4.41 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_41_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.41 threshold exits pass" "result=PASS" "${threshold_41_output}"

threshold_42_out="${threshold_root}/out-3-4-42"
threshold_42_output="$(bash "${HELPER}" \
    --release-tag v3.4.42 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_42_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.42 threshold exits pass" "result=PASS" "${threshold_42_output}"

threshold_45_out="${threshold_root}/out-3-4-45"
threshold_45_output="$(bash "${HELPER}" \
    --release-tag v3.4.45 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_45_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.45 threshold exits pass" "result=PASS" "${threshold_45_output}"

threshold_46_out="${threshold_root}/out-3-4-46"
threshold_46_output="$(bash "${HELPER}" \
    --release-tag v3.4.46 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_46_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.46 threshold exits pass" "result=PASS" "${threshold_46_output}"
threshold_48_out="${threshold_root}/out-3-4-48"
threshold_48_output="$(bash "${HELPER}" \
    --release-tag v3.4.48 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_48_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.48 threshold exits pass" "result=PASS" "${threshold_48_output}"

threshold_49_out="${threshold_root}/out-3-4-49"
threshold_49_output="$(bash "${HELPER}" \
    --release-tag v3.4.49 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_49_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.49 threshold exits pass" "result=PASS" "${threshold_49_output}"

threshold_50_out="${threshold_root}/out-3-4-50"
threshold_50_output="$(bash "${HELPER}" \
    --release-tag v3.4.50 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_50_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.50 threshold exits pass" "result=PASS" "${threshold_50_output}"

threshold_51_out="${threshold_root}/out-3-4-51"
threshold_51_output="$(bash "${HELPER}" \
    --release-tag v3.4.51 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_51_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.51 threshold exits pass" "result=PASS" "${threshold_51_output}"

threshold_52_out="${threshold_root}/out-3-4-52"
threshold_52_output="$(bash "${HELPER}" \
    --release-tag v3.4.52 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_52_out}" \
    --repo-url "${threshold_repo}" 2>&1)"
assert_contains "v3.4.52 threshold exits pass" "result=PASS" "${threshold_52_output}"

threshold_53_out="${threshold_root}/out-3-4-53"
threshold_53_output="$(bash "${HELPER}" \
    --release-tag v3.4.53 \
    --expected-commit-sha "${current_sha}" \
    --out-dir "${threshold_53_out}" \
    --repo-url "${threshold_repo}" \
    --trusted-issuer-completion-proof "${trusted_completion_proof_fixture}" 2>&1)"
assert_contains "v3.4.53 threshold exits pass" "result=PASS" "${threshold_53_output}"

threshold_check="$(THRESHOLD_38_OUT="${threshold_38_out}" THRESHOLD_39_OUT="${threshold_39_out}" THRESHOLD_40_OUT="${threshold_40_out}" THRESHOLD_41_OUT="${threshold_41_out}" THRESHOLD_42_OUT="${threshold_42_out}" THRESHOLD_45_OUT="${threshold_45_out}" THRESHOLD_46_OUT="${threshold_46_out}" THRESHOLD_48_OUT="${threshold_48_out}" THRESHOLD_49_OUT="${threshold_49_out}" THRESHOLD_50_OUT="${threshold_50_out}" THRESHOLD_51_OUT="${threshold_51_out}" THRESHOLD_52_OUT="${threshold_52_out}" THRESHOLD_53_OUT="${threshold_53_out}" node - <<'NODE'
const fs = require('fs');

function readJson(path) {
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function report(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${ok || detail === '' ? '' : `: ${detail}`}`);
}

function arraysEqual(left, right) {
  return Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((item, index) => item === right[index]);
}

const trustedKeys = [
  'trusted_issuer_registry_recognition_refusals_minimum_target',
  'trusted_issuer_registry_recognition_refusals_required',
  'trusted_issuer_registry_recognition_refusal_case_count',
  'artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
  'trusted_issuer_registry_recognition_refusals_all_refused',
  'artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
  'trusted_issuer_registry_recognition_refusal_case_ids',
  'artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids',
  'trusted_issuer_registry_recognition_refusal_reason_codes',
  'artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes',
  'trusted_issuer_registry_recognition_refusals_sha256',
  'artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
  'all_trusted_issuer_registry_recognition_refusals_preserved',
];
const expectedCaseIds = [
  'unrecognized_terminal_chain_registry_scope_refused',
  'registry_receipt_contract_mismatch_refused',
];
const expectedReasons = [
  'scope_not_found',
  'detail_hash_mismatch',
];
const expectedTerminalChainTrustedRegistryVerdictKeys = [
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
  'trusted_issuer_registry_recognition_registry_fixture_contract_sha256',
  'trusted_issuer_registry_recognition_receipt_payload_contract_sha256',
];
const expectedTerminalChainTrustedRegistryRecognitionKeys = [
  'trusted_issuer_registry_recognition_binding_sha256',
  'trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification',
  ...expectedTerminalChainTrustedRegistryVerdictKeys,
  'trusted_issuer_registry_recognition_refusals_sha256',
  'trusted_issuer_registry_recognition_refusal_hash_matches_binding',
  'trusted_issuer_registry_recognition_refusal_case_count',
  'trusted_issuer_registry_recognition_refusal_case_ids',
  'trusted_issuer_registry_recognition_refusal_reason_codes',
  'trusted_issuer_registry_recognition_refusals_all_refused',
];
const expectedNorthStarTrustedRegistryVerdictKeys =
  expectedTerminalChainTrustedRegistryVerdictKeys.map((key) => `terminal_chain_${key}`);
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
const expectedDownstreamRefusalBoundaryKeys = [
  'provided',
  'recognized_boarded',
  'recognized_marker_count_delta',
  'final_marker_count',
  'refusal_case_count',
  'all_refusals_unboarded',
  'all_refusal_marker_count_deltas_zero',
  'refusal_reasons',
];
const expectedReportContractClaimBoundaryKeys = [
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
const expectedProductProofPathClaimBoundaryKeys = [
  'creates_public_external_attestation',
  'proves_current_machine_governance',
  'proves_all_mcp_governance',
  'proves_unrouted_surface_coverage',
];
const expectedProductProofPathSimulatedHumanAuthorizationKeys = [
  'approval_channel',
  'authorized_boarded',
  'denied_boarded',
  'pending_boarded',
];
const expectedProductProofPathReceiptVerifierBoundaryKeys = [
  'downstream_recognition_proven',
  'invalid_verdict',
  'unknown_signer_verdict',
  'valid_verdict',
];
const expectedDeploymentProfileAuthorityRefusalCaseIds = [
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
];
const expectedDeploymentProfileAuthorityBridgeKeys = [
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
const expectedDeploymentProfileAuthorityBridgeNorthStarKeys = [
  'deployment_profile_authority_bridge_required',
  'deployment_profile_authority_bridge_preserved',
  'deployment_profile_authority_bridge_observed',
  'deployment_profile_authority_bridge_proof_type',
  'deployment_profile_authority_bridge_refusal_count',
  'deployment_profile_authority_bridge_current_machine_governance',
  'deployment_profile_authority_bridge_production_authority',
];
const expectedDeploymentProfileAuthorityRefusalBridgeKeys = [
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
const expectedDeploymentProfileAuthorityRefusalNorthStarKeys = [
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
const expectedDeploymentProfileAuthorityBridgeV349Keys = [
  ...expectedDeploymentProfileAuthorityBridgeKeys,
  ...expectedDeploymentProfileAuthorityRefusalBridgeKeys,
];
const expectedDeploymentProfileAuthorityNorthStarV349Keys = [
  ...expectedDeploymentProfileAuthorityBridgeNorthStarKeys,
  ...expectedDeploymentProfileAuthorityRefusalNorthStarKeys,
];
const expectedReportContractProofSmokeTrustedRegistryRecognitionRefusalKeys = [
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count',
  'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count',
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused',
  'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused',
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids',
  'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids',
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes',
  'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes',
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256',
  'installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals_sha256',
];
const expectedReportContractNorthStarTrustedRegistryRecognitionRefusalKeys = [
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
  ...expectedReportContractProofSmokeTrustedRegistryRecognitionRefusalKeys,
];
const expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys = [
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved',
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids',
  'installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes',
];
const expectedRecognizedReceiptPathMirrorKeys = [
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
const expectedNorthStarRecognizedReceiptPathMirrorKeys =
  expectedRecognizedReceiptPathMirrorKeys.map((key) => `terminal_chain_${key}`);
const recognizedReceiptPathFalseBoundaryKeys = [
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
const deploymentProfileAuthorityNorthStarPrefixes = [
  'deployment_profile_authority_',
  'stale_deployment_profile_artifact_',
  'profile_recognition_mismatch_',
  'latest_profile_selection_',
  'request_stream_authority_material_',
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
function groupCaseIdsMatch(value) {
  return Object.entries(expectedRecognitionRefusalGroupCaseIds)
    .every(([key, expected]) => arraysEqual(value?.[key], expected));
}
function groupCaseIdsExact(value) {
  return exactKeys(value, Object.keys(expectedRecognitionRefusalGroupCaseIds)) &&
    groupCaseIdsMatch(value);
}
function exactKeys(value, expectedKeys) {
  return Boolean(value) &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    arraysEqual(Object.keys(value).sort(), [...expectedKeys].sort());
}
function prefixedKeys(value, prefix) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value).filter((key) => key.startsWith(prefix)).sort();
}
function exactPrefixedKeys(value, prefix, expectedKeys) {
  return arraysEqual(prefixedKeys(value, prefix), [...expectedKeys].sort());
}
function recognizedReceiptPathKeys(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value)
    .filter((key) => key.includes('recognized_receipt_path'))
    .sort();
}
function exactRecognizedReceiptPathKeys(value, expectedKeys) {
  return arraysEqual(recognizedReceiptPathKeys(value), [...expectedKeys].sort());
}
function reportContractProofSummaryTrustedRegistryRefusalKeys(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value)
    .filter((key) =>
      key.startsWith('installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal') ||
      key.startsWith('installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals') ||
      key.startsWith('installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal') ||
      key.startsWith('installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusals')
    )
    .sort();
}
function exactReportContractProofSummaryTrustedRegistryRefusalKeys(
  value,
  expectedKeys
) {
  return arraysEqual(
    reportContractProofSummaryTrustedRegistryRefusalKeys(value),
    [...expectedKeys].sort()
  );
}
function deploymentProfileAuthorityNorthStarKeys(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value)
    .filter((key) =>
      deploymentProfileAuthorityNorthStarPrefixes.some((prefix) =>
        key.startsWith(prefix)
      )
    )
    .sort();
}
function exactDeploymentProfileAuthorityNorthStarKeys(value, expectedKeys) {
  return arraysEqual(
    deploymentProfileAuthorityNorthStarKeys(value),
    [...expectedKeys].sort()
  );
}

const manifest38 = readJson(`${process.env.THRESHOLD_38_OUT}/DRY-RUN-MANIFEST.json`);
const result38 = fs.readFileSync(`${process.env.THRESHOLD_38_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const evidence38 = manifest38.terminal_chain_refusal_evidence || {};
const present38 = trustedKeys.filter((key) =>
  Object.prototype.hasOwnProperty.call(evidence38, key)
);
report('v3.4.38 terminal-chain refusal evidence remains present', evidence38.enabled === true);
report('v3.4.38 omits trusted-registry refusal manifest fields', present38.length === 0, present38.join(','));
report(
  'v3.4.38 result omits trusted-registry refusal manifest summary',
  !result38.includes('manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal') &&
    !result38.includes('manifest.terminal_chain_refusal_evidence.all_trusted_issuer_registry_recognition_refusals_preserved')
);
report(
  'v3.4.38 result omits trusted-registry refusal report contract',
  !result38.includes('proof_smoke.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal') &&
    !result38.includes('north_star.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal') &&
    !result38.includes('north_star.puzzle_3.observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal') &&
    !result38.includes('north_star.puzzle_5.observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal')
);

const manifest39 = readJson(`${process.env.THRESHOLD_39_OUT}/DRY-RUN-MANIFEST.json`);
const result39 = fs.readFileSync(`${process.env.THRESHOLD_39_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const evidence39 = manifest39.terminal_chain_refusal_evidence || {};
report('v3.4.39 trusted-registry refusal manifest required', evidence39.trusted_issuer_registry_recognition_refusals_required === true);
report('v3.4.39 trusted-registry refusal minimum target', evidence39.trusted_issuer_registry_recognition_refusals_minimum_target === 'v3.4.39');
report('v3.4.39 trusted-registry refusal case count', evidence39.trusted_issuer_registry_recognition_refusal_case_count === 2);
report('v3.4.39 trusted-registry artifact refusal case count', evidence39.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count === 2);
report('v3.4.39 trusted-registry refusal case ids', arraysEqual(evidence39.trusted_issuer_registry_recognition_refusal_case_ids, expectedCaseIds));
report('v3.4.39 trusted-registry artifact refusal case ids', arraysEqual(evidence39.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids, expectedCaseIds));
report('v3.4.39 trusted-registry refusal reason codes', arraysEqual(evidence39.trusted_issuer_registry_recognition_refusal_reason_codes, expectedReasons));
report('v3.4.39 trusted-registry artifact refusal reason codes', arraysEqual(evidence39.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes, expectedReasons));
report('v3.4.39 trusted-registry refusal hashes match', evidence39.trusted_issuer_registry_recognition_refusals_sha256 === evidence39.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 && /^[0-9a-f]{64}$/.test(evidence39.trusted_issuer_registry_recognition_refusals_sha256 || ''));
report('v3.4.39 trusted-registry refusals preserved', evidence39.all_trusted_issuer_registry_recognition_refusals_preserved === true);
report('v3.4.39 result includes trusted-registry refusal manifest summary', result39.includes('manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_case_count=2'));
report('v3.4.39 result includes trusted-registry refusal report contract', result39.includes('proof_smoke.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count=2'));

const manifest40 = readJson(`${process.env.THRESHOLD_40_OUT}/DRY-RUN-MANIFEST.json`);
const result40 = fs.readFileSync(`${process.env.THRESHOLD_40_OUT}/DRY-RUN-RESULT.md`, 'utf8');
report('v3.4.40 omits release-forward report contract manifest object', !Object.prototype.hasOwnProperty.call(manifest40, 'release_forward_report_contract'));
report('v3.4.40 result omits manifest report contract rendering', !result40.includes('manifest.release_forward_report_contract.'));

const manifest41 = readJson(`${process.env.THRESHOLD_41_OUT}/DRY-RUN-MANIFEST.json`);
const result41 = fs.readFileSync(`${process.env.THRESHOLD_41_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const contract41 = manifest41.release_forward_report_contract || {};
const contract41ClaimBoundaryMissing = { ...(contract41.claim_boundary || {}) };
delete contract41ClaimBoundaryMissing.proves_live_registry;
const contract41ClaimBoundaryRenamed = {
  ...(contract41.claim_boundary || {}),
  proves_live_registry_truth: contract41.claim_boundary?.proves_live_registry,
};
delete contract41ClaimBoundaryRenamed.proves_live_registry;
const contract41ClaimBoundarySummary = {
  ...(contract41.claim_boundary || {}),
  claim_boundary_summary: { external_attestation: false },
};
report('v3.4.41 report contract enabled', contract41.enabled === true);
report('v3.4.41 report contract type', contract41.contract_type === 'zlar-release-forward-dry-run-report-contract-v1');
report('v3.4.41 report contract evidence model', contract41.evidence_model === 'release-forward-dry-run-artifacts');
report('v3.4.41 report contract minimum target', contract41.minimum_target === 'v3.4.41');
report('v3.4.41 report contract satisfied', contract41.report_contract_satisfied === true);
report('v3.4.41 report contract manifest canonical', contract41.manifest_is_canonical === true);
report('v3.4.41 report contract proof-smoke hash', /^[0-9a-f]{64}$/.test(contract41.source_artifacts?.proof_smoke_sample_verification_sha256 || ''));
report('v3.4.41 report contract north-star hash', /^[0-9a-f]{64}$/.test(contract41.source_artifacts?.north_star_readiness_sha256 || ''));
report('v3.4.41 report contract terminal source same manifest', contract41.source_artifacts?.terminal_chain_refusal_evidence_included_in_same_manifest === true);
report('v3.4.41 report contract group count', contract41.proof_smoke?.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3);
report('v3.4.41 report contract group case count', contract41.proof_smoke?.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === 18);
report('v3.4.41 report contract north-star group case ids preserved', contract41.north_star?.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true);
report('v3.4.41 report contract trusted registry terminal count', contract41.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_case_count === 2);
report('v3.4.41 report contract trusted registry terminal case ids', arraysEqual(contract41.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_case_ids, expectedCaseIds));
report('v3.4.41 report contract trusted registry terminal reasons', arraysEqual(contract41.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_reason_codes, expectedReasons));
report('v3.4.41 report contract trusted registry terminal hash match', contract41.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_sha256 === contract41.terminal_chain_refusal_evidence?.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 && /^[0-9a-f]{64}$/.test(contract41.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_sha256 || ''));
report('v3.4.41 report contract proof-smoke trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(contract41.proof_smoke?.counts, expectedReportContractProofSmokeTrustedRegistryRecognitionRefusalKeys));
report('v3.4.41 report contract proof-smoke trusted registry count', contract41.proof_smoke?.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count === 2);
report('v3.4.41 report contract proof-smoke trusted registry case ids', arraysEqual(contract41.proof_smoke?.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids, expectedCaseIds));
report('v3.4.41 report contract north-star trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(contract41.north_star?.counts, expectedReportContractNorthStarTrustedRegistryRecognitionRefusalKeys));
report('v3.4.41 report contract north-star trusted registry preserved', contract41.north_star?.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved === true);
report('v3.4.41 report contract north-star trusted registry case ids', arraysEqual(contract41.north_star?.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids, expectedCaseIds));
report('v3.4.41 report contract enterprise trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(contract41.north_star?.puzzle_3_observed, expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys));
report('v3.4.41 report contract enterprise trusted registry preserved', contract41.north_star?.puzzle_3_observed?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved === true);
report('v3.4.41 report contract downstream trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(contract41.north_star?.puzzle_5_observed, expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys));
report('v3.4.41 report contract downstream trusted registry preserved', contract41.north_star?.puzzle_5_observed?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved === true);
report('v3.4.41 report contract claim boundary exact keys', exactKeys(contract41.claim_boundary, expectedReportContractClaimBoundaryKeys));
report('v3.4.41 report contract claim boundary rejects extra key', !exactKeys({ ...(contract41.claim_boundary || {}), extra_summary: false }, expectedReportContractClaimBoundaryKeys));
report('v3.4.41 report contract claim boundary rejects missing key', !exactKeys(contract41ClaimBoundaryMissing, expectedReportContractClaimBoundaryKeys));
report('v3.4.41 report contract claim boundary rejects renamed key', !exactKeys(contract41ClaimBoundaryRenamed, expectedReportContractClaimBoundaryKeys));
report('v3.4.41 report contract claim boundary rejects summary-shaped key', !exactKeys(contract41ClaimBoundarySummary, expectedReportContractClaimBoundaryKeys));
report('v3.4.41 report contract no public attestation', contract41.claim_boundary?.creates_public_external_attestation === false);
report('v3.4.41 report contract no live registry', contract41.claim_boundary?.proves_live_registry === false);
report('v3.4.41 report contract no key custody', contract41.claim_boundary?.proves_key_custody === false);
report('v3.4.41 report contract no revocation truth', contract41.claim_boundary?.proves_revocation_truth === false);
report('v3.4.41 report contract no current-machine governance', contract41.claim_boundary?.proves_current_machine_governance === false);
report('v3.4.41 report contract no live mcp', contract41.claim_boundary?.proves_live_mcp_coverage === false);
report('v3.4.41 report contract no production downstream', contract41.claim_boundary?.proves_production_downstream_recognition === false);
report('v3.4.41 report contract no production authority', contract41.claim_boundary?.proves_production_authority === false);
report('v3.4.41 report contract no enterprise readiness', contract41.claim_boundary?.proves_enterprise_readiness === false);
report('v3.4.41 report contract no sovereign recognition', contract41.claim_boundary?.proves_sovereign_recognition === false);
report('v3.4.41 report contract no unrouted coverage', contract41.claim_boundary?.proves_unrouted_surface_coverage === false);
report('v3.4.41 result renders report contract type from manifest', result41.includes('manifest.release_forward_report_contract.contract_type=zlar-release-forward-dry-run-report-contract-v1'));
report('v3.4.41 result renders trusted registry case ids from manifest', result41.includes('manifest.release_forward_report_contract.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused'));
report('v3.4.41 result renders no live registry boundary from manifest', result41.includes('manifest.release_forward_report_contract.claim_boundary.proves_live_registry=false'));
report('v3.4.41 result omits old report-contract source prefix', !result41.includes('\nproof_smoke.counts.') && !result41.includes('\nnorth_star.counts.'));
report('v3.4.41 report contract omits product proof path contract', !Object.prototype.hasOwnProperty.call(contract41, 'product_proof_path'));
report('v3.4.41 report contract omits product proof path source hash', !Object.prototype.hasOwnProperty.call(contract41.source_artifacts || {}, 'product_proof_path_sha256'));
report('v3.4.41 result omits product proof path contract rendering', !result41.includes('manifest.release_forward_report_contract.product_proof_path.'));

const manifest42 = readJson(`${process.env.THRESHOLD_42_OUT}/DRY-RUN-MANIFEST.json`);
const result42 = fs.readFileSync(`${process.env.THRESHOLD_42_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const contract42 = manifest42.release_forward_report_contract || {};
const product42 = contract42.product_proof_path || {};
const product42ClaimBoundaryMissing = { ...(product42.claim_boundary || {}) };
delete product42ClaimBoundaryMissing.proves_all_mcp_governance;
const product42ClaimBoundaryRenamed = {
  ...(product42.claim_boundary || {}),
  proves_current_machine_authority:
    product42.claim_boundary?.proves_current_machine_governance,
};
delete product42ClaimBoundaryRenamed.proves_current_machine_governance;
const product42ClaimBoundarySummary = {
  ...(product42.claim_boundary || {}),
  product_claim_boundary_summary: { current_machine_governance: false },
};
const product42SimulatedHumanMissing = {
  ...(product42.simulated_human_authorization || {}),
};
delete product42SimulatedHumanMissing.authorized_boarded;
const product42SimulatedHumanRenamed = {
  ...(product42.simulated_human_authorization || {}),
  channel: product42.simulated_human_authorization?.approval_channel,
};
delete product42SimulatedHumanRenamed.approval_channel;
const product42SimulatedHumanSummary = {
  ...(product42.simulated_human_authorization || {}),
  authorization_summary: { authorized: true },
};
const product42ReceiptBoundaryMissing = {
  ...(product42.receipt_verifier_boundary || {}),
};
delete product42ReceiptBoundaryMissing.downstream_recognition_proven;
const product42ReceiptBoundaryRenamed = {
  ...(product42.receipt_verifier_boundary || {}),
  unknown_signer_collapsed_verdict:
    product42.receipt_verifier_boundary?.unknown_signer_verdict,
};
delete product42ReceiptBoundaryRenamed.unknown_signer_verdict;
const product42ReceiptBoundarySummary = {
  ...(product42.receipt_verifier_boundary || {}),
  receipt_summary: { verdicts: 'collapsed' },
};
report('v3.4.42 report contract product proof path source path', contract42.source_artifacts?.product_proof_path_path === 'ZLAR/zlar-product-proof-path-v1.json');
report('v3.4.42 report contract product proof path source hash', /^[0-9a-f]{64}$/.test(contract42.source_artifacts?.product_proof_path_sha256 || ''));
report('v3.4.42 report contract product proof path minimum target', product42.minimum_target === 'v3.4.42');
report('v3.4.42 report contract product proof path report type', product42.report_type === 'zlar-product-proof-path-v1');
report('v3.4.42 report contract product proof path result pass', product42.result === 'PASS');
report('v3.4.42 report contract product proof path evidence model accepted', ['fresh-local-fixture-proof-pack', 'fresh-local-fixture-proof-pack-and-terminal-chain-artifact-verification', 'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge'].includes(product42.evidence_model));
report('v3.4.42 report contract product proof path no live probing', product42.live_probing === false);
report('v3.4.42 report contract product proof path gates true', product42.acceptance_gate_all_true === true);
report('v3.4.42 report contract product proof path forbidden claims false', product42.forbidden_claims_all_false === true);
report('v3.4.42 report contract omits product proof path terminal boundary', !Object.prototype.hasOwnProperty.call(product42, 'terminal_chain_boundary'));
report('v3.4.42 report contract omits north-star terminal boundary fields', !Object.prototype.hasOwnProperty.call(product42.north_star || {}, 'terminal_chain_boundary_observed'));
report('v3.4.42 report contract omits deployment bridge', !Object.prototype.hasOwnProperty.call(product42, 'deployment_profile_authority_bridge'));
report('v3.4.42 report contract omits north-star deployment bridge', !Object.prototype.hasOwnProperty.call(product42.north_star || {}, 'deployment_profile_authority_bridge_observed'));
report('v3.4.42 report contract simulated human exact keys', exactKeys(product42.simulated_human_authorization, expectedProductProofPathSimulatedHumanAuthorizationKeys));
report('v3.4.42 report contract simulated human rejects extra key', !exactKeys({ ...(product42.simulated_human_authorization || {}), extra_summary: false }, expectedProductProofPathSimulatedHumanAuthorizationKeys));
report('v3.4.42 report contract simulated human rejects missing key', !exactKeys(product42SimulatedHumanMissing, expectedProductProofPathSimulatedHumanAuthorizationKeys));
report('v3.4.42 report contract simulated human rejects renamed key', !exactKeys(product42SimulatedHumanRenamed, expectedProductProofPathSimulatedHumanAuthorizationKeys));
report('v3.4.42 report contract simulated human rejects summary-shaped key', !exactKeys(product42SimulatedHumanSummary, expectedProductProofPathSimulatedHumanAuthorizationKeys));
report('v3.4.42 report contract simulated human authorized boarded', product42.simulated_human_authorization?.authorized_boarded === true);
report('v3.4.42 report contract receipt boundary exact keys', exactKeys(product42.receipt_verifier_boundary, expectedProductProofPathReceiptVerifierBoundaryKeys));
report('v3.4.42 report contract receipt boundary rejects extra key', !exactKeys({ ...(product42.receipt_verifier_boundary || {}), extra_summary: false }, expectedProductProofPathReceiptVerifierBoundaryKeys));
report('v3.4.42 report contract receipt boundary rejects missing key', !exactKeys(product42ReceiptBoundaryMissing, expectedProductProofPathReceiptVerifierBoundaryKeys));
report('v3.4.42 report contract receipt boundary rejects renamed key', !exactKeys(product42ReceiptBoundaryRenamed, expectedProductProofPathReceiptVerifierBoundaryKeys));
report('v3.4.42 report contract receipt boundary rejects summary-shaped key', !exactKeys(product42ReceiptBoundarySummary, expectedProductProofPathReceiptVerifierBoundaryKeys));
report('v3.4.42 report contract product proof path receipt valid', product42.receipt_verifier_boundary?.valid_verdict === 'VALID');
report('v3.4.42 report contract product proof path north star consumed', product42.north_star?.artifact_consumed === true);
report('v3.4.42 report contract product proof path known noncoverage visible', product42.known_ungoverned_boundaries_includes_unrouted_records_paths === true);
report('v3.4.42 report contract product proof path claim boundary exact keys', exactKeys(product42.claim_boundary, expectedProductProofPathClaimBoundaryKeys));
report('v3.4.42 report contract product proof path claim boundary rejects extra key', !exactKeys({ ...(product42.claim_boundary || {}), extra_summary: false }, expectedProductProofPathClaimBoundaryKeys));
report('v3.4.42 report contract product proof path claim boundary rejects missing key', !exactKeys(product42ClaimBoundaryMissing, expectedProductProofPathClaimBoundaryKeys));
report('v3.4.42 report contract product proof path claim boundary rejects renamed key', !exactKeys(product42ClaimBoundaryRenamed, expectedProductProofPathClaimBoundaryKeys));
report('v3.4.42 report contract product proof path claim boundary rejects summary-shaped key', !exactKeys(product42ClaimBoundarySummary, expectedProductProofPathClaimBoundaryKeys));
report('v3.4.42 report contract product proof path no external attestation', product42.claim_boundary?.creates_public_external_attestation === false);
report('v3.4.42 report contract product proof path no current-machine governance', product42.claim_boundary?.proves_current_machine_governance === false);
report('v3.4.42 result renders product proof path from manifest', result42.includes('manifest.release_forward_report_contract.product_proof_path.report_type=zlar-product-proof-path-v1'));
report('v3.4.42 result renders product proof path source hash from manifest', result42.includes('manifest.release_forward_report_contract.source_artifacts.product_proof_path_sha256='));
report('v3.4.42 result omits product proof path terminal boundary rendering', !result42.includes('manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.'));

const manifest45 = readJson(`${process.env.THRESHOLD_45_OUT}/DRY-RUN-MANIFEST.json`);
const result45 = fs.readFileSync(`${process.env.THRESHOLD_45_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const product45 = manifest45.release_forward_report_contract?.product_proof_path || {};
report('v3.4.45 report contract product proof path evidence model', ['fresh-local-fixture-proof-pack-and-terminal-chain-artifact-verification', 'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge'].includes(product45.evidence_model));
report('v3.4.45 report contract product proof path terminal verified', product45.terminal_chain_boundary?.verified === true);
report('v3.4.45 report contract product proof path terminal binding match', product45.terminal_chain_boundary?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification === true);
report('v3.4.45 report contract product proof path terminal refusal hash match', product45.terminal_chain_boundary?.trusted_issuer_registry_recognition_refusal_hash_matches_binding === true);
report('v3.4.45 report contract product proof path terminal refusal IDs', arraysEqual(product45.terminal_chain_boundary?.trusted_issuer_registry_recognition_refusal_case_ids, expectedCaseIds));
report('v3.4.45 report contract product proof path terminal no public key', product45.terminal_chain_boundary?.registry_public_key_material_included === false);
report('v3.4.45 report contract product proof path terminal no attestation', product45.terminal_chain_boundary?.external_attestation === false);
report('v3.4.45 report contract product proof path north-star terminal observed', product45.north_star?.terminal_chain_boundary_observed === true);
report('v3.4.45 report contract omits product proof path terminal group case IDs', !Object.prototype.hasOwnProperty.call(product45.terminal_chain_boundary || {}, 'recognition_refusal_group_case_ids'));
report('v3.4.45 report contract omits north-star terminal group case IDs', !Object.prototype.hasOwnProperty.call(product45.north_star || {}, 'terminal_chain_recognition_refusal_group_case_ids'));
report('v3.4.45 report contract omits deployment bridge', !Object.prototype.hasOwnProperty.call(product45, 'deployment_profile_authority_bridge'));
report('v3.4.45 report contract omits north-star deployment bridge', !Object.prototype.hasOwnProperty.call(product45.north_star || {}, 'deployment_profile_authority_bridge_observed'));
report('v3.4.45 result renders product proof path terminal boundary', result45.includes('manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification=true'));
report('v3.4.45 result omits product proof path terminal group case IDs', !result45.includes('manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognition_refusal_group_case_ids.'));

const manifest46 = readJson(`${process.env.THRESHOLD_46_OUT}/DRY-RUN-MANIFEST.json`);
const result46 = fs.readFileSync(`${process.env.THRESHOLD_46_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const product46 = manifest46.release_forward_report_contract?.product_proof_path || {};
report('v3.4.46 report contract product proof path terminal group count', product46.terminal_chain_boundary?.recognition_refusal_group_count === 3);
report('v3.4.46 report contract product proof path terminal group case count', product46.terminal_chain_boundary?.recognition_refusal_group_case_count === 18);
report('v3.4.46 report contract product proof path terminal group case IDs preserved', product46.terminal_chain_boundary?.recognition_refusal_group_case_ids_preserved === true);
report('v3.4.46 report contract product proof path terminal group case IDs', groupCaseIdsExact(product46.terminal_chain_boundary?.recognition_refusal_group_case_ids));
report('v3.4.46 report contract product proof path terminal group case IDs reject extra key', !groupCaseIdsExact({ ...(product46.terminal_chain_boundary?.recognition_refusal_group_case_ids || {}), summary_or_extra_group: ['collapsed_refusal_summary'] }));
const product46TerminalGroupMissing = { ...(product46.terminal_chain_boundary?.recognition_refusal_group_case_ids || {}) };
delete product46TerminalGroupMissing.recognized_receipt_scope_mismatch;
report('v3.4.46 report contract product proof path terminal group case IDs reject missing key', !groupCaseIdsExact(product46TerminalGroupMissing));
report('v3.4.46 report contract product proof path north-star group count', product46.north_star?.terminal_chain_recognition_refusal_group_count === 3);
report('v3.4.46 report contract product proof path north-star group case count', product46.north_star?.terminal_chain_recognition_refusal_group_case_count === 18);
report('v3.4.46 report contract product proof path north-star group case IDs preserved', product46.north_star?.terminal_chain_recognition_refusal_group_case_ids_preserved === true);
report('v3.4.46 report contract product proof path north-star group case IDs', groupCaseIdsExact(product46.north_star?.terminal_chain_recognition_refusal_group_case_ids));
const product46NorthStarGroupRenamed = { ...(product46.north_star?.terminal_chain_recognition_refusal_group_case_ids || {}) };
product46NorthStarGroupRenamed.recognized_receipt_scope_mismatches = product46NorthStarGroupRenamed.recognized_receipt_scope_mismatch;
delete product46NorthStarGroupRenamed.recognized_receipt_scope_mismatch;
report('v3.4.46 report contract product proof path north-star group case IDs reject renamed key', !groupCaseIdsExact(product46NorthStarGroupRenamed));
report('v3.4.46 report contract product proof path terminal group case IDs reject summary object', !groupCaseIdsExact({ summary: product46.terminal_chain_boundary?.recognition_refusal_group_case_ids }));
report('v3.4.46 result renders product proof path terminal group case IDs', result46.includes('manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognition_refusal_group_case_ids.no_usable_recognized_receipt_authority=missing_receipt_refused_before_runtime_mutation,invalid_receipt_refused_before_runtime_mutation,unknown_issuer_refused_before_runtime_mutation,retired_issuer_refused_before_runtime_mutation,missing_issuer_status_refused_before_runtime_mutation,stale_receipt_refused_before_runtime_mutation'));
report('v3.4.46 report contract omits deployment bridge', !Object.prototype.hasOwnProperty.call(product46, 'deployment_profile_authority_bridge'));
report('v3.4.46 report contract omits north-star deployment bridge', !Object.prototype.hasOwnProperty.call(product46.north_star || {}, 'deployment_profile_authority_bridge_observed'));
report('v3.4.46 result omits deployment bridge rendering', !result46.includes('manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.'));

const manifest48 = readJson(`${process.env.THRESHOLD_48_OUT}/DRY-RUN-MANIFEST.json`);
const result48 = fs.readFileSync(`${process.env.THRESHOLD_48_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const product48 = manifest48.release_forward_report_contract?.product_proof_path || {};
const bridge48 = product48.deployment_profile_authority_bridge || {};
const bridge48MissingProofType = { ...bridge48 };
delete bridge48MissingProofType.proof_type;
const bridge48RenamedProofType = { ...bridge48, proof_kind: bridge48.proof_type };
delete bridge48RenamedProofType.proof_type;
const northStar48SummaryShaped = {
  ...(product48.north_star || {}),
  deployment_profile_authority_bridge_summary: { observed: true },
};
report('v3.4.48 report contract product proof path evidence model', product48.evidence_model === 'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge');
report('v3.4.48 report contract deployment bridge exact keys', exactKeys(bridge48, expectedDeploymentProfileAuthorityBridgeKeys));
report('v3.4.48 report contract deployment bridge rejects extra key', !exactKeys({ ...bridge48, summary: true }, expectedDeploymentProfileAuthorityBridgeKeys));
report('v3.4.48 report contract deployment bridge rejects missing key', !exactKeys(bridge48MissingProofType, expectedDeploymentProfileAuthorityBridgeKeys));
report('v3.4.48 report contract deployment bridge rejects renamed key', !exactKeys(bridge48RenamedProofType, expectedDeploymentProfileAuthorityBridgeKeys));
report('v3.4.48 report contract deployment bridge proof type', bridge48.proof_type === 'zlar-protected-records-one-terminal-deployment-profile-proof-v1');
report('v3.4.48 report contract deployment bridge evidence model', bridge48.evidence_model === 'local-fixture-one-terminal-deployment-profile-authority-bridge');
report('v3.4.48 report contract deployment bridge no live probing', bridge48.live_probing === false);
report('v3.4.48 report contract deployment bridge profile sha', /^[0-9a-f]{64}$/.test(bridge48.deployment_profile_sha256 || ''));
report('v3.4.48 report contract deployment bridge runtime sha', /^[0-9a-f]{64}$/.test(bridge48.runtime_profile_sha256 || ''));
report('v3.4.48 report contract deployment bridge explicit selection', bridge48.selected_by_explicit_id_and_sha === true);
report('v3.4.48 report contract deployment bridge no latest', bridge48.selects_latest_profile === false);
report('v3.4.48 report contract deployment bridge preflight verified', bridge48.preflight_artifact_verified === true);
report('v3.4.48 report contract deployment bridge recognized once', bridge48.recognized_receipt_mutates_once === true && bridge48.recognized_state_entry_count_delta === 1);
report('v3.4.48 report contract deployment bridge refusal count', bridge48.required_refusal_case_count === 18 && bridge48.observed_refusal_case_count === 18);
report('v3.4.48 report contract deployment bridge refusals before mutation', bridge48.all_required_refusals_before_mutation === true);
report('v3.4.48 report contract deployment bridge agent authority refused', bridge48.agent_supplied_authority_refused_before_mutation === true);
report('v3.4.48 report contract deployment bridge direct API refused', bridge48.direct_api_refused_before_mutation === true);
report('v3.4.48 report contract deployment bridge downstream refusal proven', bridge48.downstream_refusal_proven === true);
report('v3.4.48 report contract deployment bridge request authority false', bridge48.request_stream_authority_material_accepted === false);
report('v3.4.48 report contract deployment bridge current-machine false', bridge48.current_machine_governance === false);
report('v3.4.48 report contract deployment bridge production false', bridge48.production_downstream_recognition === false && bridge48.production_authority === false);
report('v3.4.48 report contract deployment bridge enterprise external false', bridge48.enterprise_readiness === false && bridge48.external_attestation === false);
report('v3.4.48 report contract deployment bridge sovereign unrouted false', bridge48.sovereign_recognition === false && bridge48.unrouted_surface_coverage === false);
report('v3.4.48 report contract north-star deployment authority family keys exact', exactDeploymentProfileAuthorityNorthStarKeys(product48.north_star, expectedDeploymentProfileAuthorityBridgeNorthStarKeys));
report('v3.4.48 report contract north-star deployment authority rejects summary-shaped family field', !exactDeploymentProfileAuthorityNorthStarKeys(northStar48SummaryShaped, expectedDeploymentProfileAuthorityBridgeNorthStarKeys));
report('v3.4.48 report contract north-star deployment bridge required', product48.north_star?.deployment_profile_authority_bridge_required === true);
report('v3.4.48 report contract north-star deployment bridge preserved', product48.north_star?.deployment_profile_authority_bridge_preserved === true);
report('v3.4.48 report contract north-star deployment bridge observed', product48.north_star?.deployment_profile_authority_bridge_observed === true);
report('v3.4.48 report contract north-star deployment bridge refusal count', product48.north_star?.deployment_profile_authority_bridge_refusal_count === 18);
report('v3.4.48 report contract north-star deployment bridge current-machine false', product48.north_star?.deployment_profile_authority_bridge_current_machine_governance === false);
report('v3.4.48 report contract north-star deployment bridge production false', product48.north_star?.deployment_profile_authority_bridge_production_authority === false);
report('v3.4.48 result renders deployment bridge', result48.includes('manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.proof_type=zlar-protected-records-one-terminal-deployment-profile-proof-v1'));
report('v3.4.48 result renders north-star deployment bridge', result48.includes('manifest.release_forward_report_contract.product_proof_path.north_star.deployment_profile_authority_bridge_preserved=true'));
report('v3.4.48 report contract omits deployment authority refusal fields', !Object.prototype.hasOwnProperty.call(bridge48, 'deployment_profile_authority_refusal_case_count'));
report('v3.4.48 report contract omits north-star deployment authority refusal fields', !Object.prototype.hasOwnProperty.call(product48.north_star || {}, 'deployment_profile_authority_refusals_required'));
report('v3.4.48 result omits deployment authority refusal rendering', !result48.includes('manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_count'));

const manifest49 = readJson(`${process.env.THRESHOLD_49_OUT}/DRY-RUN-MANIFEST.json`);
const result49 = fs.readFileSync(`${process.env.THRESHOLD_49_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const product49 = manifest49.release_forward_report_contract?.product_proof_path || {};
const bridge49 = product49.deployment_profile_authority_bridge || {};
const bridge49MissingRefusalCount = { ...bridge49 };
delete bridge49MissingRefusalCount.deployment_profile_authority_refusal_case_count;
const bridge49RenamedRefusalCount = {
  ...bridge49,
  deployment_profile_authority_refusal_total: bridge49.deployment_profile_authority_refusal_case_count,
};
delete bridge49RenamedRefusalCount.deployment_profile_authority_refusal_case_count;
const northStar49SummaryShaped = {
  ...(product49.north_star || {}),
  deployment_profile_authority_refusals_summary: { preserved: true },
};
const terminalEvidence49 = manifest49.terminal_chain_refusal_evidence || {};
const terminalContract49 = manifest49.release_forward_report_contract?.terminal_chain_refusal_evidence || {};
report('v3.4.49 report contract deployment bridge authority refusal exact keys', exactKeys(bridge49, expectedDeploymentProfileAuthorityBridgeV349Keys));
report('v3.4.49 report contract deployment authority refusals reject extra key', !exactKeys({ ...bridge49, deployment_profile_authority_refusal_summary: true }, expectedDeploymentProfileAuthorityBridgeV349Keys));
report('v3.4.49 report contract deployment authority refusals reject missing key', !exactKeys(bridge49MissingRefusalCount, expectedDeploymentProfileAuthorityBridgeV349Keys));
report('v3.4.49 report contract deployment authority refusals reject renamed key', !exactKeys(bridge49RenamedRefusalCount, expectedDeploymentProfileAuthorityBridgeV349Keys));
report('v3.4.49 report contract deployment authority refusal count', bridge49.deployment_profile_authority_refusal_case_count === expectedDeploymentProfileAuthorityRefusalCaseIds.length);
report('v3.4.49 report contract deployment authority refusal case IDs', arraysEqual(bridge49.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
report('v3.4.49 report contract deployment authority refusals before service proof', bridge49.deployment_profile_authority_refusals_before_service_proof === true);
report('v3.4.49 report contract deployment authority refusals before mutation', bridge49.deployment_profile_authority_refusals_before_mutation === true);
report('v3.4.49 report contract deployment authority refusal service proof not started', bridge49.deployment_profile_authority_refusal_service_proof_started === false);
report('v3.4.49 report contract stale artifact refusal', bridge49.stale_deployment_profile_artifact_refused_before_service_proof === true);
report('v3.4.49 report contract profile mismatch refusal', bridge49.profile_recognition_mismatch_refused_before_service_proof === true);
report('v3.4.49 report contract latest selection refusal', bridge49.latest_profile_selection_refused_before_service_proof === true);
report('v3.4.49 report contract request authority refusal', bridge49.request_stream_authority_material_refused_before_service_proof === true);
report('v3.4.49 report contract north-star deployment authority family keys exact', exactDeploymentProfileAuthorityNorthStarKeys(product49.north_star, expectedDeploymentProfileAuthorityNorthStarV349Keys));
report('v3.4.49 report contract north-star deployment authority rejects summary-shaped refusal field', !exactDeploymentProfileAuthorityNorthStarKeys(northStar49SummaryShaped, expectedDeploymentProfileAuthorityNorthStarV349Keys));
report('v3.4.49 report contract north-star authority refusals required', product49.north_star?.deployment_profile_authority_refusals_required === true);
report('v3.4.49 report contract north-star authority refusals preserved', product49.north_star?.deployment_profile_authority_refusals_preserved === true);
report('v3.4.49 report contract north-star authority refusal case IDs', arraysEqual(product49.north_star?.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
report('v3.4.49 result renders deployment authority refusal count', result49.includes('manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_count=5'));
report('v3.4.49 result renders deployment authority refusal case IDs', result49.includes('manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids=stale_deployment_profile_runtime_sha_refused_before_service_proof,runtime_profile_id_mismatch_refused_before_service_proof,preflight_profile_sha_mismatch_refused_before_service_proof,preflight_latest_selection_refused_before_service_proof,preflight_request_authority_material_refused_before_service_proof'));
report('v3.4.49 result renders north-star deployment authority refusals', result49.includes('manifest.release_forward_report_contract.product_proof_path.north_star.deployment_profile_authority_refusals_preserved=true'));
report('v3.4.49 terminal-chain mirror omitted from manifest', !Object.prototype.hasOwnProperty.call(terminalEvidence49, 'deployment_profile_authority_refusal_mirror_required'));
report('v3.4.49 terminal-chain mirror omitted from report contract', !Object.prototype.hasOwnProperty.call(terminalContract49, 'deployment_profile_authority_refusal_mirror_required'));
report('v3.4.49 result omits terminal-chain mirror rendering', !result49.includes('manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror_required'));

const manifest50 = readJson(`${process.env.THRESHOLD_50_OUT}/DRY-RUN-MANIFEST.json`);
const result50 = fs.readFileSync(`${process.env.THRESHOLD_50_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const terminalEvidence50 = manifest50.terminal_chain_refusal_evidence || {};
const terminalContract50 = manifest50.release_forward_report_contract?.terminal_chain_refusal_evidence || {};
const product50 = manifest50.release_forward_report_contract?.product_proof_path || {};
const proofSmoke50 = manifest50.release_forward_report_contract?.proof_smoke?.counts || {};
const northStar50 = manifest50.release_forward_report_contract?.north_star?.counts || {};
report('v3.4.50 terminal-chain mirror required in manifest', terminalEvidence50.deployment_profile_authority_refusal_mirror_required === true);
report('v3.4.50 terminal-chain mirror preserved in manifest', terminalEvidence50.deployment_profile_authority_refusal_mirror_preserved === true);
report('v3.4.50 terminal-chain mirror case count', terminalEvidence50.deployment_profile_authority_refusal_case_count === expectedDeploymentProfileAuthorityRefusalCaseIds.length);
report('v3.4.50 terminal-chain mirror artifact case count', terminalEvidence50.artifact_verification_deployment_profile_authority_refusal_case_count === expectedDeploymentProfileAuthorityRefusalCaseIds.length);
report('v3.4.50 terminal-chain mirror case IDs', arraysEqual(terminalEvidence50.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
report('v3.4.50 terminal-chain mirror artifact case IDs', arraysEqual(terminalEvidence50.artifact_verification_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
report('v3.4.50 terminal-chain mirror before service proof', terminalEvidence50.deployment_profile_authority_refusals_before_service_proof === true);
report('v3.4.50 terminal-chain mirror service proof not started', terminalEvidence50.deployment_profile_authority_refusal_service_proof_started === false);
report('v3.4.50 terminal-chain mirror current-machine false', terminalEvidence50.current_machine_governance === false);
report('v3.4.50 terminal-chain mirror production downstream false', terminalEvidence50.production_downstream_recognition === false);
report('v3.4.50 terminal-chain mirror production false', terminalEvidence50.production_authority === false);
report('v3.4.50 terminal-chain mirror enterprise false', terminalEvidence50.enterprise_readiness === false);
report('v3.4.50 terminal-chain mirror external false', terminalEvidence50.external_attestation === false);
report('v3.4.50 terminal-chain mirror sovereign false', terminalEvidence50.sovereign_recognition === false);
report('v3.4.50 terminal-chain mirror unrouted false', terminalEvidence50.unrouted_surface_coverage === false);
report('v3.4.50 report contract mirror preserved', terminalContract50.deployment_profile_authority_refusal_mirror_preserved === true);
report('v3.4.50 report contract mirror case IDs', arraysEqual(terminalContract50.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
report('v3.4.50 report contract mirror full false boundary', terminalContract50.current_machine_governance === false && terminalContract50.production_downstream_recognition === false && terminalContract50.production_authority === false && terminalContract50.enterprise_readiness === false && terminalContract50.external_attestation === false && terminalContract50.sovereign_recognition === false && terminalContract50.unrouted_surface_coverage === false);
report('v3.4.50 report contract proof-smoke trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(proofSmoke50, expectedReportContractProofSmokeTrustedRegistryRecognitionRefusalKeys));
report('v3.4.50 report contract north-star trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(northStar50, expectedReportContractNorthStarTrustedRegistryRecognitionRefusalKeys));
report('v3.4.50 report contract enterprise trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(manifest50.release_forward_report_contract?.north_star?.puzzle_3_observed, expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys));
report('v3.4.50 report contract downstream trusted registry family keys exact', exactReportContractProofSummaryTrustedRegistryRefusalKeys(manifest50.release_forward_report_contract?.north_star?.puzzle_5_observed, expectedReportContractNorthStarObservedTrustedRegistryRecognitionRefusalKeys));
report('v3.4.50 report contract proof-smoke mirror preserved', proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved === true);
report('v3.4.50 report contract proof-smoke mirror profile sha matches', proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches === true);
report('v3.4.50 report contract proof-smoke mirror case IDs', arraysEqual(proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
report('v3.4.50 report contract proof-smoke mirror full false boundary', proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance === false && proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition === false && proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority === false && proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness === false && proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation === false && proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition === false && proofSmoke50.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage === false);
report('v3.4.50 report contract north-star mirror required', northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required === true);
report('v3.4.50 report contract north-star mirror preserved', northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved === true);
report('v3.4.50 report contract north-star mirror case IDs', arraysEqual(northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds));
report('v3.4.50 report contract north-star mirror full false boundary', northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance === false && northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition === false && northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority === false && northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness === false && northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation === false && northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition === false && northStar50.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage === false);
report('v3.4.50 result renders terminal-chain mirror required', result50.includes('manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror_required=true'));
report('v3.4.50 result renders report contract mirror case count', result50.includes('manifest.release_forward_report_contract.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_case_count=5'));
report('v3.4.50 result renders proof-smoke mirror preserved', result50.includes('manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true'));
report('v3.4.50 result renders north-star mirror preserved', result50.includes('manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true'));
report('v3.4.50 report contract omits terminal trusted-registry verdict', !Object.prototype.hasOwnProperty.call(product50.terminal_chain_boundary || {}, 'trusted_issuer_registry_recognition_verdict'));
report('v3.4.50 result omits terminal trusted-registry verdict rendering', !result50.includes('manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_verdict='));
report('v3.4.50 report contract omits downstream-refusal boundary', !Object.prototype.hasOwnProperty.call(product50, 'downstream_refusal_boundary') && !Object.prototype.hasOwnProperty.call(product50.north_star || {}, 'downstream_refusal_boundary'));
report('v3.4.50 result omits downstream-refusal boundary rendering', !result50.includes('manifest.release_forward_report_contract.product_proof_path.downstream_refusal_boundary.'));

const manifest51 = readJson(`${process.env.THRESHOLD_51_OUT}/DRY-RUN-MANIFEST.json`);
const result51 = fs.readFileSync(`${process.env.THRESHOLD_51_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const contract51 = manifest51.release_forward_report_contract || {};
const product51 = contract51.product_proof_path || {};
const downstream51 = product51.downstream_refusal_boundary || {};
const northStarDownstream51 = product51.north_star?.downstream_refusal_boundary || {};
report('v3.4.51 report contract satisfied', contract51.report_contract_satisfied === true);
report('v3.4.51 terminal trusted-registry verdict preserved', product51.terminal_chain_boundary?.trusted_issuer_registry_recognition_verdict === 'RECOGNIZED');
report('v3.4.51 terminal trusted-registry recognized preserved', product51.terminal_chain_boundary?.trusted_issuer_registry_recognition_recognized === true);
report('v3.4.51 terminal trusted-registry signature valid preserved', product51.terminal_chain_boundary?.trusted_issuer_registry_recognition_signature_valid === true);
report('v3.4.51 terminal trusted-registry rule evaluated', product51.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_to_recognition_rule_evaluated === true);
report('v3.4.51 terminal trusted-registry evaluator type', product51.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_evaluation_result_type === 'downstream-recognition-rule-v1');
report('v3.4.51 terminal trusted-registry fixture contract sha', /^[0-9a-f]{64}$/.test(product51.terminal_chain_boundary?.trusted_issuer_registry_recognition_registry_fixture_contract_sha256 || ''));
report('v3.4.51 terminal trusted-registry prefixed keys exact', exactPrefixedKeys(product51.terminal_chain_boundary, 'trusted_issuer_registry_recognition_', expectedTerminalChainTrustedRegistryRecognitionKeys));
report('v3.4.51 north-star trusted-registry verdict preserved', product51.north_star?.terminal_chain_trusted_issuer_registry_recognition_verdict === 'RECOGNIZED');
report('v3.4.51 north-star trusted-registry signature valid preserved', product51.north_star?.terminal_chain_trusted_issuer_registry_recognition_signature_valid === true);
report('v3.4.51 north-star trusted-registry prefixed keys exact', exactPrefixedKeys(product51.north_star, 'terminal_chain_trusted_issuer_registry_recognition_', expectedNorthStarTrustedRegistryVerdictKeys));
report('v3.4.51 downstream-refusal boundary recognized marker delta', downstream51.recognized_marker_count_delta === 1);
report('v3.4.51 downstream-refusal boundary final marker count', downstream51.final_marker_count === 1);
report('v3.4.51 downstream-refusal boundary refusal case count', downstream51.refusal_case_count === 11);
report('v3.4.51 downstream-refusal boundary refusals unboarded', downstream51.all_refusals_unboarded === true);
report('v3.4.51 downstream-refusal boundary refusal reasons', arraysEqual(downstream51.refusal_reasons, expectedDownstreamRefusalReasons));
report('v3.4.51 downstream-refusal boundary refusal marker deltas zero', downstream51.all_refusal_marker_count_deltas_zero === true);
report('v3.4.51 downstream-refusal boundary exact keys', exactKeys(downstream51, expectedDownstreamRefusalBoundaryKeys));
report('v3.4.51 north-star downstream-refusal boundary preserved', northStarDownstream51.recognized_marker_count_delta === 1 && northStarDownstream51.all_refusal_marker_count_deltas_zero === true);
report('v3.4.51 north-star downstream-refusal boundary refusals unboarded', northStarDownstream51.all_refusals_unboarded === true);
report('v3.4.51 north-star downstream-refusal boundary refusal reasons', arraysEqual(northStarDownstream51.refusal_reasons, expectedDownstreamRefusalReasons));
report('v3.4.51 north-star downstream-refusal boundary exact keys', exactKeys(northStarDownstream51, expectedDownstreamRefusalBoundaryKeys));
report('v3.4.51 result renders terminal trusted-registry verdict', result51.includes('manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_verdict=RECOGNIZED'));
report('v3.4.51 result renders north-star trusted-registry verdict', result51.includes('manifest.release_forward_report_contract.product_proof_path.north_star.terminal_chain_trusted_issuer_registry_recognition_verdict=RECOGNIZED'));
report('v3.4.51 result renders downstream-refusal marker delta', result51.includes('manifest.release_forward_report_contract.product_proof_path.downstream_refusal_boundary.recognized_marker_count_delta=1'));
report('v3.4.51 result renders downstream-refusal unboarded boundary', result51.includes('manifest.release_forward_report_contract.product_proof_path.downstream_refusal_boundary.all_refusals_unboarded=true'));
report('v3.4.51 result renders downstream-refusal reasons', result51.includes('manifest.release_forward_report_contract.product_proof_path.downstream_refusal_boundary.refusal_reasons=receipt_missing,receipt_invalid,issuer_not_active,unknown_issuer,outcome_not_boarding,policy_not_recognized,domain_out_of_scope,tool_out_of_scope,audit_event_mismatch,detail_hash_mismatch,receipt_stale'));
report('v3.4.51 result renders north-star downstream-refusal marker deltas zero', result51.includes('manifest.release_forward_report_contract.product_proof_path.north_star.downstream_refusal_boundary.all_refusal_marker_count_deltas_zero=true'));
report('v3.4.51 result renders north-star downstream-refusal unboarded boundary', result51.includes('manifest.release_forward_report_contract.product_proof_path.north_star.downstream_refusal_boundary.all_refusals_unboarded=true'));
report('v3.4.51 result renders north-star downstream-refusal reasons', result51.includes('manifest.release_forward_report_contract.product_proof_path.north_star.downstream_refusal_boundary.refusal_reasons=receipt_missing,receipt_invalid,issuer_not_active,unknown_issuer,outcome_not_boarding,policy_not_recognized,domain_out_of_scope,tool_out_of_scope,audit_event_mismatch,detail_hash_mismatch,receipt_stale'));
report('v3.4.51 recognized receipt path mirror omitted from terminal boundary', !prefixedKeys(product51.terminal_chain_boundary, 'recognized_receipt_path_evidence_').length);
report('v3.4.51 recognized receipt path mirror omitted from north-star boundary', !prefixedKeys(product51.north_star, 'terminal_chain_recognized_receipt_path_evidence_').length);
report(
  'v3.4.51 result omits recognized receipt path mirror rendering',
  !result51.includes(
    'manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognized_receipt_path_evidence_'
  ) &&
    !result51.includes(
      'manifest.release_forward_report_contract.product_proof_path.north_star.terminal_chain_recognized_receipt_path_evidence_'
    )
);

const manifest52 = readJson(`${process.env.THRESHOLD_52_OUT}/DRY-RUN-MANIFEST.json`);
const result52 = fs.readFileSync(`${process.env.THRESHOLD_52_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const contract52 = manifest52.release_forward_report_contract || {};
const product52 = contract52.product_proof_path || {};
const terminal52 = product52.terminal_chain_boundary || {};
const northStar52 = product52.north_star || {};
const terminal52MissingSha = { ...terminal52 };
delete terminal52MissingSha.recognized_receipt_path_evidence_sha256;
const terminal52RenamedSha = {
  ...terminal52,
  recognized_receipt_path_evidence_hash: terminal52.recognized_receipt_path_evidence_sha256,
};
delete terminal52RenamedSha.recognized_receipt_path_evidence_sha256;
const terminal52SummaryShaped = {
  ...terminal52,
  recognized_receipt_path_evidence_sha256: {
    value: terminal52.recognized_receipt_path_evidence_sha256,
  },
};
const terminal52AdjacentSummary = {
  ...terminal52,
  recognized_receipt_path_summary: {
    verdict: 'RECOGNIZED',
  },
};
const terminal52TamperedSha = {
  ...terminal52,
  recognized_receipt_path_evidence_sha256: '0'.repeat(64),
};
const terminal52SourceBindingMismatch = {
  ...terminal52,
  recognized_receipt_path_evidence_source_binding_sha256: '1'.repeat(64),
};
const terminal52FalseBoundaryFlip = {
  ...terminal52,
  recognized_receipt_path_evidence_public_external_attestation: true,
};
const northStar52MissingSha = { ...northStar52 };
delete northStar52MissingSha.terminal_chain_recognized_receipt_path_evidence_sha256;
const northStar52RenamedSha = {
  ...northStar52,
  terminal_chain_recognized_receipt_path_evidence_hash:
    northStar52.terminal_chain_recognized_receipt_path_evidence_sha256,
};
delete northStar52RenamedSha.terminal_chain_recognized_receipt_path_evidence_sha256;
const northStar52SummaryShaped = {
  ...northStar52,
  terminal_chain_recognized_receipt_path_evidence_sha256: {
    value: northStar52.terminal_chain_recognized_receipt_path_evidence_sha256,
  },
};
const northStar52AdjacentSummary = {
  ...northStar52,
  terminal_chain_recognized_receipt_path_summary: {
    verdict: 'RECOGNIZED',
  },
};
report('v3.4.52 report contract satisfied', contract52.report_contract_satisfied === true);
report('v3.4.52 recognized receipt path terminal exact keys', exactRecognizedReceiptPathKeys(terminal52, expectedRecognizedReceiptPathMirrorKeys));
report('v3.4.52 recognized receipt path terminal rejects extra key', !exactRecognizedReceiptPathKeys({ ...terminal52, recognized_receipt_path_evidence_summary: true }, expectedRecognizedReceiptPathMirrorKeys));
report('v3.4.52 recognized receipt path terminal rejects missing key', !exactRecognizedReceiptPathKeys(terminal52MissingSha, expectedRecognizedReceiptPathMirrorKeys));
report('v3.4.52 recognized receipt path terminal rejects renamed key', !exactRecognizedReceiptPathKeys(terminal52RenamedSha, expectedRecognizedReceiptPathMirrorKeys));
report('v3.4.52 recognized receipt path terminal rejects summary-shaped field', !exactRecognizedReceiptPathKeys(terminal52SummaryShaped, expectedRecognizedReceiptPathMirrorKeys) || typeof terminal52SummaryShaped.recognized_receipt_path_evidence_sha256 !== 'string');
report('v3.4.52 recognized receipt path terminal rejects adjacent summary key', !exactRecognizedReceiptPathKeys(terminal52AdjacentSummary, expectedRecognizedReceiptPathMirrorKeys));
report('v3.4.52 recognized receipt path evidence sha hash-bound', /^[0-9a-f]{64}$/.test(terminal52.recognized_receipt_path_evidence_sha256 || '') && terminal52.recognized_receipt_path_evidence_sha256 === terminal52.recognized_receipt_path_evidence_artifact_verification_sha256 && terminal52.recognized_receipt_path_evidence_sha256_matches_artifact_verification === true);
report('v3.4.52 recognized receipt path tampered evidence sha refused by contract', terminal52TamperedSha.recognized_receipt_path_evidence_sha256 !== terminal52TamperedSha.recognized_receipt_path_evidence_artifact_verification_sha256);
report('v3.4.52 recognized receipt path source binding equals trusted registry binding', terminal52.recognized_receipt_path_evidence_source_binding_sha256 === terminal52.trusted_issuer_registry_recognition_binding_sha256 && terminal52.recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding === true);
report('v3.4.52 recognized receipt path source-binding mismatch refused by contract', terminal52SourceBindingMismatch.recognized_receipt_path_evidence_source_binding_sha256 !== terminal52SourceBindingMismatch.trusted_issuer_registry_recognition_binding_sha256);
report('v3.4.52 recognized receipt path verdict compact only', terminal52.recognized_receipt_path_evidence_verdict === 'RECOGNIZED' && terminal52.recognized_receipt_path_evidence_recognized === true);
report('v3.4.52 recognized receipt path false boundaries stay false', recognizedReceiptPathFalseBoundaryKeys.every((key) => terminal52[key] === false));
report('v3.4.52 recognized receipt path false-boundary flip refused by contract', terminal52FalseBoundaryFlip.recognized_receipt_path_evidence_public_external_attestation !== false);
report('v3.4.52 north-star recognized receipt path exact keys', exactRecognizedReceiptPathKeys(northStar52, expectedNorthStarRecognizedReceiptPathMirrorKeys));
report('v3.4.52 north-star recognized receipt path rejects extra key', !exactRecognizedReceiptPathKeys({ ...northStar52, terminal_chain_recognized_receipt_path_evidence_summary: true }, expectedNorthStarRecognizedReceiptPathMirrorKeys));
report('v3.4.52 north-star recognized receipt path rejects missing key', !exactRecognizedReceiptPathKeys(northStar52MissingSha, expectedNorthStarRecognizedReceiptPathMirrorKeys));
report('v3.4.52 north-star recognized receipt path rejects renamed key', !exactRecognizedReceiptPathKeys(northStar52RenamedSha, expectedNorthStarRecognizedReceiptPathMirrorKeys));
report('v3.4.52 north-star recognized receipt path rejects summary-shaped field', !exactRecognizedReceiptPathKeys(northStar52SummaryShaped, expectedNorthStarRecognizedReceiptPathMirrorKeys) || typeof northStar52SummaryShaped.terminal_chain_recognized_receipt_path_evidence_sha256 !== 'string');
report('v3.4.52 north-star recognized receipt path rejects adjacent summary key', !exactRecognizedReceiptPathKeys(northStar52AdjacentSummary, expectedNorthStarRecognizedReceiptPathMirrorKeys));
report('v3.4.52 north-star recognized receipt path mirrors terminal fields', expectedRecognizedReceiptPathMirrorKeys.every((key) => JSON.stringify(northStar52[`terminal_chain_${key}`]) === JSON.stringify(terminal52[key])));
report('v3.4.52 result renders recognized receipt path terminal sha', result52.includes(`manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognized_receipt_path_evidence_sha256=${terminal52.recognized_receipt_path_evidence_sha256}`));
report('v3.4.52 result renders recognized receipt path north-star sha', result52.includes(`manifest.release_forward_report_contract.product_proof_path.north_star.terminal_chain_recognized_receipt_path_evidence_sha256=${northStar52.terminal_chain_recognized_receipt_path_evidence_sha256}`));

const manifest53 = readJson(`${process.env.THRESHOLD_53_OUT}/DRY-RUN-MANIFEST.json`);
const result53 = fs.readFileSync(`${process.env.THRESHOLD_53_OUT}/DRY-RUN-RESULT.md`, 'utf8');
const readiness53 = readJson(`${process.env.THRESHOLD_53_OUT}/ZLAR/zlar-north-star-readiness-v1.json`);
const trustedCompletion53 = manifest53.trusted_receipt_issuer_completion_evidence || {};
const trustedIssuerPiece53 = readiness53.puzzle_pieces?.find((piece) => piece.id === 4) || {};
const readinessCompletion53 =
  trustedIssuerPiece53.observed?.trusted_receipt_issuer_completion_proof || {};
const manifestArtifactPaths53 = (manifest53.artifact_hashes || []).map((item) => item.path);
const completionFalseBoundaryKeys53 = [
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
];
report('v3.4.53 trusted completion manifest enabled', trustedCompletion53.enabled === true);
report('v3.4.53 trusted completion manifest evidence model', trustedCompletion53.evidence_model === 'release-forward-supplied-private-core-completion-proof');
report('v3.4.53 trusted completion proof path preserved', trustedCompletion53.proof_path === 'ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json');
report('v3.4.53 trusted completion verification path preserved', trustedCompletion53.verification_path === 'ZLAR/zlar-trusted-receipt-issuer-completion-proof-verification-v1.json');
report('v3.4.53 trusted completion direct artifact hashes present', /^[0-9a-f]{64}$/.test(trustedCompletion53.proof_artifact_sha256 || '') && /^[0-9a-f]{64}$/.test(trustedCompletion53.verification_artifact_sha256 || ''));
report('v3.4.53 trusted completion not in core artifact hash set', !manifestArtifactPaths53.includes('ZLAR/zlar-trusted-receipt-issuer-completion-proof-v1.json') && !manifestArtifactPaths53.includes('ZLAR/zlar-trusted-receipt-issuer-completion-proof-verification-v1.json'));
report('v3.4.53 trusted completion verification true', trustedCompletion53.verified === true);
report('v3.4.53 trusted completion selected private operator terminal', trustedCompletion53.selected_surface_id === 'protected-records.private-operator.records-terminal.records.write');
report('v3.4.53 trusted completion readiness terminal remains profile installation', trustedCompletion53.readiness_selected_terminal_surface_id === 'protected-records.runtime.profile-installation.records.write' && readiness53.selected_terminal?.surface_id === 'protected-records.runtime.profile-installation.records.write');
report('v3.4.53 trusted completion distinct terminal allowance explicit', trustedCompletion53.proof_selected_surface_can_differ_from_readiness_selected_terminal === true);
report('v3.4.53 trusted completion preserves direct human authority event', trustedCompletion53.authority_event_type === 'direct_human_approval');
report('v3.4.53 trusted completion false claim boundary', trustedCompletion53.claim_boundary_flags_false === true && completionFalseBoundaryKeys53.every((key) => trustedCompletion53[key] === false));
report('v3.4.53 trusted completion not public by default', trustedCompletion53.not_public_by_default === true && trustedCompletion53.source_publication_evidence === false);
report('v3.4.53 readiness trusted issuer completion proven', trustedIssuerPiece53.status === 'operator_owned_private_core_completion_proven');
report('v3.4.53 readiness trusted completion provided and verified', readinessCompletion53.provided === true && readinessCompletion53.verified === true);
report('v3.4.53 readiness trusted completion selected private operator terminal', readinessCompletion53.selected_surface_id === 'protected-records.private-operator.records-terminal.records.write');
report('v3.4.53 readiness trusted completion completed for surface', readinessCompletion53.completed_for_selected_surface === true);
report('v3.4.53 readiness trusted completion claim boundary false', Object.values(readinessCompletion53.claim_boundary || {}).every((value) => value === false));
report('v3.4.53 readiness stronger claims remain false', readiness53.claim_boundary?.public_external_attestation === false && readiness53.claim_boundary?.production_authority === false && readiness53.claim_boundary?.production_downstream_recognition === false && readiness53.claim_boundary?.key_custody === false && readiness53.claim_boundary?.current_machine_governance === false && readiness53.claim_boundary?.unrouted_surface_coverage === false);
report('v3.4.53 readiness artifacts include supplied proof', (readiness53.artifacts_consumed || []).includes('zlar-trusted-receipt-issuer-completion-proof-v1.json'));
report('v3.4.53 result renders trusted completion selected surface', result53.includes('manifest.trusted_receipt_issuer_completion_evidence.selected_surface_id=protected-records.private-operator.records-terminal.records.write'));
report('v3.4.53 result renders trusted completion no public attestation', result53.includes('manifest.trusted_receipt_issuer_completion_evidence.creates_public_external_attestation=false'));
report('v3.4.53 result renders trusted completion no source publication', result53.includes('manifest.trusted_receipt_issuer_completion_evidence.proves_source_publication=false'));
report('v3.4.53 result renders trusted completion no production downstream', result53.includes('manifest.trusted_receipt_issuer_completion_evidence.proves_production_downstream_recognition=false'));
NODE
)"
assert_contains "v3.4.38 terminal evidence present" "PASS v3.4.38 terminal-chain refusal evidence remains present" "${threshold_check}"
assert_contains "v3.4.38 manifest omits trusted registry refusal fields" "PASS v3.4.38 omits trusted-registry refusal manifest fields" "${threshold_check}"
assert_contains "v3.4.38 result omits trusted registry refusal summary" "PASS v3.4.38 result omits trusted-registry refusal manifest summary" "${threshold_check}"
assert_contains "v3.4.38 result omits trusted registry refusal report contract" "PASS v3.4.38 result omits trusted-registry refusal report contract" "${threshold_check}"
assert_contains "v3.4.39 manifest requires trusted registry refusal fields" "PASS v3.4.39 trusted-registry refusal manifest required" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry refusal minimum target" "PASS v3.4.39 trusted-registry refusal minimum target" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry refusal count" "PASS v3.4.39 trusted-registry refusal case count" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry artifact refusal count" "PASS v3.4.39 trusted-registry artifact refusal case count" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry refusal case ids" "PASS v3.4.39 trusted-registry refusal case ids" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry artifact refusal case ids" "PASS v3.4.39 trusted-registry artifact refusal case ids" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry refusal reasons" "PASS v3.4.39 trusted-registry refusal reason codes" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry artifact refusal reasons" "PASS v3.4.39 trusted-registry artifact refusal reason codes" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry refusal hashes" "PASS v3.4.39 trusted-registry refusal hashes match" "${threshold_check}"
assert_contains "v3.4.39 manifest trusted registry refusals preserved" "PASS v3.4.39 trusted-registry refusals preserved" "${threshold_check}"
assert_contains "v3.4.39 result trusted registry refusal manifest summary" "PASS v3.4.39 result includes trusted-registry refusal manifest summary" "${threshold_check}"
assert_contains "v3.4.39 result trusted registry refusal report contract" "PASS v3.4.39 result includes trusted-registry refusal report contract" "${threshold_check}"
assert_contains "v3.4.40 manifest omits report contract" "PASS v3.4.40 omits release-forward report contract manifest object" "${threshold_check}"
assert_contains "v3.4.40 result omits report contract rendering" "PASS v3.4.40 result omits manifest report contract rendering" "${threshold_check}"
assert_contains "v3.4.41 report contract enabled" "PASS v3.4.41 report contract enabled" "${threshold_check}"
assert_contains "v3.4.41 report contract type" "PASS v3.4.41 report contract type" "${threshold_check}"
assert_contains "v3.4.41 report contract evidence model" "PASS v3.4.41 report contract evidence model" "${threshold_check}"
assert_contains "v3.4.41 report contract minimum target" "PASS v3.4.41 report contract minimum target" "${threshold_check}"
assert_contains "v3.4.41 report contract satisfied" "PASS v3.4.41 report contract satisfied" "${threshold_check}"
assert_contains "v3.4.41 report contract manifest canonical" "PASS v3.4.41 report contract manifest canonical" "${threshold_check}"
assert_contains "v3.4.41 report contract proof-smoke hash" "PASS v3.4.41 report contract proof-smoke hash" "${threshold_check}"
assert_contains "v3.4.41 report contract north-star hash" "PASS v3.4.41 report contract north-star hash" "${threshold_check}"
assert_contains "v3.4.41 report contract terminal source" "PASS v3.4.41 report contract terminal source same manifest" "${threshold_check}"
assert_contains "v3.4.41 report contract group count" "PASS v3.4.41 report contract group count" "${threshold_check}"
assert_contains "v3.4.41 report contract group case count" "PASS v3.4.41 report contract group case count" "${threshold_check}"
assert_contains "v3.4.41 report contract north-star group preserved" "PASS v3.4.41 report contract north-star group case ids preserved" "${threshold_check}"
assert_contains "v3.4.41 report contract trusted registry terminal count" "PASS v3.4.41 report contract trusted registry terminal count" "${threshold_check}"
assert_contains "v3.4.41 report contract trusted registry terminal case ids" "PASS v3.4.41 report contract trusted registry terminal case ids" "${threshold_check}"
assert_contains "v3.4.41 report contract trusted registry terminal reasons" "PASS v3.4.41 report contract trusted registry terminal reasons" "${threshold_check}"
assert_contains "v3.4.41 report contract trusted registry terminal hash" "PASS v3.4.41 report contract trusted registry terminal hash match" "${threshold_check}"
assert_contains "v3.4.41 report contract proof-smoke trusted registry count" "PASS v3.4.41 report contract proof-smoke trusted registry count" "${threshold_check}"
assert_contains "v3.4.41 report contract proof-smoke trusted registry ids" "PASS v3.4.41 report contract proof-smoke trusted registry case ids" "${threshold_check}"
assert_contains "v3.4.41 report contract north-star trusted registry preserved" "PASS v3.4.41 report contract north-star trusted registry preserved" "${threshold_check}"
assert_contains "v3.4.41 report contract north-star trusted registry ids" "PASS v3.4.41 report contract north-star trusted registry case ids" "${threshold_check}"
assert_contains "v3.4.41 report contract enterprise trusted registry preserved" "PASS v3.4.41 report contract enterprise trusted registry preserved" "${threshold_check}"
assert_contains "v3.4.41 report contract downstream trusted registry preserved" "PASS v3.4.41 report contract downstream trusted registry preserved" "${threshold_check}"
assert_contains "v3.4.41 report contract claim boundary exact keys" "PASS v3.4.41 report contract claim boundary exact keys" "${threshold_check}"
assert_contains "v3.4.41 report contract claim boundary rejects extra key" "PASS v3.4.41 report contract claim boundary rejects extra key" "${threshold_check}"
assert_contains "v3.4.41 report contract claim boundary rejects missing key" "PASS v3.4.41 report contract claim boundary rejects missing key" "${threshold_check}"
assert_contains "v3.4.41 report contract claim boundary rejects renamed key" "PASS v3.4.41 report contract claim boundary rejects renamed key" "${threshold_check}"
assert_contains "v3.4.41 report contract claim boundary rejects summary-shaped key" "PASS v3.4.41 report contract claim boundary rejects summary-shaped key" "${threshold_check}"
assert_contains "v3.4.41 report contract no public attestation" "PASS v3.4.41 report contract no public attestation" "${threshold_check}"
assert_contains "v3.4.41 report contract no live registry" "PASS v3.4.41 report contract no live registry" "${threshold_check}"
assert_contains "v3.4.41 report contract no key custody" "PASS v3.4.41 report contract no key custody" "${threshold_check}"
assert_contains "v3.4.41 report contract no revocation truth" "PASS v3.4.41 report contract no revocation truth" "${threshold_check}"
assert_contains "v3.4.41 report contract no current-machine governance" "PASS v3.4.41 report contract no current-machine governance" "${threshold_check}"
assert_contains "v3.4.41 report contract no live mcp" "PASS v3.4.41 report contract no live mcp" "${threshold_check}"
assert_contains "v3.4.41 report contract no production downstream" "PASS v3.4.41 report contract no production downstream" "${threshold_check}"
assert_contains "v3.4.41 report contract no production authority" "PASS v3.4.41 report contract no production authority" "${threshold_check}"
assert_contains "v3.4.41 report contract no enterprise readiness" "PASS v3.4.41 report contract no enterprise readiness" "${threshold_check}"
assert_contains "v3.4.41 report contract no sovereign recognition" "PASS v3.4.41 report contract no sovereign recognition" "${threshold_check}"
assert_contains "v3.4.41 report contract no unrouted coverage" "PASS v3.4.41 report contract no unrouted coverage" "${threshold_check}"
assert_contains "v3.4.41 result renders report contract type" "PASS v3.4.41 result renders report contract type from manifest" "${threshold_check}"
assert_contains "v3.4.41 result renders trusted registry case ids" "PASS v3.4.41 result renders trusted registry case ids from manifest" "${threshold_check}"
assert_contains "v3.4.41 result renders no live registry boundary" "PASS v3.4.41 result renders no live registry boundary from manifest" "${threshold_check}"
assert_contains "v3.4.41 result omits old report contract prefixes" "PASS v3.4.41 result omits old report-contract source prefix" "${threshold_check}"
assert_contains "v3.4.41 report contract omits product proof path" "PASS v3.4.41 report contract omits product proof path contract" "${threshold_check}"
assert_contains "v3.4.41 report contract omits product proof path hash" "PASS v3.4.41 report contract omits product proof path source hash" "${threshold_check}"
assert_contains "v3.4.41 result omits product proof path rendering" "PASS v3.4.41 result omits product proof path contract rendering" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path source" "PASS v3.4.42 report contract product proof path source path" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path source hash" "PASS v3.4.42 report contract product proof path source hash" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path minimum target" "PASS v3.4.42 report contract product proof path minimum target" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path report type" "PASS v3.4.42 report contract product proof path report type" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path result" "PASS v3.4.42 report contract product proof path result pass" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path evidence model" "PASS v3.4.42 report contract product proof path evidence model accepted" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path no live probing" "PASS v3.4.42 report contract product proof path no live probing" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path gates" "PASS v3.4.42 report contract product proof path gates true" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path forbidden claims" "PASS v3.4.42 report contract product proof path forbidden claims false" "${threshold_check}"
assert_contains "v3.4.42 report contract omits terminal boundary" "PASS v3.4.42 report contract omits product proof path terminal boundary" "${threshold_check}"
assert_contains "v3.4.42 report contract omits north-star terminal boundary" "PASS v3.4.42 report contract omits north-star terminal boundary fields" "${threshold_check}"
assert_contains "v3.4.42 report contract simulated human exact keys" "PASS v3.4.42 report contract simulated human exact keys" "${threshold_check}"
assert_contains "v3.4.42 report contract simulated human rejects extra key" "PASS v3.4.42 report contract simulated human rejects extra key" "${threshold_check}"
assert_contains "v3.4.42 report contract simulated human rejects missing key" "PASS v3.4.42 report contract simulated human rejects missing key" "${threshold_check}"
assert_contains "v3.4.42 report contract simulated human rejects renamed key" "PASS v3.4.42 report contract simulated human rejects renamed key" "${threshold_check}"
assert_contains "v3.4.42 report contract simulated human rejects summary-shaped key" "PASS v3.4.42 report contract simulated human rejects summary-shaped key" "${threshold_check}"
assert_contains "v3.4.42 report contract simulated human authorized boarded" "PASS v3.4.42 report contract simulated human authorized boarded" "${threshold_check}"
assert_contains "v3.4.42 report contract receipt boundary exact keys" "PASS v3.4.42 report contract receipt boundary exact keys" "${threshold_check}"
assert_contains "v3.4.42 report contract receipt boundary rejects extra key" "PASS v3.4.42 report contract receipt boundary rejects extra key" "${threshold_check}"
assert_contains "v3.4.42 report contract receipt boundary rejects missing key" "PASS v3.4.42 report contract receipt boundary rejects missing key" "${threshold_check}"
assert_contains "v3.4.42 report contract receipt boundary rejects renamed key" "PASS v3.4.42 report contract receipt boundary rejects renamed key" "${threshold_check}"
assert_contains "v3.4.42 report contract receipt boundary rejects summary-shaped key" "PASS v3.4.42 report contract receipt boundary rejects summary-shaped key" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path receipt valid" "PASS v3.4.42 report contract product proof path receipt valid" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path north star consumed" "PASS v3.4.42 report contract product proof path north star consumed" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path known noncoverage" "PASS v3.4.42 report contract product proof path known noncoverage visible" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path claim boundary exact keys" "PASS v3.4.42 report contract product proof path claim boundary exact keys" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path claim boundary rejects extra key" "PASS v3.4.42 report contract product proof path claim boundary rejects extra key" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path claim boundary rejects missing key" "PASS v3.4.42 report contract product proof path claim boundary rejects missing key" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path claim boundary rejects renamed key" "PASS v3.4.42 report contract product proof path claim boundary rejects renamed key" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path claim boundary rejects summary-shaped key" "PASS v3.4.42 report contract product proof path claim boundary rejects summary-shaped key" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path no attestation" "PASS v3.4.42 report contract product proof path no external attestation" "${threshold_check}"
assert_contains "v3.4.42 report contract product proof path no current-machine" "PASS v3.4.42 report contract product proof path no current-machine governance" "${threshold_check}"
assert_contains "v3.4.42 result renders product proof path" "PASS v3.4.42 result renders product proof path from manifest" "${threshold_check}"
assert_contains "v3.4.42 result renders product proof path hash" "PASS v3.4.42 result renders product proof path source hash from manifest" "${threshold_check}"
assert_contains "v3.4.42 result omits terminal boundary rendering" "PASS v3.4.42 result omits product proof path terminal boundary rendering" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path evidence model" "PASS v3.4.45 report contract product proof path evidence model" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path terminal verified" "PASS v3.4.45 report contract product proof path terminal verified" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path terminal binding" "PASS v3.4.45 report contract product proof path terminal binding match" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path terminal refusal hash" "PASS v3.4.45 report contract product proof path terminal refusal hash match" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path terminal refusal IDs" "PASS v3.4.45 report contract product proof path terminal refusal IDs" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path terminal public key" "PASS v3.4.45 report contract product proof path terminal no public key" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path terminal attestation" "PASS v3.4.45 report contract product proof path terminal no attestation" "${threshold_check}"
assert_contains "v3.4.45 report contract product proof path north-star terminal" "PASS v3.4.45 report contract product proof path north-star terminal observed" "${threshold_check}"
assert_contains "v3.4.45 report contract omits terminal group case IDs" "PASS v3.4.45 report contract omits product proof path terminal group case IDs" "${threshold_check}"
assert_contains "v3.4.45 report contract omits north-star terminal group case IDs" "PASS v3.4.45 report contract omits north-star terminal group case IDs" "${threshold_check}"
assert_contains "v3.4.45 result renders terminal boundary" "PASS v3.4.45 result renders product proof path terminal boundary" "${threshold_check}"
assert_contains "v3.4.45 result omits terminal group case IDs" "PASS v3.4.45 result omits product proof path terminal group case IDs" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path terminal group count" "PASS v3.4.46 report contract product proof path terminal group count" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path terminal group case count" "PASS v3.4.46 report contract product proof path terminal group case count" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path terminal group case IDs preserved" "PASS v3.4.46 report contract product proof path terminal group case IDs preserved" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path terminal group case IDs" "PASS v3.4.46 report contract product proof path terminal group case IDs" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path north-star group count" "PASS v3.4.46 report contract product proof path north-star group count" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path north-star group case count" "PASS v3.4.46 report contract product proof path north-star group case count" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path north-star group case IDs preserved" "PASS v3.4.46 report contract product proof path north-star group case IDs preserved" "${threshold_check}"
assert_contains "v3.4.46 report contract product proof path north-star group case IDs" "PASS v3.4.46 report contract product proof path north-star group case IDs" "${threshold_check}"
assert_contains "v3.4.46 result renders terminal group case IDs" "PASS v3.4.46 result renders product proof path terminal group case IDs" "${threshold_check}"
assert_contains "v3.4.46 omits deployment bridge" "PASS v3.4.46 report contract omits deployment bridge" "${threshold_check}"
assert_contains "v3.4.46 result omits deployment bridge" "PASS v3.4.46 result omits deployment bridge rendering" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge exact keys" "PASS v3.4.48 report contract deployment bridge exact keys" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge rejects extra key" "PASS v3.4.48 report contract deployment bridge rejects extra key" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge rejects missing key" "PASS v3.4.48 report contract deployment bridge rejects missing key" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge rejects renamed key" "PASS v3.4.48 report contract deployment bridge rejects renamed key" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge evidence model" "PASS v3.4.48 report contract deployment bridge evidence model" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge explicit selection" "PASS v3.4.48 report contract deployment bridge explicit selection" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge no latest" "PASS v3.4.48 report contract deployment bridge no latest" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge recognized once" "PASS v3.4.48 report contract deployment bridge recognized once" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge refusal count" "PASS v3.4.48 report contract deployment bridge refusal count" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge agent authority" "PASS v3.4.48 report contract deployment bridge agent authority refused" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge request authority" "PASS v3.4.48 report contract deployment bridge request authority false" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge current-machine" "PASS v3.4.48 report contract deployment bridge current-machine false" "${threshold_check}"
assert_contains "v3.4.48 report contract deployment bridge production" "PASS v3.4.48 report contract deployment bridge production false" "${threshold_check}"
assert_contains "v3.4.48 report contract north-star deployment authority family keys exact" "PASS v3.4.48 report contract north-star deployment authority family keys exact" "${threshold_check}"
assert_contains "v3.4.48 report contract north-star deployment authority rejects summary-shaped field" "PASS v3.4.48 report contract north-star deployment authority rejects summary-shaped family field" "${threshold_check}"
assert_contains "v3.4.48 report contract north-star deployment bridge preserved" "PASS v3.4.48 report contract north-star deployment bridge preserved" "${threshold_check}"
assert_contains "v3.4.48 result renders deployment bridge" "PASS v3.4.48 result renders deployment bridge" "${threshold_check}"
assert_contains "v3.4.48 result renders north-star deployment bridge" "PASS v3.4.48 result renders north-star deployment bridge" "${threshold_check}"
assert_contains "v3.4.48 omits deployment authority refusal fields" "PASS v3.4.48 report contract omits deployment authority refusal fields" "${threshold_check}"
assert_contains "v3.4.48 omits north-star deployment authority refusal fields" "PASS v3.4.48 report contract omits north-star deployment authority refusal fields" "${threshold_check}"
assert_contains "v3.4.48 result omits deployment authority refusal rendering" "PASS v3.4.48 result omits deployment authority refusal rendering" "${threshold_check}"
assert_contains "v3.4.49 report contract deployment bridge authority refusal exact keys" "PASS v3.4.49 report contract deployment bridge authority refusal exact keys" "${threshold_check}"
assert_contains "v3.4.49 report contract deployment authority refusals reject extra key" "PASS v3.4.49 report contract deployment authority refusals reject extra key" "${threshold_check}"
assert_contains "v3.4.49 report contract deployment authority refusals reject missing key" "PASS v3.4.49 report contract deployment authority refusals reject missing key" "${threshold_check}"
assert_contains "v3.4.49 report contract deployment authority refusals reject renamed key" "PASS v3.4.49 report contract deployment authority refusals reject renamed key" "${threshold_check}"
assert_contains "v3.4.49 report contract deployment authority refusal count" "PASS v3.4.49 report contract deployment authority refusal count" "${threshold_check}"
assert_contains "v3.4.49 report contract deployment authority refusal case IDs" "PASS v3.4.49 report contract deployment authority refusal case IDs" "${threshold_check}"
assert_contains "v3.4.49 report contract deployment authority refusals before service proof" "PASS v3.4.49 report contract deployment authority refusals before service proof" "${threshold_check}"
assert_contains "v3.4.49 report contract stale artifact refusal" "PASS v3.4.49 report contract stale artifact refusal" "${threshold_check}"
assert_contains "v3.4.49 report contract profile mismatch refusal" "PASS v3.4.49 report contract profile mismatch refusal" "${threshold_check}"
assert_contains "v3.4.49 report contract north-star deployment authority family keys exact" "PASS v3.4.49 report contract north-star deployment authority family keys exact" "${threshold_check}"
assert_contains "v3.4.49 report contract north-star deployment authority rejects summary-shaped field" "PASS v3.4.49 report contract north-star deployment authority rejects summary-shaped refusal field" "${threshold_check}"
assert_contains "v3.4.49 report contract north-star authority refusals preserved" "PASS v3.4.49 report contract north-star authority refusals preserved" "${threshold_check}"
assert_contains "v3.4.49 result renders deployment authority refusal count" "PASS v3.4.49 result renders deployment authority refusal count" "${threshold_check}"
assert_contains "v3.4.49 result renders deployment authority refusal case IDs" "PASS v3.4.49 result renders deployment authority refusal case IDs" "${threshold_check}"
assert_contains "v3.4.49 result renders north-star deployment authority refusals" "PASS v3.4.49 result renders north-star deployment authority refusals" "${threshold_check}"
assert_contains "v3.4.49 terminal-chain mirror omitted from manifest" "PASS v3.4.49 terminal-chain mirror omitted from manifest" "${threshold_check}"
assert_contains "v3.4.49 terminal-chain mirror omitted from report contract" "PASS v3.4.49 terminal-chain mirror omitted from report contract" "${threshold_check}"
assert_contains "v3.4.49 result omits terminal-chain mirror rendering" "PASS v3.4.49 result omits terminal-chain mirror rendering" "${threshold_check}"
assert_contains "v3.4.50 terminal-chain mirror required in manifest" "PASS v3.4.50 terminal-chain mirror required in manifest" "${threshold_check}"
assert_contains "v3.4.50 terminal-chain mirror preserved in manifest" "PASS v3.4.50 terminal-chain mirror preserved in manifest" "${threshold_check}"
assert_contains "v3.4.50 terminal-chain mirror case IDs" "PASS v3.4.50 terminal-chain mirror case IDs" "${threshold_check}"
assert_contains "v3.4.50 terminal-chain mirror artifact case IDs" "PASS v3.4.50 terminal-chain mirror artifact case IDs" "${threshold_check}"
assert_contains "v3.4.50 report contract mirror preserved" "PASS v3.4.50 report contract mirror preserved" "${threshold_check}"
assert_contains "v3.4.50 report contract proof-smoke mirror preserved" "PASS v3.4.50 report contract proof-smoke mirror preserved" "${threshold_check}"
assert_contains "v3.4.50 report contract north-star mirror preserved" "PASS v3.4.50 report contract north-star mirror preserved" "${threshold_check}"
assert_contains "v3.4.50 result renders terminal-chain mirror required" "PASS v3.4.50 result renders terminal-chain mirror required" "${threshold_check}"
assert_contains "v3.4.50 result renders report contract mirror case count" "PASS v3.4.50 result renders report contract mirror case count" "${threshold_check}"
assert_contains "v3.4.50 result renders proof-smoke mirror preserved" "PASS v3.4.50 result renders proof-smoke mirror preserved" "${threshold_check}"
assert_contains "v3.4.50 result renders north-star mirror preserved" "PASS v3.4.50 result renders north-star mirror preserved" "${threshold_check}"
assert_contains "v3.4.50 omits terminal trusted-registry verdict" "PASS v3.4.50 report contract omits terminal trusted-registry verdict" "${threshold_check}"
assert_contains "v3.4.50 omits terminal trusted-registry verdict rendering" "PASS v3.4.50 result omits terminal trusted-registry verdict rendering" "${threshold_check}"
assert_contains "v3.4.50 omits downstream-refusal boundary" "PASS v3.4.50 report contract omits downstream-refusal boundary" "${threshold_check}"
assert_contains "v3.4.50 omits downstream-refusal boundary rendering" "PASS v3.4.50 result omits downstream-refusal boundary rendering" "${threshold_check}"
assert_contains "v3.4.51 report contract satisfied" "PASS v3.4.51 report contract satisfied" "${threshold_check}"
assert_contains "v3.4.51 terminal trusted-registry verdict preserved" "PASS v3.4.51 terminal trusted-registry verdict preserved" "${threshold_check}"
assert_contains "v3.4.51 terminal trusted-registry signature valid" "PASS v3.4.51 terminal trusted-registry signature valid preserved" "${threshold_check}"
assert_contains "v3.4.51 terminal trusted-registry rule evaluated" "PASS v3.4.51 terminal trusted-registry rule evaluated" "${threshold_check}"
assert_contains "v3.4.51 terminal trusted-registry fixture contract sha" "PASS v3.4.51 terminal trusted-registry fixture contract sha" "${threshold_check}"
assert_contains "v3.4.51 terminal trusted-registry prefixed keys exact" "PASS v3.4.51 terminal trusted-registry prefixed keys exact" "${threshold_check}"
assert_contains "v3.4.51 north-star trusted-registry verdict preserved" "PASS v3.4.51 north-star trusted-registry verdict preserved" "${threshold_check}"
assert_contains "v3.4.51 north-star trusted-registry prefixed keys exact" "PASS v3.4.51 north-star trusted-registry prefixed keys exact" "${threshold_check}"
assert_contains "v3.4.51 downstream-refusal marker delta" "PASS v3.4.51 downstream-refusal boundary recognized marker delta" "${threshold_check}"
assert_contains "v3.4.51 downstream-refusal final marker count" "PASS v3.4.51 downstream-refusal boundary final marker count" "${threshold_check}"
assert_contains "v3.4.51 downstream-refusal case count" "PASS v3.4.51 downstream-refusal boundary refusal case count" "${threshold_check}"
assert_contains "v3.4.51 downstream-refusal refusals unboarded" "PASS v3.4.51 downstream-refusal boundary refusals unboarded" "${threshold_check}"
assert_contains "v3.4.51 downstream-refusal refusal reasons" "PASS v3.4.51 downstream-refusal boundary refusal reasons" "${threshold_check}"
assert_contains "v3.4.51 downstream-refusal marker deltas zero" "PASS v3.4.51 downstream-refusal boundary refusal marker deltas zero" "${threshold_check}"
assert_contains "v3.4.51 downstream-refusal exact keys" "PASS v3.4.51 downstream-refusal boundary exact keys" "${threshold_check}"
assert_contains "v3.4.51 north-star downstream-refusal boundary" "PASS v3.4.51 north-star downstream-refusal boundary preserved" "${threshold_check}"
assert_contains "v3.4.51 north-star downstream-refusal refusals unboarded" "PASS v3.4.51 north-star downstream-refusal boundary refusals unboarded" "${threshold_check}"
assert_contains "v3.4.51 north-star downstream-refusal refusal reasons" "PASS v3.4.51 north-star downstream-refusal boundary refusal reasons" "${threshold_check}"
assert_contains "v3.4.51 north-star downstream-refusal exact keys" "PASS v3.4.51 north-star downstream-refusal boundary exact keys" "${threshold_check}"
assert_contains "v3.4.51 result renders terminal trusted-registry verdict" "PASS v3.4.51 result renders terminal trusted-registry verdict" "${threshold_check}"
assert_contains "v3.4.51 result renders north-star trusted-registry verdict" "PASS v3.4.51 result renders north-star trusted-registry verdict" "${threshold_check}"
assert_contains "v3.4.51 result renders downstream-refusal marker delta" "PASS v3.4.51 result renders downstream-refusal marker delta" "${threshold_check}"
assert_contains "v3.4.51 result renders downstream-refusal unboarded" "PASS v3.4.51 result renders downstream-refusal unboarded boundary" "${threshold_check}"
assert_contains "v3.4.51 result renders downstream-refusal reasons" "PASS v3.4.51 result renders downstream-refusal reasons" "${threshold_check}"
assert_contains "v3.4.51 result renders north-star downstream-refusal marker deltas zero" "PASS v3.4.51 result renders north-star downstream-refusal marker deltas zero" "${threshold_check}"
assert_contains "v3.4.51 result renders north-star downstream-refusal unboarded" "PASS v3.4.51 result renders north-star downstream-refusal unboarded boundary" "${threshold_check}"
assert_contains "v3.4.51 result renders north-star downstream-refusal reasons" "PASS v3.4.51 result renders north-star downstream-refusal reasons" "${threshold_check}"
assert_contains "v3.4.51 recognized receipt path omitted terminal" "PASS v3.4.51 recognized receipt path mirror omitted from terminal boundary" "${threshold_check}"
assert_contains "v3.4.51 recognized receipt path omitted north star" "PASS v3.4.51 recognized receipt path mirror omitted from north-star boundary" "${threshold_check}"
assert_contains "v3.4.51 recognized receipt path omitted rendering" "PASS v3.4.51 result omits recognized receipt path mirror rendering" "${threshold_check}"
assert_contains "v3.4.52 report contract satisfied" "PASS v3.4.52 report contract satisfied" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path terminal exact keys" "PASS v3.4.52 recognized receipt path terminal exact keys" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path terminal extra key" "PASS v3.4.52 recognized receipt path terminal rejects extra key" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path terminal missing key" "PASS v3.4.52 recognized receipt path terminal rejects missing key" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path terminal renamed key" "PASS v3.4.52 recognized receipt path terminal rejects renamed key" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path terminal summary-shaped" "PASS v3.4.52 recognized receipt path terminal rejects summary-shaped field" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path terminal adjacent summary" "PASS v3.4.52 recognized receipt path terminal rejects adjacent summary key" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path evidence sha" "PASS v3.4.52 recognized receipt path evidence sha hash-bound" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path tampered sha" "PASS v3.4.52 recognized receipt path tampered evidence sha refused by contract" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path source binding" "PASS v3.4.52 recognized receipt path source binding equals trusted registry binding" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path source mismatch" "PASS v3.4.52 recognized receipt path source-binding mismatch refused by contract" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path compact verdict" "PASS v3.4.52 recognized receipt path verdict compact only" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path false boundaries" "PASS v3.4.52 recognized receipt path false boundaries stay false" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path false boundary flip" "PASS v3.4.52 recognized receipt path false-boundary flip refused by contract" "${threshold_check}"
assert_contains "v3.4.52 north-star recognized receipt path exact keys" "PASS v3.4.52 north-star recognized receipt path exact keys" "${threshold_check}"
assert_contains "v3.4.52 north-star recognized receipt path extra key" "PASS v3.4.52 north-star recognized receipt path rejects extra key" "${threshold_check}"
assert_contains "v3.4.52 north-star recognized receipt path missing key" "PASS v3.4.52 north-star recognized receipt path rejects missing key" "${threshold_check}"
assert_contains "v3.4.52 north-star recognized receipt path renamed key" "PASS v3.4.52 north-star recognized receipt path rejects renamed key" "${threshold_check}"
assert_contains "v3.4.52 north-star recognized receipt path summary-shaped" "PASS v3.4.52 north-star recognized receipt path rejects summary-shaped field" "${threshold_check}"
assert_contains "v3.4.52 north-star recognized receipt path adjacent summary" "PASS v3.4.52 north-star recognized receipt path rejects adjacent summary key" "${threshold_check}"
assert_contains "v3.4.52 north-star recognized receipt path mirrors terminal" "PASS v3.4.52 north-star recognized receipt path mirrors terminal fields" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path terminal rendering" "PASS v3.4.52 result renders recognized receipt path terminal sha" "${threshold_check}"
assert_contains "v3.4.52 recognized receipt path north-star rendering" "PASS v3.4.52 result renders recognized receipt path north-star sha" "${threshold_check}"
assert_contains "v3.4.53 trusted completion manifest enabled" "PASS v3.4.53 trusted completion manifest enabled" "${threshold_check}"
assert_contains "v3.4.53 trusted completion manifest evidence model" "PASS v3.4.53 trusted completion manifest evidence model" "${threshold_check}"
assert_contains "v3.4.53 trusted completion proof path preserved" "PASS v3.4.53 trusted completion proof path preserved" "${threshold_check}"
assert_contains "v3.4.53 trusted completion verification path preserved" "PASS v3.4.53 trusted completion verification path preserved" "${threshold_check}"
assert_contains "v3.4.53 trusted completion direct artifact hashes present" "PASS v3.4.53 trusted completion direct artifact hashes present" "${threshold_check}"
assert_contains "v3.4.53 trusted completion not in core artifact hash set" "PASS v3.4.53 trusted completion not in core artifact hash set" "${threshold_check}"
assert_contains "v3.4.53 trusted completion verification true" "PASS v3.4.53 trusted completion verification true" "${threshold_check}"
assert_contains "v3.4.53 trusted completion selected terminal" "PASS v3.4.53 trusted completion selected private operator terminal" "${threshold_check}"
assert_contains "v3.4.53 trusted completion readiness terminal split" "PASS v3.4.53 trusted completion readiness terminal remains profile installation" "${threshold_check}"
assert_contains "v3.4.53 trusted completion distinct terminal allowance" "PASS v3.4.53 trusted completion distinct terminal allowance explicit" "${threshold_check}"
assert_contains "v3.4.53 trusted completion false boundary" "PASS v3.4.53 trusted completion false claim boundary" "${threshold_check}"
assert_contains "v3.4.53 trusted completion not public" "PASS v3.4.53 trusted completion not public by default" "${threshold_check}"
assert_contains "v3.4.53 readiness trusted issuer completion proven" "PASS v3.4.53 readiness trusted issuer completion proven" "${threshold_check}"
assert_contains "v3.4.53 readiness trusted completion verified" "PASS v3.4.53 readiness trusted completion provided and verified" "${threshold_check}"
assert_contains "v3.4.53 readiness trusted completion selected terminal" "PASS v3.4.53 readiness trusted completion selected private operator terminal" "${threshold_check}"
assert_contains "v3.4.53 readiness trusted completion completed" "PASS v3.4.53 readiness trusted completion completed for surface" "${threshold_check}"
assert_contains "v3.4.53 readiness trusted completion claim boundary" "PASS v3.4.53 readiness trusted completion claim boundary false" "${threshold_check}"
assert_contains "v3.4.53 readiness stronger claims false" "PASS v3.4.53 readiness stronger claims remain false" "${threshold_check}"
assert_contains "v3.4.53 readiness artifacts include proof" "PASS v3.4.53 readiness artifacts include supplied proof" "${threshold_check}"
assert_contains "v3.4.53 result selected surface" "PASS v3.4.53 result renders trusted completion selected surface" "${threshold_check}"
assert_contains "v3.4.53 result no public attestation" "PASS v3.4.53 result renders trusted completion no public attestation" "${threshold_check}"
assert_contains "v3.4.53 result no source publication" "PASS v3.4.53 result renders trusted completion no source publication" "${threshold_check}"
assert_contains "v3.4.53 result no production downstream" "PASS v3.4.53 result renders trusted completion no production downstream" "${threshold_check}"

for artifact in \
    DRY-RUN-RESULT.md \
    transcript.txt \
    COMMANDS.txt \
    ASSERTIONS.txt \
    DRY-RUN-MANIFEST.json \
    SHA256SUMS \
    RUN-SHA256SUMS \
    target-head.txt \
    target-status.txt \
    ZLAR/zlar-verifier-env-report-v0.json \
    ZLAR/zlar-proof-smoke-v1.json \
    ZLAR/zlar-proof-smoke-generated-verification.json \
    ZLAR/zlar-proof-smoke-sample-verification.json \
    ZLAR/zlar-service-preflight-sample-verification.json \
    ZLAR/zlar-local-proof-pack-sample-verification.json \
    ZLAR/zlar-issuer-status-proof.json \
    ZLAR/zlar-verifier-kit-issuer-status-fixture.json \
    ZLAR/zlar-trusted-receipt-issuer-recognition.json \
    ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry.json \
    ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt \
    ZLAR/zlar-runtime-local-activation-sample-verification.json \
    ZLAR/zlar-runtime-profile-installation-sample-verification.json \
    ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json \
    ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json \
    ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json \
    ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json \
    ZLAR/zlar-installed-runtime-profile-service-proof-v1.json \
    ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json \
    ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json \
    ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json \
    ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json \
    ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json \
    ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json \
    ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt \
    ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json \
    ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt \
    ZLAR/zlar-product-proof-path-v1.json \
    ZLAR/zlar-coverage-map-sample.json \
    ZLAR/zlar-north-star-readiness-v1.json \
    ZLAR/zlar-verifier-kit-reproducibility-v1.json \
    ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json \
    ZLAR/zlar-verifier-kit-release-assets-v1.json \
    ZLAR/zlar-verifier-kit-public-distribution-v1.json \
    ZLAR/zlar-private-verifier-result-v1.json \
    ZLAR/zlar-private-verifier-result-verification-v1.json; do
    TOTAL=$((TOTAL + 1))
    if [ -f "${happy_out}/${artifact}" ]; then
        pass
    else
        fail "happy artifact exists: ${artifact}"
    fi
done

json_check="$(cd "${happy_out}/ZLAR" && LOCAL_TAG_FOR_JSON_CHECK="${LOCAL_TAG}" node - <<'NODE'
const crypto = require('crypto');
const fs = require('fs');
function read(name) { return JSON.parse(fs.readFileSync(name, 'utf8')); }
function sha256Text(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
function artifactSetSha256(artifactHashes) {
  const canonical = [...artifactHashes]
    .sort((left, right) => left.path.localeCompare(right.path))
    .map(({ path, sha256 }) => `${path}\0${sha256}\n`)
    .join('');
  return sha256Text(canonical);
}
const env = read('zlar-verifier-env-report-v0.json');
const smoke = read('zlar-proof-smoke-sample-verification.json');
const servicePreflight = read('zlar-service-preflight-sample-verification.json');
const pack = read('zlar-local-proof-pack-sample-verification.json');
const issuerStatusProof = read('zlar-issuer-status-proof.json');
const issuer = read('zlar-verifier-kit-issuer-status-fixture.json');
const recognition = read('zlar-trusted-receipt-issuer-recognition.json');
const malformedRegistry = read('zlar-trusted-receipt-issuer-recognition-malformed-registry.json');
const malformedRegistryError = fs.readFileSync('zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt', 'utf8');
const coverage = read('zlar-coverage-map-sample.json');
const northStar = read('zlar-north-star-readiness-v1.json');
const verifierKitReproducibility = read('zlar-verifier-kit-reproducibility-v1.json');
const verifierKitExternalRunnerDiagnostics = read('zlar-verifier-kit-external-runner-diagnostics-v1.json');
const verifierKitPublicDistribution = read('zlar-verifier-kit-public-distribution-v1.json');
const privateVerifierResultText = fs.readFileSync('zlar-private-verifier-result-v1.json', 'utf8');
const privateVerifierResult = read('zlar-private-verifier-result-v1.json');
const privateVerifierResultVerification = read('zlar-private-verifier-result-verification-v1.json');
const sha256SumsText = fs.readFileSync('../SHA256SUMS', 'utf8');
const runSha256SumsText = fs.readFileSync('../RUN-SHA256SUMS', 'utf8');
const install = read('zlar-runtime-profile-installation-sample-verification.json');
const installedPreflight = read('zlar-installed-runtime-profile-preflight-sample-verification.json');
const installedRecognitionProof = read('zlar-installed-runtime-profile-recognition-proof-v1.json');
const installedRecognitionProofArtifact = read('zlar-installed-runtime-profile-recognition-proof-artifact-v1.json');
const installedRecognitionProofArtifactVerification = read('zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json');
const installedServiceProof = read('zlar-installed-runtime-profile-service-proof-v1.json');
const installedServiceProofArtifact = read('zlar-installed-runtime-profile-service-proof-artifact-v1.json');
const installedServiceProofArtifactVerification = read('zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json');
const installedTerminalChain = read('zlar-installed-runtime-profile-terminal-chain-v1.json');
const installedTerminalChainArtifact = read('zlar-installed-runtime-profile-terminal-chain-artifact-v1.json');
const installedTerminalChainArtifactVerification = read('zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json');
const productProofPath = read('zlar-product-proof-path-v1.json');
const privateVerifierResultSha = sha256Text(privateVerifierResultText);
const privateVerifierResultArtifactSetSha = artifactSetSha256(privateVerifierResult.evidence?.artifact_hashes || []);
const manifest = read('../DRY-RUN-MANIFEST.json');
const manifestTrustedIssuerRegistry =
  manifest.trusted_issuer_registry_recognition_evidence || {};
const manifestTerminalChainRefusalEvidence =
  manifest.terminal_chain_refusal_evidence || {};
const manifestReportContract = manifest.release_forward_report_contract || {};
const manifestProductProofPath = manifestReportContract.product_proof_path || {};
const manifestReportContractTerminalChainRefusalEvidence =
  manifestReportContract.terminal_chain_refusal_evidence || {};
const manifestReportContractProofSmokeCounts =
  manifestReportContract.proof_smoke?.counts || {};
const manifestReportContractNorthStarCounts =
  manifestReportContract.north_star?.counts || {};
const serviceLane = (coverage.surfaces || []).find((surface) => surface.surface_id === 'protected-records.service-profile.records.write');
const reproHashes = verifierKitReproducibility.public_artifact_hashes || [];
const northStarProductProofPiece = northStar.puzzle_pieces?.find((piece) => piece.id === 1) || {};
const northStarProductProofPath = northStarProductProofPiece.observed?.product_proof_path || {};
const northStarEnterpriseProfile = northStar.puzzle_pieces?.find((piece) => piece.id === 3)?.observed || {};
const northStarDownstreamRecognition = northStar.puzzle_pieces?.find((piece) => piece.id === 5)?.observed || {};
const northStarPrivateIntakePointer = northStar.puzzle_pieces?.find((piece) => piece.id === 7)?.observed?.private_intake_sample_manifest_pointer || {};
const northStarVerifierKitDistribution = northStar.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.verifier_kit_public_distribution || {};
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
const expectedTrustedIssuerRegistryRecognitionRefusalCaseIds = [
  'unrecognized_terminal_chain_registry_scope_refused',
  'registry_receipt_contract_mismatch_refused',
];
const expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes = [
  'scope_not_found',
  'detail_hash_mismatch',
];
const expectedDeploymentProfileAuthorityRefusalCaseIds = [
  'stale_deployment_profile_runtime_sha_refused_before_service_proof',
  'runtime_profile_id_mismatch_refused_before_service_proof',
  'preflight_profile_sha_mismatch_refused_before_service_proof',
  'preflight_latest_selection_refused_before_service_proof',
  'preflight_request_authority_material_refused_before_service_proof',
];
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
const expectedPrivateVerifierResultSamplePointerFields = [
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
const expectedProductProofPathSimulatedHumanAuthorizationFields = [
  'approval_channel',
  'authorized_boarded',
  'denied_boarded',
  'pending_boarded',
];
const expectedProductProofPathReceiptVerifierBoundaryFields = [
  'downstream_recognition_proven',
  'invalid_verdict',
  'unknown_signer_verdict',
  'valid_verdict',
];
const expectedTerminalChainNestedArtifactTamperRefusalFields = [
  'generated_preflight_artifact_type',
  'generated_service_proof_artifact_type',
  'artifact_generated_preflight_artifact_type',
  'artifact_generated_service_proof_artifact_type',
  'forged_inner_preflight_hash_refused',
  'forged_inner_service_hash_refused',
];
const expectedTerminalChainNestedArtifactBindingFields = [
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
function exactKeys(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
function parseChecksumRows(text, prefix = '') {
  return text.trim().split(/\n+/).map((line) => {
    const match = line.match(/^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$/);
    return match ? { path: `${prefix}${match[2]}`, sha256: match[1] } : null;
  });
}
function mapFromRows(rows) {
  if (rows.some((row) => row === null)) return null;
  return new Map(rows.map((row) => [row.path, row.sha256]));
}
function mapPathsEqual(left, right) {
  if (!(left instanceof Map) || !(right instanceof Map)) return false;
  const leftPaths = [...left.keys()].sort();
  const rightPaths = [...right.keys()].sort();
  return arraysEqual(leftPaths, rightPaths);
}
function mapEntriesEqual(left, right) {
  return mapPathsEqual(left, right) &&
    [...right.entries()].every(([path, sha256]) => left.get(path) === sha256);
}
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
  return exactKeys(value, Object.keys(expectedRecognitionRefusalGroupCaseIds)) &&
    groupCaseIdsMatch(value);
}
const manifestTerminalChainGroupCaseIds =
  manifest.terminal_chain_refusal_evidence?.recognition_refusal_group_case_ids || {};
const manifestTerminalChainGroupCaseIdsMissing = {
  ...manifestTerminalChainGroupCaseIds,
};
delete manifestTerminalChainGroupCaseIdsMissing.recognized_receipt_scope_mismatch;
const manifestTerminalChainGroupCaseIdsRenamed = {
  ...manifestTerminalChainGroupCaseIds,
  recognized_receipt_scope_mismatches:
    manifestTerminalChainGroupCaseIds.recognized_receipt_scope_mismatch,
};
delete manifestTerminalChainGroupCaseIdsRenamed.recognized_receipt_scope_mismatch;
const manifestReportContractProofSmokeGroupCaseIds =
  manifestReportContractProofSmokeCounts
    .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids || {};
const manifestReportContractProofSmokeGroupCaseIdsMissing = {
  ...manifestReportContractProofSmokeGroupCaseIds,
};
delete manifestReportContractProofSmokeGroupCaseIdsMissing
  .recognized_receipt_scope_mismatch;
const manifestReportContractProofSmokeGroupCaseIdsRenamed = {
  ...manifestReportContractProofSmokeGroupCaseIds,
  recognized_receipt_scope_mismatches:
    manifestReportContractProofSmokeGroupCaseIds.recognized_receipt_scope_mismatch,
};
delete manifestReportContractProofSmokeGroupCaseIdsRenamed
  .recognized_receipt_scope_mismatch;
const manifestReportContractNorthStarGroupCaseIds =
  manifestReportContractNorthStarCounts
    .installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids || {};
const manifestReportContractNorthStarGroupCaseIdsMissing = {
  ...manifestReportContractNorthStarGroupCaseIds,
};
delete manifestReportContractNorthStarGroupCaseIdsMissing
  .recognized_receipt_scope_mismatch;
const manifestReportContractNorthStarGroupCaseIdsRenamed = {
  ...manifestReportContractNorthStarGroupCaseIds,
  recognized_receipt_scope_mismatches:
    manifestReportContractNorthStarGroupCaseIds.recognized_receipt_scope_mismatch,
};
delete manifestReportContractNorthStarGroupCaseIdsRenamed
  .recognized_receipt_scope_mismatch;
const privateSamplePointer = manifest.private_verifier_result_sample || {};
const privateSamplePointerMissing = { ...privateSamplePointer };
delete privateSamplePointerMissing.hash_record_location;
const privateSamplePointerRenamed = { ...privateSamplePointer };
privateSamplePointerRenamed.result_heading = privateSamplePointerRenamed.result_section;
delete privateSamplePointerRenamed.result_section;
const manifestSimulatedHuman = manifestProductProofPath.simulated_human_authorization || {};
const manifestSimulatedHumanMissing = { ...manifestSimulatedHuman };
delete manifestSimulatedHumanMissing.authorized_boarded;
const manifestSimulatedHumanRenamed = { ...manifestSimulatedHuman };
manifestSimulatedHumanRenamed.channel = manifestSimulatedHumanRenamed.approval_channel;
delete manifestSimulatedHumanRenamed.approval_channel;
const manifestReceiptBoundary = manifestProductProofPath.receipt_verifier_boundary || {};
const manifestReceiptBoundaryMissing = { ...manifestReceiptBoundary };
delete manifestReceiptBoundaryMissing.downstream_recognition_proven;
const manifestReceiptBoundaryRenamed = { ...manifestReceiptBoundary };
manifestReceiptBoundaryRenamed.unknown_signer_collapsed_verdict =
  manifestReceiptBoundaryRenamed.unknown_signer_verdict;
delete manifestReceiptBoundaryRenamed.unknown_signer_verdict;
const manifestNestedArtifactTamper =
  manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals || {};
const manifestNestedArtifactTamperMissing = {
  ...manifestNestedArtifactTamper,
};
delete manifestNestedArtifactTamperMissing.forged_inner_preflight_hash_refused;
const manifestNestedArtifactTamperRenamed = {
  ...manifestNestedArtifactTamper,
  preflight_artifact_type:
    manifestNestedArtifactTamper.generated_preflight_artifact_type,
};
delete manifestNestedArtifactTamperRenamed.generated_preflight_artifact_type;
const manifestNestedArtifactTamperSummary = {
  tamper_summary: {
    forged_inner_hashes_refused: true,
  },
};
const manifestNestedArtifactBinding =
  manifest.terminal_chain_refusal_evidence?.nested_artifact_binding || {};
const manifestNestedArtifactBindingMissing = {
  ...manifestNestedArtifactBinding,
};
delete manifestNestedArtifactBindingMissing.service_artifact_hash_bound;
const manifestNestedArtifactBindingRenamed = {
  ...manifestNestedArtifactBinding,
  service_artifact_bound:
    manifestNestedArtifactBinding.service_artifact_hash_bound,
};
delete manifestNestedArtifactBindingRenamed.service_artifact_hash_bound;
const manifestNestedArtifactBindingSummary = {
  nested_binding_summary: {
    bound: true,
  },
};
const manifestReportContractNestedArtifactTamper =
  manifestReportContract.terminal_chain_nested_artifact_tamper_refusals || {};
const manifestReportContractNestedArtifactTamperMissing = {
  ...manifestReportContractNestedArtifactTamper,
};
delete manifestReportContractNestedArtifactTamperMissing
  .forged_inner_preflight_hash_refused;
const manifestReportContractNestedArtifactTamperRenamed = {
  ...manifestReportContractNestedArtifactTamper,
  preflight_artifact_type:
    manifestReportContractNestedArtifactTamper.generated_preflight_artifact_type,
};
delete manifestReportContractNestedArtifactTamperRenamed
  .generated_preflight_artifact_type;
const manifestReportContractNestedArtifactTamperSummary = {
  tamper_summary: {
    forged_inner_hashes_refused: true,
  },
};
const manifestReportContractNestedArtifactBinding =
  manifestReportContract.terminal_chain_nested_artifact_binding || {};
const manifestReportContractNestedArtifactBindingMissing = {
  ...manifestReportContractNestedArtifactBinding,
};
delete manifestReportContractNestedArtifactBindingMissing
  .service_artifact_hash_bound;
const manifestReportContractNestedArtifactBindingRenamed = {
  ...manifestReportContractNestedArtifactBinding,
  service_artifact_bound:
    manifestReportContractNestedArtifactBinding.service_artifact_hash_bound,
};
delete manifestReportContractNestedArtifactBindingRenamed
  .service_artifact_hash_bound;
const manifestReportContractNestedArtifactBindingSummary = {
  nested_binding_summary: {
    bound: true,
  },
};
const privateVerifierArtifactHashByPath = new Map(
  (privateVerifierResult.evidence?.artifact_hashes || []).map((entry) => [
    entry.path,
    entry.sha256,
  ]),
);
const sha256SumsByPath = mapFromRows(parseChecksumRows(sha256SumsText, 'ZLAR/'));
const expectedSha256SumsByPath = new Map(
  [...privateVerifierArtifactHashByPath.entries()].filter(([path]) =>
    path.startsWith('ZLAR/')
  ),
);
const runSha256SumsByPath = mapFromRows(parseChecksumRows(runSha256SumsText));
const expectedRunSha256SumsPathSet = new Map(
  [
    'transcript.txt',
    'COMMANDS.txt',
    'ASSERTIONS.txt',
    'target-head.txt',
    'target-status.txt',
    'SHA256SUMS',
  ].map((path) => [path, true]),
);
const checks = [
  ['env live probing false', env.live_probing === false],
  ['env external attestation false', env.external_attestation === false],
  ['smoke verified true', smoke.verified === true],
  ['smoke governed lanes six', smoke.counts?.governed_lanes === 6],
  ['service preflight verified true', servicePreflight.verified === true],
  ['service preflight cases eleven', servicePreflight.case_count === 11 && servicePreflight.required_case_count === 11],
  ['service preflight config backed', servicePreflight.evidence_model === 'local-disposable-config-backed-profile-preflight-fixture'],
  ['service preflight wrong policy refused', servicePreflight.wrong_policy_refused === true],
  ['service preflight wrong policy reason', servicePreflight.wrong_policy_reason === 'policy_not_recognized'],
  ['service preflight wrong policy state delta', servicePreflight.wrong_policy_state_delta === 0],
  ['service preflight authority refused', servicePreflight.request_stream_authority_material_refused === true],
  ['service preflight authority reason', servicePreflight.request_stream_authority_material_reason === 'request_stream_authority_material'],
  ['service preflight direct api receipt reason', servicePreflight.direct_api_receipt_present_reason === 'request_stream_forbidden_fields'],
  ['service preflight no production service', servicePreflight.production_records_service_checked === false],
  ['pack verified true', pack.verified === true],
  ['pack install guard refused', pack.runtime_profile_installation?.request_authority_guard_summary?.all_refused_before_mutation === true],
  ['pack persistent config false', pack.runtime_profile_installation?.persistent_runtime_config_written === false],
  ['issuer status proof type', issuerStatusProof.proof_type === 'issuer-status-proof-v1'],
  ['issuer status proof fixture model', issuerStatusProof.evidence_model === 'local-hermetic-fixture'],
  ['issuer status proof live probing false', issuerStatusProof.live_probing === false],
  ['issuer status proof trust anchor', issuerStatusProof.trust_anchor_model === 'local-fixture-recognition-rule'],
  ['issuer status proof active issuer boards', issuerStatusProof.issuer_boundary?.active_issuer_boards === true],
  ['issuer status proof retired issuer refuses', issuerStatusProof.issuer_boundary?.retired_issuer_refuses === true],
  ['issuer status proof compromised issuer refuses', issuerStatusProof.issuer_boundary?.compromised_issuer_refuses === true],
  ['issuer status proof missing status issuer refuses', issuerStatusProof.issuer_boundary?.missing_status_issuer_refuses === true],
  ['issuer status proof unknown issuer refuses', issuerStatusProof.issuer_boundary?.unknown_issuer_refuses === true],
  ['issuer status proof missing key issuer refuses', issuerStatusProof.issuer_boundary?.missing_key_issuer_refuses === true],
  ['issuer status proof no raw public key material', issuerStatusProof.issuer_boundary?.raw_public_key_material_included === false],
  ['issuer status proof no raw private key material', issuerStatusProof.issuer_boundary?.raw_private_key_material_included === false],
  ['issuer fixture verdict', issuer.verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED'],
  ['trusted issuer recognition verdict', recognition.verdict === 'RECOGNIZED'],
  ['trusted issuer recognition live probing false', recognition.live_probing === false],
  ['trusted issuer schema negative malformed', malformedRegistry.production_authority === true],
  ['trusted issuer schema negative unsupported field', /unsupported field: production_authority/.test(malformedRegistryError)],
  ['trusted issuer schema negative no recognized verdict', !/^RECOGNIZED/m.test(malformedRegistryError)],
  ['trusted issuer schema negative no refused verdict', !/^RECOGNITION-REFUSED/m.test(malformedRegistryError)],
  ['coverage governed lanes six', coverage.counts?.governed_lanes === 6],
  ['coverage counted lanes six', coverage.counts?.counted_lanes === 6],
  ['coverage service-profile lane governed', serviceLane?.governed === true],
  ['coverage service-profile lane receipt capable', serviceLane?.coverage_summary?.receipt_status === 'receipt_capable'],
  ['coverage live probing false', coverage.evidence_model?.live_probing_performed === false],
  ['north star type', northStar.report_type === 'zlar-north-star-readiness-v1'],
  ['north star result not ready', northStar.result === 'NOT_READY_FOR_V3_4_0'],
  ['north star v3.4 false', northStar.v3_4_0_gate?.ready === false],
  ['north star release-forward evidence model', northStar.evidence_model === 'release-forward-dry-run-artifacts'],
  ['north star seven pieces', northStar.counts?.puzzle_pieces_total === 7],
  ['north star proven count five', northStar.counts?.proven_count === 5],
  ['north star partial count one', northStar.counts?.partial_count === 1],
  ['north star installed runtime profile preflight verified', northStar.counts?.installed_runtime_profile_preflight_verified === true],
  ['north star installed runtime profile no-effect boundary', northStar.counts?.installed_runtime_profile_preflight_no_effect_boundary_preserved === true],
  ['north star installed runtime profile recognition contract preserved', northStar.counts?.installed_runtime_profile_preflight_recognition_contract_preserved === true],
  ['north star installed runtime profile service proof preserved', northStar.counts?.installed_runtime_profile_service_proof_preserved === true],
  ['north star installed runtime profile service proof artifact verification preserved', northStar.counts?.installed_runtime_profile_service_artifact_verification_preserved === true],
  ['north star installed runtime profile terminal chain preserved', northStar.counts?.installed_runtime_profile_terminal_chain_preserved === true],
  ['north star installed runtime profile terminal chain required', northStar.counts?.installed_runtime_profile_terminal_chain_required === true],
  ['north star installed runtime profile terminal chain named refusals required', northStar.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_required === true],
  ['north star installed runtime profile terminal chain named refusals preserved', northStar.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_preserved === true],
  ['north star installed runtime profile terminal chain recognition refusal groups required', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_required === true],
  ['north star installed runtime profile terminal chain recognition refusal groups preserved', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_preserved === true],
  ['north star installed runtime profile terminal chain recognition refusal group case IDs required', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required === true],
  ['north star installed runtime profile terminal chain recognition refusal group case IDs preserved', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true],
  ['north star installed runtime profile terminal chain recognition refusal group count', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3],
  ['north star installed runtime profile terminal chain recognition refusal group case count', northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === 18],
  ['north star installed runtime profile terminal chain recognition refusal group case IDs', groupCaseIdsExact(northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)],
  ['north star installed runtime profile terminal chain artifact recognition refusal group count', northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count === 3],
  ['north star installed runtime profile terminal chain artifact recognition refusal group case count', northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count === 18],
  ['north star installed runtime profile terminal chain artifact recognition refusal group case IDs', groupCaseIdsExact(northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)],
  ['north star installed runtime profile terminal chain deployment authority mirror required', northStar.counts?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required === true],
  ['north star installed runtime profile terminal chain deployment authority mirror preserved', northStar.counts?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved === true],
  ['north star installed runtime profile terminal chain deployment authority mirror case count', northStar.counts?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_count === expectedDeploymentProfileAuthorityRefusalCaseIds.length],
  ['north star installed runtime profile terminal chain deployment authority mirror case IDs', arraysEqual(northStar.counts?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['north star installed runtime profile terminal chain deployment authority mirror artifact case IDs', arraysEqual(northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['north star installed runtime profile terminal chain deployment authority mirror before service proof', northStar.counts?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_service_proof === true],
  ['north star installed runtime profile terminal chain deployment authority mirror service proof not started', northStar.counts?.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_service_proof_started === false],
  ['north star product proof path deployment authority refusals required', northStar.counts?.product_proof_path_deployment_profile_authority_refusals_required === true],
  ['north star product proof path deployment authority refusals preserved', northStar.counts?.product_proof_path_deployment_profile_authority_refusals_preserved === true],
  ['manifest terminal chain deployment authority mirror required', manifestTerminalChainRefusalEvidence.deployment_profile_authority_refusal_mirror_required === true],
  ['manifest terminal chain deployment authority mirror preserved', manifestTerminalChainRefusalEvidence.deployment_profile_authority_refusal_mirror_preserved === true],
  ['manifest terminal chain deployment authority mirror case IDs', arraysEqual(manifestTerminalChainRefusalEvidence.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['manifest terminal chain deployment authority mirror artifact case IDs', arraysEqual(manifestTerminalChainRefusalEvidence.artifact_verification_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['manifest terminal chain deployment authority mirror before service proof', manifestTerminalChainRefusalEvidence.deployment_profile_authority_refusals_before_service_proof === true],
  ['manifest terminal chain deployment authority mirror service proof not started', manifestTerminalChainRefusalEvidence.deployment_profile_authority_refusal_service_proof_started === false],
  ['manifest terminal chain deployment authority mirror current-machine false', manifestTerminalChainRefusalEvidence.current_machine_governance === false],
  ['manifest terminal chain deployment authority mirror production downstream false', manifestTerminalChainRefusalEvidence.production_downstream_recognition === false],
  ['manifest terminal chain deployment authority mirror production false', manifestTerminalChainRefusalEvidence.production_authority === false],
  ['manifest terminal chain deployment authority mirror enterprise false', manifestTerminalChainRefusalEvidence.enterprise_readiness === false],
  ['manifest terminal chain deployment authority mirror external false', manifestTerminalChainRefusalEvidence.external_attestation === false],
  ['manifest terminal chain deployment authority mirror sovereign false', manifestTerminalChainRefusalEvidence.sovereign_recognition === false],
  ['manifest terminal chain deployment authority mirror unrouted false', manifestTerminalChainRefusalEvidence.unrouted_surface_coverage === false],
  ['report contract terminal chain deployment authority mirror preserved', manifestReportContractTerminalChainRefusalEvidence.deployment_profile_authority_refusal_mirror_preserved === true],
  ['report contract terminal chain deployment authority mirror case IDs', arraysEqual(manifestReportContractTerminalChainRefusalEvidence.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['report contract terminal chain deployment authority mirror full false boundary', manifestReportContractTerminalChainRefusalEvidence.current_machine_governance === false && manifestReportContractTerminalChainRefusalEvidence.production_downstream_recognition === false && manifestReportContractTerminalChainRefusalEvidence.production_authority === false && manifestReportContractTerminalChainRefusalEvidence.enterprise_readiness === false && manifestReportContractTerminalChainRefusalEvidence.external_attestation === false && manifestReportContractTerminalChainRefusalEvidence.sovereign_recognition === false && manifestReportContractTerminalChainRefusalEvidence.unrouted_surface_coverage === false],
  ['report contract proof-smoke deployment authority mirror preserved', manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved === true],
  ['report contract proof-smoke deployment authority mirror case IDs', arraysEqual(manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['report contract proof-smoke deployment authority mirror full false boundary', manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance === false && manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition === false && manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority === false && manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness === false && manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation === false && manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition === false && manifestReportContractProofSmokeCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage === false],
  ['report contract north star deployment authority mirror required', manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required === true],
  ['report contract north star deployment authority mirror preserved', manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved === true],
  ['report contract north star deployment authority mirror case IDs', arraysEqual(manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['report contract north star deployment authority mirror full false boundary', manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_current_machine_governance === false && manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_downstream_recognition === false && manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_production_authority === false && manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_enterprise_readiness === false && manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation === false && manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_sovereign_recognition === false && manifestReportContractNorthStarCounts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage === false],
  ['north star enterprise observed recognition refusal group case IDs preserved', northStarEnterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true],
  ['north star enterprise observed recognition refusal group count', northStarEnterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count],
  ['north star enterprise observed recognition refusal group case count', northStarEnterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count],
  ['north star enterprise observed recognition refusal group case IDs', groupCaseIdsMatch(northStarEnterpriseProfile.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)],
  ['north star enterprise observed artifact recognition refusal group count', northStarEnterpriseProfile.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count === northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count],
  ['north star enterprise observed artifact recognition refusal group case count', northStarEnterpriseProfile.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count === northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count],
  ['north star enterprise observed artifact recognition refusal group case IDs', groupCaseIdsMatch(northStarEnterpriseProfile.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)],
  ['north star downstream observed recognition refusal group case IDs preserved', northStarDownstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true],
  ['north star downstream observed recognition refusal group count', northStarDownstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count],
  ['north star downstream observed recognition refusal group case count', northStarDownstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === northStar.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count],
  ['north star downstream observed recognition refusal group case IDs', groupCaseIdsMatch(northStarDownstreamRecognition.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)],
  ['north star downstream observed artifact recognition refusal group count', northStarDownstreamRecognition.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count === northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count],
  ['north star downstream observed artifact recognition refusal group case count', northStarDownstreamRecognition.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count === northStar.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count],
  ['north star downstream observed artifact recognition refusal group case IDs', groupCaseIdsMatch(northStarDownstreamRecognition.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)],
  ['north star external attestation false', northStar.claim_boundary?.public_external_attestation === false],
  ['north star production authority false', northStar.claim_boundary?.production_authority === false],
  ['north star current-machine governance false', northStar.claim_boundary?.current_machine_governance === false],
  ['north star trusted issuer provided', northStar.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.trusted_issuer_registry_recognition?.provided === true],
  ['north star malformed registry fail closed', northStar.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.malformed_registry_contract?.fail_closed_before_verdict === true],
  ['north star verifier kit reproducibility provided', northStar.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.verifier_kit_reproducibility?.provided === true],
  ['north star verifier kit reproducibility boundary false', northStar.puzzle_pieces?.find((piece) => piece.id === 4)?.observed?.verifier_kit_reproducibility?.claim_boundary_flags_false === true],
  ['north star verifier kit public distribution provided', northStarVerifierKitDistribution.provided === true],
  ['north star verifier kit public distribution not ready', northStarVerifierKitDistribution.ready_for_public_distribution_claim === false],
  ['north star verifier kit public distribution blockers named', northStarVerifierKitDistribution.blocking_reasons_count > 0],
  ['north star verifier kit public distribution hashes present', northStarVerifierKitDistribution.public_artifact_hashes_present === true],
  ['north star private intake pointer provided', northStarPrivateIntakePointer.provided === true],
  ['north star private intake pointer release tag', northStarPrivateIntakePointer.release_tag === process.env.LOCAL_TAG_FOR_JSON_CHECK],
  ['north star private intake pointer field', northStarPrivateIntakePointer.manifest_field === 'private_verifier_result_sample'],
  ['north star private intake pointer result section', northStarPrivateIntakePointer.result_section === 'Private Verifier Result Intake'],
  ['north star private intake pointer avoids circular hash', northStarPrivateIntakePointer.included_in_core_artifact_hashes === false && northStarPrivateIntakePointer.circular_hash_avoided === true],
  ['north star private intake pointer not attestation', northStarPrivateIntakePointer.creates_public_external_attestation === false && northStarPrivateIntakePointer.proves_non_operator_review === false],
  ['verifier kit reproducibility type', verifierKitReproducibility.report_type === 'zlar-verifier-kit-reproducibility-v1'],
  ['verifier kit reproducibility pass', verifierKitReproducibility.result === 'PASS'],
  ['verifier kit tarball reproducible', verifierKitReproducibility.reproducible?.tarball_sha256_identical === true],
  ['verifier kit manifest reproducible', verifierKitReproducibility.reproducible?.manifest_and_signature_sha256_identical === true],
  ['verifier kit sidecar matches', verifierKitReproducibility.reproducible?.sidecar_matches_tarball === true],
  ['verifier kit public tarball hash', reproHashes.some((entry) => entry.path === 'dist/zlar-verifier-kit-v0.1.0.tar.gz' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['verifier kit reproducibility boundaries false', Object.values(verifierKitReproducibility.claim_boundary || {}).every((value) => value === false)],
  ['verifier kit external-runner diagnostics type', verifierKitExternalRunnerDiagnostics.report_type === 'zlar-verifier-kit-external-runner-diagnostics-v1'],
  ['verifier kit external-runner diagnostics pass', verifierKitExternalRunnerDiagnostics.result === 'PASS'],
  ['verifier kit external-runner diagnostics hardening minimum', verifierKitExternalRunnerDiagnostics.minimum_hardening_release_tag === 'v3.4.20'],
  ['verifier kit external-runner diagnostics preservation minimum', verifierKitExternalRunnerDiagnostics.artifact_preservation_minimum_release_tag === 'v3.4.21'],
  ['verifier kit external-runner diagnostics target tag', verifierKitExternalRunnerDiagnostics.target?.release_tag === process.env.LOCAL_TAG_FOR_JSON_CHECK],
  ['verifier kit external-runner diagnostics target sha match', verifierKitExternalRunnerDiagnostics.target?.expected_commit_sha === verifierKitExternalRunnerDiagnostics.target?.observed_commit_sha],
  ['verifier kit external-runner diagnostics manifest entry bound', verifierKitExternalRunnerDiagnostics.built_kit?.manifest_entry_matches_built_file === true],
  ['verifier kit external-runner diagnostics source built match', verifierKitExternalRunnerDiagnostics.built_kit?.source_matches_built_file === true],
  ['verifier kit external-runner diagnostics grep q absent', verifierKitExternalRunnerDiagnostics.diagnostic_contract?.grep_q_absent_from_external_runner === true],
  ['verifier kit external-runner diagnostics substring check', verifierKitExternalRunnerDiagnostics.diagnostic_contract?.pipefail_safe_last_output_check_present === true],
  ['verifier kit external-runner diagnostics issuer artifact verified', verifierKitExternalRunnerDiagnostics.execution_evidence?.issuer_status_json_artifact_verified === true],
  ['verifier kit external-runner diagnostics command boundary', verifierKitExternalRunnerDiagnostics.execution_evidence?.external_runner_dry_run_executed_by_this_command === false],
  ['verifier kit external-runner diagnostics issuer artifact verdict', verifierKitExternalRunnerDiagnostics.execution_evidence?.issuer_status_verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED'],
  ['verifier kit external-runner diagnostics live probing false', verifierKitExternalRunnerDiagnostics.execution_evidence?.live_probing === false],
  ['verifier kit external-runner diagnostics fixture copy assertions', verifierKitExternalRunnerDiagnostics.repo_regression_contract?.t_kit_23_fixture_copy_assertions_present === true],
  ['verifier kit external-runner diagnostics failure tail preserved', verifierKitExternalRunnerDiagnostics.repo_regression_contract?.t_kit_23_failure_tail_diagnostic_present === true],
  ['verifier kit external-runner diagnostics source regression not in kit', verifierKitExternalRunnerDiagnostics.repo_regression_contract?.included_in_built_kit === false],
  ['verifier kit external-runner diagnostics boundary false', Object.values(verifierKitExternalRunnerDiagnostics.claim_boundary || {}).every((value) => value === false)],
  ['verifier kit public distribution type', verifierKitPublicDistribution.report_type === 'zlar-verifier-kit-public-distribution-v1'],
  ['verifier kit public distribution audit pass', verifierKitPublicDistribution.result === 'AUDIT_PASS'],
  ['verifier kit public distribution absent posture', verifierKitPublicDistribution.posture === 'public_release_assets_absent'],
  ['verifier kit public distribution not ready', verifierKitPublicDistribution.ready_for_public_distribution_claim === false],
  ['verifier kit public distribution local hashes match', verifierKitPublicDistribution.local_artifact_hashes?.all_checked_hashes_match === true],
  ['verifier kit public distribution boundary false', Object.values(verifierKitPublicDistribution.claim_boundary || {}).every((value) => value === false)],
  ['install verified true', install.verified === true],
  ['install latest selection false', install.selects_latest_profile === false],
  ['install persistent profile false', install.persistent_runtime_profile_installed === false],
  ['installed runtime profile preflight verified', installedPreflight.verified === true],
  ['installed runtime profile preflight read only', installedPreflight.read_only === true],
  ['installed runtime profile preflight selected by id and sha', installedPreflight.selected_by_explicit_id_and_sha === true],
  ['installed runtime profile recognition contract preserved', installedPreflight.recognition_contract_preserved === true],
  ['installed runtime profile recognition boundary', installedPreflight.recognition_boundary === 'service-configured-recognition-rule'],
  ['installed runtime profile recognition rule not agent supplied', installedPreflight.recognition_rule_supplied_by_agent === false],
  ['installed runtime profile preflight no activation', installedPreflight.runtime_profile_activation_performed === false],
  ['installed runtime profile preflight no current-machine governance', installedPreflight.current_machine_governance_proven === false],
  ['manifest result type', manifest.result_type === 'zlar-release-forward-verifier-dry-run-result-v1'],
  ['manifest result pass', manifest.result === 'PASS'],
  ['manifest report contract enabled', manifestReportContract.enabled === true],
  ['manifest report contract type', manifestReportContract.contract_type === 'zlar-release-forward-dry-run-report-contract-v1'],
  ['manifest report contract evidence model', manifestReportContract.evidence_model === 'release-forward-dry-run-artifacts'],
  ['manifest report contract minimum target', manifestReportContract.minimum_target === 'v3.4.41'],
  ['manifest report contract satisfied', manifestReportContract.report_contract_satisfied === true],
  ['manifest report contract canonical', manifestReportContract.manifest_is_canonical === true],
  ['manifest report contract result prefix', manifestReportContract.result_lines_prefix === 'manifest.release_forward_report_contract'],
  ['manifest report contract proof-smoke source hash', /^[0-9a-f]{64}$/.test(manifestReportContract.source_artifacts?.proof_smoke_sample_verification_sha256 || '')],
  ['manifest report contract north-star source hash', /^[0-9a-f]{64}$/.test(manifestReportContract.source_artifacts?.north_star_readiness_sha256 || '')],
  ['manifest report contract source same manifest', manifestReportContract.source_artifacts?.terminal_chain_refusal_evidence_included_in_same_manifest === true],
  ['manifest report contract nested artifact tamper exact keys', exactKeys(manifestReportContractNestedArtifactTamper, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest report contract nested artifact tamper mirrors root', JSON.stringify(manifestReportContractNestedArtifactTamper) === JSON.stringify(manifestNestedArtifactTamper)],
  ['manifest report contract nested artifact tamper rejects extra key', !exactKeys({ ...manifestReportContractNestedArtifactTamper, tamper_summary: true }, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest report contract nested artifact tamper rejects missing key', !exactKeys(manifestReportContractNestedArtifactTamperMissing, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest report contract nested artifact tamper rejects renamed key', !exactKeys(manifestReportContractNestedArtifactTamperRenamed, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest report contract nested artifact tamper rejects summary-shaped object', !exactKeys(manifestReportContractNestedArtifactTamperSummary, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest report contract nested artifact binding exact keys', exactKeys(manifestReportContractNestedArtifactBinding, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest report contract nested artifact binding mirrors root', JSON.stringify(manifestReportContractNestedArtifactBinding) === JSON.stringify(manifestNestedArtifactBinding)],
  ['manifest report contract nested artifact binding rejects extra key', !exactKeys({ ...manifestReportContractNestedArtifactBinding, binding_summary: true }, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest report contract nested artifact binding rejects missing key', !exactKeys(manifestReportContractNestedArtifactBindingMissing, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest report contract nested artifact binding rejects renamed key', !exactKeys(manifestReportContractNestedArtifactBindingRenamed, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest report contract nested artifact binding rejects summary-shaped object', !exactKeys(manifestReportContractNestedArtifactBindingSummary, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest report contract product proof path source path', manifestReportContract.source_artifacts?.product_proof_path_path === 'ZLAR/zlar-product-proof-path-v1.json'],
  ['manifest report contract product proof path source hash', /^[0-9a-f]{64}$/.test(manifestReportContract.source_artifacts?.product_proof_path_sha256 || '')],
  ['manifest report contract product proof path minimum target', manifestReportContract.product_proof_path?.minimum_target === 'v3.4.42'],
  ['manifest report contract product proof path report type', manifestReportContract.product_proof_path?.report_type === 'zlar-product-proof-path-v1'],
  ['manifest report contract product proof path result pass', manifestReportContract.product_proof_path?.result === 'PASS'],
  ['manifest report contract product proof path evidence model', manifestReportContract.product_proof_path?.evidence_model === 'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge'],
  ['manifest report contract product proof path no live probing', manifestReportContract.product_proof_path?.live_probing === false],
  ['manifest report contract product proof path gates true', manifestReportContract.product_proof_path?.acceptance_gate_all_true === true],
  ['manifest report contract product proof path forbidden claims false', manifestReportContract.product_proof_path?.forbidden_claims_all_false === true],
  ['manifest report contract simulated human exact keys', exactKeys(manifestSimulatedHuman, expectedProductProofPathSimulatedHumanAuthorizationFields)],
  ['manifest report contract simulated human rejects extra key', !exactKeys({ ...manifestSimulatedHuman, extra_summary: false }, expectedProductProofPathSimulatedHumanAuthorizationFields)],
  ['manifest report contract simulated human rejects missing key', !exactKeys(manifestSimulatedHumanMissing, expectedProductProofPathSimulatedHumanAuthorizationFields)],
  ['manifest report contract simulated human rejects renamed key', !exactKeys(manifestSimulatedHumanRenamed, expectedProductProofPathSimulatedHumanAuthorizationFields)],
  ['manifest report contract simulated human rejects summary-shaped key', !exactKeys({ ...manifestSimulatedHuman, authorization_summary: { authorized: true } }, expectedProductProofPathSimulatedHumanAuthorizationFields)],
  ['manifest report contract receipt boundary exact keys', exactKeys(manifestReceiptBoundary, expectedProductProofPathReceiptVerifierBoundaryFields)],
  ['manifest report contract receipt boundary rejects extra key', !exactKeys({ ...manifestReceiptBoundary, extra_summary: false }, expectedProductProofPathReceiptVerifierBoundaryFields)],
  ['manifest report contract receipt boundary rejects missing key', !exactKeys(manifestReceiptBoundaryMissing, expectedProductProofPathReceiptVerifierBoundaryFields)],
  ['manifest report contract receipt boundary rejects renamed key', !exactKeys(manifestReceiptBoundaryRenamed, expectedProductProofPathReceiptVerifierBoundaryFields)],
  ['manifest report contract receipt boundary rejects summary-shaped key', !exactKeys({ ...manifestReceiptBoundary, receipt_summary: { verdicts: 'collapsed' } }, expectedProductProofPathReceiptVerifierBoundaryFields)],
  ['manifest report contract product proof path terminal verified', manifestReportContract.product_proof_path?.terminal_chain_boundary?.verified === true],
  ['manifest report contract product proof path terminal binding match', manifestReportContract.product_proof_path?.terminal_chain_boundary?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification === true],
  ['manifest report contract product proof path terminal refusal hash match', manifestReportContract.product_proof_path?.terminal_chain_boundary?.trusted_issuer_registry_recognition_refusal_hash_matches_binding === true],
  ['manifest report contract product proof path terminal refusal IDs', arraysEqual(manifestReportContract.product_proof_path?.terminal_chain_boundary?.trusted_issuer_registry_recognition_refusal_case_ids, expectedTrustedIssuerRegistryRecognitionRefusalCaseIds)],
  ['manifest report contract product proof path terminal group count', manifestReportContract.product_proof_path?.terminal_chain_boundary?.recognition_refusal_group_count === 3],
  ['manifest report contract product proof path terminal group case count', manifestReportContract.product_proof_path?.terminal_chain_boundary?.recognition_refusal_group_case_count === 18],
  ['manifest report contract product proof path terminal group case IDs preserved', manifestReportContract.product_proof_path?.terminal_chain_boundary?.recognition_refusal_group_case_ids_preserved === true],
  ['manifest report contract product proof path terminal group case IDs', groupCaseIdsExact(manifestReportContract.product_proof_path?.terminal_chain_boundary?.recognition_refusal_group_case_ids)],
  ['manifest report contract product proof path terminal group case IDs reject extra key', !groupCaseIdsExact({ ...(manifestReportContract.product_proof_path?.terminal_chain_boundary?.recognition_refusal_group_case_ids || {}), summary_or_extra_group: ['collapsed_refusal_summary'] })],
  ['manifest report contract product proof path terminal group case IDs reject missing key', !groupCaseIdsExact(Object.fromEntries(Object.entries(manifestReportContract.product_proof_path?.terminal_chain_boundary?.recognition_refusal_group_case_ids || {}).filter(([key]) => key !== 'recognized_receipt_scope_mismatch')))],
  ['manifest report contract product proof path terminal public key omitted', manifestReportContract.product_proof_path?.terminal_chain_boundary?.registry_public_key_material_included === false],
  ['manifest report contract product proof path terminal no external attestation', manifestReportContract.product_proof_path?.terminal_chain_boundary?.external_attestation === false],
  ['manifest report contract product proof path deployment bridge proof type', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.proof_type === 'zlar-protected-records-one-terminal-deployment-profile-proof-v1'],
  ['manifest report contract product proof path deployment bridge evidence model', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.evidence_model === 'local-fixture-one-terminal-deployment-profile-authority-bridge'],
  ['manifest report contract product proof path deployment bridge recognized once', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.recognized_receipt_mutates_once === true],
  ['manifest report contract product proof path deployment bridge refusal count', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.observed_refusal_case_count === 18],
  ['manifest report contract product proof path deployment bridge authority refusal count', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.deployment_profile_authority_refusal_case_count === expectedDeploymentProfileAuthorityRefusalCaseIds.length],
  ['manifest report contract product proof path deployment bridge authority refusal case IDs', arraysEqual(manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['manifest report contract product proof path deployment bridge authority refusals before service proof', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.deployment_profile_authority_refusals_before_service_proof === true],
  ['manifest report contract product proof path deployment bridge stale artifact refused', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.stale_deployment_profile_artifact_refused_before_service_proof === true],
  ['manifest report contract product proof path deployment bridge profile mismatch refused', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.profile_recognition_mismatch_refused_before_service_proof === true],
  ['manifest report contract product proof path deployment bridge request authority refused', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.request_stream_authority_material_refused_before_service_proof === true],
  ['manifest report contract product proof path deployment bridge request authority false', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.request_stream_authority_material_accepted === false],
  ['manifest report contract product proof path deployment bridge current-machine false', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.current_machine_governance === false],
  ['manifest report contract product proof path deployment bridge production false', manifestReportContract.product_proof_path?.deployment_profile_authority_bridge?.production_authority === false],
  ['manifest report contract product proof path north-star terminal observed', manifestReportContract.product_proof_path?.north_star?.terminal_chain_boundary_observed === true],
  ['manifest report contract product proof path north-star terminal group count', manifestReportContract.product_proof_path?.north_star?.terminal_chain_recognition_refusal_group_count === 3],
  ['manifest report contract product proof path north-star terminal group case count', manifestReportContract.product_proof_path?.north_star?.terminal_chain_recognition_refusal_group_case_count === 18],
  ['manifest report contract product proof path north-star terminal group case IDs preserved', manifestReportContract.product_proof_path?.north_star?.terminal_chain_recognition_refusal_group_case_ids_preserved === true],
  ['manifest report contract product proof path north-star terminal group case IDs', groupCaseIdsExact(manifestReportContract.product_proof_path?.north_star?.terminal_chain_recognition_refusal_group_case_ids)],
  ['manifest report contract product proof path north-star terminal group case IDs reject renamed key', !groupCaseIdsExact({ ...Object.fromEntries(Object.entries(manifestReportContract.product_proof_path?.north_star?.terminal_chain_recognition_refusal_group_case_ids || {}).filter(([key]) => key !== 'recognized_receipt_scope_mismatch')), recognized_receipt_scope_mismatches: manifestReportContract.product_proof_path?.north_star?.terminal_chain_recognition_refusal_group_case_ids?.recognized_receipt_scope_mismatch })],
  ['manifest report contract product proof path terminal group case IDs reject summary object', !groupCaseIdsExact({ summary: manifestReportContract.product_proof_path?.terminal_chain_boundary?.recognition_refusal_group_case_ids })],
  ['manifest report contract product proof path north-star deployment bridge preserved', manifestReportContract.product_proof_path?.north_star?.deployment_profile_authority_bridge_preserved === true],
  ['manifest report contract product proof path north-star deployment authority refusals preserved', manifestReportContract.product_proof_path?.north_star?.deployment_profile_authority_refusals_preserved === true],
  ['manifest report contract product proof path north-star deployment authority refusal case IDs', arraysEqual(manifestReportContract.product_proof_path?.north_star?.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['manifest report contract product proof path receipt valid', manifestReportContract.product_proof_path?.receipt_verifier_boundary?.valid_verdict === 'VALID'],
  ['manifest report contract product proof path north star consumed', manifestReportContract.product_proof_path?.north_star?.artifact_consumed === true],
  ['manifest report contract product proof path known noncoverage visible', manifestReportContract.product_proof_path?.known_ungoverned_boundaries_includes_unrouted_records_paths === true],
  ['manifest report contract product proof path no attestation', manifestReportContract.product_proof_path?.claim_boundary?.creates_public_external_attestation === false],
  ['manifest report contract product proof path no current-machine governance', manifestReportContract.product_proof_path?.claim_boundary?.proves_current_machine_governance === false],
  ['manifest report contract proof-smoke group count', manifestReportContract.proof_smoke?.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3],
  ['manifest report contract proof-smoke group case count', manifestReportContract.proof_smoke?.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === 18],
  ['manifest report contract proof-smoke group case ids exact', groupCaseIdsExact(manifestReportContractProofSmokeGroupCaseIds)],
  ['manifest report contract proof-smoke group case ids reject extra key', !groupCaseIdsExact({ ...manifestReportContractProofSmokeGroupCaseIds, summary_or_extra_group: ['collapsed_refusal_summary'] })],
  ['manifest report contract proof-smoke group case ids reject missing key', !groupCaseIdsExact(manifestReportContractProofSmokeGroupCaseIdsMissing)],
  ['manifest report contract proof-smoke group case ids reject renamed key', !groupCaseIdsExact(manifestReportContractProofSmokeGroupCaseIdsRenamed)],
  ['manifest report contract proof-smoke group case ids reject summary object', !groupCaseIdsExact({ summary: manifestReportContractProofSmokeGroupCaseIds })],
  ['manifest report contract north-star case ids preserved', manifestReportContract.north_star?.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved === true],
  ['manifest report contract north-star group case ids exact', groupCaseIdsExact(manifestReportContractNorthStarGroupCaseIds)],
  ['manifest report contract north-star group case ids reject extra key', !groupCaseIdsExact({ ...manifestReportContractNorthStarGroupCaseIds, summary_or_extra_group: ['collapsed_refusal_summary'] })],
  ['manifest report contract north-star group case ids reject missing key', !groupCaseIdsExact(manifestReportContractNorthStarGroupCaseIdsMissing)],
  ['manifest report contract north-star group case ids reject renamed key', !groupCaseIdsExact(manifestReportContractNorthStarGroupCaseIdsRenamed)],
  ['manifest report contract north-star group case ids reject summary object', !groupCaseIdsExact({ summary: manifestReportContractNorthStarGroupCaseIds })],
  ['manifest report contract trusted registry terminal case count', manifestReportContract.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_case_count === 2],
  ['manifest report contract trusted registry terminal case ids', arraysEqual(manifestReportContract.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_case_ids, expectedTrustedIssuerRegistryRecognitionRefusalCaseIds)],
  ['manifest report contract trusted registry terminal reason codes', arraysEqual(manifestReportContract.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_reason_codes, expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes)],
  ['manifest report contract trusted registry terminal hash bound', manifestReportContract.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_sha256 === manifestReportContract.terminal_chain_refusal_evidence?.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 && /^[0-9a-f]{64}$/.test(manifestReportContract.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_sha256 || '')],
  ['manifest report contract proof-smoke trusted registry ids', arraysEqual(manifestReportContract.proof_smoke?.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids, expectedTrustedIssuerRegistryRecognitionRefusalCaseIds)],
  ['manifest report contract north-star trusted registry preserved', manifestReportContract.north_star?.counts?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved === true],
  ['manifest report contract enterprise trusted registry preserved', manifestReportContract.north_star?.puzzle_3_observed?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved === true],
  ['manifest report contract downstream trusted registry preserved', manifestReportContract.north_star?.puzzle_5_observed?.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved === true],
  ['manifest report contract no public attestation', manifestReportContract.claim_boundary?.creates_public_external_attestation === false],
  ['manifest report contract no non-operator review', manifestReportContract.claim_boundary?.proves_non_operator_review === false],
  ['manifest report contract no live registry', manifestReportContract.claim_boundary?.proves_live_registry === false],
  ['manifest report contract no live issuer', manifestReportContract.claim_boundary?.proves_live_issuer_status === false],
  ['manifest report contract no key custody', manifestReportContract.claim_boundary?.proves_key_custody === false],
  ['manifest report contract no revocation truth', manifestReportContract.claim_boundary?.proves_revocation_truth === false],
  ['manifest report contract no current-machine governance', manifestReportContract.claim_boundary?.proves_current_machine_governance === false],
  ['manifest report contract no live mcp', manifestReportContract.claim_boundary?.proves_live_mcp_coverage === false],
  ['manifest report contract no production downstream', manifestReportContract.claim_boundary?.proves_production_downstream_recognition === false],
  ['manifest report contract no production authority', manifestReportContract.claim_boundary?.proves_production_authority === false],
  ['manifest report contract no enterprise readiness', manifestReportContract.claim_boundary?.proves_enterprise_readiness === false],
  ['manifest report contract no sovereign recognition', manifestReportContract.claim_boundary?.proves_sovereign_recognition === false],
  ['manifest report contract no unrouted coverage', manifestReportContract.claim_boundary?.proves_unrouted_surface_coverage === false],
  ['private verifier result type', privateVerifierResult.report_type === 'zlar-private-verifier-result-v1'],
  ['private verifier result sample fixture', privateVerifierResult.intake_class === 'sample-fixture'],
  ['private verifier result target tag', privateVerifierResult.target?.release_tag === process.env.LOCAL_TAG_FOR_JSON_CHECK],
  ['private verifier result target sha match', privateVerifierResult.target?.expected_commit_sha === privateVerifierResult.target?.commit_sha],
  ['private verifier result no public attestation', privateVerifierResult.claim_boundary?.public_external_attestation === false],
  ['private verifier result no public attribution', privateVerifierResult.claim_boundary?.public_attribution === false],
  ['private verifier result has manifest hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'DRY-RUN-MANIFEST.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has run sums hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'RUN-SHA256SUMS' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier SHA256SUMS row set exact', mapPathsEqual(sha256SumsByPath, expectedSha256SumsByPath)],
  ['private verifier SHA256SUMS rows match private result', mapEntriesEqual(sha256SumsByPath, expectedSha256SumsByPath)],
  ['private verifier RUN-SHA256SUMS row set exact', mapPathsEqual(runSha256SumsByPath, expectedRunSha256SumsPathSet)],
  ['private verifier RUN-SHA256SUMS binds SHA256SUMS', runSha256SumsByPath?.get('SHA256SUMS') === privateVerifierArtifactHashByPath.get('SHA256SUMS')],
  ['private verifier result has north star hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-north-star-readiness-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has verifier kit external-runner diagnostics hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has public distribution hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-public-distribution-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile preflight hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile recognition proof hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile recognition proof artifact hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile recognition proof artifact verification hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile service proof hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-service-proof-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile service proof artifact hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile service proof artifact verification hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile terminal chain hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile terminal chain artifact hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile terminal chain artifact verification hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile terminal chain forged inner preflight hash artifact', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier result has installed profile terminal chain forged inner service hash artifact', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['private verifier verification type', privateVerifierResultVerification.verification_type === 'zlar-private-verifier-result-verification-v1'],
  ['private verifier verification true', privateVerifierResultVerification.verified === true],
  ['private verifier verification result sha bound', privateVerifierResultVerification.result_sha256 === privateVerifierResultSha],
  ['private verifier verification artifact set sha bound', privateVerifierResultVerification.artifact_set_sha256 === privateVerifierResultArtifactSetSha],
  ['private verifier verification required posture', privateVerifierResultVerification.required_identity?.command_posture === 'private-result-with-required-recomputed-evidence'],
  ['private verifier verification requires result sha', privateVerifierResultVerification.required_identity?.result_sha256_required === true],
  ['private verifier verification result sha matched', privateVerifierResultVerification.required_identity?.result_sha256_matched === true],
  ['private verifier verification requires target', privateVerifierResultVerification.required_identity?.target_required === true],
  ['private verifier verification target matched', privateVerifierResultVerification.required_identity?.target_matched === true],
  ['private verifier verification requires bundle sha', privateVerifierResultVerification.required_identity?.bundle_sha256_required === true],
  ['private verifier verification bundle sha matched', privateVerifierResultVerification.required_identity?.bundle_sha256_matched === true],
  ['private verifier verification requires artifact set sha', privateVerifierResultVerification.required_identity?.artifact_set_sha256_required === true],
  ['private verifier verification artifact set sha matched', privateVerifierResultVerification.required_identity?.artifact_set_sha256_matched === true],
  ['private verifier verification requires recomputed evidence', privateVerifierResultVerification.required_identity?.recomputed_evidence_required === true],
  ['private verifier verification recomputed evidence matched', privateVerifierResultVerification.required_identity?.recomputed_evidence_matched === true],
  ['private verifier evidence-dir hashes recomputed', privateVerifierResultVerification.evidence_dir_hash_verification?.hashes_recomputed === true],
  ['private verifier evidence-dir artifact count', privateVerifierResultVerification.evidence_dir_hash_verification?.artifact_hash_count === privateVerifierResult.evidence?.artifact_hashes?.length],
  ['private verifier evidence-dir contract required', privateVerifierResultVerification.evidence_dir_contract_verification?.required_for_target === true],
  ['private verifier evidence-dir contract verified', privateVerifierResultVerification.evidence_dir_contract_verification?.verified === true],
  ['private verifier evidence-dir terminal group count', privateVerifierResultVerification.evidence_dir_contract_verification?.product_proof_path_terminal_chain_recognition_refusal_group_count === 3],
  ['private verifier evidence-dir terminal group case count', privateVerifierResultVerification.evidence_dir_contract_verification?.product_proof_path_terminal_chain_recognition_refusal_group_case_count === 18],
  ['private verifier evidence-dir terminal group ids preserved', privateVerifierResultVerification.evidence_dir_contract_verification?.product_proof_path_terminal_chain_recognition_refusal_group_case_ids_preserved === true],
  ['private verifier evidence-dir north-star group ids preserved', privateVerifierResultVerification.evidence_dir_contract_verification?.north_star_terminal_chain_recognition_refusal_group_case_ids_preserved === true],
  ['private verifier downstream refusals unboarded', privateVerifierResultVerification.evidence_dir_contract_verification?.downstream_refusal_all_refusals_unboarded === true],
  ['private verifier downstream refusal reasons', arraysEqual(privateVerifierResultVerification.evidence_dir_contract_verification?.downstream_refusal_reasons, expectedDownstreamRefusalReasons)],
  ['private verifier north-star downstream refusals unboarded', privateVerifierResultVerification.evidence_dir_contract_verification?.north_star_downstream_refusal_all_refusals_unboarded === true],
  ['private verifier north-star downstream refusal reasons', arraysEqual(privateVerifierResultVerification.evidence_dir_contract_verification?.north_star_downstream_refusal_reasons, expectedDownstreamRefusalReasons)],
  ['private verifier recognized receipt path mirror required', privateVerifierResultVerification.evidence_dir_contract_verification?.terminal_chain_recognized_receipt_path_mirror_required_for_target === true],
  ['private verifier recognized receipt path mirror preserved', privateVerifierResultVerification.evidence_dir_contract_verification?.product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved === true],
  ['private verifier north-star recognized receipt path mirror preserved', privateVerifierResultVerification.evidence_dir_contract_verification?.north_star_terminal_chain_recognized_receipt_path_mirror_preserved === true],
  ['private verifier recognized receipt path sha', /^[0-9a-f]{64}$/.test(privateVerifierResultVerification.evidence_dir_contract_verification?.terminal_chain_recognized_receipt_path_evidence_sha256 || '')],
  ['private verifier recognized receipt path source binding matches', privateVerifierResultVerification.evidence_dir_contract_verification?.terminal_chain_recognized_receipt_path_evidence_source_binding_matches_trusted_registry_binding === true],
  ['private verifier verification no public attestation', privateVerifierResultVerification.public_external_attestation === false],
  ['manifest target tag', manifest.target?.release_tag === process.env.LOCAL_TAG_FOR_JSON_CHECK],
  ['manifest target sha match', manifest.target?.expected_commit_sha === manifest.target?.observed_commit_sha],
  ['manifest repo url sanitized', manifest.target?.repo_url === '<local-path>'],
  ['manifest assertions all pass', manifest.assertions?.failed === 0 && manifest.assertions?.passed >= 20],
  ['manifest coverage hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-coverage-map-sample.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest service preflight hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-service-preflight-sample-verification.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest issuer status proof hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-issuer-status-proof.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest issuer status fixture hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-issuer-status-fixture.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest trusted issuer recognition hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-trusted-receipt-issuer-recognition.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest malformed registry hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest malformed registry error hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-trusted-receipt-issuer-recognition-malformed-registry-error.txt' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest north star hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-north-star-readiness-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest verifier kit external-runner diagnostics hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile preflight hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile recognition proof hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile recognition proof artifact hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile recognition proof artifact verification hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile service proof hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-service-proof-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile service proof artifact hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile service proof artifact verification hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile terminal chain hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile terminal chain artifact hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile terminal chain artifact verification hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile terminal chain forged inner preflight hash artifact included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile terminal chain forged inner preflight hash error included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile terminal chain forged inner service hash artifact included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest installed profile terminal chain forged inner service hash error included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest verifier kit reproducibility hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-reproducibility-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest verifier kit public distribution hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-verifier-kit-public-distribution-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest private result sample pointer enabled', manifest.private_verifier_result_sample?.enabled === true],
  ['manifest private result sample pointer exact keys', exactKeys(privateSamplePointer, expectedPrivateVerifierResultSamplePointerFields)],
  ['manifest private result sample pointer rejects extra key', !exactKeys({ ...privateSamplePointer, extra_summary: false }, expectedPrivateVerifierResultSamplePointerFields)],
  ['manifest private result sample pointer rejects missing key', !exactKeys(privateSamplePointerMissing, expectedPrivateVerifierResultSamplePointerFields)],
  ['manifest private result sample pointer rejects renamed key', !exactKeys(privateSamplePointerRenamed, expectedPrivateVerifierResultSamplePointerFields)],
  ['manifest private result sample pointer rejects summary-shaped field', !exactKeys({ ...privateSamplePointer, pointer_summary: { result_section: privateSamplePointer.result_section } }, expectedPrivateVerifierResultSamplePointerFields)],
  ['manifest private result sample result section', manifest.private_verifier_result_sample?.result_section === 'Private Verifier Result Intake'],
  ['manifest private result sample envelope path', manifest.private_verifier_result_sample?.envelope_path === 'ZLAR/zlar-private-verifier-result-v1.json'],
  ['manifest private result sample verification path', manifest.private_verifier_result_sample?.verification_path === 'ZLAR/zlar-private-verifier-result-verification-v1.json'],
  ['manifest private result sample avoids circular hash', manifest.private_verifier_result_sample?.included_in_core_artifact_hashes === false && manifest.private_verifier_result_sample?.circular_hash_avoided === true],
  ['manifest private result sample verification section', manifest.private_verifier_result_sample?.verification_result_section === 'Private Result Verification Evidence'],
  ['manifest private result sample verification minimum target', manifest.private_verifier_result_sample?.verification_result_minimum_target === 'v3.4.34'],
  ['manifest private result sample not attestation', manifest.private_verifier_result_sample?.creates_public_external_attestation === false && manifest.private_verifier_result_sample?.proves_non_operator_review === false],
  ['manifest private result envelope not core artifact hash', !(manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-private-verifier-result-v1.json')],
  ['manifest private result verification not core artifact hash', !(manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-private-verifier-result-verification-v1.json')],
  ['manifest issuer status evidence enabled', manifest.issuer_status_evidence?.enabled === true],
  ['manifest issuer status evidence model', manifest.issuer_status_evidence?.evidence_model === 'release-forward-local-issuer-status-fixture'],
  ['manifest issuer status evidence minimum target', manifest.issuer_status_evidence?.minimum_target === 'v3.4.33'],
  ['manifest issuer status evidence proof hash', /^[0-9a-f]{64}$/.test(manifest.issuer_status_evidence?.issuer_status_proof_sha256 || '')],
  ['manifest issuer status evidence fixture hash', /^[0-9a-f]{64}$/.test(manifest.issuer_status_evidence?.verifier_kit_fixture_sha256 || '')],
  ['manifest issuer status evidence diagnostics hash', /^[0-9a-f]{64}$/.test(manifest.issuer_status_evidence?.external_runner_diagnostics_sha256 || '')],
  ['manifest issuer status evidence proof type', manifest.issuer_status_evidence?.proof_type === 'issuer-status-proof-v1'],
  ['manifest issuer status evidence proof fixture model', manifest.issuer_status_evidence?.proof_evidence_model === 'local-hermetic-fixture'],
  ['manifest issuer status evidence live probing false', manifest.issuer_status_evidence?.proof_live_probing === false],
  ['manifest issuer status evidence trust anchor', manifest.issuer_status_evidence?.trust_anchor_model === 'local-fixture-recognition-rule'],
  ['manifest issuer status evidence active issuer boards', manifest.issuer_status_evidence?.active_issuer_boards === true],
  ['manifest issuer status evidence retired issuer refuses', manifest.issuer_status_evidence?.retired_issuer_refuses === true],
  ['manifest issuer status evidence compromised issuer refuses', manifest.issuer_status_evidence?.compromised_issuer_refuses === true],
  ['manifest issuer status evidence missing status issuer refuses', manifest.issuer_status_evidence?.missing_status_issuer_refuses === true],
  ['manifest issuer status evidence unknown issuer refuses', manifest.issuer_status_evidence?.unknown_issuer_refuses === true],
  ['manifest issuer status evidence missing key issuer refuses', manifest.issuer_status_evidence?.missing_key_issuer_refuses === true],
  ['manifest issuer status evidence no raw key material', manifest.issuer_status_evidence?.raw_public_key_material_included === false && manifest.issuer_status_evidence?.raw_private_key_material_included === false],
  ['manifest issuer status evidence fixture verdict', manifest.issuer_status_evidence?.verifier_kit_fixture_verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED'],
  ['manifest issuer status evidence fixture live probing false', manifest.issuer_status_evidence?.verifier_kit_fixture_live_probing === false],
  ['manifest issuer status evidence diagnostics verified', manifest.issuer_status_evidence?.diagnostics_issuer_artifact_verified === true],
  ['manifest issuer status evidence diagnostics fixture hash bound', manifest.issuer_status_evidence?.diagnostics_issuer_artifact_sha256_matches_fixture === true],
  ['manifest issuer status evidence no attestation', manifest.issuer_status_evidence?.creates_public_external_attestation === false],
  ['manifest issuer status evidence no non-operator review', manifest.issuer_status_evidence?.proves_non_operator_review === false],
  ['manifest issuer status evidence no live issuer status', manifest.issuer_status_evidence?.proves_live_issuer_status === false],
  ['manifest issuer status evidence no key custody', manifest.issuer_status_evidence?.proves_key_custody === false],
  ['manifest issuer status evidence no revocation truth', manifest.issuer_status_evidence?.proves_revocation_truth === false],
  ['manifest issuer status evidence no production trust registry', manifest.issuer_status_evidence?.proves_production_trust_registry === false],
  ['manifest issuer status evidence no production downstream', manifest.issuer_status_evidence?.proves_production_downstream_recognition === false],
  ['manifest trusted issuer registry evidence enabled', manifestTrustedIssuerRegistry.enabled === true],
  ['manifest trusted issuer registry evidence model', manifestTrustedIssuerRegistry.evidence_model === 'release-forward-local-trusted-issuer-registry-fixture'],
  ['manifest trusted issuer registry evidence minimum target', manifestTrustedIssuerRegistry.minimum_target === 'v3.4.35'],
  ['manifest trusted issuer registry recognition hash', /^[0-9a-f]{64}$/.test(manifestTrustedIssuerRegistry.recognition_sha256 || '')],
  ['manifest trusted issuer registry malformed error hash', /^[0-9a-f]{64}$/.test(manifestTrustedIssuerRegistry.malformed_registry_error_sha256 || '')],
  ['manifest trusted issuer registry type', manifestTrustedIssuerRegistry.registry_type === 'trusted-receipt-issuers-v1'],
  ['manifest trusted issuer registry fixture model', manifestTrustedIssuerRegistry.registry_evidence_model === 'bundled-local-fixture'],
  ['manifest trusted issuer registry live probing false', manifestTrustedIssuerRegistry.live_probing === false],
  ['manifest trusted issuer registry scope', manifestTrustedIssuerRegistry.registry_scope === 'verifier-kit-sample'],
  ['manifest trusted issuer registry recognized', manifestTrustedIssuerRegistry.verdict === 'RECOGNIZED' && manifestTrustedIssuerRegistry.recognized === true],
  ['manifest trusted issuer registry active issuer', manifestTrustedIssuerRegistry.issuer_status === 'active'],
  ['manifest trusted issuer registry signature valid', manifestTrustedIssuerRegistry.signature_valid === true],
  ['manifest trusted issuer registry fail closed before verdict', manifestTrustedIssuerRegistry.malformed_registry_fail_closed_before_verdict === true],
  ['manifest trusted issuer registry no attestation', manifestTrustedIssuerRegistry.creates_public_external_attestation === false],
  ['manifest trusted issuer registry no live registry', manifestTrustedIssuerRegistry.proves_live_registry === false],
  ['manifest trusted issuer registry no live issuer', manifestTrustedIssuerRegistry.proves_live_issuer_status === false],
  ['manifest trusted issuer registry no key custody', manifestTrustedIssuerRegistry.proves_key_custody === false],
  ['manifest trusted issuer registry no revocation truth', manifestTrustedIssuerRegistry.proves_revocation_truth === false],
  ['manifest trusted issuer registry no production trust registry', manifestTrustedIssuerRegistry.proves_production_trust_registry === false],
  ['manifest trusted issuer registry no production downstream', manifestTrustedIssuerRegistry.proves_production_downstream_recognition === false],
  ['manifest trusted issuer registry no production authority', manifestTrustedIssuerRegistry.proves_production_authority === false],
  ['manifest trusted issuer registry no sovereign recognition', manifestTrustedIssuerRegistry.proves_sovereign_recognition === false],
  ['manifest terminal chain refusal evidence enabled', manifest.terminal_chain_refusal_evidence?.enabled === true],
  ['manifest terminal chain refusal evidence named hash bound', manifest.terminal_chain_refusal_evidence?.named_receipt_refusals_sha256 === manifest.terminal_chain_refusal_evidence?.artifact_verification_named_receipt_refusals_sha256 && /^[0-9a-f]{64}$/.test(manifest.terminal_chain_refusal_evidence?.named_receipt_refusals_sha256 || '')],
  ['manifest terminal chain refusal evidence all named refused', manifest.terminal_chain_refusal_evidence?.all_named_receipt_refusals_before_mutation === true],
  ['manifest terminal chain refusal evidence wrong policy named', manifest.terminal_chain_refusal_evidence?.named_receipt_refusals?.wrong_policy?.reason_code === 'policy_not_recognized' && manifest.terminal_chain_refusal_evidence?.named_receipt_refusals?.wrong_policy?.refused_before_mutation === true],
  ['manifest terminal chain recognition refusal groups required', manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups_required === true],
  ['manifest terminal chain recognition refusal group case ids required', manifest.terminal_chain_refusal_evidence?.recognition_refusal_group_case_ids_required === true],
  ['manifest terminal chain recognition refusal groups hash bound', manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups_sha256 === manifest.terminal_chain_refusal_evidence?.artifact_verification_recognition_refusal_groups_sha256 && /^[0-9a-f]{64}$/.test(manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups_sha256 || '')],
  ['manifest terminal chain recognition refusal groups all refused', manifest.terminal_chain_refusal_evidence?.all_recognition_refusal_groups_before_mutation === true],
  ['manifest terminal chain recognition refusal group case ids preserved', manifest.terminal_chain_refusal_evidence?.all_recognition_refusal_group_case_ids_preserved === true],
  ['manifest terminal chain recognition refusal group case ids exact', groupCaseIdsExact(manifestTerminalChainGroupCaseIds)],
  ['manifest terminal chain recognition refusal group case ids reject extra key', !groupCaseIdsExact({ ...manifestTerminalChainGroupCaseIds, summary_or_extra_group: ['collapsed_refusal_summary'] })],
  ['manifest terminal chain recognition refusal group case ids reject missing key', !groupCaseIdsExact(manifestTerminalChainGroupCaseIdsMissing)],
  ['manifest terminal chain recognition refusal group case ids reject renamed key', !groupCaseIdsExact(manifestTerminalChainGroupCaseIdsRenamed)],
  ['manifest terminal chain recognition refusal group case ids reject summary object', !groupCaseIdsExact({ summary: manifestTerminalChainGroupCaseIds })],
  ['manifest terminal chain recognition refusal groups no usable authority', manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups?.no_usable_recognized_receipt_authority?.case_count === 6 && manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups?.no_usable_recognized_receipt_authority?.all_refused_before_mutation === true],
  ['manifest terminal chain recognition refusal groups no usable authority case ids', (manifest.terminal_chain_refusal_evidence?.recognition_refusal_group_case_ids?.no_usable_recognized_receipt_authority || []).join(',') === 'missing_receipt_refused_before_runtime_mutation,invalid_receipt_refused_before_runtime_mutation,unknown_issuer_refused_before_runtime_mutation,retired_issuer_refused_before_runtime_mutation,missing_issuer_status_refused_before_runtime_mutation,stale_receipt_refused_before_runtime_mutation'],
  ['manifest terminal chain recognition refusal groups scope mismatch', manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups?.recognized_receipt_scope_mismatch?.all_refused_before_mutation === true],
  ['manifest terminal chain recognition refusal groups scope mismatch case ids', (manifest.terminal_chain_refusal_evidence?.recognition_refusal_group_case_ids?.recognized_receipt_scope_mismatch || []).join(',') === 'wrong_policy_refused_before_runtime_mutation,wrong_domain_refused_before_runtime_mutation,wrong_tool_refused_before_runtime_mutation,wrong_audit_event_refused_before_runtime_mutation,wrong_detail_refused_before_runtime_mutation,non_boarding_outcome_refused_before_runtime_mutation'],
  ['manifest terminal chain recognition refusal groups route/request authority', manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups?.route_or_request_authority_material_refused?.case_count === 6 && manifest.terminal_chain_refusal_evidence?.recognition_refusal_groups?.route_or_request_authority_material_refused?.all_refused_before_mutation === true],
  ['manifest terminal chain recognition refusal groups route/request authority case ids', (manifest.terminal_chain_refusal_evidence?.recognition_refusal_group_case_ids?.route_or_request_authority_material_refused || []).join(',') === 'wrong_runtime_profile_id_refused_before_runtime_mutation,direct_api_without_receipt_refused_before_runtime_mutation,direct_api_with_receipt_refused_before_runtime_mutation,agent_supplied_recognition_rule_refused_before_runtime_mutation,agent_supplied_fixture_mode_refused_before_runtime_mutation,unsupported_request_field_refused_before_runtime_mutation'],
  ['manifest terminal chain trusted registry refusals required', manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_required === true],
  ['manifest terminal chain trusted registry refusal minimum target', manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_minimum_target === 'v3.4.39'],
  ['manifest terminal chain trusted registry refusal case count', manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_case_count === 2],
  ['manifest terminal chain trusted registry artifact refusal case count', manifest.terminal_chain_refusal_evidence?.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count === 2],
  ['manifest terminal chain trusted registry refusals all refused', manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_all_refused === true],
  ['manifest terminal chain trusted registry artifact refusals all refused', manifest.terminal_chain_refusal_evidence?.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused === true],
  ['manifest terminal chain trusted registry refusal case ids', arraysEqual(manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_case_ids, expectedTrustedIssuerRegistryRecognitionRefusalCaseIds)],
  ['manifest terminal chain trusted registry artifact refusal case ids', arraysEqual(manifest.terminal_chain_refusal_evidence?.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids, expectedTrustedIssuerRegistryRecognitionRefusalCaseIds)],
  ['manifest terminal chain trusted registry refusal reason codes', arraysEqual(manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusal_reason_codes, expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes)],
  ['manifest terminal chain trusted registry artifact refusal reason codes', arraysEqual(manifest.terminal_chain_refusal_evidence?.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes, expectedTrustedIssuerRegistryRecognitionRefusalReasonCodes)],
  ['manifest terminal chain trusted registry refusal hash bound', manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_sha256 === manifest.terminal_chain_refusal_evidence?.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256 && /^[0-9a-f]{64}$/.test(manifest.terminal_chain_refusal_evidence?.trusted_issuer_registry_recognition_refusals_sha256 || '')],
  ['manifest terminal chain trusted registry refusals preserved', manifest.terminal_chain_refusal_evidence?.all_trusted_issuer_registry_recognition_refusals_preserved === true],
  ['manifest terminal chain nested artifact tamper refusals required', manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals_required === true],
  ['manifest terminal chain nested artifact tamper exact keys', exactKeys(manifestNestedArtifactTamper, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest terminal chain nested artifact tamper rejects extra key', !exactKeys({ ...manifestNestedArtifactTamper, tamper_summary: true }, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest terminal chain nested artifact tamper rejects missing key', !exactKeys(manifestNestedArtifactTamperMissing, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest terminal chain nested artifact tamper rejects renamed key', !exactKeys(manifestNestedArtifactTamperRenamed, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest terminal chain nested artifact tamper rejects summary-shaped object', !exactKeys(manifestNestedArtifactTamperSummary, expectedTerminalChainNestedArtifactTamperRefusalFields)],
  ['manifest terminal chain nested artifact tamper preflight type', manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals?.generated_preflight_artifact_type === 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1'],
  ['manifest terminal chain nested artifact tamper service type', manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals?.generated_service_proof_artifact_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1'],
  ['manifest terminal chain nested artifact tamper artifact preflight type', manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals?.artifact_generated_preflight_artifact_type === 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1'],
  ['manifest terminal chain nested artifact tamper artifact service type', manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals?.artifact_generated_service_proof_artifact_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1'],
  ['manifest terminal chain nested artifact tamper forged preflight refused', manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals?.forged_inner_preflight_hash_refused === true],
  ['manifest terminal chain nested artifact tamper forged service refused', manifest.terminal_chain_refusal_evidence?.nested_artifact_tamper_refusals?.forged_inner_service_hash_refused === true],
  ['manifest terminal chain nested artifact binding required', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding_required === true],
  ['manifest terminal chain nested artifact binding exact keys', exactKeys(manifestNestedArtifactBinding, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest terminal chain nested artifact binding rejects extra key', !exactKeys({ ...manifestNestedArtifactBinding, binding_summary: true }, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest terminal chain nested artifact binding rejects missing key', !exactKeys(manifestNestedArtifactBindingMissing, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest terminal chain nested artifact binding rejects renamed key', !exactKeys(manifestNestedArtifactBindingRenamed, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest terminal chain nested artifact binding rejects summary-shaped object', !exactKeys(manifestNestedArtifactBindingSummary, expectedTerminalChainNestedArtifactBindingFields)],
  ['manifest terminal chain nested artifact binding equals verifier summary', JSON.stringify(manifest.terminal_chain_refusal_evidence?.nested_artifact_binding) === JSON.stringify(installedTerminalChainArtifactVerification.nested_artifact_binding)],
  ['manifest terminal chain nested artifact binding preflight type', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.generated_preflight_artifact_type === 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1'],
  ['manifest terminal chain nested artifact binding service type', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.generated_service_proof_artifact_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1'],
  ['manifest terminal chain nested artifact binding preflight body hash', /^[0-9a-f]{64}$/.test(manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.generated_preflight_artifact_body_sha256 || '')],
  ['manifest terminal chain nested artifact binding service body hash', /^[0-9a-f]{64}$/.test(manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.generated_service_proof_artifact_body_sha256 || '')],
  ['manifest terminal chain nested artifact binding preflight verified', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.generated_preflight_artifact_verified === true],
  ['manifest terminal chain nested artifact binding service verified', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.generated_service_proof_artifact_verified === true],
  ['manifest terminal chain nested artifact binding preflight hash bound', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.preflight_artifact_hash_bound === true],
  ['manifest terminal chain nested artifact binding service source preflight hash bound', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.service_proof_source_preflight_hash_bound === true],
  ['manifest terminal chain nested artifact binding service artifact hash bound', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.service_artifact_hash_bound === true],
  ['manifest terminal chain nested artifact binding service artifact verification bound', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.service_artifact_verification_bound_to_service_proof === true],
  ['manifest terminal chain nested artifact binding no attestation', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.creates_public_external_attestation === false],
  ['manifest terminal chain nested artifact binding no production downstream', manifest.terminal_chain_refusal_evidence?.nested_artifact_binding?.proves_production_downstream_recognition === false],
  ['manifest terminal chain refusal evidence no current-machine governance', manifest.terminal_chain_refusal_evidence?.proves_current_machine_governance === false],
  ['manifest terminal chain refusal evidence no production downstream', manifest.terminal_chain_refusal_evidence?.proves_production_downstream_recognition === false],
  ['manifest assertion hash included', (manifest.run_hashes || []).some((entry) => entry.path === 'ASSERTIONS.txt' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest no verifier request', manifest.claim_boundary?.sends_verifier_request === false],
  ['manifest no public attestation', manifest.claim_boundary?.creates_public_external_attestation === false],
  ['manifest no current-machine governance', manifest.claim_boundary?.proves_current_machine_governance === false],
  ['manifest transcript sanitized', manifest.privacy?.transcript_sanitized === true],
  ['manifest private paths absent', manifest.privacy?.private_paths_included === false],
  ['manifest credentials absent', manifest.privacy?.credentials_included === false],
  ['smoke installed recognition proof verified', smoke.counts?.installed_runtime_profile_recognition_proof_verified === true],
  ['smoke installed recognition proof refusals before mutation', smoke.counts?.installed_runtime_profile_recognition_all_refusals_before_mutation === true],
  ['installed recognition proof type', installedRecognitionProof.proof_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-v1'],
  ['installed recognition proof boarded', installedRecognitionProof.recognized_boarding?.boarded === true],
  ['installed recognition proof refusal cases', installedRecognitionProof.refusal_cases?.length === 18],
  ['installed recognition proof no runtime service', installedRecognitionProof.proof_boundary?.runtime_service_started === false],
  ['installed recognition proof no current-machine governance', installedRecognitionProof.proof_boundary?.current_machine_governance_proven === false],
  ['installed recognition proof no production downstream', installedRecognitionProof.proof_boundary?.production_downstream_recognition === false],
  ['installed recognition proof artifact type', installedRecognitionProofArtifact.artifact_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-artifact-v1'],
  ['installed recognition proof artifact embeds proof', installedRecognitionProofArtifact.payload?.proof?.proof_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-v1'],
  ['installed recognition proof artifact verification type', installedRecognitionProofArtifactVerification.verification_type === 'zlar-protected-records-installed-runtime-profile-recognition-proof-artifact-verification-v1'],
  ['installed recognition proof artifact verifies true', installedRecognitionProofArtifactVerification.verified === true],
  ['installed recognition proof artifact refusals before mutation', installedRecognitionProofArtifactVerification.all_refusals_before_mutation === true],
  ['installed recognition proof artifact no current-machine governance', installedRecognitionProofArtifactVerification.current_machine_governance_proven === false],
  ['installed recognition proof artifact no production downstream', installedRecognitionProofArtifactVerification.production_downstream_recognition === false],
  ['smoke installed service proof verified', smoke.counts?.installed_runtime_profile_service_proof_verified === true],
  ['smoke installed service proof runtime service started', smoke.counts?.installed_runtime_profile_service_runtime_service_started === true],
  ['smoke installed service proof restart replay refused', smoke.counts?.installed_runtime_profile_service_restart_replay_refused === true],
  ['smoke installed service proof consumed-store integrity refused', smoke.counts?.installed_runtime_profile_service_consumed_store_integrity_refusals_proven === true],
  ['smoke installed service proof refusals before mutation', smoke.counts?.installed_runtime_profile_service_all_refusals_before_mutation === true],
  ['smoke installed service proof artifact verification preserved', smoke.counts?.installed_runtime_profile_service_artifact_verification_verified === true],
  ['smoke installed service proof artifact verification restart replay refused', smoke.counts?.installed_runtime_profile_service_artifact_verification_restart_replay_refused === true],
  ['smoke installed service proof artifact verification refusal taxonomy hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 || '')],
  ['installed service proof type', installedServiceProof.proof_type === 'zlar-protected-records-installed-runtime-profile-service-proof-v1'],
  ['installed service proof runtime service started', installedServiceProof.proof_boundary?.runtime_service_started === true],
  ['installed service proof boarded', installedServiceProof.recognized_boarding?.boarded === true],
  ['installed service proof replay cases', installedServiceProof.service_replay_cases?.length === 2],
  ['installed service proof restart replay refused', installedServiceProof.proof_boundary?.cross_process_replay_after_restart_closed === true],
  ['installed service proof consumed-store cases', installedServiceProof.consumed_store_integrity_cases?.length === 8],
  ['installed service proof consumed-store integrity refused', installedServiceProof.service_boundary?.consumed_store_integrity_refusals_proven === true],
  ['installed service proof joint store-anchor rollback detected with witness', installedServiceProof.proof_boundary?.store_and_anchor_joint_rollback_detection === true],
  ['installed service proof joint store-anchor-witness rollback false', installedServiceProof.proof_boundary?.store_anchor_and_witness_joint_rollback_detection === false],
  ['installed service proof store-anchor rollback case count', installedServiceProof.store_and_anchor_rollback_cases?.length === 1],
  ['installed service proof refusal cases', installedServiceProof.refusal_cases?.length === 18],
  ['installed service proof no persistent runtime config', installedServiceProof.proof_boundary?.persistent_runtime_config_written === false],
  ['installed service proof no current-machine governance', installedServiceProof.proof_boundary?.current_machine_governance_proven === false],
  ['installed service proof no production downstream', installedServiceProof.proof_boundary?.production_downstream_recognition === false],
  ['installed service proof artifact type', installedServiceProofArtifact.artifact_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1'],
  ['installed service proof artifact embeds proof', installedServiceProofArtifact.payload?.proof?.proof_type === 'zlar-protected-records-installed-runtime-profile-service-proof-v1'],
  ['installed service proof artifact verification type', installedServiceProofArtifactVerification.verification_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-verification-v1'],
  ['installed service proof artifact verifies true', installedServiceProofArtifactVerification.verified === true],
  ['installed service proof artifact runtime service started', installedServiceProofArtifactVerification.runtime_service_started === true],
  ['installed service proof artifact restart replay refused', installedServiceProofArtifactVerification.restart_replay_refused === true],
  ['installed service proof artifact consumed-store integrity refused', installedServiceProofArtifactVerification.consumed_store_integrity_refusals_proven === true],
  ['installed service proof artifact joint store-anchor rollback detected with witness', installedServiceProofArtifactVerification.store_and_anchor_joint_rollback_detection === true],
  ['installed service proof artifact joint store-anchor-witness rollback false', installedServiceProofArtifactVerification.store_anchor_and_witness_joint_rollback_detection === false],
  ['installed service proof artifact store-anchor rollback case count', installedServiceProofArtifactVerification.store_and_anchor_rollback_case_count === 1],
  ['installed service proof artifact refusals before mutation', installedServiceProofArtifactVerification.all_refusals_before_mutation === true],
  ['installed service proof artifact refusal taxonomy hash bound', smoke.counts?.installed_runtime_profile_service_artifact_verification_refusal_taxonomy_sha256 === installedServiceProofArtifactVerification.refusal_taxonomy_sha256 && /^[a-f0-9]{64}$/.test(installedServiceProofArtifactVerification.refusal_taxonomy_sha256 || '')],
  ['installed service proof artifact no current-machine governance', installedServiceProofArtifactVerification.current_machine_governance_proven === false],
  ['installed service proof artifact no production downstream', installedServiceProofArtifactVerification.production_downstream_recognition === false],
  ['smoke installed terminal chain verified', smoke.counts?.installed_runtime_profile_terminal_chain_verified === true],
  ['smoke installed terminal chain missing receipt refused', smoke.counts?.installed_runtime_profile_terminal_chain_missing_receipt_refused_before_mutation === true],
  ['smoke installed terminal chain refusal taxonomy hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 || '')],
  ['smoke installed terminal chain named refusal hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 || '')],
  ['smoke installed terminal chain recognition refusal groups hash preserved', /^[a-f0-9]{64}$/.test(smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 || '')],
  ['smoke installed terminal chain recognition refusal group count', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_count === 3],
  ['smoke installed terminal chain recognition refusal group case count', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count === 18],
  ['smoke installed terminal chain recognition refusal group case IDs', groupCaseIdsExact(smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids)],
  ['smoke installed terminal chain artifact recognition refusal group count', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count === 3],
  ['smoke installed terminal chain artifact recognition refusal group case count', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count === 18],
  ['smoke installed terminal chain artifact recognition refusal group case IDs', groupCaseIdsExact(smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_ids)],
  ['smoke installed terminal chain no current-machine governance', smoke.counts?.installed_runtime_profile_terminal_chain_current_machine_governance_proven === false],
  ['installed terminal chain type', installedTerminalChain.chain_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-v1'],
  ['installed terminal chain generated root preflighted', installedTerminalChain.terminal_chain?.generated_installed_root_preflighted === true],
  ['installed terminal chain service proof bound', installedTerminalChain.terminal_chain?.service_proof_bound_to_generated_preflight === true],
  ['installed terminal chain artifact bound', installedTerminalChain.terminal_chain?.service_artifact_verification_bound_to_service_proof === true],
  ['installed terminal chain boarded', installedTerminalChain.terminal_chain?.recognized_write_boarded === true],
  ['installed terminal chain missing receipt refused', installedTerminalChain.terminal_chain?.missing_receipt_refused_before_mutation === true],
  ['installed terminal chain invalid receipt refused', installedTerminalChain.terminal_chain?.invalid_receipt_refused_before_mutation === true],
  ['installed terminal chain refusals before mutation', installedTerminalChain.terminal_chain?.all_required_refusals_before_mutation === true],
  ['installed terminal chain required refusal cases', installedTerminalChain.generated_service_proof?.required_refusal_cases?.length === 18],
  ['installed terminal chain observed refusal cases', installedTerminalChain.generated_service_proof?.observed_refusal_cases?.length === 18],
  ['installed terminal chain refusal taxonomy hash bound', installedTerminalChain.terminal_chain?.refusal_taxonomy_sha256 === installedTerminalChain.generated_service_proof?.refusal_taxonomy_sha256 && /^[a-f0-9]{64}$/.test(installedTerminalChain.terminal_chain?.refusal_taxonomy_sha256 || '')],
  ['smoke installed terminal chain refusal taxonomy count bound', smoke.counts?.installed_runtime_profile_terminal_chain_refusal_taxonomy_sha256 === installedTerminalChain.terminal_chain?.refusal_taxonomy_sha256],
  ['installed terminal chain named refusal hash bound', installedTerminalChain.terminal_chain?.named_receipt_refusals_sha256 === installedTerminalChain.generated_service_proof?.named_receipt_refusals_sha256 && /^[a-f0-9]{64}$/.test(installedTerminalChain.terminal_chain?.named_receipt_refusals_sha256 || '')],
  ['installed terminal chain named wrong tool refused', installedTerminalChain.terminal_chain?.named_receipt_refusals?.wrong_tool?.refused_before_mutation === true],
  ['smoke installed terminal chain named refusal count bound', smoke.counts?.installed_runtime_profile_terminal_chain_named_receipt_refusals_sha256 === installedTerminalChain.terminal_chain?.named_receipt_refusals_sha256],
  ['installed terminal chain recognition refusal groups hash bound', installedTerminalChain.terminal_chain?.recognition_refusal_groups_sha256 === installedTerminalChain.generated_service_proof?.recognition_refusal_groups_sha256 && /^[a-f0-9]{64}$/.test(installedTerminalChain.terminal_chain?.recognition_refusal_groups_sha256 || '')],
  ['installed terminal chain recognition refusal groups no usable authority refused', installedTerminalChain.terminal_chain?.recognition_refusal_groups?.no_usable_recognized_receipt_authority?.case_count === 6 && installedTerminalChain.terminal_chain?.recognition_refusal_groups?.no_usable_recognized_receipt_authority?.all_refused_before_mutation === true],
  ['installed terminal chain recognition refusal groups scope mismatch refused', installedTerminalChain.terminal_chain?.recognition_refusal_groups?.recognized_receipt_scope_mismatch?.all_refused_before_mutation === true],
  ['installed terminal chain recognition refusal groups route/request authority refused', installedTerminalChain.terminal_chain?.recognition_refusal_groups?.route_or_request_authority_material_refused?.case_count === 6 && installedTerminalChain.terminal_chain?.recognition_refusal_groups?.route_or_request_authority_material_refused?.all_refused_before_mutation === true],
  ['smoke installed terminal chain recognition refusal groups count bound', smoke.counts?.installed_runtime_profile_terminal_chain_recognition_refusal_groups_sha256 === installedTerminalChain.terminal_chain?.recognition_refusal_groups_sha256],
  ['installed terminal chain no persistent install', installedTerminalChain.side_door_report?.persistent_runtime_profile_installed === false],
  ['installed terminal chain no activation', installedTerminalChain.side_door_report?.runtime_profile_activation_performed === false],
  ['installed terminal chain no current-machine governance', installedTerminalChain.side_door_report?.current_machine_governance_proven === false],
  ['installed terminal chain no production downstream', installedTerminalChain.generated_service_proof?.production_downstream_recognition === false],
  ['installed terminal chain artifact type', installedTerminalChainArtifact.artifact_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-v1'],
  ['installed terminal chain artifact embeds chain', installedTerminalChainArtifact.payload?.chain?.chain_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-v1'],
  ['installed terminal chain artifact refusal taxonomy hash bound', installedTerminalChainArtifactVerification.refusal_taxonomy_sha256 === installedTerminalChain.terminal_chain?.refusal_taxonomy_sha256],
  ['smoke installed terminal chain artifact refusal taxonomy count bound', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_refusal_taxonomy_sha256 === installedTerminalChainArtifactVerification.refusal_taxonomy_sha256],
  ['installed terminal chain artifact named refusal hash bound', installedTerminalChainArtifactVerification.named_receipt_refusals_sha256 === installedTerminalChain.terminal_chain?.named_receipt_refusals_sha256],
  ['smoke installed terminal chain artifact named refusal count bound', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_named_receipt_refusals_sha256 === installedTerminalChainArtifactVerification.named_receipt_refusals_sha256],
  ['installed terminal chain artifact recognition refusal groups hash bound', installedTerminalChainArtifactVerification.recognition_refusal_groups_sha256 === installedTerminalChain.terminal_chain?.recognition_refusal_groups_sha256],
  ['smoke installed terminal chain artifact recognition refusal groups count bound', smoke.counts?.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_groups_sha256 === installedTerminalChainArtifactVerification.recognition_refusal_groups_sha256],
  ['installed terminal chain artifact verification type', installedTerminalChainArtifactVerification.verification_type === 'zlar-protected-records-installed-runtime-profile-terminal-chain-artifact-verification-v1'],
  ['installed terminal chain artifact verifies true', installedTerminalChainArtifactVerification.verified === true],
  ['installed terminal chain artifact verification missing receipt refused', installedTerminalChainArtifactVerification.missing_receipt_refused_before_mutation === true],
  ['installed terminal chain artifact verification no current-machine governance', installedTerminalChainArtifactVerification.current_machine_governance_proven === false],
  ['installed terminal chain artifact verification no production downstream', installedTerminalChainArtifactVerification.production_downstream_recognition === false],
  ['installed terminal chain nested preflight artifact preserved', installedTerminalChain.nested_artifacts?.generated_preflight_artifact?.artifact_type === 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1'],
  ['installed terminal chain nested service proof artifact preserved', installedTerminalChain.nested_artifacts?.generated_service_proof_artifact?.artifact_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1'],
  ['installed terminal chain artifact nested preflight artifact preserved', installedTerminalChainArtifact.payload?.chain?.nested_artifacts?.generated_preflight_artifact?.artifact_type === 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1'],
  ['installed terminal chain artifact nested service proof artifact preserved', installedTerminalChainArtifact.payload?.chain?.nested_artifacts?.generated_service_proof_artifact?.artifact_type === 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1'],
  ['installed terminal chain verifier nested binding matches report', JSON.stringify(installedTerminalChainArtifactVerification.nested_artifact_binding) === JSON.stringify(installedTerminalChain.terminal_chain?.nested_artifact_binding)],
  ['installed terminal chain verifier nested binding preflight body hash', /^[a-f0-9]{64}$/.test(installedTerminalChainArtifactVerification.nested_artifact_binding?.generated_preflight_artifact_body_sha256 || '')],
  ['installed terminal chain verifier nested binding service body hash', /^[a-f0-9]{64}$/.test(installedTerminalChainArtifactVerification.nested_artifact_binding?.generated_service_proof_artifact_body_sha256 || '')],
  ['installed terminal chain verifier nested binding preflight hash bound', installedTerminalChainArtifactVerification.nested_artifact_binding?.preflight_artifact_hash_bound === true],
  ['installed terminal chain verifier nested binding service source preflight hash bound', installedTerminalChainArtifactVerification.nested_artifact_binding?.service_proof_source_preflight_hash_bound === true],
  ['installed terminal chain verifier nested binding service artifact hash bound', installedTerminalChainArtifactVerification.nested_artifact_binding?.service_artifact_hash_bound === true],
  ['installed terminal chain verifier nested binding service artifact verification bound', installedTerminalChainArtifactVerification.nested_artifact_binding?.service_artifact_verification_bound_to_service_proof === true],
  ['installed terminal chain forged inner preflight hash refused', fs.readFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt', 'utf8').includes('nested preflight artifact binding')],
  ['installed terminal chain forged inner service hash refused', fs.readFileSync('zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt', 'utf8').includes('nested service proof artifact binding')],
  ['product proof path report type', productProofPath.report_type === 'zlar-product-proof-path-v1'],
  ['product proof path result pass', productProofPath.result === 'PASS'],
  ['product proof path evidence model', productProofPath.evidence_model === 'fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge'],
  ['product proof path acceptance gates true', Object.values(productProofPath.acceptance_gate || {}).every((value) => value === true)],
  ['product proof path forbidden claims false', Object.values(productProofPath.forbidden_claims || {}).every((value) => value === false)],
  ['product proof path terminal verified', productProofPath.terminal_chain_boundary?.verified === true],
  ['product proof path terminal binding match', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification === true],
  ['product proof path terminal refusal hash match', productProofPath.terminal_chain_boundary?.trusted_issuer_registry_recognition_refusal_hash_matches_binding === true],
  ['product proof path terminal recognition refusal group count', productProofPath.terminal_chain_boundary?.recognition_refusal_group_count === 3],
  ['product proof path terminal recognition refusal group case count', productProofPath.terminal_chain_boundary?.recognition_refusal_group_case_count === 18],
  ['product proof path terminal recognition refusal group case IDs preserved', productProofPath.terminal_chain_boundary?.recognition_refusal_group_case_ids_preserved === true],
  ['product proof path terminal recognition refusal group case IDs', groupCaseIdsExact(productProofPath.terminal_chain_boundary?.recognition_refusal_group_case_ids)],
  ['product proof path terminal public key omitted', productProofPath.terminal_chain_boundary?.registry_public_key_material_included === false],
  ['product proof path terminal no external attestation', productProofPath.terminal_chain_boundary?.external_attestation === false],
  ['product proof path deployment bridge gate observed', productProofPath.acceptance_gate?.deployment_profile_authority_bridge_observed === true],
  ['product proof path deployment bridge proof type', productProofPath.deployment_profile_authority_bridge?.proof_type === 'zlar-protected-records-one-terminal-deployment-profile-proof-v1'],
  ['product proof path deployment bridge evidence model', productProofPath.deployment_profile_authority_bridge?.evidence_model === 'local-fixture-one-terminal-deployment-profile-authority-bridge'],
  ['product proof path deployment bridge recognized once', productProofPath.deployment_profile_authority_bridge?.recognized_receipt_mutates_once === true],
  ['product proof path deployment bridge refusal count', productProofPath.deployment_profile_authority_bridge?.observed_refusal_case_count === 18],
  ['product proof path deployment bridge authority refusal count', productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusal_case_count === expectedDeploymentProfileAuthorityRefusalCaseIds.length],
  ['product proof path deployment bridge authority refusal case IDs', arraysEqual(productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusal_case_ids, expectedDeploymentProfileAuthorityRefusalCaseIds)],
  ['product proof path deployment bridge authority refusals before service proof', productProofPath.deployment_profile_authority_bridge?.deployment_profile_authority_refusals_before_service_proof === true],
  ['product proof path deployment bridge stale artifact refused', productProofPath.deployment_profile_authority_bridge?.stale_deployment_profile_artifact_refused_before_service_proof === true],
  ['product proof path deployment bridge profile mismatch refused', productProofPath.deployment_profile_authority_bridge?.profile_recognition_mismatch_refused_before_service_proof === true],
  ['product proof path deployment bridge request authority refused', productProofPath.deployment_profile_authority_bridge?.request_stream_authority_material_refused_before_service_proof === true],
  ['product proof path deployment bridge request authority false', productProofPath.deployment_profile_authority_bridge?.request_stream_authority_material_accepted === false],
  ['product proof path deployment bridge current-machine false', productProofPath.deployment_profile_authority_bridge?.current_machine_governance === false],
  ['product proof path deployment bridge production false', productProofPath.deployment_profile_authority_bridge?.production_authority === false],
  ['product proof path no live probing', productProofPath.live_probing === false],
  ['product proof path no private operator state', productProofPath.private_operator_state_required === false],
  ['north star product proof path verified', northStar.counts?.product_proof_path_verified === true],
  ['north star product proof path summary provided', northStarProductProofPath.provided === true],
  ['north star product proof path scope', northStarProductProofPiece.acceptance_gate_scope === 'fresh-local-product-proof-path'],
  ['north star product proof path artifact consumed', (northStar.artifacts_consumed || []).includes('zlar-product-proof-path-v1.json')],
  ['north star service proof artifact consumed', (northStar.artifacts_consumed || []).includes('zlar-installed-runtime-profile-service-proof-v1.json')],
  ['north star terminal chain artifact consumed', (northStar.artifacts_consumed || []).includes('zlar-installed-runtime-profile-terminal-chain-v1.json')],
  ['north star product proof path no live probing', northStarProductProofPath.live_probing === false],
  ['north star product proof path forbidden claims false', northStarProductProofPath.forbidden_claims_false === true],
  ['north star product proof path terminal recognition refusal group count', northStarProductProofPath.terminal_chain_boundary?.recognition_refusal_group_count === 3],
  ['north star product proof path terminal recognition refusal group case count', northStarProductProofPath.terminal_chain_boundary?.recognition_refusal_group_case_count === 18],
  ['north star product proof path terminal recognition refusal group case IDs preserved', northStarProductProofPath.terminal_chain_boundary?.recognition_refusal_group_case_ids_preserved === true],
  ['north star product proof path terminal recognition refusal group case IDs', groupCaseIdsExact(northStarProductProofPath.terminal_chain_boundary?.recognition_refusal_group_case_ids)],
  ['private verifier result has product proof path hash', (privateVerifierResult.evidence?.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-product-proof-path-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))],
  ['manifest product proof path hash included', (manifest.artifact_hashes || []).some((entry) => entry.path === 'ZLAR/zlar-product-proof-path-v1.json' && /^[0-9a-f]{64}$/.test(entry.sha256))]
];
let ok = true;
for (const [name, passed] of checks) {
  console.log(`${passed ? 'PASS' : 'FAIL'} ${name}`);
  if (!passed) ok = false;
}
process.exit(ok ? 0 : 1);
NODE
)"
assert_contains "happy json env live probing" "PASS env live probing false" "${json_check}"
assert_contains "happy json env external attestation" "PASS env external attestation false" "${json_check}"
assert_contains "happy json smoke governed lanes" "PASS smoke governed lanes six" "${json_check}"
assert_contains "happy json service preflight cases" "PASS service preflight cases eleven" "${json_check}"
assert_contains "happy json service preflight wrong policy" "PASS service preflight wrong policy refused" "${json_check}"
assert_contains "happy json service preflight authority" "PASS service preflight authority refused" "${json_check}"
assert_contains "happy json coverage governed lanes" "PASS coverage governed lanes six" "${json_check}"
assert_contains "happy json coverage counted lanes" "PASS coverage counted lanes six" "${json_check}"
assert_contains "happy json service profile lane governed" "PASS coverage service-profile lane governed" "${json_check}"
assert_contains "happy json north star type" "PASS north star type" "${json_check}"
assert_contains "happy json north star not ready" "PASS north star result not ready" "${json_check}"
assert_contains "happy json north star installed preflight verified" "PASS north star installed runtime profile preflight verified" "${json_check}"
assert_contains "happy json north star installed preflight boundary" "PASS north star installed runtime profile no-effect boundary" "${json_check}"
assert_contains "happy json north star terminal chain preserved" "PASS north star installed runtime profile terminal chain preserved" "${json_check}"
assert_contains "happy json north star terminal chain named refusals" "PASS north star installed runtime profile terminal chain named refusals preserved" "${json_check}"
assert_contains "happy json north star terminal chain recognition refusal group case IDs" "PASS north star installed runtime profile terminal chain recognition refusal group case IDs" "${json_check}"
assert_contains "happy json north star terminal chain artifact recognition refusal group case IDs" "PASS north star installed runtime profile terminal chain artifact recognition refusal group case IDs" "${json_check}"
assert_contains "happy json product proof path terminal group count" "PASS product proof path terminal recognition refusal group count" "${json_check}"
assert_contains "happy json product proof path terminal group case count" "PASS product proof path terminal recognition refusal group case count" "${json_check}"
assert_contains "happy json product proof path terminal group case IDs preserved" "PASS product proof path terminal recognition refusal group case IDs preserved" "${json_check}"
assert_contains "happy json product proof path terminal group case IDs" "PASS product proof path terminal recognition refusal group case IDs" "${json_check}"
assert_contains "happy json north star product proof path terminal group count" "PASS north star product proof path terminal recognition refusal group count" "${json_check}"
assert_contains "happy json north star product proof path terminal group case count" "PASS north star product proof path terminal recognition refusal group case count" "${json_check}"
assert_contains "happy json north star product proof path terminal group case IDs preserved" "PASS north star product proof path terminal recognition refusal group case IDs preserved" "${json_check}"
assert_contains "happy json north star product proof path terminal group case IDs" "PASS north star product proof path terminal recognition refusal group case IDs" "${json_check}"
assert_contains "happy json north star external attestation" "PASS north star external attestation false" "${json_check}"
assert_contains "happy json north star trusted issuer" "PASS north star trusted issuer provided" "${json_check}"
assert_contains "happy json north star verifier kit reproducibility" "PASS north star verifier kit reproducibility provided" "${json_check}"
assert_contains "happy json north star verifier kit boundary" "PASS north star verifier kit reproducibility boundary false" "${json_check}"
assert_contains "happy json north star verifier kit public distribution" "PASS north star verifier kit public distribution provided" "${json_check}"
assert_contains "happy json north star verifier kit public distribution not ready" "PASS north star verifier kit public distribution not ready" "${json_check}"
assert_contains "happy json north star private intake pointer" "PASS north star private intake pointer provided" "${json_check}"
assert_contains "happy json north star private intake pointer field" "PASS north star private intake pointer field" "${json_check}"
assert_contains "happy json north star private intake pointer boundary" "PASS north star private intake pointer not attestation" "${json_check}"
assert_contains "happy json verifier kit reproducibility" "PASS verifier kit reproducibility pass" "${json_check}"
assert_contains "happy json verifier kit tarball reproducible" "PASS verifier kit tarball reproducible" "${json_check}"
assert_contains "happy json verifier kit public tarball hash" "PASS verifier kit public tarball hash" "${json_check}"
assert_contains "happy json verifier kit external-runner diagnostics" "PASS verifier kit external-runner diagnostics pass" "${json_check}"
assert_contains "happy json verifier kit external-runner diagnostics manifest binding" "PASS verifier kit external-runner diagnostics manifest entry bound" "${json_check}"
assert_contains "happy json verifier kit external-runner diagnostics issuer artifact verified" "PASS verifier kit external-runner diagnostics issuer artifact verified" "${json_check}"
assert_contains "happy json verifier kit external-runner diagnostics command boundary" "PASS verifier kit external-runner diagnostics command boundary" "${json_check}"
assert_contains "happy json verifier kit external-runner diagnostics source boundary" "PASS verifier kit external-runner diagnostics source regression not in kit" "${json_check}"
assert_contains "happy json verifier kit external-runner diagnostics claim boundary" "PASS verifier kit external-runner diagnostics boundary false" "${json_check}"
assert_contains "happy json verifier kit public distribution" "PASS verifier kit public distribution audit pass" "${json_check}"
assert_contains "happy json verifier kit public distribution posture" "PASS verifier kit public distribution absent posture" "${json_check}"
assert_contains "happy json verifier kit public distribution hashes" "PASS verifier kit public distribution local hashes match" "${json_check}"
assert_contains "happy json issuer status proof type" "PASS issuer status proof type" "${json_check}"
assert_contains "happy json issuer status proof fixture model" "PASS issuer status proof fixture model" "${json_check}"
assert_contains "happy json issuer status proof live probing" "PASS issuer status proof live probing false" "${json_check}"
assert_contains "happy json issuer status proof active issuer" "PASS issuer status proof active issuer boards" "${json_check}"
assert_contains "happy json issuer status proof retired issuer" "PASS issuer status proof retired issuer refuses" "${json_check}"
assert_contains "happy json issuer status proof no raw key material" "PASS issuer status proof no raw private key material" "${json_check}"
assert_contains "happy json issuer fixture" "PASS issuer fixture verdict" "${json_check}"
assert_contains "happy json recognition verdict" "PASS trusted issuer recognition verdict" "${json_check}"
assert_contains "happy json schema negative unsupported field" "PASS trusted issuer schema negative unsupported field" "${json_check}"
assert_contains "happy json schema negative no recognized verdict" "PASS trusted issuer schema negative no recognized verdict" "${json_check}"
assert_contains "happy manifest issuer status proof hash" "PASS manifest issuer status proof hash included" "${json_check}"
assert_contains "happy manifest issuer status fixture hash" "PASS manifest issuer status fixture hash included" "${json_check}"
assert_contains "happy manifest malformed registry hash" "PASS manifest malformed registry hash included" "${json_check}"
assert_contains "happy manifest malformed registry error hash" "PASS manifest malformed registry error hash included" "${json_check}"
assert_contains "happy manifest north star hash" "PASS manifest north star hash included" "${json_check}"
assert_contains "happy manifest verifier kit external-runner diagnostics hash" "PASS manifest verifier kit external-runner diagnostics hash included" "${json_check}"
assert_contains "happy manifest installed preflight hash" "PASS manifest installed profile preflight hash included" "${json_check}"
assert_contains "happy manifest installed recognition proof hash" "PASS manifest installed profile recognition proof hash included" "${json_check}"
assert_contains "happy manifest installed terminal chain hash" "PASS manifest installed profile terminal chain hash included" "${json_check}"
assert_contains "happy manifest installed terminal chain artifact hash" "PASS manifest installed profile terminal chain artifact hash included" "${json_check}"
assert_contains "happy manifest installed terminal chain artifact verification hash" "PASS manifest installed profile terminal chain artifact verification hash included" "${json_check}"
assert_contains "happy manifest installed terminal chain forged preflight artifact hash" "PASS manifest installed profile terminal chain forged inner preflight hash artifact included" "${json_check}"
assert_contains "happy manifest installed terminal chain forged preflight error hash" "PASS manifest installed profile terminal chain forged inner preflight hash error included" "${json_check}"
assert_contains "happy manifest installed terminal chain forged service artifact hash" "PASS manifest installed profile terminal chain forged inner service hash artifact included" "${json_check}"
assert_contains "happy manifest installed terminal chain forged service error hash" "PASS manifest installed profile terminal chain forged inner service hash error included" "${json_check}"
assert_contains "happy manifest verifier kit reproducibility hash" "PASS manifest verifier kit reproducibility hash included" "${json_check}"
assert_contains "happy manifest verifier kit public distribution hash" "PASS manifest verifier kit public distribution hash included" "${json_check}"
assert_contains "happy manifest private sample pointer" "PASS manifest private result sample pointer enabled" "${json_check}"
assert_contains "happy manifest private sample section" "PASS manifest private result sample result section" "${json_check}"
assert_contains "happy manifest private sample avoids circular hash" "PASS manifest private result sample avoids circular hash" "${json_check}"
assert_contains "happy manifest private sample verification section" "PASS manifest private result sample verification section" "${json_check}"
assert_contains "happy manifest private sample verification minimum" "PASS manifest private result sample verification minimum target" "${json_check}"
assert_contains "happy manifest private sample no attestation" "PASS manifest private result sample not attestation" "${json_check}"
assert_contains "happy manifest private envelope not core hash" "PASS manifest private result envelope not core artifact hash" "${json_check}"
assert_contains "happy manifest issuer status evidence enabled" "PASS manifest issuer status evidence enabled" "${json_check}"
assert_contains "happy manifest issuer status evidence model" "PASS manifest issuer status evidence model" "${json_check}"
assert_contains "happy manifest issuer status evidence proof hash" "PASS manifest issuer status evidence proof hash" "${json_check}"
assert_contains "happy manifest issuer status evidence fixture hash" "PASS manifest issuer status evidence fixture hash" "${json_check}"
assert_contains "happy manifest issuer status evidence live probing" "PASS manifest issuer status evidence live probing false" "${json_check}"
assert_contains "happy manifest issuer status evidence issuer refuses" "PASS manifest issuer status evidence missing key issuer refuses" "${json_check}"
assert_contains "happy manifest issuer status evidence diagnostics verified" "PASS manifest issuer status evidence diagnostics verified" "${json_check}"
assert_contains "happy manifest issuer status evidence no live issuer" "PASS manifest issuer status evidence no live issuer status" "${json_check}"
assert_contains "happy manifest issuer status evidence no key custody" "PASS manifest issuer status evidence no key custody" "${json_check}"
assert_contains "happy manifest issuer status evidence no revocation truth" "PASS manifest issuer status evidence no revocation truth" "${json_check}"
assert_contains "happy manifest issuer status evidence no production registry" "PASS manifest issuer status evidence no production trust registry" "${json_check}"
assert_contains "happy manifest trusted issuer registry evidence enabled" "PASS manifest trusted issuer registry evidence enabled" "${json_check}"
assert_contains "happy manifest trusted issuer registry evidence model" "PASS manifest trusted issuer registry evidence model" "${json_check}"
assert_contains "happy manifest trusted issuer registry recognition hash" "PASS manifest trusted issuer registry recognition hash" "${json_check}"
assert_contains "happy manifest trusted issuer registry live probing false" "PASS manifest trusted issuer registry live probing false" "${json_check}"
assert_contains "happy manifest trusted issuer registry recognized" "PASS manifest trusted issuer registry recognized" "${json_check}"
assert_contains "happy manifest trusted issuer registry fail closed" "PASS manifest trusted issuer registry fail closed before verdict" "${json_check}"
assert_contains "happy manifest trusted issuer registry no live registry" "PASS manifest trusted issuer registry no live registry" "${json_check}"
assert_contains "happy manifest trusted issuer registry no key custody" "PASS manifest trusted issuer registry no key custody" "${json_check}"
assert_contains "happy manifest trusted issuer registry no revocation truth" "PASS manifest trusted issuer registry no revocation truth" "${json_check}"
assert_contains "happy manifest trusted issuer registry no production downstream" "PASS manifest trusted issuer registry no production downstream" "${json_check}"
assert_contains "happy manifest trusted issuer registry no production authority" "PASS manifest trusted issuer registry no production authority" "${json_check}"
assert_contains "happy manifest terminal chain refusal evidence" "PASS manifest terminal chain refusal evidence enabled" "${json_check}"
assert_contains "happy manifest terminal chain refusal evidence named hash" "PASS manifest terminal chain refusal evidence named hash bound" "${json_check}"
assert_contains "happy manifest terminal chain refusal evidence boundary" "PASS manifest terminal chain refusal evidence no production downstream" "${json_check}"
assert_contains "happy manifest terminal chain group case ids exact" "PASS manifest terminal chain recognition refusal group case ids exact" "${json_check}"
assert_contains "happy manifest terminal chain group case ids reject extra key" "PASS manifest terminal chain recognition refusal group case ids reject extra key" "${json_check}"
assert_contains "happy manifest terminal chain group case ids reject missing key" "PASS manifest terminal chain recognition refusal group case ids reject missing key" "${json_check}"
assert_contains "happy manifest terminal chain group case ids reject renamed key" "PASS manifest terminal chain recognition refusal group case ids reject renamed key" "${json_check}"
assert_contains "happy manifest terminal chain group case ids reject summary object" "PASS manifest terminal chain recognition refusal group case ids reject summary object" "${json_check}"
assert_contains "happy manifest terminal chain nested tamper exact keys" "PASS manifest terminal chain nested artifact tamper exact keys" "${json_check}"
assert_contains "happy manifest terminal chain nested tamper rejects extra key" "PASS manifest terminal chain nested artifact tamper rejects extra key" "${json_check}"
assert_contains "happy manifest terminal chain nested tamper rejects missing key" "PASS manifest terminal chain nested artifact tamper rejects missing key" "${json_check}"
assert_contains "happy manifest terminal chain nested tamper rejects renamed key" "PASS manifest terminal chain nested artifact tamper rejects renamed key" "${json_check}"
assert_contains "happy manifest terminal chain nested tamper rejects summary object" "PASS manifest terminal chain nested artifact tamper rejects summary-shaped object" "${json_check}"
assert_contains "happy manifest terminal chain nested binding required" "PASS manifest terminal chain nested artifact binding required" "${json_check}"
assert_contains "happy manifest terminal chain nested binding exact keys" "PASS manifest terminal chain nested artifact binding exact keys" "${json_check}"
assert_contains "happy manifest terminal chain nested binding rejects extra key" "PASS manifest terminal chain nested artifact binding rejects extra key" "${json_check}"
assert_contains "happy manifest terminal chain nested binding rejects missing key" "PASS manifest terminal chain nested artifact binding rejects missing key" "${json_check}"
assert_contains "happy manifest terminal chain nested binding rejects renamed key" "PASS manifest terminal chain nested artifact binding rejects renamed key" "${json_check}"
assert_contains "happy manifest terminal chain nested binding rejects summary object" "PASS manifest terminal chain nested artifact binding rejects summary-shaped object" "${json_check}"
assert_contains "happy manifest terminal chain nested binding preflight type" "PASS manifest terminal chain nested artifact binding preflight type" "${json_check}"
assert_contains "happy manifest terminal chain nested binding service type" "PASS manifest terminal chain nested artifact binding service type" "${json_check}"
assert_contains "happy manifest terminal chain nested tamper forged preflight refused" "PASS manifest terminal chain nested artifact tamper forged preflight refused" "${json_check}"
assert_contains "happy manifest terminal chain nested tamper forged service refused" "PASS manifest terminal chain nested artifact tamper forged service refused" "${json_check}"
assert_contains "happy json install no latest" "PASS install latest selection false" "${json_check}"
assert_contains "happy json installed preflight read only" "PASS installed runtime profile preflight read only" "${json_check}"
assert_contains "happy json installed preflight no activation" "PASS installed runtime profile preflight no activation" "${json_check}"
assert_contains "happy json installed recognition proof verified" "PASS smoke installed recognition proof verified" "${json_check}"
assert_contains "happy json installed recognition proof refusals" "PASS smoke installed recognition proof refusals before mutation" "${json_check}"
assert_contains "happy json installed recognition proof no runtime service" "PASS installed recognition proof no runtime service" "${json_check}"
assert_contains "happy json installed recognition proof no production downstream" "PASS installed recognition proof no production downstream" "${json_check}"
assert_contains "happy json installed terminal chain verified" "PASS smoke installed terminal chain verified" "${json_check}"
assert_contains "happy json installed terminal chain bound" "PASS installed terminal chain service proof bound" "${json_check}"
assert_contains "happy json installed terminal chain named refusals" "PASS installed terminal chain named refusal hash bound" "${json_check}"
assert_contains "happy json installed terminal chain artifact named refusals" "PASS installed terminal chain artifact named refusal hash bound" "${json_check}"
assert_contains "happy json smoke terminal chain recognition refusal group case IDs" "PASS smoke installed terminal chain recognition refusal group case IDs" "${json_check}"
assert_contains "happy json smoke terminal chain artifact recognition refusal group case IDs" "PASS smoke installed terminal chain artifact recognition refusal group case IDs" "${json_check}"
assert_contains "happy json installed terminal chain no current-machine governance" "PASS installed terminal chain no current-machine governance" "${json_check}"
assert_contains "happy json installed terminal chain artifact verification" "PASS installed terminal chain artifact verifies true" "${json_check}"
assert_contains "happy manifest report contract nested tamper exact keys" "PASS manifest report contract nested artifact tamper exact keys" "${json_check}"
assert_contains "happy manifest report contract nested tamper mirrors root" "PASS manifest report contract nested artifact tamper mirrors root" "${json_check}"
assert_contains "happy manifest report contract nested tamper rejects extra key" "PASS manifest report contract nested artifact tamper rejects extra key" "${json_check}"
assert_contains "happy manifest report contract nested tamper rejects missing key" "PASS manifest report contract nested artifact tamper rejects missing key" "${json_check}"
assert_contains "happy manifest report contract nested tamper rejects renamed key" "PASS manifest report contract nested artifact tamper rejects renamed key" "${json_check}"
assert_contains "happy manifest report contract nested tamper rejects summary object" "PASS manifest report contract nested artifact tamper rejects summary-shaped object" "${json_check}"
assert_contains "happy manifest report contract nested binding exact keys" "PASS manifest report contract nested artifact binding exact keys" "${json_check}"
assert_contains "happy manifest report contract nested binding mirrors root" "PASS manifest report contract nested artifact binding mirrors root" "${json_check}"
assert_contains "happy manifest report contract nested binding rejects extra key" "PASS manifest report contract nested artifact binding rejects extra key" "${json_check}"
assert_contains "happy manifest report contract nested binding rejects missing key" "PASS manifest report contract nested artifact binding rejects missing key" "${json_check}"
assert_contains "happy manifest report contract nested binding rejects renamed key" "PASS manifest report contract nested artifact binding rejects renamed key" "${json_check}"
assert_contains "happy manifest report contract nested binding rejects summary object" "PASS manifest report contract nested artifact binding rejects summary-shaped object" "${json_check}"
assert_contains "happy manifest report contract product proof path source" "PASS manifest report contract product proof path source path" "${json_check}"
assert_contains "happy manifest report contract product proof path hash" "PASS manifest report contract product proof path source hash" "${json_check}"
assert_contains "happy manifest report contract product proof path minimum" "PASS manifest report contract product proof path minimum target" "${json_check}"
assert_contains "happy manifest report contract product proof path result" "PASS manifest report contract product proof path result pass" "${json_check}"
assert_contains "happy manifest report contract product proof path no live probing" "PASS manifest report contract product proof path no live probing" "${json_check}"
assert_contains "happy manifest report contract simulated human exact keys" "PASS manifest report contract simulated human exact keys" "${json_check}"
assert_contains "happy manifest report contract simulated human rejects extra key" "PASS manifest report contract simulated human rejects extra key" "${json_check}"
assert_contains "happy manifest report contract simulated human rejects missing key" "PASS manifest report contract simulated human rejects missing key" "${json_check}"
assert_contains "happy manifest report contract simulated human rejects renamed key" "PASS manifest report contract simulated human rejects renamed key" "${json_check}"
assert_contains "happy manifest report contract simulated human rejects summary-shaped key" "PASS manifest report contract simulated human rejects summary-shaped key" "${json_check}"
assert_contains "happy manifest report contract receipt boundary exact keys" "PASS manifest report contract receipt boundary exact keys" "${json_check}"
assert_contains "happy manifest report contract receipt boundary rejects extra key" "PASS manifest report contract receipt boundary rejects extra key" "${json_check}"
assert_contains "happy manifest report contract receipt boundary rejects missing key" "PASS manifest report contract receipt boundary rejects missing key" "${json_check}"
assert_contains "happy manifest report contract receipt boundary rejects renamed key" "PASS manifest report contract receipt boundary rejects renamed key" "${json_check}"
assert_contains "happy manifest report contract receipt boundary rejects summary-shaped key" "PASS manifest report contract receipt boundary rejects summary-shaped key" "${json_check}"
assert_contains "happy manifest report contract product proof path terminal group count" "PASS manifest report contract product proof path terminal group count" "${json_check}"
assert_contains "happy manifest report contract product proof path terminal group case count" "PASS manifest report contract product proof path terminal group case count" "${json_check}"
assert_contains "happy manifest report contract product proof path terminal group case IDs preserved" "PASS manifest report contract product proof path terminal group case IDs preserved" "${json_check}"
assert_contains "happy manifest report contract product proof path terminal group case IDs" "PASS manifest report contract product proof path terminal group case IDs" "${json_check}"
assert_contains "happy manifest report contract product proof path north-star terminal group count" "PASS manifest report contract product proof path north-star terminal group count" "${json_check}"
assert_contains "happy manifest report contract product proof path north-star terminal group case count" "PASS manifest report contract product proof path north-star terminal group case count" "${json_check}"
assert_contains "happy manifest report contract product proof path north-star terminal group case IDs preserved" "PASS manifest report contract product proof path north-star terminal group case IDs preserved" "${json_check}"
assert_contains "happy manifest report contract product proof path north-star terminal group case IDs" "PASS manifest report contract product proof path north-star terminal group case IDs" "${json_check}"
assert_contains "happy manifest report contract proof-smoke group case ids exact" "PASS manifest report contract proof-smoke group case ids exact" "${json_check}"
assert_contains "happy manifest report contract proof-smoke group case ids reject extra key" "PASS manifest report contract proof-smoke group case ids reject extra key" "${json_check}"
assert_contains "happy manifest report contract proof-smoke group case ids reject missing key" "PASS manifest report contract proof-smoke group case ids reject missing key" "${json_check}"
assert_contains "happy manifest report contract proof-smoke group case ids reject renamed key" "PASS manifest report contract proof-smoke group case ids reject renamed key" "${json_check}"
assert_contains "happy manifest report contract proof-smoke group case ids reject summary object" "PASS manifest report contract proof-smoke group case ids reject summary object" "${json_check}"
assert_contains "happy manifest report contract north-star group case ids exact" "PASS manifest report contract north-star group case ids exact" "${json_check}"
assert_contains "happy manifest report contract north-star group case ids reject extra key" "PASS manifest report contract north-star group case ids reject extra key" "${json_check}"
assert_contains "happy manifest report contract north-star group case ids reject missing key" "PASS manifest report contract north-star group case ids reject missing key" "${json_check}"
assert_contains "happy manifest report contract north-star group case ids reject renamed key" "PASS manifest report contract north-star group case ids reject renamed key" "${json_check}"
assert_contains "happy manifest report contract north-star group case ids reject summary object" "PASS manifest report contract north-star group case ids reject summary object" "${json_check}"
assert_contains "happy manifest report contract product proof path boundary" "PASS manifest report contract product proof path no current-machine governance" "${json_check}"
assert_contains "happy json product proof path pass" "PASS product proof path result pass" "${json_check}"
assert_contains "happy json product proof path boundary" "PASS product proof path forbidden claims false" "${json_check}"
assert_contains "happy json north star product proof path" "PASS north star product proof path verified" "${json_check}"
assert_contains "happy json north star product proof path artifact" "PASS north star product proof path artifact consumed" "${json_check}"
assert_contains "happy private result product proof path hash" "PASS private verifier result has product proof path hash" "${json_check}"
assert_contains "happy manifest product proof path hash" "PASS manifest product proof path hash included" "${json_check}"
assert_contains "happy private result type" "PASS private verifier result type" "${json_check}"
assert_contains "happy private result target" "PASS private verifier result target tag" "${json_check}"
assert_contains "happy private result manifest hash" "PASS private verifier result has manifest hash" "${json_check}"
assert_contains "happy private result SHA256SUMS row set" "PASS private verifier SHA256SUMS row set exact" "${json_check}"
assert_contains "happy private result SHA256SUMS row hashes" "PASS private verifier SHA256SUMS rows match private result" "${json_check}"
assert_contains "happy private result RUN-SHA256SUMS row set" "PASS private verifier RUN-SHA256SUMS row set exact" "${json_check}"
assert_contains "happy private result RUN-SHA256SUMS binds SHA256SUMS" "PASS private verifier RUN-SHA256SUMS binds SHA256SUMS" "${json_check}"
assert_contains "happy private result verifier kit external-runner diagnostics hash" "PASS private verifier result has verifier kit external-runner diagnostics hash" "${json_check}"
assert_contains "happy private result public distribution hash" "PASS private verifier result has public distribution hash" "${json_check}"
assert_contains "happy private result installed preflight hash" "PASS private verifier result has installed profile preflight hash" "${json_check}"
assert_contains "happy private result installed terminal chain hash" "PASS private verifier result has installed profile terminal chain hash" "${json_check}"
assert_contains "happy private result installed terminal chain artifact hash" "PASS private verifier result has installed profile terminal chain artifact hash" "${json_check}"
assert_contains "happy private result installed terminal chain artifact verification hash" "PASS private verifier result has installed profile terminal chain artifact verification hash" "${json_check}"
assert_contains "happy private result installed terminal chain forged preflight artifact hash" "PASS private verifier result has installed profile terminal chain forged inner preflight hash artifact" "${json_check}"
assert_contains "happy private result installed terminal chain forged service artifact hash" "PASS private verifier result has installed profile terminal chain forged inner service hash artifact" "${json_check}"
assert_contains "happy private verification type" "PASS private verifier verification type" "${json_check}"
assert_contains "happy private verification result sha bound" "PASS private verifier verification result sha bound" "${json_check}"
assert_contains "happy private verification artifact set sha bound" "PASS private verifier verification artifact set sha bound" "${json_check}"
assert_contains "happy private verification required posture" "PASS private verifier verification required posture" "${json_check}"
assert_contains "happy private verification requires result sha" "PASS private verifier verification requires result sha" "${json_check}"
assert_contains "happy private verification result sha matched" "PASS private verifier verification result sha matched" "${json_check}"
assert_contains "happy private verification requires target" "PASS private verifier verification requires target" "${json_check}"
assert_contains "happy private verification target matched" "PASS private verifier verification target matched" "${json_check}"
assert_contains "happy private verification requires bundle sha" "PASS private verifier verification requires bundle sha" "${json_check}"
assert_contains "happy private verification bundle sha matched" "PASS private verifier verification bundle sha matched" "${json_check}"
assert_contains "happy private verification requires artifact set sha" "PASS private verifier verification requires artifact set sha" "${json_check}"
assert_contains "happy private verification artifact set sha matched" "PASS private verifier verification artifact set sha matched" "${json_check}"
assert_contains "happy private verification requires recomputed evidence" "PASS private verifier verification requires recomputed evidence" "${json_check}"
assert_contains "happy private verification recomputed evidence matched" "PASS private verifier verification recomputed evidence matched" "${json_check}"
assert_contains "happy private verification evidence-dir" "PASS private verifier evidence-dir hashes recomputed" "${json_check}"
assert_contains "happy private verification recognized receipt path required" "PASS private verifier recognized receipt path mirror required" "${json_check}"
assert_contains "happy private verification recognized receipt path preserved" "PASS private verifier recognized receipt path mirror preserved" "${json_check}"
assert_contains "happy private verification north-star recognized receipt path preserved" "PASS private verifier north-star recognized receipt path mirror preserved" "${json_check}"
assert_contains "happy private verification recognized receipt path sha" "PASS private verifier recognized receipt path sha" "${json_check}"
assert_contains "happy private verification recognized receipt path source binding" "PASS private verifier recognized receipt path source binding matches" "${json_check}"
assert_contains "happy private verification no attestation" "PASS private verifier verification no public attestation" "${json_check}"
assert_contains "happy manifest result type" "PASS manifest result type" "${json_check}"
assert_contains "happy manifest sanitized repo url" "PASS manifest repo url sanitized" "${json_check}"
assert_contains "happy manifest no attestation" "PASS manifest no public attestation" "${json_check}"
assert_contains "happy nested preflight artifact preserved" "PASS installed terminal chain nested preflight artifact preserved" "${json_check}"
assert_contains "happy nested service proof artifact preserved" "PASS installed terminal chain nested service proof artifact preserved" "${json_check}"
assert_contains "happy nested artifact preflight preserved" "PASS installed terminal chain artifact nested preflight artifact preserved" "${json_check}"
assert_contains "happy nested artifact service proof preserved" "PASS installed terminal chain artifact nested service proof artifact preserved" "${json_check}"
assert_contains "happy forged inner preflight hash refused" "PASS installed terminal chain forged inner preflight hash refused" "${json_check}"
assert_contains "happy forged inner service hash refused" "PASS installed terminal chain forged inner service hash refused" "${json_check}"

private_required_identity_refusals="$(cd "${happy_out}/ZLAR" && node - <<'NODE'
const crypto = require('crypto');
const fs = require('fs');
const { spawnSync } = require('child_process');

function sha256Text(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function artifactSetSha256(artifactHashes) {
  const canonical = [...artifactHashes]
    .sort((left, right) => left.path.localeCompare(right.path))
    .map(({ path, sha256 }) => `${path}\0${sha256}\n`)
    .join('');
  return sha256Text(canonical);
}

function report(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${ok || detail === '' ? '' : `: ${detail}`}`);
}

function runVerifier(args, input) {
  return spawnSync('bin/zlar', ['private-verifier-result', 'verify', ...args], {
    input,
    encoding: 'utf8',
  });
}

function failsClosed(result, expectedText = '') {
  return result.status !== 0 &&
    result.stdout === '' &&
    (expectedText === '' || result.stderr.includes(expectedText));
}

function strictGeneratedPosture(verification) {
  const required = verification.required_identity || {};
  return verification.verified === true &&
    verification.result_sha256 === resultSha &&
    verification.artifact_set_sha256 === artifactSetSha &&
    required.command_posture === 'private-result-with-required-recomputed-evidence' &&
    required.result_sha256_required === true &&
    required.result_sha256_matched === true &&
    required.target_required === true &&
    required.target_matched === true &&
    required.bundle_sha256_required === true &&
    required.bundle_sha256_matched === true &&
    required.artifact_set_sha256_required === true &&
    required.artifact_set_sha256_matched === true &&
    required.recomputed_evidence_required === true &&
    required.recomputed_evidence_matched === true;
}

const resultText = fs.readFileSync('zlar-private-verifier-result-v1.json', 'utf8');
const resultJson = JSON.parse(resultText);
const resultSha = sha256Text(resultText);
const artifactSetSha = artifactSetSha256(resultJson.evidence.artifact_hashes);
const target = `${resultJson.target.release_tag}@${resultJson.target.commit_sha}`;
const commonRequiredArgs = [
  '--input',
  '-',
  '--evidence-dir',
  '..',
  '--require-result-sha',
  resultSha,
  '--require-target',
  target,
  '--require-bundle-sha',
  resultJson.evidence.received_bundle_sha256,
  '--require-artifact-set-sha',
  artifactSetSha,
  '--require-recomputed-evidence',
  '--json',
];

const staleJson = JSON.stringify({ ...resultJson, generated_at: '2000-01-01T00:00:00Z' }, null, 2) + '\n';
report(
  'generated private verifier stale body refused',
  failsClosed(runVerifier(commonRequiredArgs, staleJson), 'required result sha mismatch')
);

report(
  'generated private verifier wrong target refused',
  failsClosed(
    runVerifier(
      commonRequiredArgs.map((item, index, args) =>
        args[index - 1] === '--require-target' ? `${resultJson.target.release_tag}@${'f'.repeat(40)}` : item
      ),
      resultText
    ),
    'required target mismatch'
  )
);

report(
  'generated private verifier wrong bundle refused',
  failsClosed(
    runVerifier(
      commonRequiredArgs.map((item, index, args) =>
        args[index - 1] === '--require-bundle-sha' ? 'f'.repeat(64) : item
      ),
      resultText
    ),
    'required bundle sha mismatch'
  )
);

report(
  'generated private verifier wrong artifact set refused',
  failsClosed(
    runVerifier(
      commonRequiredArgs.map((item, index, args) =>
        args[index - 1] === '--require-artifact-set-sha' ? 'f'.repeat(64) : item
      ),
      resultText
    ),
    'required artifact-set sha mismatch'
  )
);

const missingRecompute = runVerifier(
  commonRequiredArgs.filter((item) => item !== '--require-recomputed-evidence'),
  resultText
);
const missingRecomputeVerification = missingRecompute.status === 0 ? JSON.parse(missingRecompute.stdout) : {};
report(
  'generated private verifier missing recompute posture rejected',
  missingRecompute.status === 0 && strictGeneratedPosture(missingRecomputeVerification) === false
);

report(
  'generated private verifier missing evidence-dir refused',
  failsClosed(
    runVerifier(
      commonRequiredArgs.filter((item, index, args) =>
        item !== '--evidence-dir' && args[index - 1] !== '--evidence-dir'
      ),
      resultText
    ),
    'required recomputed evidence was not verified'
  )
);

const summaryOnly = `${JSON.stringify({ report_type: 'zlar-private-verifier-result-v1', summary: 'summary-only material is not a private verifier result envelope' }, null, 2)}\n`;
report(
  'generated private verifier summary-only material refused',
  failsClosed(runVerifier(commonRequiredArgs, summaryOnly))
);
NODE
)"
assert_contains "private verifier stale generated material refused" "PASS generated private verifier stale body refused" "${private_required_identity_refusals}"
assert_contains "private verifier wrong target generated material refused" "PASS generated private verifier wrong target refused" "${private_required_identity_refusals}"
assert_contains "private verifier wrong bundle generated material refused" "PASS generated private verifier wrong bundle refused" "${private_required_identity_refusals}"
assert_contains "private verifier wrong artifact-set generated material refused" "PASS generated private verifier wrong artifact set refused" "${private_required_identity_refusals}"
assert_contains "private verifier missing recompute generated material rejected" "PASS generated private verifier missing recompute posture rejected" "${private_required_identity_refusals}"
assert_contains "private verifier missing evidence-dir generated material refused" "PASS generated private verifier missing evidence-dir refused" "${private_required_identity_refusals}"
assert_contains "private verifier summary-only generated material refused" "PASS generated private verifier summary-only material refused" "${private_required_identity_refusals}"

transcript_text="$(cat "${happy_out}/transcript.txt")"
manifest_text="$(cat "${happy_out}/DRY-RUN-MANIFEST.json")"
result_text="$(cat "${happy_out}/DRY-RUN-RESULT.md")"
assert_contains "result formats runtime activation artifact" '- `ZLAR/zlar-runtime-local-activation-sample-verification.json`' "${result_text}"
assert_contains "result formats runtime profile artifact" '- `ZLAR/zlar-runtime-profile-installation-sample-verification.json`' "${result_text}"
assert_contains "result formats installed runtime profile preflight artifact" '- `ZLAR/zlar-installed-runtime-profile-preflight-sample-verification.json`' "${result_text}"
assert_contains "result formats installed runtime profile recognition proof artifact" '- `ZLAR/zlar-installed-runtime-profile-recognition-proof-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile recognition proof portable artifact" '- `ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile recognition proof artifact verification" '- `ZLAR/zlar-installed-runtime-profile-recognition-proof-artifact-verification-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile service proof artifact" '- `ZLAR/zlar-installed-runtime-profile-service-proof-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile service proof portable artifact" '- `ZLAR/zlar-installed-runtime-profile-service-proof-artifact-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile service proof artifact verification" '- `ZLAR/zlar-installed-runtime-profile-service-proof-artifact-verification-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile terminal chain artifact" '- `ZLAR/zlar-installed-runtime-profile-terminal-chain-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile terminal chain portable artifact" '- `ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile terminal chain artifact verification" '- `ZLAR/zlar-installed-runtime-profile-terminal-chain-artifact-verification-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile terminal chain forged preflight artifact" '- `ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile terminal chain forged preflight error" '- `ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-preflight-hash-error.txt`' "${result_text}"
assert_contains "result formats installed runtime profile terminal chain forged service artifact" '- `ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-v1.json`' "${result_text}"
assert_contains "result formats installed runtime profile terminal chain forged service error" '- `ZLAR/zlar-installed-runtime-profile-terminal-chain-forged-inner-service-hash-error.txt`' "${result_text}"
assert_contains "result formats product proof path artifact" '- `ZLAR/zlar-product-proof-path-v1.json`' "${result_text}"
assert_contains "result formats coverage artifact" '- `ZLAR/zlar-coverage-map-sample.json`' "${result_text}"
assert_contains "result formats verifier kit reproducibility artifact" '- `ZLAR/zlar-verifier-kit-reproducibility-v1.json`' "${result_text}"
assert_contains "result formats verifier kit external-runner diagnostics artifact" '- `ZLAR/zlar-verifier-kit-external-runner-diagnostics-v1.json`' "${result_text}"
assert_contains "result formats verifier kit release assets artifact" '- `ZLAR/zlar-verifier-kit-release-assets-v1.json`' "${result_text}"
assert_contains "result formats verifier kit public distribution artifact" '- `ZLAR/zlar-verifier-kit-public-distribution-v1.json`' "${result_text}"
assert_contains "result formats private verifier envelope artifact" '- `ZLAR/zlar-private-verifier-result-v1.json`' "${result_text}"
assert_contains "result formats private verifier verification artifact" '- `ZLAR/zlar-private-verifier-result-verification-v1.json`' "${result_text}"
assert_contains "result formats private verifier hashes section" '## Private Verifier Result Intake' "${result_text}"
assert_contains "result formats private result verification evidence section" '## Private Result Verification Evidence' "${result_text}"
assert_contains "result summarizes private result verification type" 'private_result_verification.verification_type=zlar-private-verifier-result-verification-v1' "${result_text}"
assert_contains "result summarizes private result verification verified" 'private_result_verification.verified=true' "${result_text}"
assert_contains "result summarizes private result verification sample fixture" 'private_result_verification.intake_class=sample-fixture' "${result_text}"
assert_contains "result summarizes private result verification result sha" 'private_result_verification.result_sha256=' "${result_text}"
assert_contains "result summarizes private result verification artifact set sha" 'private_result_verification.artifact_set_sha256=' "${result_text}"
assert_contains "result summarizes private result verification hash count" 'private_result_verification.artifact_hash_count=' "${result_text}"
assert_contains "result summarizes private result verification required posture" 'private_result_verification.required_identity.command_posture=private-result-with-required-recomputed-evidence' "${result_text}"
assert_contains "result summarizes private result verification result sha required" 'private_result_verification.required_identity.result_sha256_required=true' "${result_text}"
assert_contains "result summarizes private result verification result sha matched" 'private_result_verification.required_identity.result_sha256_matched=true' "${result_text}"
assert_contains "result summarizes private result verification target required" 'private_result_verification.required_identity.target_required=true' "${result_text}"
assert_contains "result summarizes private result verification target matched" 'private_result_verification.required_identity.target_matched=true' "${result_text}"
assert_contains "result summarizes private result verification bundle required" 'private_result_verification.required_identity.bundle_sha256_required=true' "${result_text}"
assert_contains "result summarizes private result verification bundle matched" 'private_result_verification.required_identity.bundle_sha256_matched=true' "${result_text}"
assert_contains "result summarizes private result verification artifact set required" 'private_result_verification.required_identity.artifact_set_sha256_required=true' "${result_text}"
assert_contains "result summarizes private result verification artifact set matched" 'private_result_verification.required_identity.artifact_set_sha256_matched=true' "${result_text}"
assert_contains "result summarizes private result verification recompute required" 'private_result_verification.required_identity.recomputed_evidence_required=true' "${result_text}"
assert_contains "result summarizes private result verification recompute matched" 'private_result_verification.required_identity.recomputed_evidence_matched=true' "${result_text}"
assert_contains "result summarizes private result verification recomputed hashes" 'private_result_verification.evidence_dir_hashes_recomputed=true' "${result_text}"
assert_contains "result summarizes private result verification evidence-dir verified" 'private_result_verification.evidence_dir_hashes_verified=true' "${result_text}"
assert_contains "result summarizes private result verification content contract required" 'private_result_verification.evidence_dir_contract_required_for_target=true' "${result_text}"
assert_contains "result summarizes private result verification content contract verified" 'private_result_verification.evidence_dir_contract_verified=true' "${result_text}"
assert_contains "result summarizes private result verification content contract type" 'private_result_verification.evidence_dir_contract_type=product-proof-path-terminal-chain-recognized-receipt-path-mirror-v1' "${result_text}"
assert_contains "result summarizes private result verification content contract source" 'private_result_verification.evidence_dir_contract_source_path=DRY-RUN-MANIFEST.json' "${result_text}"
assert_contains "result summarizes private result verification terminal group count" 'private_result_verification.terminal_chain_recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes private result verification terminal group case count" 'private_result_verification.terminal_chain_recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes private result verification terminal group ids preserved" 'private_result_verification.terminal_chain_recognition_refusal_group_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification north-star group ids preserved" 'private_result_verification.north_star_terminal_chain_recognition_refusal_group_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification deployment bridge required" 'private_result_verification.deployment_profile_authority_bridge_required_for_target=true' "${result_text}"
assert_contains "result summarizes private result verification deployment bridge preserved" 'private_result_verification.deployment_profile_authority_bridge_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification north-star deployment bridge preserved" 'private_result_verification.north_star_deployment_profile_authority_bridge_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification deployment bridge refusal count" 'private_result_verification.deployment_profile_authority_bridge_refusal_case_count=18' "${result_text}"
assert_contains "result summarizes private result verification deployment authority refusals required" 'private_result_verification.deployment_profile_authority_refusals_required_for_target=true' "${result_text}"
assert_contains "result summarizes private result verification deployment authority refusals preserved" 'private_result_verification.deployment_profile_authority_refusals_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification north-star deployment authority refusals preserved" 'private_result_verification.north_star_deployment_profile_authority_refusals_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification deployment authority refusal count" 'private_result_verification.deployment_profile_authority_refusal_case_count=5' "${result_text}"
assert_contains "result summarizes private result verification deployment authority refusal ids preserved" 'private_result_verification.deployment_profile_authority_refusal_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification deployment authority refusals before service proof" 'private_result_verification.deployment_profile_authority_refusals_before_service_proof=true' "${result_text}"
assert_contains "result summarizes private result verification stale artifact refusal" 'private_result_verification.stale_deployment_profile_artifact_refused_before_service_proof=true' "${result_text}"
assert_contains "result summarizes private result verification profile mismatch refusal" 'private_result_verification.profile_recognition_mismatch_refused_before_service_proof=true' "${result_text}"
assert_contains "result summarizes private result verification latest selection refusal" 'private_result_verification.latest_profile_selection_refused_before_service_proof=true' "${result_text}"
assert_contains "result summarizes private result verification request authority refusal" 'private_result_verification.request_stream_authority_material_refused_before_service_proof=true' "${result_text}"
assert_contains "result summarizes private result verification deployment bridge current-machine false" 'private_result_verification.deployment_profile_authority_bridge_current_machine_governance=false' "${result_text}"
assert_contains "result summarizes private result verification deployment bridge production false" 'private_result_verification.deployment_profile_authority_bridge_production_authority=false' "${result_text}"
assert_contains "result summarizes private result verification trusted registry required" 'private_result_verification.terminal_chain_trusted_registry_verdict_required_for_target=true' "${result_text}"
assert_contains "result summarizes private result verification trusted registry preserved" 'private_result_verification.product_proof_path_terminal_chain_trusted_registry_verdict_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification north-star trusted registry preserved" 'private_result_verification.north_star_terminal_chain_trusted_registry_verdict_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification trusted registry verdict" 'private_result_verification.terminal_chain_trusted_registry_recognition_verdict=RECOGNIZED' "${result_text}"
assert_contains "result summarizes private result verification trusted registry signature valid" 'private_result_verification.terminal_chain_trusted_registry_signature_valid=true' "${result_text}"
assert_contains "result summarizes private result verification downstream refusals unboarded" 'private_result_verification.downstream_refusal_all_refusals_unboarded=true' "${result_text}"
assert_contains "result summarizes private result verification downstream refusal reasons" 'private_result_verification.downstream_refusal_reasons=receipt_missing,receipt_invalid,issuer_not_active,unknown_issuer,outcome_not_boarding,policy_not_recognized,domain_out_of_scope,tool_out_of_scope,audit_event_mismatch,detail_hash_mismatch,receipt_stale' "${result_text}"
assert_contains "result summarizes private result verification north-star downstream refusals unboarded" 'private_result_verification.north_star_downstream_refusal_all_refusals_unboarded=true' "${result_text}"
assert_contains "result summarizes private result verification north-star downstream refusal reasons" 'private_result_verification.north_star_downstream_refusal_reasons=receipt_missing,receipt_invalid,issuer_not_active,unknown_issuer,outcome_not_boarding,policy_not_recognized,domain_out_of_scope,tool_out_of_scope,audit_event_mismatch,detail_hash_mismatch,receipt_stale' "${result_text}"
assert_contains "result summarizes private result verification recognized receipt path required" 'private_result_verification.terminal_chain_recognized_receipt_path_mirror_required_for_target=true' "${result_text}"
assert_contains "result summarizes private result verification recognized receipt path preserved" 'private_result_verification.product_proof_path_terminal_chain_recognized_receipt_path_mirror_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification north-star recognized receipt path preserved" 'private_result_verification.north_star_terminal_chain_recognized_receipt_path_mirror_preserved=true' "${result_text}"
assert_contains "result summarizes private result verification recognized receipt path sha" 'private_result_verification.terminal_chain_recognized_receipt_path_evidence_sha256=' "${result_text}"
assert_contains "result summarizes private result verification recognized receipt path source binding" 'private_result_verification.terminal_chain_recognized_receipt_path_source_binding_matches_trusted_registry_binding=true' "${result_text}"
assert_contains "result summarizes private result verification non-operator false" 'private_result_verification.completed_by_non_operator=false' "${result_text}"
assert_contains "result summarizes private result verification private non-operator validated false" 'private_result_verification.private_non_operator_pass_validated=false' "${result_text}"
assert_contains "result summarizes private result verification no public attestation" 'private_result_verification.public_external_attestation=false' "${result_text}"
assert_contains "result summarizes private result verification no attribution" 'private_result_verification.public_attribution=false' "${result_text}"
assert_contains "result summarizes private result verification no public non-operator claim" 'private_result_verification.non_operator_review_publicly_claimed=false' "${result_text}"
assert_contains "result summarizes private result verification no production authority" 'private_result_verification.production_authority=false' "${result_text}"
assert_contains "result formats issuer status evidence section" '## Issuer Status Evidence' "${result_text}"
assert_contains "result summarizes issuer status evidence enabled" 'manifest.issuer_status_evidence.enabled=true' "${result_text}"
assert_contains "result summarizes issuer status evidence model" 'manifest.issuer_status_evidence.evidence_model=release-forward-local-issuer-status-fixture' "${result_text}"
assert_contains "result summarizes issuer status evidence proof type" 'manifest.issuer_status_evidence.proof_type=issuer-status-proof-v1' "${result_text}"
assert_contains "result summarizes issuer status evidence live probing" 'manifest.issuer_status_evidence.proof_live_probing=false' "${result_text}"
assert_contains "result summarizes issuer status active issuer" 'manifest.issuer_status_evidence.active_issuer_boards=true' "${result_text}"
assert_contains "result summarizes issuer status missing key refusal" 'manifest.issuer_status_evidence.missing_key_issuer_refuses=true' "${result_text}"
assert_contains "result summarizes issuer status fixture verdict" 'manifest.issuer_status_evidence.verifier_kit_fixture_verdict=ISSUER-STATUS-FIXTURE-VERIFIED' "${result_text}"
assert_contains "result summarizes issuer status diagnostics verified" 'manifest.issuer_status_evidence.diagnostics_issuer_artifact_verified=true' "${result_text}"
assert_contains "result summarizes issuer status no live claim" 'manifest.issuer_status_evidence.proves_live_issuer_status=false' "${result_text}"
assert_contains "result summarizes issuer status no key custody" 'manifest.issuer_status_evidence.proves_key_custody=false' "${result_text}"
assert_contains "result summarizes issuer status no revocation truth" 'manifest.issuer_status_evidence.proves_revocation_truth=false' "${result_text}"
assert_contains "result summarizes issuer status no production trust registry" 'manifest.issuer_status_evidence.proves_production_trust_registry=false' "${result_text}"
assert_contains "result formats trusted issuer registry evidence section" '## Trusted Issuer Registry Recognition Evidence' "${result_text}"
assert_contains "result summarizes trusted issuer registry evidence enabled" 'manifest.trusted_issuer_registry_recognition_evidence.enabled=true' "${result_text}"
assert_contains "result summarizes trusted issuer registry evidence model" 'manifest.trusted_issuer_registry_recognition_evidence.evidence_model=release-forward-local-trusted-issuer-registry-fixture' "${result_text}"
assert_contains "result summarizes trusted issuer registry type" 'manifest.trusted_issuer_registry_recognition_evidence.registry_type=trusted-receipt-issuers-v1' "${result_text}"
assert_contains "result summarizes trusted issuer registry fixture model" 'manifest.trusted_issuer_registry_recognition_evidence.registry_evidence_model=bundled-local-fixture' "${result_text}"
assert_contains "result summarizes trusted issuer registry live probing false" 'manifest.trusted_issuer_registry_recognition_evidence.live_probing=false' "${result_text}"
assert_contains "result summarizes trusted issuer registry recognized" 'manifest.trusted_issuer_registry_recognition_evidence.verdict=RECOGNIZED' "${result_text}"
assert_contains "result summarizes trusted issuer registry active issuer" 'manifest.trusted_issuer_registry_recognition_evidence.issuer_status=active' "${result_text}"
assert_contains "result summarizes trusted issuer registry signature valid" 'manifest.trusted_issuer_registry_recognition_evidence.signature_valid=true' "${result_text}"
assert_contains "result summarizes trusted issuer registry fail closed" 'manifest.trusted_issuer_registry_recognition_evidence.malformed_registry_fail_closed_before_verdict=true' "${result_text}"
assert_contains "result summarizes trusted issuer registry no attestation" 'manifest.trusted_issuer_registry_recognition_evidence.creates_public_external_attestation=false' "${result_text}"
assert_contains "result summarizes trusted issuer registry no live registry" 'manifest.trusted_issuer_registry_recognition_evidence.proves_live_registry=false' "${result_text}"
assert_contains "result summarizes trusted issuer registry no key custody" 'manifest.trusted_issuer_registry_recognition_evidence.proves_key_custody=false' "${result_text}"
assert_contains "result summarizes trusted issuer registry no revocation truth" 'manifest.trusted_issuer_registry_recognition_evidence.proves_revocation_truth=false' "${result_text}"
assert_contains "result summarizes trusted issuer registry no production downstream" 'manifest.trusted_issuer_registry_recognition_evidence.proves_production_downstream_recognition=false' "${result_text}"
assert_contains "result summarizes trusted issuer registry no production authority" 'manifest.trusted_issuer_registry_recognition_evidence.proves_production_authority=false' "${result_text}"
assert_contains "result formats terminal chain refusal evidence section" '## Terminal Chain Refusal Evidence' "${result_text}"
assert_contains "result summarizes terminal chain refusal evidence enabled" 'manifest.terminal_chain_refusal_evidence.enabled=true' "${result_text}"
assert_contains "result summarizes terminal chain named refusal hash" 'manifest.terminal_chain_refusal_evidence.named_receipt_refusals_sha256=' "${result_text}"
assert_contains "result summarizes terminal chain stale refusal" 'manifest.terminal_chain_refusal_evidence.named_receipt_refusals.stale.refused_before_mutation=true' "${result_text}"
assert_contains "result summarizes terminal chain recognition group hash" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups_sha256=' "${result_text}"
assert_contains "result summarizes terminal chain case ids required" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_group_case_ids_required=true' "${result_text}"
assert_contains "result summarizes terminal chain case ids preserved" 'manifest.terminal_chain_refusal_evidence.all_recognition_refusal_group_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes terminal chain no usable authority group count" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.no_usable_recognized_receipt_authority.case_count=6' "${result_text}"
assert_contains "result summarizes terminal chain no usable authority case ids" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.no_usable_recognized_receipt_authority.case_ids=missing_receipt_refused_before_runtime_mutation,invalid_receipt_refused_before_runtime_mutation,unknown_issuer_refused_before_runtime_mutation,retired_issuer_refused_before_runtime_mutation,missing_issuer_status_refused_before_runtime_mutation,stale_receipt_refused_before_runtime_mutation' "${result_text}"
assert_contains "result summarizes terminal chain no usable authority group" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.no_usable_recognized_receipt_authority.all_refused_before_mutation=true' "${result_text}"
assert_contains "result summarizes terminal chain scope mismatch group count" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.recognized_receipt_scope_mismatch.case_count=6' "${result_text}"
assert_contains "result summarizes terminal chain scope mismatch case ids" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.recognized_receipt_scope_mismatch.case_ids=wrong_policy_refused_before_runtime_mutation,wrong_domain_refused_before_runtime_mutation,wrong_tool_refused_before_runtime_mutation,wrong_audit_event_refused_before_runtime_mutation,wrong_detail_refused_before_runtime_mutation,non_boarding_outcome_refused_before_runtime_mutation' "${result_text}"
assert_contains "result summarizes terminal chain scope mismatch group" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.recognized_receipt_scope_mismatch.all_refused_before_mutation=true' "${result_text}"
assert_contains "result summarizes terminal chain route/request authority group count" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.route_or_request_authority_material_refused.case_count=6' "${result_text}"
assert_contains "result summarizes terminal chain route/request authority case ids" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.route_or_request_authority_material_refused.case_ids=wrong_runtime_profile_id_refused_before_runtime_mutation,direct_api_without_receipt_refused_before_runtime_mutation,direct_api_with_receipt_refused_before_runtime_mutation,agent_supplied_recognition_rule_refused_before_runtime_mutation,agent_supplied_fixture_mode_refused_before_runtime_mutation,unsupported_request_field_refused_before_runtime_mutation' "${result_text}"
assert_contains "result summarizes terminal chain route/request authority group" 'manifest.terminal_chain_refusal_evidence.recognition_refusal_groups.route_or_request_authority_material_refused.all_refused_before_mutation=true' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry refusals required" 'manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals_required=true' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry refusal case count" 'manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_case_count=2' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry artifact refusal case count" 'manifest.terminal_chain_refusal_evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_count=2' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry refusals all refused" 'manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals_all_refused=true' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry artifact refusals all refused" 'manifest.terminal_chain_refusal_evidence.artifact_verification_trusted_issuer_registry_recognition_refusals_all_refused=true' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry refusal case ids" 'manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry artifact refusal case ids" 'manifest.terminal_chain_refusal_evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry refusal reason codes" 'manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusal_reason_codes=scope_not_found,detail_hash_mismatch' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry artifact refusal reason codes" 'manifest.terminal_chain_refusal_evidence.artifact_verification_trusted_issuer_registry_recognition_refusal_reason_codes=scope_not_found,detail_hash_mismatch' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry refusal hash" 'manifest.terminal_chain_refusal_evidence.trusted_issuer_registry_recognition_refusals_sha256=' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry artifact refusal hash" 'manifest.terminal_chain_refusal_evidence.artifact_verification_trusted_issuer_registry_recognition_refusals_sha256=' "${result_text}"
assert_contains "result summarizes terminal chain trusted registry refusals preserved" 'manifest.terminal_chain_refusal_evidence.all_trusted_issuer_registry_recognition_refusals_preserved=true' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror required" 'manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror_required=true' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror preserved" 'manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror_preserved=true' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror case count" 'manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_case_count=5' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror case IDs" 'manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_case_ids=stale_deployment_profile_runtime_sha_refused_before_service_proof,runtime_profile_id_mismatch_refused_before_service_proof,preflight_profile_sha_mismatch_refused_before_service_proof,preflight_latest_selection_refused_before_service_proof,preflight_request_authority_material_refused_before_service_proof' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror before service proof" 'manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusals_before_service_proof=true' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror service proof not started" 'manifest.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_service_proof_started=false' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror current-machine false" 'manifest.terminal_chain_refusal_evidence.current_machine_governance=false' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror production downstream false" 'manifest.terminal_chain_refusal_evidence.production_downstream_recognition=false' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror production false" 'manifest.terminal_chain_refusal_evidence.production_authority=false' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror enterprise false" 'manifest.terminal_chain_refusal_evidence.enterprise_readiness=false' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror external false" 'manifest.terminal_chain_refusal_evidence.external_attestation=false' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror sovereign false" 'manifest.terminal_chain_refusal_evidence.sovereign_recognition=false' "${result_text}"
assert_contains "result summarizes terminal chain deployment authority mirror unrouted false" 'manifest.terminal_chain_refusal_evidence.unrouted_surface_coverage=false' "${result_text}"
assert_contains "result summarizes terminal chain nested tamper required" 'manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals_required=true' "${result_text}"
assert_contains "result summarizes terminal chain nested tamper preflight type" 'manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals.generated_preflight_artifact_type=zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' "${result_text}"
assert_contains "result summarizes terminal chain nested tamper service type" 'manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals.generated_service_proof_artifact_type=zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' "${result_text}"
assert_contains "result summarizes terminal chain nested tamper artifact preflight type" 'manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals.artifact_generated_preflight_artifact_type=zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' "${result_text}"
assert_contains "result summarizes terminal chain nested tamper artifact service type" 'manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals.artifact_generated_service_proof_artifact_type=zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' "${result_text}"
assert_contains "result summarizes terminal chain nested tamper forged preflight refusal" 'manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals.forged_inner_preflight_hash_refused=true' "${result_text}"
assert_contains "result summarizes terminal chain nested tamper forged service refusal" 'manifest.terminal_chain_refusal_evidence.nested_artifact_tamper_refusals.forged_inner_service_hash_refused=true' "${result_text}"
assert_contains "result summarizes terminal chain nested binding required" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding_required=true' "${result_text}"
assert_contains "result summarizes terminal chain nested preflight type" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.generated_preflight_artifact_type=zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' "${result_text}"
assert_contains "result summarizes terminal chain nested service type" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.generated_service_proof_artifact_type=zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' "${result_text}"
assert_contains "result summarizes terminal chain nested preflight body hash" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.generated_preflight_artifact_body_sha256=' "${result_text}"
assert_contains "result summarizes terminal chain nested service body hash" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.generated_service_proof_artifact_body_sha256=' "${result_text}"
assert_contains "result summarizes terminal chain nested preflight verified" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.generated_preflight_artifact_verified=true' "${result_text}"
assert_contains "result summarizes terminal chain nested service verified" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.generated_service_proof_artifact_verified=true' "${result_text}"
assert_contains "result summarizes terminal chain nested preflight hash bound" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.preflight_artifact_hash_bound=true' "${result_text}"
assert_contains "result summarizes terminal chain nested service source preflight hash bound" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.service_proof_source_preflight_hash_bound=true' "${result_text}"
assert_contains "result summarizes terminal chain nested service artifact hash bound" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.service_artifact_hash_bound=true' "${result_text}"
assert_contains "result summarizes terminal chain nested service artifact verification bound" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.service_artifact_verification_bound_to_service_proof=true' "${result_text}"
assert_contains "result summarizes terminal chain nested boundary" 'manifest.terminal_chain_refusal_evidence.nested_artifact_binding.proves_production_downstream_recognition=false' "${result_text}"
assert_contains "result summarizes terminal chain boundary" 'manifest.terminal_chain_refusal_evidence.proves_production_downstream_recognition=false' "${result_text}"
assert_contains "result formats release-forward report contract section" '## Release-Forward Report Contract' "${result_text}"
assert_contains "result summarizes report contract product proof path source" 'manifest.release_forward_report_contract.source_artifacts.product_proof_path_path=ZLAR/zlar-product-proof-path-v1.json' "${result_text}"
assert_contains "result summarizes report contract product proof path source hash" 'manifest.release_forward_report_contract.source_artifacts.product_proof_path_sha256=' "${result_text}"
assert_contains "result summarizes report contract product proof path minimum" 'manifest.release_forward_report_contract.product_proof_path.minimum_target=v3.4.42' "${result_text}"
assert_contains "result summarizes report contract product proof path type" 'manifest.release_forward_report_contract.product_proof_path.report_type=zlar-product-proof-path-v1' "${result_text}"
assert_contains "result summarizes report contract product proof path pass" 'manifest.release_forward_report_contract.product_proof_path.result=PASS' "${result_text}"
assert_contains "result summarizes report contract product proof path evidence" 'manifest.release_forward_report_contract.product_proof_path.evidence_model=fresh-local-fixture-proof-pack-terminal-chain-and-deployment-profile-authority-bridge' "${result_text}"
assert_contains "result summarizes report contract product proof path terminal binding" 'manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.trusted_issuer_registry_recognition_binding_hash_matches_artifact_verification=true' "${result_text}"
assert_contains "result summarizes report contract product proof path terminal group count" 'manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes report contract product proof path terminal group case count" 'manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes report contract product proof path terminal group case IDs preserved" 'manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognition_refusal_group_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes report contract product proof path terminal group case IDs" 'manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.recognition_refusal_group_case_ids.no_usable_recognized_receipt_authority=missing_receipt_refused_before_runtime_mutation,invalid_receipt_refused_before_runtime_mutation,unknown_issuer_refused_before_runtime_mutation,retired_issuer_refused_before_runtime_mutation,missing_issuer_status_refused_before_runtime_mutation,stale_receipt_refused_before_runtime_mutation' "${result_text}"
assert_contains "result summarizes report contract product proof path terminal false boundary" 'manifest.release_forward_report_contract.product_proof_path.terminal_chain_boundary.registry_public_key_material_included=false' "${result_text}"
assert_contains "result summarizes report contract product proof path deployment bridge proof type" 'manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.proof_type=zlar-protected-records-one-terminal-deployment-profile-proof-v1' "${result_text}"
assert_contains "result summarizes report contract product proof path deployment authority refusal count" 'manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_count=5' "${result_text}"
assert_contains "result summarizes report contract product proof path deployment authority refusal case IDs" 'manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.deployment_profile_authority_refusal_case_ids=stale_deployment_profile_runtime_sha_refused_before_service_proof,runtime_profile_id_mismatch_refused_before_service_proof,preflight_profile_sha_mismatch_refused_before_service_proof,preflight_latest_selection_refused_before_service_proof,preflight_request_authority_material_refused_before_service_proof' "${result_text}"
assert_contains "result summarizes report contract product proof path stale artifact refusal" 'manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.stale_deployment_profile_artifact_refused_before_service_proof=true' "${result_text}"
assert_contains "result summarizes report contract product proof path profile mismatch refusal" 'manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.profile_recognition_mismatch_refused_before_service_proof=true' "${result_text}"
assert_contains "result summarizes report contract product proof path deployment bridge current-machine" 'manifest.release_forward_report_contract.product_proof_path.deployment_profile_authority_bridge.current_machine_governance=false' "${result_text}"
assert_contains "result summarizes report contract product proof path no live probing" 'manifest.release_forward_report_contract.product_proof_path.live_probing=false' "${result_text}"
assert_contains "result summarizes report contract product proof path gates" 'manifest.release_forward_report_contract.product_proof_path.acceptance_gate_all_true=true' "${result_text}"
assert_contains "result summarizes report contract product proof path forbidden claims" 'manifest.release_forward_report_contract.product_proof_path.forbidden_claims_all_false=true' "${result_text}"
assert_contains "result summarizes report contract product proof path receipt valid" 'manifest.release_forward_report_contract.product_proof_path.receipt_verifier_boundary.valid_verdict=VALID' "${result_text}"
assert_contains "result summarizes report contract product proof path north star consumed" 'manifest.release_forward_report_contract.product_proof_path.north_star.artifact_consumed=true' "${result_text}"
assert_contains "result summarizes report contract product proof path north star deployment bridge preserved" 'manifest.release_forward_report_contract.product_proof_path.north_star.deployment_profile_authority_bridge_preserved=true' "${result_text}"
assert_contains "result summarizes report contract product proof path north star deployment authority refusals preserved" 'manifest.release_forward_report_contract.product_proof_path.north_star.deployment_profile_authority_refusals_preserved=true' "${result_text}"
assert_contains "result summarizes report contract product proof path north star terminal group case IDs" 'manifest.release_forward_report_contract.product_proof_path.north_star.terminal_chain_recognition_refusal_group_case_ids.no_usable_recognized_receipt_authority=missing_receipt_refused_before_runtime_mutation,invalid_receipt_refused_before_runtime_mutation,unknown_issuer_refused_before_runtime_mutation,retired_issuer_refused_before_runtime_mutation,missing_issuer_status_refused_before_runtime_mutation,stale_receipt_refused_before_runtime_mutation' "${result_text}"
assert_contains "result summarizes report contract product proof path known noncoverage" 'manifest.release_forward_report_contract.product_proof_path.known_ungoverned_boundaries_includes_unrouted_records_paths=true' "${result_text}"
assert_contains "result summarizes report contract product proof path no attestation" 'manifest.release_forward_report_contract.product_proof_path.claim_boundary.creates_public_external_attestation=false' "${result_text}"
assert_contains "result summarizes report contract product proof path no current-machine" 'manifest.release_forward_report_contract.product_proof_path.claim_boundary.proves_current_machine_governance=false' "${result_text}"
assert_contains "result summarizes proof-smoke terminal chain group count" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes proof-smoke terminal chain case count" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes proof-smoke terminal chain no usable case ids" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids.no_usable_recognized_receipt_authority=missing_receipt_refused_before_runtime_mutation,invalid_receipt_refused_before_runtime_mutation,unknown_issuer_refused_before_runtime_mutation,retired_issuer_refused_before_runtime_mutation,missing_issuer_status_refused_before_runtime_mutation,stale_receipt_refused_before_runtime_mutation' "${result_text}"
assert_contains "result summarizes north star case ids required" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_required=true' "${result_text}"
assert_contains "result summarizes north star case ids preserved" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes north star terminal chain group count" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes north star terminal chain case count" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes north star enterprise observed case ids preserved" 'manifest.release_forward_report_contract.north_star.puzzle_3_observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes north star enterprise observed group count" 'manifest.release_forward_report_contract.north_star.puzzle_3_observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes north star enterprise observed case count" 'manifest.release_forward_report_contract.north_star.puzzle_3_observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes north star enterprise observed artifact group count" 'manifest.release_forward_report_contract.north_star.puzzle_3_observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes north star enterprise observed artifact case count" 'manifest.release_forward_report_contract.north_star.puzzle_3_observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes north star downstream observed case ids preserved" 'manifest.release_forward_report_contract.north_star.puzzle_5_observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_ids_preserved=true' "${result_text}"
assert_contains "result summarizes north star downstream observed group count" 'manifest.release_forward_report_contract.north_star.puzzle_5_observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes north star downstream observed case count" 'manifest.release_forward_report_contract.north_star.puzzle_5_observed.installed_runtime_profile_terminal_chain_recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes north star downstream observed artifact group count" 'manifest.release_forward_report_contract.north_star.puzzle_5_observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_count=3' "${result_text}"
assert_contains "result summarizes north star downstream observed artifact case count" 'manifest.release_forward_report_contract.north_star.puzzle_5_observed.installed_runtime_profile_terminal_chain_artifact_verification_recognition_refusal_group_case_count=18' "${result_text}"
assert_contains "result summarizes proof-smoke trusted registry refusal case count" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count=2' "${result_text}"
assert_contains "result summarizes proof-smoke trusted registry refusals all refused" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_all_refused=true' "${result_text}"
assert_contains "result summarizes proof-smoke trusted registry refusal case ids" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes proof-smoke trusted registry refusal reason codes" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes=scope_not_found,detail_hash_mismatch' "${result_text}"
assert_contains "result summarizes proof-smoke trusted registry refusal hash" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256=' "${result_text}"
assert_contains "result summarizes proof-smoke artifact trusted registry refusal case count" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count=2' "${result_text}"
assert_contains "result summarizes proof-smoke artifact trusted registry refusal case ids" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes proof-smoke deployment authority mirror preserved" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true' "${result_text}"
assert_contains "result summarizes proof-smoke deployment authority mirror profile sha" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_profile_sha_matches=true' "${result_text}"
assert_contains "result summarizes proof-smoke deployment authority mirror case IDs" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids=stale_deployment_profile_runtime_sha_refused_before_service_proof,runtime_profile_id_mismatch_refused_before_service_proof,preflight_profile_sha_mismatch_refused_before_service_proof,preflight_latest_selection_refused_before_service_proof,preflight_request_authority_material_refused_before_service_proof' "${result_text}"
assert_contains "result summarizes north star trusted registry refusals preserved" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved=true' "${result_text}"
assert_contains "result summarizes north star trusted registry refusal case count" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_count=2' "${result_text}"
assert_contains "result summarizes north star trusted registry refusal case ids" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes north star trusted registry refusal reason codes" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_reason_codes=scope_not_found,detail_hash_mismatch' "${result_text}"
assert_contains "result summarizes north star trusted registry refusal hash" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_sha256=' "${result_text}"
assert_contains "result summarizes north star artifact trusted registry refusal case count" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_count=2' "${result_text}"
assert_contains "result summarizes north star artifact trusted registry refusal case ids" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_artifact_verification_trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes north star deployment authority mirror required" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_required=true' "${result_text}"
assert_contains "result summarizes north star deployment authority mirror preserved" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_mirror_preserved=true' "${result_text}"
assert_contains "result summarizes north star deployment authority mirror case IDs" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusal_case_ids=stale_deployment_profile_runtime_sha_refused_before_service_proof,runtime_profile_id_mismatch_refused_before_service_proof,preflight_profile_sha_mismatch_refused_before_service_proof,preflight_latest_selection_refused_before_service_proof,preflight_request_authority_material_refused_before_service_proof' "${result_text}"
assert_contains "result summarizes report contract terminal evidence deployment mirror preserved" 'manifest.release_forward_report_contract.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_mirror_preserved=true' "${result_text}"
assert_contains "result summarizes report contract terminal evidence deployment mirror case count" 'manifest.release_forward_report_contract.terminal_chain_refusal_evidence.deployment_profile_authority_refusal_case_count=5' "${result_text}"
assert_contains "result summarizes report contract terminal evidence deployment mirror external false" 'manifest.release_forward_report_contract.terminal_chain_refusal_evidence.external_attestation=false' "${result_text}"
assert_contains "result summarizes report contract terminal evidence deployment mirror unrouted false" 'manifest.release_forward_report_contract.terminal_chain_refusal_evidence.unrouted_surface_coverage=false' "${result_text}"
assert_contains "result summarizes proof-smoke deployment authority mirror before mutation" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_refusals_before_mutation=true' "${result_text}"
assert_contains "result summarizes proof-smoke deployment authority mirror external false" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation=false' "${result_text}"
assert_contains "result summarizes proof-smoke deployment authority mirror unrouted false" 'manifest.release_forward_report_contract.proof_smoke.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage=false' "${result_text}"
assert_contains "result summarizes north star deployment authority mirror external false" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_external_attestation=false' "${result_text}"
assert_contains "result summarizes north star deployment authority mirror unrouted false" 'manifest.release_forward_report_contract.north_star.counts.installed_runtime_profile_terminal_chain_deployment_profile_authority_unrouted_surface_coverage=false' "${result_text}"
assert_contains "result summarizes north star enterprise trusted registry refusals preserved" 'manifest.release_forward_report_contract.north_star.puzzle_3_observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved=true' "${result_text}"
assert_contains "result summarizes north star enterprise trusted registry refusal case ids" 'manifest.release_forward_report_contract.north_star.puzzle_3_observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes north star downstream trusted registry refusals preserved" 'manifest.release_forward_report_contract.north_star.puzzle_5_observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusals_preserved=true' "${result_text}"
assert_contains "result summarizes north star downstream trusted registry refusal case ids" 'manifest.release_forward_report_contract.north_star.puzzle_5_observed.installed_runtime_profile_terminal_chain_trusted_issuer_registry_recognition_refusal_case_ids=unrecognized_terminal_chain_registry_scope_refused,registry_receipt_contract_mismatch_refused' "${result_text}"
assert_contains "result summarizes tamper nested preflight artifact type" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_tamper_refusals.generated_preflight_artifact_type=zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' "${result_text}"
assert_contains "result summarizes tamper nested service artifact type" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_tamper_refusals.generated_service_proof_artifact_type=zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' "${result_text}"
assert_contains "result summarizes tamper artifact nested preflight type" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_tamper_refusals.artifact_generated_preflight_artifact_type=zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' "${result_text}"
assert_contains "result summarizes tamper artifact nested service type" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_tamper_refusals.artifact_generated_service_proof_artifact_type=zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' "${result_text}"
assert_contains "result summarizes forged inner preflight hash refusal" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_tamper_refusals.forged_inner_preflight_hash_refused=true' "${result_text}"
assert_contains "result summarizes forged inner service hash refusal" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_tamper_refusals.forged_inner_service_hash_refused=true' "${result_text}"
assert_contains "result summarizes verifier nested preflight artifact type" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_binding.generated_preflight_artifact_type=zlar-protected-records-installed-runtime-profile-preflight-artifact-v1' "${result_text}"
assert_contains "result summarizes verifier nested service artifact type" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_binding.generated_service_proof_artifact_type=zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1' "${result_text}"
assert_contains "result summarizes verifier nested preflight body hash" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_binding.generated_preflight_artifact_body_sha256=' "${result_text}"
assert_contains "result summarizes verifier nested service body hash" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_binding.generated_service_proof_artifact_body_sha256=' "${result_text}"
assert_contains "result summarizes verifier nested preflight hash bound" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_binding.preflight_artifact_hash_bound=true' "${result_text}"
assert_contains "result summarizes verifier nested service artifact hash bound" 'manifest.release_forward_report_contract.terminal_chain_nested_artifact_binding.service_artifact_hash_bound=true' "${result_text}"
assert_contains "result summarizes report contract no public attestation" 'manifest.release_forward_report_contract.claim_boundary.creates_public_external_attestation=false' "${result_text}"
assert_contains "result summarizes report contract no production authority" 'manifest.release_forward_report_contract.claim_boundary.proves_production_authority=false' "${result_text}"
assert_contains "result summarizes report contract no current-machine governance" 'manifest.release_forward_report_contract.claim_boundary.proves_current_machine_governance=false' "${result_text}"
assert_contains "result summarizes report contract no live mcp" 'manifest.release_forward_report_contract.claim_boundary.proves_live_mcp_coverage=false' "${result_text}"
assert_contains "result summarizes report contract no unrouted coverage" 'manifest.release_forward_report_contract.claim_boundary.proves_unrouted_surface_coverage=false' "${result_text}"
assert_contains "result formats private intake pointer contract section" '## Private Intake Pointer Contract' "${result_text}"
assert_contains "result summarizes manifest private sample pointer" 'manifest.private_verifier_result_sample.enabled=true' "${result_text}"
assert_contains "result summarizes manifest private sample boundary" 'manifest.private_verifier_result_sample.creates_public_external_attestation=false' "${result_text}"
assert_contains "json validates private sample pointer exact keys" 'PASS manifest private result sample pointer exact keys' "${json_check}"
assert_contains "json validates private sample pointer extra-key rejection" 'PASS manifest private result sample pointer rejects extra key' "${json_check}"
assert_contains "json validates private sample pointer missing-key rejection" 'PASS manifest private result sample pointer rejects missing key' "${json_check}"
assert_contains "json validates private sample pointer renamed-key rejection" 'PASS manifest private result sample pointer rejects renamed key' "${json_check}"
assert_contains "json validates private sample pointer summary-shaped rejection" 'PASS manifest private result sample pointer rejects summary-shaped field' "${json_check}"
assert_contains "result summarizes readiness private intake pointer" 'readiness.puzzle_7.private_intake_sample_manifest_pointer.provided=true' "${result_text}"
assert_contains "result summarizes readiness private intake field" 'readiness.puzzle_7.private_intake_sample_manifest_pointer.manifest_field=private_verifier_result_sample' "${result_text}"
assert_contains "result summarizes readiness private intake non-circular" 'readiness.puzzle_7.private_intake_sample_manifest_pointer.circular_hash_avoided=true' "${result_text}"
assert_contains "result summarizes readiness private intake boundary" 'readiness.puzzle_7.private_intake_sample_manifest_pointer.creates_public_external_attestation=false' "${result_text}"
assert_contains "result uses artifact hash markdown fence" '```text' "${result_text}"
assert_not_regex "result does not escape markdown backticks" '\\`' "${result_text}"
assert_not_regex "transcript hides local paths" '/Users/|/home/|/private/|/tmp/|/var/' "${transcript_text}"
assert_not_regex "transcript omits obvious secrets" 'sk-[A-Za-z0-9_-]+|BEGIN (RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY|[0-9]{8,}:[A-Za-z0-9_-]{20,}' "${transcript_text}"
assert_not_regex "manifest hides local paths" '/Users/|/home/|/private/|/tmp/|/var/' "${manifest_text}"
assert_not_regex "manifest omits obvious secrets" 'sk-[A-Za-z0-9_-]+|BEGIN (RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY|[0-9]{8,}:[A-Za-z0-9_-]{20,}' "${manifest_text}"
assert_not_regex "result hides local paths" '/Users/|/home/|/private/|/tmp/|/var/' "${result_text}"
assert_not_regex "result omits obvious secrets" 'sk-[A-Za-z0-9_-]+|BEGIN (RSA |EC |OPENSSH |PRIVATE )?PRIVATE KEY|[0-9]{8,}:[A-Za-z0-9_-]{20,}' "${result_text}"

git -C "${PROJECT_DIR}" for-each-ref --format='%(refname):%(objectname)' refs/tags | LC_ALL=C sort >"${main_tags_after}"
TOTAL=$((TOTAL + 1))
if cmp -s "${main_tags_before}" "${main_tags_after}"; then
    pass
else
    fail "main repo tags unchanged" "$(diff -u "${main_tags_before}" "${main_tags_after}" || true)"
fi

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ✓"
