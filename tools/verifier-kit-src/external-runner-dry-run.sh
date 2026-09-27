#!/usr/bin/env bash
# Hermetic dry-run helper for a clean ZLAR Verifier Kit external-runner flow.

set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_PWD="$(pwd)"
ENGAGEMENT_DIR=""
ISSUER_STATUS_JSON_OUT=""
COMMANDS=()
ARTIFACTS=()
LAST_OUTPUT=""

usage() {
    cat <<'USAGE'
Usage:
  bash external-runner-dry-run.sh
  bash external-runner-dry-run.sh --engagement-dir ../engagement-bundle
  bash external-runner-dry-run.sh --issuer-status-json-out ../zlar-verifier-kit-issuer-status-fixture.json

Runs kit-local sample verification checks, the bundled issuer-status
fixture, the bundled trusted issuer registry fixture recognition check, and,
when supplied, synthetic engagement receipt and chain checks.
This helper is not external attestation by itself. It runs after unpacking
and does not verify the tarball SHA-256 sidecar. The optional
--issuer-status-json-out path writes the already-validated issuer-status JSON
artifact and refuses to overwrite an existing file.
USAGE
}

print_boundary() {
    echo "coverage_boundary:"
    echo "- Checks this kit's self-test, built-in vectors, bundled sample receipt, bundled sample audit chain, bundled issuer-status fixture, and bundled trusted issuer registry fixture recognition."
    echo "- Checks a supplied synthetic engagement receipt and chain when --engagement-dir is provided."
    echo "- Does not prove routed coverage, human attendance, external time anchoring, live active issuer status, key custody, revocation truth, production trust-registry state, production downstream recognition, production signing identity, hardware-rooted signing, policy replay, or broad agent governance."
    echo "- No external attestation is claimed for this run unless a real non-operator runner fills, signs, or publishes the result."
}

print_summary() {
    local result="$1"
    echo
    echo "result: ${result}"
    echo "commands_executed:"
    if [ "${#COMMANDS[@]}" -eq 0 ]; then
        echo "- none"
    else
        local cmd
        for cmd in "${COMMANDS[@]}"; do
            printf -- "- %s\n" "${cmd}"
        done
    fi
    echo "artifacts_verified:"
    if [ "${#ARTIFACTS[@]}" -eq 0 ]; then
        echo "- none"
    else
        local artifact
        for artifact in "${ARTIFACTS[@]}"; do
            printf -- "- %s\n" "${artifact}"
        done
    fi
    print_boundary
}

fail() {
    echo
    echo "failure_reason: $*"
    print_summary "FAIL"
    exit 1
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command not found: $1"
    fi
}

require_file() {
    if [ ! -f "$1" ]; then
        fail "required file not found: $1"
    fi
}

run_capture() {
    local label="$1"
    shift
    COMMANDS+=("${label}")
    echo
    printf '$ %s\n' "${label}"
    local output
    local ec
    set +e
    output="$("$@" 2>&1)"
    ec=$?
    set -e
    printf '%s\n' "${output}"
    if [ "${ec}" -ne 0 ]; then
        fail "command failed with exit ${ec}: ${label}"
    fi
    LAST_OUTPUT="${output}"
}

expect_first_line() {
    local expected="$1"
    local actual
    actual="$(printf '%s\n' "${LAST_OUTPUT}" | sed -n '1p')"
    if [ "${actual}" != "${expected}" ]; then
        fail "expected first line '${expected}', got '${actual}'"
    fi
}

expect_final_line() {
    local expected="$1"
    local actual
    actual="$(printf '%s\n' "${LAST_OUTPUT}" | tail -n 1)"
    if [ "${actual}" != "${expected}" ]; then
        fail "expected final line '${expected}', got '${actual}'"
    fi
}

expect_output_contains() {
    local expected="$1"
    if [[ "${LAST_OUTPUT}" != *"${expected}"* ]]; then
        fail "expected output to contain '${expected}'"
    fi
}

resolve_output_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "${ORIGINAL_PWD}" "$1" ;;
    esac
}

write_issuer_status_json_artifact() {
    if [ -z "${ISSUER_STATUS_JSON_OUT}" ]; then
        return 0
    fi
    local output_path
    output_path="$(resolve_output_path "${ISSUER_STATUS_JSON_OUT}")"
    if [ -e "${output_path}" ]; then
        fail "refusing to overwrite issuer-status JSON output"
    fi
    local output_dir
    output_dir="${output_path%/*}"
    if [ -z "${output_dir}" ]; then
        output_dir="/"
    fi
    if [ ! -d "${output_dir}" ]; then
        fail "issuer-status JSON output directory does not exist"
    fi
    printf '%s\n' "${LAST_OUTPUT}" > "${output_path}"
    echo "issuer_status_json_written: yes"
    ARTIFACTS+=("zlar-verifier-kit-issuer-status-fixture.json")
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --engagement-dir)
            if [ "$#" -lt 2 ]; then
                fail "--engagement-dir requires a directory"
            fi
            ENGAGEMENT_DIR="$2"
            shift 2
            ;;
        --issuer-status-json-out)
            if [ "$#" -lt 2 ]; then
                fail "--issuer-status-json-out requires a file path"
            fi
            ISSUER_STATUS_JSON_OUT="$2"
            shift 2
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

require_cmd node
require_cmd sed
require_cmd tail

cd "${KIT_DIR}"

echo "ZLAR verifier kit external-runner dry run"
echo "kit_dir: extracted kit directory"
echo "started_at_utc: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

require_file "verify-test-vectors.mjs"
require_file "verify.mjs"
require_file "verify-chain.mjs"
require_file "verify-issuer-status.mjs"
require_file "verify-recognition.mjs"
require_file "examples/sample-receipt.json"
require_file "examples/sample-chain.jsonl"
require_file "examples/trusted-receipt-issuers-v1.json"
require_file "spec/test-key.pub"
require_file "spec/trusted-receipt-issuers-v1.schema.json"

run_capture "node verify-test-vectors.mjs" node verify-test-vectors.mjs
expect_final_line "ALL VECTORS MATCH SPEC EXPECTATIONS"
ARTIFACTS+=("built-in receipt vectors")

run_capture "node verify.mjs examples/sample-receipt.json --pubkey spec/test-key.pub" \
    node verify.mjs examples/sample-receipt.json --pubkey spec/test-key.pub
expect_first_line "VALID"
ARTIFACTS+=("examples/sample-receipt.json")

run_capture "node verify-chain.mjs examples/sample-chain.jsonl" \
    node verify-chain.mjs examples/sample-chain.jsonl
expect_final_line "Result: INTACT"
ARTIFACTS+=("examples/sample-chain.jsonl")

run_capture "node verify-issuer-status.mjs" node verify-issuer-status.mjs
expect_first_line "ISSUER-STATUS-FIXTURE-VERIFIED"
ARTIFACTS+=("issuer-status fixture text result")

run_capture "node verify-issuer-status.mjs --json" node verify-issuer-status.mjs --json
expect_output_contains '"verdict": "ISSUER-STATUS-FIXTURE-VERIFIED"'
expect_output_contains '"live_probing": false'
expect_output_contains 'external attestation'
ARTIFACTS+=("issuer-status fixture JSON result")
write_issuer_status_json_artifact

run_capture "node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample" \
    node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample
expect_first_line "RECOGNIZED"
ARTIFACTS+=("trusted issuer registry fixture recognition result")
ARTIFACTS+=("examples/trusted-receipt-issuers-v1.json")

run_capture "node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample --json" \
    node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample --json
expect_output_contains '"verdict": "RECOGNIZED"'
expect_output_contains '"live_probing": false'
expect_output_contains 'external attestation'
ARTIFACTS+=("trusted issuer registry fixture JSON result")

if [ -n "${ENGAGEMENT_DIR}" ]; then
    case "${ENGAGEMENT_DIR}" in
        /*) ;;
        *) ENGAGEMENT_DIR="${ORIGINAL_PWD}/${ENGAGEMENT_DIR}" ;;
    esac
    require_file "${ENGAGEMENT_DIR}/engagement-receipt.json"
    require_file "${ENGAGEMENT_DIR}/engagement-pubkey.pub"
    require_file "${ENGAGEMENT_DIR}/engagement-chain.jsonl"

    run_capture "node verify.mjs <engagement-receipt.json> --pubkey <engagement-pubkey.pub>" \
        node verify.mjs "${ENGAGEMENT_DIR}/engagement-receipt.json" --pubkey "${ENGAGEMENT_DIR}/engagement-pubkey.pub"
    expect_first_line "VALID"
    ARTIFACTS+=("engagement-bundle/engagement-receipt.json")
    ARTIFACTS+=("engagement-bundle/engagement-pubkey.pub")

    run_capture "node verify-chain.mjs <engagement-chain.jsonl>" \
        node verify-chain.mjs "${ENGAGEMENT_DIR}/engagement-chain.jsonl"
    expect_final_line "Result: INTACT"
    ARTIFACTS+=("engagement-bundle/engagement-chain.jsonl")
fi

print_summary "PASS"
