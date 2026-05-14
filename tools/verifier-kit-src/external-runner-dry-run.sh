#!/usr/bin/env bash
# Hermetic dry-run helper for a clean ZLAR Verifier Kit external-runner flow.

set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_PWD="$(pwd)"
ENGAGEMENT_DIR=""
COMMANDS=()
ARTIFACTS=()
LAST_OUTPUT=""

usage() {
    cat <<'USAGE'
Usage:
  bash external-runner-dry-run.sh
  bash external-runner-dry-run.sh --engagement-dir ../engagement-bundle

Runs kit-local sample verification checks and, when supplied, synthetic
engagement receipt and chain checks. This helper is not external
attestation by itself. It runs after unpacking and does not verify the
tarball SHA-256 sidecar.
USAGE
}

print_boundary() {
    echo "coverage_boundary:"
    echo "- Checks this kit's self-test, built-in vectors, bundled sample receipt, and bundled sample audit chain."
    echo "- Checks a supplied synthetic engagement receipt and chain when --engagement-dir is provided."
    echo "- Does not prove routed coverage, human attendance, external time anchoring, production signing identity, hardware-rooted signing, policy replay, or broad agent governance."
    echo "- Not externally attested yet unless this output was produced by an actual non-operator runner."
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

while [ "$#" -gt 0 ]; do
    case "$1" in
        --engagement-dir)
            if [ "$#" -lt 2 ]; then
                fail "--engagement-dir requires a directory"
            fi
            ENGAGEMENT_DIR="$2"
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
require_file "examples/sample-receipt.json"
require_file "examples/sample-chain.jsonl"
require_file "spec/test-key.pub"

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
