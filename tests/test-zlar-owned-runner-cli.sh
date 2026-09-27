#!/bin/bash
# ZLAR-owned runner CLI regression.
#
# This test stays below live proof: it exercises help and pre-gate validation
# only. Functional execution/deny behavior is covered by the Node fake-gate
# tests in test-zlar-owned-runner.mjs.

set -uo pipefail

PROJECT_DIR="$(cd -P "$(dirname "$0")/.." && pwd)"
ZLAR="${PROJECT_DIR}/bin/zlar"
RUNNER="${PROJECT_DIR}/bin/zlar-run"
DEFAULT_SCRATCH_ROOT="$(cd -P "${PROJECT_DIR}/../ZLAR-Draft/build" && pwd)/zlar-owned-runner-cli-test"
SCRATCH_ROOT="${ZLAR_RUNNER_TEST_ROOT:-${DEFAULT_SCRATCH_ROOT}}"
SCRATCH="${SCRATCH_ROOT}/shell"

rm -rf "${SCRATCH}"
mkdir -p "${SCRATCH}"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); }

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
    local label="$1" needle="$2" haystack="$3"
    if printf '%s' "${haystack}" | grep -Fq -- "${needle}"; then
        pass
    else
        fail "${label}" "missing: ${needle}"
    fi
}

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        pass
    else
        fail "${label}" "expected=${expected} actual=${actual}"
    fi
}

echo "ZLAR-Owned Runner CLI Tests"
echo "==========================="

help_out=$("${RUNNER}" --help 2>&1)
help_rc=$?
assert_eq "zlar-run --help exits zero" "0" "${help_rc}"
assert_contains "zlar-run help names cmd shape" "zlar run --cmd" "${help_out}"
assert_contains "zlar-run help names evidence constraint" "Evidence output is create-new-only" "${help_out}"
assert_contains "zlar-run help names receipt constraint" "Receipt output is opt-in, create-new-only" "${help_out}"
assert_contains "zlar-run help names non-claims" "does not prove raw Codex desktop governance" "${help_out}"

zlar_help_out=$("${ZLAR}" help 2>&1)
zlar_help_rc=$?
assert_eq "zlar help exits zero" "0" "${zlar_help_rc}"
assert_contains "zlar help lists run" "run         Run one Bash command through the ZLAR-owned runner surface" "${zlar_help_out}"

missing_request="${SCRATCH}/missing-command.json"
missing_evidence="${SCRATCH}/missing-command-evidence.json"
printf '{"cwd":"%s","reason":"missing command fixture"}\n' "${SCRATCH}" > "${missing_request}"
missing_out=$("${ZLAR}" run --json "${missing_request}" --evidence-out "${missing_evidence}" 2>&1)
missing_rc=$?
assert_eq "missing command exits two" "2" "${missing_rc}"
assert_contains "missing command stderr names block" "ZLAR runner blocked before gate" "${missing_out}"
assert_eq "missing command evidence written" "true" "$([ -f "${missing_evidence}" ] && echo true || echo false)"

if [ -f "${missing_evidence}" ]; then
    contract=$(jq -r '.runner_contract' "${missing_evidence}" 2>/dev/null)
    executed=$(jq -r '.execution.executed' "${missing_evidence}" 2>/dev/null)
    reason=$(jq -r '.execution.block_reasons[0]' "${missing_evidence}" 2>/dev/null)
    receipt_claim=$(jq -r '.receipt_claim' "${missing_evidence}" 2>/dev/null)
    assert_eq "evidence contract" "zlar-owned-enforceable-runner-v1" "${contract}"
    assert_eq "evidence executed false" "false" "${executed}"
    assert_eq "evidence missing command reason" "missing_command" "${reason}"
    assert_eq "evidence no receipt claim" "false" "${receipt_claim}"
fi

bad_out=$("${RUNNER}" --not-a-real-option 2>&1)
bad_rc=$?
assert_eq "bad option exits two" "2" "${bad_rc}"
assert_contains "bad option prints usage" "Usage:" "${bad_out}"

echo
echo "Results: ${PASS} passed, ${FAIL} failed"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
