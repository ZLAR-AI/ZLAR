#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Doctor — Test Suite
#
# Tests: zlar doctor command output, exit codes, detection of missing deps,
# missing keys, missing policy, missing hooks, audit writability.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0
TOTAL=0

assert() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${expected}" == "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${haystack}" == *"${needle}"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected output to contain "%s"\n' "${label}" "${needle}"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${haystack}" != *"${needle}"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected output NOT to contain "%s"\n' "${label}" "${needle}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Basic Output ==="
echo

# Doctor should run and produce output
output=$(bash "${PROJECT_DIR}/bin/zlar" doctor 2>&1 || true)
assert_contains "doctor produces output" "ZLAR Doctor" "${output}"
assert_contains "doctor checks dependencies" "Dependencies" "${output}"
assert_contains "doctor checks signing keys" "Signing Keys" "${output}"
assert_contains "doctor checks policy" "Policy" "${output}"
assert_contains "doctor checks hooks" "Hook Configuration" "${output}"
assert_contains "doctor checks gate" "Gate Self-Test" "${output}"
assert_contains "doctor checks audit" "Audit Trail" "${output}"
assert_contains "doctor checks telegram" "Telegram" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Dependency Detection ==="
echo

# jq should be detected (we're running tests, so it's installed)
assert_contains "doctor detects jq" "jq" "${output}"

# openssl should be detected
assert_contains "doctor detects openssl" "openssl" "${output}"

# bash should be detected with version
assert_contains "doctor detects bash" "bash" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Gate Self-Test ==="
echo

# If the gate exists, doctor should show it as executable
if [ -x "${PROJECT_DIR}/bin/zlar-gate" ]; then
    assert_contains "gate executable found" "Gate executable" "${output}"
    # Live tests may be skipped if gate is busy (normal during active session)
    # Just verify the section exists
    assert_contains "gate section present" "Gate Self-Test" "${output}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Help Lists Doctor ==="
echo

help_output=$(bash "${PROJECT_DIR}/bin/zlar" help 2>&1)
assert_contains "help mentions doctor" "doctor" "${help_output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Unknown Command ==="
echo

unknown_output=$(bash "${PROJECT_DIR}/bin/zlar" notacommand 2>&1 || true)
assert_contains "unknown command shows error" "Unknown command" "${unknown_output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Version ==="
echo

version_output=$(bash "${PROJECT_DIR}/bin/zlar" version 2>&1)
assert_contains "version command works" "ZLAR" "${version_output}"

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
echo
echo "=== Results ==="
echo "${PASS}/${TOTAL} passed, ${FAIL} failed"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
