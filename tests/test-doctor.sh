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
assert_contains "doctor checks Codex hook reality" "Codex:" "${output}"
assert_contains "doctor distinguishes hook config from invocation observation" "doctor verifies configuration, not that this invocation crossed the hook" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Dependency Detection ==="
echo

# jq should be detected (we're running tests, so it's installed)
assert_contains "doctor detects jq" "jq" "${output}"

# openssl should be detected
assert_contains "doctor detects openssl" "openssl" "${output}"

# bash should be detected with version
assert_contains "doctor detects bash" "bash" "${output}"
assert_contains "doctor names bash 3.2+ support floor" "3.2+ supported for gate" "${output}"
assert_not_contains "doctor does not require bash 4+" "gate requires bash 4+" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Doctor: Key Pair Match Detection ==="
echo

if command -v openssl >/dev/null 2>&1 && openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
    DOCTOR_TMP=$(mktemp -d)
    DOCTOR_HOME="${DOCTOR_TMP}/home"
    DOCTOR_PROJECT="${DOCTOR_TMP}/project"
    mkdir -p "${DOCTOR_HOME}" "${DOCTOR_PROJECT}/bin" "${DOCTOR_PROJECT}/etc/keys"
    cp "${PROJECT_DIR}/bin/zlar" "${DOCTOR_PROJECT}/bin/zlar"
    chmod +x "${DOCTOR_PROJECT}/bin/zlar"

    openssl genpkey -algorithm ed25519 -out "${DOCTOR_HOME}/.zlar-signing.key" 2>/dev/null
    chmod 600 "${DOCTOR_HOME}/.zlar-signing.key"
    openssl pkey -in "${DOCTOR_HOME}/.zlar-signing.key" -pubout -out "${DOCTOR_PROJECT}/etc/keys/policy-signing.pub" 2>/dev/null

    matched_output=$(HOME="${DOCTOR_HOME}" bash "${DOCTOR_PROJECT}/bin/zlar" doctor 2>&1 || true)
    assert_contains "doctor accepts matching signing key pair" "Key pair matches" "${matched_output}"
    assert_not_contains "doctor does not report mismatch for matching signing key pair" "Key pair mismatch" "${matched_output}"

    openssl genpkey -algorithm ed25519 -out "${DOCTOR_TMP}/other.key" 2>/dev/null
    openssl pkey -in "${DOCTOR_TMP}/other.key" -pubout -out "${DOCTOR_PROJECT}/etc/keys/policy-signing.pub" 2>/dev/null
    mismatched_output=$(HOME="${DOCTOR_HOME}" bash "${DOCTOR_PROJECT}/bin/zlar" doctor 2>&1 || true)
    assert_contains "doctor reports mismatched signing key pair" "Key pair mismatch" "${mismatched_output}"

    rm -rf "${DOCTOR_TMP}"
else
    echo "  SKIP: openssl Ed25519 unavailable for isolated key-pair regression"
fi

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
