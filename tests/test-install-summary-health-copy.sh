#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_SH="${ROOT}/install.sh"

failures=0
passed=0
total=0

assert_contains() {
    local name="$1"
    local needle="$2"
    total=$((total + 1))
    if grep -Fq "${needle}" "${INSTALL_SH}"; then
        passed=$((passed + 1))
        printf "PASS: %s\n" "${name}"
    else
        printf "FAIL: %s\n" "${name}"
        printf "  missing: %s\n" "${needle}"
        failures=$((failures + 1))
    fi
}

assert_not_contains() {
    local name="$1"
    local needle="$2"
    total=$((total + 1))
    if grep -Fq "${needle}" "${INSTALL_SH}"; then
        printf "FAIL: %s\n" "${name}"
        printf "  unexpected: %s\n" "${needle}"
        failures=$((failures + 1))
    else
        passed=$((passed + 1))
        printf "PASS: %s\n" "${name}"
    fi
}

assert_contains "deny examples are labeled as policy, not health" "Policy denies by default"
assert_contains "signing-key read is a DENY policy example" "DENY  Reading the signing key"
assert_contains "destructive shell example is a DENY policy example" "DENY  rm, rm -rf (file deletion)"

assert_not_contains "signing-key read is not rendered as a failed health check" "✗  Reading the signing key"
assert_not_contains "destructive shell deny is not rendered as a failed health check" "✗  rm, rm -rf (file deletion)"

if [ "${failures}" -ne 0 ]; then
    printf "\nResults: %d/%d passed (%d FAILED)\n" "${passed}" "${total}" "${failures}"
    printf "\n%d install summary health-copy assertion(s) failed\n" "${failures}"
    exit 1
fi

printf "\nResults: %d/%d passed ok\n" "${passed}" "${total}"
