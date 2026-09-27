#!/bin/bash
# Guard that Dependabot version updates stay frozen for private proof windows.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

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

assert_absent() {
    local label="$1"
    local path="$2"
    TOTAL=$((TOTAL + 1))

    if [ -e "${path}" ]; then
        fail "${label}" "${path} exists"
    else
        pass
    fi
}

assert_file_contains() {
    local label="$1"
    local file="$2"
    local needle="$3"
    TOTAL=$((TOTAL + 1))

    if grep -Fq -- "${needle}" "${file}"; then
        pass
    else
        fail "${label}" "${file} missing: ${needle}"
    fi
}

assert_file_exists() {
    local label="$1"
    local file="$2"
    TOTAL=$((TOTAL + 1))

    if [ -f "${file}" ]; then
        pass
    else
        fail "${label}" "${file} missing"
    fi
}

assert_executable_workflow_exists() {
    local label="$1"
    local file="$2"
    local workflow_name="$3"
    TOTAL=$((TOTAL + 1))

    if [ -f "${file}" ] && grep -Fq "name: ${workflow_name}" "${file}" && grep -Fq "branches" "${file}"; then
        pass
    else
        fail "${label}" "${file} missing expected workflow shape"
    fi
}

echo "=== Dependabot Version Updates Freeze Guard ==="

assert_absent "active dependabot yml is absent" ".github/dependabot.yml"
assert_absent "active dependabot yaml is absent" ".github/dependabot.yaml"

assert_file_exists "frozen dependabot config is preserved" ".github/dependabot.yml.frozen"
assert_file_contains "frozen file names freeze" ".github/dependabot.yml.frozen" "FROZEN: Dependabot version updates are intentionally disabled."
assert_file_contains "frozen file records workflow-disable blocker" ".github/dependabot.yml.frozen" "cannot be disabled through the normal Actions workflow-disable endpoint"
assert_file_contains "frozen file records restore path" ".github/dependabot.yml.frozen" ".github/dependabot.yml"
assert_file_contains "frozen file preserves version update config" ".github/dependabot.yml.frozen" "updates:"

assert_executable_workflow_exists "CI workflow remains present" ".github/workflows/ci.yml" "CI"
assert_executable_workflow_exists "CodeQL workflow remains present" ".github/workflows/codeql.yml" "CodeQL"
assert_executable_workflow_exists "Scorecard workflow remains present" ".github/workflows/scorecard.yml" "OpenSSF Scorecard"

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ok"
