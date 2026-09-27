#!/bin/bash
# Static regression checks for stabilization entrypoint scripts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
INSTALLER="${PROJECT_DIR}/install.sh"
QUICKSTART="${PROJECT_DIR}/scripts/quickstart.sh"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

assert_contains() {
    local label="$1" needle="$2" file="$3"
    if grep -Fq -- "${needle}" "${file}"; then
        pass "${label}"
    else
        fail "${label}"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" file="$3"
    if grep -Fq -- "${needle}" "${file}"; then
        fail "${label}"
    else
        pass "${label}"
    fi
}

assert_syntax() {
    local label="$1" file="$2"
    if bash -n "${file}"; then
        pass "${label}"
    else
        fail "${label}"
    fi
}

echo "=== Stabilization Scripts ==="
echo

assert_syntax "installer parses" "${INSTALLER}"
assert_syntax "quickstart parses" "${QUICKSTART}"

assert_not_contains "installer has no stale fallback version" 'ZLAR_VERSION="3.0.0"' "${INSTALLER}"
assert_contains "installer leaves unknown version unresolved" 'ZLAR_VERSION=""' "${INSTALLER}"
assert_contains "installer derives version from selected source" 'if [ -f "${SCRIPT_SOURCE_DIR}/VERSION" ]; then' "${INSTALLER}"
assert_contains "installer fails if source version is missing" 'Source at ${SCRIPT_SOURCE_DIR} has no VERSION file' "${INSTALLER}"

assert_not_contains "quickstart does not append fallback JSON after gate" "|| echo '{}'" "${QUICKSTART}"
assert_contains "quickstart captures gate process status" 'GATE_STATUS=$?' "${QUICKSTART}"
assert_contains "quickstart expects deny exit code 2" '[ "${DECISION2}" = "deny" ] && [ "${STATUS2}" -eq 2 ]' "${QUICKSTART}"
assert_contains "quickstart checks privilege-deny exit code 2" '[ "${DECISION4}" = "deny" ] && [ "${STATUS4}" -eq 2 ]' "${QUICKSTART}"

echo
echo "${PASS} passed, ${FAIL} failed out of $((PASS + FAIL)) tests"
[ "${FAIL}" -eq 0 ] || exit 1
