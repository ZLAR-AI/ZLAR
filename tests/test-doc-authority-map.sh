#!/bin/bash
# Guard that high-risk stale-map docs carry routing authority labels.
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

assert_contains() {
    local label="$1"
    local file="$2"
    local pattern="$3"
    TOTAL=$((TOTAL + 1))

    if grep -Eq "${pattern}" "${file}"; then
        pass
    else
        fail "${label}" "${file} missing pattern: ${pattern}"
    fi
}

assert_top_contains() {
    local label="$1"
    local file="$2"
    local pattern="$3"
    TOTAL=$((TOTAL + 1))

    if sed -n '1,12p' "${file}" | grep -Eq "${pattern}"; then
        pass
    else
        fail "${label}" "${file} missing top-of-file pattern: ${pattern}"
    fi
}

echo "=== Documentation Authority Map Guard ==="

for file in \
    docs/operator-loop.md \
    docs/troubleshooting.md \
    docs/token-rotation.md \
    docs/architecture-map.md
do
    assert_top_contains "${file} has authority label" "${file}" '^> Authority label: '
    assert_top_contains "${file} has routing rule" "${file}" '^> Routing rule: '
done

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ok"
