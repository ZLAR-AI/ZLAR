#!/bin/bash
# Public privacy hygiene guards for tracked examples and fixtures.
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

assert_no_tracked_fixed() {
    local label="$1"
    local needle="$2"
    TOTAL=$((TOTAL + 1))

    local matches
    if matches=$(git grep -n -F "${needle}" -- . 2>/dev/null); then
        fail "${label}" "${matches}"
    else
        pass
    fi
}

assert_no_tracked_regex() {
    local label="$1"
    local pattern="$2"
    TOTAL=$((TOTAL + 1))

    local matches
    if matches=$(git grep -n -E "${pattern}" -- . 2>/dev/null); then
        fail "${label}" "${matches}"
    else
        pass
    fi
}

assert_gate_json_not_committed_with_numeric_chat_id() {
    TOTAL=$((TOTAL + 1))

    if ! git ls-files --error-unmatch etc/gate.json >/dev/null 2>&1; then
        pass
        return
    fi

    local chat_id
    chat_id=$(jq -r '.telegram.chat_id // ""' etc/gate.json 2>/dev/null || echo "")
    if [[ "${chat_id}" =~ ^[0-9]{7,}$ ]]; then
        fail "tracked etc/gate.json must not contain a numeric Telegram chat id" "etc/gate.json telegram.chat_id=${chat_id}"
    else
        pass
    fi
}

assert_gate_example_uses_placeholder() {
    TOTAL=$((TOTAL + 1))

    local chat_id
    chat_id=$(jq -r '.telegram.chat_id // ""' etc/gate.example.json 2>/dev/null || echo "")
    if [[ "${chat_id}" =~ ^[0-9]{7,}$ ]]; then
        fail "gate example must use a placeholder chat id" "etc/gate.example.json telegram.chat_id=${chat_id}"
    else
        pass
    fi
}

echo "=== Public Privacy Hygiene ==="

private_user="vincentnijjar"
private_given="vincent"
private_path="/Users/${private_user}"
private_fixture_user='"user"[[:space:]]*:[[:space:]]*"'"${private_given}"'"'

assert_gate_json_not_committed_with_numeric_chat_id
assert_gate_example_uses_placeholder
assert_no_tracked_fixed "no tracked private local user path" "${private_path}"
assert_no_tracked_regex "no tracked fixture user named after operator" "${private_fixture_user}"
assert_no_tracked_regex "no tracked Telegram-shaped human authorizer examples" 'human:[0-9]{7,}'

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ✓"
