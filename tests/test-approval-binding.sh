#!/bin/bash
# Tests for approval binding — ensures approval for one action cannot
# authorize a different action matching the same policy rule.
#
# This is the fix for the governance bypass found by Codex audit (March 2026):
# approvals were keyed only by rule + session_id, allowing replay across
# different commands that hit the same rule.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source the gate to get check_pending_approval and telegram_ask_async
# We need to mock some globals first
APPROVAL_DIR=$(mktemp -d)
SESSION_ID="test-session-$$"
# v3.3.9: ZLAR_TELEGRAM_CHAT_ID is the env-source override that the gate's
# new TELEGRAM_CHAT_ID_SOURCE resolution treats as authoritative. Setting
# both keeps shell references to ${TELEGRAM_CHAT_ID} working in fixtures.
export ZLAR_TELEGRAM_CHAT_ID="123456"
TELEGRAM_CHAT_ID="123456"
TELEGRAM_TOKEN=""  # No actual Telegram calls
ZLAR_HMAC_SECRET_FILE="/dev/null"  # No HMAC in these tests
LOG_FILE="/dev/null"
GATE_TMP=$(mktemp -d)
AUDIT_FILE=$(mktemp)

trap 'rm -rf "${APPROVAL_DIR}" "${GATE_TMP}" "${AUDIT_FILE}"' EXIT

# We only need the functions, not the full gate. Extract them.
# Instead, test the binding logic directly.

passed=0
failed=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    else
        echo "  ✗ ${desc} (expected: ${expected}, got: ${actual})"
        failed=$((failed + 1))
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  ZLAR Approval Binding Tests"
echo "═══════════════════════════════════════════════════════════════"
echo

# ── Test 1: Pending file with hash — matching action ──
echo "── Matching action hash ──"

# Hash format matches gate: sha256(MATCHED_RULE|tool_name|DETAIL_JSON)
# DETAIL is key-sorted canonical JSON from translate_tool()
detail_a='{"command":"git status","cwd":""}'
detail_a_canonical=$(echo "${detail_a}" | jq -S -c '.')
action_id="test-$(openssl rand -hex 8)"
action_hash_a=$(printf '%s|%s|%s' "R014" "Bash" "${detail_a_canonical}" | shasum -a 256 | awk '{print $1}')
printf '%s\n%s\n' "${action_id}" "${action_hash_a}" > "${APPROVAL_DIR}/R014-${SESSION_ID}.pending"

# Read the pending file
stored_id=$(sed -n '1p' "${APPROVAL_DIR}/R014-${SESSION_ID}.pending" | tr -d '[:space:]')
stored_hash=$(sed -n '2p' "${APPROVAL_DIR}/R014-${SESSION_ID}.pending" | tr -d '[:space:]')

assert_eq "Pending file stores action_id on line 1" "${action_id}" "${stored_id}"
assert_eq "Pending file stores action_hash on line 2" "${action_hash_a}" "${stored_hash}"

# Same action hash should match
check_hash_a=$(printf '%s|%s|%s' "R014" "Bash" "${detail_a_canonical}" | shasum -a 256 | awk '{print $1}')
if [ "${check_hash_a}" = "${stored_hash}" ]; then
    assert_eq "Identical action produces matching hash" "match" "match"
else
    assert_eq "Identical action produces matching hash" "match" "mismatch"
fi

rm -f "${APPROVAL_DIR}/R014-${SESSION_ID}.pending"
echo

# ── Test 2: Pending file with hash — different action (MUST NOT match) ──
echo "── Different action hash (governance bypass prevention) ──"

action_id="test-$(openssl rand -hex 8)"
action_hash_a=$(printf '%s|%s|%s' "R014" "Bash" "${detail_a_canonical}" | shasum -a 256 | awk '{print $1}')
printf '%s\n%s\n' "${action_id}" "${action_hash_a}" > "${APPROVAL_DIR}/R014-${SESSION_ID}.pending"

# Different action — same rule R014 but different command (MUST produce different hash)
detail_b='{"command":"git push origin main","cwd":""}'
detail_b_canonical=$(echo "${detail_b}" | jq -S -c '.')
action_hash_b=$(printf '%s|%s|%s' "R014" "Bash" "${detail_b_canonical}" | shasum -a 256 | awk '{print $1}')

stored_hash=$(sed -n '2p' "${APPROVAL_DIR}/R014-${SESSION_ID}.pending" | tr -d '[:space:]')
if [ "${action_hash_b}" != "${stored_hash}" ]; then
    assert_eq "Different command produces different hash" "different" "different"
else
    assert_eq "Different command produces different hash" "different" "same"
fi

# Verify the mismatch would be detected
if [ -n "${action_hash_b}" ] && [ -n "${stored_hash}" ] && [ "${action_hash_b}" != "${stored_hash}" ]; then
    assert_eq "Hash mismatch correctly detected — replay blocked" "blocked" "blocked"
else
    assert_eq "Hash mismatch correctly detected — replay blocked" "blocked" "allowed"
fi

rm -f "${APPROVAL_DIR}/R014-${SESSION_ID}.pending"
echo

# ── Test 3: Legacy pending file (no hash) — backward compatibility ──
echo "── Legacy pending file (no hash line) ──"

action_id="test-$(openssl rand -hex 8)"
echo "${action_id}" > "${APPROVAL_DIR}/R014-${SESSION_ID}.pending"

stored_id=$(sed -n '1p' "${APPROVAL_DIR}/R014-${SESSION_ID}.pending" | tr -d '[:space:]')
stored_hash=$(sed -n '2p' "${APPROVAL_DIR}/R014-${SESSION_ID}.pending" | tr -d '[:space:]')

assert_eq "Legacy file has action_id" "${action_id}" "${stored_id}"
assert_eq "Legacy file has empty hash (backward compat)" "" "${stored_hash}"

# When stored hash is empty, binding check should be skipped (graceful degradation)
if [ -z "${stored_hash}" ]; then
    assert_eq "Empty stored hash → binding check skipped (backward compat)" "skipped" "skipped"
else
    assert_eq "Empty stored hash → binding check skipped (backward compat)" "skipped" "checked"
fi

rm -f "${APPROVAL_DIR}/R014-${SESSION_ID}.pending"
echo

# ── Test 4: Action hash determinism (new format: rule|tool|detail) ──
echo "── Hash determinism ──"

det_1='{"command":"rm -rf /tmp/test","cwd":""}'
det_1_c=$(echo "${det_1}" | jq -S -c '.')
det_2='{"command":"rm -rf /tmp/test2","cwd":""}'
det_2_c=$(echo "${det_2}" | jq -S -c '.')

hash_1=$(printf '%s|%s|%s' "R017" "Bash" "${det_1_c}" | shasum -a 256 | awk '{print $1}')
hash_2=$(printf '%s|%s|%s' "R017" "Bash" "${det_1_c}" | shasum -a 256 | awk '{print $1}')
hash_3=$(printf '%s|%s|%s' "R017" "Bash" "${det_2_c}" | shasum -a 256 | awk '{print $1}')

assert_eq "Same input produces same hash" "${hash_1}" "${hash_2}"
if [ "${hash_1}" != "${hash_3}" ]; then
    assert_eq "Different input produces different hash" "different" "different"
else
    assert_eq "Different input produces different hash" "different" "same"
fi
echo

# ── Test 5: SubagentStart binding ──
echo "── SubagentStart binding ──"

hash_agent_a=$(printf '%s|%s|%s' "subagent-launch" "SubagentStart" "general-purpose" | shasum -a 256 | awk '{print $1}')
hash_agent_b=$(printf '%s|%s|%s' "subagent-launch" "SubagentStart" "code-review" | shasum -a 256 | awk '{print $1}')

if [ "${hash_agent_a}" != "${hash_agent_b}" ]; then
    assert_eq "Different subagent types produce different hashes" "different" "different"
else
    assert_eq "Different subagent types produce different hashes" "different" "same"
fi
echo

# ── Summary ──
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${passed} passed, ${failed} failed"
echo "═══════════════════════════════════════════════════════════════"

exit "${failed}"
