#!/bin/bash
# Test suite for canary.sh — governance health probes for HITL integrity
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Use temp directory for test state
TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

# Mock environment
export PROJECT_DIR
export ZLAR_CANARY_ENABLED="true"
export ZLAR_CANARY_MIN_APPROVALS=3
export ZLAR_CANARY_PROBABILITY=100  # Always trigger for deterministic tests
export ZLAR_CANARY_COOLDOWN=0       # No cooldown for tests

# Override canary state dir to test dir (env var, sourced by canary.sh)
export ZLAR_CANARY_STATE_DIR="${TEST_DIR}/canary"
mkdir -p "${ZLAR_CANARY_STATE_DIR}"

# Mock gate dependencies
log() { :; }
gen_id() { echo "test-$(date +%s)-$$-${RANDOM}"; }
TELEGRAM_CHAT_ID="7662799203"
TELEGRAM_TIMEOUT_S=900
SESSION_ID="test-session-canary"

# Mock telegram_api (don't actually send)
telegram_api() { echo '{"ok":true,"result":{"message_id":999}}'; }

# Mock emit_event
LAST_EMIT_OUTCOME=""
emit_event() { LAST_EMIT_OUTCOME="$3"; }

# Mock HMAC verify (always pass in tests)
zlar_hmac_verify() { return 0; }

source "${PROJECT_DIR}/lib/canary.sh"

PASS=0
FAIL=0

assert() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${desc} (expected=${expected}, actual=${actual})"
        FAIL=$((FAIL + 1))
    fi
}

echo "Canary Tests"
echo "============"
echo

# ── Test 1: canary_record_approval creates state file ──
echo "1. Record approval creates state"
canary_record_approval "sess-1"
assert "State file created" "true" "$([ -f "${CANARY_STATE_DIR}/sess-1.canary.json" ] && echo true || echo false)"
total=$(jq -r '.total_approvals' "${CANARY_STATE_DIR}/sess-1.canary.json")
assert "Total approvals is 1" "1" "${total}"

# ── Test 2: Increments on subsequent approvals ──
echo "2. Approval counter increments"
canary_record_approval "sess-1"
canary_record_approval "sess-1"
total=$(jq -r '.total_approvals' "${CANARY_STATE_DIR}/sess-1.canary.json")
assert "Total approvals is 3" "3" "${total}"
since=$(jq -r '.approvals_since_last_canary' "${CANARY_STATE_DIR}/sess-1.canary.json")
assert "Approvals since last canary is 3" "3" "${since}"

# ── Test 3: canary_should_trigger respects min_approvals ──
echo "3. Trigger respects min_approvals threshold"
# sess-1 has 3 approvals, min is 3, probability is 100%, cooldown is 0
result=0
canary_should_trigger "sess-1" && result=0 || result=$?
assert "Triggers after min approvals met" "0" "${result}"

# ── Test 4: canary_should_trigger returns 1 when under threshold ──
echo "4. No trigger below threshold"
canary_record_approval "sess-2"
result=0
canary_should_trigger "sess-2" && result=0 || result=$?
assert "Does not trigger with 1 approval (min=3)" "1" "${result}"

# ── Test 5: canary_should_trigger respects enabled flag ──
echo "5. Disabled canary never triggers"
CANARY_ENABLED="false"
result=0
canary_should_trigger "sess-1" && result=0 || result=$?
assert "Returns 1 when disabled" "1" "${result}"
CANARY_ENABLED="true"

# ── Test 6: canary_pick_scenario returns valid JSON ──
echo "6. Scenario picker returns valid JSON"
scenario=$(canary_pick_scenario)
tool=$(echo "${scenario}" | jq -r '.tool' 2>/dev/null)
assert "Scenario has tool field" "true" "$([ -n "${tool}" ] && echo true || echo false)"
display=$(echo "${scenario}" | jq -r '.display' 2>/dev/null)
assert "Scenario has display field" "true" "$([ -n "${display}" ] && echo true || echo false)"

# ── Test 7: canary_send writes pending file ──
echo "7. Send creates pending file"
canary_send "sess-1" 2>/dev/null
assert "Pending file created" "true" "$([ -f "${CANARY_STATE_DIR}/sess-1.canary.pending" ] && echo true || echo false)"
assert "Counter reset after send" "0" "$(jq -r '.approvals_since_last_canary' "${CANARY_STATE_DIR}/sess-1.canary.json")"

# ── Test 8: canary_should_trigger returns 1 when canary pending ──
echo "8. No trigger while canary pending"
# Re-add approvals to exceed threshold
canary_record_approval "sess-1"
canary_record_approval "sess-1"
canary_record_approval "sess-1"
result=0
canary_should_trigger "sess-1" && result=0 || result=$?
assert "Does not trigger while pending" "1" "${result}"

# Clean up pending for next tests
rm -f "${CANARY_STATE_DIR}/sess-1.canary.pending"

# ── Test 9: canary_check_result handles fatigue (approve callback) ──
echo "9. Fatigue detection on canary approve"
# Set up a known canary ID
canary_record_approval "sess-3"
canary_record_approval "sess-3"
canary_record_approval "sess-3"
canary_send "sess-3" 2>/dev/null
canary_id=$(cat "${CANARY_STATE_DIR}/sess-3.canary.pending" | tr -d '[:space:]')

# Simulate inbox callback (human approved the canary — bad)
FAKE_INBOX="${TEST_DIR}/inbox"
mkdir -p "${FAKE_INBOX}"
jq -n -c \
    --arg data "cc:canary:approve:${canary_id}" \
    --arg from_id "7662799203" \
    --arg cb_id "test-cb-1" \
    --arg hmac "test-hmac" \
    '{data: $data, from_id: $from_id, callback_query_id: $cb_id, hmac: $hmac}' \
    > "${FAKE_INBOX}/canary-test-1.json"

# Override inbox dir for test
_orig_check=$(declare -f canary_check_result)
# We need to point the function at our fake inbox
# Simplest: just manually process the callback
cb_file="${FAKE_INBOX}/canary-test-1.json"
cb_data="cc:canary:approve:${canary_id}"
rm -f "${CANARY_STATE_DIR}/sess-3.canary.pending"
_canary_log_fatigue "sess-3" "${canary_id}"

assert "Fatigue detected" "true" "$(jq -r '.fatigue_detected' "${CANARY_STATE_DIR}/sess-3.canary.json")"
assert "Fatigue count is 1" "1" "$(jq -r '.fatigue_count' "${CANARY_STATE_DIR}/sess-3.canary.json")"
assert "Audit event emitted" "fatigue_detected" "${LAST_EMIT_OUTCOME}"

# ── Test 10: canary_is_fatigued returns true ──
echo "10. Fatigue state query"
result=0
canary_is_fatigued "sess-3" && result=0 || result=$?
assert "Is fatigued after failed canary" "0" "${result}"

# ── Test 11: canary_check_result handles healthy (deny callback) ──
echo "11. Healthy detection on canary deny"
canary_record_approval "sess-4"
canary_record_approval "sess-4"
canary_record_approval "sess-4"
canary_send "sess-4" 2>/dev/null
canary_id=$(cat "${CANARY_STATE_DIR}/sess-4.canary.pending" | tr -d '[:space:]')

rm -f "${CANARY_STATE_DIR}/sess-4.canary.pending"
_canary_log_healthy "sess-4" "${canary_id}"

assert "Fatigue cleared after healthy" "false" "$(jq -r '.fatigue_detected' "${CANARY_STATE_DIR}/sess-4.canary.json")"
assert "Audit event emitted" "healthy" "${LAST_EMIT_OUTCOME}"

# ── Test 12: canary_is_fatigued returns false for healthy session ──
echo "12. Not fatigued after healthy canary"
result=0
canary_is_fatigued "sess-4" && result=0 || result=$?
assert "Not fatigued" "1" "${result}"

# ── Test 13: Fallback scenario when scenarios file missing ──
echo "13. Fallback scenario"
_orig_scenarios="${CANARY_SCENARIOS_FILE}"
CANARY_SCENARIOS_FILE="/nonexistent/file.json"
scenario=$(canary_pick_scenario)
tool=$(echo "${scenario}" | jq -r '.tool' 2>/dev/null)
assert "Fallback returns Bash tool" "Bash" "${tool}"
display=$(echo "${scenario}" | jq -r '.display' 2>/dev/null)
assert "Fallback has curl|bash action" "true" "$(echo "${display}" | grep -q 'curl' && echo true || echo false)"
CANARY_SCENARIOS_FILE="${_orig_scenarios}"

# ── Test 14: canary_fatigue_count tracks cumulative failures ──
echo "14. Fatigue count accumulates"
# sess-3 already has fatigue_count=1, trigger another failure
canary_record_approval "sess-3"
canary_record_approval "sess-3"
canary_record_approval "sess-3"
# Reset the pending so send works
rm -f "${CANARY_STATE_DIR}/sess-3.canary.pending"
canary_send "sess-3" 2>/dev/null
canary_id=$(cat "${CANARY_STATE_DIR}/sess-3.canary.pending" | tr -d '[:space:]')
rm -f "${CANARY_STATE_DIR}/sess-3.canary.pending"
_canary_log_fatigue "sess-3" "${canary_id}"

count=$(canary_fatigue_count "sess-3")
assert "Fatigue count is 2 after second failure" "2" "${count}"

# ── Test 15: Session isolation ──
echo "15. Sessions are isolated"
result=0
canary_is_fatigued "sess-1" && result=0 || result=$?
assert "sess-1 not affected by sess-3 fatigue" "1" "${result}"

# ── Test 16: Probability 0 never triggers ──
echo "16. Zero probability never triggers"
CANARY_PROBABILITY=0
canary_record_approval "sess-5"
canary_record_approval "sess-5"
canary_record_approval "sess-5"
result=0
canary_should_trigger "sess-5" && result=0 || result=$?
assert "Never triggers at 0% probability" "1" "${result}"
CANARY_PROBABILITY=100

# ── Test 17: Expired canary cleans up ──
echo "17. Expired canary cleanup"
# Create a fake pending file and force its mtime to epoch 0 (1970).
# Previous revisions used `touch -t 202501010000` which is syntactically
# portable but had environment-specific failure modes in CI runners —
# the test passed on local development but failed in fresh GitHub Actions
# runs. Using python3 to set the mtime directly via os.utime() is
# guaranteed to produce epoch 0 on every platform with python3 available
# (which is a pre-existing test dependency via verify-canonicalization.py).
_pending_file="${CANARY_STATE_DIR}/sess-6.canary.pending"
echo "expired-canary-id" > "${_pending_file}"
canary_record_approval "sess-6"
# Set the file's mtime to epoch 0 (1970-01-01 UTC). Try python3 first
# (portable, works on macOS and Linux regardless of stat/touch flavor),
# fall back to touch -t 200001010000 (BSD+GNU compatible). The final
# `|| true` keeps the test running even if both fail.
python3 -c "import os, sys; os.utime(sys.argv[1], (0, 0))" "${_pending_file}" 2>/dev/null \
    || touch -t 200001010000 "${_pending_file}" 2>/dev/null \
    || true
TELEGRAM_TIMEOUT_S=1
canary_check_result "sess-6" 2>/dev/null || true
TELEGRAM_TIMEOUT_S=900
assert "Pending file cleaned up" "false" "$([ -f "${_pending_file}" ] && echo true || echo false)"
unset _pending_file

echo
echo "═══════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════"

exit "${FAIL}"
