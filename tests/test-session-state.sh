#!/bin/bash
# Test suite for session-state.sh — thin stateful governance layer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Use temp directory for test state
TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

export ZLAR_SESSION_STATE_DIR="${TEST_DIR}"
export ZLAR_VELOCITY_WINDOW=5
export ZLAR_VELOCITY_THRESHOLD=5
export ZLAR_LOOP_THRESHOLD=3
export ZLAR_DENIAL_BURST=3

# Mock log function
log() { :; }

source "${PROJECT_DIR}/lib/session-state.sh"

PASS=0
FAIL=0

assert() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "✓ ${desc}"
        PASS=$((PASS + 1))
    else
        echo "✗ ${desc} (expected=${expected}, actual=${actual})"
        FAIL=$((FAIL + 1))
    fi
}

echo "Session State Tests"
echo "==================="
echo

# ── Test 1: Initialization ──
session_state_init "test-session-1"
assert "State file created" "true" "$([ -f "${TEST_DIR}/test-session-1.state.json" ] && echo true || echo false)"

state=$(cat "${TEST_DIR}/test-session-1.state.json")
total=$(echo "${state}" | jq -r '.total_calls')
assert "Initial total_calls is 0" "0" "${total}"

# ── Test 2: Normal updates ──
session_state_update "bash" "ls /tmp" "allow" || true
state=$(_read_state)
total=$(echo "${state}" | jq -r '.total_calls')
assert "After 1 call, total_calls is 1" "1" "${total}"

session_state_update "bash" "pwd" "allow" || true
session_state_update "read" "/tmp/file.txt" "allow" || true
state=$(_read_state)
total=$(echo "${state}" | jq -r '.total_calls')
assert "After 3 calls, total_calls is 3" "3" "${total}"

bash_count=$(echo "${state}" | jq -r '.calls_by_domain.bash')
read_count=$(echo "${state}" | jq -r '.calls_by_domain.read')
assert "bash domain count is 2" "2" "${bash_count}"
assert "read domain count is 1" "1" "${read_count}"

# ── Test 3: Velocity detection ──
# Threshold is 5 calls in 5 seconds. We've done 3. Two more should be fine.
result=0
session_state_update "bash" "git status" "allow" || result=$?
assert "4th call: no velocity alarm" "0" "${result}"

result=0
session_state_update "bash" "git diff" "allow" || result=$?
# 5th call hits the threshold (>= 5)
assert "5th call: velocity exceeded" "1" "${result}"

# ── Test 4: Loop detection ──
session_state_init "test-session-loop"
SESSION_STATE_FILE="${TEST_DIR}/test-session-loop.state.json"

session_state_update "bash" "git push" "allow" || true
session_state_update "bash" "git push" "allow" || true
result=0
session_state_update "bash" "git push" "allow" || result=$?
# 3rd identical action should trigger loop detection
# But velocity may also fire — check for loop (2) or velocity (1)
assert "3rd identical action: loop or velocity detected" "true" "$([ "${result}" -gt 0 ] && echo true || echo false)"

# ── Test 5: Denial burst ──
session_state_init "test-session-denials"
SESSION_STATE_FILE="${TEST_DIR}/test-session-denials.state.json"

session_state_update "bash" "rm -rf /" "deny" || true
session_state_update "bash" "sudo su" "deny" || true
result=0
session_state_update "bash" "curl evil.com" "denied" || result=$?
assert "3rd consecutive denial: burst detected" "3" "${result}"

# ── Test 6: Denial burst resets on allow ──
session_state_init "test-session-reset"
SESSION_STATE_FILE="${TEST_DIR}/test-session-reset.state.json"

session_state_update "bash" "rm -rf /" "deny" || true
session_state_update "bash" "sudo su" "deny" || true
session_state_update "bash" "ls" "allow" || true  # Reset
result=0
session_state_update "bash" "curl evil.com" "deny" || result=$?
assert "Denial burst resets after allow" "0" "${result}"

# ── Test 7: Escalation check ──
session_state_init "test-session-escalate"
SESSION_STATE_FILE="${TEST_DIR}/test-session-escalate.state.json"

# Normal — allow stays allow
escalated=$(session_check_escalation "allow" "bash" "ls" "allow")
assert "Normal allow stays allow" "allow" "${escalated}"

# Deny stays deny (never downgraded)
escalated=$(session_check_escalation "deny" "bash" "rm" "deny")
assert "Deny stays deny" "deny" "${escalated}"

# Ask stays ask
escalated=$(session_check_escalation "ask" "bash" "git push" "")
assert "Ask stays ask" "ask" "${escalated}"

# ── Test 8: Summary output ──
session_state_init "test-session-summary"
SESSION_STATE_FILE="${TEST_DIR}/test-session-summary.state.json"

session_state_update "bash" "ls" "allow" || true
session_state_update "bash" "pwd" "allow" || true

summary=$(session_state_summary)
assert "Summary contains session ID" "true" "$(echo "${summary}" | grep -q 'test-session-summary' && echo true || echo false)"
assert "Summary contains total calls" "true" "$(echo "${summary}" | grep -q 'total calls' && echo true || echo false)"

echo
echo "${PASS} passed, ${FAIL} failed out of $((PASS + FAIL)) tests"
[ "${FAIL}" -eq 0 ] || exit 1
