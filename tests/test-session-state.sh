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

# ════════════════════════════════════════════════════════════════════════
# Path B Phase 1: Seal, Verify, Rebuild
# ════════════════════════════════════════════════════════════════════════

echo
echo "Path B Phase 1 Tests"
echo "===================="
echo

# Set up mock audit trail
AUDIT_DIR="${TEST_DIR}/var/log"
mkdir -p "${AUDIT_DIR}"
export SESSION_AUDIT_FILE="${AUDIT_DIR}/audit.jsonl"

# Helper: write a mock audit event
write_audit_event() {
    local sid="$1" domain="$2" action="$3" outcome="$4" id="$5" seq="${6:-1}" risk="${7:-50}"
    echo "{\"id\":\"${id}\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"seq\":${seq},\"session_id\":\"${sid}\",\"domain\":\"${domain}\",\"action\":\"${action}\",\"outcome\":\"${outcome}\",\"risk_score\":${risk},\"rule\":\"R001\",\"severity\":\"info\",\"authorizer\":\"policy\"}" >> "${SESSION_AUDIT_FILE}"
}

# ── Test 9: Seal write and read ──
session_state_init "test-seal"
SESSION_STATE_FILE="${TEST_DIR}/test-seal.state.json"

_session_state_seal "evt-001"
sealed=$(jq -r '._last_audit_id' "${SESSION_STATE_FILE}")
assert "Seal writes audit ID to state" "evt-001" "${sealed}"

_session_state_seal "evt-002"
sealed=$(jq -r '._last_audit_id' "${SESSION_STATE_FILE}")
assert "Seal overwrites previous ID" "evt-002" "${sealed}"

# Verify state fields survive seal (seal only adds _last_audit_id)
total=$(jq -r '.total_calls' "${SESSION_STATE_FILE}")
assert "Seal preserves total_calls" "0" "${total}"

# ── Test 10: Verify — consistent state ──
session_state_init "test-verify-ok"
SESSION_STATE_FILE="${TEST_DIR}/test-verify-ok.state.json"

write_audit_event "test-verify-ok" "bash" "ls" "allow" "evt-v1"
write_audit_event "test-verify-ok" "bash" "pwd" "allow" "evt-v2"
_session_state_seal "evt-v2"

result=0
session_state_verify "test-verify-ok" || result=$?
assert "Verify passes for consistent seal" "0" "${result}"

# ── Test 11: Verify — stale state ──
write_audit_event "test-verify-ok" "bash" "git status" "allow" "evt-v3"
# State is sealed to evt-v2 but audit has evt-v3

result=0
session_state_verify "test-verify-ok" || result=$?
assert "Verify fails for stale seal" "1" "${result}"

# ── Test 12: Verify — no seal ──
session_state_init "test-verify-noseal"
SESSION_STATE_FILE="${TEST_DIR}/test-verify-noseal.state.json"
# Fresh state has empty _last_audit_id

result=0
session_state_verify "test-verify-noseal" || result=$?
assert "Verify fails for empty seal" "1" "${result}"

# ── Test 13: Rebuild from audit events ──
# Create audit events for a known session
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-rebuild" "bash" "ls /tmp" "allow" "evt-r1"
write_audit_event "test-rebuild" "bash" "pwd" "allow" "evt-r2"
write_audit_event "test-rebuild" "read" "/etc/hosts" "allow" "evt-r3"
write_audit_event "test-rebuild" "bash" "rm -rf /" "deny" "evt-r4"
write_audit_event "test-rebuild" "bash" "sudo su" "deny" "evt-r5"

SESSION_STATE_FILE="${TEST_DIR}/test-rebuild.state.json"
rm -f "${SESSION_STATE_FILE}"

result=0
session_state_rebuild "test-rebuild" || result=$?
assert "Rebuild succeeds" "0" "${result}"
assert "Rebuild creates state file" "true" "$([ -f "${SESSION_STATE_FILE}" ] && echo true || echo false)"

state=$(cat "${SESSION_STATE_FILE}")
total=$(echo "${state}" | jq -r '.total_calls')
assert "Rebuild: total_calls = 5" "5" "${total}"

bash_count=$(echo "${state}" | jq -r '.calls_by_domain.bash')
read_count=$(echo "${state}" | jq -r '.calls_by_domain.read')
assert "Rebuild: bash domain count = 4" "4" "${bash_count}"
assert "Rebuild: read domain count = 1" "1" "${read_count}"

denials=$(echo "${state}" | jq -r '.consecutive_denials')
assert "Rebuild: consecutive_denials = 2" "2" "${denials}"

last_action=$(echo "${state}" | jq -r '.recent_actions[-1]')
assert "Rebuild: last recent_action = sudo su" "sudo su" "${last_action}"

actions_len=$(echo "${state}" | jq -r '.recent_actions | length')
assert "Rebuild: recent_actions has 5 entries" "5" "${actions_len}"

sealed=$(echo "${state}" | jq -r '._last_audit_id')
assert "Rebuild: sealed to last event" "evt-r5" "${sealed}"

burst=$(echo "${state}" | jq -r '.denial_burst')
assert "Rebuild: denial_burst = false (2 < 3)" "false" "${burst}"

# ── Test 14: Rebuild with denial burst ──
write_audit_event "test-rebuild" "bash" "kill -9 1" "deny" "evt-r6"

rm -f "${SESSION_STATE_FILE}"
session_state_rebuild "test-rebuild"

state=$(cat "${SESSION_STATE_FILE}")
denials=$(echo "${state}" | jq -r '.consecutive_denials')
assert "Rebuild: consecutive_denials = 3 after third deny" "3" "${denials}"
burst=$(echo "${state}" | jq -r '.denial_burst')
assert "Rebuild: denial_burst = true (3 >= 3)" "true" "${burst}"

# ── Test 15: Rebuild with loop detection ──
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-loop-rebuild" "bash" "git push" "allow" "evt-l1"
write_audit_event "test-loop-rebuild" "bash" "git push" "allow" "evt-l2"
write_audit_event "test-loop-rebuild" "bash" "git push" "allow" "evt-l3"

SESSION_STATE_FILE="${TEST_DIR}/test-loop-rebuild.state.json"
session_state_rebuild "test-loop-rebuild"

state=$(cat "${SESSION_STATE_FILE}")
loops=$(echo "${state}" | jq -r '.loop_count')
assert "Rebuild: loop_count = 3" "3" "${loops}"
loop_detected=$(echo "${state}" | jq -r '.loop_detected')
assert "Rebuild: loop_detected = true (3 >= 3)" "true" "${loop_detected}"

# ── Test 16: Rebuild skips seq>=2 events ──
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-seq2" "bash" "git push" "ask_pending" "evt-s1" 1
write_audit_event "test-seq2" "bash" "git push" "authorized" "evt-s2" 2

SESSION_STATE_FILE="${TEST_DIR}/test-seq2.state.json"
session_state_rebuild "test-seq2"

state=$(cat "${SESSION_STATE_FILE}")
total=$(echo "${state}" | jq -r '.total_calls')
assert "Rebuild: seq=2 events excluded (total=1)" "1" "${total}"

# ── Test 17: Init auto-rebuilds from audit ──
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-auto-rebuild" "bash" "ls" "allow" "evt-a1"
write_audit_event "test-auto-rebuild" "read" "/tmp" "allow" "evt-a2"

SESSION_STATE_FILE="${TEST_DIR}/test-auto-rebuild.state.json"
rm -f "${SESSION_STATE_FILE}"

session_state_init "test-auto-rebuild"
assert "Auto-rebuild creates state file" "true" "$([ -f "${SESSION_STATE_FILE}" ] && echo true || echo false)"

state=$(cat "${SESSION_STATE_FILE}")
total=$(echo "${state}" | jq -r '.total_calls')
assert "Auto-rebuild: total_calls = 2" "2" "${total}"

# ── Test 18: Init creates fresh when no audit events ──
rm -f "${SESSION_AUDIT_FILE}"
SESSION_STATE_FILE="${TEST_DIR}/test-fresh-init.state.json"
rm -f "${SESSION_STATE_FILE}"

session_state_init "test-fresh-init"
assert "Fresh init creates state file" "true" "$([ -f "${SESSION_STATE_FILE}" ] && echo true || echo false)"

state=$(cat "${SESSION_STATE_FILE}")
total=$(echo "${state}" | jq -r '.total_calls')
assert "Fresh init: total_calls = 0" "0" "${total}"

sealed=$(echo "${state}" | jq -r '._last_audit_id')
assert "Fresh init: empty seal" "" "${sealed}"

# ── Test 19: Rebuild with no events returns 1 ──
rm -f "${SESSION_AUDIT_FILE}"
touch "${SESSION_AUDIT_FILE}"

result=0
session_state_rebuild "nonexistent-session" || result=$?
assert "Rebuild returns 1 for no events" "1" "${result}"

# ── Test 20: Verify after rebuild is consistent ──
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-verify-rebuild" "bash" "ls" "allow" "evt-vr1"
write_audit_event "test-verify-rebuild" "bash" "pwd" "allow" "evt-vr2"

SESSION_STATE_FILE="${TEST_DIR}/test-verify-rebuild.state.json"
session_state_rebuild "test-verify-rebuild"

result=0
session_state_verify "test-verify-rebuild" || result=$?
assert "Verify passes after rebuild" "0" "${result}"

# ── Test 21: Init rebuilds stale EXISTING state file ──
# This is the Item 1 fix: if the state file EXISTS but its seal
# is behind the audit trail, init should detect staleness and rebuild.
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-stale-init" "bash" "ls" "allow" "evt-si1"
write_audit_event "test-stale-init" "bash" "pwd" "allow" "evt-si2"

SESSION_STATE_FILE="${TEST_DIR}/test-stale-init.state.json"
session_state_rebuild "test-stale-init"

# State is sealed to evt-si2, total_calls=2
total_before=$(jq -r '.total_calls' "${SESSION_STATE_FILE}")
assert "Pre-stale: total_calls = 2" "2" "${total_before}"

# Now add more audit events AFTER the seal
write_audit_event "test-stale-init" "read" "/etc/hosts" "allow" "evt-si3"
write_audit_event "test-stale-init" "bash" "git status" "allow" "evt-si4"

# Re-init — file exists, seal is stale (evt-si2 vs evt-si4)
session_state_init "test-stale-init"

total_after=$(jq -r '.total_calls' "${SESSION_STATE_FILE}")
assert "Stale init rebuilds: total_calls = 4" "4" "${total_after}"

sealed=$(jq -r '._last_audit_id' "${SESSION_STATE_FILE}")
assert "Stale init rebuilds: sealed to last event" "evt-si4" "${sealed}"

# ── Test 22: Init skips rebuild for consistent EXISTING state file ──
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-fresh-existing" "bash" "ls" "allow" "evt-fe1"

SESSION_STATE_FILE="${TEST_DIR}/test-fresh-existing.state.json"
session_state_rebuild "test-fresh-existing"

# State is consistent — no new events after seal
session_state_init "test-fresh-existing"

total=$(jq -r '.total_calls' "${SESSION_STATE_FILE}")
assert "Consistent init: total_calls unchanged = 1" "1" "${total}"

sealed=$(jq -r '._last_audit_id' "${SESSION_STATE_FILE}")
assert "Consistent init: seal unchanged" "evt-fe1" "${sealed}"

# ── Test 23: Init rebuilds pre-Phase-B state file (no seal) ──
rm -f "${SESSION_AUDIT_FILE}"
write_audit_event "test-preseal" "bash" "ls" "allow" "evt-ps1"
write_audit_event "test-preseal" "bash" "pwd" "allow" "evt-ps2"

SESSION_STATE_FILE="${TEST_DIR}/test-preseal.state.json"
# Create a pre-Phase-B state file (no _last_audit_id field)
echo '{"session_id":"test-preseal","started":"2026-04-12T00:00:00Z","total_calls":1,"calls_by_domain":{"bash":1},"recent_timestamps":[],"recent_actions":["ls"],"consecutive_denials":0,"escalations":0}' > "${SESSION_STATE_FILE}"

session_state_init "test-preseal"

total=$(jq -r '.total_calls' "${SESSION_STATE_FILE}")
assert "Pre-seal init rebuilds: total_calls = 2" "2" "${total}"

sealed=$(jq -r '._last_audit_id' "${SESSION_STATE_FILE}")
assert "Pre-seal init rebuilds: seal set" "evt-ps2" "${sealed}"

echo
echo "${PASS} passed, ${FAIL} failed out of $((PASS + FAIL)) tests"
[ "${FAIL}" -eq 0 ] || exit 1
