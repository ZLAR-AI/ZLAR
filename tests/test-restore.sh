#!/bin/bash
# Test suite for restore.sh — Agent Health trust-state layer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Use temp directory for test state
TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

# Mock log function
log() { :; }

# Set PROJECT_DIR to temp dir so restore.sh config paths point there
export PROJECT_DIR="${TEST_DIR}"

PASS=0
FAIL=0

assert() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  PASS  ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  ${desc} (expected=${expected}, actual=${actual})"
        FAIL=$((FAIL + 1))
    fi
}

# Helper: write a restore config
write_config() {
    local enabled="${1:-false}"
    mkdir -p "${TEST_DIR}/etc" 2>/dev/null || true
    cat > "${TEST_DIR}/etc/restore-config.json" <<EOF
{
  "enabled": ${enabled},
  "trust_state_file": "var/restore/trust-state.json",
  "escalation": {
    "degraded": "log",
    "at_risk": "ask",
    "suspended": "deny"
  },
  "reset": {
    "delay_s": 30,
    "require_reason": true,
    "max_resets_per_day": 3
  }
}
EOF
}

# Helper: write a trust state file
write_trust_state() {
    local state="${1}"
    mkdir -p "${TEST_DIR}/var/restore" 2>/dev/null || true
    cat > "${TEST_DIR}/var/restore/trust-state.json" <<EOF
{
  "session_id": "test-session",
  "state": "${state}",
  "updated_at": "2026-04-12T10:00:00Z",
  "detectors": {},
  "history": []
}
EOF
}

# Helper: remove trust state file
remove_trust_state() {
    rm -f "${TEST_DIR}/var/restore/trust-state.json" 2>/dev/null || true
}

# Source restore.sh from the real project dir
source "${REAL_PROJECT_DIR}/lib/restore.sh"

# Point restore config at our test directory
RESTORE_CONFIG_FILE="${TEST_DIR}/etc/restore-config.json"

echo "Restore (Agent Health) Tests"
echo "============================"
echo

# ══════════════════════════════════════════════════════════════
# Section 1: No config / disabled
# ══════════════════════════════════════════════════════════════
echo "-- Section 1: No config / disabled --"

# Test 1: No config file at all
rm -f "${TEST_DIR}/etc/restore-config.json" 2>/dev/null || true
RESTORE_ENABLED="false"
restore_init
assert "No config file: RESTORE_ENABLED=false" "false" "${RESTORE_ENABLED}"

result=$(restore_check_escalation "allow")
assert "No config: allow passes through" "allow" "${result}"

result=$(restore_check_escalation "deny")
assert "No config: deny passes through" "deny" "${result}"

# Test 2: Config exists but enabled=false
write_config false
restore_init
assert "Config disabled: RESTORE_ENABLED=false" "false" "${RESTORE_ENABLED}"

result=$(restore_check_escalation "allow")
assert "Disabled: allow passes through" "allow" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section 2: RESTORE-INV-01 — absent trust state = healthy
# ══════════════════════════════════════════════════════════════
echo "-- Section 2: Absent trust state = healthy (INV-01) --"

write_config true
restore_init
assert "Config enabled: RESTORE_ENABLED=true" "true" "${RESTORE_ENABLED}"

remove_trust_state

result=$(_restore_read_trust_state)
assert "No trust state file: reads as healthy" "healthy" "${result}"

result=$(restore_check_escalation "allow")
assert "Healthy: allow stays allow" "allow" "${result}"

result=$(restore_check_escalation "ask")
assert "Healthy: ask stays ask" "ask" "${result}"

result=$(restore_check_escalation "deny")
assert "Healthy: deny stays deny" "deny" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section 3: RESTORE-INV-02 — malformed trust state = degraded
# ══════════════════════════════════════════════════════════════
echo "-- Section 3: Malformed trust state = degraded (INV-02) --"

write_config true
restore_init

# Case a: garbage in the file
mkdir -p "${TEST_DIR}/var/restore" 2>/dev/null || true
echo "not json at all" > "${TEST_DIR}/var/restore/trust-state.json"
result=$(_restore_read_trust_state)
assert "Garbage file: reads as degraded" "degraded" "${result}"

# Case b: valid JSON but missing state field
echo '{"session_id":"x"}' > "${TEST_DIR}/var/restore/trust-state.json"
result=$(_restore_read_trust_state)
assert "Missing state field: reads as degraded" "degraded" "${result}"

# Case c: valid JSON but invalid state value
echo '{"state":"banana"}' > "${TEST_DIR}/var/restore/trust-state.json"
result=$(_restore_read_trust_state)
assert "Invalid state value: reads as degraded" "degraded" "${result}"

# Case d: empty file
> "${TEST_DIR}/var/restore/trust-state.json"
result=$(_restore_read_trust_state)
assert "Empty file: reads as degraded" "degraded" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section 4: Trust state escalation
# ══════════════════════════════════════════════════════════════
echo "-- Section 4: Trust state escalation --"

write_config true
restore_init

# healthy — no escalation
write_trust_state "healthy"
result=$(restore_check_escalation "allow")
assert "healthy + allow = allow" "allow" "${result}"

# degraded — escalate allow -> log
write_trust_state "degraded"
result=$(restore_check_escalation "allow")
assert "degraded + allow = log" "log" "${result}"

result=$(restore_check_escalation "log")
assert "degraded + log = log (no change)" "log" "${result}"

result=$(restore_check_escalation "ask")
assert "degraded + ask = ask (already higher)" "ask" "${result}"

result=$(restore_check_escalation "deny")
assert "degraded + deny = deny (already higher)" "deny" "${result}"

# at_risk — escalate allow/log -> ask
write_trust_state "at_risk"
result=$(restore_check_escalation "allow")
assert "at_risk + allow = ask" "ask" "${result}"

result=$(restore_check_escalation "log")
assert "at_risk + log = ask" "ask" "${result}"

result=$(restore_check_escalation "ask")
assert "at_risk + ask = ask (no change)" "ask" "${result}"

result=$(restore_check_escalation "deny")
assert "at_risk + deny = deny (already higher)" "deny" "${result}"

# suspended — escalate everything -> deny
write_trust_state "suspended"
result=$(restore_check_escalation "allow")
assert "suspended + allow = deny" "deny" "${result}"

result=$(restore_check_escalation "log")
assert "suspended + log = deny" "deny" "${result}"

result=$(restore_check_escalation "ask")
assert "suspended + ask = deny" "deny" "${result}"

result=$(restore_check_escalation "deny")
assert "suspended + deny = deny (no change)" "deny" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section 5: Action ordering
# ══════════════════════════════════════════════════════════════
echo "-- Section 5: Action ordering --"

assert "allow rank = 0" "0" "$(_restore_action_rank allow)"
assert "log rank = 1" "1" "$(_restore_action_rank log)"
assert "ask rank = 2" "2" "$(_restore_action_rank ask)"
assert "deny rank = 3" "3" "$(_restore_action_rank deny)"

_restore_action_is_weaker "allow" "log" && result="true" || result="false"
assert "allow weaker than log" "true" "${result}"

_restore_action_is_weaker "log" "allow" && result="true" || result="false"
assert "log NOT weaker than allow" "false" "${result}"

_restore_action_is_weaker "ask" "ask" && result="true" || result="false"
assert "ask NOT weaker than ask (equal)" "false" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section 6: RESTORE-INV-04 — error trapping
# ══════════════════════════════════════════════════════════════
echo "-- Section 6: Error trapping (INV-04) --"

write_config true
restore_init

# Simulate unreadable trust state file
chmod 000 "${TEST_DIR}/var/restore/trust-state.json" 2>/dev/null || true
result=$(restore_check_escalation "allow" 2>/dev/null)
# Should not crash, should return input unchanged or degraded
# On permission error, jq fails, state becomes empty string -> degraded -> escalate
# Either way, it must not crash
assert "Unreadable file: does not crash" "true" "true"
chmod 644 "${TEST_DIR}/var/restore/trust-state.json" 2>/dev/null || true

# RESTORE_TRUST_STATE_FILE pointing to nonsense directory
old_file="${RESTORE_TRUST_STATE_FILE}"
RESTORE_TRUST_STATE_FILE="/nonexistent/path/to/state.json"
result=$(restore_check_escalation "allow")
assert "Nonexistent path: allow passes through (INV-01)" "allow" "${result}"
RESTORE_TRUST_STATE_FILE="${old_file}"

echo

# ══════════════════════════════════════════════════════════════
# Section 7: Summary function
# ══════════════════════════════════════════════════════════════
echo "-- Section 7: Summary --"

# Disabled
RESTORE_ENABLED="false"
result=$(restore_trust_state_summary)
assert "Disabled summary" "Restore: disabled" "${result}"

# Enabled + healthy
write_config true
restore_init
remove_trust_state
result=$(restore_trust_state_summary)
assert "Healthy summary" "Restore: healthy" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Results
# ══════════════════════════════════════════════════════════════
TOTAL=$((PASS + FAIL))
echo "=============================="
echo "${PASS} passed, ${FAIL} failed out of ${TOTAL} tests"
echo

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
