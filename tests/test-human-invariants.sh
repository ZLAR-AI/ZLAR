#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Human Invariants — Test Suite
#
# Tests: H6 (decision cap), H13 (capacity), H14 (approval rate),
# H15 (deliberation floor), H17 (authenticity), combined checks.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail
# Note: set -e is NOT used here because human invariant functions return non-zero
# to signal violations (exceeded, overloaded, too_fast, etc.). This is intentional
# behavior, not an error.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
export ZLAR_PROJECT_DIR="${PROJECT_DIR}"

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf "${TEMP_DIR}"; }
trap cleanup EXIT

# Override state directory to temp
export _HI_PROJECT_DIR="${TEMP_DIR}"
mkdir -p "${TEMP_DIR}/var/human-state" "${TEMP_DIR}/var/log"

source "${PROJECT_DIR}/lib/human-invariants.sh"

PASS=0
FAIL=0
TOTAL=0

assert() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${expected}" == "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== H6: Decision Cap (No Throughput Pressure) ==="
echo

# Set low cap for testing
HI_DAILY_DECISION_CAP=3
HUMAN="test-human-h6"

# First 3 decisions should be ok
for i in 1 2 3; do
    hi_record_decision "${HUMAN}" "approve" || true
done
result=$(hi_check_capacity "${HUMAN}" 2>/dev/null || true)
assert "3 decisions at cap=3 → exceeded" "exceeded" "${result}"

# Under cap
HUMAN2="test-human-h6-under"
hi_record_decision "${HUMAN2}" "approve" || true
result2=$(hi_check_capacity "${HUMAN2}" 2>/dev/null || true)
assert "1 decision at cap=3 → ok" "ok" "${result2}"

# Reset cap
HI_DAILY_DECISION_CAP=80

echo
echo "=== H13: Judgment Must Be Over-Provisioned ==="
echo

HI_PENDING_CAP=2
HUMAN="test-human-h13"

r1=$(hi_increment_pending "${HUMAN}" 2>/dev/null)
assert "1 pending at cap=2 → ok" "ok" "${r1}"

r2=$(hi_increment_pending "${HUMAN}" 2>/dev/null)
assert "2 pending at cap=2 → ok" "ok" "${r2}"

r3=$(hi_increment_pending "${HUMAN}" 2>/dev/null)
assert "3 pending at cap=2 → overloaded" "overloaded" "${r3}"

hi_decrement_pending "${HUMAN}" 2>/dev/null
hi_decrement_pending "${HUMAN}" 2>/dev/null
r4=$(hi_increment_pending "${HUMAN}" 2>/dev/null)
assert "after decrement → ok again" "ok" "${r4}"

HI_PENDING_CAP=5

echo
echo "=== H15: Deliberation Floor ==="
echo

HUMAN="test-human-h15"
HI_DELIBERATION_FLOOR_CRITICAL=5
HI_DELIBERATION_FLOOR_WARN=3
HI_DELIBERATION_FLOOR_INFO=1

# Record ask time
hi_record_ask_time "${HUMAN}" 2>/dev/null

# Immediate check (0-1 seconds later) — should be too fast for critical
result=$(hi_check_deliberation "${HUMAN}" "critical" 2>/dev/null)
assert "immediate response to critical → too_fast" "too_fast" "${result}"

# Immediate check for info with 1s floor — might pass depending on timing
# Use a more reliable test: manually set ask_epoch to 10 seconds ago
state_file="${TEMP_DIR}/var/human-state/test-human-h15-elapsed.json"
epoch_ago=$(($(date +%s) - 10))
jq -n --argjson t "${epoch_ago}" '{human_id:"test-human-h15-elapsed",date:"2026-04-06",decisions_today:0,approvals_recent:[],pending_count:0,last_ask_epoch:$t}' > "${state_file}"

result2=$(hi_check_deliberation "test-human-h15-elapsed" "critical" 2>/dev/null)
assert "10s elapsed for critical (floor=5) → ok" "ok" "${result2}"

result3=$(hi_check_deliberation "test-human-h15-elapsed" "warn" 2>/dev/null)
assert "10s elapsed for warn (floor=3) → ok" "ok" "${result3}"

# Set ask_epoch to 2 seconds ago for warn test
epoch_2s=$(($(date +%s) - 2))
state_file_2s="${TEMP_DIR}/var/human-state/test-human-h15-2s.json"
jq -n --argjson t "${epoch_2s}" '{human_id:"test-human-h15-2s",date:"2026-04-06",decisions_today:0,approvals_recent:[],pending_count:0,last_ask_epoch:$t}' > "${state_file_2s}"

result4=$(hi_check_deliberation "test-human-h15-2s" "warn" 2>/dev/null)
assert "2s elapsed for warn (floor=3) → too_fast" "too_fast" "${result4}"

# Restore defaults
HI_DELIBERATION_FLOOR_CRITICAL=30
HI_DELIBERATION_FLOOR_WARN=10
HI_DELIBERATION_FLOOR_INFO=3

echo
echo "=== H17: Human Authenticity ==="
echo

HUMAN="test-human-h17"
HI_MIN_RESPONSE_TIME=3

# Record ask time and check immediately (< 3 seconds)
hi_record_ask_time "${HUMAN}" 2>/dev/null
result=$(hi_check_authenticity "${HUMAN}" 2>/dev/null)
assert "instant response → suspicious" "suspicious" "${result}"

# Set ask_epoch to 5 seconds ago
state_file_auth="${TEMP_DIR}/var/human-state/test-human-h17-ok.json"
epoch_5s=$(($(date +%s) - 5))
jq -n --argjson t "${epoch_5s}" '{human_id:"test-human-h17-ok",date:"2026-04-06",decisions_today:0,approvals_recent:[],pending_count:0,last_ask_epoch:$t}' > "${state_file_auth}"

result2=$(hi_check_authenticity "test-human-h17-ok" 2>/dev/null)
assert "5s elapsed (min=3) → ok" "ok" "${result2}"

HI_MIN_RESPONSE_TIME=2

echo
echo "=== H14: Approval Rate (Rubber-Stamp Detection) ==="
echo

HUMAN="test-human-h14"
HI_APPROVAL_RATE_THRESHOLD=80
HI_APPROVAL_RATE_WINDOW=10

# Not enough data yet
result=$(hi_check_approval_rate "${HUMAN}" 2>/dev/null)
assert "no data → ok (insufficient)" "ok" "${result}"

# Record 9 approvals and 1 denial (90% approval rate)
for i in $(seq 1 9); do
    hi_record_decision "${HUMAN}" "approve"
done
hi_record_decision "${HUMAN}" "deny"

result2=$(hi_check_approval_rate "${HUMAN}" 2>/dev/null)
assert "90% approval rate (threshold=80%) → rubber_stamping" "rubber_stamping" "${result2}"

# Record more denials to bring rate down
HUMAN_LOW="test-human-h14-low"
for i in $(seq 1 5); do
    hi_record_decision "${HUMAN_LOW}" "approve"
done
for i in $(seq 1 5); do
    hi_record_decision "${HUMAN_LOW}" "deny"
done

result3=$(hi_check_approval_rate "${HUMAN_LOW}" 2>/dev/null)
assert "50% approval rate → ok" "ok" "${result3}"

HI_APPROVAL_RATE_THRESHOLD=90
HI_APPROVAL_RATE_WINDOW=20

echo
echo "=== Combined: Pre-Ask Check ==="
echo

HUMAN="test-human-combined-pre"
HI_DAILY_DECISION_CAP=5
HI_PENDING_CAP=3

result=$(hi_pre_ask_check "${HUMAN}" 2>/dev/null)
assert "fresh human pre-ask → ok" "ok" "${result}"

# Exhaust daily cap
for i in $(seq 1 5); do
    hi_record_decision "${HUMAN}" "approve"
done
result2=$(hi_pre_ask_check "${HUMAN}" 2>/dev/null)
assert "exhausted cap pre-ask → capacity_exceeded" "capacity_exceeded" "${result2}"

HI_DAILY_DECISION_CAP=80
HI_PENDING_CAP=5

echo
echo "=== Combined: Post-Response Check ==="
echo

HUMAN="test-human-combined-post"
HI_MIN_RESPONSE_TIME=3
HI_DELIBERATION_FLOOR_CRITICAL=5

# Record ask, then check immediately
hi_record_ask_time "${HUMAN}" 2>/dev/null
hi_increment_pending "${HUMAN}" 2>/dev/null
result=$(hi_post_response_check "${HUMAN}" "critical" "approve" 2>/dev/null)
assert "instant critical approval → suspicious" "suspicious" "${result}"

# With enough elapsed time
state_file_ok="${TEMP_DIR}/var/human-state/test-human-post-ok.json"
epoch_20s=$(($(date +%s) - 20))
jq -n --argjson t "${epoch_20s}" '{human_id:"test-human-post-ok",date:"2026-04-06",decisions_today:0,approvals_recent:[],pending_count:1,last_ask_epoch:$t}' > "${state_file_ok}"

result2=$(hi_post_response_check "test-human-post-ok" "critical" "approve" 2>/dev/null)
assert "20s critical approval → ok" "ok" "${result2}"

HI_MIN_RESPONSE_TIME=2
HI_DELIBERATION_FLOOR_CRITICAL=30

echo
echo "=== State Persistence Across Calls ==="
echo

HUMAN="test-human-persist"
HI_DAILY_DECISION_CAP=100

hi_record_decision "${HUMAN}" "approve"
hi_record_decision "${HUMAN}" "deny"
hi_record_decision "${HUMAN}" "approve"

# Read state directly to verify persistence
state_file="${TEMP_DIR}/var/human-state/${HUMAN}.json"
count=$(jq -r '.decisions_today' "${state_file}" 2>/dev/null)
assert "decisions_today persisted" "3" "${count}"

approvals_len=$(jq -r '.approvals_recent | length' "${state_file}" 2>/dev/null)
assert "approvals_recent length" "3" "${approvals_len}"

# ─── Results ──────────────────────────────────────────────────────────────────

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [[ ${FAIL} -gt 0 ]]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
else
    echo " ✓"
fi
