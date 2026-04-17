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
echo "=== H13: Action Hash Dedup (v2.8.0 — retry idempotency) ==="
echo

# Regression test for the April 9 2026 incident. Claude Code's
# deny-then-retry pattern meant every gate invocation for the same logical
# ask called hi_increment_pending, pumping the counter through the cap
# before the human had a chance to approve. The fix is to dedupe by
# action_hash so repeated calls with the same hash never add a new entry.

HI_PENDING_CAP=3
HUMAN="test-human-h13-dedup"
state_file_dedup="${TEMP_DIR}/var/human-state/${HUMAN}.json"

# Same action_hash five times: should never exceed 1 pending.
r_d1=$(hi_increment_pending "${HUMAN}" "hash-retry-abc" 2>/dev/null)
assert "retry 1 with same hash at cap=3 → ok" "ok" "${r_d1}"

r_d2=$(hi_increment_pending "${HUMAN}" "hash-retry-abc" 2>/dev/null)
assert "retry 2 with same hash at cap=3 → ok" "ok" "${r_d2}"

r_d3=$(hi_increment_pending "${HUMAN}" "hash-retry-abc" 2>/dev/null)
assert "retry 3 with same hash at cap=3 → ok" "ok" "${r_d3}"

r_d4=$(hi_increment_pending "${HUMAN}" "hash-retry-abc" 2>/dev/null)
assert "retry 4 with same hash at cap=3 → ok" "ok" "${r_d4}"

r_d5=$(hi_increment_pending "${HUMAN}" "hash-retry-abc" 2>/dev/null)
assert "retry 5 with same hash at cap=3 → ok" "ok" "${r_d5}"

len_after_retries=$(jq -r '.pending | length' "${state_file_dedup}")
assert "5 retries with same hash → pending length is 1" "1" "${len_after_retries}"

# Two more DISTINCT hashes: length becomes 3 (still at cap, not over).
hi_increment_pending "${HUMAN}" "hash-distinct-B" 2>/dev/null >/dev/null
hi_increment_pending "${HUMAN}" "hash-distinct-C" 2>/dev/null >/dev/null
len_distinct=$(jq -r '.pending | length' "${state_file_dedup}")
assert "retry + 2 distinct → pending length is 3" "3" "${len_distinct}"

# Fourth DISTINCT hash exceeds cap=3.
r_over=$(hi_increment_pending "${HUMAN}" "hash-distinct-D" 2>/dev/null)
assert "4th distinct hash at cap=3 → overloaded" "overloaded" "${r_over}"

# Length stays at 3 because the overloaded path does not append.
len_after_over=$(jq -r '.pending | length' "${state_file_dedup}")
assert "overloaded path does not append → length still 3" "3" "${len_after_over}"

# A retry of an ALREADY-pending hash while AT cap is still ok (not overloaded).
# This is the critical Claude Code retry-loop case.
r_retry_at_cap=$(hi_increment_pending "${HUMAN}" "hash-retry-abc" 2>/dev/null)
assert "retry of pending hash at cap → ok (not overloaded)" "ok" "${r_retry_at_cap}"

# Decrement by specific hash removes that exact entry.
hi_decrement_pending "${HUMAN}" "hash-distinct-B" 2>/dev/null
len_after_dec=$(jq -r '.pending | length' "${state_file_dedup}")
assert "decrement by hash → length 2" "2" "${len_after_dec}"

has_B=$(jq -r '[.pending[] | select(.action_hash == "hash-distinct-B")] | length' "${state_file_dedup}")
assert "decrement by hash → specific hash removed" "0" "${has_B}"

has_retry=$(jq -r '[.pending[] | select(.action_hash == "hash-retry-abc")] | length' "${state_file_dedup}")
assert "decrement by hash → untargeted hash still present" "1" "${has_retry}"

# Decrement for a hash that does not exist is a no-op (not an error).
hi_decrement_pending "${HUMAN}" "hash-nonexistent" 2>/dev/null
len_after_noop=$(jq -r '.pending | length' "${state_file_dedup}")
assert "decrement by unknown hash → length unchanged" "2" "${len_after_noop}"

HI_PENDING_CAP=5

echo
echo "=== H13: TTL Expiration (v2.8.0 — orphan cleanup) ==="
echo

# Regression test for the orphaned-increment failure mode: if the
# post-response path is skipped (gate crashed, standing approval bypassed
# the flow, Claude pivoted before retrying), the pending entry must age out
# automatically rather than drift the counter permanently. Orphans were the
# second half of the April 9 incident — retry double-counting pumped the
# counter up, and nothing ever brought it down.

HUMAN_TTL="test-human-h13-ttl"
state_file_ttl="${TEMP_DIR}/var/human-state/${HUMAN_TTL}.json"

# Short TTL so the test runs in human time, not 30 min.
HI_PENDING_TTL=5
HI_PENDING_CAP=3

# Seed the file with three entries aged well beyond the TTL.
today_ttl=$(date -u +%Y-%m-%d)
stale_ts=$(($(date +%s) - 100))
jq -n --arg hid "${HUMAN_TTL}" --arg d "${today_ttl}" --argjson stale "${stale_ts}" '
    {human_id: $hid, date: $d, decisions_today: 0, approvals_recent: [], last_ask_epoch: 0,
     pending: [
       {action_hash: "stale-A", ts: $stale},
       {action_hash: "stale-B", ts: $stale},
       {action_hash: "stale-C", ts: $stale}
     ]}' > "${state_file_ttl}"

# Stale entries present before filter.
len_before_ttl=$(jq -r '.pending | length' "${state_file_ttl}")
assert "ttl: 3 stale entries present before filter" "3" "${len_before_ttl}"

# A fresh increment should filter all 3 stale entries and add 1 new entry.
# The stale entries do NOT count toward the cap even though the file says
# there are 3 pending and cap=3 — they've timed out.
r_after_stale=$(hi_increment_pending "${HUMAN_TTL}" "fresh-D" 2>/dev/null)
assert "ttl: increment after 3 stale → ok (stale filtered, not counted)" "ok" "${r_after_stale}"

len_after_ttl=$(jq -r '.pending | length' "${state_file_ttl}")
assert "ttl: length after filter + add is 1" "1" "${len_after_ttl}"

# None of the stale entries should remain.
has_stale=$(jq -r '[.pending[] | select(.action_hash | startswith("stale-"))] | length' "${state_file_ttl}")
assert "ttl: all stale entries filtered out" "0" "${has_stale}"

has_fresh=$(jq -r '[.pending[] | select(.action_hash == "fresh-D")] | length' "${state_file_ttl}")
assert "ttl: fresh entry present" "1" "${has_fresh}"

# Restore defaults.
HI_PENDING_TTL=1800
HI_PENDING_CAP=5

echo
echo "=== H13: Schema Migration from v2.7.x Scalar (v2.8.0) ==="
echo

# Regression test for the April 9 2026 rescue path. A state file written
# by v2.7.x with pending_count above the cap must auto-heal on first
# v2.8.0 access. The scalar is dropped, the array starts empty, and the
# next ask finds capacity again. No manual reset required — this is what
# unblocks a production human without human intervention.

HUMAN_MIGRATE="test-human-h13-migrate"
state_file_migrate="${TEMP_DIR}/var/human-state/${HUMAN_MIGRATE}.json"

# Seed with the exact shape of the April 9 production incident:
# pending_count scalar ABOVE the cap, no pending array, today's date
# (so rollover does NOT kick in — only the mid-day migration path does).
today_migrate=$(date -u +%Y-%m-%d)
jq -n --arg hid "${HUMAN_MIGRATE}" --arg d "${today_migrate}" '
    {human_id: $hid, date: $d, decisions_today: 0, approvals_recent: [], pending_count: 6, last_ask_epoch: 0}
' > "${state_file_migrate}"

# Verify the file is in the OLD shape before first v2.8.0 access.
has_old_before=$(jq -r 'has("pending_count")' "${state_file_migrate}")
assert "migration: pre-check has pending_count scalar" "true" "${has_old_before}"

# First call triggers migration via _hi_ensure_state. Without the migration,
# this would return "overloaded" (6 > 5) — the exact bug that locked the
# gate on April 9.
r_migrate=$(hi_increment_pending "${HUMAN_MIGRATE}" "post-migration-A" 2>/dev/null)
assert "migration: increment after old schema → ok (was overloaded in v2.7.x)" "ok" "${r_migrate}"

# pending_count must be gone.
has_old_after=$(jq -r 'has("pending_count")' "${state_file_migrate}")
assert "migration: pending_count dropped" "false" "${has_old_after}"

# pending array must exist with just the new entry (not 6 phantoms).
has_pending_after=$(jq -r 'has("pending")' "${state_file_migrate}")
assert "migration: pending array exists" "true" "${has_pending_after}"

len_migrate=$(jq -r '.pending | length' "${state_file_migrate}")
assert "migration: pending has 1 entry (stale scalar not carried over)" "1" "${len_migrate}"

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

# Record decisions with high variance — stddev > 4s means H14 should pass
HUMAN_LOW="test-human-h14-low"
for elapsed in 2 8 15 5 20; do
    hi_record_decision "${HUMAN_LOW}" "approve" "${elapsed}" "info"
done
for elapsed in 10 3 18 6 12; do
    hi_record_decision "${HUMAN_LOW}" "deny" "${elapsed}" "info"
done

result3=$(hi_check_approval_rate "${HUMAN_LOW}" 2>/dev/null)
assert "varied response times (stddev > 4s) → ok" "ok" "${result3}"

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

# v2.9.0: approvals_recent replaced by response_times
response_len=$(jq -r '.response_times | length' "${state_file}" 2>/dev/null)
assert "response_times length" "3" "${response_len}"

echo
echo "=== v3.1.3: Human-State HMAC Tamper Detection ==="
echo

# Install an HMAC key so sealed writes actually seal. Without a key the module
# runs unauthenticated (backward-compat path) and tamper tests are no-ops.
_TEST_HMAC_KEY_DIR="${TEMP_DIR}/etc/keys"
mkdir -p "${_TEST_HMAC_KEY_DIR}"
_HI_HMAC_KEY_FILE="${_TEST_HMAC_KEY_DIR}/human-state-hmac.key"
openssl rand -hex 32 > "${_HI_HMAC_KEY_FILE}"
chmod 600 "${_HI_HMAC_KEY_FILE}"
_HI_HMAC_KEY=$(cat "${_HI_HMAC_KEY_FILE}")

# Seal a fresh state by exercising a write path.
HUMAN="test-hmac"
hi_record_decision "${HUMAN}" "approve" 0 "info" 100
state_file="${TEMP_DIR}/var/human-state/${HUMAN}.json"

# 1. Seal-after-write: _hmac field present.
hmac_present=$(jq -r 'has("_hmac")' "${state_file}" 2>/dev/null)
assert "write adds _hmac field" "true" "${hmac_present}"

# 2. Clean read passes verification (no rebuild).
decisions_before=$(jq -r '.decisions_today' "${state_file}" 2>/dev/null)
_=$(hi_check_capacity "${HUMAN}" 2>/dev/null)
decisions_after=$(jq -r '.decisions_today' "${state_file}" 2>/dev/null)
assert "clean read preserves state" "${decisions_before}" "${decisions_after}"

# 3. Tamper: inflate decisions_today without updating _hmac. Next read must
#    detect the mismatch and rebuild with safe defaults (decisions_today = 0).
jq '.decisions_today = 999' "${state_file}" > "${state_file}.attacker" && \
    mv "${state_file}.attacker" "${state_file}"
_=$(hi_check_capacity "${HUMAN}" 2>/dev/null)  # triggers _hi_ensure_state
rebuilt=$(jq -r '.decisions_today' "${state_file}" 2>/dev/null)
assert "tampered state rebuilt to safe default" "0" "${rebuilt}"

# 4. Missing _hmac on an existing file is also tampering.
hi_record_decision "${HUMAN}" "approve" 0 "info" 100
jq 'del(._hmac)' "${state_file}" > "${state_file}.stripped" && \
    mv "${state_file}.stripped" "${state_file}"
_=$(hi_check_capacity "${HUMAN}" 2>/dev/null)
after_strip=$(jq -r '.decisions_today' "${state_file}" 2>/dev/null)
assert "stripped _hmac rebuilt to safe default" "0" "${after_strip}"

# 5. After rebuild, the new state is itself sealed — not left unkeyed.
hmac_after_rebuild=$(jq -r 'has("_hmac")' "${state_file}" 2>/dev/null)
assert "rebuild re-seals with _hmac" "true" "${hmac_after_rebuild}"

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
