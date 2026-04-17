#!/bin/bash
# Tests for R012 retry approval race fix — ensures that repeated retries of
# a gated command do NOT each generate a fresh Telegram ask that orphans the
# prior callback_id.
#
# Fix shape:
#   - check_pending_approval distinguishes "no pending" (return 2) from
#     "still pending" (return 3). Callers treat 3 as "do not re-ask".
#   - Successful approval seeds an approved-cache file with a TTL so
#     same-fingerprint retries replay the decision without a new ask.
#
# Observed in session 5 (3x): each retry burned another Vincent phone ping.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TEST_DIR=$(mktemp -d)
INBOX_DIR="${TEST_DIR}/inbox/cc"
CONSUMED_FILE="${TEST_DIR}/.consumed-callbacks"
APPROVAL_DIR="${TEST_DIR}/approvals"
mkdir -p "${INBOX_DIR}" "${APPROVAL_DIR}"
trap 'rm -rf "${TEST_DIR}"' EXIT

export APPROVAL_DIR
export SESSION_ID="test-race-$$"
export TELEGRAM_CHAT_ID="123456"
export TELEGRAM_TIMEOUT_S=300
export ZLAR_APPROVED_TTL_S=300
unset ZLAR_INBOX_HMAC_SECRET 2>/dev/null || true

# Stub log so function writes go nowhere noisy
log() { :; }

# Extract check_pending_approval from zlar-gate. The function uses two
# hardcoded paths (the Telegram inbox dir and the consumed-callbacks file
# under PROJECT_DIR). Redirect both to the test directory via sed.
sed -n '/^check_pending_approval()/,/^}$/p' "${PROJECT_DIR}/bin/zlar-gate" > "${TEST_DIR}/cpa.sh"
sed -i.bak "s|/var/run/zlar-tg/inbox/cc|${INBOX_DIR}|g" "${TEST_DIR}/cpa.sh"
sed -i.bak 's|"${PROJECT_DIR}/var/log/.consumed-callbacks"|"'"${CONSUMED_FILE}"'"|g' "${TEST_DIR}/cpa.sh"
# shellcheck source=/dev/null
source "${TEST_DIR}/cpa.sh"

passed=0
failed=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    else
        echo "  ✗ ${desc} (expected=${expected}, got=${actual})"
        failed=$((failed + 1))
    fi
}

run_cpa() {
    local rule="$1" hash="$2"
    local rc=0
    check_pending_approval "${rule}" "${hash}" >/dev/null 2>&1 || rc=$?
    echo "${rc}"
}

RULE="R012"
HASH="abc123def456789012345678901234567890abcdefabcdefabcdefabcdefabcdef"
HASH_PREFIX="${HASH:0:16}"
PENDING_FILE="${APPROVAL_DIR}/${RULE}-${SESSION_ID}-${HASH_PREFIX}.pending"
APPROVED_FILE="${APPROVAL_DIR}/${RULE}-${SESSION_ID}-${HASH_PREFIX}.approved"

echo "═══════════════════════════════════════════════════════════════"
echo "  R012 Retry Approval Race Tests"
echo "═══════════════════════════════════════════════════════════════"
echo

# ── Test 1: no pending file, no approved cache → return 2 (send fresh ask) ──
echo "── Fresh call ──"
rm -f "${PENDING_FILE}" "${APPROVED_FILE}"
rc=$(run_cpa "${RULE}" "${HASH}")
assert_eq "No state → return 2 (fresh ask path)" "2" "${rc}"
echo

# ── Test 2: pending file exists, no callback → return 3 (NOT 2; do not re-ask) ──
echo "── Still waiting (THE race fix) ──"
printf '%s\n%s\n' "action-id-A" "${HASH}" > "${PENDING_FILE}"
rc=$(run_cpa "${RULE}" "${HASH}")
assert_eq "Pending exists, no callback → return 3 (suppress re-ask)" "3" "${rc}"
assert_eq "Pending file preserved across check" "true" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"
echo

# ── Test 3: pending file + approve callback in inbox → return 0, writes approved cache ──
echo "── Approval arrives ──"
cat > "${INBOX_DIR}/cb1.json" <<EOF
{"data":"cc:approve:action-id-A","from_id":"${TELEGRAM_CHAT_ID}","callback_query_id":"qid1","hmac":""}
EOF
rc=$(run_cpa "${RULE}" "${HASH}")
assert_eq "Approve callback matched → return 0" "0" "${rc}"
assert_eq "Pending file cleaned up" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"
assert_eq "Approved cache file created" "true" "$([ -f "${APPROVED_FILE}" ] && echo true || echo false)"
echo

# ── Test 4: approved cache hit → return 0 without any pending file ──
echo "── Cache hit on subsequent retry ──"
rc=$(run_cpa "${RULE}" "${HASH}")
assert_eq "Fresh approved cache → return 0 (no re-ask)" "0" "${rc}"
echo

# ── Test 5: expired approved cache → return 2 (fresh ask) ──
echo "── Cache expiry ──"
# Backdate the approved file beyond TTL
if stat -f %m "${APPROVED_FILE}" >/dev/null 2>&1; then
    # BSD (macOS): touch with -t YYYYMMDDhhmm
    touch -t "200001010000" "${APPROVED_FILE}"
else
    # GNU: touch -d
    touch -d "2000-01-01 00:00" "${APPROVED_FILE}"
fi
rc=$(run_cpa "${RULE}" "${HASH}")
assert_eq "Expired approved cache → return 2 (fresh ask)" "2" "${rc}"
assert_eq "Expired cache file cleaned up" "false" "$([ -f "${APPROVED_FILE}" ] && echo true || echo false)"
echo

# ── Test 6: deny callback → return 1 (no approved cache written) ──
echo "── Denial ──"
rm -f "${PENDING_FILE}" "${APPROVED_FILE}" "${INBOX_DIR}"/*.json
rm -f "${CONSUMED_FILE}"
printf '%s\n%s\n' "action-id-B" "${HASH}" > "${PENDING_FILE}"
cat > "${INBOX_DIR}/cb2.json" <<EOF
{"data":"cc:deny:action-id-B","from_id":"${TELEGRAM_CHAT_ID}","callback_query_id":"qid2","hmac":""}
EOF
rc=$(run_cpa "${RULE}" "${HASH}")
assert_eq "Deny callback matched → return 1" "1" "${rc}"
assert_eq "No approved cache on deny" "false" "$([ -f "${APPROVED_FILE}" ] && echo true || echo false)"
echo

# ── Test 7: pending expired by age → return 2 (fresh ask) ──
echo "── Stale pending file ──"
rm -f "${PENDING_FILE}" "${APPROVED_FILE}" "${INBOX_DIR}"/*.json
rm -f "${CONSUMED_FILE}"
printf '%s\n%s\n' "action-id-C" "${HASH}" > "${PENDING_FILE}"
if stat -f %m "${PENDING_FILE}" >/dev/null 2>&1; then
    touch -t "200001010000" "${PENDING_FILE}"
else
    touch -d "2000-01-01 00:00" "${PENDING_FILE}"
fi
rc=$(run_cpa "${RULE}" "${HASH}")
assert_eq "Stale pending → return 2 (expired, fresh ask)" "2" "${rc}"
assert_eq "Stale pending cleaned up" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"
echo

echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${passed} passed, ${failed} failed"
echo "═══════════════════════════════════════════════════════════════"

if [ "${failed}" -gt 0 ]; then
    exit 1
fi
