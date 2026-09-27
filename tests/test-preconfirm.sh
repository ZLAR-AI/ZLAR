#!/bin/bash
# Test suite for lib/preconfirm-cc.sh — Element E2 Tier 2 preconfirm state machine
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

# Test environment
export PROJECT_DIR
export APPROVAL_DIR="${TEST_DIR}/approvals"
export TELEGRAM_TOKEN="test-token"
export RATE_LIMIT_FILE="${TEST_DIR}/rate-limit"
export TELEGRAM_FLOOD_GUARD_MS=0
# v3.3.9: ZLAR_TELEGRAM_CHAT_ID is the env-source override authoritative
# under the new TELEGRAM_CHAT_ID_SOURCE resolution.
export ZLAR_TELEGRAM_CHAT_ID="12345678"
export TELEGRAM_CHAT_ID="12345678"
export SESSION_ID="test-session-pc"
export TELEGRAM_TIMEOUT_S=900
export ZLAR_INBOX_CC_DIR="${TEST_DIR}/inbox/cc"
export ZLAR_INBOX_HMAC_SECRET=""

mkdir -p "${APPROVAL_DIR}" "${ZLAR_INBOX_CC_DIR}" "${PROJECT_DIR}/var/log"
: > "${PROJECT_DIR}/var/log/.consumed-callbacks"

# Mocks
log() { :; }
gen_id() { echo "pc-test-$(date +%s)-$$-${RANDOM}"; }
zlar_hmac_verify() { return 0; }
telegram_api() { echo '{"ok":true,"result":{"message_id":42}}'; }
_mdv2e() { printf '%s' "$1"; }

source "${PROJECT_DIR}/lib/preconfirm-cc.sh"

PASS=0; FAIL=0

assert() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"; PASS=$((PASS + 1))
    else
        echo "  ✗ ${desc} (expected=${expected}, actual=${actual})"; FAIL=$((FAIL + 1))
    fi
}

assert_rc() {
    local desc="$1" expected="$2"
    shift 2
    local actual=0; "$@" && actual=0 || actual=$?
    assert "${desc}" "${expected}" "${actual}"
}

echo "Preconfirm CC Tests"
echo "==================="
echo

ACTION_HASH="aabbccdd1122334455667788deadbeef0011223344556677deadbeef00112233"
ACTION_RULE="R012W_EDIT"
PENDING_FILE="${APPROVAL_DIR}/pc-${ACTION_RULE}-${SESSION_ID}-${ACTION_HASH:0:16}.pending"

_make_cb() {
    local filename="$1" cb_data="$2" from="${3:-${TELEGRAM_CHAT_ID}}"
    jq -n -c --arg data "${cb_data}" --arg from_id "${from}" \
        --arg cb_id "cb-${RANDOM}" --arg hmac "test-hmac" \
        '{data: $data, from_id: $from_id, callback_query_id: $cb_id, hmac: $hmac}' \
        > "${ZLAR_INBOX_CC_DIR}/${filename}"
}

_clean_inbox()     { rm -f "${ZLAR_INBOX_CC_DIR}"/*.json 2>/dev/null || true; }
_clean_pending()   { rm -f "${APPROVAL_DIR}"/pc-*.pending "${APPROVAL_DIR}"/pc-*.blocked "${APPROVAL_DIR}"/pc-*.acked 2>/dev/null || true; }
_clean_consumed()  { : > "${PROJECT_DIR}/var/log/.consumed-callbacks"; }

# ── 1. State 2: no pending file ──
echo "1. State 2: no pending file"
_clean_pending; _clean_inbox; _clean_consumed; _clean_pending
assert_rc "Returns 2 when no pending file" 2 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"

# ── 2. State 3: pending exists, no callback ──
echo "2. State 3: pending file, no inbox callback"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-001" "${ACTION_HASH}" > "${PENDING_FILE}"
assert_rc "Returns 3 with pending and no callback" 3 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Pending file not removed" "true" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"

# ── 3. State 0: PROCEED callback ──
echo "3. State 0: PROCEED callback in inbox"
_make_cb "001.json" "cc:pc_proceed:pc-action-001"
assert_rc "Returns 0 on PROCEED" 0 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Pending file removed after PROCEED" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"

# ── 4. PROCEED callback consumed ──
echo "4. PROCEED callback marked consumed"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-002" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "002.json" "cc:pc_proceed:pc-action-002"
check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}" || true
assert "002.json in consumed file" "true" \
    "$(grep -qxF '002.json' "${PROJECT_DIR}/var/log/.consumed-callbacks" && echo true || echo false)"

# ── 5. State 1: BLOCK callback ──
echo "5. State 1: BLOCK callback in inbox"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-003" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "003.json" "cc:pc_block:pc-action-003"
assert_rc "Returns 1 on BLOCK" 1 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Pending file removed after BLOCK" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"

# ── 6. BLOCK callback consumed ──
echo "6. BLOCK callback marked consumed"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-004" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "004.json" "cc:pc_block:pc-action-004"
check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}" || true
assert "004.json in consumed file" "true" \
    "$(grep -qxF '004.json' "${PROJECT_DIR}/var/log/.consumed-callbacks" && echo true || echo false)"

# ── 7. Wrong chat_id ignored ──
echo "7. Callback from wrong chat_id ignored"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-005" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "005.json" "cc:pc_proceed:pc-action-005" "99999999"
assert_rc "Returns 3 when callback from wrong chat" 3 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Pending file unchanged" "true" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"

# ── 8. Already-consumed callback skipped ──
echo "8. Consumed callback skipped"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-006" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "006.json" "cc:pc_proceed:pc-action-006"
echo "006.json" >> "${PROJECT_DIR}/var/log/.consumed-callbacks"
assert_rc "Returns 3 when callback already consumed" 3 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"

# ── 9. Corrupt (empty) pending file ──
echo "9. Corrupt pending file triggers re-send"
_clean_inbox; _clean_consumed; _clean_pending
: > "${PENDING_FILE}"
assert_rc "Returns 2 on empty pending file" 2 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Corrupt pending file removed" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"

# ── 10. Timeout = hard deny (returns 1, not 2) ──
echo "10. Timeout triggers hard deny"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-007" "${ACTION_HASH}" > "${PENDING_FILE}"
python3 -c "import os, sys; os.utime(sys.argv[1], (0, 0))" "${PENDING_FILE}" 2>/dev/null \
    || touch -t 200001010000 "${PENDING_FILE}" 2>/dev/null || true
TELEGRAM_TIMEOUT_S=1
assert_rc "Returns 1 on timeout (hard deny)" 1 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Expired pending file removed" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"
TELEGRAM_TIMEOUT_S=900

# ── 11. Action ID mismatch not matched ──
echo "11. Wrong action_id not matched"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-008" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "008.json" "cc:pc_proceed:pc-action-WRONG"
assert_rc "Returns 3 on action_id mismatch" 3 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
rm -f "${PENDING_FILE}"

# ── 12. HMAC failure skips callback ──
echo "12. Invalid HMAC skips callback"
_clean_inbox; _clean_consumed; _clean_pending
printf '%s\n%s\n' "pc-action-009" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "009.json" "cc:pc_proceed:pc-action-009"
ZLAR_INBOX_HMAC_SECRET="active"
zlar_hmac_verify() { return 1; }
assert_rc "Returns 3 when HMAC fails" 3 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
ZLAR_INBOX_HMAC_SECRET=""
zlar_hmac_verify() { return 0; }
rm -f "${PENDING_FILE}"

# ── 13. telegram_preconfirm_async creates pending file ──
echo "13. telegram_preconfirm_async creates pending file"
_clean_pending; _clean_inbox
telegram_preconfirm_async "${ACTION_HASH}" "R012W_EDIT" "critical" "cat policy.json" || true
pf_count=$(find "${APPROVAL_DIR}" -name 'pc-*.pending' | wc -l | tr -d ' ')
assert "Pending file created" "true" "$([ "${pf_count}" -ge 1 ] && echo true || echo false)"

# ── 14. Pending file contains action_id on line 1 ──
echo "14. Pending file has action_id on line 1"
pf=$(find "${APPROVAL_DIR}" -name 'pc-*.pending' | head -1)
if [ -n "${pf}" ]; then
    pc_id=$(sed -n '1p' "${pf}" | tr -d '[:space:]')
    assert "Action ID is non-empty" "true" "$([ -n "${pc_id}" ] && echo true || echo false)"
else
    assert "Pending file found" "true" "false"
fi

# ── 15. No token returns 2 ──
echo "15. No token returns 2"
_clean_pending
saved_token="${TELEGRAM_TOKEN}"; TELEGRAM_TOKEN=""
assert_rc "Returns 2 with no token" 2 telegram_preconfirm_async "${ACTION_HASH}" "R012" "warn" "cmd"
TELEGRAM_TOKEN="${saved_token}"

# ── 16. Rate limited returns 3 ──
echo "16. Rate limited returns 3"
_clean_pending
echo "$(date +%s%N 2>/dev/null | cut -c1-13 || echo "$(($(date +%s) * 1000))")" > "${RATE_LIMIT_FILE}"
TELEGRAM_FLOOD_GUARD_MS=60000
assert_rc "Returns 3 when rate limited" 3 telegram_preconfirm_async "${ACTION_HASH}" "R012" "warn" "cmd"
TELEGRAM_FLOOD_GUARD_MS=0; : > "${RATE_LIMIT_FILE}"

# ── 17. PROCEED/BLOCK buttons in payload ──
echo "17. Preconfirm card has PROCEED and BLOCK buttons"
_clean_pending
# Write body to file — avoids subshell variable loss from $(...) capture
telegram_api() { echo "$2" > "${TEST_DIR}/last-body"; echo '{"ok":true,"result":{"message_id":42}}'; }
telegram_preconfirm_async "${ACTION_HASH}" "R012W_EDIT" "critical" "cmd" || true
last_body=$(cat "${TEST_DIR}/last-body" 2>/dev/null || echo "")
assert "PROCEED button in payload" "true" \
    "$(echo "${last_body}" | jq -r '.reply_markup.inline_keyboard[0][0].callback_data' 2>/dev/null | grep -q 'pc_proceed' && echo true || echo false)"
assert "BLOCK button in payload" "true" \
    "$(echo "${last_body}" | jq -r '.reply_markup.inline_keyboard[0][1].callback_data' 2>/dev/null | grep -q 'pc_block' && echo true || echo false)"
telegram_api() { echo '{"ok":true,"result":{"message_id":42}}'; }

# ── 18. Failed send does not write pending file ──
echo "18. Failed send does not create pending file"
_clean_pending
telegram_api() { echo '{"ok":false}'; }
assert_rc "Returns 1 on failed send" 1 telegram_preconfirm_async "${ACTION_HASH}" "R012W_EDIT" "critical" "cmd"
pf_count=$(find "${APPROVAL_DIR}" -name 'pc-*.pending' | wc -l | tr -d ' ')
assert "No pending file on failed send" "false" "$([ "${pf_count}" -ge 1 ] && echo true || echo false)"
telegram_api() { echo '{"ok":true,"result":{"message_id":42}}'; }


# ── 19. Retry after BLOCK returns 1 (blocked tombstone, not re-send) ──
echo "19. Retry after BLOCK: tombstone returns 1 within TTL"
_clean_inbox; _clean_consumed; _clean_pending
rm -f "${APPROVAL_DIR}"/pc-*.blocked "${APPROVAL_DIR}"/pc-*.acked 2>/dev/null || true
printf '%s\n%s\n' "pc-action-010" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "010.json" "cc:pc_block:pc-action-010"
check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}" || true  # returns 1, writes blocked file
# Retry: blocked tombstone must be respected (return 1, not 2)
assert_rc "Retry after BLOCK returns 1 (tombstone)" 1 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"

# ── 20. Retry after timeout returns 1 (blocked tombstone, not re-send) ──
echo "20. Retry after timeout: tombstone returns 1 within TTL"
_clean_inbox; _clean_consumed; _clean_pending
rm -f "${APPROVAL_DIR}"/pc-*.blocked "${APPROVAL_DIR}"/pc-*.acked 2>/dev/null || true
printf '%s\n%s\n' "pc-action-011" "${ACTION_HASH}" > "${PENDING_FILE}"
python3 -c "import os, sys; os.utime(sys.argv[1], (0, 0))" "${PENDING_FILE}" 2>/dev/null \
    || touch -t 200001010000 "${PENDING_FILE}" 2>/dev/null || true
TELEGRAM_TIMEOUT_S=1
check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}" || true  # returns 1, writes blocked file
TELEGRAM_TIMEOUT_S=900
# Retry: blocked tombstone must be respected (return 1, not 2)
assert_rc "Retry after timeout returns 1 (tombstone)" 1 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
rm -f "${APPROVAL_DIR}"/pc-*.blocked "${APPROVAL_DIR}"/pc-*.acked 2>/dev/null || true

# ── 21. Retry after PROCEED returns 0 (acked tombstone, not re-send) ──
echo "21. Retry after PROCEED: acked tombstone returns 0 within TTL"
_clean_inbox; _clean_consumed; _clean_pending
rm -f "${APPROVAL_DIR}"/pc-*.blocked "${APPROVAL_DIR}"/pc-*.acked 2>/dev/null || true
printf '%s\n%s\n' "pc-action-012" "${ACTION_HASH}" > "${PENDING_FILE}"
_make_cb "012.json" "cc:pc_proceed:pc-action-012"
check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}" || true  # returns 0, writes acked file
# Retry (e.g. main ask send failed): acked tombstone returns 0, not 2 (re-send)
assert_rc "Retry after PROCEED returns 0 (acked tombstone)" 0 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
rm -f "${APPROVAL_DIR}"/pc-*.acked 2>/dev/null || true

# ── 22. Expired blocked tombstone is ignored (returns 2, not 1) ──
echo "22. Expired blocked tombstone ignored — returns 2 for fresh preconfirm"
_clean_inbox; _clean_consumed; _clean_pending
blocked_f="${APPROVAL_DIR}/pc-${ACTION_RULE}-${SESSION_ID}-${ACTION_HASH:0:16}.blocked"
touch "${blocked_f}"
python3 -c "import os, sys; os.utime(sys.argv[1], (0, 0))" "${blocked_f}" 2>/dev/null \
    || touch -t 200001010000 "${blocked_f}" 2>/dev/null || true
assert_rc "Expired blocked tombstone: returns 2 (fresh preconfirm allowed)" 2 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Expired blocked tombstone cleaned up" "false" "$([ -f "${blocked_f}" ] && echo true || echo false)"

# ── 23. Action hash mismatch in pending file forces re-send ──
echo "23. Action hash mismatch in pending file forces re-send"
_clean_inbox; _clean_consumed; _clean_pending
rm -f "${APPROVAL_DIR}"/pc-*.blocked "${APPROVAL_DIR}"/pc-*.acked 2>/dev/null || true
printf '%s\n%s\n' "pc-action-013" "different_hash_entirely_not_matching_action_hash_at_all" > "${PENDING_FILE}"
assert_rc "Hash mismatch in pending → returns 2 (re-send)" 2 check_preconfirm "${ACTION_RULE}" "${ACTION_HASH}"
assert "Mismatched pending file removed" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"

echo
echo "═══════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════"

exit "${FAIL}"
