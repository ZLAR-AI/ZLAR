#!/bin/bash
# test-inbox-hmac.sh — Tests for inbox HMAC computation and verification
# Verifies that dispatcher and gates agree on HMAC format and that
# forged, tampered, and missing-secret scenarios are correctly rejected.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "✓ $1"; }
fail() { FAIL=$((FAIL + 1)); echo "✗ $1"; }

# Source the shared HMAC library
export ZLAR_HMAC_SECRET_FILE="/tmp/zlar-test-hmac-secret-$$"
source "${PROJECT_DIR}/lib/hmac.sh"

# ── Setup ──
openssl rand -hex 32 > "${ZLAR_HMAC_SECRET_FILE}"
chmod 600 "${ZLAR_HMAC_SECRET_FILE}"
zlar_hmac_load_secret

cleanup() { rm -f "${ZLAR_HMAC_SECRET_FILE}"; }
trap cleanup EXIT

# ── Test 1: Secret loads correctly ──
if [ -n "${ZLAR_INBOX_HMAC_SECRET}" ] && [ ${#ZLAR_INBOX_HMAC_SECRET} -eq 64 ]; then
    pass "Secret loads as 64-char hex"
else
    fail "Secret load: got '${ZLAR_INBOX_HMAC_SECRET}' (length ${#ZLAR_INBOX_HMAC_SECRET})"
fi

# ── Test 2: Compute produces non-empty output ──
hmac=$(zlar_hmac_compute "cc:approve:abc123" "7662799203" "cb_999")
if [ -n "${hmac}" ]; then
    pass "Compute produces non-empty HMAC: ${hmac:0:20}..."
else
    fail "Compute returned empty"
fi

# ── Test 3: Verify accepts matching HMAC ──
if zlar_hmac_verify "cc:approve:abc123" "7662799203" "cb_999" "${hmac}"; then
    pass "Verify accepts valid HMAC"
else
    fail "Verify rejected valid HMAC"
fi

# ── Test 4: Verify rejects tampered data ──
if ! zlar_hmac_verify "cc:DENY:abc123" "7662799203" "cb_999" "${hmac}"; then
    pass "Verify rejects tampered data"
else
    fail "Verify accepted tampered data"
fi

# ── Test 5: Verify rejects tampered from_id ──
if ! zlar_hmac_verify "cc:approve:abc123" "9999999999" "cb_999" "${hmac}"; then
    pass "Verify rejects tampered from_id"
else
    fail "Verify accepted tampered from_id"
fi

# ── Test 6: Verify rejects tampered callback_id ──
if ! zlar_hmac_verify "cc:approve:abc123" "7662799203" "cb_FAKE" "${hmac}"; then
    pass "Verify rejects tampered callback_id"
else
    fail "Verify accepted tampered callback_id"
fi

# ── Test 7: Verify rejects empty HMAC field ──
if ! zlar_hmac_verify "cc:approve:abc123" "7662799203" "cb_999" ""; then
    pass "Verify rejects empty HMAC (unsigned file)"
else
    fail "Verify accepted empty HMAC"
fi

# ── Test 8: Missing secret → deny (no legacy mode downgrade) ──
saved_secret="${ZLAR_INBOX_HMAC_SECRET}"
ZLAR_INBOX_HMAC_SECRET=""
if ! zlar_hmac_verify "cc:approve:abc123" "7662799203" "cb_999" "${hmac}"; then
    pass "Missing secret denies (no downgrade attack)"
else
    fail "Missing secret allowed verification (downgrade attack possible!)"
fi
ZLAR_INBOX_HMAC_SECRET="${saved_secret}"

# ── Test 9: Different secrets produce different HMACs ──
hmac1=$(zlar_hmac_compute "test" "123" "456")
old_secret="${ZLAR_INBOX_HMAC_SECRET}"
ZLAR_INBOX_HMAC_SECRET="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
hmac2=$(zlar_hmac_compute "test" "123" "456")
ZLAR_INBOX_HMAC_SECRET="${old_secret}"
if [ "${hmac1}" != "${hmac2}" ]; then
    pass "Different secrets produce different HMACs"
else
    fail "Different secrets produced same HMAC"
fi

# ── Test 10: OC gate callback format ──
oc_hmac=$(zlar_hmac_compute "oc:approve:evt_789" "7662799203" "cb_oc_111")
if zlar_hmac_verify "oc:approve:evt_789" "7662799203" "cb_oc_111" "${oc_hmac}"; then
    pass "OC gate callback format works"
else
    fail "OC gate callback format failed"
fi

# ── Results ──
echo ""
echo "${PASS} passed, ${FAIL} failed out of $((PASS + FAIL)) tests"
[ "${FAIL}" -eq 0 ] || exit 1
