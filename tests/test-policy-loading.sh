#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Tests for load_policy() — policy signature verification fail-closed guarantees
#
# Exercises every rejection path in load_policy() to lock in the fail-closed
# behavior. Motivated by ChatGPT cross-model audit recommendation (March 2026).
#
# load_policy() is defined inline below (mirrors bin/zlar-gate ~line 617).
# Keep in sync with the gate.
#
# Run: bash tests/test-policy-loading.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail   # -e intentionally omitted — tests assert on non-zero returns

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source the crypto abstraction layer (required by load_policy)
export _CRYPTO_PROJECT_DIR="${PROJECT_DIR}"
# shellcheck source=../lib/crypto.sh
source "${PROJECT_DIR}/lib/crypto.sh"

# ── Test infrastructure ───────────────────────────────────────────────────────

PASS=0
FAIL=0

TEST_TMP=$(mktemp -d)
trap 'rm -rf "${TEST_TMP}"' EXIT

assert_exit() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${actual}" -eq "${expected}" ]; then
        echo "  ✓ ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${desc} (expected exit=${expected}, got=${actual})"
        FAIL=$((FAIL + 1))
    fi
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${desc} (expected='${expected}', got='${actual}')"
        FAIL=$((FAIL + 1))
    fi
}

# ── Stubs required by load_policy ────────────────────────────────────────────

log() { :; }  # Suppress gate log output during tests

GATE_TMP="${TEST_TMP}/gate-tmp"
mkdir -p "${GATE_TMP}"

# ── load_policy inline ────────────────────────────────────────────────────────
# Mirrors bin/zlar-gate load_policy() (lines ~617-670). Keep in sync.
# POLICY_FILE and POLICY_PUBKEY are set per-test below.

load_policy() {
    if [ ! -f "${POLICY_FILE}" ]; then
        log "FATAL: Policy file not found: ${POLICY_FILE}"
        return 1
    fi

    if [ ! -f "${POLICY_PUBKEY}" ]; then
        log "FATAL: Policy public key not found — cannot verify signature"
        return 1
    fi

    {
        local sig_value sig_algo
        sig_value=$(jq -r '.signature.value // ""' "${POLICY_FILE}" 2>/dev/null)
        sig_algo=$(jq -r '.signature.algorithm // "ed25519"' "${POLICY_FILE}" 2>/dev/null)
        if [ -z "${sig_value}" ] || [ "${sig_value}" = "" ]; then
            log "FATAL: Policy is unsigned"
            return 1
        fi

        local canon_file hash_file sig_file
        canon_file=$(mktemp "${GATE_TMP}/canon.XXXXXX")
        hash_file=$(mktemp  "${GATE_TMP}/hash.XXXXXX")
        sig_file=$(mktemp   "${GATE_TMP}/sig.XXXXXX")

        jq '.signature.value = ""' "${POLICY_FILE}" > "${canon_file}" 2>/dev/null
        zlar_crypto_hash "${canon_file}" "${hash_file}"
        echo "${sig_value}" | base64 -d > "${sig_file}" 2>/dev/null

        if ! zlar_crypto_verify "${POLICY_PUBKEY}" "${hash_file}" "${sig_file}" "${sig_algo}"; then
            rm -f "${canon_file}" "${hash_file}" "${sig_file}"
            log "FATAL: Policy signature INVALID"
            return 1
        fi
        rm -f "${canon_file}" "${hash_file}" "${sig_file}"
    }

    POLICY_VERSION=$(jq -r '.version // "unknown"' "${POLICY_FILE}" 2>/dev/null)
    POLICY_DEFAULT_ACTION=$(jq -r '.default_action // "deny"' "${POLICY_FILE}" 2>/dev/null)
    POLICY_RULES_JSON=$(jq -c '.rules' "${POLICY_FILE}" 2>/dev/null)
    POLICY_LOADED="true"
}

# ── Key material ──────────────────────────────────────────────────────────────

TEST_PRIVKEY="${TEST_TMP}/test-signing.key"
TEST_PUBKEY="${TEST_TMP}/test-signing.pub"
openssl genpkey -algorithm ed25519 -out "${TEST_PRIVKEY}" 2>/dev/null
openssl pkey -in "${TEST_PRIVKEY}" -pubout -out "${TEST_PUBKEY}" 2>/dev/null

# Helper: create a minimal valid signed policy using the test key pair
make_signed_policy() {
    local outfile="$1"
    printf '{"version":"test-1.0.0","default_action":"deny","rules":[],"signature":{"value":"","algorithm":"ed25519"}}\n' > "${outfile}"
    local canon_file hash_file sig_file sig_b64
    canon_file=$(mktemp "${TEST_TMP}/sign-canon.XXXXXX")
    hash_file=$(mktemp  "${TEST_TMP}/sign-hash.XXXXXX")
    sig_file=$(mktemp   "${TEST_TMP}/sign-sig.XXXXXX")
    jq '.signature.value = ""' "${outfile}" > "${canon_file}"
    zlar_crypto_hash "${canon_file}" "${hash_file}"
    zlar_crypto_sign "${TEST_PRIVKEY}" "${hash_file}" "${sig_file}" "ed25519"
    sig_b64=$(base64 < "${sig_file}" | tr -d '\n')
    jq --arg sig "${sig_b64}" '.signature.value = $sig' "${outfile}" > "${outfile}.tmp"
    mv "${outfile}.tmp" "${outfile}"
    rm -f "${canon_file}" "${hash_file}" "${sig_file}"
}

# ── Tests ─────────────────────────────────────────────────────────────────────

echo ""
echo "── Policy Loading — Fail-Closed Corpus ──"

ec=0

# 1. Missing policy file → return 1
POLICY_FILE="${TEST_TMP}/nonexistent.json"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "Missing policy file → return 1" 1 "${ec}"

# 2. Missing pubkey → return 1
POLICY_FILE="${TEST_TMP}/policy-no-pubkey.json"
printf '{"version":"1","default_action":"deny","rules":[],"signature":{"value":"AAAA","algorithm":"ed25519"}}\n' > "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_TMP}/nonexistent.pub"
ec=0; load_policy || ec=$?
assert_exit "Missing pubkey → return 1" 1 "${ec}"

# 3. Empty signature value → return 1
POLICY_FILE="${TEST_TMP}/policy-empty-sig.json"
printf '{"version":"1","default_action":"deny","rules":[],"signature":{"value":"","algorithm":"ed25519"}}\n' > "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "Empty signature value → return 1" 1 "${ec}"

# 4. Missing signature field entirely → return 1
POLICY_FILE="${TEST_TMP}/policy-no-sig-field.json"
printf '{"version":"1","default_action":"deny","rules":[]}\n' > "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "No signature field → return 1" 1 "${ec}"

# 5. Null signature value → return 1
POLICY_FILE="${TEST_TMP}/policy-null-sig.json"
printf '{"version":"1","default_action":"deny","rules":[],"signature":{"value":null,"algorithm":"ed25519"}}\n' > "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "Null signature value → return 1" 1 "${ec}"

# 6. Malformed base64 → base64 -d produces garbage, verify fails → return 1
POLICY_FILE="${TEST_TMP}/policy-bad-b64.json"
printf '{"version":"1","default_action":"deny","rules":[],"signature":{"value":"not!valid!base64!!!!","algorithm":"ed25519"}}\n' > "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "Malformed base64 signature → return 1" 1 "${ec}"

# 7. Correct-length random bytes (valid base64, but not a real signature) → return 1
POLICY_FILE="${TEST_TMP}/policy-random-sig.json"
RANDOM_SIG=$(openssl rand -base64 64 | tr -d '\n')
printf '{"version":"1","default_action":"deny","rules":[],"signature":{"value":"%s","algorithm":"ed25519"}}\n' "${RANDOM_SIG}" > "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "Random bytes as signature → return 1" 1 "${ec}"

# 8. Correct signature but verified against wrong pubkey → return 1
WRONG_PRIVKEY="${TEST_TMP}/wrong.key"
WRONG_PUBKEY="${TEST_TMP}/wrong.pub"
openssl genpkey -algorithm ed25519 -out "${WRONG_PRIVKEY}" 2>/dev/null
openssl pkey -in "${WRONG_PRIVKEY}" -pubout -out "${WRONG_PUBKEY}" 2>/dev/null
POLICY_FILE="${TEST_TMP}/policy-wrong-key.json"
make_signed_policy "${POLICY_FILE}"
POLICY_PUBKEY="${WRONG_PUBKEY}"   # signed with TEST_PRIVKEY, but verify with WRONG_PUBKEY
ec=0; load_policy || ec=$?
assert_exit "Signature/key mismatch → return 1" 1 "${ec}"

# 9. Tampered content after signing → return 1
POLICY_FILE="${TEST_TMP}/policy-tampered.json"
make_signed_policy "${POLICY_FILE}"
jq '.default_action = "allow"' "${POLICY_FILE}" > "${POLICY_FILE}.tmp" && mv "${POLICY_FILE}.tmp" "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "Tampered policy body → return 1" 1 "${ec}"

# 10. Policy with extra injected rule after signing → return 1
POLICY_FILE="${TEST_TMP}/policy-injected-rule.json"
make_signed_policy "${POLICY_FILE}"
jq '.rules += [{"id":"R999","action":"allow","domain":"bash","description":"injected"}]' "${POLICY_FILE}" > "${POLICY_FILE}.tmp"
mv "${POLICY_FILE}.tmp" "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
ec=0; load_policy || ec=$?
assert_exit "Injected rule after signing → return 1" 1 "${ec}"

# 11. Valid signed policy → return 0
POLICY_FILE="${TEST_TMP}/policy-valid.json"
make_signed_policy "${POLICY_FILE}"
POLICY_PUBKEY="${TEST_PUBKEY}"
POLICY_VERSION="" POLICY_DEFAULT_ACTION="" POLICY_RULES_JSON="" POLICY_LOADED=""
ec=0; load_policy || ec=$?
assert_exit "Valid signed policy → return 0" 0 "${ec}"

# 12. Valid signed policy → sets POLICY_DEFAULT_ACTION correctly
assert_eq "Valid policy → POLICY_DEFAULT_ACTION=deny" "deny" "${POLICY_DEFAULT_ACTION}"

# 13. Valid signed policy → sets POLICY_LOADED=true
assert_eq "Valid policy → POLICY_LOADED=true" "true" "${POLICY_LOADED}"

# 14. Live repo policy loads with real pubkey
LIVE_POLICY="${PROJECT_DIR}/etc/policies/active.policy.json"
LIVE_PUBKEY="${PROJECT_DIR}/etc/keys/policy-signing.pub"
if [ -f "${LIVE_POLICY}" ] && [ -f "${LIVE_PUBKEY}" ]; then
    POLICY_FILE="${LIVE_POLICY}"
    POLICY_PUBKEY="${LIVE_PUBKEY}"
    POLICY_VERSION="" POLICY_DEFAULT_ACTION="" POLICY_RULES_JSON="" POLICY_LOADED=""
    ec=0; load_policy || ec=$?
    assert_exit "Live repo policy loads successfully" 0 "${ec}"
else
    echo "  ⊘ Live policy or pubkey not present — skipping"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "──────────────────────────────────────────────────"
echo "${PASS} passed, ${FAIL} failed out of $((PASS + FAIL)) tests"

[ "${FAIL}" -eq 0 ] || exit 1
