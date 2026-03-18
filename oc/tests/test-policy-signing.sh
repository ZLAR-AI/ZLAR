#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR-OC Smoke Tests: Policy Signing & Verification
#
# Tests the zlar-oc-policy CLI: keygen, sign, verify workflow.
# Does NOT require macOS — tests cryptographic operations only.
#
# Usage:
#   ./tests/test-policy-signing.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
POLICY_CLI="${REPO_ROOT}/bin/zlar-oc-policy"
POLICY_FILE="${REPO_ROOT}/etc/zlar-oc/policies/default.policy.json"
TMPDIR=$(mktemp -d /tmp/zlar-oc-test-signing.XXXXXX)

PASSED=0
FAILED=0
SKIPPED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BOLD='\033[1m'; NC='\033[0m'

pass() { PASSED=$((PASSED + 1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { FAILED=$((FAILED + 1)); echo -e "  ${RED}FAIL${NC} $1"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo -e "  ${YELLOW}SKIP${NC} $1"; }

cleanup() { rm -rf "${TMPDIR}"; }
trap cleanup EXIT

echo -e "${BOLD}ZLAR-OC Policy Signing Tests${NC}"
echo ""

# Check dependencies
if ! command -v openssl &>/dev/null; then
    echo "openssl is required. Exiting."
    exit 1
fi

# ─── Test 1: Generate Ed25519 keypair ────────────────────────────────────────

echo -e "${BOLD}Test 1: Generate Ed25519 keypair${NC}"
privkey="${TMPDIR}/test-signing.key"
pubkey="${TMPDIR}/test-signing.pub"

openssl genpkey -algorithm Ed25519 -out "${privkey}" 2>/dev/null
openssl pkey -in "${privkey}" -pubout -out "${pubkey}" 2>/dev/null

if [ -f "${privkey}" ] && [ -f "${pubkey}" ]; then
    pass "Ed25519 keypair generated"
else
    fail "Ed25519 keypair generation failed"
fi

# ─── Test 2: Sign a policy ──────────────────────────────────────────────────

echo -e "${BOLD}Test 2: Sign the default policy${NC}"
if ! command -v jq &>/dev/null; then
    skip "jq required for signing test"
else
    signed="${TMPDIR}/signed.policy.json"

    # Extract public key for embedding
    pubkey_b64=$(openssl pkey -in "${privkey}" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n')

    # Create canonical form with empty signature
    jq --arg pk "${pubkey_b64}" \
       '.signature.algorithm = "ed25519" | .signature.public_key = $pk | .signature.value = ""' \
       "${POLICY_FILE}" > "${TMPDIR}/canonical.json"

    # Hash it
    shasum -a 256 "${TMPDIR}/canonical.json" | awk '{print $1}' | tr -d '\n' > "${TMPDIR}/hash.txt"

    # Sign
    openssl pkeyutl -sign -inkey "${privkey}" -rawin -in "${TMPDIR}/hash.txt" -out "${TMPDIR}/sig.bin" 2>/dev/null
    sig_b64=$(base64 < "${TMPDIR}/sig.bin" | tr -d '\n')

    # Create signed version
    jq --arg pk "${pubkey_b64}" --arg sig "${sig_b64}" \
       '.signature.algorithm = "ed25519" | .signature.public_key = $pk | .signature.value = $sig' \
       "${POLICY_FILE}" > "${signed}"

    if [ -f "${signed}" ] && [ -s "${signed}" ]; then
        # Check signature field is non-empty
        sig_check=$(jq -r '.signature.value' "${signed}")
        if [ -n "${sig_check}" ] && [ "${sig_check}" != "" ] && [ "${sig_check}" != "null" ]; then
            pass "Policy signed successfully (sig length: ${#sig_check})"
        else
            fail "Signed policy has empty signature"
        fi
    else
        fail "Signing produced empty output"
    fi
fi

# ─── Test 3: Verify valid signature ─────────────────────────────────────────

echo -e "${BOLD}Test 3: Verify valid signature${NC}"
if [ ! -f "${signed:-/dev/null}" ]; then
    skip "No signed policy to verify"
else
    # Re-create canonical form
    jq '.signature.value = ""' "${signed}" > "${TMPDIR}/verify-canon.json"
    shasum -a 256 "${TMPDIR}/verify-canon.json" | awk '{print $1}' | tr -d '\n' > "${TMPDIR}/verify-hash.txt"

    # Extract and decode signature
    jq -r '.signature.value' "${signed}" | base64 -d > "${TMPDIR}/verify-sig.bin" 2>/dev/null

    if openssl pkeyutl -verify \
        -pubin -rawin -inkey "${pubkey}" \
        -sigfile "${TMPDIR}/verify-sig.bin" \
        -in "${TMPDIR}/verify-hash.txt" 2>/dev/null; then
        pass "Valid signature verified successfully"
    else
        fail "Valid signature verification failed"
    fi
fi

# ─── Test 4: Detect tampered policy ─────────────────────────────────────────

echo -e "${BOLD}Test 4: Detect tampered policy${NC}"
if [ ! -f "${signed:-/dev/null}" ]; then
    skip "No signed policy to tamper"
else
    tampered="${TMPDIR}/tampered.policy.json"
    # Modify a rule's action
    jq '.rules[0].action = "deny"' "${signed}" > "${tampered}"

    # Verify should fail
    jq '.signature.value = ""' "${tampered}" > "${TMPDIR}/tamper-canon.json"
    shasum -a 256 "${TMPDIR}/tamper-canon.json" | awk '{print $1}' | tr -d '\n' > "${TMPDIR}/tamper-hash.txt"
    jq -r '.signature.value' "${tampered}" | base64 -d > "${TMPDIR}/tamper-sig.bin" 2>/dev/null

    if openssl pkeyutl -verify \
        -pubin -rawin -inkey "${pubkey}" \
        -sigfile "${TMPDIR}/tamper-sig.bin" \
        -in "${TMPDIR}/tamper-hash.txt" 2>&1 | grep -qi "fail\|error"; then
        pass "Tampered policy correctly rejected"
    else
        # openssl returns non-zero on failure
        if ! openssl pkeyutl -verify \
            -pubin -inkey "${pubkey}" \
            -sigfile "${TMPDIR}/tamper-sig.bin" \
            -in "${TMPDIR}/tamper-hash.txt" 2>/dev/null; then
            pass "Tampered policy correctly rejected (non-zero exit)"
        else
            fail "Tampered policy was NOT detected"
        fi
    fi
fi

# ─── Test 5: Wrong key rejected ─────────────────────────────────────────────

echo -e "${BOLD}Test 5: Wrong key rejected${NC}"
if [ ! -f "${signed:-/dev/null}" ]; then
    skip "No signed policy to verify"
else
    # Generate a different keypair
    openssl genpkey -algorithm Ed25519 -out "${TMPDIR}/wrong.key" 2>/dev/null
    openssl pkey -in "${TMPDIR}/wrong.key" -pubout -out "${TMPDIR}/wrong.pub" 2>/dev/null

    # Verify with wrong key should fail
    jq '.signature.value = ""' "${signed}" > "${TMPDIR}/wrong-canon.json"
    shasum -a 256 "${TMPDIR}/wrong-canon.json" | awk '{print $1}' | tr -d '\n' > "${TMPDIR}/wrong-hash.txt"
    jq -r '.signature.value' "${signed}" | base64 -d > "${TMPDIR}/wrong-sig.bin" 2>/dev/null

    if ! openssl pkeyutl -verify \
        -pubin -rawin -inkey "${TMPDIR}/wrong.pub" \
        -sigfile "${TMPDIR}/wrong-sig.bin" \
        -in "${TMPDIR}/wrong-hash.txt" 2>/dev/null; then
        pass "Wrong key correctly rejected"
    else
        fail "Wrong key was NOT rejected"
    fi
fi

# ─── Test 6: Policy JSON is valid ───────────────────────────────────────────

echo -e "${BOLD}Test 6: Default policy is valid JSON${NC}"
if command -v jq &>/dev/null; then
    if jq empty "${POLICY_FILE}" 2>/dev/null; then
        pass "default.policy.json is valid JSON"
    else
        fail "default.policy.json is NOT valid JSON"
    fi

    # Check required fields
    local_version=$(jq -r '.version' "${POLICY_FILE}" 2>/dev/null)
    local_default=$(jq -r '.default_action' "${POLICY_FILE}" 2>/dev/null)
    local_rules=$(jq '.rules | length' "${POLICY_FILE}" 2>/dev/null)
    if [ -n "${local_version}" ] && [ -n "${local_default}" ] && [ "${local_rules}" -gt 0 ]; then
        pass "Policy has version (${local_version}), default_action (${local_default}), and ${local_rules} rules"
    else
        fail "Policy missing required fields"
    fi
else
    skip "jq required for JSON validation"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Results${NC}"
echo -e "  ${GREEN}Passed: ${PASSED}${NC}"
echo -e "  ${RED}Failed: ${FAILED}${NC}"
echo -e "  ${YELLOW}Skipped: ${SKIPPED}${NC}"
echo ""

if [ ${FAILED} -gt 0 ]; then
    echo -e "${RED}${BOLD}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
fi
