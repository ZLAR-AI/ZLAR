#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Tests for lib/crypto.sh — Cryptographic Abstraction Layer
#
# Tests Ed25519 operations through the abstraction layer, verifying that
# the library produces identical results to direct openssl calls.
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail   # -e intentionally omitted — assertions use return codes to
                   # signal failures, and pipefail + set -e masks silent exits
                   # in command substitutions (see history of this file).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# ── Preflight: Ed25519 support ────────────────────────────────────────────────
# The gate requires an openssl that supports Ed25519. macOS ships LibreSSL
# which does NOT, which caused this test to exit silently for months until
# v2.7.1. If Ed25519 isn't available, fail loudly with a clear message.
if ! openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
    echo "SKIP: tests/test-crypto.sh — openssl does not support Ed25519"
    echo "      Your openssl: $(openssl version 2>&1)"
    echo "      On macOS: brew install openssl@3 && export PATH=\"\$(brew --prefix openssl@3)/bin:\$PATH\""
    echo "      On Linux: ensure OpenSSL 1.1.1+ (not LibreSSL)"
    exit 77   # POSIX convention for "skipped", CI can treat this as non-failure
fi

# Source the library under test
export _CRYPTO_PROJECT_DIR="${PROJECT_DIR}"
# shellcheck source=../lib/crypto.sh
source "${PROJECT_DIR}/lib/crypto.sh"

# Test infrastructure
PASS=0
FAIL=0
TMPDIR_TEST=$(mktemp -d)

cleanup() { rm -rf "${TMPDIR_TEST}"; }
trap cleanup EXIT

assert() {
    local desc="$1" result="$2" expected="$3"
    if echo "${result}" | grep -q "${expected}"; then
        echo "  ✓ ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${desc}"
        echo "    expected: ${expected}"
        echo "    got:      ${result}"
        FAIL=$((FAIL + 1))
    fi
}

assert_exit() {
    local desc="$1" exit_code="$2" expected="$3"
    if [ "${exit_code}" -eq "${expected}" ]; then
        echo "  ✓ ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${desc}"
        echo "    expected exit: ${expected}"
        echo "    got exit:      ${exit_code}"
        FAIL=$((FAIL + 1))
    fi
}

echo "═══════════════════════════════════════════════════════"
echo " ZLAR Crypto Abstraction Layer Tests"
echo "═══════════════════════════════════════════════════════"
echo ""

# ─── Algorithm Resolution ────────────────────────────────────────────────────

echo "── Algorithm Resolution ──"

# Default algorithm
unset ZLAR_SIGN_ALGORITHM
algo=$(zlar_crypto_algorithm)
assert "Default algorithm is ed25519" "${algo}" "ed25519"

label=$(zlar_crypto_label)
assert "Default label is Ed25519" "${label}" "Ed25519"

# Environment variable override
export ZLAR_SIGN_ALGORITHM="ml-dsa-44"
algo=$(zlar_crypto_algorithm)
assert "Env override to ml-dsa-44" "${algo}" "ml-dsa-44"

label=$(zlar_crypto_label)
assert "ML-DSA-44 label" "${label}" "ML-DSA-44"

export ZLAR_SIGN_ALGORITHM="hybrid"
label=$(zlar_crypto_label)
assert "Hybrid label" "${label}" "Ed25519+ML-DSA-44"

# Reset to default for remaining tests
unset ZLAR_SIGN_ALGORITHM

echo ""

# ─── Ed25519 Key Generation ──────────────────────────────────────────────────

echo "── Ed25519 Key Generation ──"

privkey="${TMPDIR_TEST}/test.key"
pubkey="${TMPDIR_TEST}/test.pub"

zlar_crypto_keygen "${privkey}" "${pubkey}"
ec=$?
assert_exit "Keygen succeeds" "${ec}" 0

assert "Private key exists" "$([ -f "${privkey}" ] && echo 'exists')" "exists"
assert "Public key exists" "$([ -f "${pubkey}" ] && echo 'exists')" "exists"

# Private key should be mode 600
perms=$(stat -f%Lp "${privkey}" 2>/dev/null || stat -c%a "${privkey}" 2>/dev/null)
assert "Private key permissions are 600" "${perms}" "600"

# Public key should be mode 644
perms=$(stat -f%Lp "${pubkey}" 2>/dev/null || stat -c%a "${pubkey}" 2>/dev/null)
assert "Public key permissions are 644" "${perms}" "644"

# Key is actually Ed25519
key_type=$(openssl pkey -in "${privkey}" -text -noout 2>/dev/null | head -1)
assert "Key type is Ed25519" "${key_type}" "ED25519"

echo ""

# ─── Signing and Verification ────────────────────────────────────────────────

echo "── Signing and Verification ──"

# Create a test hash file
echo -n "test-content-hash-12345" > "${TMPDIR_TEST}/test-hash.bin"

# Sign
sigfile="${TMPDIR_TEST}/test.sig"
zlar_crypto_sign "${privkey}" "${TMPDIR_TEST}/test-hash.bin" "${sigfile}"
ec=$?
assert_exit "Signing succeeds" "${ec}" 0
assert "Signature file exists" "$([ -f "${sigfile}" ] && echo 'exists')" "exists"
assert "Signature file is non-empty" "$([ -s "${sigfile}" ] && echo 'nonempty')" "nonempty"

# Verify with correct key
zlar_crypto_verify "${pubkey}" "${TMPDIR_TEST}/test-hash.bin" "${sigfile}"
ec=$?
assert_exit "Verification succeeds with correct key" "${ec}" 0

# Verify with wrong content should fail
echo -n "wrong-content" > "${TMPDIR_TEST}/wrong-hash.bin"
ec=0
zlar_crypto_verify "${pubkey}" "${TMPDIR_TEST}/wrong-hash.bin" "${sigfile}" 2>/dev/null || ec=$?
assert_exit "Verification fails with wrong content" "${ec}" 1

# Verify with tampered signature should fail
cp "${sigfile}" "${TMPDIR_TEST}/tampered.sig"
# Flip a byte in the signature
printf '\x00' | dd of="${TMPDIR_TEST}/tampered.sig" bs=1 seek=10 count=1 conv=notrunc 2>/dev/null
ec=0
zlar_crypto_verify "${pubkey}" "${TMPDIR_TEST}/test-hash.bin" "${TMPDIR_TEST}/tampered.sig" 2>/dev/null || ec=$?
assert_exit "Verification fails with tampered signature" "${ec}" 1

# Verify with wrong key should fail
zlar_crypto_keygen "${TMPDIR_TEST}/other.key" "${TMPDIR_TEST}/other.pub"
ec=0
zlar_crypto_verify "${TMPDIR_TEST}/other.pub" "${TMPDIR_TEST}/test-hash.bin" "${sigfile}" 2>/dev/null || ec=$?
assert_exit "Verification fails with wrong key" "${ec}" 1

echo ""

# ─── Algorithm Override for Verification ─────────────────────────────────────

echo "── Algorithm Override for Verification ──"

# Verify an Ed25519 signature when the default algorithm is different
export ZLAR_SIGN_ALGORITHM="ml-dsa-44"
ec=0
zlar_crypto_verify "${pubkey}" "${TMPDIR_TEST}/test-hash.bin" "${sigfile}" "ed25519" || ec=$?
assert_exit "Can verify Ed25519 sig when default is ml-dsa-44" "${ec}" 0
unset ZLAR_SIGN_ALGORITHM

echo ""

# ─── Public Key Utilities ────────────────────────────────────────────────────

echo "── Public Key Utilities ──"

b64=$(zlar_crypto_pubkey_b64 "${privkey}")
assert "Public key base64 is non-empty" "$([ -n "${b64}" ] && echo 'nonempty')" "nonempty"
# Ed25519 DER public key is 44 bytes → ~60 chars base64
assert "Public key base64 has reasonable length" "$([ ${#b64} -gt 20 ] && echo 'ok')" "ok"

fp=$(zlar_crypto_pubkey_fingerprint "${pubkey}")
assert "Fingerprint is 16 chars" "$([ ${#fp} -eq 16 ] && echo 'ok')" "ok"
assert "Fingerprint is hex" "$(echo "${fp}" | grep -E '^[0-9a-f]{16}$' && echo 'ok')" "ok"

echo ""

# ─── Hash Function ───────────────────────────────────────────────────────────

echo "── Hash Function ──"

echo -n "hello world" > "${TMPDIR_TEST}/hash-input.txt"
zlar_crypto_hash "${TMPDIR_TEST}/hash-input.txt" "${TMPDIR_TEST}/hash-output.txt"

hash_val=$(cat "${TMPDIR_TEST}/hash-output.txt")
expected_hash="b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
assert "Hash matches expected SHA-256" "${hash_val}" "${expected_hash}"

hash_label=$(zlar_crypto_hash_label)
assert "Hash label is SHA-256" "${hash_label}" "SHA-256"

echo ""

# ─── Compatibility: Library Produces Same Output as Direct OpenSSL ────────────

echo "── Compatibility with Direct OpenSSL ──"

# Sign the same content with direct openssl and compare
direct_sig="${TMPDIR_TEST}/direct.sig"
openssl pkeyutl -sign -inkey "${privkey}" -rawin \
    -in "${TMPDIR_TEST}/test-hash.bin" \
    -out "${direct_sig}" 2>/dev/null

# Both should verify against the same pubkey
zlar_crypto_verify "${pubkey}" "${TMPDIR_TEST}/test-hash.bin" "${direct_sig}" "ed25519"
ec=$?
assert_exit "Direct openssl signature verifies through abstraction" "${ec}" 0

# Library signature should verify with direct openssl
openssl pkeyutl -verify \
    -pubin -inkey "${pubkey}" -rawin \
    -sigfile "${sigfile}" \
    -in "${TMPDIR_TEST}/test-hash.bin" &>/dev/null
ec=$?
assert_exit "Abstraction signature verifies with direct openssl" "${ec}" 0

echo ""

# ─── ML-DSA-44 (Post-Quantum) ────────────────────────────────────────────────

echo "── ML-DSA-44 (Post-Quantum) ──"

# Check if ML-DSA-44 is available (OpenSSL 3.6+)
if openssl list -signature-algorithms 2>/dev/null | grep -qi "mldsa44\|ml-dsa-44"; then
    export ZLAR_SIGN_ALGORITHM="ml-dsa-44"

    pqc_privkey="${TMPDIR_TEST}/pqc.key"
    pqc_pubkey="${TMPDIR_TEST}/pqc.pub"

    zlar_crypto_keygen "${pqc_privkey}" "${pqc_pubkey}"
    ec=$?
    assert_exit "ML-DSA-44 keygen succeeds" "${ec}" 0
    assert "PQC private key exists" "$([ -f "${pqc_privkey}" ] && echo 'exists')" "exists"

    pqc_key_type=$(openssl pkey -in "${pqc_privkey}" -text -noout 2>/dev/null | head -1)
    assert "Key type is ML-DSA-44" "${pqc_key_type}" "ML-DSA-44"

    # Sign with ML-DSA-44
    echo -n "pqc-test-content" > "${TMPDIR_TEST}/pqc-hash.bin"
    pqc_sigfile="${TMPDIR_TEST}/pqc.sig"
    zlar_crypto_sign "${pqc_privkey}" "${TMPDIR_TEST}/pqc-hash.bin" "${pqc_sigfile}"
    ec=$?
    assert_exit "ML-DSA-44 signing succeeds" "${ec}" 0

    pqc_sig_size=$(wc -c < "${pqc_sigfile}" | tr -d ' ')
    assert "ML-DSA-44 signature is 2420 bytes" "$([ "${pqc_sig_size}" -eq 2420 ] && echo 'ok')" "ok"

    # Verify ML-DSA-44
    ec=0
    zlar_crypto_verify "${pqc_pubkey}" "${TMPDIR_TEST}/pqc-hash.bin" "${pqc_sigfile}" || ec=$?
    assert_exit "ML-DSA-44 verification succeeds" "${ec}" 0

    # Wrong content should fail
    echo -n "wrong" > "${TMPDIR_TEST}/pqc-wrong.bin"
    ec=0
    zlar_crypto_verify "${pqc_pubkey}" "${TMPDIR_TEST}/pqc-wrong.bin" "${pqc_sigfile}" 2>/dev/null || ec=$?
    assert_exit "ML-DSA-44 verification fails with wrong content" "${ec}" 1

    # Cross-algorithm: Ed25519 sig should NOT verify with ML-DSA-44 key
    ec=0
    zlar_crypto_verify "${pqc_pubkey}" "${TMPDIR_TEST}/test-hash.bin" "${sigfile}" "ml-dsa-44" 2>/dev/null || ec=$?
    assert_exit "Ed25519 sig fails against ML-DSA-44 key" "${ec}" 1

    unset ZLAR_SIGN_ALGORITHM
else
    echo "  (skipped — ML-DSA-44 not available, requires OpenSSL 3.6+)"
fi

echo ""

# ─── Hybrid (Ed25519 + ML-DSA-44) ───────────────────────────────────────────

echo "── Hybrid (Ed25519 + ML-DSA-44) ──"

if openssl list -signature-algorithms 2>/dev/null | grep -qi "mldsa44\|ml-dsa-44"; then
    export ZLAR_SIGN_ALGORITHM="hybrid"

    hybrid_privdir="${TMPDIR_TEST}/hybrid-keys"
    hybrid_pubkey="${TMPDIR_TEST}/hybrid.pub"

    zlar_crypto_keygen "${hybrid_privdir}" "${hybrid_pubkey}"
    ec=$?
    assert_exit "Hybrid keygen succeeds" "${ec}" 0
    assert "Hybrid private dir exists" "$([ -d "${hybrid_privdir}" ] && echo 'exists')" "exists"
    assert "Ed25519 subkey exists" "$([ -f "${hybrid_privdir}/ed25519.key" ] && echo 'exists')" "exists"
    assert "ML-DSA-44 subkey exists" "$([ -f "${hybrid_privdir}/ml-dsa-44.key" ] && echo 'exists')" "exists"
    assert "Combined pubkey exists" "$([ -f "${hybrid_pubkey}" ] && echo 'exists')" "exists"

    # Sign with hybrid
    echo -n "hybrid-test-content" > "${TMPDIR_TEST}/hybrid-hash.bin"
    hybrid_sigfile="${TMPDIR_TEST}/hybrid.sig"
    zlar_crypto_sign "${hybrid_privdir}" "${TMPDIR_TEST}/hybrid-hash.bin" "${hybrid_sigfile}"
    ec=$?
    assert_exit "Hybrid signing succeeds" "${ec}" 0

    hybrid_sig_size=$(wc -c < "${hybrid_sigfile}" | tr -d ' ')
    # Hybrid sig = 4-byte length prefix + 64 bytes Ed25519 + 2420 bytes ML-DSA-44 = 2488 bytes
    assert "Hybrid signature is ~2488 bytes" "$([ "${hybrid_sig_size}" -gt 2480 ] && [ "${hybrid_sig_size}" -lt 2500 ] && echo 'ok')" "ok"

    # Verify hybrid
    ec=0
    zlar_crypto_verify "${hybrid_pubkey}" "${TMPDIR_TEST}/hybrid-hash.bin" "${hybrid_sigfile}" || ec=$?
    assert_exit "Hybrid verification succeeds (both algos pass)" "${ec}" 0

    # Wrong content should fail
    ec=0
    zlar_crypto_verify "${hybrid_pubkey}" "${TMPDIR_TEST}/pqc-wrong.bin" "${hybrid_sigfile}" 2>/dev/null || ec=$?
    assert_exit "Hybrid verification fails with wrong content" "${ec}" 1

    label=$(zlar_crypto_label)
    assert "Hybrid label is correct" "${label}" "Ed25519+ML-DSA-44"

    unset ZLAR_SIGN_ALGORITHM
else
    echo "  (skipped — ML-DSA-44 not available, requires OpenSSL 3.6+)"
fi

echo ""

# ─── Double-Source Guard ─────────────────────────────────────────────────────

echo "── Double-Source Guard ──"

# Sourcing twice should be safe (guard prevents re-execution)
source "${PROJECT_DIR}/lib/crypto.sh"
algo=$(zlar_crypto_algorithm)
assert "Double-source is safe" "${algo}" "ed25519"

echo ""

# ─── Results ─────────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════"
echo " Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════════════════════════════════════════"

[ "${FAIL}" -eq 0 ] || exit 1
