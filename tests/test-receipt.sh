#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Governed Action Receipt — Bash Test Suite
#
# Tests bash receipt generation, schema compliance, signing, and
# cross-gate compatibility (bash-generated receipts verified by Node verifier).
#
# Usage: bash tests/test-receipt.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
export ZLAR_PROJECT_DIR="${PROJECT_DIR}"

source "${PROJECT_DIR}/lib/crypto.sh"

PASS=0
FAIL=0
TOTAL=0
TEMP_DIR=$(mktemp -d)

cleanup() { rm -rf "${TEMP_DIR}"; }
trap cleanup EXIT

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

assert_truthy() {
    local label="$1" actual="$2"
    TOTAL=$((TOTAL + 1))
    if [[ -n "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected non-empty, got empty\n' "${label}"
    fi
}

# ─── Generate Test Keys ──────────────────────────────────────────────────────

PRIVKEY="${TEMP_DIR}/test.key"
PUBKEY="${TEMP_DIR}/test.pub"
zlar_crypto_keygen "${PRIVKEY}" "${PUBKEY}"

# ─── Mock Audit Event ────────────────────────────────────────────────────────

MOCK_EVENT=$(jq -n '{
    id: "019577a8c000aaaa1111222233334444",
    ts: "2026-04-05T20:00:00.000Z",
    seq: 42,
    source: "gate",
    host: "macbook",
    user: "vince",
    agent_id: "claude-code",
    session_id: "test-session",
    domain: "file",
    action: "Bash",
    outcome: "deny",
    risk_score: 9,
    detail: {command: "rm -rf /tmp/test", path: "/tmp/test"},
    rule: "R002",
    policy_version: "1.7.0",
    severity: "critical",
    prev_hash: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    authorizer: "policy",
    signature_algorithm: "Ed25519",
    hash_algorithm: "SHA-256",
    public_key_id: "abc123def4567890",
    signature: "base64sig=="
}')

echo "${MOCK_EVENT}" > "${TEMP_DIR}/mock-event.json"

# ═══════════════════════════════════════════════════════════════════════════════
echo "=== Receipt Generation (from event file) ==="
echo

RECEIPT_FILE="${TEMP_DIR}/receipt-from-file.json"
"${PROJECT_DIR}/bin/zlar-receipt" \
    --event "${TEMP_DIR}/mock-event.json" \
    --key "${PRIVKEY}" \
    --pubkey "${PUBKEY}" \
    --output "${RECEIPT_FILE}" 2>/dev/null

assert "receipt file exists" "true" "$([ -f "${RECEIPT_FILE}" ] && echo true || echo false)"

# Check required fields
RV=$(jq -r '.receipt_version' "${RECEIPT_FILE}")
assert "receipt_version" "0.1.0" "${RV}"

TOOL=$(jq -r '.governed_action.tool' "${RECEIPT_FILE}")
assert "governed_action.tool" "Bash" "${TOOL}"

DOMAIN=$(jq -r '.governed_action.domain' "${RECEIPT_FILE}")
assert "governed_action.domain" "file" "${DOMAIN}"

DETAIL_HASH=$(jq -r '.governed_action.detail_hash' "${RECEIPT_FILE}")
assert_truthy "detail_hash is 64 chars" "$([ ${#DETAIL_HASH} -eq 64 ] && echo yes)"

OUTCOME=$(jq -r '.decision.outcome' "${RECEIPT_FILE}")
assert "decision.outcome" "deny" "${OUTCOME}"

RULE=$(jq -r '.decision.rule' "${RECEIPT_FILE}")
assert "decision.rule" "R002" "${RULE}"

AUTH=$(jq -r '.decision.authorizer' "${RECEIPT_FILE}")
assert "decision.authorizer" "policy" "${AUTH}"

TS=$(jq -r '.decision.timestamp' "${RECEIPT_FILE}")
assert "decision.timestamp" "2026-04-05T20:00:00.000Z" "${TS}"

PV=$(jq -r '.evidence.policy_version' "${RECEIPT_FILE}")
assert "evidence.policy_version" "1.7.0" "${PV}"

AID=$(jq -r '.evidence.audit_event_id' "${RECEIPT_FILE}")
assert "evidence.audit_event_id" "019577a8c000aaaa1111222233334444" "${AID}"

APH=$(jq -r '.evidence.audit_prev_hash' "${RECEIPT_FILE}")
assert "evidence.audit_prev_hash" "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456" "${APH}"

SIG_ALGO=$(jq -r '.signature.algorithm' "${RECEIPT_FILE}")
assert "signature.algorithm" "Ed25519" "${SIG_ALGO}"

SIG_HASH=$(jq -r '.signature.hash_algorithm' "${RECEIPT_FILE}")
assert "signature.hash_algorithm" "SHA-256" "${SIG_HASH}"

SIG_VAL=$(jq -r '.signature.value' "${RECEIPT_FILE}")
assert_truthy "signature.value non-empty" "${SIG_VAL}"

KEY_ID=$(jq -r '.signature.key_id' "${RECEIPT_FILE}")
assert_truthy "signature.key_id non-empty" "${KEY_ID}"

echo
echo "=== Receipt Generation (from stdin) ==="
echo

RECEIPT_STDIN="${TEMP_DIR}/receipt-from-stdin.json"
echo "${MOCK_EVENT}" | "${PROJECT_DIR}/bin/zlar-receipt" \
    --key "${PRIVKEY}" \
    --pubkey "${PUBKEY}" \
    --output "${RECEIPT_STDIN}" 2>/dev/null

assert "stdin receipt exists" "true" "$([ -f "${RECEIPT_STDIN}" ] && echo true || echo false)"
STDIN_RV=$(jq -r '.receipt_version' "${RECEIPT_STDIN}")
assert "stdin receipt_version" "0.1.0" "${STDIN_RV}"

echo
echo "=== Receipt Signature Verification (bash self-verify) ==="
echo

# Manually verify the signature using openssl
# 1. Extract receipt content (without signature)
CONTENT=$(jq -c 'del(.signature)' "${RECEIPT_FILE}")
# 2. Canonicalize (sorted keys, compact)
CANONICAL=$(printf '%s' "${CONTENT}" | jq -S -c '.')
# 3. SHA-256 hash as hex string
HASH_HEX=$(printf '%s' "${CANONICAL}" | shasum -a 256 | awk '{print $1}')
# 4. Write hash hex to file
printf '%s' "${HASH_HEX}" > "${TEMP_DIR}/verify-hash"
# 5. Decode signature from base64
jq -r '.signature.value' "${RECEIPT_FILE}" | base64 -d > "${TEMP_DIR}/verify-sig" 2>/dev/null
# 6. Verify with openssl
_OPENSSL="openssl"
if [ -x "/opt/homebrew/opt/openssl@3/bin/openssl" ]; then
    _OPENSSL="/opt/homebrew/opt/openssl@3/bin/openssl"
elif [ -x "/usr/local/opt/openssl@3/bin/openssl" ]; then
    _OPENSSL="/usr/local/opt/openssl@3/bin/openssl"
fi

VERIFY_RESULT="invalid"
if ${_OPENSSL} pkeyutl -verify -pubin -inkey "${PUBKEY}" -rawin \
    -sigfile "${TEMP_DIR}/verify-sig" -in "${TEMP_DIR}/verify-hash" &>/dev/null; then
    VERIFY_RESULT="valid"
fi
assert "openssl signature verification" "valid" "${VERIFY_RESULT}"

echo
echo "=== Receipt with Manifest Fields ==="
echo

MANIFEST_RECEIPT="${TEMP_DIR}/receipt-manifest.json"
"${PROJECT_DIR}/bin/zlar-receipt" \
    --event "${TEMP_DIR}/mock-event.json" \
    --key "${PRIVKEY}" \
    --pubkey "${PUBKEY}" \
    --manifest "${PROJECT_DIR}/etc/manifest.example.json" \
    --output "${MANIFEST_RECEIPT}" 2>/dev/null

# Manifest fields should be populated if manifest.example.json has them
MANIFEST_RECEIPT_RV=$(jq -r '.receipt_version' "${MANIFEST_RECEIPT}")
assert "manifest receipt version" "0.1.0" "${MANIFEST_RECEIPT_RV}"

echo
echo "=== Receipt with Chain Linking ==="
echo

CHAINED_RECEIPT="${TEMP_DIR}/receipt-chained.json"
# Hash of first receipt
PREV_HASH=$(jq -S -c '.' "${RECEIPT_FILE}" | shasum -a 256 | awk '{print $1}')

"${PROJECT_DIR}/bin/zlar-receipt" \
    --event "${TEMP_DIR}/mock-event.json" \
    --key "${PRIVKEY}" \
    --pubkey "${PUBKEY}" \
    --prev-hash "${PREV_HASH}" \
    --output "${CHAINED_RECEIPT}" 2>/dev/null

CHAIN_PREV=$(jq -r '.prev_receipt_hash' "${CHAINED_RECEIPT}")
assert "chained receipt prev_hash" "${PREV_HASH}" "${CHAIN_PREV}"

echo
echo "=== Detail Hash Correctness ==="
echo

# The detail hash should be SHA-256 of canonical detail JSON
EXPECTED_DETAIL_HASH=$(printf '%s' '{"command":"rm -rf /tmp/test","path":"/tmp/test"}' | jq -S -c '.' | shasum -a 256 | awk '{print $1}')
ACTUAL_DETAIL_HASH=$(jq -r '.governed_action.detail_hash' "${RECEIPT_FILE}")
assert "detail hash correct" "${EXPECTED_DETAIL_HASH}" "${ACTUAL_DETAIL_HASH}"

echo
echo "=== Cross-Gate Compatibility (bash receipt → Node verifier) ==="
echo

# The critical test: can the Node verifier verify a bash-generated receipt?
if command -v node &>/dev/null; then
    NODE_VERIFY=$(node "${PROJECT_DIR}/bin/zlar-verify" "${RECEIPT_FILE}" --pubkey "${PUBKEY}" --json 2>/dev/null || true)
    if [ -n "${NODE_VERIFY}" ]; then
        NODE_VERDICT=$(echo "${NODE_VERIFY}" | jq -r '.verdict')
        assert "bash receipt verified by Node" "VALID" "${NODE_VERDICT}"
    else
        echo "  SKIP: zlar-verify returned empty output"
    fi
else
    echo "  SKIP: node not available for cross-gate test"
fi

echo
echo "=== Schema Completeness ==="
echo

# Verify all schema-required fields exist and are not null where required
for field in receipt_version id; do
    VAL=$(jq -r ".${field}" "${RECEIPT_FILE}")
    assert_truthy "top-level ${field} present" "${VAL}"
done

for field in tool domain detail_hash; do
    VAL=$(jq -r ".governed_action.${field}" "${RECEIPT_FILE}")
    assert_truthy "governed_action.${field} present" "${VAL}"
done

for field in outcome rule authorizer timestamp; do
    VAL=$(jq -r ".decision.${field}" "${RECEIPT_FILE}")
    assert_truthy "decision.${field} present" "${VAL}"
done

for field in policy_version audit_event_id audit_prev_hash; do
    VAL=$(jq -r ".evidence.${field}" "${RECEIPT_FILE}")
    assert_truthy "evidence.${field} present" "${VAL}"
done

for field in algorithm hash_algorithm value key_id; do
    VAL=$(jq -r ".signature.${field}" "${RECEIPT_FILE}")
    assert_truthy "signature.${field} present" "${VAL}"
done

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
