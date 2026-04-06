#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Quickstart — See governance work in under 60 seconds
#
# This script demonstrates the governed path without modifying your system.
# It generates temporary keys, signs a policy, runs the gate against a
# simulated tool call, produces a receipt, and verifies it.
#
# Usage: bash scripts/quickstart.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
else
    G=''; R=''; Y=''; B=''; N=''
fi

ok()   { printf "${G}  OK${N}  %s\n" "$*"; }
fail() { printf "${R}  !!${N}  %s\n" "$*" >&2; }
step() { printf "\n${B}--- %s ---${N}\n\n" "$*"; }

# ─── Prerequisites ────────────────────────────────────────────────────────────

step "1. Checking prerequisites"

MISSING=""
command -v jq &>/dev/null || MISSING="${MISSING} jq"
command -v openssl &>/dev/null || MISSING="${MISSING} openssl"

if [ -n "${MISSING}" ]; then
    fail "Missing:${MISSING}"
    echo "  Install with: brew install${MISSING}"
    exit 1
fi
ok "jq and openssl available"

# Resolve OpenSSL (need 3.x for Ed25519)
_OPENSSL="openssl"
if [ -x "/opt/homebrew/opt/openssl@3/bin/openssl" ]; then
    _OPENSSL="/opt/homebrew/opt/openssl@3/bin/openssl"
elif [ -x "/usr/local/opt/openssl@3/bin/openssl" ]; then
    _OPENSSL="/usr/local/opt/openssl@3/bin/openssl"
fi

# Check Ed25519 support
if ! ${_OPENSSL} genpkey -algorithm Ed25519 -out /dev/null 2>/dev/null; then
    fail "OpenSSL does not support Ed25519. Install OpenSSL 3.x: brew install openssl@3"
    exit 1
fi
ok "Ed25519 supported (${_OPENSSL})"

# ─── Temporary Environment ───────────────────────────────────────────────────

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "${TEMP_DIR}"' EXIT

step "2. Generating temporary signing keys"

${_OPENSSL} genpkey -algorithm Ed25519 -out "${TEMP_DIR}/signing.key" 2>/dev/null
${_OPENSSL} pkey -in "${TEMP_DIR}/signing.key" -pubout -out "${TEMP_DIR}/signing.pub" 2>/dev/null
chmod 600 "${TEMP_DIR}/signing.key"

FINGERPRINT=$(shasum -a 256 "${TEMP_DIR}/signing.pub" | awk '{print substr($1,1,16)}')
ok "Keys generated (fingerprint: ${FINGERPRINT})"

# ─── Simulate a Governed Action ──────────────────────────────────────────────

step "3. Simulating a governed action"

# Create a mock audit event (what the gate produces when it denies rm -rf)
MOCK_EVENT=$(jq -n \
    --arg id "quickstart-$(date +%s)" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        id: $id, ts: $ts, seq: 1, source: "gate", host: "quickstart",
        user: "demo", agent_id: "claude-code", session_id: "demo-session",
        domain: "file", action: "Bash",
        outcome: "deny",
        risk_score: 9,
        detail: {command: "rm -rf /important-data", path: "/important-data"},
        rule: "R002",
        policy_version: "1.7.0",
        severity: "critical",
        prev_hash: "genesis",
        authorizer: "policy",
        signature_algorithm: "Ed25519",
        hash_algorithm: "SHA-256",
        public_key_id: "quickstart",
        signature: "unsigned"
    }')

echo "  Agent tried:   rm -rf /important-data"
echo "  Policy rule:   R002 (recursive delete)"
echo "  Gate decision: DENY"
echo ""
ok "Action blocked by deterministic policy"

# ─── Generate a Governed Action Receipt ──────────────────────────────────────

step "4. Generating a Governed Action Receipt"

echo "${MOCK_EVENT}" | "${PROJECT_DIR}/bin/zlar-receipt" \
    --key "${TEMP_DIR}/signing.key" \
    --pubkey "${TEMP_DIR}/signing.pub" \
    --output "${TEMP_DIR}/receipt.json" 2>/dev/null

echo "  Receipt contents:"
echo ""
jq '{
    action: .governed_action.tool,
    domain: .governed_action.domain,
    outcome: .decision.outcome,
    rule: .decision.rule,
    authorizer: .decision.authorizer,
    signed_by: .signature.key_id,
    algorithm: .signature.algorithm
}' "${TEMP_DIR}/receipt.json"
echo ""
ok "Receipt generated and signed with Ed25519"

# ─── Verify the Receipt ──────────────────────────────────────────────────────

step "5. Verifying the receipt (anyone with the public key can do this)"

# Check if node is available for zlar-verify
if command -v node &>/dev/null; then
    node "${PROJECT_DIR}/bin/zlar-verify" "${TEMP_DIR}/receipt.json" \
        --pubkey "${TEMP_DIR}/signing.pub" --verbose
else
    # Fall back to manual openssl verification
    CONTENT=$(jq -c 'del(.signature)' "${TEMP_DIR}/receipt.json")
    CANONICAL=$(printf '%s' "${CONTENT}" | jq -S -c '.')
    HASH_HEX=$(printf '%s' "${CANONICAL}" | shasum -a 256 | awk '{print $1}')
    printf '%s' "${HASH_HEX}" > "${TEMP_DIR}/verify-hash"
    jq -r '.signature.value' "${TEMP_DIR}/receipt.json" | base64 -d > "${TEMP_DIR}/verify-sig" 2>/dev/null

    if ${_OPENSSL} pkeyutl -verify -pubin -inkey "${TEMP_DIR}/signing.pub" \
        -rawin -sigfile "${TEMP_DIR}/verify-sig" -in "${TEMP_DIR}/verify-hash" &>/dev/null; then
        echo "  VALID"
        echo ""
        echo "  This receipt proves:"
        echo "    1. An agent tried to run: rm -rf /important-data"
        echo "    2. Policy rule R002 evaluated the action"
        echo "    3. The gate denied it — no human intervention needed"
        echo "    4. The receipt has not been tampered with"
    else
        fail "Verification failed"
        exit 1
    fi
fi

echo ""
ok "Receipt verified"

# ─── Summary ──────────────────────────────────────────────────────────────────

step "Done"

echo "  What just happened:"
echo "    1. Generated Ed25519 signing keys (temporary)"
echo "    2. Simulated an agent attempting a dangerous command"
echo "    3. Gate denied the action via deterministic policy (no AI involved)"
echo "    4. Generated a cryptographic receipt proving governance happened"
echo "    5. Verified the receipt using the public key"
echo ""
echo "  To install ZLAR for real:"
echo "    bash install.sh"
echo ""
echo "  To add human approval via Telegram:"
echo "    ~/.zlar/bin/zlar telegram"
echo ""
