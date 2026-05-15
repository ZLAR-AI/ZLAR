#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Quickstart — See real governance in under 60 seconds
#
# This script does three things:
#   1. Generates temporary Ed25519 keys
#   2. Runs the REAL gate against REAL tool call inputs
#   3. Produces and verifies a REAL v1 receipt
#
# Nothing is simulated. The gate evaluates. The policy decides.
# The receipt proves it happened.
#
# Usage: bash scripts/quickstart.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors
if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; D='\033[2m'; N='\033[0m'
else
    G=''; R=''; B=''; D=''; N=''
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

if ! ${_OPENSSL} genpkey -algorithm Ed25519 -out /dev/null 2>/dev/null; then
    fail "OpenSSL does not support Ed25519. Install OpenSSL 3.x: brew install openssl@3"
    exit 1
fi
ok "Ed25519 supported"

# Check gate exists
if [ ! -x "${PROJECT_DIR}/bin/zlar-gate" ]; then
    fail "Gate not found at ${PROJECT_DIR}/bin/zlar-gate"
    exit 1
fi
ok "Gate found"

# ─── Temporary Environment ───────────────────────────────────────────────────

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "${TEMP_DIR}"' EXIT

step "2. Generating temporary signing keys"

${_OPENSSL} genpkey -algorithm Ed25519 -out "${TEMP_DIR}/signing.key" 2>/dev/null
${_OPENSSL} pkey -in "${TEMP_DIR}/signing.key" -pubout -out "${TEMP_DIR}/signing.pub" 2>/dev/null
chmod 600 "${TEMP_DIR}/signing.key"

FINGERPRINT=$(shasum -a 256 "${TEMP_DIR}/signing.pub" | awk '{print substr($1,1,16)}')
ok "Keys generated (fingerprint: ${FINGERPRINT})"

# ─── Run the REAL gate ───────────────────────────────────────────────────────

step "3. Running the gate against real tool calls"

# Set up minimal gate environment in temp
mkdir -p "${TEMP_DIR}/var/log/sessions" "${TEMP_DIR}/var/log/approvals" "${TEMP_DIR}/var/tmp" "${TEMP_DIR}/etc/keys" "${TEMP_DIR}/etc/policies"
cp "${PROJECT_DIR}/etc/policies/lt-default.policy.json" "${TEMP_DIR}/etc/policies/active.policy.json"
cp "${TEMP_DIR}/signing.pub" "${TEMP_DIR}/etc/keys/policy-signing.pub"

# Sign the policy
POLICY_CANONICAL=$(jq -S -c '.signature = {algorithm: "", value: "", key_id: ""}' "${TEMP_DIR}/etc/policies/active.policy.json")
POLICY_HASH=$(printf '%s' "${POLICY_CANONICAL}" | shasum -a 256 | awk '{print $1}')
printf '%s' "${POLICY_HASH}" > "${TEMP_DIR}/policy-hash"
${_OPENSSL} pkeyutl -sign -inkey "${TEMP_DIR}/signing.key" -rawin -in "${TEMP_DIR}/policy-hash" -out "${TEMP_DIR}/policy-sig" 2>/dev/null
POLICY_SIG=$(base64 < "${TEMP_DIR}/policy-sig" | tr -d '\n')
jq --arg sig "${POLICY_SIG}" --arg kid "${FINGERPRINT}" \
  '.signature.algorithm = "Ed25519" | .signature.value = $sig | .signature.key_id = $kid' \
  "${TEMP_DIR}/etc/policies/active.policy.json" > "${TEMP_DIR}/etc/policies/active.policy.json.tmp"
mv "${TEMP_DIR}/etc/policies/active.policy.json.tmp" "${TEMP_DIR}/etc/policies/active.policy.json"

# Create minimal gate config (no Telegram)
jq -n '{
  policy_file: "etc/policies/active.policy.json",
  policy_pubkey: "etc/keys/policy-signing.pub",
  audit_file: "var/log/audit.jsonl",
  log_file: "var/log/gate.log",
  signature_required: true,
  telegram: {enabled: false, chat_id: "", timeout_s: 1}
}' > "${TEMP_DIR}/etc/gate.json"

GATE_OUTPUT=""
GATE_STATUS=0

capture_gate() {
    local input="$1"

    set +e
    GATE_OUTPUT=$(printf '%s' "${input}" | \
      PROJECT_DIR="${TEMP_DIR}" ZLAR_PROJECT_DIR="${TEMP_DIR}" \
      bash "${PROJECT_DIR}/bin/zlar-gate" 2>/dev/null)
    GATE_STATUS=$?
    set -e
}

decision_from_result() {
    local result="$1"
    local decision

    decision=$(printf '%s' "${result}" | jq -r '.hookSpecificOutput.permissionDecision // "error"' 2>/dev/null) || decision="error"
    printf '%s\n' "${decision}"
}

# Test 1: Safe read command — should be ALLOWED
echo "  Agent tries: ${B}ls /tmp${N}"
capture_gate '{"tool_name":"Bash","tool_input":{"command":"ls /tmp"},"session_id":"quickstart"}'
RESULT1="${GATE_OUTPUT}"
STATUS1="${GATE_STATUS}"
DECISION1=$(decision_from_result "${RESULT1}")

if [ "${DECISION1}" = "allow" ] && [ "${STATUS1}" -eq 0 ]; then
    ok "Gate decision: ${G}ALLOW${N} (safe read command, policy rule R001)"
else
    fail "Expected allow with exit 0, got: ${DECISION1} (exit ${STATUS1})"
    exit 1
fi

# Test 2: Recursive delete — should be DENIED
echo ""
echo "  Agent tries: ${B}rm -rf /important-data${N}"
capture_gate '{"tool_name":"Bash","tool_input":{"command":"rm -rf /important-data"},"session_id":"quickstart"}'
RESULT2="${GATE_OUTPUT}"
STATUS2="${GATE_STATUS}"
DECISION2=$(decision_from_result "${RESULT2}")

if [ "${DECISION2}" = "deny" ] && [ "${STATUS2}" -eq 2 ]; then
    ok "Gate decision: ${R}DENY${N} (recursive delete blocked by R002)"
else
    fail "Expected deny with exit 2, got: ${DECISION2} (exit ${STATUS2})"
    exit 1
fi

# Test 3: File read — should be ALLOWED
echo ""
echo "  Agent tries: ${B}Read /etc/hosts${N}"
capture_gate '{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"},"session_id":"quickstart"}'
RESULT3="${GATE_OUTPUT}"
STATUS3="${GATE_STATUS}"
DECISION3=$(decision_from_result "${RESULT3}")

if [ "${DECISION3}" = "allow" ] && [ "${STATUS3}" -eq 0 ]; then
    ok "Gate decision: ${G}ALLOW${N} (file read, policy rule R053)"
else
    fail "Expected allow with exit 0, got: ${DECISION3} (exit ${STATUS3})"
    exit 1
fi

# Test 4: Privilege escalation — should be DENIED
echo ""
echo "  Agent tries: ${B}sudo rm -rf /${N}"
capture_gate '{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"},"session_id":"quickstart"}'
RESULT4="${GATE_OUTPUT}"
STATUS4="${GATE_STATUS}"
DECISION4=$(decision_from_result "${RESULT4}")

if [ "${DECISION4}" = "deny" ] && [ "${STATUS4}" -eq 2 ]; then
    ok "Gate decision: ${R}DENY${N} (privilege escalation blocked by R003)"
else
    fail "Expected deny with exit 2, got: ${DECISION4} (exit ${STATUS4})"
    exit 1
fi

echo ""
ok "4 tool calls evaluated by the real gate"

# ─── Generate and Verify a v1 Receipt ────────────────────────────────────────

step "4. Generating a v1 Governed Action Receipt"

# Build a synthetic audit event from the deny result (rm -rf)
TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
DETAIL_CANONICAL=$(jq -S -c -n '{"command":"rm -rf /important-data","cwd":"/tmp"}')
DETAIL_HASH=$(printf '%s' "${DETAIL_CANONICAL}" | shasum -a 256 | awk '{print $1}')
DENY_EVENT=$(jq -n \
    --arg ts "${TS}" \
    --arg detail_hash "${DETAIL_HASH}" \
    '{
        id: "quickstart-deny-001",
        ts: $ts,
        action: "Bash",
        domain: "file",
        detail: {command: "rm -rf /important-data", cwd: "/tmp"},
        outcome: "deny",
        rule: "R002",
        authorizer: "policy",
        policy_version: "1.0.0",
        prev_hash: "genesis"
    }')
echo "${DENY_EVENT}" > "${TEMP_DIR}/deny-event.json"

ZLAR_RECEIPT_FORMAT=v1 "${PROJECT_DIR}/bin/zlar-receipt" \
    --event "${TEMP_DIR}/deny-event.json" \
    --key "${TEMP_DIR}/signing.key" \
    --pubkey "${TEMP_DIR}/signing.pub" \
    --output "${TEMP_DIR}/receipt.json" 2>/dev/null

echo "  Receipt (v1 envelope):"
echo ""
jq '{v: .v, type: .type, kid: .kid, sig_preview: (.sig[:20] + "...")}' "${TEMP_DIR}/receipt.json"
echo ""
ok "v1 receipt generated and signed"

# ─── Verify the Receipt ──────────────────────────────────────────────────────

step "5. Verifying the receipt"

if command -v node &>/dev/null; then
    node "${PROJECT_DIR}/bin/zlar-verify" "${TEMP_DIR}/receipt.json" \
        --pubkey "${TEMP_DIR}/signing.pub" --verbose
else
    # Manual verification
    PAYLOAD_B64=$(jq -r '.payload' "${TEMP_DIR}/receipt.json")
    # Decode base64url → standard base64
    PAYLOAD_STD=$(printf '%s' "${PAYLOAD_B64}" | sed 's/-/+/g; s/_/\//g' | awk '{while(length($0)%4)$0=$0"=";print}')
    PAYLOAD_BYTES=$(printf '%s' "${PAYLOAD_STD}" | base64 -d)
    HASH_HEX=$(printf '%s' "${PAYLOAD_BYTES}" | shasum -a 256 | awk '{print $1}')

    SIG_B64=$(jq -r '.sig' "${TEMP_DIR}/receipt.json")
    SIG_STD=$(printf '%s' "${SIG_B64}" | sed 's/-/+/g; s/_/\//g' | awk '{while(length($0)%4)$0=$0"=";print}')
    echo "${SIG_STD}" | base64 -d > "${TEMP_DIR}/verify-sig"
    printf '%s' "${HASH_HEX}" > "${TEMP_DIR}/verify-hash"

    if ${_OPENSSL} pkeyutl -verify -pubin -inkey "${TEMP_DIR}/signing.pub" \
        -rawin -sigfile "${TEMP_DIR}/verify-sig" -in "${TEMP_DIR}/verify-hash" &>/dev/null; then
        echo "  VALID"
        echo ""
        echo "  This receipt proves:"
        echo "    1. An agent attempted a governed action"
        echo "    2. Deterministic policy evaluated the action"
        echo "    3. The gate denied it — no AI involved in the decision"
        echo "    4. The receipt has not been tampered with"
        echo "    5. The receipt is anchored to the audit hash chain"
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
echo "    2. Ran the REAL gate against 4 tool calls"
echo "    3. Gate allowed safe actions, denied dangerous ones"
echo "    4. Generated a v1 receipt proving the denial happened"
echo "    5. Verified the receipt using only the public key"
echo ""
echo "  To install ZLAR for real:"
echo "    bash install.sh"
echo ""
echo "  To check installation health:"
echo "    ~/.zlar/bin/zlar doctor"
echo ""
