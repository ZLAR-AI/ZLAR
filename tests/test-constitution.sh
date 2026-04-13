#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Test suite for the Second Authority Law — Constitutional validation
#
# Categories:
#   A: Constitution presence and signature (6 tests)
#   B: Key separation (3 tests)
#   C: Permanent core enforcement (8 tests)
#   D: Derived properties (3 tests)
#   E: Observability obligations (2 tests)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Use temp directory for test state
TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

# Mock log function
log() { :; }

# Set PROJECT_DIR to temp dir
export PROJECT_DIR="${TEST_DIR}"

# Source crypto
export _CRYPTO_PROJECT_DIR="${REAL_PROJECT_DIR}"
source "${REAL_PROJECT_DIR}/lib/crypto.sh"

PASS=0
FAIL=0

assert() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  PASS  ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  ${desc} (expected=${expected}, actual=${actual})"
        FAIL=$((FAIL + 1))
    fi
}

# ── Setup: generate test keys ──────────────────────────────────────────────

setup_keys() {
    mkdir -p "${TEST_DIR}/etc/keys" "${TEST_DIR}/var/log" "${TEST_DIR}/var/log/sessions" \
             "${TEST_DIR}/etc/policies" "${TEST_DIR}/var/tmp" 2>/dev/null

    # Constitutional keypair
    zlar_crypto_keygen "${TEST_DIR}/const.key" "${TEST_DIR}/etc/keys/constitution-signing.pub" 2>/dev/null

    # Policy keypair (different)
    zlar_crypto_keygen "${TEST_DIR}/policy.key" "${TEST_DIR}/etc/keys/policy-signing.pub" 2>/dev/null

    # Same-key pair (for testing PC-06 violation)
    cp "${TEST_DIR}/const.key" "${TEST_DIR}/same.key"
    cp "${TEST_DIR}/etc/keys/constitution-signing.pub" "${TEST_DIR}/same.pub"
}

# ── Setup: create and sign a valid constitution ────────────────────────────

create_valid_constitution() {
    local output="${1:-${TEST_DIR}/etc/constitution.json}"
    cat > "${TEST_DIR}/etc/constitution-unsigned.json" <<'CONSTEOF'
{
  "constitution_version": "1.0.0",
  "created_at": "2026-04-13T00:00:00Z",
  "author": "test",
  "preamble": "Test constitution.",
  "permanent_core": {
    "clauses": [
      {"id":"PC-01","title":"Evidence","enforcement":"reject_silent_consequential_power"},
      {"id":"PC-02","title":"Real authority","enforcement":"check_human_authority_real"},
      {"id":"PC-03","title":"Sovereign stop","enforcement":"structural"},
      {"id":"PC-04","title":"Suspended means stop","enforcement":"check_suspended_means_stop"},
      {"id":"PC-05","title":"Deny governance-critical powers","enforcement":"check_manifest_denies_reserved_powers"},
      {"id":"PC-06","title":"Key separation","enforcement":"check_key_separation"},
      {"id":"PC-07","title":"Core unamendable","enforcement":"structural"}
    ]
  },
  "derived_properties": {"properties":[]},
  "observability_obligations": {"obligations":[]},
  "amendable_constraints": {
    "manifest_deny_required_classes": [
      "governance_mutation","evidence_mutation","stop_restart_control",
      "key_material_signing_authority","self_expansion_of_authority",
      "communication_channel_mutation"
    ],
    "escalation": {"degraded":"log","at_risk":"ask","suspended":"deny"},
    "evidence": {"minimum_retention_hours": 720},
    "amendment_ceremony": {"cooling_off_period_hours": 72, "minimum_cooling_off_hours": 24}
  },
  "signature": {"algorithm":"","public_key":"","value":""}
}
CONSTEOF

    # Sign it
    local algo pubkey_b64 canon_file hash_file sig_file sig_b64
    algo=$(zlar_crypto_algorithm)
    pubkey_b64=$(zlar_crypto_pubkey_b64 "${TEST_DIR}/const.key")

    canon_file=$(mktemp "${TEST_DIR}/var/tmp/canon.XXXXXX")
    hash_file=$(mktemp "${TEST_DIR}/var/tmp/hash.XXXXXX")
    sig_file=$(mktemp "${TEST_DIR}/var/tmp/sig.XXXXXX")

    jq --arg pubkey "${pubkey_b64}" --arg algo "${algo}" \
       '.signature.algorithm = $algo | .signature.public_key = $pubkey | .signature.value = ""' \
       "${TEST_DIR}/etc/constitution-unsigned.json" > "${canon_file}"
    zlar_crypto_hash "${canon_file}" "${hash_file}"
    zlar_crypto_sign "${TEST_DIR}/const.key" "${hash_file}" "${sig_file}" 2>/dev/null
    sig_b64=$(base64 < "${sig_file}" | tr -d '\n')

    jq --arg pubkey "${pubkey_b64}" --arg sig "${sig_b64}" --arg algo "${algo}" \
       '.signature.algorithm = $algo | .signature.public_key = $pubkey | .signature.value = $sig' \
       "${TEST_DIR}/etc/constitution-unsigned.json" > "${output}"

    rm -f "${canon_file}" "${hash_file}" "${sig_file}"

    # Set presence tracker (simulates zlar-constitution deploy)
    mkdir -p "$(dirname "${CONSTITUTION_PRESENCE_FILE}")" 2>/dev/null || true
    shasum -a 256 "${output}" 2>/dev/null | awk '{print $1}' > "${CONSTITUTION_PRESENCE_FILE}"
}

# ── Setup: create a valid policy ───────────────────────────────────────────

create_valid_policy() {
    cat > "${TEST_DIR}/etc/policies/active.policy.json" <<'POLICYEOF'
{
  "version": "test-1.0",
  "default_action": "deny",
  "signature": {"algorithm":"ed25519","public_key":"","value":"test"},
  "rules": [
    {"id":"R001","action":"allow","domain":"read","audit":true,"risk_score":{"irreversibility":0,"consequence":0,"blast_radius":0}},
    {"id":"R041","action":"ask","domain":"bash","audit":true,"risk_score":{"irreversibility":50,"consequence":50,"blast_radius":50}},
    {"id":"R002","action":"deny","domain":"bash","audit":true,"risk_score":{"irreversibility":100,"consequence":100,"blast_radius":95}}
  ]
}
POLICYEOF
}

# ── Source the gate's validate_constitution function ───────────────────────
# We extract and source just the function, not the whole gate.

GATE_TMP="${TEST_DIR}/var/tmp"
CONSTITUTION_FILE="${TEST_DIR}/etc/constitution.json"
CONSTITUTION_PUBKEY="${TEST_DIR}/etc/keys/constitution-signing.pub"
CONSTITUTION_PRESENCE_FILE="${TEST_DIR}/var/log/.constitution-last-hash"
POLICY_FILE="${TEST_DIR}/etc/policies/active.policy.json"
POLICY_PUBKEY="${TEST_DIR}/etc/keys/policy-signing.pub"
SESSION_DIR="${TEST_DIR}/var/log/sessions"
SESSION_ID="test-session-001"
MANIFEST_LOADED="false"
MANIFEST_JSON=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT_ID=""
_CONSTITUTION_VALIDATED=""

# Source the validate_constitution function from the gate.
# Extract lines 991-1130 which contain the complete function.
eval "$(sed -n '991,1149p' "${REAL_PROJECT_DIR}/bin/zlar-gate")"

# Source _dp03_check from the constitution CLI for direct testing.
eval "$(sed -n '692,780p' "${REAL_PROJECT_DIR}/bin/zlar-constitution")"

# ── Run setup ──────────────────────────────────────────────────────────────

setup_keys
create_valid_policy

echo "Second Authority Law — Constitutional Tests"
echo "============================================"
echo

# ══════════════════════════════════════════════════════════════
# Section A: Presence and signature
# ══════════════════════════════════════════════════════════════
echo "-- Section A: Presence and signature --"

# A1: No constitution + no presence file = pre-constitutional mode (pass)
rm -f "${CONSTITUTION_FILE}" "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "A1: No file, no tracker = pre-constitutional (pass)" "pass" "${result}"

# A2: No constitution + presence file = deletion attack (fail)
echo "deadbeef" > "${CONSTITUTION_PRESENCE_FILE}"
rm -f "${CONSTITUTION_FILE}" 2>/dev/null
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "A2: No file, tracker exists = deletion attack (fail)" "fail" "${result}"

# A2b: File exists + no tracker = ignore (DoS prevention — pass)
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
echo '{"constitution_version":"fake","signature":{"value":""}}' > "${CONSTITUTION_FILE}"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "A2b: Fake file, no tracker = ignored (DoS prevention, pass)" "pass" "${result}"
rm -f "${CONSTITUTION_FILE}"

# A3: Unsigned constitution = fail
cat > "${CONSTITUTION_FILE}" <<'EOF'
{"constitution_version":"1.0.0","signature":{"algorithm":"","public_key":"","value":""}}
EOF
# Set tracker so validation engages (simulates prior deploy)
shasum -a 256 "${CONSTITUTION_FILE}" 2>/dev/null | awk '{print $1}' > "${CONSTITUTION_PRESENCE_FILE}"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "A3: Unsigned constitution = fail" "fail" "${result}"

# A4: Invalid signature = fail
create_valid_constitution
# Tamper with the constitution
jq '.constitution_version = "tampered"' "${CONSTITUTION_FILE}" > "${CONSTITUTION_FILE}.tmp"
mv "${CONSTITUTION_FILE}.tmp" "${CONSTITUTION_FILE}"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "A4: Tampered constitution (invalid sig) = fail" "fail" "${result}"

# A5: Valid signature = pass
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "A5: Valid signed constitution = pass" "pass" "${result}"

# A6: Missing constitutional public key = fail
mv "${CONSTITUTION_PUBKEY}" "${CONSTITUTION_PUBKEY}.bak"
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "A6: Missing constitutional pubkey = fail" "fail" "${result}"
mv "${CONSTITUTION_PUBKEY}.bak" "${CONSTITUTION_PUBKEY}"

echo

# ══════════════════════════════════════════════════════════════
# Section B: Key separation (PC-06)
# ══════════════════════════════════════════════════════════════
echo "-- Section B: Key separation (PC-06) --"

# B1: Same key for constitution and policy = fail
cp "${POLICY_PUBKEY}" "${POLICY_PUBKEY}.real"
cp "${CONSTITUTION_PUBKEY}" "${POLICY_PUBKEY}"
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "B1: Same key for both = fail (PC-06)" "fail" "${result}"
cp "${POLICY_PUBKEY}.real" "${POLICY_PUBKEY}"

# B2: Different keys = pass
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "B2: Different keys = pass" "pass" "${result}"

# B3: Session cache works (second call skips full validation)
# After B2, cache should be set. Call again — should hit cache.
validate_constitution && result="pass" || result="fail"
assert "B3: Cached validation = pass (cache hit)" "pass" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section C: Permanent core enforcement
# ══════════════════════════════════════════════════════════════
echo "-- Section C: Permanent core enforcement --"

# C1: PC-01 — audit:false on consequential rule = fail
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
jq '.rules[1].audit = false' "${POLICY_FILE}" > "${POLICY_FILE}.tmp"
mv "${POLICY_FILE}.tmp" "${POLICY_FILE}"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C1: PC-01 audit:false on risk>0 rule = fail" "fail" "${result}"
create_valid_policy  # restore

# C2: PC-01 — audit:false on zero-risk rule = pass (not consequential)
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
jq '.rules[0].audit = false' "${POLICY_FILE}" > "${POLICY_FILE}.tmp"
mv "${POLICY_FILE}.tmp" "${POLICY_FILE}"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C2: PC-01 audit:false on zero-risk rule = pass (not consequential)" "pass" "${result}"
create_valid_policy  # restore

# C3: PC-02 — no ask rules = fail
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
jq '.rules = [.rules[] | select(.action != "ask")]' "${POLICY_FILE}" > "${POLICY_FILE}.tmp"
mv "${POLICY_FILE}.tmp" "${POLICY_FILE}"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C3: PC-02 no ask rules = fail (no human contestability)" "fail" "${result}"
create_valid_policy  # restore

# C4: PC-02 — at least one ask rule = pass
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C4: PC-02 at least one ask rule = pass" "pass" "${result}"

# C5: PC-04 — suspended escalation not deny = fail
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
mkdir -p "${TEST_DIR}/etc" 2>/dev/null
echo '{"enabled":true,"escalation":{"degraded":"log","at_risk":"ask","suspended":"ask"}}' > "${TEST_DIR}/etc/restore-config.json"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C5: PC-04 suspended=ask = fail" "fail" "${result}"
rm -f "${TEST_DIR}/etc/restore-config.json"

# C6: PC-04 — suspended escalation deny = pass
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
echo '{"enabled":true,"escalation":{"degraded":"log","at_risk":"ask","suspended":"deny"}}' > "${TEST_DIR}/etc/restore-config.json"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C6: PC-04 suspended=deny = pass" "pass" "${result}"
rm -f "${TEST_DIR}/etc/restore-config.json"

# C7: PC-05 — default_action not deny = fail
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
jq '.default_action = "allow"' "${POLICY_FILE}" > "${POLICY_FILE}.tmp"
mv "${POLICY_FILE}.tmp" "${POLICY_FILE}"
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C7: PC-05 default_action=allow = fail (deny-wins)" "fail" "${result}"
create_valid_policy  # restore

# C8: PC-05 — default_action deny = pass
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && result="pass" || result="fail"
assert "C8: PC-05 default_action=deny = pass" "pass" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section D: Derived properties
# ══════════════════════════════════════════════════════════════
echo "-- Section D: Derived properties --"

# D1: Presence tracker set after successful validation
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
create_valid_policy
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution
[ -f "${CONSTITUTION_PRESENCE_FILE}" ] && result="true" || result="false"
assert "D1: Presence tracker created after validation" "true" "${result}"

# D2: Session cache file created
[ -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" ] && result="true" || result="false"
assert "D2: Session cache file created" "true" "${result}"

# D3: Cache hash matches constitution hash
local_hash=$(shasum -a 256 "${CONSTITUTION_FILE}" 2>/dev/null | awk '{print $1}')
cached_hash=$(cat "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null | tr -d '[:space:]')
[ "${local_hash}" = "${cached_hash}" ] && result="match" || result="mismatch"
assert "D3: Cache hash matches constitution hash" "match" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section E: CLI integration
# ══════════════════════════════════════════════════════════════
echo "-- Section E: CLI integration --"

# E1: zlar-constitution inspect exits 0
"${REAL_PROJECT_DIR}/bin/zlar-constitution" inspect --input "${CONSTITUTION_FILE}" >/dev/null 2>&1 && result="pass" || result="fail"
assert "E1: zlar-constitution inspect exits 0" "pass" "${result}"

# E2: zlar-constitution verify exits 0 on valid constitution
"${REAL_PROJECT_DIR}/bin/zlar-constitution" verify --input "${CONSTITUTION_FILE}" --pubkey "${CONSTITUTION_PUBKEY}" >/dev/null 2>&1 && result="pass" || result="fail"
assert "E2: zlar-constitution verify exits 0 on valid sig" "pass" "${result}"

echo

# ══════════════════════════════════════════════════════════════
# Section F: Amendment ceremony
# ══════════════════════════════════════════════════════════════
echo "-- Section F: Amendment ceremony --"

CONST_CLI="${REAL_PROJECT_DIR}/bin/zlar-constitution"

# F1: Propose amendment to Layer 3 succeeds
# We need a deployed constitution for propose to work.
# The test constitution is already at ${TEST_DIR}/etc/constitution.json
# (that's what CONSTITUTION_FILE points to). Just ensure presence tracker.
# ZLAR_PROJECT_DIR tells the CLI to use the test directory instead of the real repo.
export ZLAR_PROJECT_DIR="${TEST_DIR}"
export AMENDMENTS_DIR="${TEST_DIR}/var/amendments"
mkdir -p "${AMENDMENTS_DIR}" 2>/dev/null

# Ensure valid constitution is deployed
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
create_valid_policy
shasum -a 256 "${CONSTITUTION_FILE}" | awk '{print $1}' > "${TEST_DIR}/var/log/.constitution-last-hash"

# Propose a valid Layer 3 amendment
propose_output=$("${CONST_CLI}" propose-amendment \
    --key "${TEST_DIR}/const.key" \
    --path "amendable_constraints.evidence.minimum_retention_hours" \
    --value "1440" \
    --reason "Extend retention to 60 days for compliance" 2>&1) && f1_rc=0 || f1_rc=$?
assert "F1: Propose Layer 3 amendment succeeds" "0" "${f1_rc}"

# Extract proposal ID from output
proposal_id=$(echo "${propose_output}" | grep "Amendment proposed:" | sed 's/.*proposed: //' | tr -d '[:space:]')

# F2: Propose amendment to permanent core is rejected
"${CONST_CLI}" propose-amendment \
    --key "${TEST_DIR}/const.key" \
    --path "permanent_core.clauses" \
    --value "[]" \
    --reason "test" >/dev/null 2>&1 && f2_rc=0 || f2_rc=$?
assert "F2: Propose to permanent core rejected (PC-07)" "1" "${f2_rc}"

# F3: Ratify before cooling-off is rejected
# The proposal we just created has a 72h cooling-off. Ratify should fail.
if [ -n "${proposal_id}" ]; then
    "${CONST_CLI}" ratify \
        --proposal "${proposal_id}" \
        --key "${TEST_DIR}/const.key" >/dev/null 2>&1 && f3_rc=0 || f3_rc=$?
    assert "F3: Ratify before cooling-off rejected (DP-02)" "1" "${f3_rc}"
else
    echo "  SKIP  F3: No proposal ID from F1"
fi

# F4: Ratify after cooling-off (simulate by backdating proposal)
# Create a new proposal with a deadline in the past
propose2_output=$("${CONST_CLI}" propose-amendment \
    --key "${TEST_DIR}/const.key" \
    --path "amendable_constraints.human_judgment.max_daily_decision_cap" \
    --value "150" \
    --reason "Reduce decision cap" 2>&1) && true
proposal_id2=$(echo "${propose2_output}" | grep "Amendment proposed:" | sed 's/.*proposed: //' | tr -d '[:space:]')

if [ -n "${proposal_id2}" ]; then
    # Backdate the cooling-off deadline to make it already elapsed
    local_file="${AMENDMENTS_DIR}/${proposal_id2}.proposal.json"
    if [ -f "${local_file}" ]; then
        past_deadline=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "1 day ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        past_proposed=$(date -u -v-4d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "4 days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        # Re-create the proposal with backdated timestamps and re-sign
        jq --arg dl "${past_deadline}" --arg pa "${past_proposed}" \
            '.cooling_off_deadline = $dl | .proposed_at = $pa' \
            "${local_file}" > "${local_file}.tmp"
        # Re-sign with zeroed signature and ob03_notifications (matches verification canonical form)
        jq -S -c '.signature = {algorithm:"",value:"",key_id:""} | .ob03_notifications = []' "${local_file}.tmp" > "${local_file}.canon"
        _f4_hash="${TEST_DIR}/var/tmp/f4-hash"
        _f4_sig="${TEST_DIR}/var/tmp/f4-sig"
        zlar_crypto_hash "${local_file}.canon" "${_f4_hash}" 2>/dev/null
        zlar_crypto_sign "${TEST_DIR}/const.key" "${_f4_hash}" "${_f4_sig}" 2>/dev/null
        _f4_sig_b64=$(base64 < "${_f4_sig}" | tr -d '\n')
        _f4_algo=$(zlar_crypto_algorithm)
        _f4_fp=$(zlar_crypto_pubkey_fingerprint "${TEST_DIR}/etc/keys/constitution-signing.pub" 2>/dev/null || echo "test")
        jq --arg algo "${_f4_algo}" --arg sig "${_f4_sig_b64}" --arg kid "${_f4_fp}" \
            '.signature.algorithm = $algo | .signature.value = $sig | .signature.key_id = $kid' \
            "${local_file}.tmp" > "${local_file}"
        rm -f "${local_file}.tmp" "${local_file}.canon" "${_f4_hash}" "${_f4_sig}"

        "${CONST_CLI}" ratify \
            --proposal "${proposal_id2}" \
            --key "${TEST_DIR}/const.key" >/dev/null 2>&1 && f4_rc=0 || f4_rc=$?
        assert "F4: Ratify after cooling-off succeeds" "0" "${f4_rc}"
    else
        echo "  SKIP  F4: Proposal file not found"
    fi
else
    echo "  SKIP  F4: No proposal ID from propose"
fi

# F5: Activate with DP-03 inconsistency is rejected
# Create and backdate a proposal that would violate PC-04 (suspended != deny)
propose3_output=$("${CONST_CLI}" propose-amendment \
    --key "${TEST_DIR}/const.key" \
    --path "amendable_constraints.escalation.suspended" \
    --value '"ask"' \
    --reason "Test DP-03 rejection" 2>&1) && true
proposal_id3=$(echo "${propose3_output}" | grep "Amendment proposed:" | sed 's/.*proposed: //' | tr -d '[:space:]')

if [ -n "${proposal_id3}" ]; then
    local_file3="${AMENDMENTS_DIR}/${proposal_id3}.proposal.json"
    if [ -f "${local_file3}" ]; then
        # Backdate and force to ratified state
        past_deadline=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "1 day ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        past_proposed=$(date -u -v-4d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "4 days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        now_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        jq --arg dl "${past_deadline}" --arg pa "${past_proposed}" --arg rat "${now_iso}" \
            '.cooling_off_deadline = $dl | .proposed_at = $pa | .state = "ratified" | .ratified_at = $rat' \
            "${local_file3}" > "${local_file3}.tmp"
        # Re-sign (zero sig + ob03 to match verification canonical form)
        jq -S -c '.signature = {algorithm:"",value:"",key_id:""} | .ob03_notifications = []' "${local_file3}.tmp" > "${local_file3}.canon"
        _f5_hash="${TEST_DIR}/var/tmp/f5-hash"
        _f5_sig="${TEST_DIR}/var/tmp/f5-sig"
        zlar_crypto_hash "${local_file3}.canon" "${_f5_hash}" 2>/dev/null
        zlar_crypto_sign "${TEST_DIR}/const.key" "${_f5_hash}" "${_f5_sig}" 2>/dev/null
        _f5_sig_b64=$(base64 < "${_f5_sig}" | tr -d '\n')
        _f5_algo=$(zlar_crypto_algorithm)
        _f5_fp=$(zlar_crypto_pubkey_fingerprint "${TEST_DIR}/etc/keys/constitution-signing.pub" 2>/dev/null || echo "test")
        jq --arg algo "${_f5_algo}" --arg sig "${_f5_sig_b64}" --arg kid "${_f5_fp}" \
            '.signature.algorithm = $algo | .signature.value = $sig | .signature.key_id = $kid' \
            "${local_file3}.tmp" > "${local_file3}"
        rm -f "${local_file3}.tmp" "${local_file3}.canon" "${_f5_hash}" "${_f5_sig}"

        "${CONST_CLI}" activate \
            --proposal "${proposal_id3}" \
            --key "${TEST_DIR}/const.key" >/dev/null 2>&1 && f5_rc=0 || f5_rc=$?
        assert "F5: Activate with DP-03 violation rejected (suspended=ask)" "1" "${f5_rc}"
    else
        echo "  SKIP  F5: Proposal file not found"
    fi
else
    echo "  SKIP  F5: No proposal ID"
fi

# F6: Withdraw cancels proposal
propose4_output=$("${CONST_CLI}" propose-amendment \
    --key "${TEST_DIR}/const.key" \
    --path "amendable_constraints.evidence.minimum_retention_hours" \
    --value "2160" \
    --reason "Test withdraw" 2>&1) && true
proposal_id4=$(echo "${propose4_output}" | grep "Amendment proposed:" | sed 's/.*proposed: //' | tr -d '[:space:]')

if [ -n "${proposal_id4}" ]; then
    "${CONST_CLI}" withdraw \
        --proposal "${proposal_id4}" \
        --key "${TEST_DIR}/const.key" >/dev/null 2>&1 && f6_rc=0 || f6_rc=$?
    assert "F6: Withdraw proposed amendment succeeds" "0" "${f6_rc}"

    # Verify state is withdrawn
    local_file4="${AMENDMENTS_DIR}/${proposal_id4}.proposal.json"
    withdraw_state=$(jq -r '.state' "${local_file4}" 2>/dev/null)
    assert "F6b: Withdrawn state is recorded" "withdrawn" "${withdraw_state}"
else
    echo "  SKIP  F6: No proposal ID"
fi

echo

# ══════════════════════════════════════════════════════════════
# Section G: Gate integration with deployed constitution
# ══════════════════════════════════════════════════════════════
echo "-- Section G: Gate integration --"

# G1: Gate validates deployed constitution (cache miss)
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
create_valid_policy
_CONSTITUTION_VALIDATED=""
validate_constitution && g1_result="pass" || g1_result="fail"
assert "G1: Gate validates deployed constitution (cache miss)" "pass" "${g1_result}"

# G2: Cache hit on second call (session cache)
validate_constitution && g2_result="pass" || g2_result="fail"
assert "G2: Cache hit on second call" "pass" "${g2_result}"

# G3: Constitution deletion after deploy triggers hard deny
rm -f "${CONSTITUTION_FILE}" 2>/dev/null
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && g3_result="pass" || g3_result="fail"
assert "G3: Constitution deleted after deploy = hard deny" "fail" "${g3_result}"

# G4: Constitution modification invalidates cache
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
create_valid_policy
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution  # populate cache
# Now tamper with the constitution (changes hash)
jq '.constitution_version = "tampered"' "${CONSTITUTION_FILE}" > "${CONSTITUTION_FILE}.tmp"
mv "${CONSTITUTION_FILE}.tmp" "${CONSTITUTION_FILE}"
# Update presence tracker to match tampered file (so it's not a deletion attack)
shasum -a 256 "${CONSTITUTION_FILE}" | awk '{print $1}' > "${CONSTITUTION_PRESENCE_FILE}"
_CONSTITUTION_VALIDATED=""
validate_constitution && g4_result="pass" || g4_result="fail"
assert "G4: Tampered constitution invalidates cache = fail" "fail" "${g4_result}"

# G5: Valid constitution after re-sign = pass (gate picks up new version)
rm -f "${CONSTITUTION_PRESENCE_FILE}" 2>/dev/null
create_valid_constitution
create_valid_policy
_CONSTITUTION_VALIDATED=""
rm -f "${SESSION_DIR}/${SESSION_ID}.constitution-valid" 2>/dev/null
validate_constitution && g5_result="pass" || g5_result="fail"
assert "G5: Re-signed constitution validates" "pass" "${g5_result}"

# G6: DP-03 rejects garbage manifest_deny_required_classes (content, not just cardinality)
# Create constitution with six entries that are NOT the required class names
garbage_constitution=$(mktemp "${TEST_DIR}/garbage-const.XXXXXX")
jq '.amendable_constraints.manifest_deny_required_classes = ["a","b","c","d","e","f"]' \
    "${CONSTITUTION_FILE}" > "${garbage_constitution}" 2>/dev/null
dp03_output=$(_dp03_check "${garbage_constitution}" 2>&1) && dp03_rc=0 || dp03_rc=$?
assert "G6a: DP-03 rejects garbage deny classes" "1" "$([ "${dp03_rc}" -ge 1 ] && echo 1 || echo 0)"
echo "${dp03_output}" | grep -q "missing 'governance_mutation'" && g6b="found" || g6b="not_found"
assert "G6b: DP-03 names the missing class" "found" "${g6b}"
rm -f "${garbage_constitution}"

# G7: DP-03 accepts correct six classes
dp03_valid=$(_dp03_check "${CONSTITUTION_FILE}" 2>&1) && dp03_valid_rc=0 || dp03_valid_rc=$?
assert "G7: DP-03 accepts valid constitution" "0" "${dp03_valid_rc}"

echo

# ══════════════════════════════════════════════════════════════
# Results
# ══════════════════════════════════════════════════════════════
TOTAL=$((PASS + FAIL))
echo "=============================="
echo "${PASS} passed, ${FAIL} failed out of ${TOTAL} tests"
echo

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
