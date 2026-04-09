#!/bin/bash
# test-manifest.sh — tests for capability manifest v0
#
# Tests the manifest CLI (sign, verify, check, render, new)
# and the invariants from docs/MANIFEST-INVARIANTS.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export ZLAR_PROJECT_DIR="${PROJECT_DIR}"

PASS=0
FAIL=0
TOTAL=0
TEMP_DIR=$(mktemp -d)

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

cleanup() { rm -rf "${TEMP_DIR}"; }
trap cleanup EXIT

echo "=== Manifest v0 Tests ==="
echo

# ── CLI: new ──

echo "Manifest generation:"
"${PROJECT_DIR}/bin/zlar-manifest" new --agent-id test-agent --principal "zlar:human:tester" > "${TEMP_DIR}/test.json" 2>/dev/null

assert "new: creates valid JSON" "true" "$(jq empty "${TEMP_DIR}/test.json" 2>/dev/null && echo true || echo false)"
assert "new: manifest_version" "0.1.0" "$(jq -r '.manifest_version' "${TEMP_DIR}/test.json")"
assert "new: agent_id" "zlar:agent:test-agent" "$(jq -r '.identity.agent_id' "${TEMP_DIR}/test.json")"
assert "new: principal" "zlar:human:tester" "$(jq -r '.identity.principal' "${TEMP_DIR}/test.json")"
assert "new: has issued_at" "true" "$(jq -r '.identity.issued_at' "${TEMP_DIR}/test.json" | grep -q '^20' && echo true || echo false)"
assert "new: has allow array" "true" "$(jq -e '.authority.allow | type == "array"' "${TEMP_DIR}/test.json" >/dev/null 2>&1 && echo true || echo false)"
assert "new: has deny array" "true" "$(jq -e '.authority.deny | type == "array"' "${TEMP_DIR}/test.json" >/dev/null 2>&1 && echo true || echo false)"
assert "new: unmatched_action" "escalate" "$(jq -r '.authority.unmatched_action' "${TEMP_DIR}/test.json")"
assert "new: has expires" "true" "$(jq -r '.expires' "${TEMP_DIR}/test.json" | grep -q '^20' && echo true || echo false)"
assert "new: signature empty" "" "$(jq -r '.signature.value' "${TEMP_DIR}/test.json")"
echo

# ── CLI: sign + verify ──

echo "Signing and verification:"

if [[ -f "${HOME}/.zlar-signing.key" ]]; then
    # Derive a matching public key into TEMP_DIR so zlar-manifest can
    # compute key_id and verify signatures. We deliberately do NOT write
    # the public key into etc/keys/policy-signing.pub — test-policy-loading.sh
    # expects that path to either be absent or matched to a valid signed
    # active.policy.json, and would fail if we installed an unsigned pubkey
    # there. The ZLAR_MANIFEST_PUBKEY env var override in bin/zlar-manifest
    # lets us point at a hermetic temp key instead.
    openssl pkey -in "${HOME}/.zlar-signing.key" -pubout -out "${TEMP_DIR}/test-manifest-pubkey.pem" 2>/dev/null
    export ZLAR_MANIFEST_PUBKEY="${TEMP_DIR}/test-manifest-pubkey.pem"

    "${PROJECT_DIR}/bin/zlar-manifest" sign --input "${TEMP_DIR}/test.json" 2>/dev/null
    assert "sign: signature populated" "true" "$([[ -n "$(jq -r '.signature.value' "${TEMP_DIR}/test.json")" ]] && echo true || echo false)"
    assert "sign: algorithm set" "Ed25519" "$(jq -r '.signature.algorithm' "${TEMP_DIR}/test.json")"
    assert "sign: key_id set" "true" "$([[ -n "$(jq -r '.signature.key_id' "${TEMP_DIR}/test.json")" ]] && echo true || echo false)"

    # Verify should pass
    verify_result=$("${PROJECT_DIR}/bin/zlar-manifest" verify --input "${TEMP_DIR}/test.json" 2>&1 || true)
    assert "verify: valid signature passes" "true" "$(echo "${verify_result}" | grep -q 'VALID' && echo true || echo false)"

    # Tamper and verify should fail
    jq '.authority.allow += ["bash.dangerous"]' "${TEMP_DIR}/test.json" > "${TEMP_DIR}/tampered.json"
    # Copy signature from original
    jq --argjson sig "$(jq '.signature' "${TEMP_DIR}/test.json")" '.signature = $sig' "${TEMP_DIR}/tampered.json" > "${TEMP_DIR}/tampered2.json"
    tamper_result=$("${PROJECT_DIR}/bin/zlar-manifest" verify --input "${TEMP_DIR}/tampered2.json" 2>&1 || true)
    assert "verify: tampered manifest fails" "true" "$(echo "${tamper_result}" | grep -q 'INVALID' && echo true || echo false)"

    unset ZLAR_MANIFEST_PUBKEY
else
    echo "  SKIP: No signing key found at ~/.zlar-signing.key"
fi
echo

# ── CLI: check ──

echo "Check command:"
check_result=$("${PROJECT_DIR}/bin/zlar-manifest" check --input "${TEMP_DIR}/test.json" 2>&1)
assert "check: shows agent_id" "true" "$(echo "${check_result}" | grep -q 'test-agent' && echo true || echo false)"
assert "check: shows expiry" "true" "$(echo "${check_result}" | grep -q 'valid\|EXPIRED' && echo true || echo false)"

# Create expired manifest
jq '.expires = "2020-01-01T00:00:00Z"' "${TEMP_DIR}/test.json" > "${TEMP_DIR}/expired.json"
expired_result=$("${PROJECT_DIR}/bin/zlar-manifest" check --input "${TEMP_DIR}/expired.json" 2>&1)
assert "check: detects expiry" "true" "$(echo "${expired_result}" | grep -q 'EXPIRED' && echo true || echo false)"
echo

# ── CLI: render ──

echo "Render command:"
render_result=$("${PROJECT_DIR}/bin/zlar-manifest" render --input "${TEMP_DIR}/test.json" 2>&1)
assert "render: shows agent_id" "true" "$(echo "${render_result}" | grep -q 'test-agent' && echo true || echo false)"
assert "render: shows allowed caps" "true" "$(echo "${render_result}" | grep -q 'bash.read' && echo true || echo false)"
assert "render: shows denied caps" "true" "$(echo "${render_result}" | grep -q 'bash.dangerous' && echo true || echo false)"

simple_result=$("${PROJECT_DIR}/bin/zlar-manifest" render --input "${TEMP_DIR}/test.json" --simple 2>&1)
assert "render --simple: no jargon" "true" "$(echo "${simple_result}" | grep -q 'Your AI assistant' && echo true || echo false)"
assert "render --simple: shows permission" "true" "$(echo "${simple_result}" | grep -q 'can:' && echo true || echo false)"
assert "render --simple: shows denial" "true" "$(echo "${simple_result}" | grep -q 'cannot:' && echo true || echo false)"
assert "render --simple: shows timeout" "true" "$(echo "${simple_result}" | grep -q 'minutes' && echo true || echo false)"
echo

# ── Schema invariants ──

echo "Schema invariants:"

# Required sections
for section in identity authority escalation expires; do
    assert "required: ${section} exists" "true" "$(jq -e ".${section}" "${TEMP_DIR}/test.json" >/dev/null 2>&1 && echo true || echo false)"
done

# Exclusion tests — these fields must NOT exist
for excluded in self_modify auto_approve reputation_score severity trust_score fail_open logging; do
    assert "excluded: ${excluded} absent" "true" "$(jq -e ".${excluded} // empty" "${TEMP_DIR}/test.json" >/dev/null 2>&1 && echo false || echo true)"
done

# Authority structure
assert "authority: allow is array" "true" "$(jq -e '.authority.allow | type == "array"' "${TEMP_DIR}/test.json" >/dev/null 2>&1 && echo true || echo false)"
assert "authority: deny is array" "true" "$(jq -e '.authority.deny | type == "array"' "${TEMP_DIR}/test.json" >/dev/null 2>&1 && echo true || echo false)"
assert "authority: no wildcards" "0" "$(jq '[.authority.allow[], .authority.deny[]] | map(select(contains("*"))) | length' "${TEMP_DIR}/test.json" 2>/dev/null)"
echo

# ── Results ──

echo "═══════════════════════════════════════"
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [[ ${FAIL} -gt 0 ]]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
else
    echo " ✓"
fi
