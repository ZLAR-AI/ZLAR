#!/bin/bash
# Worker Receipt live-ish bash-gate emission tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMP_DIR=$(mktemp -d)

cleanup() { rm -rf "${TEMP_DIR}"; }
trap cleanup EXIT

PASS=0
FAIL=0
TOTAL=0

assert() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${expected}" == "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s - expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

assert_truthy() {
    local label="$1" actual="$2"
    TOTAL=$((TOTAL + 1))
    if [[ -n "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s - expected non-empty, got empty\n' "${label}"
    fi
}

AUDIT_FILE="${TEMP_DIR}/audit.jsonl"
WORKER_RECEIPT_FILE="${TEMP_DIR}/worker-receipts.jsonl"
LOG_FILE="${TEMP_DIR}/gate.log"
GATE_TMP="${TEMP_DIR}/tmp"
mkdir -p "${GATE_TMP}"

WORKER_RECEIPT_HELPER="${PROJECT_DIR}/bin/zlar-worker-receipt"
AUDIT_SIGNING_KEY="${TEMP_DIR}/missing-signing.key"
ZLAR_REQUIRE_SIGNED_AUDIT="false"
ZLAR_EMIT_RECEIPTS="false"
RECEIPT_FILE="${TEMP_DIR}/receipts.jsonl"
POLICY_VERSION="test-policy-1"
PUBLIC_KEY_ID="policy-key-live"
SIGNATURE_ALGORITHM="Ed25519"
HASH_ALGORITHM="SHA-256"
AGENT_CONFIG_HASH="null"
AGENT_CONFIG_SOURCE="null"
AGENT_FINGERPRINT="null"
AGENT_ID="claude-code"
SESSION_ID="worker-receipt-test"
SEQ=0
LAST_EMITTED_EVENT_ID=""
MATCHED_RULE=""
MATCHED_RULE_DESCRIPTION=""
POLICY_RULES_JSON='[
  {"id":"R001","description":"Allow harmless live-ish bash status."},
  {"id":"R002","description":"Deny dangerous credential exposure."}
]'

log() {
    printf '[test] %s\n' "$*" >> "${LOG_FILE}"
}

gen_id() {
    printf 'wr-live-%03d\n' "$((SEQ + 1))"
}

rotate_audit_if_needed() {
    :
}

zlar_crypto_sign() {
    return 1
}

eval "$(awk '/^_emit_worker_receipt\(\) \{/,/^}$/ {print}' "${PROJECT_DIR}/bin/zlar-gate")"
eval "$(awk '/^emit_event\(\) \{/,/^}$/ {print}' "${PROJECT_DIR}/bin/zlar-gate")"

echo "=== live-ish emit_event Worker Receipt append ==="

MATCHED_RULE="R001"
MATCHED_RULE_DESCRIPTION="Allow harmless live-ish bash status."
emit_event "bash" "git status --short" "allow" \
    '{"command":"git status --short","cwd":"/Users/tester/Desktop/ZLAR/ZLAR_Repo"}' \
    "R001" "info" 0 "policy"

assert "audit line count after allow" "1" "$(wc -l < "${AUDIT_FILE}" | tr -d ' ')"
assert "worker receipt count after allow" "1" "$(wc -l < "${WORKER_RECEIPT_FILE}" | tr -d ' ')"

ALLOW_EVENT_ID=$(jq -r '.id' "${AUDIT_FILE}")
assert "receipt event id matches audit" "${ALLOW_EVENT_ID}" "$(jq -r '.event.id' "${WORKER_RECEIPT_FILE}")"
assert "frozen rule description" "Allow harmless live-ish bash status." "$(jq -r '.decision.rule_description' "${WORKER_RECEIPT_FILE}")"
assert "policy key id" "policy-key-live" "$(jq -r '.decision.policy_key_id' "${WORKER_RECEIPT_FILE}")"

WHY_JSON="${TEMP_DIR}/why.json"
ZLAR_WORKER_RECEIPT_FILE="${WORKER_RECEIPT_FILE}" "${PROJECT_DIR}/bin/zlar" why "${ALLOW_EVENT_ID}" --json > "${WHY_JSON}"
assert "zlar why reads emitted receipt" "${ALLOW_EVENT_ID}" "$(jq -r '.event.id' "${WHY_JSON}")"

WR_BEFORE_INTERNAL=$(wc -l < "${WORKER_RECEIPT_FILE}" | tr -d ' ')
MATCHED_RULE=""
MATCHED_RULE_DESCRIPTION=""
emit_event "internal" "TodoWrite" "allow" '{"tool":"TodoWrite"}' "internal-fast-path" "info" 0 "gate"
emit_event "mcp" "MCP:github/create_issue" "deny" '{"server":"github","tool":"create_issue","args":{"title":"test"}}' "MCP-R001" "warn" 50 "policy"
emit_event "gate" "manifest" "deny" '{"reason":"test"}' "manifest:deny" "critical" 100 "gate"
assert "operational/internal/MCP events write audit" "4" "$(wc -l < "${AUDIT_FILE}" | tr -d ' ')"
assert "operational/internal/MCP events do not append worker receipt" "${WR_BEFORE_INTERNAL}" "$(wc -l < "${WORKER_RECEIPT_FILE}" | tr -d ' ')"

MATCHED_RULE="R002"
MATCHED_RULE_DESCRIPTION="Deny dangerous credential exposure."
emit_event "bash" "cat /Users/tester/.ssh/id_rsa && echo sk-live-1234567890" "deny" \
    '{"command":"cat /Users/tester/.ssh/id_rsa && echo sk-live-1234567890","cwd":"/Users/tester/Desktop/ZLAR/ZLAR_Repo"}' \
    "R002" "critical" 100 "policy"

DENY_EVENT_ID=$(tail -1 "${AUDIT_FILE}" | jq -r '.id')
assert "second eligible event appended receipt" "2" "$(wc -l < "${WORKER_RECEIPT_FILE}" | tr -d ' ')"
DENY_RECEIPT=$(tail -1 "${WORKER_RECEIPT_FILE}")
assert "deny receipt id" "${DENY_EVENT_ID}" "$(printf '%s' "${DENY_RECEIPT}" | jq -r '.event.id')"
assert "deny receipt redacts path" "true" "$(printf '%s' "${DENY_RECEIPT}" | grep -q '\[REDACTED_PATH\]' && echo true || echo false)"
assert "deny receipt redacts secret" "false" "$(printf '%s' "${DENY_RECEIPT}" | grep -q 'sk-live' && echo true || echo false)"

WR_BEFORE_FAILURE=$(wc -l < "${WORKER_RECEIPT_FILE}" | tr -d ' ')
AUDIT_BEFORE_FAILURE=$(wc -l < "${AUDIT_FILE}" | tr -d ' ')
WORKER_RECEIPT_HELPER="${TEMP_DIR}/missing-helper"
set +e
emit_event "bash" "git diff --stat" "allow" '{"command":"git diff --stat","cwd":"/repo"}' "R001" "info" 0 "policy"
FAIL_RC=$?
set -e
assert "worker receipt helper failure does not fail emit_event" "0" "${FAIL_RC}"
assert "audit still appended when worker receipt helper missing" "$((AUDIT_BEFORE_FAILURE + 1))" "$(wc -l < "${AUDIT_FILE}" | tr -d ' ')"
assert "worker receipt not appended when helper missing" "${WR_BEFORE_FAILURE}" "$(wc -l < "${WORKER_RECEIPT_FILE}" | tr -d ' ')"
assert "worker receipt failure logged" "true" "$(grep -q 'Worker Receipt emission skipped' "${LOG_FILE}" && echo true || echo false)"

echo
printf "Worker Receipt gate emission tests: %d/%d passed, %d failed\n" "${PASS}" "${TOTAL}" "${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
    exit 1
fi
