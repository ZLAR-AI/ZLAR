#!/bin/bash
# Ensure Codex proof probes do not stack approve and deny asks in one prompt.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SMOKE="${PROJECT_DIR}/mcp-gate/smoke-codex-cli.mjs"

PASS=0
FAIL=0

assert_contains() {
    local label="$1" needle="$2" file="$3"
    if grep -Fq -- "${needle}" "${file}"; then
        echo "  ✓ ${label}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${label}"
        FAIL=$((FAIL + 1))
    fi
}

echo "Codex Proof Probe Splitting Tests"
echo "================================="

assert_contains "approve probe prompt exists" "PASS2_APPROVE_PROMPT" "${SMOKE}"
assert_contains "deny probe prompt exists" "PASS2_DENY_PROMPT" "${SMOKE}"
assert_contains "legacy stacked pass2 is rejected" "pass2 is split to prevent stacked asks" "${SMOKE}"
assert_contains "approve probe declares expected approval" "expected human decision is APPROVE" "${SMOKE}"
assert_contains "deny probe declares expected denial" "expected human decision is DENY" "${SMOKE}"
assert_contains "operator instructions forbid one-prompt approve/deny" "Do not run approve and deny proof probes in one Codex prompt." "${SMOKE}"
assert_contains "approve rule carries per-rule proof metadata" "proof_probe_expected_decision: 'approve'" "${SMOKE}"
assert_contains "deny rule carries per-rule proof metadata" "proof_probe_expected_decision: 'deny'" "${SMOKE}"
assert_contains "smoke verify inspects outgoing approve card text" "Pass 2A approve Telegram card labels proof probe and expected APPROVE" "${SMOKE}"
assert_contains "smoke verify inspects outgoing deny card text" "Pass 2B deny Telegram card labels proof probe and expected DENY" "${SMOKE}"
assert_contains "gate derives approve label from smoke marker" "marker_ask_approve" "${PROJECT_DIR}/mcp-gate/gate.mjs"
assert_contains "gate derives deny label from smoke marker" "marker_ask_deny" "${PROJECT_DIR}/mcp-gate/gate.mjs"

approve_prompt=$(node "${SMOKE}" prompt pass2-approve 2>/dev/null)
deny_prompt=$(node "${SMOKE}" prompt pass2-deny 2>/dev/null)
if printf '%s' "${approve_prompt}" | grep -Fq "${TOOL_ASK_APPROVE:-test.marker_ask_approve}" && \
   printf '%s' "${approve_prompt}" | grep -Fq "expected human decision is APPROVE"; then
    echo "  ✓ approve prompt renders split expected decision"
    PASS=$((PASS + 1))
else
    echo "  ✗ approve prompt renders split expected decision"
    FAIL=$((FAIL + 1))
fi
if printf '%s' "${deny_prompt}" | grep -Fq "${TOOL_ASK_DENY:-test.marker_ask_deny}" && \
   printf '%s' "${deny_prompt}" | grep -Fq "expected human decision is DENY"; then
    echo "  ✓ deny prompt renders split expected decision"
    PASS=$((PASS + 1))
else
    echo "  ✗ deny prompt renders split expected decision"
    FAIL=$((FAIL + 1))
fi

echo
echo "Results: ${PASS} passed, ${FAIL} failed"
exit "${FAIL}"
