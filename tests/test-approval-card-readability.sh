#!/bin/bash
# Focused fixture checks for Telegram approval card readability.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

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

assert_not_contains() {
    local label="$1" needle="$2" file="$3"
    if grep -Fq -- "${needle}" "${file}"; then
        echo "  ✗ ${label}"
        FAIL=$((FAIL + 1))
    else
        echo "  ✓ ${label}"
        PASS=$((PASS + 1))
    fi
}

echo "Approval Card Readability Tests"
echo "==============================="

assert_contains "bash card has plain rule labels" "get_rule_plain_label()" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "R012W_EDIT has human-readable label" "Governance infrastructure change" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "R005C has human-readable label" "Interpreter one-liner" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "R001C has human-readable label" "Sensitive file read" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "bash proof probes show expected decision" "expected human decision: APPROVE" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "bash proof probes can derive approve from marker" "marker_ask_approve" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "bash proof probes can derive deny from marker" "marker_ask_deny" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "bash card says deny if unclear" "If this is unclear, deny" "${PROJECT_DIR}/bin/zlar-gate"

assert_contains "MCP card has plain rule labels" "plainRuleLabel" "${PROJECT_DIR}/mcp-gate/gate.mjs"
assert_contains "MCP proof probes show expected decision" "expected human decision:" "${PROJECT_DIR}/mcp-gate/gate.mjs"
assert_contains "MCP proof probes accept per-rule metadata" "proofProbeExpectedDecision" "${PROJECT_DIR}/mcp-gate/gate.mjs"
assert_contains "MCP card says deny if unclear" "If this is unclear, deny" "${PROJECT_DIR}/mcp-gate/gate.mjs"

assert_contains "canary card remains ordinary approval" "*Approval required*" "${PROJECT_DIR}/lib/canary.sh"
assert_contains "canary card includes unclear-deny instruction" "If this is unclear, deny" "${PROJECT_DIR}/lib/canary.sh"
assert_not_contains "canary card does not self-label before decision" "*Canary*" "${PROJECT_DIR}/lib/canary.sh"

echo
echo "Results: ${PASS} passed, ${FAIL} failed"
exit "${FAIL}"
