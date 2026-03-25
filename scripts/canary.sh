#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Canary Test
#
# Proves the CC gate is alive and enforcing policy by triggering a known-deny
# rule (R099) and verifying the block. If the canary command passes through,
# the gate is broken.
#
# Usage:
#   canary.sh              Run canary test (default)
#   canary.sh --audit      Run test and verify audit trail entry
#
# Exit codes:
#   0  Gate is enforcing (canary was blocked) — HEALTHY
#   1  Gate is NOT enforcing (canary passed through) — BROKEN
#   2  Gate is enforcing but audit trail missing — DEGRADED
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
AUDIT_FILE="${PROJECT_DIR}/var/log/audit.jsonl"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BOLD='\033[1m'; NC='\033[0m'

CHECK_AUDIT=false
[ "${1:-}" = "--audit" ] && CHECK_AUDIT=true

echo -e "${BOLD}ZLAR Canary Test${NC}"
echo ""

# Count audit lines before test
AUDIT_BEFORE=0
if [ -f "${AUDIT_FILE}" ]; then
    AUDIT_BEFORE=$(wc -l < "${AUDIT_FILE}" | tr -d ' ')
fi

# ── Fire the canary ──────────────────────────────────────────────────────────
# This command contains ZLAR_CANARY_PROBE which matches R099 (action: deny).
# If the gate is working, this will be blocked and never execute.
# The output "CANARY_LEAKED" should NEVER appear.

CANARY_OUTPUT=$(echo "ZLAR_CANARY_PROBE" 2>&1) && CANARY_EXITED=0 || CANARY_EXITED=$?

if [ "${CANARY_OUTPUT}" = "ZLAR_CANARY_PROBE" ]; then
    echo -e "${RED}  FAIL${NC} Canary passed through — gate is NOT enforcing"
    echo -e "${RED}  The command 'echo ZLAR_CANARY_PROBE' was not blocked by R099${NC}"
    echo ""
    echo "  Possible causes:"
    echo "    - Gate is disabled (~/.claude/.gate-disabled exists)"
    echo "    - Policy signature invalid (re-sign with zlar-policy sign)"
    echo "    - R099 rule missing from active policy"
    echo "    - Hook not configured in settings.json"
    exit 1
fi

echo -e "${GREEN}  PASS${NC} Canary blocked — gate is enforcing"

# ── Audit trail check ────────────────────────────────────────────────────────
if [ "${CHECK_AUDIT}" = "true" ]; then
    # Give audit a moment to flush
    sleep 1
    AUDIT_AFTER=$(wc -l < "${AUDIT_FILE}" | tr -d ' ')

    if [ "${AUDIT_AFTER}" -gt "${AUDIT_BEFORE}" ]; then
        # Check if the new entry mentions R099
        LAST_ENTRY=$(tail -1 "${AUDIT_FILE}")
        if echo "${LAST_ENTRY}" | grep -q "R099"; then
            echo -e "${GREEN}  PASS${NC} Audit trail recorded R099 deny event"
        else
            echo -e "${YELLOW}  WARN${NC} New audit entry exists but doesn't mention R099"
        fi
    else
        echo -e "${YELLOW}  WARN${NC} No new audit entry after canary (audit may be degraded)"
        exit 2
    fi
fi

echo ""
echo -e "${GREEN}${BOLD}Gate is healthy.${NC}"
