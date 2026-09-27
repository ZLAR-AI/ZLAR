#!/bin/bash
# grant-trust-lane.sh — Authority grant for Fast Lane access
#
# Grants a human operator Fast Lane trust. Fast Lane collapses H15 and H17
# floors to the absolute minimum (500ms) for all severities, and bypasses H14.
# The grant persists across UTC rollover — authority must be explicitly revoked,
# not silently expired by a date change.
#
# This script is terminal-only. It must not be called from an agent session.
# Every grant is written to audit.jsonl.
#
# Usage:
#   ./scripts/grant-trust-lane.sh <human_id> "<reason>"
#
# Example:
#   ./scripts/grant-trust-lane.sh 1000000007 "Trusted operator — sustained clean canary record"
#
# To revoke: delete trust_lane_grant from state and set trust_lane=guarded.
# (No revoke script yet — use jq directly against human state + HMAC reseal.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# shellcheck source=../lib/human-invariants.sh
source "${PROJECT_DIR}/lib/human-invariants.sh"

# ── Args ────────────────────────────────────────────────────────────────────

HUMAN_ID="${1:-}"
GRANT_REASON="${2:-}"

if [ -z "${HUMAN_ID}" ] || [ -z "${GRANT_REASON}" ]; then
    echo "Usage: $0 <human_id> \"<reason>\"" >&2
    exit 1
fi

# ── Confirm terminal context ─────────────────────────────────────────────────
# Refuse to run if stdin is not a TTY — guards against agent invocation.

if [ ! -t 0 ]; then
    echo "ERROR: grant-trust-lane.sh must be run from a terminal (stdin is not a TTY)." >&2
    echo "       This script cannot be invoked by an agent." >&2
    exit 1
fi

# ── Interactive confirmation ─────────────────────────────────────────────────

STATE_FILE="${PROJECT_DIR}/var/human-state/${HUMAN_ID}.json"
if [ ! -f "${STATE_FILE}" ]; then
    echo "ERROR: No state file found for human_id=${HUMAN_ID}" >&2
    echo "       Run the gate at least once to initialise state." >&2
    exit 1
fi

CURRENT_LANE=$(jq -r '.trust_lane // "guarded"' "${STATE_FILE}" 2>/dev/null)
echo ""
echo "  ZLAR Trust Lane Grant"
echo "  ─────────────────────────────────────────────"
echo "  Human ID : ${HUMAN_ID}"
echo "  Current  : ${CURRENT_LANE}"
echo "  Target   : fast"
echo "  Reason   : ${GRANT_REASON}"
echo ""
printf "  Type 'GRANT' to confirm: "
read -r CONFIRM

if [ "${CONFIRM}" != "GRANT" ]; then
    echo "  Aborted." >&2
    exit 1
fi

# ── Apply grant ──────────────────────────────────────────────────────────────

NOW_EPOCH=$(date +%s)
GRANT_PAYLOAD=$(jq -n -c \
    --arg source "authority" \
    --argjson granted_at "${NOW_EPOCH}" \
    --arg reason "${GRANT_REASON}" \
    '{source:$source,granted_at:$granted_at,reason:$reason}')

# Load, patch, reseal.
jq --argjson grant "${GRANT_PAYLOAD}" \
   'del(._hmac) | .trust_lane = "fast" | .trust_lane_grant = $grant' \
   "${STATE_FILE}" 2>/dev/null | _hi_sealed_write "${STATE_FILE}"

# ── Audit entry ──────────────────────────────────────────────────────────────

AUDIT_FILE="${PROJECT_DIR}/var/log/audit.jsonl"
mkdir -p "$(dirname "${AUDIT_FILE}")"

AUDIT_EVENT=$(jq -n -c \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg human_id "${HUMAN_ID}" \
    --arg reason "${GRANT_REASON}" \
    --arg operator "$(whoami)" \
    --argjson granted_at "${NOW_EPOCH}" \
    '{
        ts: $ts,
        source: "grant-trust-lane",
        event: "trust_lane_grant",
        human_id: $human_id,
        granted_at: $granted_at,
        reason: $reason,
        operator: $operator,
        trust_lane: "fast"
    }')
echo "${AUDIT_EVENT}" >> "${AUDIT_FILE}"

# ── Verify ───────────────────────────────────────────────────────────────────

RESULT_LANE=$(jq -r '.trust_lane // "unknown"' "${STATE_FILE}" 2>/dev/null)
RESULT_GRANT=$(jq -r '.trust_lane_grant.source // "none"' "${STATE_FILE}" 2>/dev/null)

echo ""
if [ "${RESULT_LANE}" = "fast" ] && [ "${RESULT_GRANT}" = "authority" ]; then
    echo "  ✓ Fast Lane granted for ${HUMAN_ID}"
    echo "  ✓ Audit entry written to ${AUDIT_FILE}"
else
    echo "  ✗ Grant may have failed — verify state manually." >&2
    echo "    trust_lane=${RESULT_LANE}, grant.source=${RESULT_GRANT}" >&2
    exit 1
fi
echo ""
