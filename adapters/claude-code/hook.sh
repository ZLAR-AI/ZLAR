#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Gate — Claude Code Adapter
#
# Thin wrapper for Claude Code's PreToolUse hook.
# Claude Code's hook format IS the gate's native format, so this adapter
# is a straight pass-through. Fail-closed: if gate is missing, ALL denied.
#
# Install: scripts/zlar-setup.sh → configures .claude/settings.json or
#          ~/.claude/settings.json to point here.
#
# Hook contract:
#   stdin:  {"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"..."}
#   stdout: {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
#   exit:   always 0 (decision is in the JSON)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"
GATE="${PROJECT_DIR}/bin/zlar-gate"

# Fail-closed: gate must exist and be executable
if [ ! -x "${GATE}" ]; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"ZLAR gate not found or not executable. All actions blocked."}}'
    exit 0
fi

# Pass-through — Claude Code format IS the gate's native format
RESPONSE=$("${GATE}" 2>>"${PROJECT_DIR}/var/log/gate-stderr.log")
EXIT_CODE=$?

if [ ${EXIT_CODE} -ne 0 ] || [ -z "${RESPONSE}" ]; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"ZLAR gate error (exit '"${EXIT_CODE}"'). All actions blocked."}}'
    exit 0
fi

echo "${RESPONSE}"
exit 0
