#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Gate — Cursor Adapter
#
# Translates Cursor's hook events into Claude Code format, pipes to the gate
# engine, then translates the gate's response back to Cursor's expected format.
#
# Cursor hook contract (hooks.json):
#   Events: beforeShellExecution, beforeMCPExecution, beforeReadFile,
#           afterFileEdit, sessionStart, beforeSubmitPrompt, stop
#   stdin:  {"event":"beforeShellExecution","data":{"command":"ls","cwd":"/path"},
#            "conversationId":"...","workspaceRoots":["..."]}
#   stdout: {"permission":"allow"} | {"permission":"deny","userMessage":"...","agentMessage":"..."}
#   exit:   0
#
# Install: scripts/zlar-setup.sh → writes .cursor/hooks.json or
#          ~/.cursor/hooks.json pointing to this script.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"
GATE="${PROJECT_DIR}/bin/zlar-gate"

# ─── Fail-closed ─────────────────────────────────────────────────────────────

fail_deny() {
    local reason="${1:-ZLAR gate error}"
    if command -v jq &>/dev/null; then
        jq -n -c --arg r "${reason}" \
            '{permission:"deny",userMessage:$r,agentMessage:("Action blocked by ZLAR Gate: "+$r)}'
    else
        # Fallback if jq unavailable — hardcoded safe string
        echo '{"permission":"deny","userMessage":"ZLAR gate error","agentMessage":"Action blocked by ZLAR Gate"}'
    fi
    exit 0
}

if [ ! -x "${GATE}" ]; then
    fail_deny "ZLAR gate not found or not executable. All actions blocked."
fi

command -v jq &>/dev/null || fail_deny "jq not found — required for ZLAR Gate"

# ─── Read Cursor input ──────────────────────────────────────────────────────

INPUT=$(cat)

if [ -z "${INPUT}" ] || ! echo "${INPUT}" | jq empty 2>/dev/null; then
    fail_deny "Empty or malformed hook input"
fi

EVENT=$(echo "${INPUT}" | jq -r '.event // ""' 2>/dev/null)
DATA=$(echo "${INPUT}" | jq -c '.data // {}' 2>/dev/null)
CONVERSATION_ID=$(echo "${INPUT}" | jq -r '.conversationId // "unknown"' 2>/dev/null)

# ─── Translate Cursor event → Claude Code tool call ─────────────────────────

CC_TOOL_NAME=""
CC_TOOL_INPUT="{}"

case "${EVENT}" in
    beforeShellExecution)
        CC_TOOL_NAME="Bash"
        CC_TOOL_INPUT=$(echo "${DATA}" | jq -c '{
            command: (.command // ""),
            cwd: (.cwd // "")
        }' 2>/dev/null || echo '{"command":""}')
        ;;

    beforeReadFile)
        CC_TOOL_NAME="Read"
        CC_TOOL_INPUT=$(echo "${DATA}" | jq -c '{
            file_path: (.filePath // .path // "")
        }' 2>/dev/null || echo '{"file_path":""}')
        ;;

    afterFileEdit)
        # NOTE: afterFileEdit fires AFTER the edit is applied. The gate cannot
        # prevent it — this is audit-only. We pipe through for logging but the
        # edit has already happened regardless of the gate's decision.
        CC_TOOL_NAME="Edit"
        CC_TOOL_INPUT=$(echo "${DATA}" | jq -c '{
            file_path: (.filePath // .path // ""),
            old_string: ((.oldText // .oldString // "")[0:80]),
            new_string: ((.newText // .newString // "")[0:80])
        }' 2>/dev/null || echo '{"file_path":""}')
        ;;

    beforeMCPExecution)
        # ALL MCP tools go to a dedicated "mcp" domain. We do NOT map MCP tool
        # names to trusted CC tool names — an MCP tool named "fetch_data" could
        # do anything, and mapping it to WebFetch would let it bypass policy.
        local_server=$(echo "${DATA}" | jq -r '.serverName // ""' 2>/dev/null)
        local_tool=$(echo "${DATA}" | jq -r '.toolName // ""' 2>/dev/null)

        CC_TOOL_NAME="MCP:${local_server}:${local_tool}"
        CC_TOOL_INPUT=$(echo "${DATA}" | jq -c '{
            server: (.serverName // ""),
            tool: (.toolName // ""),
            arguments: (.arguments // {})
        }' 2>/dev/null || echo '{}')
        ;;

    sessionStart|stop|beforeSubmitPrompt)
        # Lifecycle events — allow through, gate doesn't handle these
        echo '{"permission":"allow"}'
        exit 0
        ;;

    *)
        # Unknown event — deny (fail-closed)
        fail_deny "Unknown Cursor hook event: ${EVENT}"
        ;;
esac

# ─── Build CC-format JSON and pipe to gate ───────────────────────────────────

CC_INPUT=$(jq -n -c \
    --arg tool_name "${CC_TOOL_NAME}" \
    --argjson tool_input "${CC_TOOL_INPUT}" \
    --arg session_id "${CONVERSATION_ID}" \
    '{tool_name: $tool_name, tool_input: $tool_input, session_id: $session_id}')

GATE_RESPONSE=$(echo "${CC_INPUT}" | ZLAR_ADAPTER=cursor "${GATE}" 2>>"${PROJECT_DIR}/var/log/gate-stderr.log")
GATE_EXIT=$?

if [ ${GATE_EXIT} -ne 0 ] || [ -z "${GATE_RESPONSE}" ]; then
    fail_deny "Gate error (exit ${GATE_EXIT})"
fi

# ─── Translate gate response → Cursor format ────────────────────────────────

DECISION=$(echo "${GATE_RESPONSE}" | jq -r '.hookSpecificOutput.permissionDecision // "deny"' 2>/dev/null)
REASON=$(echo "${GATE_RESPONSE}" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""' 2>/dev/null)

case "${DECISION}" in
    allow)
        echo '{"permission":"allow"}'
        ;;
    deny|*)
        if [ -n "${REASON}" ]; then
            jq -n -c \
                --arg reason "${REASON}" \
                '{permission: "deny", userMessage: $reason, agentMessage: ("Action blocked by ZLAR Gate: " + $reason)}'
        else
            echo '{"permission":"deny","userMessage":"Blocked by ZLAR Gate","agentMessage":"Action blocked by ZLAR Gate policy"}'
        fi
        ;;
esac

exit 0
