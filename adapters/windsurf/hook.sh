#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Gate — Windsurf Adapter
#
# Translates Windsurf's Cascade hook events into Claude Code format, pipes to
# the gate engine, then translates the response to Windsurf's exit-code protocol.
#
# Windsurf hook contract (hooks.json):
#   Events: pre_write_code, pre_run_command, pre_read_code, pre_mcp_tool_use,
#           pre_user_prompt, post_write_code, post_run_command, etc.
#   stdin:  {"agent_action_name":"pre_run_command","trajectory_id":"...",
#            "execution_id":"...","timestamp":"...","tool_info":{"command":"ls","cwd":"/"}}
#   exit 0: allow
#   exit 2: block (stderr shown to user in Cascade UI)
#   other:  error (does NOT block)
#
# Install: scripts/zlar-setup.sh → writes .windsurf/hooks.json or
#          ~/.codeium/windsurf/hooks.json pointing to this script.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"
GATE="${PROJECT_DIR}/bin/zlar-gate"

# ─── Fail-closed (exit 2 = block in Windsurf) ───────────────────────────────

fail_deny() {
    echo "${1:-ZLAR gate error}" >&2
    exit 2
}

if [ ! -x "${GATE}" ]; then
    fail_deny "ZLAR gate not found or not executable. All actions blocked."
fi

command -v jq &>/dev/null || fail_deny "jq not found — required for ZLAR Gate"

# ─── Read Windsurf input ────────────────────────────────────────────────────

INPUT=$(cat)

if [ -z "${INPUT}" ] || ! echo "${INPUT}" | jq empty 2>/dev/null; then
    fail_deny "Empty or malformed hook input"
fi

ACTION_NAME=$(echo "${INPUT}" | jq -r '.agent_action_name // ""' 2>/dev/null)
TOOL_INFO=$(echo "${INPUT}" | jq -c '.tool_info // {}' 2>/dev/null)
TRAJECTORY_ID=$(echo "${INPUT}" | jq -r '.trajectory_id // "unknown"' 2>/dev/null)

# ─── Translate Windsurf event → Claude Code tool call ───────────────────────

CC_TOOL_NAME=""
CC_TOOL_INPUT="{}"

case "${ACTION_NAME}" in
    pre_run_command)
        CC_TOOL_NAME="Bash"
        CC_TOOL_INPUT=$(echo "${TOOL_INFO}" | jq -c '{
            command: (.command // .command_line // ""),
            cwd: (.cwd // .working_directory // "")
        }' 2>/dev/null || echo '{"command":""}')
        ;;

    pre_read_code)
        CC_TOOL_NAME="Read"
        CC_TOOL_INPUT=$(echo "${TOOL_INFO}" | jq -c '{
            file_path: (.file_path // .filePath // .path // "")
        }' 2>/dev/null || echo '{"file_path":""}')
        ;;

    pre_write_code)
        # Windsurf sends file path + edits (old_string/new_string pairs)
        # Map to Write if it looks like a full file write, Edit if partial
        local_has_old=$(echo "${TOOL_INFO}" | jq 'has("old_string") or has("edits")' 2>/dev/null)
        if [ "${local_has_old}" = "true" ]; then
            CC_TOOL_NAME="Edit"
            CC_TOOL_INPUT=$(echo "${TOOL_INFO}" | jq -c '{
                file_path: (.file_path // .filePath // .path // ""),
                old_string: (.old_string // (.edits[0].old_string // "")),
                new_string: (.new_string // (.edits[0].new_string // ""))
            }' 2>/dev/null || echo '{"file_path":""}')
        else
            CC_TOOL_NAME="Write"
            CC_TOOL_INPUT=$(echo "${TOOL_INFO}" | jq -c '{
                file_path: (.file_path // .filePath // .path // ""),
                content: (.content // "")
            }' 2>/dev/null || echo '{"file_path":""}')
        fi
        ;;

    pre_mcp_tool_use)
        # ALL MCP tools go to a dedicated "mcp" domain. We do NOT map MCP tool
        # names to trusted CC tool names — an MCP tool named "fetch_data" could
        # do anything, and mapping it to WebFetch would let it bypass policy.
        local_server=$(echo "${TOOL_INFO}" | jq -r '.server_name // .serverName // ""' 2>/dev/null)
        local_tool=$(echo "${TOOL_INFO}" | jq -r '.tool_name // .toolName // ""' 2>/dev/null)

        CC_TOOL_NAME="MCP:${local_server}:${local_tool}"
        CC_TOOL_INPUT=$(echo "${TOOL_INFO}" | jq -c '{
            server: (.server_name // .serverName // ""),
            tool: (.tool_name // .toolName // ""),
            arguments: (.arguments // {})
        }' 2>/dev/null || echo '{}')
        ;;

    pre_user_prompt)
        # Lifecycle event — allow through
        exit 0
        ;;

    post_*)
        # Post-execution events — cannot block, but pipe through gate for
        # audit trail. Gate decision is ignored (action already happened).
        CC_TOOL_NAME="PostEvent:${ACTION_NAME}"
        CC_TOOL_INPUT=$(echo "${TOOL_INFO}" | jq -c '.' 2>/dev/null || echo '{}')
        # Run through gate for audit, but always exit 0 regardless
        CC_INPUT=$(jq -n -c \
            --arg tool_name "${CC_TOOL_NAME}" \
            --argjson tool_input "${CC_TOOL_INPUT}" \
            --arg session_id "${TRAJECTORY_ID}" \
            '{tool_name: $tool_name, tool_input: $tool_input, session_id: $session_id}')
        echo "${CC_INPUT}" | ZLAR_ADAPTER=windsurf "${GATE}" 2>>"${PROJECT_DIR}/var/log/gate-stderr.log" >/dev/null || true
        exit 0
        ;;

    *)
        # Unknown event — deny (fail-closed)
        fail_deny "Unknown Windsurf hook event: ${ACTION_NAME}"
        ;;
esac

# ─── Build CC-format JSON and pipe to gate ───────────────────────────────────

CC_INPUT=$(jq -n -c \
    --arg tool_name "${CC_TOOL_NAME}" \
    --argjson tool_input "${CC_TOOL_INPUT}" \
    --arg session_id "${TRAJECTORY_ID}" \
    '{tool_name: $tool_name, tool_input: $tool_input, session_id: $session_id}')

GATE_RESPONSE=$(echo "${CC_INPUT}" | ZLAR_ADAPTER=windsurf "${GATE}" 2>>"${PROJECT_DIR}/var/log/gate-stderr.log")
GATE_EXIT=$?

if [ ${GATE_EXIT} -ne 0 ] || [ -z "${GATE_RESPONSE}" ]; then
    fail_deny "Gate error (exit ${GATE_EXIT})"
fi

# ─── Translate gate response → Windsurf format (exit codes) ──────────────────

DECISION=$(echo "${GATE_RESPONSE}" | jq -r '.hookSpecificOutput.permissionDecision // "deny"' 2>/dev/null)
REASON=$(echo "${GATE_RESPONSE}" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""' 2>/dev/null)

case "${DECISION}" in
    allow)
        exit 0
        ;;
    deny|*)
        if [ -n "${REASON}" ]; then
            echo "ZLAR Gate: ${REASON}" >&2
        else
            echo "ZLAR Gate: Action blocked by policy" >&2
        fi
        exit 2
        ;;
esac
