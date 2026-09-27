#!/bin/bash
# Process-level regression tests for the Claude Code adapter wrapper.
#
# Uses a temporary install-shaped root and a fake gate. It never touches the
# user's real ~/.zlar, ~/.claude, hooks, profiles, services, or machine config.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ADAPTER_SOURCE="${PROJECT_DIR}/adapters/claude-code/hook.sh"

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq unavailable"
    exit 77
fi

TEST_DIR=$(mktemp -d)
INSTALL_ROOT="${TEST_DIR}/.zlar"
ADAPTER_DIR="${INSTALL_ROOT}/adapters/claude-code"
BIN_DIR="${INSTALL_ROOT}/bin"
LOG_DIR="${INSTALL_ROOT}/var/log"
SENTINEL="${TEST_DIR}/tool-input-was-executed"
mkdir -p "${ADAPTER_DIR}" "${BIN_DIR}" "${LOG_DIR}"
trap 'rm -rf "${TEST_DIR}"' EXIT

cp "${ADAPTER_SOURCE}" "${ADAPTER_DIR}/hook.sh"
chmod +x "${ADAPTER_DIR}/hook.sh"

cat > "${BIN_DIR}/zlar-gate" <<'GATESH'
#!/bin/bash
set -eu

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INPUT=$(cat)
printf '%s' "${INPUT}" > "${PROJECT_DIR}/var/log/gate-stdin.json"

COMMAND=$(printf '%s' "${INPUT}" | jq -r '.tool_input.command // ""')
case "${COMMAND}" in
    *adapter-blank-response*)
        exit 99
        ;;
    *adapter-deny-fixture*)
        printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[policy] adapter deny fixture"}}\n'
        exit 2
        ;;
    *)
        printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}\n'
        exit 0
        ;;
esac
GATESH
chmod +x "${BIN_DIR}/zlar-gate"

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS + 1)); }

fail() {
    local label="$1"
    local detail="${2:-}"
    FAIL=$((FAIL + 1))
    printf '  FAIL: %s\n' "${label}"
    if [ -n "${detail}" ]; then
        printf '%s\n' "${detail}" | sed 's/^/    /'
    fi
}

assert_equal() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "${expected}" = "${actual}" ]; then
        pass
    else
        fail "${label}" "expected=${expected} actual=${actual}"
    fi
}

assert_true() {
    local label="$1" value="$2"
    assert_equal "${label}" "true" "${value}"
}

run_adapter() {
    local input="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    printf '%s\n' "${input}" | "${ADAPTER_DIR}/hook.sh" > "${stdout_path}" 2> "${stderr_path}"
    RC=$?
}

json_field() {
    local path="$1"
    local expr="$2"
    jq -r "${expr}" "${path}" 2>/dev/null
}

echo "=== Claude Code Adapter Hook ==="
echo

ALLOW_OUT="${TEST_DIR}/allow.json"
ALLOW_ERR="${TEST_DIR}/allow.stderr"
ALLOW_INPUT='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"pwd"},"session_id":"adapter-allow"}'
run_adapter "${ALLOW_INPUT}" "${ALLOW_OUT}" "${ALLOW_ERR}"
assert_equal "allow fixture exits zero" "0" "${RC}"
assert_equal "allow fixture emits no stderr" "" "$(cat "${ALLOW_ERR}")"
assert_equal "allow fixture returns allow JSON" "allow" "$(json_field "${ALLOW_OUT}" '.hookSpecificOutput.permissionDecision')"

DENY_OUT="${TEST_DIR}/deny.json"
DENY_ERR="${TEST_DIR}/deny.stderr"
DENY_INPUT='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"adapter-deny-fixture"},"session_id":"adapter-deny"}'
run_adapter "${DENY_INPUT}" "${DENY_OUT}" "${DENY_ERR}"
assert_equal "deny fixture exits zero for Claude hook contract" "0" "${RC}"
assert_equal "deny fixture emits no stderr" "" "$(cat "${DENY_ERR}")"
assert_equal "deny fixture preserves gate deny JSON" "deny" "$(json_field "${DENY_OUT}" '.hookSpecificOutput.permissionDecision')"
assert_equal "deny fixture preserves gate reason" "[policy] adapter deny fixture" "$(json_field "${DENY_OUT}" '.hookSpecificOutput.permissionDecisionReason')"

NO_EXEC_OUT="${TEST_DIR}/no-exec.json"
NO_EXEC_ERR="${TEST_DIR}/no-exec.stderr"
NO_EXEC_INPUT='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"touch '"${SENTINEL}"'"},"session_id":"adapter-no-exec"}'
run_adapter "${NO_EXEC_INPUT}" "${NO_EXEC_OUT}" "${NO_EXEC_ERR}"
assert_equal "tool-input command fixture exits zero" "0" "${RC}"
assert_equal "tool-input command fixture returns allow JSON" "allow" "$(json_field "${NO_EXEC_OUT}" '.hookSpecificOutput.permissionDecision')"
assert_true "adapter does not execute tool_input.command" "$([ ! -e "${SENTINEL}" ] && echo true || echo false)"

BLANK_OUT="${TEST_DIR}/blank.json"
BLANK_ERR="${TEST_DIR}/blank.stderr"
BLANK_INPUT='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"adapter-blank-response"},"session_id":"adapter-blank"}'
run_adapter "${BLANK_INPUT}" "${BLANK_OUT}" "${BLANK_ERR}"
assert_equal "blank gate response exits zero for Claude hook contract" "0" "${RC}"
assert_equal "blank gate response fails closed" "deny" "$(json_field "${BLANK_OUT}" '.hookSpecificOutput.permissionDecision')"
assert_equal "blank gate response names gate error" "true" "$(jq -r '.hookSpecificOutput.permissionDecisionReason | contains("ZLAR gate error (exit 99)")' "${BLANK_OUT}")"

MISSING_GATE="${BIN_DIR}/zlar-gate.moved"
mv "${BIN_DIR}/zlar-gate" "${MISSING_GATE}"
MISSING_OUT="${TEST_DIR}/missing.json"
MISSING_ERR="${TEST_DIR}/missing.stderr"
run_adapter "${ALLOW_INPUT}" "${MISSING_OUT}" "${MISSING_ERR}"
assert_equal "missing gate exits zero for Claude hook contract" "0" "${RC}"
assert_equal "missing gate fails closed" "deny" "$(json_field "${MISSING_OUT}" '.hookSpecificOutput.permissionDecision')"
assert_equal "missing gate reason names missing gate" "true" "$(jq -r '.hookSpecificOutput.permissionDecisionReason | contains("ZLAR gate not found")' "${MISSING_OUT}")"
mv "${MISSING_GATE}" "${BIN_DIR}/zlar-gate"

assert_equal "fake gate captured last input without execution side effect" "adapter-blank-response" \
    "$(jq -r '.tool_input.command' "${LOG_DIR}/gate-stdin.json")"

echo
echo "${PASS} passed, ${FAIL} failed out of ${TOTAL} tests"
[ "${FAIL}" -eq 0 ] || exit 1
