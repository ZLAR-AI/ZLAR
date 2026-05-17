#!/bin/bash
# Static/unit checks for Telegram destination validation.
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

assert_status() {
    local label="$1" input="$2" expected="$3"
    local actual
    if [ -z "${input}" ]; then
        actual="missing"
    elif [[ "${input}" == @* ]]; then
        actual="invalid_bot_username"
    elif [ "${input}" = "YOUR_TELEGRAM_CHAT_ID" ] || [ "${input}" = "your_chat_id_here" ] || \
         [ "${input}" = "<telegram_chat_id>" ] || [ "${input}" = "<CHAT_ID>" ] || \
         [ "${input}" = "TELEGRAM_CHAT_ID" ]; then
        actual="invalid_placeholder"
    elif [[ "${input}" =~ ^-?[0-9]+$ ]]; then
        actual="valid_numeric"
    else
        actual="invalid_non_numeric"
    fi
    if [ "${actual}" = "${expected}" ]; then
        echo "  ✓ ${label}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${label} expected=${expected} actual=${actual}"
        FAIL=$((FAIL + 1))
    fi
}

echo "Telegram Destination Validation Tests"
echo "====================================="

assert_status "numeric user chat id accepted" "123456789" "valid_numeric"
assert_status "negative group chat id accepted" "-1001234567890" "valid_numeric"
assert_status "bot username rejected" "@ZLAR_00_bot" "invalid_bot_username"
assert_status "placeholder rejected" "YOUR_TELEGRAM_CHAT_ID" "invalid_placeholder"
assert_status "non-numeric destination rejected" "ZLAR_00_bot" "invalid_non_numeric"
assert_status "bare dash rejected" "-" "invalid_non_numeric"

assert_contains "bin/zlar has destination validator" "telegram_chat_id_status()" "${PROJECT_DIR}/bin/zlar"
assert_contains "zlar telegram rejects bot usernames" "That is a bot/user username" "${PROJECT_DIR}/bin/zlar"
assert_contains "zlar status prints chat_id status" "chat_id status:" "${PROJECT_DIR}/bin/zlar"
assert_contains "doctor accepts TELEGRAM_BOT_TOKEN fallback" 'TELEGRAM_BOT_TOKEN' "${PROJECT_DIR}/bin/zlar"
assert_contains "doctor live checks are opt-in" "zlar doctor --live" "${PROJECT_DIR}/bin/zlar"
assert_contains "boot rejects username chat ids" '@*)' "${PROJECT_DIR}/scripts/zlar-tg-boot.sh"
assert_contains "boot requires numeric regex" '^-?[0-9]+$' "${PROJECT_DIR}/scripts/zlar-tg-boot.sh"
assert_contains "bash gate has enforcement-path destination validator" "telegram_chat_id_status()" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "bash gate rejects placeholder before ask send" "invalid_placeholder" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "bash gate emits config_error audit" '"config_error"' "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "bash gate denies invalid destination before preconfirm" "Refuse invalid Telegram destinations before Tier 2" "${PROJECT_DIR}/bin/zlar-gate"
assert_contains "preconfirm validates destination before rate limit" "_telegram_dispatch_ready" "${PROJECT_DIR}/lib/preconfirm-cc.sh"
assert_contains "canary validates numeric chat id" "_canary_chat_id_status()" "${PROJECT_DIR}/lib/canary.sh"
assert_contains "MCP gate validates numeric chat id" "telegramChatIdStatus" "${PROJECT_DIR}/mcp-gate/gate.mjs"
assert_contains "MCP gate emits Telegram config_error audit" "telegram_config_error" "${PROJECT_DIR}/mcp-gate/gate.mjs"
assert_contains "MCP gate rejects invalid destination before preAskCheck" "telegramDestinationReadiness('mcp_ask')" "${PROJECT_DIR}/mcp-gate/gate.mjs"

echo
echo "Results: ${PASS} passed, ${FAIL} failed"
exit "${FAIL}"
