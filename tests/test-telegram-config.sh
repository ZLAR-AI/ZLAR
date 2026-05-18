#!/bin/bash
# tests/test-telegram-config.sh — v3.3.9 Telegram dispatch readiness
#
# Asserts the contract of the chat_id source resolution (env > gate.json >
# unconfigured), the dispatch_ready helper (refuse on non-authoritative or
# invalid destinations, audit once per process), the empty-cb_from callback
# rejection, and the status composition in bin/zlar.
#
# Strategy: unit-test the resolution + helper inline (replicating the
# logic from bin/zlar-gate to keep tests fast and hermetic). Add structural
# greps to detect drift between the gate's actual code and the inline copy.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

passed=0
failed=0
FAILED_ASSERTIONS=()

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    else
        echo "  ✗ ${desc}: expected '${expected}', got '${actual}'"
        failed=$((failed + 1))
        FAILED_ASSERTIONS+=("${desc}: expected='${expected}' actual='${actual}'")
    fi
}

assert_true() {
    local desc="$1" cond="$2"
    if [ "${cond}" = "true" ]; then
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    else
        echo "  ✗ ${desc}"
        failed=$((failed + 1))
        FAILED_ASSERTIONS+=("${desc}: condition false")
    fi
}

# ── Inline replication of bin/zlar-gate's resolution + helper ──
# Drift detection at TC-DRIFT below.

resolve_chat_id_source() {
    if [ -n "${ZLAR_TELEGRAM_CHAT_ID:-}" ]; then
        TELEGRAM_CHAT_ID="${ZLAR_TELEGRAM_CHAT_ID}"
        TELEGRAM_CHAT_ID_SOURCE="env"
    elif [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
        TELEGRAM_CHAT_ID_SOURCE="gate.json"
    else
        TELEGRAM_CHAT_ID=""
        TELEGRAM_CHAT_ID_SOURCE="unconfigured"
    fi
}

log() { :; }
TELEGRAM_AUDIT_EMIT_COUNT=0
emit_event() {
    if [ "$1" = "telegram" ] && [ "$2" = "config_error" ]; then
        TELEGRAM_AUDIT_EMIT_COUNT=$((TELEGRAM_AUDIT_EMIT_COUNT + 1))
    fi
}

telegram_chat_id_status() {
    local value="${1:-}"
    case "${value}" in
        '' )
            echo "missing"
            ;;
        @* )
            echo "invalid_bot_username"
            ;;
        YOUR_TELEGRAM_CHAT_ID|your_chat_id_here|'<telegram_chat_id>'|'<CHAT_ID>'|TELEGRAM_CHAT_ID|CHAT_ID|placeholder|PLACEHOLDER|changeme|CHANGE_ME|todo|TODO )
            echo "invalid_placeholder"
            ;;
        * )
            if [[ "${value}" =~ ^-?[0-9]+$ ]]; then
                echo "valid_numeric"
            else
                echo "invalid_non_numeric"
            fi
            ;;
    esac
}

_TELEGRAM_MISCONFIG_LOGGED=""
_telegram_dispatch_ready() {
    local status source_ok="false"
    status=$(telegram_chat_id_status "${TELEGRAM_CHAT_ID:-}")
    case "${TELEGRAM_CHAT_ID_SOURCE:-unconfigured}" in
        gate.json|env) source_ok="true" ;;
    esac
    if [ "${source_ok}" = "true" ] && [ "${status}" = "valid_numeric" ]; then
        return 0
    fi
    if [ -z "${_TELEGRAM_MISCONFIG_LOGGED}" ]; then
        _TELEGRAM_MISCONFIG_LOGGED="1"
        log "GATE: Telegram destination invalid — refusing to dispatch general ask"
        emit_event "telegram" "config_error" "warn" "{}" "telegram-config" "warn" 0 "system"
    fi
    return 1
}

reset_state() {
    unset ZLAR_TELEGRAM_CHAT_ID TELEGRAM_CHAT_ID TELEGRAM_CHAT_ID_SOURCE
    _TELEGRAM_MISCONFIG_LOGGED=""
    TELEGRAM_AUDIT_EMIT_COUNT=0
}

# Composite state computation — mirrors bin/zlar's status block.
compute_state() {
    local cfg_enabled="$1" token_present="$2" chat_id_source="$3" chat_id_status="${4:-valid_numeric}"
    if [ "${cfg_enabled}" = "false" ]; then
        echo "disabled (config)"
    elif [ "${token_present}" = "missing" ]; then
        echo "fail-closed (token missing)"
    elif [ "${chat_id_source}" = "unconfigured" ]; then
        echo "fail-closed (chat_id unconfigured)"
    elif [ "${chat_id_status}" != "valid_numeric" ]; then
        echo "fail-closed (chat_id invalid)"
    else
        echo "enabled"
    fi
}

# Inline replication of bin/zlar-gate:1921 callback check.
check_callback() {
    local cb_from="$1" gate_chat_id="$2"
    if [ -z "${cb_from}" ] || [ "${cb_from}" != "${gate_chat_id}" ]; then
        echo "rejected"
    else
        echo "accepted"
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  test-telegram-config.sh — v3.3.9 dispatch readiness"
echo "═══════════════════════════════════════════════════════════════"

# ── TC-1: env source ──
echo ""
echo "TC-1: ZLAR_TELEGRAM_CHAT_ID set → source=env, ready=0"
reset_state
export ZLAR_TELEGRAM_CHAT_ID="123456789"
resolve_chat_id_source
assert_eq "source resolves to env" "env" "${TELEGRAM_CHAT_ID_SOURCE}"
_telegram_dispatch_ready
assert_eq "dispatch_ready returns 0" "0" "$?"

# ── TC-2: gate.json source ──
echo ""
echo "TC-2: gate.json populated TELEGRAM_CHAT_ID (no env) → source=gate.json, ready=0"
reset_state
TELEGRAM_CHAT_ID="-1001234567890"
resolve_chat_id_source
assert_eq "source resolves to gate.json" "gate.json" "${TELEGRAM_CHAT_ID_SOURCE}"
_telegram_dispatch_ready
assert_eq "dispatch_ready returns 0" "0" "$?"

# ── TC-3a: unconfigured ──
echo ""
echo "TC-3a: neither env nor gate.json → source=unconfigured, ready=1"
reset_state
resolve_chat_id_source
assert_eq "source resolves to unconfigured" "unconfigured" "${TELEGRAM_CHAT_ID_SOURCE}"
assert_eq "TELEGRAM_CHAT_ID is empty" "" "${TELEGRAM_CHAT_ID}"
_ready_rc=0
_telegram_dispatch_ready || _ready_rc=$?
assert_eq "dispatch_ready returns 1" "1" "${_ready_rc}"

# ── TC-3b: once-per-process audit emit ──
echo ""
echo "TC-3b: 3 calls under unconfigured → exactly 1 telegram_config_error audit"
reset_state
resolve_chat_id_source
_telegram_dispatch_ready || true
_telegram_dispatch_ready || true
_telegram_dispatch_ready || true
assert_eq "exactly 1 audit emit across 3 calls" "1" "${TELEGRAM_AUDIT_EMIT_COUNT}"

# ── TC-3c: structural — early guard precedes telegram_ask_async call site ──
# The rate-limit write lives inside telegram_ask_async. The structural
# property "no rate-limit consumed under unconfigured" is enforced by the
# early guard returning before telegram_ask_async is invoked from main().
echo ""
echo "TC-3c: structural — early guard returns before telegram_ask_async is called"
EARLY_GUARD_LINE=$(grep -n 'Refuse invalid Telegram destinations before Tier 2' "${PROJECT_DIR}/bin/zlar-gate" | head -1 | cut -d: -f1)
ASK_ASYNC_CALL_LINE=$(grep -n '^                            telegram_ask_async "\${action_id}"' "${PROJECT_DIR}/bin/zlar-gate" | head -1 | cut -d: -f1)
if [ -n "${EARLY_GUARD_LINE}" ] && [ -n "${ASK_ASYNC_CALL_LINE}" ] && [ "${EARLY_GUARD_LINE}" -lt "${ASK_ASYNC_CALL_LINE}" ]; then
    assert_true "early guard at L${EARLY_GUARD_LINE} < telegram_ask_async call at L${ASK_ASYNC_CALL_LINE}" "true"
else
    assert_true "early guard precedes telegram_ask_async call (early=${EARLY_GUARD_LINE} call=${ASK_ASYNC_CALL_LINE})" "false"
fi

# ── TC-3d: structural — early guard precedes hi_pre_ask_check ──
echo ""
echo "TC-3d: structural — early guard precedes hi_pre_ask_check (no pending consumed)"
HI_PRE_LINE=$(grep -n 'hi_pre_ask_check "\${TELEGRAM_CHAT_ID}"' "${PROJECT_DIR}/bin/zlar-gate" | head -1 | cut -d: -f1)
if [ -n "${EARLY_GUARD_LINE}" ] && [ -n "${HI_PRE_LINE}" ] && [ "${EARLY_GUARD_LINE}" -lt "${HI_PRE_LINE}" ]; then
    assert_true "early guard at L${EARLY_GUARD_LINE} < hi_pre_ask_check at L${HI_PRE_LINE}" "true"
else
    assert_true "early guard precedes hi_pre_ask_check (early=${EARLY_GUARD_LINE} hi=${HI_PRE_LINE})" "false"
fi

# ── TC-4: env precedence over gate.json ──
echo ""
echo "TC-4: env precedence over gate.json"
reset_state
export ZLAR_TELEGRAM_CHAT_ID="222222222"
TELEGRAM_CHAT_ID="111111111"
resolve_chat_id_source
assert_eq "source is env (not gate.json)" "env" "${TELEGRAM_CHAT_ID_SOURCE}"
assert_eq "value resolves to env value" "222222222" "${TELEGRAM_CHAT_ID}"

echo ""
echo "TC-4b: authoritative but invalid chat_id values fail closed before dispatch"
reset_state
export ZLAR_TELEGRAM_CHAT_ID="@ZLAR_00_bot"
resolve_chat_id_source
assert_eq "bot username status rejected" "invalid_bot_username" "$(telegram_chat_id_status "${TELEGRAM_CHAT_ID}")"
_ready_rc=0
_telegram_dispatch_ready || _ready_rc=$?
assert_eq "@username dispatch_ready returns 1" "1" "${_ready_rc}"
reset_state
TELEGRAM_CHAT_ID="YOUR_TELEGRAM_CHAT_ID"
resolve_chat_id_source
assert_eq "placeholder status rejected" "invalid_placeholder" "$(telegram_chat_id_status "${TELEGRAM_CHAT_ID}")"
_ready_rc=0
_telegram_dispatch_ready || _ready_rc=$?
assert_eq "placeholder dispatch_ready returns 1" "1" "${_ready_rc}"
reset_state
TELEGRAM_CHAT_ID="not-a-number"
resolve_chat_id_source
assert_eq "nonnumeric status rejected" "invalid_non_numeric" "$(telegram_chat_id_status "${TELEGRAM_CHAT_ID}")"
_ready_rc=0
_telegram_dispatch_ready || _ready_rc=$?
assert_eq "nonnumeric dispatch_ready returns 1" "1" "${_ready_rc}"

# ── TC-5: line 1921 contains the unconditional empty-string check ──
echo ""
echo "TC-5: structural — bin/zlar-gate:1921 has unconditional -z cb_from check"
if grep -qE 'if \[ -z "\$\{cb_from\}" \] \|\| \[ "\$\{cb_from\}" != "\$\{TELEGRAM_CHAT_ID\}" \]' "${PROJECT_DIR}/bin/zlar-gate"; then
    assert_true "unconditional empty-cb_from rejection present" "true"
else
    assert_true "unconditional empty-cb_from rejection present" "false"
fi

# ── TC-6/7/8: composite state computation in bin/zlar ──
echo ""
echo "TC-6: state=enabled when token=present, source=gate.json, cfg_enabled=true"
assert_eq "enabled" "enabled" "$(compute_state true present gate.json valid_numeric)"

echo ""
echo "TC-7: state=fail-closed (token missing) when token=missing, source=gate.json"
assert_eq "fail-closed (token missing)" "fail-closed (token missing)" "$(compute_state true missing gate.json valid_numeric)"

echo ""
echo "TC-8: state=fail-closed (chat_id unconfigured) when token=present, source=unconfigured"
assert_eq "fail-closed (chat_id unconfigured)" "fail-closed (chat_id unconfigured)" "$(compute_state true present unconfigured missing)"

echo ""
echo "TC-8a: state=fail-closed (chat_id invalid) when source is configured but value is invalid"
assert_eq "fail-closed (chat_id invalid)" "fail-closed (chat_id invalid)" "$(compute_state true present gate.json invalid_bot_username)"

echo ""
echo "TC-8b: state=disabled (config) when cfg_enabled=false (overrides everything)"
assert_eq "disabled (config)" "disabled (config)" "$(compute_state false present gate.json invalid_bot_username)"

# ── TC-9: line 1921 callback rejection — both configured and unconfigured ──
echo ""
echo "TC-9: empty cb_from rejected unconditionally (configured + unconfigured)"
assert_eq "configured + empty cb_from → rejected" "rejected" "$(check_callback '' '12345')"
assert_eq "unconfigured + empty cb_from → rejected (no '' == '' bypass)" "rejected" "$(check_callback '' '')"
assert_eq "configured + matching cb_from → accepted" "accepted" "$(check_callback '12345' '12345')"
assert_eq "configured + mismatched cb_from → rejected" "rejected" "$(check_callback '99999' '12345')"

# ── TC-DRIFT: inline helper shape matches bin/zlar-gate ──
echo ""
echo "TC-DRIFT: bin/zlar-gate contains _telegram_dispatch_ready with expected case branches"
if grep -q '_telegram_dispatch_ready()' "${PROJECT_DIR}/bin/zlar-gate" && \
   grep -q 'case "\${source}"' "${PROJECT_DIR}/bin/zlar-gate" && \
   grep -q 'gate.json|env)' "${PROJECT_DIR}/bin/zlar-gate" && \
   grep -q 'telegram_chat_id_status()' "${PROJECT_DIR}/bin/zlar-gate" && \
   grep -q 'invalid_bot_username' "${PROJECT_DIR}/bin/zlar-gate" && \
   grep -q 'invalid_placeholder' "${PROJECT_DIR}/bin/zlar-gate" && \
   grep -q '_TELEGRAM_MISCONFIG_LOGGED=""' "${PROJECT_DIR}/bin/zlar-gate"; then
    assert_true "helper shape matches inline replica" "true"
else
    assert_true "helper shape matches inline replica" "false"
fi

# ── Status block drift check ──
echo ""
echo "TC-STATUS: bin/zlar keeps a coherent top-level Telegram status block"
STATUS_BLOCK=$(sed -n '/# Telegram (v3.3.9/,/# Audit/p' "${PROJECT_DIR}/bin/zlar")
status_block_contains() {
    grep -qE "$1" <<< "${STATUS_BLOCK}"
}
if status_block_contains 'printf "  \$\{BOLD\}Telegram:\$\{NC\}\\n"'; then
    assert_true "Telegram block has a top-level heading" "true"
else
    assert_true "Telegram block has a top-level heading" "false"
fi
if status_block_contains 'printf "    state:[[:space:]]+\$\{TG_STATE_DISPLAY\}\\n"'; then
    assert_true "Telegram block has a coherent state line" "true"
else
    assert_true "Telegram block has a coherent state line" "false"
fi
if status_block_contains 'printf "    chat_id source:[[:space:]]+\$\{TG_SOURCE_DISPLAY\}\\n"'; then
    assert_true "Telegram block has a chat_id source line" "true"
else
    assert_true "Telegram block has a chat_id source line" "false"
fi
if status_block_contains 'printf "    chat_id status:[[:space:]]+\$\(telegram_chat_id_display "\$\{TG_CHAT_ID_STATUS\}"\)\\n"'; then
    assert_true "Telegram block has a chat_id status line" "true"
else
    assert_true "Telegram block has a chat_id status line" "false"
fi
if status_block_contains 'printf "    token:[[:space:]]+\$\{TG_TOKEN_DISPLAY\}\\n"'; then
    assert_true "Telegram block has a token presence line" "true"
else
    assert_true "Telegram block has a token presence line" "false"
fi

# ── Final summary ──
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${passed} passed, ${failed} failed"
echo "═══════════════════════════════════════════════════════════════"

if [ "${failed}" -gt 0 ]; then
    echo ""
    echo "FAILED ASSERTIONS:"
    for f in "${FAILED_ASSERTIONS[@]}"; do
        echo "  - ${f}"
    done
    exit 1
fi

exit 0
