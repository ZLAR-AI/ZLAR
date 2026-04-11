#!/bin/bash
# restore.sh — Agent Health trust-state layer for ZLAR gate
#
# The restore subsystem observes agent behavior across the session and
# maintains a trust state: healthy -> degraded -> at_risk -> suspended.
# This library reads the trust state and advises the gate on escalation.
#
# Design principle: the trust state informs the gate's decision. It does
# not override policy. If trust state is degraded and policy says "allow",
# the gate may escalate to "log" or "ask" — the human decides, not the
# detector.
#
# Invariants:
#   RESTORE-INV-01: Absent trust state = healthy (no file = no degradation)
#   RESTORE-INV-02: Malformed trust state = degraded (parse failure is a signal)
#   RESTORE-INV-03: Monotone transitions (state only worsens without human reset)
#   RESTORE-INV-04: Restore cannot crash the gate (all errors trapped)

# ── Configuration ──

RESTORE_CONFIG_FILE="${PROJECT_DIR}/etc/restore-config.json"
RESTORE_ENABLED="false"
RESTORE_TRUST_STATE_FILE=""
RESTORE_ESCALATION_DEGRADED="log"
RESTORE_ESCALATION_AT_RISK="ask"
RESTORE_ESCALATION_SUSPENDED="deny"

# ── Initialization ──

restore_init() {
    # Load config if present
    if [ ! -f "${RESTORE_CONFIG_FILE}" ]; then
        RESTORE_ENABLED="false"
        return 0
    fi

    local _enabled
    _enabled=$(jq -r '.enabled // false' "${RESTORE_CONFIG_FILE}" 2>/dev/null || echo "false")

    if [ "${_enabled}" != "true" ]; then
        RESTORE_ENABLED="false"
        return 0
    fi

    RESTORE_ENABLED="true"

    local _trust_path
    _trust_path=$(jq -r '.trust_state_file // "var/restore/trust-state.json"' "${RESTORE_CONFIG_FILE}" 2>/dev/null)
    RESTORE_TRUST_STATE_FILE="${PROJECT_DIR}/${_trust_path}"

    # Ensure trust state directory exists
    local _trust_dir
    _trust_dir=$(dirname "${RESTORE_TRUST_STATE_FILE}")
    mkdir -p "${_trust_dir}" 2>/dev/null || true

    # Load escalation mappings
    RESTORE_ESCALATION_DEGRADED=$(jq -r '.escalation.degraded // "log"' "${RESTORE_CONFIG_FILE}" 2>/dev/null || echo "log")
    RESTORE_ESCALATION_AT_RISK=$(jq -r '.escalation.at_risk // "ask"' "${RESTORE_CONFIG_FILE}" 2>/dev/null || echo "ask")
    RESTORE_ESCALATION_SUSPENDED=$(jq -r '.escalation.suspended // "deny"' "${RESTORE_CONFIG_FILE}" 2>/dev/null || echo "deny")
}

# ── Trust State Reader ──

# Returns current trust state: healthy, degraded, at_risk, suspended
# RESTORE-INV-01: absent file = healthy
# RESTORE-INV-02: malformed file = degraded
_restore_read_trust_state() {
    # Not enabled — healthy (no opinion)
    [ "${RESTORE_ENABLED}" = "true" ] || { echo "healthy"; return 0; }

    # No file — healthy (INV-01)
    [ -f "${RESTORE_TRUST_STATE_FILE}" ] || { echo "healthy"; return 0; }

    local state
    state=$(jq -r '.state // ""' "${RESTORE_TRUST_STATE_FILE}" 2>/dev/null)

    # Malformed or empty — degraded (INV-02)
    case "${state}" in
        healthy|degraded|at_risk|suspended)
            echo "${state}"
            ;;
        *)
            echo "degraded"
            ;;
    esac
}

# ── Action Ordering ──
# allow < log < ask < deny

_restore_action_rank() {
    case "${1}" in
        allow) echo 0 ;;
        log)   echo 1 ;;
        ask)   echo 2 ;;
        deny)  echo 3 ;;
        *)     echo 0 ;;
    esac
}

_restore_action_is_weaker() {
    local rank_a rank_b
    rank_a=$(_restore_action_rank "${1}")
    rank_b=$(_restore_action_rank "${2}")
    [ "${rank_a}" -lt "${rank_b}" ]
}

# ── Escalation Check ──
# Called by the gate after session-state checks.
# If trust state warrants escalation, may upgrade the action.
#
# Escalation rules:
#   healthy    -> no change
#   degraded   -> escalate allow -> log (configurable)
#   at_risk    -> escalate allow/log -> ask (configurable)
#   suspended  -> escalate allow/log/ask -> deny (configurable)
#
# RESTORE-INV-04: Error-trapped. Any failure returns input action unchanged.

restore_check_escalation() {
    local policy_action="${1:?}"

    # Not enabled — pass through
    [ "${RESTORE_ENABLED}" = "true" ] || { echo "${policy_action}"; return; }

    local trust_state
    trust_state=$(_restore_read_trust_state 2>/dev/null) || { echo "${policy_action}"; return; }

    local target_action=""

    case "${trust_state}" in
        healthy)
            echo "${policy_action}"
            return
            ;;
        degraded)
            target_action="${RESTORE_ESCALATION_DEGRADED}"
            ;;
        at_risk)
            target_action="${RESTORE_ESCALATION_AT_RISK}"
            ;;
        suspended)
            target_action="${RESTORE_ESCALATION_SUSPENDED}"
            ;;
        *)
            # Unknown state — treat as degraded (INV-02 extended)
            target_action="${RESTORE_ESCALATION_DEGRADED}"
            ;;
    esac

    if _restore_action_is_weaker "${policy_action}" "${target_action}"; then
        echo "${target_action}"
    else
        echo "${policy_action}"
    fi
}

# ── Trust State Summary ──

restore_trust_state_summary() {
    [ "${RESTORE_ENABLED}" = "true" ] || { echo "Restore: disabled"; return; }

    local trust_state
    trust_state=$(_restore_read_trust_state 2>/dev/null) || { echo "Restore: error reading state"; return; }

    echo "Restore: ${trust_state}"

    if [ -f "${RESTORE_TRUST_STATE_FILE}" ] && [ "${trust_state}" != "healthy" ]; then
        local updated_at
        updated_at=$(jq -r '.updated_at // "unknown"' "${RESTORE_TRUST_STATE_FILE}" 2>/dev/null)
        echo "  last updated: ${updated_at}"
    fi
}
