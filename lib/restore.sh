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
RESTORE_HMAC_KEY_FILE=""
RESTORE_HMAC_KEY=""
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
        # Config integrity check: even if disabled, verify the config hasn't been
        # tampered with. An agent setting enabled=false is the primary attack vector.
        _restore_verify_config_integrity
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

    # Load HMAC key if configured
    local _hmac_path
    _hmac_path=$(jq -r '.hmac_key_file // ""' "${RESTORE_CONFIG_FILE}" 2>/dev/null)
    if [ -n "${_hmac_path}" ]; then
        RESTORE_HMAC_KEY_FILE="${PROJECT_DIR}/${_hmac_path}"
        if [ -f "${RESTORE_HMAC_KEY_FILE}" ]; then
            RESTORE_HMAC_KEY=$(cat "${RESTORE_HMAC_KEY_FILE}" 2>/dev/null | tr -d '[:space:]')
        fi
    fi

    # Load escalation mappings
    RESTORE_ESCALATION_DEGRADED=$(jq -r '.escalation.degraded // "log"' "${RESTORE_CONFIG_FILE}" 2>/dev/null || echo "log")
    RESTORE_ESCALATION_AT_RISK=$(jq -r '.escalation.at_risk // "ask"' "${RESTORE_CONFIG_FILE}" 2>/dev/null || echo "ask")
    RESTORE_ESCALATION_SUSPENDED=$(jq -r '.escalation.suspended // "deny"' "${RESTORE_CONFIG_FILE}" 2>/dev/null || echo "deny")

    # Config integrity check (runs whether enabled or disabled)
    _restore_verify_config_integrity
}

# ── Config Integrity ──
#
# Verifies restore-config.json against its HMAC sidecar file.
# If the HMAC key exists and verification fails, force restore ON with
# maximum escalation. The attacker who tampers gets the opposite of
# what they wanted.
#
# RESTORE-INV-12: Config integrity — tampered config forces fail-closed.

_restore_verify_config_integrity() {
    # No HMAC key for config = no verification (operator hasn't set it up yet)
    local _config_hmac_key_file="${PROJECT_DIR}/etc/keys/restore-config-hmac.key"
    [ -f "${_config_hmac_key_file}" ] || return 0

    local _config_hmac_key
    _config_hmac_key=$(cat "${_config_hmac_key_file}" 2>/dev/null | tr -d '[:space:]')
    [ -n "${_config_hmac_key}" ] || return 0

    local _config_hmac_file="${RESTORE_CONFIG_FILE}.hmac"

    # Sidecar missing = unsigned config with key present = tampered
    if [ ! -f "${_config_hmac_file}" ]; then
        _restore_force_closed "config HMAC sidecar missing"
        return 0
    fi

    # Compute and compare
    local _stored_hmac _canonical _computed_hmac
    _stored_hmac=$(cat "${_config_hmac_file}" 2>/dev/null | tr -d '[:space:]')
    _canonical=$(jq -c '.' "${RESTORE_CONFIG_FILE}" 2>/dev/null)
    _computed_hmac=$(printf '%s' "${_canonical}" | openssl dgst -sha256 -hmac "${_config_hmac_key}" 2>/dev/null | awk '{print $NF}')

    if [ "${_computed_hmac}" != "${_stored_hmac}" ]; then
        _restore_force_closed "config HMAC mismatch"
        return 0
    fi
}

# Force restore to fail-closed state: enabled with all escalations at deny.
_restore_force_closed() {
    local _reason="${1:-unknown}"
    RESTORE_ENABLED="true"
    RESTORE_ESCALATION_DEGRADED="deny"
    RESTORE_ESCALATION_AT_RISK="deny"
    RESTORE_ESCALATION_SUSPENDED="deny"

    # Set trust state file path if not already set (config was tampered, but we
    # still need to know where to read trust state from)
    if [ -z "${RESTORE_TRUST_STATE_FILE}" ]; then
        RESTORE_TRUST_STATE_FILE="${PROJECT_DIR}/var/restore/trust-state.json"
        mkdir -p "$(dirname "${RESTORE_TRUST_STATE_FILE}")" 2>/dev/null || true
    fi

    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [restore] CRITICAL: Config integrity failure (${_reason}) — forcing fail-closed. All escalations set to deny." >> "${PROJECT_DIR}/var/log/gate.log" 2>/dev/null || true

    # Telegram alert if available
    if [ -n "${TELEGRAM_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
        local _alert_body
        _alert_body=$(jq -n --arg chat "${TELEGRAM_CHAT_ID}" --arg reason "${_reason}" \
            '{"chat_id":$chat,"text":"🚨 ZLAR CRITICAL: Restore config integrity failure (\($reason)). Agent Health forced to maximum escalation. All actions require human approval. Check etc/restore-config.json for tampering."}')
        curl -s -m 10 -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
            -H "Content-Type: application/json" -d "${_alert_body}" >/dev/null 2>&1 || true
    fi
}

# ── Trust State Reader ──

# Returns current trust state: healthy, degraded, at_risk, suspended
# RESTORE-INV-01: absent file = healthy
# RESTORE-INV-02: malformed file = degraded
_restore_read_trust_state() {
    # Not enabled — healthy (no opinion)
    [ "${RESTORE_ENABLED}" = "true" ] || { echo "healthy"; return 0; }

    # Pending evaluation marker: if background trigger is still running,
    # escalate floor to degraded for interim actions
    local _eval_marker="${PROJECT_DIR}/var/restore/.evaluating"
    if [ -f "${_eval_marker}" ]; then
        local _eval_ts _now_ts _age
        _eval_ts=$(cat "${_eval_marker}" 2>/dev/null | tr -d '[:space:]')
        _now_ts=$(date +%s 2>/dev/null)
        _age=$(( _now_ts - _eval_ts )) 2>/dev/null || _age=999
        if [ "${_age}" -lt 30 ] 2>/dev/null; then
            # Evaluation in progress — read file state but floor to degraded
            local _file_state
            _file_state=$(_restore_read_trust_state_from_file)
            case "${_file_state}" in
                at_risk|suspended)
                    echo "${_file_state}"
                    ;;
                *)
                    echo "degraded"
                    ;;
            esac
            return 0
        fi
    fi

    _restore_read_trust_state_from_file
}

# Internal: read trust state from the cached file with HMAC verification
_restore_read_trust_state_from_file() {
    # No file — healthy (INV-01)
    [ -f "${RESTORE_TRUST_STATE_FILE}" ] || { echo "healthy"; return 0; }

    # HMAC verification if key is available
    if [ -n "${RESTORE_HMAC_KEY}" ]; then
        local _stored_hmac _payload _computed_hmac
        _stored_hmac=$(jq -r '._hmac // ""' "${RESTORE_TRUST_STATE_FILE}" 2>/dev/null)
        if [ -n "${_stored_hmac}" ]; then
            _payload=$(jq -c 'del(._hmac)' "${RESTORE_TRUST_STATE_FILE}" 2>/dev/null)
            _computed_hmac=$(printf '%s' "${_payload}" | openssl dgst -sha256 -hmac "${RESTORE_HMAC_KEY}" 2>/dev/null | awk '{print $NF}')
            if [ "${_computed_hmac}" != "${_stored_hmac}" ]; then
                echo "degraded"
                return 0
            fi
        elif [ -n "${RESTORE_HMAC_KEY}" ]; then
            # Key exists but no HMAC in file — treat as tampered
            echo "degraded"
            return 0
        fi
    fi

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
