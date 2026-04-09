#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Fail-Closed Alert — out-of-band notification when invariants fire
#
# When a human invariant fires (H6 capacity_exceeded, H13 overloaded,
# H14 rubber_stamping), the gate refuses to route new asks to the human.
# In the original v2.7.x design the alert path that would notify the
# human was subject to the same uniform invariant check as agent tool
# calls — the gate could block the notification that would have announced
# the gate was blocking. Origin: April 9 2026 incident where a Claude
# Code session hit H14 and the agent's attempt to send a Telegram reply
# announcing the failure was itself blocked by the same H14 check.
#
# This library closes that gap. It sends a Telegram message DIRECTLY
# via curl, from inside the gate process itself — bypassing every layer
# that could be subject to the failing invariant. It is best-effort and
# silent on failure (no recursion possible into the gate).
#
# Dedupe: a flag file at ${GATE_TMP}/fail-closed-alert.flag tracks the
# epoch of the last alert. New alerts are suppressed inside a configurable
# window (default 3600 seconds = 1 hour) so the gate does not spam the
# human on every blocked tool call.
#
# Usage:
#   source lib/fail-closed-alert.sh
#   fail_closed_alert <reason>     # one of: capacity_exceeded, overloaded, rubber_stamping
#
# Required environment (set by the calling script before invocation):
#   TELEGRAM_TOKEN     — bot token (already loaded by bin/zlar-gate from .env)
#   TELEGRAM_CHAT_ID   — target chat id (already loaded by bin/zlar-gate)
#   GATE_TMP           — private temp directory (already created by bin/zlar-gate)
#   LOG_FILE           — gate log path (optional; if missing, alert just doesn't log)
# ═══════════════════════════════════════════════════════════════════════════════

# Dedupe window in seconds. Override via ZLAR_ALERT_INTERVAL_S env var.
ZLAR_ALERT_INTERVAL_S="${ZLAR_ALERT_INTERVAL_S:-3600}"

# Internal: log a line to the gate log if LOG_FILE is set, otherwise silent.
_fca_log() {
    if [ -n "${LOG_FILE:-}" ]; then
        printf '[%s] [fail-closed-alert] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "${LOG_FILE}" 2>/dev/null || true
    fi
}

# Public: emit a fail-closed alert if the dedupe window allows it.
# Returns 0 always (best-effort, never blocks the caller).
fail_closed_alert() {
    local reason="${1:-unknown}"

    # Refuse to run if required state is missing.
    if [ -z "${GATE_TMP:-}" ]; then
        _fca_log "skipped: GATE_TMP not set"
        return 0
    fi
    if [ -z "${TELEGRAM_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
        _fca_log "skipped: TELEGRAM_TOKEN or TELEGRAM_CHAT_ID not set"
        return 0
    fi
    if ! command -v curl &>/dev/null; then
        _fca_log "skipped: curl not on PATH"
        return 0
    fi

    local flag_file="${GATE_TMP}/fail-closed-alert.flag"
    local now last_epoch last_reason delta
    now=$(date +%s)

    # State-transition + time-based dedupe (v2.7.4):
    #   Line 1: epoch of last alert
    #   Line 2: reason of last alert
    #
    # Suppress the alert if:
    #   - The previous alert was the SAME reason AND fired within the
    #     ZLAR_ALERT_INTERVAL_S window.
    #
    # Alert (i.e., do NOT suppress) if:
    #   - There is no prior state (first alert ever)
    #   - The prior reason is DIFFERENT from the current reason (state
    #     transition, e.g., H14 cleared but H13 fires)
    #   - The prior reason is the same but the time window has expired
    #     (periodic re-notify so a long-stuck gate reminds the human)
    last_epoch=0
    last_reason=""
    if [ -f "${flag_file}" ]; then
        last_epoch=$(sed -n '1p' "${flag_file}" 2>/dev/null | tr -d '[:space:]')
        last_reason=$(sed -n '2p' "${flag_file}" 2>/dev/null | tr -d '[:space:]')
        last_epoch="${last_epoch:-0}"
        case "${last_epoch}" in
            ''|*[!0-9]*) last_epoch=0 ;;
        esac
    fi

    delta=$(( now - last_epoch ))
    if [ "${last_reason}" = "${reason}" ] && [ "${delta}" -lt "${ZLAR_ALERT_INTERVAL_S}" ]; then
        _fca_log "suppressed: same reason (${reason}), ${delta}s since last alert (window: ${ZLAR_ALERT_INTERVAL_S}s)"
        return 0
    fi
    if [ -n "${last_reason}" ] && [ "${last_reason}" != "${reason}" ]; then
        _fca_log "transition: ${last_reason} → ${reason}, firing new alert"
    fi

    # Build the message. Plain text — no MarkdownV2 escaping headaches.
    local hostname_s timestamp_iso invariant_label
    hostname_s=$(hostname -s 2>/dev/null || echo "unknown")
    timestamp_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    case "${reason}" in
        rubber_stamping)
            invariant_label="H14 — approval rate >=90% over last 20 decisions"
            ;;
        overloaded)
            invariant_label="H13 — pending approval queue exceeded cap"
            ;;
        capacity_exceeded)
            invariant_label="H6 — daily decision cap reached"
            ;;
        *)
            invariant_label="${reason}"
            ;;
    esac

    local text
    text=$(printf '🚨 ZLAR Gate Fail-Closed\n─────────────────────\nReason: %s\nInvariant: %s\nTime: %s\nHost: %s\n\nThe gate is refusing to route new asks until the invariant clears. This alert is sent at most once per %s seconds.' \
        "${reason}" "${invariant_label}" "${timestamp_iso}" "${hostname_s}" "${ZLAR_ALERT_INTERVAL_S}")

    # Send via curl directly. --config - reads token from stdin so it never
    # appears in the process table. Same pattern as bin/zlar-gate's
    # telegram_api function.
    local body
    body=$(jq -n -c \
        --arg chat_id "${TELEGRAM_CHAT_ID}" \
        --arg text "${text}" \
        '{chat_id: $chat_id, text: $text}' 2>/dev/null)

    if [ -z "${body}" ]; then
        _fca_log "send failed: jq could not build request body"
        return 0
    fi

    local response http_code
    response=$(curl -s --connect-timeout 5 --max-time 10 \
        -w '\n%{http_code}' \
        -X POST \
        -H "Content-Type: application/json" \
        -d "${body}" \
        --config - 2>/dev/null <<EOF || true
url = "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage"
EOF
)
    http_code=$(printf '%s' "${response}" | tail -1)

    if [ "${http_code}" = "200" ]; then
        # Mark dedupe flag with current epoch.
        printf '%s\n%s\n' "${now}" "${reason}" > "${flag_file}" 2>/dev/null || true
        chmod 600 "${flag_file}" 2>/dev/null || true
        _fca_log "alert sent: reason=${reason} http=${http_code}"
    else
        _fca_log "alert send failed: reason=${reason} http=${http_code:-no-response}"
    fi

    return 0
}
