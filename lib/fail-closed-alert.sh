#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Fail-Closed Alert — out-of-band notification when invariants fire
#
# When a human invariant fires (H14 rubber_stamping), the gate refuses to route
# new asks to the human. H6 (capacity_exceeded) and H13 (overloaded) now send
# advisory alerts — the gate still routes asks, authority belongs to the human.
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
#   fail_closed_alert <reason>     # one of: canary_pattern_check, capacity_exceeded, overloaded, rubber_stamping (legacy)
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

    # Dedupe window: telegram_unreachable uses a shorter window (300s = 5 min)
    # because the human needs to know quickly when the gate is blocking
    # everything. Other invariant reasons (H6/H13/H14) use the standard
    # 3600s window since they are less urgent.
    local effective_window="${ZLAR_ALERT_INTERVAL_S}"
    if [ "${reason}" = "telegram_unreachable" ]; then
        effective_window="${ZLAR_ALERT_INTERVAL_TG_S:-300}"
    fi

    delta=$(( now - last_epoch ))
    if [ "${last_reason}" = "${reason}" ] && [ "${delta}" -lt "${effective_window}" ]; then
        _fca_log "suppressed: same reason (${reason}), ${delta}s since last alert (window: ${effective_window}s)"
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
        canary_pattern_check)
            invariant_label="H14 — response-time variance below floor (canary pattern check)"
            ;;
        rubber_stamping)
            # Legacy compat — keep until all callers and receipts migrated to canary_pattern_check.
            invariant_label="H14 — response-time stddev below floor over last 20 non-critical decisions"
            ;;
        overloaded)
            invariant_label="H13 — pending approval queue at capacity (advisory)"
            ;;
        capacity_exceeded)
            invariant_label="H6 — daily decision cap reached"
            ;;
        telegram_unreachable)
            invariant_label="Telegram send failed — approval requests cannot reach you"
            ;;
        *)
            invariant_label="${reason}"
            ;;
    esac

    local text
    if [ "${reason}" = "overloaded" ]; then
        # H13 advisory: queue at capacity but gate is still routing (v2.8.1).
        # The human decides if they're overwhelmed — do not lock them out.
        text=$(printf '⚠️ ZLAR Queue Advisory\n─────────────────────\nApproval queue is at capacity.\nInvariant: %s\nTime: %s\nHost: %s\n\nNew asks are still routing to you. Approve or deny pending items to clear the queue.' \
            "${invariant_label}" "${timestamp_iso}" "${hostname_s}")
    elif [ "${reason}" = "capacity_exceeded" ]; then
        # H6 advisory: daily cap reached but gate is still routing (v2.8.1).
        # The human decides if they want to continue — do not lock them out.
        text=$(printf '⚠️ ZLAR Daily Cap Advisory\n─────────────────────\nYou have reached your daily decision limit.\nInvariant: %s\nTime: %s\nHost: %s\n\nNew asks are still routing to you. This is informational — you decide whether to continue.' \
            "${invariant_label}" "${timestamp_iso}" "${hostname_s}")
    else
        text=$(printf '🚨 ZLAR Gate Fail-Closed\n─────────────────────\nReason: %s\nInvariant: %s\nTime: %s\nHost: %s\n\nThe gate is refusing to route new asks until the invariant clears. This alert is sent at most once per %s seconds.' \
            "${reason}" "${invariant_label}" "${timestamp_iso}" "${hostname_s}" "${ZLAR_ALERT_INTERVAL_S}")
    fi

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
        # Telegram is unreachable — use local macOS notification as fallback.
        # This is the HAL 9000 fix: when the only notification channel is the
        # thing that is broken, the human gets no signal. The gate silently
        # denies everything and the human does not know. Desktop notification
        # ensures the human is always reachable through at least one channel.
        _fca_local_notify "${reason}" "${invariant_label}" "${timestamp_iso}"
    fi

    return 0
}

# Internal: local desktop notification fallback when Telegram is unreachable.
# macOS only (osascript). Best-effort, silent on failure, deduped by the
# same flag file as the Telegram alert (so at most once per window).
_fca_local_notify() {
    local reason="${1:-unknown}" label="${2:-unknown}" ts="${3:-unknown}"

    # Only attempt on macOS.
    if ! command -v osascript &>/dev/null; then
        _fca_log "local fallback skipped: osascript not available (not macOS)"
        return 0
    fi

    local title="ZLAR Gate Fail-Closed"
    local body
    body=$(printf '%s\n%s' "${label}" "${ts}")

    osascript -e "display notification \"${body}\" with title \"${title}\" sound name \"Basso\"" 2>/dev/null || true
    _fca_log "local notification sent: reason=${reason}"
    return 0
}
