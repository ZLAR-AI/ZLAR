#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Human Invariants — Mechanical Enforcement
#
# The manifest has 17 invariants. The human has 17 too.
# Five of them are enforced here:
#
#   H6  — No Throughput Pressure (decision cap per day)
#   H13 — Judgment Must Be Over-Provisioned (capacity monitoring)
#   H14 — Protected Human Judgment (approval rate monitoring)
#   H15 — Deliberation Floor (minimum review time per risk class)
#   H17 — Human Authenticity (reject automated response patterns)
#
# State is per-human, not per-session. A human's daily decision count
# persists across sessions. These invariants enforce decision quality
# constraints: daily caps, deliberation floors, and approval rate monitoring.
#
# Design: every function returns a decision. Callers act on it.
# No function calls exit. No function overrides policy.
# ═══════════════════════════════════════════════════════════════════════════════

# Guard against double-sourcing
[ -n "${_ZLAR_HUMAN_INVARIANTS_LOADED:-}" ] && return 0
_ZLAR_HUMAN_INVARIANTS_LOADED=1

# ─── Configuration ────────────────────────────────────────────────────────────

_HI_PROJECT_DIR="${_HI_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
_HI_STATE_DIR="${_HI_PROJECT_DIR}/var/human-state"
_HI_LOG="${_HI_PROJECT_DIR}/var/log/human-invariants.log"

# H6: Maximum decisions per human per day. Default: 80 (research ceiling).
HI_DAILY_DECISION_CAP="${ZLAR_DAILY_DECISION_CAP:-80}"

# H13: Maximum pending decisions before capacity warning. Default: 5.
HI_PENDING_CAP="${ZLAR_PENDING_CAP:-5}"

# H14: Approval rate threshold. Above this = rubber-stamping warning. Default: 90%.
HI_APPROVAL_RATE_THRESHOLD="${ZLAR_APPROVAL_RATE_THRESHOLD:-90}"
HI_APPROVAL_RATE_WINDOW="${ZLAR_APPROVAL_RATE_WINDOW:-20}"

# H15: Minimum deliberation time in seconds per risk class.
# critical=30s, warn=10s, info=3s. Below this = approval rejected.
HI_DELIBERATION_FLOOR_CRITICAL="${ZLAR_DELIBERATION_CRITICAL:-30}"
HI_DELIBERATION_FLOOR_WARN="${ZLAR_DELIBERATION_WARN:-10}"
HI_DELIBERATION_FLOOR_INFO="${ZLAR_DELIBERATION_INFO:-3}"

# H17: Minimum response time in seconds for any action. Below this = suspicious.
HI_MIN_RESPONSE_TIME="${ZLAR_MIN_RESPONSE_TIME:-2}"

# ─── State Management ─────────────────────────────────────────────────────────

_hi_log() {
    local msg="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [human-invariants] $*"
    echo "${msg}" >> "${_HI_LOG}" 2>/dev/null || true
}

_hi_ensure_state() {
    local human_id="${1:?}"
    mkdir -p "${_HI_STATE_DIR}" 2>/dev/null || true
    local state_file="${_HI_STATE_DIR}/${human_id}.json"

    if [ ! -f "${state_file}" ]; then
        local today
        today=$(date -u +%Y-%m-%d)
        jq -n \
            --arg hid "${human_id}" \
            --arg today "${today}" \
            '{human_id: $hid, date: $today, decisions_today: 0, approvals_recent: [], pending_count: 0, last_ask_epoch: 0}' \
            > "${state_file}" 2>/dev/null
    fi

    # Reset daily counter if date has changed
    local state_date
    state_date=$(jq -r '.date // ""' "${state_file}" 2>/dev/null)
    local today
    today=$(date -u +%Y-%m-%d)
    if [ "${state_date}" != "${today}" ]; then
        # v2.7.0: also resets pending_count alongside decisions_today.
        # Belt fix for H13 pending-count leak (see commit message).
        jq --arg today "${today}" '.date = $today | .decisions_today = 0 | .pending_count = 0' \
            "${state_file}" > "${state_file}.tmp" 2>/dev/null && \
            mv "${state_file}.tmp" "${state_file}" 2>/dev/null || true
    fi

    echo "${state_file}"
}

# ─── H6: No Throughput Pressure ───────────────────────────────────────────────
# Check if the human has capacity for another decision today.
# Returns: "ok" if within cap, "exceeded" if cap reached.

hi_check_capacity() {
    local human_id="${1:?Usage: hi_check_capacity <human_id>}"
    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local decisions_today
    decisions_today=$(jq -r '.decisions_today // 0' "${state_file}" 2>/dev/null)

    if [ "${decisions_today}" -ge "${HI_DAILY_DECISION_CAP}" ]; then
        _hi_log "H6 VIOLATED: ${human_id} has reached daily cap (${decisions_today}/${HI_DAILY_DECISION_CAP})"
        echo "exceeded"
        return 1
    fi

    echo "ok"
    return 0
}

# ─── H13: Judgment Must Be Over-Provisioned ───────────────────────────────────
# Track pending decisions. If too many are pending, the system is under-resourced.
# Returns: "ok" or "overloaded"

hi_increment_pending() {
    local human_id="${1:?}"
    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    jq '.pending_count = ((.pending_count // 0) + 1)' \
        "${state_file}" > "${state_file}.tmp" 2>/dev/null && \
        mv "${state_file}.tmp" "${state_file}" 2>/dev/null || true

    local pending
    pending=$(jq -r '.pending_count // 0' "${state_file}" 2>/dev/null)

    if [ "${pending}" -gt "${HI_PENDING_CAP}" ]; then
        _hi_log "H13 WARNING: ${human_id} has ${pending} pending decisions (cap: ${HI_PENDING_CAP}) — system is under-resourced"
        echo "overloaded"
        return 1
    fi

    echo "ok"
    return 0
}

hi_decrement_pending() {
    local human_id="${1:?}"
    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    jq '.pending_count = ([0, ((.pending_count // 0) - 1)] | max)' \
        "${state_file}" > "${state_file}.tmp" 2>/dev/null && \
        mv "${state_file}.tmp" "${state_file}" 2>/dev/null || true
}

# ─── H15: Deliberation Floor ──────────────────────────────────────────────────
# Record when an ask was sent. When the response comes back, check elapsed time.
# If below the floor for this severity class, the approval is rejected.
#
# Returns: "ok" or "too_fast"

hi_record_ask_time() {
    local human_id="${1:?}"
    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local epoch_now
    epoch_now=$(date +%s)
    jq --argjson t "${epoch_now}" '.last_ask_epoch = $t' \
        "${state_file}" > "${state_file}.tmp" 2>/dev/null && \
        mv "${state_file}.tmp" "${state_file}" 2>/dev/null || true
}

hi_check_deliberation() {
    local human_id="${1:?}"
    local severity="${2:-info}"

    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local ask_epoch
    ask_epoch=$(jq -r '.last_ask_epoch // 0' "${state_file}" 2>/dev/null)
    local now_epoch
    now_epoch=$(date +%s)
    local elapsed=$((now_epoch - ask_epoch))

    # Determine floor based on severity
    local floor=0
    case "${severity}" in
        critical) floor="${HI_DELIBERATION_FLOOR_CRITICAL}" ;;
        warn)     floor="${HI_DELIBERATION_FLOOR_WARN}" ;;
        info)     floor="${HI_DELIBERATION_FLOOR_INFO}" ;;
        *)        floor="${HI_DELIBERATION_FLOOR_INFO}" ;;
    esac

    if [ "${elapsed}" -lt "${floor}" ]; then
        _hi_log "H15 VIOLATED: ${human_id} responded in ${elapsed}s for severity=${severity} (floor: ${floor}s)"
        echo "too_fast"
        return 1
    fi

    echo "ok"
    return 0
}

# ─── H17: Human Authenticity ──────────────────────────────────────────────────
# Reject suspiciously fast responses. A human cannot read, comprehend, and
# decide on a tool call in under 2 seconds.
#
# Returns: "ok" or "suspicious"

hi_check_authenticity() {
    local human_id="${1:?}"

    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local ask_epoch
    ask_epoch=$(jq -r '.last_ask_epoch // 0' "${state_file}" 2>/dev/null)
    local now_epoch
    now_epoch=$(date +%s)
    local elapsed=$((now_epoch - ask_epoch))

    if [ "${elapsed}" -lt "${HI_MIN_RESPONSE_TIME}" ]; then
        _hi_log "H17 VIOLATED: ${human_id} responded in ${elapsed}s (min: ${HI_MIN_RESPONSE_TIME}s) — possible automated response"
        echo "suspicious"
        return 1
    fi

    echo "ok"
    return 0
}

# ─── H14: Protected Human Judgment ───────────────────────────────────────────
# Track approval/denial ratio. If approval rate exceeds threshold in the
# recent window, the human may be rubber-stamping.
#
# Call hi_record_decision after each human decision.
# Call hi_check_approval_rate before routing a new decision.
#
# Returns: "ok" or "rubber_stamping"

hi_record_decision() {
    local human_id="${1:?}"
    local decision="${2:?}"  # "approve" or "deny"

    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    # Increment daily counter
    # Add decision to recent window
    local is_approval="false"
    [ "${decision}" = "approve" ] || [ "${decision}" = "allow" ] || [ "${decision}" = "authorized" ] && is_approval="true"

    jq --argjson approved "${is_approval}" \
       --argjson window "${HI_APPROVAL_RATE_WINDOW}" \
       '.decisions_today += 1 | .approvals_recent = (.approvals_recent + [$approved] | .[-$window:])' \
        "${state_file}" > "${state_file}.tmp" 2>/dev/null && \
        mv "${state_file}.tmp" "${state_file}" 2>/dev/null || true
}

hi_check_approval_rate() {
    local human_id="${1:?}"

    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local rate
    rate=$(jq -r --argjson window "${HI_APPROVAL_RATE_WINDOW}" '
        .approvals_recent as $arr |
        if ($arr | length) < ($window / 2) then
            -1  # Not enough data
        else
            ([$arr[] | select(. == true)] | length) * 100 / ($arr | length)
        end
    ' "${state_file}" 2>/dev/null)

    # Not enough data to judge
    if [ "${rate}" = "-1" ] || [ -z "${rate}" ]; then
        echo "ok"
        return 0
    fi

    if [ "${rate}" -ge "${HI_APPROVAL_RATE_THRESHOLD}" ]; then
        _hi_log "H14 WARNING: ${human_id} approval rate is ${rate}% in last ${HI_APPROVAL_RATE_WINDOW} decisions (threshold: ${HI_APPROVAL_RATE_THRESHOLD}%)"
        echo "rubber_stamping"
        return 1
    fi

    echo "ok"
    return 0
}

# ─── Combined Pre-Ask Check ──────────────────────────────────────────────────
# Call before routing a decision to a human. Checks H6 + H13 + H14.
# Returns: "ok", "capacity_exceeded", "overloaded", or "rubber_stamping"

hi_pre_ask_check() {
    local human_id="${1:?Usage: hi_pre_ask_check <human_id>}"

    # H6: Daily cap
    local cap_result
    cap_result=$(hi_check_capacity "${human_id}")
    if [ "${cap_result}" = "exceeded" ]; then
        echo "capacity_exceeded"
        return 1
    fi

    # H14: Approval rate
    local rate_result
    rate_result=$(hi_check_approval_rate "${human_id}")
    if [ "${rate_result}" = "rubber_stamping" ]; then
        echo "rubber_stamping"
        return 1
    fi

    # H13: Pending queue
    local pending_result
    pending_result=$(hi_increment_pending "${human_id}")
    if [ "${pending_result}" = "overloaded" ]; then
        echo "overloaded"
        return 1
    fi

    echo "ok"
    return 0
}

# ─── Combined Post-Response Check ─────────────────────────────────────────────
# Call after receiving a human response. Checks H15 + H17.
# Returns: "ok", "too_fast", or "suspicious"

hi_post_response_check() {
    local human_id="${1:?}"
    local severity="${2:-info}"
    local decision="${3:?}"  # "approve" or "deny"

    # Decrement pending
    hi_decrement_pending "${human_id}"

    # H17: Authenticity (must come first — if automated, deliberation is meaningless)
    local auth_result
    auth_result=$(hi_check_authenticity "${human_id}")
    if [ "${auth_result}" = "suspicious" ]; then
        echo "suspicious"
        return 1
    fi

    # H15: Deliberation floor
    local delib_result
    delib_result=$(hi_check_deliberation "${human_id}" "${severity}")
    if [ "${delib_result}" = "too_fast" ]; then
        echo "too_fast"
        return 1
    fi

    # Record the decision for H14 rate tracking
    hi_record_decision "${human_id}" "${decision}"

    echo "ok"
    return 0
}
