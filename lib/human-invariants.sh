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

# H13: Pending TTL in seconds. Entries older than this are aged out on every
# read, so orphaned increments (gate crashed, human pivoted, no response path)
# cannot drift the counter permanently. Default: 1800 (30 min).
HI_PENDING_TTL="${ZLAR_PENDING_TTL:-1800}"

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
            '{human_id: $hid, date: $today, decisions_today: 0, approvals_recent: [], pending: [], last_ask_epoch: 0}' \
            > "${state_file}" 2>/dev/null
    fi

    # Reset daily counter if date has changed
    local state_date
    state_date=$(jq -r '.date // ""' "${state_file}" 2>/dev/null)
    local today
    today=$(date -u +%Y-%m-%d)
    if [ "${state_date}" != "${today}" ]; then
        # v2.7.0: resets pending_count alongside decisions_today (H13 belt fix).
        # v2.7.2: also resets approvals_recent. Without this, yesterday's
        # approval-rate sliding window persists across the date boundary,
        # which is how H14 (rubber_stamping) can stay fire-closed after a
        # full day's reset. Origin: April 9 2026 incident where H14 fired
        # on a fresh morning session because the previous session's
        # 100% approval rate was still in the window.
        # v2.8.0: pending_count scalar replaced with pending: [{action_hash,ts}]
        # TTL array. Rollover drops the dead pending_count field and resets
        # the pending array to empty.
        jq --arg today "${today}" \
            '.date = $today | .decisions_today = 0 | .pending = [] | .approvals_recent = [] | del(.pending_count)' \
            "${state_file}" > "${state_file}.tmp" 2>/dev/null && \
            mv "${state_file}.tmp" "${state_file}" 2>/dev/null || true
    fi

    # v2.8.0 schema migration: any state file still carrying the deprecated
    # scalar pending_count (from v2.7.x written earlier today, before rollover)
    # must drop that field and gain a pending array. Idempotent after first run.
    # This is the code path that unblocks a human stuck at pending_count > cap:
    # the scalar dies here, the array starts empty, and the next ask finds
    # capacity again.
    if jq -e 'has("pending_count") or (has("pending") | not)' "${state_file}" >/dev/null 2>&1; then
        jq 'del(.pending_count) | .pending = (.pending // [])' \
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
#
# v2.8.0 rewrite: the old scalar pending_count had two failure modes that
# together locked the gate fail-closed in production (April 9 2026 incident):
#
#   1. Orphaned increments. hi_increment_pending runs on every ask, but
#      hi_decrement_pending only runs if the gate's post-response path is
#      reached. Claude Code's deny-then-retry architecture means the post
#      path can be skipped (Claude pivots, session ends, standing approval
#      bypasses the whole flow). Each orphan is a permanent +1 on the scalar.
#
#   2. Retry double-counting. When Claude retries a denied tool call before
#      the human has approved on Telegram, the gate falls into the "no prior
#      approval" branch again and increments pending_count a second time for
#      the same logical ask. Fast retries pump the counter through the cap
#      in seconds.
#
# Both failure modes collapse into one fix: a TTL-filtered array of
# {action_hash, ts} entries.
#
#   - Each increment filters stale entries (ts older than HI_PENDING_TTL)
#     before counting, so orphans age out automatically.
#   - Each increment checks whether the same action_hash is already in the
#     filtered array; if so, it's a retry and no new entry is added.
#   - Callers that don't pass an action_hash fall back to append-always
#     behavior (still bounded by TTL).
#
# Returns: "ok" or "overloaded"

hi_increment_pending() {
    local human_id="${1:?}"
    local action_hash="${2:-}"
    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local now_epoch
    now_epoch=$(date +%s)

    # Single jq pass: filter stale entries, apply dedup/cap logic, emit
    # a compact {state, action, length} object. The state field is the
    # full new state to write back; action is "ok" or "overloaded"; length
    # is the pending count after the decision (used in the warning log).
    local jq_out
    jq_out=$(jq -c \
        --argjson now "${now_epoch}" \
        --argjson ttl "${HI_PENDING_TTL}" \
        --argjson cap "${HI_PENDING_CAP}" \
        --arg hash "${action_hash}" '
        . as $state |
        ((.pending // []) | map(select($now - .ts < $ttl))) as $filtered |
        ($filtered | map(.action_hash) | index($hash)) as $idx |
        if ($hash != "" and $idx != null) then
            # Retry of an already-pending ask — do not re-append, count stays.
            {state: ($state | .pending = $filtered), action: "ok", length: ($filtered | length)}
        elif (($filtered | length) >= $cap) then
            # Would exceed cap — refuse to append, return overloaded.
            # Writing back $filtered (without the new entry) still performs
            # the stale cleanup, which is what we want.
            {state: ($state | .pending = $filtered), action: "overloaded", length: ($filtered | length)}
        else
            # Append new entry and return ok.
            ($filtered + [{action_hash: $hash, ts: $now}]) as $new |
            {state: ($state | .pending = $new), action: "ok", length: ($new | length)}
        end
    ' "${state_file}" 2>/dev/null)

    if [ -z "${jq_out}" ]; then
        # jq read or logic failed — state file may be corrupt or jq missing.
        # Fail open: the gate will still route the ask. H13 is there to
        # protect the human from overload, not to be a kill switch on
        # state corruption.
        _hi_log "ERROR: hi_increment_pending jq failed for ${human_id} — failing open"
        echo "ok"
        return 0
    fi

    # Write the new state back atomically.
    echo "${jq_out}" | jq -c '.state' > "${state_file}.tmp" 2>/dev/null && \
        mv "${state_file}.tmp" "${state_file}" 2>/dev/null || {
        _hi_log "ERROR: hi_increment_pending write failed for ${human_id} — failing open"
        rm -f "${state_file}.tmp" 2>/dev/null
        echo "ok"
        return 0
    }

    local action length
    action=$(echo "${jq_out}" | jq -r '.action')
    length=$(echo "${jq_out}" | jq -r '.length')

    if [ "${action}" = "overloaded" ]; then
        _hi_log "H13 WARNING: ${human_id} has ${length} pending decisions (cap: ${HI_PENDING_CAP}, ttl: ${HI_PENDING_TTL}s) — system is under-resourced"
        echo "overloaded"
        return 1
    fi

    echo "ok"
    return 0
}

hi_decrement_pending() {
    local human_id="${1:?}"
    local action_hash="${2:-}"
    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local now_epoch
    now_epoch=$(date +%s)

    # Filter stale, then either remove by action_hash (exact match) or drop
    # the oldest entry (FIFO). Both paths also perform the stale cleanup.
    jq \
        --argjson now "${now_epoch}" \
        --argjson ttl "${HI_PENDING_TTL}" \
        --arg hash "${action_hash}" '
        .pending = (
            ((.pending // []) | map(select($now - .ts < $ttl))) as $filtered |
            if $hash != "" then
                ($filtered | map(select(.action_hash != $hash)))
            else
                ($filtered | sort_by(.ts) | .[1:])
            end
        )
    ' "${state_file}" > "${state_file}.tmp" 2>/dev/null && \
        mv "${state_file}.tmp" "${state_file}" 2>/dev/null || {
        _hi_log "ERROR: hi_decrement_pending failed for ${human_id}"
        rm -f "${state_file}.tmp" 2>/dev/null
        return 1
    }
    return 0
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
#
# action_hash is optional. When provided, it enables retry dedup in H13:
# repeated calls with the same hash (e.g. Claude retrying a denied tool call)
# do not double-count the pending queue. Callers that don't have a stable
# action identifier can omit it — TTL alone still bounds the drift.
#
# Returns: "ok", "capacity_exceeded", "overloaded", or "rubber_stamping"

hi_pre_ask_check() {
    local human_id="${1:?Usage: hi_pre_ask_check <human_id> [action_hash]}"
    local action_hash="${2:-}"

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

    # H13: Pending queue (with TTL + retry dedup via action_hash)
    local pending_result
    pending_result=$(hi_increment_pending "${human_id}" "${action_hash}")
    if [ "${pending_result}" = "overloaded" ]; then
        echo "overloaded"
        return 1
    fi

    echo "ok"
    return 0
}

# ─── Combined Post-Response Check ─────────────────────────────────────────────
# Call after receiving a human response. Checks H15 + H17.
#
# action_hash is optional; when provided, it removes the exact pending entry
# that the matching hi_pre_ask_check added. When omitted, the oldest pending
# entry is dropped (FIFO). TTL cleans up anything else that gets left behind.
#
# Returns: "ok", "too_fast", or "suspicious"

hi_post_response_check() {
    local human_id="${1:?}"
    local severity="${2:-info}"
    local decision="${3:?}"  # "approve" or "deny"
    local action_hash="${4:-}"

    # Decrement pending (by hash if provided, else oldest)
    hi_decrement_pending "${human_id}" "${action_hash}"

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
