#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Human Invariants — Mechanical Enforcement
#
# The manifest has 17 invariants. The human has 17 too.
# Five of them are enforced here:
#
#   H6  — No Throughput Pressure (decision cap per day)
#   H13 — Judgment Must Be Over-Provisioned (capacity monitoring)
#   H14 — Protected Human Judgment (response-time variance monitoring)
#   H15 — Deliberation Floor (minimum review time per risk class)
#   H17 — Human Authenticity (reject automated response patterns)
#
# State is per-human, not per-session. A human's daily decision count
# persists across sessions. These invariants enforce decision quality
# constraints: daily caps, deliberation floors, and response-time variance monitoring.
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
# cannot drift the counter permanently.
# Default: 360 (6 min). Matches TELEGRAM_TIMEOUT_S (300s) + 60s buffer, so
# entries whose pending files have already expired are also aged out of H13.
# v2.8.1: reduced from 1800 (30 min) — the old TTL created a 25-min window
# where H13 counted entries whose pending files had already expired, causing
# spurious "overloaded" blocks during build sessions with many denied actions.
HI_PENDING_TTL="${ZLAR_PENDING_TTL:-360}"

# H14: Response time variance — low variance = rubber-stamping warning.
# Replaces approval rate tracking (which penalizes a well-calibrated gate).
# A genuine deliberator shows variable response times correlated with request
# complexity. A rubber-stamper responds uniformly fast regardless of severity.
# Threshold: std_dev < 4s over last 20 decisions = suspicious uniformity.
HI_VARIANCE_STDDEV_FLOOR="${ZLAR_VARIANCE_STDDEV_FLOOR:-4}"
HI_VARIANCE_WINDOW="${ZLAR_VARIANCE_WINDOW:-20}"
HI_VARIANCE_MIN_SAMPLE="${ZLAR_VARIANCE_MIN_SAMPLE:-10}"

# H15: Minimum deliberation time in seconds per risk class.
# critical=30s, warn=10s, info=3s. Below this = approval rejected.
HI_DELIBERATION_FLOOR_CRITICAL="${ZLAR_DELIBERATION_CRITICAL:-30}"
HI_DELIBERATION_FLOOR_WARN="${ZLAR_DELIBERATION_WARN:-10}"
HI_DELIBERATION_FLOOR_INFO="${ZLAR_DELIBERATION_INFO:-3}"

# H17: Minimum response time in seconds for any action. Below this = suspicious.
# v1 floor kept for backward compatibility — callers that set ZLAR_MIN_RESPONSE_TIME
# continue to work. H17 v2 adds ms-precision floors; see hi_check_authenticity.
HI_MIN_RESPONSE_TIME="${ZLAR_MIN_RESPONSE_TIME:-2}"

# H17 v2: millisecond-precision floors.
# HI_MIN_RESPONSE_TIME_MS: leave empty so hi_check_authenticity derives it from
# HI_MIN_RESPONSE_TIME at call time. This makes tests that override HI_MIN_RESPONSE_TIME
# (the legacy seconds knob) work without also setting the ms knob.
# Set ZLAR_MIN_RESPONSE_TIME_MS explicitly to bypass derivation.
HI_MIN_RESPONSE_TIME_MS="${ZLAR_MIN_RESPONSE_TIME_MS:-}"

# Machine-speed / authenticity floor: no operator profile can pass below this.
# Responses arriving faster than this are physically impossible for a human operator.
HI_ABSOLUTE_MIN_RESPONSE_TIME_MS="${ZLAR_ABSOLUTE_MIN_RESPONSE_TIME_MS:-500}"

# Graduated floor for calibrated operators on critical-severity approvals.
# Calibrated operators (sufficient response-time variance history) earn a lower
# floor here than the default, but not as low as the authenticity floor.
HI_CALIBRATED_CRITICAL_FLOOR_MS="${ZLAR_CALIBRATED_CRITICAL_FLOOR_MS:-1500}"

# ─── HMAC Protection (v3.1.3; refactored v3.1.4+) ────────────────────────────
# State files at var/human-state/{human_id}.json carry H6/H13/H14 counters
# that an agent with filesystem access could poison (inflate decisions_today
# to gate the human out, or deflate to suppress advisory). HMAC seals each
# write; on read, a failed verification is logged and the state rebuilt with
# safe defaults. Rebuild (not fail-closed) preserves the one human in the
# loop while the log preserves the security signal.
#
# The HMAC mechanics moved to lib/state-hmac.sh (canonical form, sealed write,
# verification) so gate-uptime and other state stores share one implementation.
# This file keeps thin wrappers that bind the shared helpers to _HI_HMAC_KEY.

# Source the shared helper from this file's own directory — not _HI_PROJECT_DIR,
# which tests override to a tmp dir for state isolation.
# shellcheck source=./state-hmac.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/state-hmac.sh"

_HI_HMAC_KEY_FILE="${_HI_PROJECT_DIR}/etc/keys/human-state-hmac.key"
_HI_HMAC_KEY=""
if [ -f "${_HI_HMAC_KEY_FILE}" ]; then
    _HI_HMAC_KEY=$(cat "${_HI_HMAC_KEY_FILE}" 2>/dev/null || true)
fi

# Thin wrappers preserving the _hi_ prefix used at call sites below.
_hi_verify_hmac()   { _state_hmac_verify       "${_HI_HMAC_KEY}" "$1"; }
_hi_sealed_write()  { _state_hmac_sealed_write "${_HI_HMAC_KEY}" "$1"; }

# ─── Timing ───────────────────────────────────────────────────────────────────

# Returns current time as integer milliseconds since Unix epoch.
# Portable: GNU date (Linux/CI) first; python3 fallback (macOS and everywhere else);
# last resort is second-granularity * 1000.
_hi_epoch_ms() {
    local ms
    ms=$(date +%s%3N 2>/dev/null)
    if printf '%s' "${ms}" | grep -qE '^[0-9]{13,}$'; then
        printf '%s\n' "${ms}"
        return
    fi
    python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || \
        printf '%s000\n' "$(date +%s)"
}

# ─── H17 v2: Calibration Check ────────────────────────────────────────────────

# Returns 0 (true) if the human has enough response-time variance to be
# considered calibrated; 1 (false) otherwise. Calibration is the same signal
# H14 uses: std_dev of non-critical response times ≥ HI_VARIANCE_STDDEV_FLOOR
# over at least HI_VARIANCE_MIN_SAMPLE entries.
#
# Takes the already-resolved state file path to avoid a redundant _hi_ensure_state
# call from within hi_check_authenticity.
_hi_is_calibrated() {
    local state_file="${1:?}"

    local stddev
    stddev=$(jq -r --argjson min_sample "${HI_VARIANCE_MIN_SAMPLE}" '
        .response_times as $arr |
        [$arr[] | select(type == "object" and .severity != "critical") | .elapsed] as $filtered |
        if ($filtered | length) < $min_sample then
            -1
        else
            (($filtered | add) / ($filtered | length)) as $mean |
            ([$filtered[] | (. - $mean) * (. - $mean)] | add) / ($filtered | length) |
            sqrt
        end
    ' "${state_file}" 2>/dev/null)

    [ -n "${stddev}" ] && [ "${stddev}" != "-1" ] || return 1

    awk -v sd="${stddev}" -v floor="${HI_VARIANCE_STDDEV_FLOOR}" \
        'BEGIN { exit (sd >= floor) ? 0 : 1 }'
}

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
            '{human_id: $hid, date: $today, decisions_today: 0, response_times: [], pending: [], last_ask_epoch: 0, last_ask_epoch_ms: 0}' \
            | _hi_sealed_write "${state_file}"
    else
        # Verify HMAC. On tamper: log + rebuild safe defaults. Rebuild, not
        # fail-closed, because locking the human out helps the attacker more
        # than the human — the attacker's goal is exactly to lock the human
        # out, and the log already preserves the security signal.
        local verify
        verify=$(_hi_verify_hmac "${state_file}")
        if [ "${verify}" = "tampered" ]; then
            _hi_log "SECURITY: ${human_id} state HMAC verification FAILED — rebuilding with safe defaults"
            local today
            today=$(date -u +%Y-%m-%d)
            jq -n \
                --arg hid "${human_id}" \
                --arg today "${today}" \
                '{human_id: $hid, date: $today, decisions_today: 0, response_times: [], pending: [], last_ask_epoch: 0, last_ask_epoch_ms: 0}' \
                | _hi_sealed_write "${state_file}"
        fi
    fi

    # Reset daily counter if date has changed
    local state_date
    state_date=$(jq -r '.date // ""' "${state_file}" 2>/dev/null)
    local today
    today=$(date -u +%Y-%m-%d)
    if [ "${state_date}" != "${today}" ]; then
        # v2.7.0: resets pending_count alongside decisions_today (H13 belt fix).
        # v2.7.2: introduced cross-day reset for H14's sliding window so
        # yesterday's window cannot keep H14 fire-closed after a full day's
        # reset. At the time the window was approvals_recent — del(.approvals_recent)
        # below scrubs that legacy field. Origin: April 9 2026 incident where
        # H14 fired on a fresh morning session because the previous session's
        # history was still in the window.
        # v2.8.0: pending_count scalar replaced with pending: [{action_hash,ts}]
        # TTL array. Rollover drops the dead pending_count field and resets
        # the pending array to empty.
        # v2.9.0: H14 switched to response-time variance. response_times is the
        # active sliding window now; the v2.7.2 cross-day reset principle
        # applies to it (response_times = []).
        jq --arg today "${today}" \
            'del(._hmac) | .date = $today | .decisions_today = 0 | .pending = [] | .response_times = [] | del(.approvals_recent) | del(.pending_count) | del(.h14_lockout_until)' \
            "${state_file}" 2>/dev/null | _hi_sealed_write "${state_file}"
    fi

    # v2.8.0 schema migration: any state file still carrying the deprecated
    # scalar pending_count (from v2.7.x written earlier today, before rollover)
    # must drop that field and gain a pending array. Idempotent after first run.
    # This is the code path that unblocks a human stuck at pending_count > cap:
    # the scalar dies here, the array starts empty, and the next ask finds
    # capacity again.
    if jq -e 'has("pending_count") or (has("pending") | not)' "${state_file}" >/dev/null 2>&1; then
        jq 'del(._hmac) | del(.pending_count) | .pending = (.pending // [])' \
            "${state_file}" 2>/dev/null | _hi_sealed_write "${state_file}"
    fi

    echo "${state_file}"
}

# ─── H6: No Throughput Pressure ───────────────────────────────────────────────
# Check if the human has capacity for another decision today.
#
# v2.8.1: decisions_today is now a risk-weighted float. Each decision costs
# max(10, risk_score) / 100 units toward the daily budget. A risk-100 decision
# costs 1.0 unit (same as before). A risk-10 decision costs 0.10 units.
# Default risk 100 preserves backward compatibility for callers that don't
# pass risk_score — one decision = one unit, same as the old integer count.
#
# Float comparison done in jq (not bash) to handle fractional values correctly.
#
# Returns: "ok" if within cap, "exceeded" if cap reached.

hi_check_capacity() {
    local human_id="${1:?Usage: hi_check_capacity <human_id>}"
    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    local result
    result=$(jq -r --argjson cap "${HI_DAILY_DECISION_CAP}" \
        'if ((.decisions_today // 0) >= $cap) then "exceeded" else "ok" end' \
        "${state_file}" 2>/dev/null || echo "ok")

    if [ "${result}" = "exceeded" ]; then
        local decisions_today
        decisions_today=$(jq -r '.decisions_today // 0' "${state_file}" 2>/dev/null)
        _hi_log "H6 ADVISORY: ${human_id} has reached daily cap (${decisions_today}/${HI_DAILY_DECISION_CAP} weighted units)"
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

    # Write the new state back atomically, sealed with HMAC.
    echo "${jq_out}" | jq -c '.state | del(._hmac)' 2>/dev/null | _hi_sealed_write "${state_file}" || {
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
        del(._hmac) |
        .pending = (
            ((.pending // []) | map(select($now - .ts < $ttl))) as $filtered |
            if $hash != "" then
                ($filtered | map(select(.action_hash != $hash)))
            else
                ($filtered | sort_by(.ts) | .[1:])
            end
        )
    ' "${state_file}" 2>/dev/null | _hi_sealed_write "${state_file}" || {
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

    local epoch_now epoch_ms_now
    epoch_now=$(date +%s)
    epoch_ms_now=$(_hi_epoch_ms)
    jq --argjson t "${epoch_now}" --argjson tms "${epoch_ms_now}" \
        'del(._hmac) | .last_ask_epoch = $t | .last_ask_epoch_ms = $tms' \
        "${state_file}" 2>/dev/null | _hi_sealed_write "${state_file}"
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
# Reject machine-speed responses. Uses millisecond-precision timing and
# per-operator calibration to distinguish fast-but-genuine human approvals
# from automation.
#
# Floor selection (ms):
#   All operators  — responses below HI_ABSOLUTE_MIN_RESPONSE_TIME_MS are
#                    always rejected (machine-speed / authenticity floor).
#   Uncalibrated   — responses below the default floor (derived from
#                    HI_MIN_RESPONSE_TIME_MS or HI_MIN_RESPONSE_TIME * 1000)
#                    are rejected regardless of severity.
#   Calibrated, warn/info — floor drops to HI_ABSOLUTE_MIN_RESPONSE_TIME_MS.
#   Calibrated, critical  — floor drops to HI_CALIBRATED_CRITICAL_FLOOR_MS.
#
# Calibration = sufficient non-critical response-time variance (same signal as H14).
#
# Backward compat: if last_ask_epoch_ms is absent, falls back to
# last_ask_epoch * 1000 (second-granularity, ≤1s precision loss).
#
# Returns: "ok" or "suspicious"

hi_check_authenticity() {
    local human_id="${1:?}"
    local severity="${2:-info}"

    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    # Read ms ask time; fall back to seconds * 1000 for pre-v2 state files.
    local ask_ms
    ask_ms=$(jq -r '.last_ask_epoch_ms // 0' "${state_file}" 2>/dev/null)
    if [ "${ask_ms}" = "0" ] || [ -z "${ask_ms}" ]; then
        local ask_epoch
        ask_epoch=$(jq -r '.last_ask_epoch // 0' "${state_file}" 2>/dev/null)
        ask_ms=$(( ask_epoch * 1000 ))
    fi

    local now_ms elapsed_ms
    now_ms=$(_hi_epoch_ms)
    elapsed_ms=$(( now_ms - ask_ms ))

    # Machine-speed / authenticity floor — uncrossable regardless of calibration.
    if [ "${elapsed_ms}" -lt "${HI_ABSOLUTE_MIN_RESPONSE_TIME_MS}" ]; then
        _hi_log "H17 VIOLATED: ${human_id} responded in ${elapsed_ms}ms (machine-speed floor: ${HI_ABSOLUTE_MIN_RESPONSE_TIME_MS}ms)"
        echo "suspicious"
        return 1
    fi

    # Resolve the default floor: prefer HI_MIN_RESPONSE_TIME_MS if explicitly set
    # (new ms knob), else derive from HI_MIN_RESPONSE_TIME for backward compat.
    local default_floor_ms
    if [ -n "${HI_MIN_RESPONSE_TIME_MS:-}" ]; then
        default_floor_ms="${HI_MIN_RESPONSE_TIME_MS}"
    else
        default_floor_ms=$(( HI_MIN_RESPONSE_TIME * 1000 ))
    fi

    # Select floor by severity and calibration status.
    local floor_ms="${default_floor_ms}"
    if _hi_is_calibrated "${state_file}"; then
        case "${severity}" in
            critical) floor_ms="${HI_CALIBRATED_CRITICAL_FLOOR_MS}" ;;
            *)        floor_ms="${HI_ABSOLUTE_MIN_RESPONSE_TIME_MS}" ;;
        esac
    fi

    if [ "${elapsed_ms}" -lt "${floor_ms}" ]; then
        _hi_log "H17 VIOLATED: ${human_id} responded in ${elapsed_ms}ms (floor: ${floor_ms}ms, severity: ${severity})"
        echo "suspicious"
        return 1
    fi

    echo "ok"
    return 0
}

# ─── H14: Protected Human Judgment ───────────────────────────────────────────
# Track response time variance. Low variance = rubber-stamping warning.
#
# Replaces approval rate tracking. A well-calibrated gate produces high
# approval rates legitimately — penalizing that creates perverse incentives
# (strategic denials to game the ratio). Response time variance is a better
# proxy: a genuine deliberator's response times vary with request complexity.
# A rubber-stamper responds uniformly regardless of severity.
#
# Call hi_record_decision after each human decision (pass elapsed seconds).
# Call hi_check_response_variance before routing a new decision.
#
# Returns: "ok" or "rubber_stamping"

hi_record_decision() {
    local human_id="${1:?}"
    local decision="${2:?}"        # "approve" or "deny" (kept for audit trail)
    local elapsed_s="${3:-0}"      # response time in seconds
    local severity="${4:-info}"    # severity tier of the decision
    local risk_score="${5:-100}"   # 0-100 risk score; default 100 = 1.0 unit (backward-compat)
    local elapsed_ms_val="${6:-}"  # optional ms-precision elapsed; omitted when unavailable

    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    # decisions_today is a float. Each decision costs max(10, risk_score) / 100 units.
    # risk=100 → 1.0 unit (same as old integer 1). risk=10 → 0.10 unit.
    # Store {elapsed, severity} pairs, plus elapsed_ms when available (H17 v2 tuning).
    # H14 variance computation reads .elapsed (seconds); elapsed_ms is a side-channel.
    jq --argjson elapsed "${elapsed_s}" \
       --arg sev "${severity}" \
       --argjson risk "${risk_score}" \
       --argjson window "${HI_VARIANCE_WINDOW}" \
       --arg ems "${elapsed_ms_val}" \
       'del(._hmac) |
        ([$risk, 10] | max | . / 100) as $cost |
        .decisions_today = ((.decisions_today // 0) + $cost) |
        ({elapsed:$elapsed,severity:$sev} + (if $ems != "" then {elapsed_ms:($ems|tonumber)} else {} end)) as $entry |
        .response_times = (.response_times + [$entry] | .[-$window:])' \
        "${state_file}" 2>/dev/null | _hi_sealed_write "${state_file}"
}

hi_check_response_variance() {
    local human_id="${1:?}"

    local state_file
    state_file=$(_hi_ensure_state "${human_id}")

    # Variance check on non-critical decisions only.
    # Critical decisions are governed by H15 (30s floor) which creates
    # artificial uniformity — including critical in variance would fire H14
    # against exactly the deliberate behavior H15 is designed to produce.
    local stddev
    stddev=$(jq -r --argjson min_sample "${HI_VARIANCE_MIN_SAMPLE}" '
        .response_times as $arr |
        # Use only warn+info tier decisions for variance
        [$arr[] | select(type == "object" and .severity != "critical") | .elapsed] as $filtered |
        if ($filtered | length) < $min_sample then
            -1
        else
            (($filtered | add) / ($filtered | length)) as $mean |
            ([$filtered[] | (. - $mean) * (. - $mean)] | add) / ($filtered | length) |
            sqrt
        end
    ' "${state_file}" 2>/dev/null)

    # Not enough non-critical data yet
    if [ "${stddev}" = "-1" ] || [ -z "${stddev}" ]; then
        echo "ok"
        return 0
    fi

    local is_uniform
    is_uniform=$(awk -v sd="${stddev}" -v floor="${HI_VARIANCE_STDDEV_FLOOR}" \
        'BEGIN { print (sd < floor) ? "yes" : "no" }')

    if [ "${is_uniform}" = "yes" ]; then
        _hi_log "H14 WARNING: ${human_id} warn/info response time std_dev is ${stddev}s (floor: ${HI_VARIANCE_STDDEV_FLOOR}s) — suspiciously uniform on non-critical decisions"
        # Reset response_times so the window starts fresh. Without this, H14 fires
        # on every pre-ask until midnight — no new decisions enter the window so
        # variance never recovers. Advisory semantics mean asks still route, so
        # new decisions accumulate naturally from here.
        jq 'del(._hmac) | .response_times = []' \
           "${state_file}" 2>/dev/null | _hi_sealed_write "${state_file}"
        _hi_log "H14: response_times cleared"
        echo "canary_pattern_check"
        return 1
    fi

    echo "ok"
    return 0
}

# Backward-compatible alias — callers that used hi_check_approval_rate get variance check instead
hi_check_approval_rate() {
    hi_check_response_variance "$@"
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

    # H14: Response time variance
    local rate_result
    rate_result=$(hi_check_response_variance "${human_id}")
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
    local risk_score="${5:-100}"  # passed through to hi_record_decision

    # Decrement pending (by hash if provided, else oldest)
    hi_decrement_pending "${human_id}" "${action_hash}"

    # H17: Authenticity (must come first — if automated, deliberation is meaningless)
    local auth_result
    auth_result=$(hi_check_authenticity "${human_id}" "${severity}")
    if [ "${auth_result}" = "suspicious" ]; then
        echo "suspicious"
        return 1
    fi

    # H15: Deliberation floor
    local delib_result
    delib_result=$(hi_check_deliberation "${human_id}" "${severity}")
    if [ "${delib_result}" = "too_fast" ]; then
        if [ "${severity}" = "critical" ]; then
            echo "too_fast"
            return 1
        fi
        # warn/info: H15 floor violation is signal-only — approval proceeds.
        # H17 (authenticity) already blocked machine-speed responses above;
        # this path is reached only when elapsed >= minResponseTime but < deliberationFloor.
        _hi_log "H15 SIGNAL (${severity}): ${human_id} responded below deliberation floor — logged, not rejected"
    fi

    # Record the decision for H14 variance tracking (elapsed = now - ask_time).
    # Also capture ms-precision elapsed for H17 v2 floor tuning.
    local _state_file _ask_epoch _ask_ms _now_epoch _now_ms _elapsed _elapsed_ms
    _state_file=$(_hi_ensure_state "${human_id}")
    _ask_epoch=$(jq -r '.last_ask_epoch // 0' "${_state_file}" 2>/dev/null || echo 0)
    _ask_ms=$(jq -r '.last_ask_epoch_ms // 0' "${_state_file}" 2>/dev/null || echo 0)
    _now_epoch=$(date +%s)
    _now_ms=$(_hi_epoch_ms)
    _elapsed=$(( _now_epoch - _ask_epoch ))
    if [ "${_ask_ms}" != "0" ] && [ -n "${_ask_ms}" ]; then
        _elapsed_ms=$(( _now_ms - _ask_ms ))
    else
        _elapsed_ms=$(( (_now_epoch - _ask_epoch) * 1000 ))
    fi
    hi_record_decision "${human_id}" "${decision}" "${_elapsed}" "${severity}" "${risk_score}" "${_elapsed_ms}"

    echo "ok"
    return 0
}
