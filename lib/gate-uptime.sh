#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Gate Uptime — streak tracking
#
# Makes the cost of turning the gate off visible. The builder's running joke —
# "on-off-on-off through the session for commit/push cycles" — is a signal
# about product-readiness. If you cannot live under your own governance, a
# procurement officer's reasonable next question is why should they. This
# module surfaces the streak so the cost of breaking it is readable at a
# glance.
#
# State: var/gate-uptime.json. HMAC-sealed via etc/keys/gate-uptime-hmac.key.
# Same tamper-detection model as human-invariants (v3.1.3): on mismatch, log
# and rebuild — tampering with the streak should be detectable, not lock the
# gate out of operation.
#
# Hot path: gu_record_heartbeat runs on every gate invocation. To avoid one
# atomic rename per tool call, heartbeat writes batch — state is persisted
# only if the heartbeat is stale (>30s) or a state transition is happening.
#
# Concurrency: this is a single-operator local file. Concurrent gate
# invocations may race; the last writer wins. Worst-case effect on the streak
# is a few seconds of drift, which is below human perception for the display.
# ═══════════════════════════════════════════════════════════════════════════════

# Guard against double-sourcing
[ -n "${_ZLAR_GATE_UPTIME_LOADED:-}" ] && return 0
_ZLAR_GATE_UPTIME_LOADED=1

_GU_PROJECT_DIR="${_GU_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
_GU_STATE_FILE="${_GU_PROJECT_DIR}/var/gate-uptime.json"
_GU_HMAC_KEY_FILE="${_GU_PROJECT_DIR}/etc/keys/gate-uptime-hmac.key"
_GU_HMAC_KEY=""
if [ -f "${_GU_HMAC_KEY_FILE}" ]; then
    _GU_HMAC_KEY=$(cat "${_GU_HMAC_KEY_FILE}" 2>/dev/null || true)
fi

# Retained for test-harness compatibility; no longer gates streak closure.
# The streak now closes only on explicit gu_record_disable — idle time (laptop
# closed, lunch, a long read) is not a disable and must not reset the streak.
# A motivational counter breaks only on an explicit act.
_GU_STALE_THRESHOLD_SECONDS="${_GU_STALE_THRESHOLD_SECONDS:-600}"

# Minimum interval between heartbeat writes. The heartbeat runs per-invocation
# but only persists if this interval has elapsed. Cheap coalescing for the hot
# path.
_GU_HEARTBEAT_BATCH_SECONDS="${_GU_HEARTBEAT_BATCH_SECONDS:-30}"

# ─── HMAC helpers (shared with lib/human-invariants.sh) ──────────────────────
# HMAC mechanics live in lib/state-hmac.sh. Thin wrappers here bind the shared
# helpers to _GU_HMAC_KEY and _GU_STATE_FILE so call sites stay readable.

# Source the shared helper from this file's own directory — not _GU_PROJECT_DIR,
# which tests override to a tmp dir for state isolation.
# shellcheck source=./state-hmac.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/state-hmac.sh"

_gu_verify_hmac()  { _state_hmac_verify       "${_GU_HMAC_KEY}" "${_GU_STATE_FILE}"; }
_gu_sealed_write() { _state_hmac_sealed_write "${_GU_HMAC_KEY}" "${_GU_STATE_FILE}"; }

# ─── State shape ──────────────────────────────────────────────────────────────
# {
#   schema_version: 1,
#   state: "on" | "off",
#   current_streak_start_epoch: N (0 when off),
#   last_heartbeat_epoch: N,
#   last_enable_at_epoch: N (0 if never),
#   last_disable_at_epoch: N (0 if never),
#   longest_streak_seconds: N,
#   longest_streak_start_epoch: N (0 if none yet),
#   lifetime_on_seconds: N,
#   _hmac: "..."
# }

_gu_default_state() {
    jq -n '{
        schema_version: 1,
        state: "off",
        current_streak_start_epoch: 0,
        last_heartbeat_epoch: 0,
        last_enable_at_epoch: 0,
        last_disable_at_epoch: 0,
        longest_streak_seconds: 0,
        longest_streak_start_epoch: 0,
        lifetime_on_seconds: 0
    }'
}

# Read state, verify HMAC. On tamper or missing: rebuild with defaults.
# Emits the state (without _hmac) to stdout.
_gu_load_state() {
    if [ ! -f "${_GU_STATE_FILE}" ]; then
        local s
        s=$(_gu_default_state)
        printf '%s' "${s}" | _gu_sealed_write
        printf '%s' "${s}"
        return 0
    fi

    local verify
    verify=$(_gu_verify_hmac)
    if [ "${verify}" = "tampered" ]; then
        # Tampered — rebuild. Log is best-effort; no separate gate-uptime log
        # channel, so we fall silent here rather than introduce a new log path
        # in a patch release. The rebuild itself is the observable signal.
        local s
        s=$(_gu_default_state)
        printf '%s' "${s}" | _gu_sealed_write
        printf '%s' "${s}"
        return 0
    fi

    jq -c 'del(._hmac)' "${_GU_STATE_FILE}" 2>/dev/null
}

# ─── Public API ───────────────────────────────────────────────────────────────

# Heartbeat: called on every gate invocation while the gate is ON.
# Transitions state off→on if needed; if the previous on-heartbeat is stale
# (>threshold), the old streak is closed and a new one opens. Otherwise the
# streak continues. Batches writes to avoid one rename per tool call.
gu_record_heartbeat() {
    local now
    now=$(date +%s)
    local state_json
    state_json=$(_gu_load_state)

    local state last_hb streak_start longest_sec lifetime_sec
    state=$(printf '%s' "${state_json}" | jq -r '.state')
    last_hb=$(printf '%s' "${state_json}" | jq -r '.last_heartbeat_epoch')
    streak_start=$(printf '%s' "${state_json}" | jq -r '.current_streak_start_epoch')
    longest_sec=$(printf '%s' "${state_json}" | jq -r '.longest_streak_seconds')
    lifetime_sec=$(printf '%s' "${state_json}" | jq -r '.lifetime_on_seconds')

    local transition=0 write=0
    local new_streak_start="${streak_start}"
    local new_longest="${longest_sec}"
    local new_longest_start
    new_longest_start=$(printf '%s' "${state_json}" | jq -r '.longest_streak_start_epoch')
    local new_lifetime="${lifetime_sec}"

    # Transition: off → on. The only path that resets the streak start
    # from a heartbeat. The gate being loaded and firing hooks is the
    # evidence the gate is on; a long idle gap is not evidence of disable.
    if [ "${state}" != "on" ]; then
        transition=1
        write=1
        new_streak_start="${now}"
    fi

    # Batch: if not transitioning, only write if the last heartbeat is older
    # than the batch interval.
    if [ "${transition}" -eq 0 ]; then
        local since_last=$(( now - last_hb ))
        if [ "${since_last}" -ge "${_GU_HEARTBEAT_BATCH_SECONDS}" ]; then
            write=1
        fi
    fi

    [ "${write}" -eq 0 ] && return 0

    printf '%s' "${state_json}" | jq -c \
        --argjson now "${now}" \
        --argjson start "${new_streak_start}" \
        --argjson longest "${new_longest}" \
        --argjson longest_start "${new_longest_start}" \
        --argjson lifetime "${new_lifetime}" \
        --argjson was_transition "${transition}" '
        .state = "on" |
        .last_heartbeat_epoch = $now |
        .current_streak_start_epoch = $start |
        .longest_streak_seconds = $longest |
        .longest_streak_start_epoch = $longest_start |
        .lifetime_on_seconds = $lifetime |
        (if $was_transition == 1 then .last_enable_at_epoch = $now else . end)
    ' | _gu_sealed_write
}

# Explicit enable: called from `zlar on`. Starts a new streak immediately.
gu_record_enable() {
    local now
    now=$(date +%s)
    local state_json
    state_json=$(_gu_load_state)

    # If already on, do not rewrite lifecycle timestamps. `zlar on` is
    # idempotent; it reports the open streak and leaves the state file alone.
    local state
    state=$(printf '%s' "${state_json}" | jq -r '.state')
    if [ "${state}" = "on" ]; then
        return 0
    fi

    printf '%s' "${state_json}" | jq -c \
        --argjson now "${now}" '
        .state = "on" |
        .current_streak_start_epoch = $now |
        .last_heartbeat_epoch = $now |
        .last_enable_at_epoch = $now
    ' | _gu_sealed_write
}

# Explicit disable: called from `zlar off`. Closes the current streak,
# updates longest/lifetime, records last_disable_at.
gu_record_disable() {
    local now
    now=$(date +%s)
    local state_json
    state_json=$(_gu_load_state)

    local state streak_start last_hb longest_sec longest_start lifetime_sec
    state=$(printf '%s' "${state_json}" | jq -r '.state')
    streak_start=$(printf '%s' "${state_json}" | jq -r '.current_streak_start_epoch')
    last_hb=$(printf '%s' "${state_json}" | jq -r '.last_heartbeat_epoch')
    longest_sec=$(printf '%s' "${state_json}" | jq -r '.longest_streak_seconds')
    longest_start=$(printf '%s' "${state_json}" | jq -r '.longest_streak_start_epoch')
    lifetime_sec=$(printf '%s' "${state_json}" | jq -r '.lifetime_on_seconds')

    # If already off, do not mint a fresh disable timestamp. Repeated `zlar off`
    # is a no-op; only an on->off transition closes a streak.
    if [ "${state}" != "on" ]; then
        return 0
    fi

    local new_longest="${longest_sec}"
    local new_longest_start="${longest_start}"
    local new_lifetime="${lifetime_sec}"

    if [ "${streak_start}" -gt 0 ]; then
        # Close at last_hb, not now. Idle time between the last gate invocation
        # and an explicit disable (stepping away, then running `zlar off`) is
        # not active gate use and must not inflate lifetime_on_seconds or
        # longest_streak_seconds. The idle-preserving semantic already prevents
        # idle from resetting the streak; this aligns disable accounting with it.
        #
        # Safety floor: if no heartbeat was recorded in this streak (e.g.
        # gu_record_enable followed immediately by gu_record_disable), fall back
        # to now so the streak gets a non-zero duration.
        local close_at="${last_hb}"
        [ "${close_at}" -le "${streak_start}" ] && close_at="${now}"
        local streak_sec=$(( close_at - streak_start ))
        if [ "${streak_sec}" -gt 0 ]; then
            new_lifetime=$(( lifetime_sec + streak_sec ))
            if [ "${streak_sec}" -gt "${longest_sec}" ]; then
                new_longest="${streak_sec}"
                new_longest_start="${streak_start}"
            fi
        fi
    fi

    printf '%s' "${state_json}" | jq -c \
        --argjson now "${now}" \
        --argjson longest "${new_longest}" \
        --argjson longest_start "${new_longest_start}" \
        --argjson lifetime "${new_lifetime}" '
        .state = "off" |
        .current_streak_start_epoch = 0 |
        .last_disable_at_epoch = $now |
        .longest_streak_seconds = $longest |
        .longest_streak_start_epoch = $longest_start |
        .lifetime_on_seconds = $lifetime
    ' | _gu_sealed_write
}

# Human-readable duration (e.g. "3d 4h 12m", "47m", "< 1m").
gu_format_duration() {
    local seconds="$1"
    [ -z "${seconds}" ] || [ "${seconds}" -lt 0 ] && { echo "—"; return; }
    [ "${seconds}" -lt 60 ] && { echo "< 1m"; return; }

    local days=$(( seconds / 86400 ))
    local hours=$(( (seconds % 86400) / 3600 ))
    local mins=$(( (seconds % 3600) / 60 ))

    if [ "${days}" -gt 0 ]; then
        printf '%dd %dh %dm' "${days}" "${hours}" "${mins}"
    elif [ "${hours}" -gt 0 ]; then
        printf '%dh %dm' "${hours}" "${mins}"
    else
        printf '%dm' "${mins}"
    fi
}

# Human-readable timestamp ("2026-04-16 21:14 UTC" or "—" for 0).
gu_format_epoch() {
    local epoch="$1"
    [ -z "${epoch}" ] || [ "${epoch}" = "0" ] || [ "${epoch}" = "null" ] && { echo "—"; return; }
    date -u -r "${epoch}" '+%Y-%m-%d %H:%M UTC' 2>/dev/null || echo "—"
}

# Emit status lines for `zlar status`. Output is plain text, no color codes.
# Caller adds formatting.
gu_status_lines() {
    local state_json
    state_json=$(_gu_load_state)
    local now
    now=$(date +%s)

    local state streak_start last_hb last_enable last_disable
    local longest_sec longest_start lifetime_sec
    state=$(printf '%s' "${state_json}" | jq -r '.state')
    streak_start=$(printf '%s' "${state_json}" | jq -r '.current_streak_start_epoch')
    last_hb=$(printf '%s' "${state_json}" | jq -r '.last_heartbeat_epoch')
    last_enable=$(printf '%s' "${state_json}" | jq -r '.last_enable_at_epoch')
    last_disable=$(printf '%s' "${state_json}" | jq -r '.last_disable_at_epoch')
    longest_sec=$(printf '%s' "${state_json}" | jq -r '.longest_streak_seconds')
    longest_start=$(printf '%s' "${state_json}" | jq -r '.longest_streak_start_epoch')
    lifetime_sec=$(printf '%s' "${state_json}" | jq -r '.lifetime_on_seconds')

    local current_sec=0
    local current_display="—"
    if [ "${state}" = "on" ] && [ "${streak_start}" -gt 0 ]; then
        current_sec=$(( now - streak_start ))
        current_display=$(gu_format_duration "${current_sec}")
    fi

    # Include the current open streak in lifetime display (not in stored total).
    local display_lifetime=$(( lifetime_sec + current_sec ))

    # v3.3.8: when the open streak has already exceeded the stored longest,
    # show the open streak as longest with a "(current — still running)"
    # annotation. The on-disk longest_streak_seconds is a write-on-disable
    # invariant — it is correct as the longest *completed* streak, but on
    # display the operator wants the live truth. Lifetime already does this
    # at line ~315 (display_lifetime = lifetime_sec + current_sec); apply
    # the same display-only correction to longest. No state mutation.
    local display_longest_sec="${longest_sec}"
    local display_longest_start="${longest_start}"
    local longest_running_annotation=""
    if [ "${state}" = "on" ] && [ "${current_sec}" -gt "${longest_sec}" ]; then
        display_longest_sec="${current_sec}"
        display_longest_start="${streak_start}"
        longest_running_annotation="  (current — still running)"
    fi

    printf '    Current streak since uptime reset:           %s\n' "${current_display}"
    printf '    Streak started:                              %s\n' "$(gu_format_epoch "${streak_start}")"

    local heartbeat_note=""
    if [ "${state}" = "on" ]; then
        if [ "${last_hb}" -gt 0 ]; then
            local heartbeat_age=$(( now - last_hb ))
            if [ "${heartbeat_age}" -gt "${_GU_STALE_THRESHOLD_SECONDS}" ]; then
                heartbeat_note="  (stale: no recent gate call; not an off signal)"
            else
                heartbeat_note="  (healthy)"
            fi
        else
            heartbeat_note="  (uninitialized)"
        fi
    fi
    printf '    Last heartbeat:                              %s%s\n' "$(gu_format_epoch "${last_hb}")" "${heartbeat_note}"

    printf '    Longest streak since reset:                  %s%s\n' "$(gu_format_duration "${display_longest_sec}")" "${longest_running_annotation}"
    if [ "${display_longest_start}" != "0" ] && [ "${display_longest_start}" != "null" ]; then
        printf '    Longest streak since reset started:          %s%s\n' "$(gu_format_epoch "${display_longest_start}")" "${longest_running_annotation}"
    fi
    printf '    Lifetime gate-on time since reset:           %s\n' "$(gu_format_duration "${display_lifetime}")"
    if [ "${state}" = "on" ] && [ "${lifetime_sec}" -eq 0 ] && [ "${current_sec}" -gt 0 ]; then
        printf '    Stored lifetime counter since reset:         0 (reset/uninitialized; current streak counted above)\n'
    elif [ "${lifetime_sec}" -eq 0 ]; then
        printf '    Stored lifetime counter since reset:         0 (uninitialized or reset)\n'
    fi
    if [ "${state}" = "on" ] && [ "${longest_sec}" -eq 0 ] && [ "${current_sec}" -gt 0 ]; then
        printf '    Stored completed-longest counter since reset: 0 (no completed streak recorded since reset)\n'
    fi
    printf '    Last enable:                                 %s\n' "$(gu_format_epoch "${last_enable}")"
    local last_disable_note=""
    if [ "${last_disable}" = "0" ] || [ "${last_disable}" = "null" ]; then
        if [ "${last_enable}" != "0" ] && [ "${last_enable}" != "null" ]; then
            last_disable_note="  (none recorded since uptime state reset)"
        else
            last_disable_note="  (uninitialized)"
        fi
    fi
    printf '    Last disable:                                %s%s\n' "$(gu_format_epoch "${last_disable}")" "${last_disable_note}"
}
