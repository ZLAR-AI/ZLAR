#!/bin/bash
# lib/preconfirm-cc.sh — Tier 2 preconfirm state machine for CC gate (Element E2)
#
# check_preconfirm(action_hash) — 4-state file probe:
#   0 = proceed_acked (human tapped PROCEED)
#   1 = blocked (human tapped BLOCK, or timeout — hard deny, not re-send)
#   2 = not sent yet (no pending file) — caller should send preconfirm card
#   3 = still waiting (pending file exists, no callback yet)
#
# telegram_preconfirm_async(action_hash, rule, severity, short_display)
#   Sends Tier 2 interrupt card and writes pc pending file.
#   Returns: 0 = sent, 1 = send failed, 2 = no token, 3 = rate limited
#
# Assumed in scope from bin/zlar-gate:
#   APPROVAL_DIR, TELEGRAM_TOKEN, RATE_LIMIT_FILE, TELEGRAM_FLOOD_GUARD_MS,
#   TELEGRAM_CHAT_ID, SESSION_ID, PROJECT_DIR, TELEGRAM_TIMEOUT_S,
#   ZLAR_INBOX_HMAC_SECRET (optional)
#   Functions: gen_id, log, zlar_hmac_verify, telegram_api, _mdv2e

_pc_pending_file() {
    echo "${APPROVAL_DIR}/pc-${1}-${SESSION_ID}-${2:0:16}.pending"
}

_pc_blocked_file() {
    echo "${APPROVAL_DIR}/pc-${1}-${SESSION_ID}-${2:0:16}.blocked"
}

_pc_acked_file() {
    echo "${APPROVAL_DIR}/pc-${1}-${SESSION_ID}-${2:0:16}.acked"
}

# _pc_tombstone_active file_path — returns 0 if tombstone exists and is within TTL.
# Cleans up expired tombstones. Uses ZLAR_APPROVED_TTL_S (default 300s).
_pc_tombstone_active() {
    local f="$1"
    [ -f "${f}" ] || return 1
    local age
    age=$(( $(date +%s) - $(stat -c %Y "${f}" 2>/dev/null || stat -f %m "${f}" 2>/dev/null || echo 0) ))
    if [ "${age}" -lt "${ZLAR_APPROVED_TTL_S:-300}" ]; then
        return 0  # still within TTL
    fi
    rm -f "${f}"  # expired — clean up
    return 1
}

check_preconfirm() {
    local rule="$1" action_hash="$2"
    local pending_file blocked_file acked_file
    pending_file=$(_pc_pending_file "${rule}" "${action_hash}")
    blocked_file=$(_pc_blocked_file "${rule}" "${action_hash}")
    acked_file=$(_pc_acked_file "${rule}" "${action_hash}")

    # Blocked tombstone: BLOCK or timeout already occurred this session within TTL.
    if _pc_tombstone_active "${blocked_file}"; then
        log "Tier 2 preconfirm BLOCKED (tombstone active, action=${action_hash:0:16})"
        return 1
    fi

    # Acked tombstone: PROCEED already given this session within TTL.
    # Guards against re-sending preconfirm if main ask send fails.
    if _pc_tombstone_active "${acked_file}"; then
        log "Tier 2 preconfirm ACKED (tombstone active, action=${action_hash:0:16})"
        return 0
    fi

    [ -f "${pending_file}" ] || return 2  # state 2: not sent yet

    local pc_action_id
    pc_action_id=$(sed -n '1p' "${pending_file}" 2>/dev/null | tr -d '[:space:]')
    if [ -z "${pc_action_id}" ]; then
        rm -f "${pending_file}"
        return 2  # corrupt pending file — re-send
    fi

    # Verify action hash stored in pending file matches caller.
    # Filename includes hash prefix, but pending file line 2 carries the full hash.
    local pending_action_hash
    pending_action_hash=$(sed -n '2p' "${pending_file}" 2>/dev/null | tr -d '[:space:]')
    if [ -n "${action_hash}" ] && [ -n "${pending_action_hash}" ] && \
       [ "${action_hash}" != "${pending_action_hash}" ]; then
        log "SECURITY: preconfirm action hash mismatch (file=${pending_action_hash:0:16}, caller=${action_hash:0:16}) — forcing re-send"
        rm -f "${pending_file}"
        return 2
    fi

    local inbox_dir="${ZLAR_INBOX_CC_DIR:-/var/run/zlar-tg/inbox/cc}"
    local consumed_file="${PROJECT_DIR}/var/log/.consumed-callbacks"
    touch "${consumed_file}" 2>/dev/null || true

    for cb_file in "${inbox_dir}"/*.json; do
        [ -f "${cb_file}" ] || continue
        local cb_basename
        cb_basename=$(basename "${cb_file}")
        if grep -qxF "${cb_basename}" "${consumed_file}" 2>/dev/null; then
            continue
        fi

        local cb_data cb_from cb_id_field cb_hmac
        cb_data=$(jq -r '.data // ""' "${cb_file}" 2>/dev/null)
        cb_from=$(jq -r '.from_id // ""' "${cb_file}" 2>/dev/null)
        cb_id_field=$(jq -r '.callback_query_id // ""' "${cb_file}" 2>/dev/null)
        cb_hmac=$(jq -r '.hmac // ""' "${cb_file}" 2>/dev/null)

        if [ "${cb_from}" != "${TELEGRAM_CHAT_ID}" ]; then
            echo "${cb_basename}" >> "${consumed_file}" 2>/dev/null || true
            continue
        fi

        if [ -n "${ZLAR_INBOX_HMAC_SECRET:-}" ]; then
            if ! zlar_hmac_verify "${cb_data}" "${cb_from}" "${cb_id_field}" "${cb_hmac}"; then
                log "SECURITY: preconfirm inbox HMAC mismatch: ${cb_file}"
                echo "${cb_basename}" >> "${consumed_file}" 2>/dev/null || true
                continue
            fi
        fi

        if [ "${cb_data}" = "cc:pc_proceed:${pc_action_id}" ]; then
            echo "${cb_basename}" >> "${consumed_file}" 2>/dev/null || true
            touch "${acked_file}" 2>/dev/null || true
            rm -f "${pending_file}"
            log "Tier 2 preconfirm PROCEED (action=${action_hash:0:16})"
            return 0
        elif [ "${cb_data}" = "cc:pc_block:${pc_action_id}" ]; then
            echo "${cb_basename}" >> "${consumed_file}" 2>/dev/null || true
            touch "${blocked_file}" 2>/dev/null || true
            rm -f "${pending_file}"
            log "Tier 2 preconfirm BLOCK (action=${action_hash:0:16})"
            return 1
        fi
    done

    # Timeout = hard deny (differs from main ask which returns 2 to re-send).
    # Write blocked tombstone so retries within TTL don't resend the preconfirm card.
    local pending_age
    pending_age=$(( $(date +%s) - $(stat -c %Y "${pending_file}" 2>/dev/null || stat -f %m "${pending_file}" 2>/dev/null || echo 0) ))
    if [ "${pending_age}" -gt "${TELEGRAM_TIMEOUT_S}" ]; then
        log "Tier 2 preconfirm EXPIRED (age=${pending_age}s)"
        touch "${blocked_file}" 2>/dev/null || true
        rm -f "${pending_file}"
        return 1  # expired = hard deny, not re-send
    fi

    return 3  # state 3: still waiting
}

telegram_preconfirm_async() {
    local action_hash="$1" rule="$2" severity="$3" short_display="$4"

    if [ -z "${TELEGRAM_TOKEN:-}" ]; then
        log "No Telegram token — cannot send preconfirm"
        return 2
    fi

    local now_ms
    now_ms=$(date +%s%N 2>/dev/null | cut -c1-13 || echo "$(($(date +%s) * 1000))")
    if [ -f "${RATE_LIMIT_FILE}" ]; then
        local last_ms
        last_ms=$(cat "${RATE_LIMIT_FILE}" 2>/dev/null | tr -d '[:space:]')
        last_ms=${last_ms:-0}
        local elapsed_ms=$((now_ms - last_ms))
        if [ "${elapsed_ms}" -lt "${TELEGRAM_FLOOD_GUARD_MS}" ]; then
            log "RATE LIMITED: preconfirm suppressed (${elapsed_ms}ms)"
            return 3
        fi
    fi
    echo "${now_ms}" > "${RATE_LIMIT_FILE}" 2>/dev/null || true

    local pc_action_id
    pc_action_id=$(gen_id)

    local emoji="⚡"
    [ "${severity}" = "critical" ] && emoji="🔴"
    [ "${severity}" = "warn" ] && emoji="🟡"

    local escaped_rule escaped_display
    escaped_rule=$(_mdv2e "${rule}")
    escaped_display=$(_mdv2e "${short_display}")

    local text
    text="${emoji} 🚨 *Tier 2 preconfirm required*

This session has a repeated quick\-approval pattern\. A second flag was recorded\.

Rule: *${escaped_rule}*
Action: ${escaped_display}

Tap PROCEED to see the full ask card, or BLOCK to halt this action immediately\."

    local keyboard
    keyboard=$(jq -n -c \
        --arg proceed "cc:pc_proceed:${pc_action_id}" \
        --arg block "cc:pc_block:${pc_action_id}" \
        '{inline_keyboard: [[
            {text: "✅ PROCEED", callback_data: $proceed},
            {text: "🚫 BLOCK", callback_data: $block}
        ]]}')

    local send_body
    send_body=$(jq -n -c \
        --arg chat_id "${TELEGRAM_CHAT_ID}" \
        --arg text "${text}" \
        --argjson reply_markup "${keyboard}" \
        '{chat_id: $chat_id, text: $text, parse_mode: "MarkdownV2", reply_markup: $reply_markup}')

    local send_result
    send_result=$(telegram_api "sendMessage" "${send_body}" 2>/dev/null)

    local msg_id
    msg_id=$(echo "${send_result}" | jq -r '.result.message_id // empty' 2>/dev/null)
    if [ -z "${msg_id}" ]; then
        log "Failed to send preconfirm card: ${send_result}"
        return 1
    fi

    # Write pending file only after successful send (mirrors telegram_ask_async)
    local pending_file
    pending_file=$(_pc_pending_file "${rule}" "${action_hash}")
    printf '%s\n%s\n' "${pc_action_id}" "${action_hash}" > "${pending_file}" 2>/dev/null

    log "Tier 2 preconfirm sent (msg_id=${msg_id}, pc_id=${pc_action_id})"
    return 0
}
