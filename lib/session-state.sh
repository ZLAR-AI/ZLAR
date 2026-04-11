#!/bin/bash
# session-state.sh — thin stateful layer for session-scoped governance
#
# The gate is stateless by design. Each tool call is evaluated independently.
# But some governance failures are only visible across multiple calls:
#   - The "$1.6M Weekend": 1,000 identical requests each pass policy individually
#   - Runaway loops: agent retrying the same action faster than human can deny
#   - Denial bursts: rapid consecutive denials signal something adversarial
#
# This library adds session-indexed counters. Not a database. Not a reasoning
# layer. A thin cache that the gate consults alongside policy.
#
# Design principle: the counters inform the gate's decision. They don't
# override policy. If policy says "allow" but velocity is anomalous,
# the gate escalates to "ask" — the human decides. The counter doesn't.

# ── Configuration ──

SESSION_STATE_DIR="${ZLAR_SESSION_STATE_DIR:-${PROJECT_DIR}/var/sessions}"
SESSION_STATE_FILE=""

# Thresholds (overridable via gate.json)
VELOCITY_WINDOW_S="${ZLAR_VELOCITY_WINDOW:-60}"        # Window for velocity calculation
VELOCITY_THRESHOLD="${ZLAR_VELOCITY_THRESHOLD:-30}"     # Max calls per window before escalation
LOOP_THRESHOLD="${ZLAR_LOOP_THRESHOLD:-5}"              # Same action N times = potential loop
DENIAL_BURST_THRESHOLD="${ZLAR_DENIAL_BURST:-3}"        # N consecutive denials = alert

# ── Initialization ──

session_state_init() {
    local session_id="${1:?Usage: session_state_init <session_id>}"
    mkdir -p "${SESSION_STATE_DIR}" 2>/dev/null || true
    SESSION_STATE_FILE="${SESSION_STATE_DIR}/${session_id}.state.json"

    if [ ! -f "${SESSION_STATE_FILE}" ]; then
        # Path B: Check if audit trail has events for this session.
        # If so, this is a resumed/recovered session — rebuild state
        # from the signed audit trail rather than starting from zero.
        if [ -f "${SESSION_AUDIT_FILE}" ] && \
           grep -q "\"session_id\":\"${session_id}\"" "${SESSION_AUDIT_FILE}" 2>/dev/null; then
            if session_state_rebuild "${session_id}"; then
                return 0
            fi
        fi
        # Fresh session — initialize empty state
        cat > "${SESSION_STATE_FILE}" 2>/dev/null <<INITEOF
{"session_id":"${session_id}","started":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","total_calls":0,"calls_by_domain":{},"recent_timestamps":[],"recent_actions":[],"consecutive_denials":0,"escalations":0,"_last_audit_id":""}
INITEOF
    else
        # Path B: Existing state file — verify seal against audit trail.
        # If stale (events occurred after last seal), rebuild to recover.
        # Without this, a crash between emit_event and seal leaves the
        # state file silently behind the audit trail.
        if ! session_state_verify "${session_id}" 2>/dev/null; then
            session_state_rebuild "${session_id}" 2>/dev/null || true
        fi
    fi
}

# ── State Readers ──

# Get current state as JSON
_read_state() {
    if [ -f "${SESSION_STATE_FILE}" ]; then
        cat "${SESSION_STATE_FILE}"
    else
        echo '{}'
    fi
}

# ── State Update ──
# Called on every tool call. Returns escalation signals as exit code:
#   0 = normal
#   1 = velocity exceeded (too many calls per window)
#   2 = loop detected (same action repeated)
#   3 = denial burst (consecutive denials)

session_state_update() {
    local domain="${1:?}"
    local action="${2:?}"
    local outcome="${3:?}"
    local ts="${4:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

    [ -f "${SESSION_STATE_FILE}" ] || return 0

    local state
    state=$(_read_state)

    local epoch_now
    epoch_now=$(date +%s)
    local window_start=$((epoch_now - VELOCITY_WINDOW_S))

    # Update state atomically via jq
    local new_state
    new_state=$(echo "${state}" | jq -c \
        --arg domain "${domain}" \
        --arg action "${action}" \
        --arg outcome "${outcome}" \
        --arg ts "${ts}" \
        --argjson epoch_now "${epoch_now}" \
        --argjson window_start "${window_start}" \
        --argjson velocity_threshold "${VELOCITY_THRESHOLD}" \
        --argjson loop_threshold "${LOOP_THRESHOLD}" \
        --argjson denial_burst "${DENIAL_BURST_THRESHOLD}" \
        '
        # Increment total calls
        .total_calls += 1 |

        # Increment domain counter
        .calls_by_domain[$domain] = ((.calls_by_domain[$domain] // 0) + 1) |

        # Add timestamp to recent list (keep last 60)
        .recent_timestamps = (.recent_timestamps + [$epoch_now] | .[-60:]) |

        # Add action to recent list (keep last 20)
        .recent_actions = (.recent_actions + [$action] | .[-20:]) |

        # Count calls in velocity window
        .velocity = ([.recent_timestamps[] | select(. >= $window_start)] | length) |

        # Count consecutive same actions (loop detection)
        .loop_count = (
            .recent_actions | reverse |
            if length == 0 then 0
            else
                . as $arr | $arr[0] as $first |
                [range(length) | select($arr[.] == $first)] |
                if length == 0 then 0
                else
                    # Count from start until different
                    [limit(20; range(($arr | length))) | select($arr[.] == $first)] | length
                end
            end
        ) |

        # Track consecutive denials
        (if $outcome == "deny" or $outcome == "denied" then
            .consecutive_denials += 1
        else
            .consecutive_denials = 0
        end) |

        # Set escalation flags
        .velocity_exceeded = (.velocity >= $velocity_threshold) |
        .loop_detected = (.loop_count >= $loop_threshold) |
        .denial_burst = (.consecutive_denials >= $denial_burst) |

        .last_updated = $ts
    ' 2>/dev/null)

    if [ -z "${new_state}" ]; then
        return 0
    fi

    echo "${new_state}" > "${SESSION_STATE_FILE}" 2>/dev/null || true

    # Return escalation signal
    local velocity_exceeded loop_detected denial_burst
    velocity_exceeded=$(echo "${new_state}" | jq -r '.velocity_exceeded')
    loop_detected=$(echo "${new_state}" | jq -r '.loop_detected')
    denial_burst=$(echo "${new_state}" | jq -r '.denial_burst')

    if [ "${denial_burst}" = "true" ]; then
        return 3
    elif [ "${loop_detected}" = "true" ]; then
        return 2
    elif [ "${velocity_exceeded}" = "true" ]; then
        return 1
    fi

    return 0
}

# ── Escalation Check ──
# Called by the gate after policy evaluation. If policy says "allow" but
# session state is anomalous, escalate to "ask".
#
# Returns the (possibly escalated) action.

session_check_escalation() {
    local policy_action="${1:?}"
    local domain="${2:?}"
    local action="${3:?}"
    local outcome="${4:-allow}"

    # Only escalate "allow" decisions. Don't downgrade "deny" or "ask".
    if [ "${policy_action}" != "allow" ]; then
        echo "${policy_action}"
        return
    fi

    local escalation_result=0
    session_state_update "${domain}" "${action}" "${outcome}" || escalation_result=$?

    case ${escalation_result} in
        1)
            log "SESSION: Velocity exceeded (${VELOCITY_THRESHOLD} calls in ${VELOCITY_WINDOW_S}s) — escalating to ask"
            echo "ask"
            ;;
        2)
            log "SESSION: Loop detected (same action ${LOOP_THRESHOLD}+ times) — escalating to ask"
            echo "ask"
            ;;
        3)
            log "SESSION: Denial burst (${DENIAL_BURST_THRESHOLD}+ consecutive denials) — escalating to ask"
            echo "ask"
            ;;
        *)
            echo "${policy_action}"
            ;;
    esac
}

# ── Budget Check (Build B: Position Limits) ──
# Aggregate action budgets — individual actions pass policy, but the aggregate
# can trigger escalation. Same pattern as trading position limits.
#
# Reads budgets from agent-policy-bindings.json for the current agent.
# Budget counters persist in the session state file under .budgets_used.
#
# Returns: "allow" if within budget, "ask" if budget exceeded
#
# Usage: budget_check <rule_id> <agent_id> <bindings_json>

budget_check() {
    local rule_id="${1:?}"
    local agent_id="${2:?}"
    local bindings_json="${3:-}"

    # No bindings → no budgets → allow
    [ -z "${bindings_json}" ] && echo "allow" && return
    [ "${bindings_json}" = "[]" ] && echo "allow" && return

    # Look up this agent's budgets
    local budget_json
    budget_json=$(echo "${bindings_json}" | jq -c --arg a "${agent_id}" --arg r "${rule_id}" \
        '[.[] | select(.agent_id == $a) | .budgets // [] | .[] | select(.rule == $r)] | .[0] // null' 2>/dev/null)

    # No budget for this rule → allow
    [ -z "${budget_json}" ] || [ "${budget_json}" = "null" ] && echo "allow" && return

    local max_count window_field
    # Check max_per_day first, then max_per_hour
    max_count=$(echo "${budget_json}" | jq -r '.max_per_day // null' 2>/dev/null)
    if [ -n "${max_count}" ] && [ "${max_count}" != "null" ]; then
        window_field="day"
    else
        max_count=$(echo "${budget_json}" | jq -r '.max_per_hour // null' 2>/dev/null)
        if [ -n "${max_count}" ] && [ "${max_count}" != "null" ]; then
            window_field="hour"
        else
            echo "allow" && return
        fi
    fi

    local on_exceed
    on_exceed=$(echo "${budget_json}" | jq -r '.on_exceed // "ask"' 2>/dev/null)

    # Count how many times this rule has fired in the window
    # Budget counters are per-AGENT, not per-session — stored in a shared
    # budget file so they survive session restarts. This is the trading
    # position limit pattern: the position is on the desk, not the trader.
    local budget_dir="${SESSION_STATE_DIR}/budgets"
    mkdir -p "${budget_dir}" 2>/dev/null || true
    local budget_file="${budget_dir}/${agent_id}.budget.json"
    if [ ! -f "${budget_file}" ]; then
        echo '{"agent_id":"'"${agent_id}"'","budgets_used":{}}' > "${budget_file}" 2>/dev/null || true
    fi

    local current_window current_count
    if [ "${window_field}" = "day" ]; then
        current_window=$(date -u +%Y-%m-%d)
    else
        current_window=$(date -u +%Y-%m-%dT%H)
    fi

    current_count=$(jq -r --arg r "${rule_id}" --arg w "${current_window}" \
        '.budgets_used[$r + ":" + $w] // 0' "${budget_file}" 2>/dev/null || echo 0)

    if [ "${current_count}" -ge "${max_count}" ]; then
        echo "${on_exceed}"
        return
    fi

    # Increment counter (only when action will be allowed — don't burn budget on denials)
    jq --arg r "${rule_id}" --arg w "${current_window}" \
        '.budgets_used = (.budgets_used // {}) | .budgets_used[$r + ":" + $w] = ((.budgets_used[$r + ":" + $w] // 0) + 1)' \
        "${budget_file}" > "${budget_file}.tmp" 2>/dev/null && \
        mv "${budget_file}.tmp" "${budget_file}" 2>/dev/null || true

    echo "allow"
}

# ── Session Summary ──
# Returns a human-readable summary of session state

session_state_summary() {
    [ -f "${SESSION_STATE_FILE}" ] || { echo "No session state"; return; }

    local state
    state=$(_read_state)

    echo "${state}" | jq -r '
        "Session: \(.session_id // "unknown")",
        "  started:     \(.started // "unknown")",
        "  total calls: \(.total_calls // 0)",
        "  velocity:    \(.velocity // 0) calls/\(env.VELOCITY_WINDOW_S // "60")s",
        "  domains:     \(.calls_by_domain | to_entries | map("\(.key)=\(.value)") | join(", "))",
        "  denials:     \(.consecutive_denials // 0) consecutive",
        "  loop count:  \(.loop_count // 0)",
        "  escalations: \(.escalations // 0)"
    '
}

# ── Path B Phase 1: Sealed State + Rebuild from Audit Trail ──────────────
#
# The gate's session state is a performance cache, not source of truth.
# These functions make that explicit: state is DERIVED from the signed
# audit trail and can be rebuilt at any time.
#
# Seal: each state file records _last_audit_id — the ID of the most
# recent audit event when the state was last updated. Verify compares
# this with the actual last event for the session. Mismatch → rebuild.
#
# Rebuild: reconstructs total_calls, calls_by_domain, recent_actions,
# consecutive_denials, and loop_count from seq=1 audit events.
# recent_timestamps is left empty (ISO→epoch requires date(1) per
# event; velocity reactivates naturally after one tool call).
#
# Phase 1 scope: sealed state + rebuild. Phase 2: eliminate pending
# approval files. Phase 3: derive all per-session state from audit.
# Phase 4: cross-session human-state (deferred).

SESSION_AUDIT_FILE="${PROJECT_DIR}/var/log/audit.jsonl"

# ── Seal ──

# Write audit event ID seal to state file.
# Called by the gate after emit_event, at end of main().
_session_state_seal() {
    local audit_id="${1:?Usage: _session_state_seal <audit_event_id>}"
    [ -f "${SESSION_STATE_FILE}" ] || return 0

    local sealed
    sealed=$(jq -c --arg id "${audit_id}" '._last_audit_id = $id' "${SESSION_STATE_FILE}" 2>/dev/null)
    if [ -n "${sealed}" ] && [ "${sealed}" != "null" ]; then
        echo "${sealed}" > "${SESSION_STATE_FILE}" 2>/dev/null
    fi
}

# ── Verify ──

# Check if state file is consistent with the audit trail.
# Compares _last_audit_id in state with the actual last audit event
# for this session. Mismatch means events occurred that state doesn't
# reflect (crash, manual audit append, etc.).
#
# Returns: 0 = consistent, 1 = stale/unverifiable
session_state_verify() {
    local session_id="${1:?Usage: session_state_verify <session_id>}"
    [ -f "${SESSION_STATE_FILE}" ] || return 1
    [ -f "${SESSION_AUDIT_FILE}" ] || return 1

    local sealed_id
    sealed_id=$(jq -r '._last_audit_id // ""' "${SESSION_STATE_FILE}" 2>/dev/null)
    [ -z "${sealed_id}" ] && return 1  # No seal → pre-Phase-B state file

    local last_audit_id
    last_audit_id=$(grep "\"session_id\":\"${session_id}\"" "${SESSION_AUDIT_FILE}" 2>/dev/null | \
        tail -1 | jq -r '.id // ""' 2>/dev/null)

    if [ "${sealed_id}" = "${last_audit_id}" ]; then
        return 0
    fi

    log "SESSION STATE: Seal stale (sealed=${sealed_id}, last_audit=${last_audit_id})"
    return 1
}

# ── Rebuild ──

# Reconstruct session state from the audit trail.
# Reads all seq=1 events for the session, computes counters and
# heuristic inputs, writes state file with seal.
#
# recent_timestamps left empty — velocity detection reactivates after
# one tool call (session_state_update populates it with current epoch).
#
# The filter includes all seq=1 events, not just state-update-causing
# ones. This slightly overcounts (includes policy-ask, risk-0 allows)
# but the error is bounded and harmless for heuristic counters.
#
# Returns: 0 = rebuilt, 1 = nothing to rebuild from
session_state_rebuild() {
    local session_id="${1:?Usage: session_state_rebuild <session_id>}"
    [ -f "${SESSION_AUDIT_FILE}" ] || return 1

    log "SESSION STATE: Rebuilding from audit for ${session_id}"

    # Single grep pass — used for both event extraction and seal
    local all_session_events
    all_session_events=$(grep "\"session_id\":\"${session_id}\"" "${SESSION_AUDIT_FILE}" 2>/dev/null)

    [ -z "${all_session_events}" ] && return 1

    local events_json
    events_json=$(echo "${all_session_events}" | \
        jq -sc '[.[] | select(.seq == 1)]' 2>/dev/null)

    local event_count
    event_count=$(echo "${events_json}" | jq 'length' 2>/dev/null || echo 0)

    if [ "${event_count}" -eq 0 ] 2>/dev/null; then
        return 1
    fi

    # Last event ID for seal (any seq — marks audit position)
    local last_id
    last_id=$(echo "${all_session_events}" | tail -1 | jq -r '.id // ""' 2>/dev/null)

    local new_state
    new_state=$(echo "${events_json}" | jq -c \
        --arg sid "${session_id}" \
        --arg last_id "${last_id}" \
        --argjson loop_t "${LOOP_THRESHOLD}" \
        --argjson burst_t "${DENIAL_BURST_THRESHOLD}" \
        '
        # Consecutive denials from tail
        (reduce (reverse | .[]) as $e (
            {count: 0, stopped: false};
            if .stopped then .
            elif ($e.outcome == "deny" or $e.outcome == "denied") then
                {count: (.count + 1), stopped: false}
            else {count: .count, stopped: true} end
        ) | .count) as $denials |

        # Loop count: how many of last 20 actions match the most recent
        ([.[-20:][] | .action] |
            if length == 0 then 0
            else . as $arr | $arr[length - 1] as $last |
                [$arr[] | select(. == $last)] | length
            end
        ) as $loops |

        {
            session_id: $sid,
            started: (.[0].ts // "unknown"),
            total_calls: length,
            calls_by_domain: (
                group_by(.domain) |
                map({key: .[0].domain, value: length}) |
                from_entries
            ),
            recent_timestamps: [],
            recent_actions: [.[-20:][] | .action],
            consecutive_denials: $denials,
            escalations: 0,
            velocity: 0,
            loop_count: $loops,
            velocity_exceeded: false,
            loop_detected: ($loops >= $loop_t),
            denial_burst: ($denials >= $burst_t),
            last_updated: (.[-1].ts // "unknown"),
            _last_audit_id: $last_id
        }
    ' 2>/dev/null)

    if [ -z "${new_state}" ] || [ "${new_state}" = "null" ]; then
        log "SESSION STATE: Rebuild jq failed"
        return 1
    fi

    echo "${new_state}" > "${SESSION_STATE_FILE}" 2>/dev/null || return 1
    log "SESSION STATE: Rebuilt (${event_count} events, sealed=${last_id})"
    return 0
}
