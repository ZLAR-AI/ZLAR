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
        # Initialize empty state
        cat > "${SESSION_STATE_FILE}" 2>/dev/null <<INITEOF
{"session_id":"${session_id}","started":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","total_calls":0,"calls_by_domain":{},"recent_timestamps":[],"recent_actions":[],"consecutive_denials":0,"escalations":0}
INITEOF
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
