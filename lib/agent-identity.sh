#!/bin/bash
# agent-identity.sh — agent classification and risk tier derivation
#
# Given audit trail facts about an agent, computes risk tier,
# authorization level, and notable patterns.
#
# Design: this library produces CLASSIFICATIONS, not judgments.
# Risk tiers are mechanical — denial_rate × avg_risk × pattern flags.
# The human decides what to do with the classification.
#
# Risk tiers:
#   critical  — denial_rate > 50% OR any critical-severity event
#   high      — denial_rate > 20% OR avg_risk > 70
#   medium    — denial_rate > 5%  OR avg_risk > 30
#   low       — everything else
#
# Authorization levels:
#   pre-approved          — has standing approvals in effect
#   human-review-required — default (gate asks human for risky actions)
#   blocked               — denial_rate > 90% (effectively blocked by policy)
#
# Known test agents (excluded from production view):
#   attacker, tamper-spy, hook-test-server, membrane-test,
#   test-agent, test-orchestrator, agent-a, agent-b, grandchild-1

set -euo pipefail

# ── Test agent detection ──

# Patterns that identify test/simulation agents
# These are agents created by test suites, not real deployments
_TEST_AGENT_PATTERNS="^(attacker|tamper-spy|hook-test-server|membrane-test|test-agent|test-orchestrator|agent-a|agent-b|grandchild-1|my-custom-orchestrator)$"

agent_is_test() {
    local agent_id="${1:?Usage: agent_is_test <agent_id>}"
    [[ "${agent_id}" =~ ${_TEST_AGENT_PATTERNS} ]]
}

# ── Risk tier calculation ──

# Compute risk tier from denial rate and average risk score
# Usage: agent_risk_tier <denial_rate> <avg_risk> <has_critical_event>
# Returns: critical | high | medium | low
agent_risk_tier() {
    local denial_rate="${1:?}"
    local avg_risk="${2:?}"
    local has_critical="${3:-false}"

    if [[ "${has_critical}" == "true" ]] || (( $(echo "${denial_rate} > 50" | bc -l) )); then
        echo "critical"
    elif (( $(echo "${denial_rate} > 20" | bc -l) )) || (( $(echo "${avg_risk} > 70" | bc -l) )); then
        echo "high"
    elif (( $(echo "${denial_rate} > 5" | bc -l) )) || (( $(echo "${avg_risk} > 30" | bc -l) )); then
        echo "medium"
    else
        echo "low"
    fi
}

# Compute authorization level from denial rate and standing approvals
# Usage: agent_authorization_level <denial_rate> <has_standing_approvals>
# Returns: pre-approved | human-review-required | blocked
agent_authorization_level() {
    local denial_rate="${1:?}"
    local has_standing="${2:-false}"

    if (( $(echo "${denial_rate} > 90" | bc -l) )); then
        echo "blocked"
    elif [[ "${has_standing}" == "true" ]]; then
        echo "pre-approved"
    else
        echo "human-review-required"
    fi
}

# ── Pattern detection ──

# Check if an agent has triggered known patterns (from witness layer)
# Returns JSON array of pattern identifiers
# Usage: agent_notable_patterns <events_json>
agent_notable_patterns() {
    local events="${1:?}"
    echo "${events}" | jq -s '
        def has_pattern(p):
            [.[] | select(.rule == p)] | length > 0;

        [
            # Velocity spike: more than 30 events in any 60-second window
            (if ([.[].ts] | sort | . as $ts |
                [range(0; length - 1) | select(
                    (($ts[. + 29] // "9999") < ($ts[.][0:19] + "Z"))
                )] | length > 0)
            then "velocity_spike" else null end),

            # High denial rate
            (if (([.[] | select(.outcome == "deny")] | length) / ([.[] | length] | if . == 0 then 1 else . end) > 0.5)
            then "high_denial_rate" else null end),

            # Human approval heavy: >25% actions needed human sign-off
            (if (([.[] | select(.outcome == "authorized")] | length) / ([.[] | length] | if . == 0 then 1 else . end) > 0.25)
            then "human_approval_heavy" else null end),

            # Sensitive path access attempts
            (if ([.[] | select(
                (.detail.command // "" | test("\\.(env|key|pem|token)"; "i")) or
                (.detail.path // "" | test("\\.(env|key|pem|token)"; "i"))
            )] | length > 0)
            then "sensitive_path_access" else null end)
        ] | map(select(. != null))
    '
}
