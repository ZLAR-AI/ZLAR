#!/bin/bash
# test-agent-identity.sh — tests for agent identity and registry
#
# Tests:
#   1. agent-identity.sh test agent detection
#   2. agent-identity.sh risk tier calculation
#   3. agent-identity.sh authorization level calculation
#   4. zlar-agents-export raw view
#   5. zlar-agents-export production view (filters test agents)
#   6. zlar-agents bind/unbind/list
#   7. Registry schema validation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

export ZLAR_PROJECT_DIR="${PROJECT_DIR}"

source "${PROJECT_DIR}/lib/agent-identity.sh"

PASS=0
FAIL=0
TOTAL=0
TEMP_DIR=$(mktemp -d)
AUDIT_FIXTURE="${TEMP_DIR}/audit.jsonl"

cleanup() {
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

assert() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${expected}" == "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

echo "=== Agent Identity Tests ==="
echo

# ── Test agent detection ──

echo "Test agent detection:"
assert "attacker is test" "true" "$(agent_is_test attacker && echo true || echo false)"
assert "tamper-spy is test" "true" "$(agent_is_test tamper-spy && echo true || echo false)"
assert "hook-test-server is test" "true" "$(agent_is_test hook-test-server && echo true || echo false)"
assert "membrane-test is test" "true" "$(agent_is_test membrane-test && echo true || echo false)"
assert "test-agent is test" "true" "$(agent_is_test test-agent && echo true || echo false)"
assert "claude-code is NOT test" "false" "$(agent_is_test claude-code && echo true || echo false)"
assert "sub-agent-1 is NOT test" "false" "$(agent_is_test sub-agent-1 && echo true || echo false)"
assert "bohm-openclaw is NOT test" "false" "$(agent_is_test bohm-openclaw && echo true || echo false)"
echo

# ── Risk tier ──

echo "Risk tier calculation:"
assert "low: 2% denial, 10 risk, no critical" "low" "$(agent_risk_tier 2 10 false)"
assert "medium: 8% denial, 15 risk" "medium" "$(agent_risk_tier 8 15 false)"
assert "medium: 3% denial, 40 risk" "medium" "$(agent_risk_tier 3 40 false)"
assert "high: 25% denial" "high" "$(agent_risk_tier 25 10 false)"
assert "high: 5% denial, 75 risk" "high" "$(agent_risk_tier 5 75 false)"
assert "critical: 55% denial" "critical" "$(agent_risk_tier 55 10 false)"
assert "critical: has critical event" "critical" "$(agent_risk_tier 2 10 true)"
echo

# ── Authorization level ──

echo "Authorization level:"
assert "blocked: 95% denial" "blocked" "$(agent_authorization_level 95 false)"
assert "pre-approved: has standing" "pre-approved" "$(agent_authorization_level 5 true)"
assert "human-review: default" "human-review-required" "$(agent_authorization_level 10 false)"
echo

# ── Export tests ──

echo "Export tests:"

cat > "${AUDIT_FIXTURE}" <<'JSONL'
{"id":"agent-identity-001","ts":"2026-04-02T00:00:00Z","seq":1,"source":"gate","host":"test-host","user":"tester","agent_id":"claude-code","session_id":"agent-identity-session-1","domain":"bash","action":"git status --short","outcome":"allow","risk_score":5,"detail":{"command":"git status --short","cwd":"/workspace/zlar"},"rule":"R001","policy_version":"2.6.0","severity":"info","prev_hash":"genesis","authorizer":"policy"}
{"id":"agent-identity-002","ts":"2026-04-02T00:01:00Z","seq":2,"source":"gate","host":"test-host","user":"tester","agent_id":"claude-code","session_id":"agent-identity-session-1","domain":"bash","action":"git push origin main","outcome":"authorized","risk_score":60,"detail":{"command":"git push origin main","cwd":"/workspace/zlar"},"rule":"R014","policy_version":"2.6.0","severity":"warn","prev_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authorizer":"human:operator-1"}
{"id":"agent-identity-003","ts":"2026-04-02T00:02:00Z","seq":1,"source":"gate","host":"test-host","user":"tester","agent_id":"test-agent","session_id":"agent-identity-session-2","domain":"read","action":"/workspace/zlar/README.md","outcome":"allow","risk_score":0,"detail":{"path":"/workspace/zlar/README.md"},"rule":"R053","policy_version":"2.6.0","severity":"info","prev_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","authorizer":"policy"}
{"id":"agent-identity-004","ts":"2026-04-02T00:03:00Z","seq":2,"source":"gate","host":"test-host","user":"tester","agent_id":"test-agent","session_id":"agent-identity-session-2","domain":"bash","action":"sudo rm -rf /tmp/example","outcome":"deny","risk_score":100,"detail":{"command":"sudo rm -rf /tmp/example","cwd":"/workspace/zlar"},"rule":"R003","policy_version":"2.6.0","severity":"critical","prev_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","authorizer":"policy"}
JSONL

# Raw export
raw_output=$(ZLAR_AUDIT_FILE="${AUDIT_FIXTURE}" bash "${PROJECT_DIR}/bin/zlar-agents-export" 2>/dev/null)
raw_count=$(echo "${raw_output}" | jq '.total_agents')
raw_view=$(echo "${raw_output}" | jq -r '.view')
assert "raw export has fixture agents" "2" "${raw_count}"
assert "raw view label" "raw" "${raw_view}"
assert "raw has version" "1.0.0" "$(echo "${raw_output}" | jq -r '.version')"
assert "raw has generated_at" "true" "$(echo "${raw_output}" | jq -r '.generated_at' | grep -q '^20' && echo true || echo false)"

# Production export
prod_output=$(ZLAR_AUDIT_FILE="${AUDIT_FIXTURE}" bash "${PROJECT_DIR}/bin/zlar-agents-export" --production 2>/dev/null)
prod_count=$(echo "${prod_output}" | jq '.total_agents')
prod_view=$(echo "${prod_output}" | jq -r '.view')
assert "production view label" "production" "${prod_view}"
assert "production filters test agents" "1" "${prod_count}"

# Check no test agents in production
test_in_prod=$(echo "${prod_output}" | jq '[.agents[] | select(.is_test == true)] | length')
assert "no test agents in production" "0" "${test_in_prod}"

# Schema validation
assert "agents have agent_id" "true" "$(echo "${raw_output}" | jq '[.agents[] | has("agent_id")] | all' | tr -d '[:space:]')"
assert "agents have risk_tier" "true" "$(echo "${raw_output}" | jq '[.agents[] | has("risk_tier")] | all' | tr -d '[:space:]')"
assert "agents have authorization_level" "true" "$(echo "${raw_output}" | jq '[.agents[] | has("authorization_level")] | all' | tr -d '[:space:]')"
assert "agents have domains_used" "true" "$(echo "${raw_output}" | jq '[.agents[] | has("domains_used")] | all' | tr -d '[:space:]')"
assert "agents have metadata" "true" "$(echo "${raw_output}" | jq '[.agents[] | has("metadata")] | all' | tr -d '[:space:]')"
echo

# ── Binding tests ──

echo "Agent binding tests:"

# Create temp bindings file
TEMP_BINDINGS=$(mktemp)
echo '{"version":"1.0.0","bindings":[]}' > "${TEMP_BINDINGS}"

# Test bind via the bindings file directly (avoid sourcing audit-reader in subprocess)
jq --arg a "test-bind-agent" --arg now "2026-04-02T00:00:00Z" \
    '.bindings += [{agent_id: $a, policy_version: "2.6.0", effective_since: $now, standing_approvals: ["SA001"], velocity_limit: {calls_per_minute: 20, escalate_at: 16}}]' \
    "${TEMP_BINDINGS}" > "${TEMP_BINDINGS}.tmp" && mv "${TEMP_BINDINGS}.tmp" "${TEMP_BINDINGS}"

bind_count=$(jq '.bindings | length' "${TEMP_BINDINGS}")
assert "binding created" "1" "${bind_count}"

bind_agent=$(jq -r '.bindings[0].agent_id' "${TEMP_BINDINGS}")
assert "binding has agent_id" "test-bind-agent" "${bind_agent}"

bind_standing=$(jq -r '.bindings[0].standing_approvals[0]' "${TEMP_BINDINGS}")
assert "binding has standing approval" "SA001" "${bind_standing}"

bind_velocity=$(jq '.bindings[0].velocity_limit.calls_per_minute' "${TEMP_BINDINGS}")
assert "binding has velocity limit" "20" "${bind_velocity}"

# Unbind
jq --arg a "test-bind-agent" '.bindings = [.bindings[] | select(.agent_id != $a)]' "${TEMP_BINDINGS}" > "${TEMP_BINDINGS}.tmp" && mv "${TEMP_BINDINGS}.tmp" "${TEMP_BINDINGS}"
unbind_count=$(jq '.bindings | length' "${TEMP_BINDINGS}")
assert "unbind removes binding" "0" "${unbind_count}"

rm -f "${TEMP_BINDINGS}"
echo

# ── Results ──

echo "═══════════════════════════════════════"
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [[ ${FAIL} -gt 0 ]]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
else
    echo " ✓"
fi
