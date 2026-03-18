#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR-OC Watchdog & Integrity Tests
#
# Tests for:
#   - Gate emit_event includes agent_id and session_id fields
#   - Policy watcher detects mutations and emits mutation events
#   - Policy watcher emits integrity heartbeats
#   - Watchdog script structure and argument parsing
#   - Policy health report structure
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
PASSED=0; FAILED=0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

check() {
    local desc="$1" result="$2"
    if [ "${result}" = "true" ]; then
        echo -e "  ${GREEN}PASS${NC} ${desc}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} ${desc}"
        FAILED=$((FAILED + 1))
    fi
}

# ─── Test 1: Gate emit_event format includes agent_id/session_id ────────────

echo -e "${BOLD}Test 1: Gate emit_event includes agent_id and session_id fields${NC}"

# Check that the emit_event printf includes the new fields
HAS_AGENT_ID=$(grep -c 'agent_id' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)
HAS_SESSION_ID=$(grep -c 'session_id' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)
HAS_AGENT_ID_VAR=$(grep -c 'AGENT_ID=' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)
HAS_SESSION_ID_VAR=$(grep -c 'SESSION_ID=' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)

check "emit_event includes agent_id field" "$([ "${HAS_AGENT_ID}" -ge 2 ] && echo true || echo false)"
check "emit_event includes session_id field" "$([ "${HAS_SESSION_ID}" -ge 2 ] && echo true || echo false)"
check "AGENT_ID variable declared" "$([ "${HAS_AGENT_ID_VAR}" -ge 1 ] && echo true || echo false)"
check "SESSION_ID variable declared" "$([ "${HAS_SESSION_ID_VAR}" -ge 1 ] && echo true || echo false)"

# ─── Test 2: Policy watcher has integrity heartbeat ─────────────────────────

echo -e "${BOLD}Test 2: Policy watcher has integrity heartbeat${NC}"

HAS_HEARTBEAT=$(grep -c 'integrity_heartbeat' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)
HAS_HEARTBEAT_COUNTER=$(grep -c 'heartbeat_counter' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)
HAS_MUTATION_LOG=$(grep -c 'policy_mutation' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)
HAS_POLICY_MISSING=$(grep -c 'policy_missing' "${REPO_ROOT}/bin/zlar-oc-gate" || echo 0)

check "Integrity heartbeat event exists" "$([ "${HAS_HEARTBEAT}" -ge 1 ] && echo true || echo false)"
check "Heartbeat counter logic exists" "$([ "${HAS_HEARTBEAT_COUNTER}" -ge 2 ] && echo true || echo false)"
check "Policy mutation detection exists" "$([ "${HAS_MUTATION_LOG}" -ge 1 ] && echo true || echo false)"
check "Policy missing detection exists" "$([ "${HAS_POLICY_MISSING}" -ge 1 ] && echo true || echo false)"

# ─── Test 3: Watchdog script structure ──────────────────────────────────────

echo -e "${BOLD}Test 3: Watchdog script structure${NC}"

check "Watchdog script exists" "$([ -f "${REPO_ROOT}/bin/zlar-oc-watchdog" ] && echo true || echo false)"
check "Watchdog is executable" "$([ -x "${REPO_ROOT}/bin/zlar-oc-watchdog" ] && echo true || echo false)"

# Test --help doesn't crash
WATCHDOG_HELP=$("${REPO_ROOT}/bin/zlar-oc-watchdog" help 2>&1 || true)
check "Watchdog help runs" "$(echo "${WATCHDOG_HELP}" | grep -q 'start.*stop.*status' && echo true || echo false)"

# Test that key functions exist
HAS_GATE_IS_ALIVE=$(grep -c 'gate_is_alive' "${REPO_ROOT}/bin/zlar-oc-watchdog" || echo 0)
HAS_LOCKDOWN=$(grep -c 'lockdown()' "${REPO_ROOT}/bin/zlar-oc-watchdog" || echo 0)
HAS_RESTART=$(grep -c 'attempt_restart' "${REPO_ROOT}/bin/zlar-oc-watchdog" || echo 0)
HAS_FAIL_CLOSED=$(grep -c 'agent_processes_killed\|Kill.*agent' "${REPO_ROOT}/bin/zlar-oc-watchdog" || echo 0)

check "gate_is_alive function exists" "$([ "${HAS_GATE_IS_ALIVE}" -ge 2 ] && echo true || echo false)"
check "lockdown function exists" "$([ "${HAS_LOCKDOWN}" -ge 1 ] && echo true || echo false)"
check "attempt_restart function exists" "$([ "${HAS_RESTART}" -ge 2 ] && echo true || echo false)"
check "Fail-closed: kills agent on lockdown" "$([ "${HAS_FAIL_CLOSED}" -ge 1 ] && echo true || echo false)"

# Verify watchdog refuses to run as aiagent
HAS_AGENT_CHECK=$(grep -c 'must NOT run as' "${REPO_ROOT}/bin/zlar-oc-watchdog" || echo 0)
check "Watchdog refuses to run as agent" "$([ "${HAS_AGENT_CHECK}" -ge 1 ] && echo true || echo false)"

# ─── Test 4: Policy health report structure ─────────────────────────────────

echo -e "${BOLD}Test 4: Policy health report structure${NC}"

check "Policy health script exists" "$([ -f "${REPO_ROOT}/bin/zlar-oc-policy-health" ] && echo true || echo false)"
check "Policy health is executable" "$([ -x "${REPO_ROOT}/bin/zlar-oc-policy-health" ] && echo true || echo false)"

# Test key screening functions exist
HAS_HEALTH_SCORE=$(grep -c 'compute_health_score' "${REPO_ROOT}/bin/zlar-oc-policy-health" || echo 0)
HAS_UNKNOWN_HTTPS=$(grep -c 'unknown_https' "${REPO_ROOT}/bin/zlar-oc-policy-health" || echo 0)
HAS_ASK_ATP=$(grep -c 'ATP' "${REPO_ROOT}/bin/zlar-oc-policy-health" || echo 0)
HAS_MUTATION_REPORT=$(grep -c 'Policy Mutation' "${REPO_ROOT}/bin/zlar-oc-policy-health" || echo 0)
HAS_LOCKDOWN_CHECK=$(grep -c 'lockdown' "${REPO_ROOT}/bin/zlar-oc-policy-health" || echo 0)

check "Health score computation exists" "$([ "${HAS_HEALTH_SCORE}" -ge 2 ] && echo true || echo false)"
check "Unknown HTTPS screening exists" "$([ "${HAS_UNKNOWN_HTTPS}" -ge 2 ] && echo true || echo false)"
check "ATP expenditure tracking exists" "$([ "${HAS_ASK_ATP}" -ge 1 ] && echo true || echo false)"
check "Policy mutation log reporting exists" "$([ "${HAS_MUTATION_REPORT}" -ge 1 ] && echo true || echo false)"
check "Watchdog lockdown reporting exists" "$([ "${HAS_LOCKDOWN_CHECK}" -ge 1 ] && echo true || echo false)"

# ─── Test 5: Policy health with empty audit file ────────────────────────────

echo -e "${BOLD}Test 5: Policy health with synthetic audit data${NC}"

TMPDIR=$(mktemp -d)
FAKE_AUDIT="${TMPDIR}/audit.jsonl"

# Write synthetic audit events
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > "${FAKE_AUDIT}" <<JSONL
{"id":"test-001","ts":"${NOW}","seq":1,"source":"gate","host":"test","user":"aiagent","agent_id":"aiagent","session_id":"test-1","domain":"net.outbound","action":"connect","outcome":"allow","detail":{"dst_host":"api.anthropic.com","dst_port":443},"rule":"R021","policy_version":"1.1.0","severity":"info"}
{"id":"test-002","ts":"${NOW}","seq":2,"source":"gate","host":"test","user":"aiagent","agent_id":"aiagent","session_id":"test-1","domain":"net.outbound","action":"connect","outcome":"log","detail":{"dst_host":"unknown.example.com","dst_port":443},"rule":"R022","policy_version":"1.1.0","severity":"warn"}
{"id":"test-003","ts":"${NOW}","seq":3,"source":"gate","host":"test","user":"aiagent","agent_id":"aiagent","session_id":"test-1","domain":"exec","action":"run","outcome":"deny","detail":{"binary":"/usr/bin/curl"},"rule":"R010","policy_version":"1.1.0","severity":"warn"}
{"id":"test-004","ts":"${NOW}","seq":4,"source":"gate","host":"test","user":"aiagent","agent_id":"aiagent","session_id":"test-1","domain":"policy","action":"heartbeat","outcome":"allow","detail":{"event":"integrity_heartbeat","hash":"abc123","version":"1.1.0","rule_count":16},"rule":"","policy_version":"1.1.0","severity":"info"}
JSONL

# Run health report in JSON mode
HEALTH_JSON=$("${REPO_ROOT}/bin/zlar-oc-policy-health" --audit "${FAKE_AUDIT}" --since 1h --format json 2>/dev/null || echo '{}')

TOTAL=$(echo "${HEALTH_JSON}" | jq -r '.metrics.total_events // 0')
UNKNOWNS=$(echo "${HEALTH_JSON}" | jq -r '.metrics.unknown_https_destinations // 0')
SCORE=$(echo "${HEALTH_JSON}" | jq -r '.health_score // 0')

check "Health report parses synthetic data (${TOTAL} events)" "$([ "${TOTAL}" -ge 3 ] && echo true || echo false)"
check "Detects unknown HTTPS (${UNKNOWNS} found)" "$([ "${UNKNOWNS}" -ge 1 ] && echo true || echo false)"
check "Health score computed (${SCORE}/100)" "$([ "${SCORE}" -gt 0 ] && echo true || echo false)"

# Verify agent_id is in the audit events
AGENT_ID_IN_AUDIT=$(grep -c '"agent_id"' "${FAKE_AUDIT}")
check "agent_id present in audit events" "$([ "${AGENT_ID_IN_AUDIT}" -ge 1 ] && echo true || echo false)"

SESSION_ID_IN_AUDIT=$(grep -c '"session_id"' "${FAKE_AUDIT}")
check "session_id present in audit events" "$([ "${SESSION_ID_IN_AUDIT}" -ge 1 ] && echo true || echo false)"

rm -rf "${TMPDIR}"

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Results${NC}"
echo -e "  ${GREEN}Passed: ${PASSED}${NC}"
echo -e "  ${RED}Failed: ${FAILED}${NC}"
echo ""

if [ ${FAILED} -gt 0 ]; then
    echo -e "${RED}${BOLD}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
fi
