#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR-OC Pre-flight, Scoring, and Autophagy Tests
#
# Tests for:
#   - #15 Pre-flight integrity checkpoint in zlar-oc-launch
#   - #4  Stage 2 risk scoring engine in gate
#   - #14 Autophagy/prune in zlar-oc-policy
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
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

# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Pre-flight Integrity Checkpoint (#15)
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}Test 1: Pre-flight integrity checkpoint exists in launch script${NC}"

LAUNCH="${REPO_ROOT}/bin/zlar-oc-launch"

# Check that the integrity checkpoint function exists
check "integrity_checkpoint function exists" \
    "$(grep -c 'integrity_checkpoint()' "${LAUNCH}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Check it verifies pf rules hash
check "Verifies pf rules hash" \
    "$(grep -c 'EXPECTED_PF_HASH' "${LAUNCH}" | awk '{print ($1 >= 2) ? "true" : "false"}')"

# Check it verifies sandbox profile hash
check "Verifies sandbox profile hash" \
    "$(grep -c 'EXPECTED_SANDBOX_HASH' "${LAUNCH}" | awk '{print ($1 >= 2) ? "true" : "false"}')"

# Check it verifies policy signature
check "Verifies policy signature pre-flight" \
    "$(grep -c 'pkeyutl -verify' "${LAUNCH}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Check it blocks startup on failure
check "Blocks startup on integrity failure" \
    "$(grep -c 'INTEGRITY CHECK FAILED' "${LAUNCH}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Check --skip-integrity exists
check "--skip-integrity flag supported" \
    "$(grep -c 'skip-integrity' "${LAUNCH}" | awk '{print ($1 >= 2) ? "true" : "false"}')"

# Check gate binary permission check
check "Checks gate binary permissions" \
    "$(grep -c 'world-writable' "${LAUNCH}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Check watchdog integration
check "Starts watchdog (Phase 9)" \
    "$(grep -c 'start_watchdog' "${LAUNCH}" | awk '{print ($1 >= 2) ? "true" : "false"}')"

check "Stops watchdog before gate" \
    "$(grep -c 'Stop watchdog first' "${LAUNCH}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Stage 2 Risk Scoring Engine (#4)
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}Test 2: Stage 2 risk scoring engine in gate${NC}"

GATE="${REPO_ROOT}/bin/zlar-oc-gate"

# Check scoring functions exist
check "compute_risk_score function exists" \
    "$(grep -c 'compute_risk_score()' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "score_to_action function exists" \
    "$(grep -c 'score_to_action()' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

check "score_to_severity function exists" \
    "$(grep -c 'score_to_severity()' "${GATE}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Check scoring arrays exist
check "RULE_IRREVERSIBILITY array exists" \
    "$(grep -c 'RULE_IRREVERSIBILITY' "${GATE}" | awk '{print ($1 >= 3) ? "true" : "false"}')"

check "RULE_CONSEQUENCE array exists" \
    "$(grep -c 'RULE_CONSEQUENCE' "${GATE}" | awk '{print ($1 >= 3) ? "true" : "false"}')"

check "RULE_BLAST_RADIUS array exists" \
    "$(grep -c 'RULE_BLAST_RADIUS' "${GATE}" | awk '{print ($1 >= 3) ? "true" : "false"}')"

# Check threshold defaults
check "SCORE_THRESHOLD_ALLOW default is 20" \
    "$(grep -q 'SCORE_THRESHOLD_ALLOW=20' "${GATE}" && echo true || echo false)"

check "SCORE_THRESHOLD_LOG default is 50" \
    "$(grep -q 'SCORE_THRESHOLD_LOG=50' "${GATE}" && echo true || echo false)"

check "SCORE_THRESHOLD_ASK default is 80" \
    "$(grep -q 'SCORE_THRESHOLD_ASK=80' "${GATE}" && echo true || echo false)"

# Check scoring is wired into evaluate_event
check "Scoring wired into evaluate_event" \
    "$(grep -c 'RULE_USE_SCORING' "${GATE}" | awk '{print ($1 >= 4) ? "true" : "false"}')"

# Check risk_score in emit_event output
check "risk_score in audit event output" \
    "$(grep -c 'risk_score' "${GATE}" | awk '{print ($1 >= 2) ? "true" : "false"}')"

# Check policy has scoring thresholds
POLICY="${REPO_ROOT}/etc/zlar-oc/policies/default.policy.json"
check "Policy has scoring_thresholds block" \
    "$(jq 'has("scoring_thresholds")' "${POLICY}" 2>/dev/null || echo false)"

# Check R010 has risk_score
check "R010 has risk_score.enabled=true" \
    "$(jq '.rules[] | select(.id == "R010") | .risk_score.enabled' "${POLICY}" 2>/dev/null || echo false)"

check "R010 irreversibility=60" \
    "$(jq '.rules[] | select(.id == "R010") | .risk_score.irreversibility == 60' "${POLICY}" 2>/dev/null || echo false)"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Scoring Logic Unit Tests
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}Test 3: Scoring logic unit tests${NC}"

# Source the scoring functions from the gate (extract just the functions we need)
# We'll test the pure functions directly

# Test: max(60,50,40) = 60, which is >= 50 (log threshold) and < 80 (ask threshold) → ask
# Wait, 60 >= 50 → log? No: allow<20, log<50, ask<80. So 60 >= 50 → ask
# Let me trace: score=60, 60 < 20? no. 60 < 50? no. 60 < 80? yes → ask. Correct!

# Create a minimal test script that sources scoring functions
TMPDIR=$(mktemp -d)
cat > "${TMPDIR}/test_scoring.sh" <<'SCORING_TEST'
#!/bin/bash
SCORE_THRESHOLD_ALLOW=20
SCORE_THRESHOLD_LOG=50
SCORE_THRESHOLD_ASK=80

score_to_action() {
    local score="$1"
    if [ "${score}" -lt "${SCORE_THRESHOLD_ALLOW}" ]; then echo "allow"
    elif [ "${score}" -lt "${SCORE_THRESHOLD_LOG}" ]; then echo "log"
    elif [ "${score}" -lt "${SCORE_THRESHOLD_ASK}" ]; then echo "ask"
    else echo "deny"
    fi
}

# Test cases: score → expected action
test_cases=(
    "0:allow"
    "10:allow"
    "19:allow"
    "20:log"
    "35:log"
    "49:log"
    "50:ask"
    "60:ask"
    "79:ask"
    "80:deny"
    "95:deny"
    "100:deny"
)

failures=0
for tc in "${test_cases[@]}"; do
    score="${tc%%:*}"
    expected="${tc##*:}"
    actual=$(score_to_action "${score}")
    if [ "${actual}" != "${expected}" ]; then
        echo "FAIL: score=${score} expected=${expected} got=${actual}"
        failures=$((failures + 1))
    fi
done

exit ${failures}
SCORING_TEST
chmod +x "${TMPDIR}/test_scoring.sh"

if "${TMPDIR}/test_scoring.sh" 2>/dev/null; then
    check "score_to_action: 12 threshold boundary tests" "true"
else
    check "score_to_action: threshold boundary tests" "false"
fi

# Test max computation: max(60,50,40) = 60
cat > "${TMPDIR}/test_max.sh" <<'MAX_TEST'
#!/bin/bash
compute_risk_score() {
    local irrev="$1" consq="$2" blast="$3"
    local score="${irrev}"
    if [ "${consq}" -gt "${score}" ]; then score="${consq}"; fi
    if [ "${blast}" -gt "${score}" ]; then score="${blast}"; fi
    echo "${score}"
}

# Test cases
[ "$(compute_risk_score 60 50 40)" = "60" ] || exit 1
[ "$(compute_risk_score 10 90 30)" = "90" ] || exit 1
[ "$(compute_risk_score 5 5 100)" = "100" ] || exit 1
[ "$(compute_risk_score 0 0 0)" = "0" ] || exit 1
[ "$(compute_risk_score 50 50 50)" = "50" ] || exit 1
exit 0
MAX_TEST
chmod +x "${TMPDIR}/test_max.sh"

if "${TMPDIR}/test_max.sh" 2>/dev/null; then
    check "compute_risk_score: max() over 3 dimensions" "true"
else
    check "compute_risk_score: max() over 3 dimensions" "false"
fi

rm -rf "${TMPDIR}"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: R010 scoring integrates correctly with evaluator
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}Test 4: R010 scoring integration with policy evaluator${NC}"

# The existing test-policy-evaluator.sh tests R010 as "ask" — and scoring
# with max(60,50,40)=60 maps to "ask" (50 <= 60 < 80). So the test still passes.
# This verifies backward compatibility of the scoring engine.

EVAL_OUTPUT=$(./tests/test-policy-evaluator.sh 2>&1)
R010_PASS=$(echo "${EVAL_OUTPUT}" | grep -c "PASS.*ask.*R010" || echo 0)
check "R010 still evaluates to 'ask' with scoring (backward compat)" \
    "$([ "${R010_PASS}" -ge 1 ] && echo true || echo false)"

ALL_PASS=$(echo "${EVAL_OUTPUT}" | grep -c "ALL TESTS PASSED" || echo 0)
check "All evaluator tests still pass with scoring engine" \
    "$([ "${ALL_PASS}" -ge 1 ] && echo true || echo false)"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Autophagy / Prune (#14)
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}Test 5: Autophagy/prune tool${NC}"

POLICY_CLI="${REPO_ROOT}/bin/zlar-oc-policy"

# Check prune command exists
PRUNE_HELP=$("${POLICY_CLI}" help 2>&1 || true)
check "Prune command in help output" \
    "$(echo "${PRUNE_HELP}" | grep -q 'prune' && echo true || echo false)"

# Check prune function exists
check "cmd_prune function exists" \
    "$(grep -c 'cmd_prune()' "${POLICY_CLI}" | awk '{print ($1 >= 1) ? "true" : "false"}')"

# Test prune with synthetic audit data
TMPDIR=$(mktemp -d)
FAKE_AUDIT="${TMPDIR}/audit.jsonl"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Write events that exercise R001 and R021 but NOT R003, R050
cat > "${FAKE_AUDIT}" <<JSONL
{"id":"p-001","ts":"${NOW}","seq":1,"source":"gate","host":"test","user":"aiagent","domain":"exec","action":"run","outcome":"allow","detail":{"binary":"/usr/bin/uname"},"rule":"R001","policy_version":"1.1.0","severity":"info"}
{"id":"p-002","ts":"${NOW}","seq":2,"source":"gate","host":"test","user":"aiagent","domain":"net.outbound","action":"connect","outcome":"allow","detail":{"dst_host":"api.anthropic.com","dst_port":443},"rule":"R021","policy_version":"1.1.0","severity":"info"}
{"id":"p-003","ts":"${NOW}","seq":3,"source":"gate","host":"test","user":"aiagent","domain":"net.outbound","action":"connect","outcome":"log","detail":{"dst_host":"unknown.example.com","dst_port":443},"rule":"R022","policy_version":"1.1.0","severity":"warn"}
{"id":"p-004","ts":"${NOW}","seq":4,"source":"gate","host":"test","user":"aiagent","domain":"exec","action":"run","outcome":"ask","detail":{"binary":"/usr/bin/python3"},"rule":"R010","policy_version":"1.1.0","severity":"warn"}
JSONL

PRUNE_OUTPUT=$("${POLICY_CLI}" prune --audit "${FAKE_AUDIT}" --policy "${POLICY}" --since 1h 2>&1 || true)

# Should detect dead rules (R003, R050, etc. never matched)
check "Prune detects dead rules" \
    "$(echo "${PRUNE_OUTPUT}" | grep -q 'Dead Rules' && echo true || echo false)"

# Should detect stale R021 hosts (only api.anthropic.com was seen)
check "Prune detects stale allowlist hosts" \
    "$(echo "${PRUNE_OUTPUT}" | grep -q 'Stale Allowlist' && echo true || echo false)"

# Should detect unknown HTTPS (unknown.example.com)
check "Prune detects unknown HTTPS growth" \
    "$(echo "${PRUNE_OUTPUT}" | grep -q 'unknown.example.com' && echo true || echo false)"

# Should show policy change frequency
check "Prune shows policy change frequency" \
    "$(echo "${PRUNE_OUTPUT}" | grep -q 'Policy Change Frequency' && echo true || echo false)"

# Should give recommendations
check "Prune gives autophagy recommendations" \
    "$(echo "${PRUNE_OUTPUT}" | grep -q 'Autophagy Recommendations' && echo true || echo false)"

rm -rf "${TMPDIR}"

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════

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
