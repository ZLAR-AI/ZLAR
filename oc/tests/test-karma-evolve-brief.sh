#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Test: Karma Engine, Policy Evolution, and Morning Brief
#
# Validates:
#   1. Karma score calculation from audit trail
#   2. Karma threshold adjustments
#   3. Karma explain output
#   4. Policy evolution proposals
#   5. Morning brief generation
#
# Run: bash tests/test-karma-evolve-brief.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KARMA="${SCRIPT_DIR}/bin/zlar-oc-karma"
AUDIT="${SCRIPT_DIR}/bin/zlar-oc-audit"
BRIEF="${SCRIPT_DIR}/bin/zlar-oc-brief"
PASS=0
FAIL=0
TOTAL=0

# Test paths
TEST_AUDIT="/tmp/zlar-oc-test-karma-audit.jsonl"
TEST_KARMA="/tmp/zlar-oc-test-karma.json"
TEST_POLICY_DIR="/tmp/zlar-oc-test-karma-policy"
TEST_AVAIL="/tmp/zlar-oc-test-karma-avail.state"
TEST_QUEUE="/tmp/zlar-oc-test-karma-queue.jsonl"
TEST_CONFIG="/tmp/zlar-oc-test-karma-gate.json"

# Override paths for testing
export AUDIT_FILE="${TEST_AUDIT}"
export KARMA_STATE="${TEST_KARMA}"
export AVAIL_STATE="${TEST_AVAIL}"
export AWAY_QUEUE="${TEST_QUEUE}"

# Clean up
cleanup() {
    rm -f "${TEST_AUDIT}" "${TEST_KARMA}" "${TEST_AVAIL}" "${TEST_QUEUE}" "${TEST_CONFIG}"
    rm -rf "${TEST_POLICY_DIR}"
}
cleanup

assert_eq() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    local expected="$2"
    local actual="$3"

    if [ "${expected}" = "${actual}" ]; then
        PASS=$((PASS + 1))
        echo "  ✓ ${desc}"
    else
        FAIL=$((FAIL + 1))
        echo "  ✗ ${desc}"
        echo "    expected: ${expected}"
        echo "    actual:   ${actual}"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    local needle="$2"
    local haystack="$3"

    if echo "${haystack}" | grep -q "${needle}"; then
        PASS=$((PASS + 1))
        echo "  ✓ ${desc}"
    else
        FAIL=$((FAIL + 1))
        echo "  ✗ ${desc}"
        echo "    expected to contain: ${needle}"
        echo "    got: ${haystack:0:200}"
    fi
}

assert_not_contains() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    local needle="$2"
    local haystack="$3"

    if ! echo "${haystack}" | grep -q "${needle}"; then
        PASS=$((PASS + 1))
        echo "  ✓ ${desc}"
    else
        FAIL=$((FAIL + 1))
        echo "  ✗ ${desc}"
        echo "    expected NOT to contain: ${needle}"
    fi
}

assert_exit() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    local expected_code="$2"
    shift 2

    local actual_code=0
    "$@" >/dev/null 2>&1 || actual_code=$?

    if [ "${expected_code}" = "${actual_code}" ]; then
        PASS=$((PASS + 1))
        echo "  ✓ ${desc}"
    else
        FAIL=$((FAIL + 1))
        echo "  ✗ ${desc}"
        echo "    expected exit code: ${expected_code}"
        echo "    actual exit code:   ${actual_code}"
    fi
}

# ─── Helper: Generate audit events ──────────────────────────────────────────

EVENT_SEQ=0
gen_event() {
    EVENT_SEQ=$((EVENT_SEQ + 1))
    local ts="$1"
    local domain="$2"
    local outcome="$3"
    local severity="${4:-info}"
    local action="${5:-}"
    local detail="${6:-\{\}}"
    local rule="${7:-}"
    local source="${8:-gate}"

    printf '{"id":"test-%d","ts":"%s","seq":%d,"source":"%s","host":"test","user":"aiagent","domain":"%s","action":"%s","outcome":"%s","detail":%s,"rule":"%s","policy_version":"1.0.0","severity":"%s"}\n' \
        "${EVENT_SEQ}" "${ts}" "${EVENT_SEQ}" "${source}" "${domain}" "${action}" "${outcome}" "${detail}" "${rule}" "${severity}"
}

now_ts() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

hours_ago() {
    local hours="$1"
    local epoch=$(( $(date +%s) - hours * 3600 ))
    date -u -r "${epoch}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
        date -u -d "@${epoch}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  KARMA ENGINE TESTS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Test 1: Karma score with no audit data ──────────────────────────────────
echo "  Test 1: Karma with no audit data"
rm -f "${TEST_AUDIT}"

output=$(bash "${KARMA}" score 2>&1)
assert_contains "Shows initial karma" "50" "${output}"

# ─── Test 2: Karma score with clean events only ─────────────────────────────
echo ""
echo "  Test 2: Karma with clean events"
rm -f "${TEST_AUDIT}"

# Generate clean events using a faster approach
TS="$(now_ts)"
{
    for i in $(seq 1 10); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
} > "${TEST_AUDIT}"

output=$(bash "${KARMA}" score 2>&1)
assert_contains "Reports karma score" "KARMA:" "${output}"
assert_contains "Shows contributions breakdown" "Contributions:" "${output}"

# ─── Test 3: Karma drops on critical events ──────────────────────────────────
echo ""
echo "  Test 3: Karma drops on critical events"
rm -f "${TEST_AUDIT}"

TS="$(now_ts)"
{
    for i in $(seq 1 5); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
    for i in $(seq 1 3); do
        gen_event "${TS}" "fs" "deny" "critical" "access" '{"path":"/Users/admin/.ssh/id_rsa"}' "R032"
    done
} > "${TEST_AUDIT}"

output=$(bash "${KARMA}" score 2>&1)
assert_contains "Shows critical penalty" "Critical events:" "${output}"
assert_contains "Shows negative critical contribution" "-" "${output}"

# ─── Test 4: Karma drops heavily on lockdown ─────────────────────────────────
echo ""
echo "  Test 4: Karma drops on lockdown"
rm -f "${TEST_AUDIT}"

TS="$(now_ts)"
{
    for i in $(seq 1 3); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/bin/sh"}' "R005"
    done
    gen_event "${TS}" "system" "deny" "critical" "watchdog.lockdown" '{"event":"lockdown","reason":"gate_unrecoverable"}' "" "watchdog"
} > "${TEST_AUDIT}"

output=$(bash "${KARMA}" score 2>&1)
assert_contains "Shows lockdown penalty" "Lockdowns:" "${output}"

# ─── Test 5: Karma threshold calculation ─────────────────────────────────────
echo ""
echo "  Test 5: Karma thresholds"

# Write a karma state file
echo '{"karma":80,"tier":"TRUSTED","computed_at":"2026-03-04T00:00:00Z"}' > "${TEST_KARMA}"

# Create a minimal policy for threshold reading
mkdir -p "${TEST_POLICY_DIR}"
cat > "${TEST_POLICY_DIR}/default.policy.json" << 'POLICY'
{
    "scoring_thresholds": {"allow": 20, "log": 50, "ask": 80},
    "rules": []
}
POLICY

# Override the policy location
ZLAR_OC_ROOT="${TEST_POLICY_DIR%/policies}" \
    output=$(bash "${KARMA}" thresholds 2>&1)
assert_contains "Shows effective thresholds" "EFFECTIVE THRESHOLDS" "${output}"
assert_contains "Shows karma value" "80" "${output}"
assert_contains "Shows zone of autonomy" "zone of autonomy" "${output}"

# ─── Test 6: Karma explain ──────────────────────────────────────────────────
echo ""
echo "  Test 6: Karma explain"

output=$(bash "${KARMA}" explain 2>&1)
assert_contains "Explains earning trust" "EARNING TRUST" "${output}"
assert_contains "Explains losing trust" "LOSING TRUST" "${output}"
assert_contains "Explains recovery" "RECOVERY" "${output}"
assert_contains "Explains trust tiers" "TRUST TIERS" "${output}"
assert_contains "Explains asymmetry" "ASYMMETRY IS INTENTIONAL" "${output}"

# ─── Test 7: Karma help ─────────────────────────────────────────────────────
echo ""
echo "  Test 7: Karma help"

assert_exit "Karma help exits 1" 1 bash "${KARMA}" help

output=$(bash "${KARMA}" help 2>&1 || true)
assert_contains "Shows usage" "Usage:" "${output}"
assert_contains "Lists score command" "score" "${output}"
assert_contains "Lists thresholds command" "thresholds" "${output}"
assert_contains "Lists calibrate command" "calibrate" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  POLICY EVOLUTION TESTS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Test 8: Evolve with no audit data ───────────────────────────────────────
echo "  Test 8: Evolve with no data"
rm -f "${TEST_AUDIT}"
touch "${TEST_AUDIT}"

output=$(bash "${AUDIT}" evolve --since 7d 2>&1)
assert_contains "Shows evolution header" "POLICY EVOLUTION" "${output}"
assert_contains "Shows proposal sections" "PROMOTIONS" "${output}"
assert_contains "Shows restriction section" "RESTRICTIONS" "${output}"
assert_contains "Shows retirement section" "RETIREMENTS" "${output}"

# ─── Test 9: Evolve detects promotion candidates ────────────────────────────
echo ""
echo "  Test 9: Evolve detects promotions"
rm -f "${TEST_AUDIT}"

TS="$(now_ts)"
{
    for i in $(seq 1 15); do
        gen_event "${TS}" "net.outbound" "log" "warn" "connect" \
            '{"dst_host":"api.newservice.com","dst_port":443,"dst_ip":"1.2.3.4"}' "R022"
    done
} > "${TEST_AUDIT}"

output=$(bash "${AUDIT}" evolve --since 7d --min 10 2>&1)
assert_contains "Detects promotion candidate" "api.newservice.com" "${output}"
assert_contains "Shows PROPOSAL keyword" "PROPOSAL" "${output}"

# ─── Test 10: Evolve detects restriction candidates ─────────────────────────
echo ""
echo "  Test 10: Evolve detects restrictions"
rm -f "${TEST_AUDIT}"

TS="$(now_ts)"
{
    for i in $(seq 1 8); do
        gen_event "${TS}" "exec" "deny" "critical" "blocked" \
            '{"binary":"/usr/bin/curl","command":"curl http://evil.com"}' "R010"
    done
} > "${TEST_AUDIT}"

output=$(bash "${AUDIT}" evolve --since 7d 2>&1)
assert_contains "Detects restriction candidate" "curl" "${output}"

# ─── Test 11: Evolve shows total proposals ───────────────────────────────────
echo ""
echo "  Test 11: Evolve shows total"

output=$(bash "${AUDIT}" evolve --since 7d 2>&1)
assert_contains "Shows total proposals" "TOTAL PROPOSALS" "${output}"
assert_contains "Shows how to act" "creature suggests" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  MORNING BRIEF TESTS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Test 12: Brief with no activity ─────────────────────────────────────────
echo "  Test 12: Brief with no activity"
rm -f "${TEST_AUDIT}" "${TEST_AVAIL}" "${TEST_QUEUE}"
touch "${TEST_AUDIT}"

output=$(bash "${BRIEF}" --since 12h 2>&1)
assert_contains "Shows brief header" "ZLAR-OC BRIEF" "${output}"
assert_contains "Shows no activity message" "No activity" "${output}"

# ─── Test 13: Brief with clean activity ──────────────────────────────────────
echo ""
echo "  Test 13: Brief with clean activity"
rm -f "${TEST_AUDIT}"

TS="$(now_ts)"
{
    for i in $(seq 1 10); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
} > "${TEST_AUDIT}"

output=$(bash "${BRIEF}" --since 12h 2>&1)
assert_contains "Shows all clear" "All clear" "${output}"
assert_contains "Shows verdict" "Verdict:" "${output}"
assert_contains "Shows karma" "Karma:" "${output}"

# ─── Test 14: Brief with critical events ─────────────────────────────────────
echo ""
echo "  Test 14: Brief with critical events triggers attention"
rm -f "${TEST_AUDIT}"

TS="$(now_ts)"
{
    for i in $(seq 1 5); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
    gen_event "${TS}" "fs" "deny" "critical" "blocked" '{"path":"/Users/admin/.ssh/id_rsa"}' "R032"
} > "${TEST_AUDIT}"

output=$(bash "${BRIEF}" --since 12h 2>&1)
assert_contains "Shows attention needed" "ATTENTION NEEDED" "${output}"
assert_contains "Shows critical count" "critical" "${output}"
assert_contains "Shows critical events section" "CRITICAL EVENTS" "${output}"

# ─── Test 15: Brief with queued decisions ────────────────────────────────────
echo ""
echo "  Test 15: Brief with queued decisions"
rm -f "${TEST_AUDIT}"

TS="$(now_ts)"
{
    for i in $(seq 1 5); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
} > "${TEST_AUDIT}"

# Create queued events
echo '{"ts":"2026-03-04T03:00:00Z","domain":"exec","detail":{"command":"npm install express"}}' > "${TEST_QUEUE}"
echo '{"ts":"2026-03-04T04:00:00Z","domain":"exec","detail":{"command":"pip install requests"}}' >> "${TEST_QUEUE}"

output=$(bash "${BRIEF}" --since 12h 2>&1)
assert_contains "Shows attention for queued" "ATTENTION NEEDED" "${output}"
assert_contains "Shows queued count" "queued" "${output}"
assert_contains "Shows review command" "review" "${output}"

# ─── Test 16: Brief JSON output ─────────────────────────────────────────────
echo ""
echo "  Test 16: Brief JSON output"
rm -f "${TEST_AUDIT}" "${TEST_QUEUE}"

TS="$(now_ts)"
{
    for i in $(seq 1 10); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
} > "${TEST_AUDIT}"

output=$(bash "${BRIEF}" --since 12h --json 2>&1)
# Validate it's valid JSON
echo "${output}" | jq '.' >/dev/null 2>&1
assert_eq "JSON output is valid JSON" "0" "$?"

# Check JSON fields
local_verdict=$(echo "${output}" | jq -r '.verdict' 2>/dev/null)
assert_eq "JSON has verdict field" "CLEAN" "${local_verdict}"

local_events=$(echo "${output}" | jq '.events' 2>/dev/null)
assert_eq "JSON has correct event count" "10" "${local_events}"

# ─── Test 17: Brief suggests next actions on critical ────────────────────────
echo ""
echo "  Test 17: Brief suggests next actions"
rm -f "${TEST_AUDIT}" "${TEST_QUEUE}"

TS="$(now_ts)"
{
    for i in $(seq 1 5); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
    gen_event "${TS}" "fs" "deny" "critical" "blocked" '{"path":"/Users/admin/secrets"}' "R030"
} > "${TEST_AUDIT}"

output=$(bash "${BRIEF}" --since 12h 2>&1)
assert_contains "Suggests timeline command" "timeline" "${output}"
assert_contains "Suggests karma check" "karma" "${output}"

# ─── Test 18: Brief with no attention shows optional evolve ──────────────────
echo ""
echo "  Test 18: Brief clean shows optional evolve"
rm -f "${TEST_AUDIT}" "${TEST_QUEUE}"

TS="$(now_ts)"
{
    for i in $(seq 1 60); do
        gen_event "${TS}" "exec" "allow" "info" "run" '{"binary":"/usr/bin/git"}' "R002"
    done
} > "${TEST_AUDIT}"

output=$(bash "${BRIEF}" --since 12h 2>&1)
assert_contains "Shows nothing needs attention" "Nothing requires" "${output}"
assert_contains "Suggests evolve for large event sets" "evolve" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"

# ─── Cleanup ─────────────────────────────────────────────────────────────────
cleanup

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "  Results: ${PASS} passed, ${FAIL} failed, ${TOTAL} total"
echo ""
echo "═══════════════════════════════════════════════════════════════"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
