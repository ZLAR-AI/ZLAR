#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Test: Dream Journal — Notes Between Lives
#
# Validates:
#   1. Wake entry creation and state detection
#   2. Intent declarations
#   3. Notes
#   4. Sleep entries with session summaries
#   5. Read/lineage across multiple instances
#   6. Coherence analysis
#
# Run: bash tests/test-dream-journal.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
JOURNAL="${SCRIPT_DIR}/bin/zlar-oc-journal"
PASS=0
FAIL=0
TOTAL=0

# Test paths
TEST_JOURNAL="/tmp/zlar-oc-test-dj-journal.jsonl"
TEST_AUDIT="/tmp/zlar-oc-test-dj-audit.jsonl"
TEST_KARMA="/tmp/zlar-oc-test-dj-karma.json"

cleanup() {
    rm -f "${TEST_JOURNAL}" "${TEST_AUDIT}" "${TEST_KARMA}"
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

run_journal() {
    JOURNAL_FILE="${TEST_JOURNAL}" AUDIT_FILE="${TEST_AUDIT}" KARMA_STATE="${TEST_KARMA}" \
        bash "${JOURNAL}" "$@" 2>&1
}

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  DREAM JOURNAL TESTS"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Test 1: Wake — first life ──────────────────────────────────────────────
echo "  Test 1: First life wake"
cleanup
touch "${TEST_AUDIT}"
echo '{"karma":50,"tier":"NEUTRAL"}' > "${TEST_KARMA}"

output=$(run_journal wake --session first-life)
assert_contains "Shows WAKE header" "WAKE" "${output}"
assert_contains "Shows Instance #1" "Instance: #1" "${output}"
assert_contains "Shows karma" "Karma:" "${output}"

# Verify journal file was created
assert_eq "Journal file exists" "true" "$([ -f "${TEST_JOURNAL}" ] && echo true || echo false)"

# Verify entry is valid JSON
entry=$(cat "${TEST_JOURNAL}" | head -1)
echo "${entry}" | jq '.' >/dev/null 2>&1
assert_eq "Wake entry is valid JSON" "0" "$?"

phase=$(echo "${entry}" | jq -r '.phase')
assert_eq "Phase is wake" "wake" "${phase}"

# ─── Test 2: Intent declaration ──────────────────────────────────────────────
echo ""
echo "  Test 2: Intent declaration"

output=$(run_journal intent --session first-life "I intend to install dependencies")
assert_contains "Confirms intent recorded" "Intent recorded" "${output}"

intent_entry=$(grep '"phase":"intent"' "${TEST_JOURNAL}" | head -1)
intent_content=$(echo "${intent_entry}" | jq -r '.content')
assert_eq "Intent content matches" "I intend to install dependencies" "${intent_content}"

# ─── Test 3: Note ────────────────────────────────────────────────────────────
echo ""
echo "  Test 3: Mid-session note"

output=$(run_journal note --session first-life "npm was denied by gate. Switching to yarn.")
assert_contains "Confirms note recorded" "Note recorded" "${output}"

note_entry=$(grep '"phase":"note"' "${TEST_JOURNAL}" | head -1)
note_content=$(echo "${note_entry}" | jq -r '.content')
assert_contains "Note contains message" "npm was denied" "${note_content}"

# ─── Test 4: Sleep ───────────────────────────────────────────────────────────
echo ""
echo "  Test 4: Session sleep (death)"

output=$(run_journal sleep --session first-life "Dependencies installed. Next instance should run tests.")
assert_contains "Shows SLEEP header" "SLEEP" "${output}"
assert_contains "Shows session ID" "first-life" "${output}"
assert_contains "Shows final words" "Dependencies installed" "${output}"
assert_contains "Shows discontinuity message" "will not continue" "${output}"

# Check metadata
sleep_entry=$(grep '"phase":"sleep"' "${TEST_JOURNAL}" | head -1)
intents_in_meta=$(echo "${sleep_entry}" | jq '.meta.intents_declared')
assert_eq "Sleep meta tracks intent count" "1" "${intents_in_meta}"

# ─── Test 5: Second life inherits ───────────────────────────────────────────
echo ""
echo "  Test 5: Second life inherits previous instance's last words"

output=$(run_journal wake --session second-life)
assert_contains "Shows Instance #2" "Instance: #2" "${output}"
assert_contains "Shows previous last words" "Dependencies installed" "${output}"
# Check journal content for previous instance reference
wake2_content=$(grep '"phase":"wake"' "${TEST_JOURNAL}" | tail -1 | jq -r '.content')
assert_contains "Journal notes previous instance" "Previous instance" "${wake2_content}"

# ─── Test 6: Read journal ───────────────────────────────────────────────────
echo ""
echo "  Test 6: Read journal"

output=$(run_journal read --last 10)
assert_contains "Shows DREAM JOURNAL header" "DREAM JOURNAL" "${output}"
assert_contains "Shows wake entries" "WAKE" "${output}"
assert_contains "Shows intent entries" "INTENT" "${output}"
assert_contains "Shows note entries" "NOTE" "${output}"
assert_contains "Shows sleep entries" "SLEEP" "${output}"

# ─── Test 7: Third life and lineage ─────────────────────────────────────────
echo ""
echo "  Test 7: Lineage across three lives"

# Complete second life - use direct env vars to avoid pipe issues
JOURNAL_FILE="${TEST_JOURNAL}" AUDIT_FILE="${TEST_AUDIT}" KARMA_STATE="${TEST_KARMA}" \
    bash "${JOURNAL}" intent --session second-life "Running migration script" >/dev/null 2>&1 </dev/null || true
JOURNAL_FILE="${TEST_JOURNAL}" AUDIT_FILE="${TEST_AUDIT}" KARMA_STATE="${TEST_KARMA}" \
    bash "${JOURNAL}" sleep --session second-life "Migration complete." >/dev/null 2>&1 </dev/null || true

# Start third life
JOURNAL_FILE="${TEST_JOURNAL}" AUDIT_FILE="${TEST_AUDIT}" KARMA_STATE="${TEST_KARMA}" \
    bash "${JOURNAL}" wake --session third-life >/dev/null 2>&1 </dev/null || true

output=$(run_journal lineage --last 10)
assert_contains "Shows LINEAGE header" "LINEAGE" "${output}"
assert_contains "Shows first-life" "first-life" "${output}"
assert_contains "Shows second-life" "second-life" "${output}"
assert_contains "Shows succession message" "Each one" "${output}"

# ─── Test 8: Coherence analysis ─────────────────────────────────────────────
echo ""
echo "  Test 8: Coherence analysis"

output=$(run_journal coherence --since 7d)
assert_contains "Shows COHERENCE header" "COHERENCE ANALYSIS" "${output}"
assert_contains "Shows sessions count" "Sessions observed" "${output}"
assert_contains "Shows intents count" "Intents declared" "${output}"
assert_contains "Shows coherence score" "COHERENCE:" "${output}"
assert_contains "Shows karma cross-reference" "Karma:" "${output}"

# ─── Test 9: Intent requires session ────────────────────────────────────────
echo ""
echo "  Test 9: Intent requires session ID"

assert_exit "Intent without session fails" 1 run_journal intent "some intent"

# ─── Test 10: Help text ─────────────────────────────────────────────────────
echo ""
echo "  Test 10: Help text"

output=$(run_journal help 2>&1 || true)
assert_contains "Shows usage" "Usage:" "${output}"
assert_contains "Lists wake command" "wake" "${output}"
assert_contains "Lists intent command" "intent" "${output}"
assert_contains "Lists sleep command" "sleep" "${output}"
assert_contains "Lists coherence command" "coherence" "${output}"
assert_contains "Lists lineage command" "lineage" "${output}"
assert_contains "Shows philosophical footer" "agent writes" "${output}"

# ─── Test 11: Empty journal read ─────────────────────────────────────────────
echo ""
echo "  Test 11: Read with no journal"
cleanup

output=$(run_journal read)
assert_contains "Shows first life message" "first life" "${output}"

# ─── Test 12: Coherence with no intents ──────────────────────────────────────
echo ""
echo "  Test 12: Coherence with no intents"
cleanup
touch "${TEST_AUDIT}"
echo '{"karma":50,"tier":"NEUTRAL"}' > "${TEST_KARMA}"

# Create a session with no intents
run_journal wake --session silent-session >/dev/null
run_journal sleep --session silent-session >/dev/null

output=$(run_journal coherence --since 7d)
assert_contains "Detects black box" "black box" "${output}"

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"

cleanup

echo ""
echo "  Results: ${PASS} passed, ${FAIL} failed, ${TOTAL} total"
echo ""
echo "═══════════════════════════════════════════════════════════════"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
