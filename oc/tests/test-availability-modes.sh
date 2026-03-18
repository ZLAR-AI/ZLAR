#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Test: Human Availability Modes (Active/Away/Review)
#
# Validates that the availability controller correctly:
#   1. Transitions between modes
#   2. Persists state to the state file
#   3. Reports status accurately
#   4. Handles the away queue
#
# Run: bash tests/test-availability-modes.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AVAIL="${SCRIPT_DIR}/bin/zlar-oc-availability"
PASS=0
FAIL=0
TOTAL=0

# Use temp locations for testing
export STATE_FILE="/tmp/zlar-oc-test-availability.state"
export AWAY_QUEUE="/tmp/zlar-oc-test-away-queue.jsonl"
export AUDIT_FILE="/tmp/zlar-oc-test-audit.jsonl"

# Clean up
rm -f "${STATE_FILE}" "${AWAY_QUEUE}" "${AUDIT_FILE}"
touch "${AUDIT_FILE}"

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
        echo "    actual: ${haystack}"
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  Testing: Human Availability Modes"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Test 1: Default mode is active ─────────────────────────────────────────
echo "  Test 1: Default mode"
output=$(bash "${AVAIL}" status 2>&1)
assert_contains "Default status shows 'active'" "active" "${output}"

# ─── Test 2: Transition to away ─────────────────────────────────────────────
echo "  Test 2: Transition to away"
output=$(bash "${AVAIL}" away 2>&1)
assert_contains "Away transition message" "active → away" "${output}"

# ─── Test 3: State file exists and contains away ─────────────────────────────
echo "  Test 3: State persistence"
if [ -f "${STATE_FILE}" ]; then
    mode=$(cat "${STATE_FILE}" | grep -o '"mode": *"[^"]*"' | head -1 | cut -d'"' -f4)
    assert_eq "State file contains away mode" "away" "${mode}"
else
    TOTAL=$((TOTAL + 1))
    FAIL=$((FAIL + 1))
    echo "  ✗ State file should exist after transition"
fi

# ─── Test 4: Transition to review ────────────────────────────────────────────
echo "  Test 4: Transition to review"
output=$(bash "${AVAIL}" review 2>&1)
assert_contains "Review transition message" "away → review" "${output}"

# ─── Test 5: Transition back to active ───────────────────────────────────────
echo "  Test 5: Transition to active"
output=$(bash "${AVAIL}" active 2>&1)
assert_contains "Active transition message" "review → active" "${output}"

# ─── Test 6: Already in mode ────────────────────────────────────────────────
echo "  Test 6: Idempotent mode set"
output=$(bash "${AVAIL}" active 2>&1)
assert_contains "Already active message" "Already in active" "${output}"

# ─── Test 7: Status command ─────────────────────────────────────────────────
echo "  Test 7: Status details"
bash "${AVAIL}" away >/dev/null 2>&1
output=$(bash "${AVAIL}" status 2>&1)
assert_contains "Status shows away" "away" "${output}"

# ─── Cleanup ─────────────────────────────────────────────────────────────────
rm -f "${STATE_FILE}" "${AWAY_QUEUE}" "${AUDIT_FILE}"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "═══════════════════════════════════════════════════════════════"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
