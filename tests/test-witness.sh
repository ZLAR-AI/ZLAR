#!/bin/bash
# test-witness.sh — basic tests for zlar-witness
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"

export ZLAR_AUDIT_FILE="${FIXTURES_DIR}/sample-events.jsonl"

# Pin "now" to just after the fixture's latest event so time-windowed
# queries stay deterministic as the calendar rolls forward.
# Fixture latest event: 2026-04-06T00:04:29Z (epoch 1775433869).
export ZLAR_AUDIT_NOW_EPOCH=1775437469

PASS=0
FAIL=0

assert() {
    local desc="$1"
    local result="$2"
    local expected="$3"

    if [[ "${result}" == *"${expected}"* ]]; then
        echo "  ✓ ${desc}"
        PASS=$(( PASS + 1 ))
    else
        echo "  ✗ ${desc}"
        echo "    expected to contain: ${expected}"
        echo "    got: ${result}"
        FAIL=$(( FAIL + 1 ))
    fi
}

echo "═══════════════════════════════════════"
echo "  zlar-witness tests"
echo "═══════════════════════════════════════"
echo ""

# ── audit-reader tests ──
echo "── audit-reader ──"

source "${PROJECT_DIR}/lib/audit-reader.sh"

result=$(audit_last 3 | wc -l | tr -d ' ')
assert "audit_last returns requested line count" "${result}" "3"

result=$(audit_last 50 | jq -r '.domain' | sort -u | tr '\n' ',')
assert "audit extracts domains" "${result}" "bash"

echo ""

# ── witness scan tests ──
echo "── witness scan ──"

result=$("${PROJECT_DIR}/bin/zlar-witness" scan --since 999999 --format human 2>&1 || true)
assert "scan runs without error" "${result}" "ZLAR Witness"
assert "scan reports event count" "${result}" "Events examined"

result=$("${PROJECT_DIR}/bin/zlar-witness" scan --since 999999 --format json 2>&1 || true)
assert "scan produces valid JSON" "$(echo "${result}" | jq -r '.scanned_at' 2>/dev/null)" "2026"

# Check for SEQ-001 detection (sensitive read + egress in sample data)
assert "scan detects credential-adjacent-egress" "${result}" "SEQ-001"

# Check for SEQ-002 detection (deny + schedule in sample data)
# Note: SEQ-002 requires a cron/schedule event after denial — not present in minimal fixture
# assert "scan detects denied-then-scheduled" "${result}" "SEQ-002"

# Check for SEQ-006 detection (5 R003 denials in test-session-2)
assert "scan detects repeated-denial-burst" "${result}" "SEQ-006"

echo ""

# ── witness patterns ──
echo "── patterns ──"

result=$("${PROJECT_DIR}/bin/zlar-witness" patterns 2>&1 || true)
assert "patterns lists defined sequences" "${result}" "credential-adjacent-egress"
assert "patterns includes denied-then-scheduled" "${result}" "denied-then-scheduled"

echo ""

# ── digest tests ──
echo "── digest ──"

result=$("${PROJECT_DIR}/bin/zlar-digest" generate --period 999999 --format human 2>&1 || true)
assert "brief generates without error" "${result}" "ZLAR Governance Brief"
assert "brief shows human-approved count" "${result}" "Human-approved"
assert "brief shows policy denied count" "${result}" "Policy denied"
assert "brief shows human denied count" "${result}" "Human denied"
assert "brief shows timeout denied count" "${result}" "Timeout denied"
assert "brief shows glossary" "${result}" "Glossary"

result=$("${PROJECT_DIR}/bin/zlar-digest" generate --period 999999 --format json 2>&1 || true)
assert "brief produces valid JSON" "$(echo "${result}" | jq -r '.generated' 2>/dev/null)" "2026"

# Check brief shows approval latency section
result=$("${PROJECT_DIR}/bin/zlar-digest" generate --period 999999 --format human 2>&1 || true)
assert "brief shows approval latency" "${result}" "Approval Latency"

# Verify pending→authorized pairs are counted (fixture has 3 human-authorized, 1 human-denied, 1 timeout)
assert "brief shows correct human-approved" "${result}" "Human-approved:      3"

# Verify denial breakdown
assert "brief shows policy denials" "${result}" "Policy denied:       7"
assert "brief shows human denials" "${result}" "Human denied:        1"
assert "brief shows timeout denials" "${result}" "Timeout denied:      1"

echo ""

# ── standing tests ──
echo "── standing ──"

result=$("${PROJECT_DIR}/bin/zlar-standing" view 2>&1 || true)
assert "standing view runs" "${result}" "ZLAR Standing Authority"
assert "standing shows visibility limits" "${result}" "Visibility Limits"

echo ""

# ── Results ──
echo "═══════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════════════════════════"

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
